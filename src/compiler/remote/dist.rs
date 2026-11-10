// Copyright 2026 Mozilla Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use super::{CompileExecutor, CompileOutcome, CompileRequest, HashKeyOptions, LocalCompile};
use crate::compiler::{Compilation, DistType};
use crate::dist::{self, CompileCommand, PathTransformer};
use crate::errors::*;
use crate::lru_disk_cache;
use crate::mock_command::CommandCreatorSync;
use async_trait::async_trait;
use fs_err::{self as fs, File};
use std::io;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::Arc;

/// What to do when sccache-dist can't complete a compile.
#[derive(Debug)]
enum DistError {
    CompileLocally(Error),
    FailCompile(Error),
}

struct DistCompileRequest {
    path_transformer: PathTransformer,
    command: CompileCommand,
    weak_toolchain_key: String,
    cwd: PathBuf,
}

/// A [`CompileExecutor`] that runs compiles on an sccache-dist cluster.
pub(crate) struct DistExecutor {
    client: Arc<dyn dist::Client>,
}

#[async_trait]
impl<T: CommandCreatorSync> CompileExecutor<T> for DistExecutor {
    fn hash_key_options(&self) -> HashKeyOptions {
        HashKeyOptions {
            may_distribute: true,
            rewrite_includes_only: self.client.rewrite_includes_only(),
        }
    }

    async fn execute(&self, request: CompileRequest<'_, T>) -> Result<CompileOutcome> {
        let CompileRequest {
            service,
            creator,
            compilation,
            cwd,
            weak_toolchain_key,
            output_name,
            hash_key_options,
        } = request;
        let mut path_transformer = dist::PathTransformer::new();
        let (local_command, dist_command, cacheable) = compilation
            .generate_compile_commands(
                &mut path_transformer,
                hash_key_options.rewrite_includes_only,
            )
            .context("Failed to generate compile commands")?;
        let local_compile = LocalCompile {
            service,
            creator,
            command: local_command,
        };
        let Some(command) = dist_command else {
            debug!("[{}]: Compiling locally", output_name);
            return Ok(CompileOutcome {
                cacheable,
                execution: DistType::NoDist,
                output: local_compile.run().await?,
            });
        };
        let dist_compile = DistCompileRequest {
            path_transformer,
            command,
            weak_toolchain_key,
            cwd,
        };
        debug!("[{}]: Attempting distributed compilation", output_name);
        let compiler_path = local_compile.executable();
        let result = self
            .run_on_cluster(
                compilation,
                dist_compile,
                compiler_path.clone(),
                &output_name,
            )
            .await
            .map_err(|error| classify_error(error, &compiler_path));
        match result {
            Ok((execution, output)) => Ok(CompileOutcome {
                cacheable,
                execution,
                output,
            }),
            Err(DistError::FailCompile(e)) => Err(e),
            Err(DistError::CompileLocally(e)) => {
                // `{:#}` prints the error and the causes in a single line.
                let errmsg = format!("{:#}", e);
                warn!(
                    "[{}]: Could not perform distributed compile, falling back to local: {}",
                    output_name, errmsg
                );
                Ok(CompileOutcome {
                    cacheable,
                    execution: DistType::Error,
                    output: local_compile.run().await?,
                })
            }
        }
    }
}

impl DistExecutor {
    pub(crate) fn new(client: Arc<dyn dist::Client>) -> Self {
        DistExecutor { client }
    }

    /// Runs `dist_compile` on the cluster and writes its outputs to their local paths on the
    /// client machine.
    async fn run_on_cluster<T: CommandCreatorSync>(
        &self,
        compilation: Box<dyn Compilation<T>>,
        dist_compile: DistCompileRequest,
        compiler_path: PathBuf,
        out_pretty: &str,
    ) -> Result<(DistType, process::Output)> {
        let DistCompileRequest {
            mut path_transformer,
            command: mut dist_compile_cmd,
            weak_toolchain_key,
            cwd,
        } = dist_compile;
        debug!("[{}]: Creating distributed compile request", out_pretty);
        let dist_output_paths = compilation
            .outputs()
            .map(|output| path_transformer.as_dist_abs(&cwd.join(output.path)))
            .collect::<Option<_>>()
            .context("Failed to adapt an output path for distributed compile")?;
        let (inputs_packager, toolchain_packager, outputs_rewriter) =
            compilation.into_dist_packagers(path_transformer)?;
        let dist_client = &self.client;

        debug!(
            "[{}]: Identifying dist toolchain for {:?}",
            out_pretty, compiler_path
        );
        let (dist_toolchain, maybe_dist_compile_executable) = dist_client
            .put_toolchain(compiler_path, weak_toolchain_key, toolchain_packager)
            .await?;
        let mut tc_archive = None;
        if let Some((dist_compile_executable, archive_path)) = maybe_dist_compile_executable {
            dist_compile_cmd.executable = dist_compile_executable;
            tc_archive = Some(archive_path);
        }

        debug!("[{}]: Requesting allocation", out_pretty);
        let jares = dist_client.do_alloc_job(dist_toolchain.clone()).await?;
        let job_alloc = match jares {
            dist::AllocJobResult::Success {
                job_alloc,
                need_toolchain: true,
            } => {
                debug!(
                    "[{}]: Sending toolchain {} for job {}",
                    out_pretty, dist_toolchain.archive_id, job_alloc.job_id
                );

                match dist_client
                    .do_submit_toolchain(job_alloc.clone(), dist_toolchain)
                    .await
                    .map_err(|e| e.context("Could not submit toolchain"))?
                {
                    dist::SubmitToolchainResult::Success => Ok(job_alloc),
                    dist::SubmitToolchainResult::JobNotFound => {
                        bail!("Job {} not found on server", job_alloc.job_id)
                    }
                    dist::SubmitToolchainResult::CannotCache => bail!(
                        "Toolchain for job {} could not be cached by server",
                        job_alloc.job_id
                    ),
                }
            }
            dist::AllocJobResult::Success {
                job_alloc,
                need_toolchain: false,
            } => Ok(job_alloc),
            dist::AllocJobResult::Fail { msg } => {
                Err(anyhow!("Failed to allocate job").context(msg))
            }
        }?;
        let job_id = job_alloc.job_id;
        let server_id = job_alloc.server_id;
        debug!("[{}]: Running job", out_pretty);
        let ((job_id, server_id), (jres, path_transformer)) = dist_client
            .do_run_job(
                job_alloc,
                dist_compile_cmd,
                dist_output_paths,
                inputs_packager,
            )
            .await
            .map(move |res| ((job_id, server_id), res))
            .with_context(|| {
                format!(
                    "could not run distributed compilation job on {:?}",
                    server_id
                )
            })?;

        let jc = match jres {
            dist::RunJobResult::Complete(jc) => jc,
            dist::RunJobResult::JobNotFound => bail!("Job {} not found on server", job_id),
        };
        debug!(
            "fetched {:?}",
            jc.outputs
                .iter()
                .map(|(p, bs)| (p, bs.lens().to_string()))
                .collect::<Vec<_>>()
        );
        let mut output_paths: Vec<PathBuf> = vec![];
        for (path, output_data) in jc.outputs {
            let len = output_data.lens().actual;
            let local_path = remove_outputs_on_error(
                &output_paths,
                path_transformer
                    .to_local(&path)
                    .with_context(|| format!("unable to transform output path {}", path)),
            )?;
            output_paths.push(local_path);
            // Do this first so cleanup works correctly
            let local_path = output_paths.last().expect("nothing in vec after push");

            let mut file = remove_outputs_on_error(
                &output_paths,
                File::create(local_path).with_context(|| {
                    format!("Failed to create output file {}", local_path.display())
                }),
            )?;
            let count = remove_outputs_on_error(
                &output_paths,
                io::copy(&mut output_data.into_reader(), &mut file)
                    .with_context(|| format!("Failed to write output to {}", local_path.display())),
            )?;

            assert!(count == len);
        }
        let mut output = jc.output;
        let extra_inputs = match tc_archive {
            Some(p) => vec![p],
            None => vec![],
        };
        remove_outputs_on_error(
            &output_paths,
            outputs_rewriter
                .handle_outputs(&path_transformer, &output_paths, &extra_inputs)
                .with_context(|| "failed to rewrite outputs from compile"),
        )?;

        if output.code != 0 {
            // Add server info to help diagnose host-specific failures, e.g. due to flaky hardware.
            // Failed builds are not cached so this tampering should not cause too much trouble.
            let server_info = format!("sccache: Job failed on server {}:\n", server_id.addr());
            output.stderr.splice(0..0, server_info.as_bytes().to_vec());
        }

        Ok((DistType::Ok(server_id), output.into()))
    }
}

/// Returns `result`, deleting `outputs` first if it's an error.
fn remove_outputs_on_error<V>(outputs: &[PathBuf], result: Result<V>) -> Result<V> {
    if result.is_err() {
        // Do our best to clear up. We may end up deleting a file that we just wrote over
        // the top of, but it's better to clear up too much than too little
        for local_path in outputs {
            if let Err(e) = fs::remove_file(local_path)
                && e.kind() != io::ErrorKind::NotFound
            {
                warn!(
                    "{} while attempting to clear up {}",
                    e,
                    local_path.display()
                );
            }
        }
    }
    result
}

/// Decides whether to fail the compile or compile locally after an sccache-dist error.
fn classify_error(error: Error, compiler_path: &Path) -> DistError {
    if let Some(HttpClientError(_)) = error.downcast_ref::<HttpClientError>() {
        DistError::FailCompile(error)
    } else if let Some(lru_disk_cache::Error::FileTooLarge) =
        error.downcast_ref::<lru_disk_cache::Error>()
    {
        DistError::FailCompile(anyhow!(
            "Could not cache dist toolchain for {:?} locally.
                 Increase `toolchain_cache_size` or decrease the toolchain archive size.",
            compiler_path
        ))
    } else {
        DistError::CompileLocally(error)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_http_client_error_fails_the_compile() {
        let e = Error::new(HttpClientError("unauthorized".to_owned()));
        // Preserve the concrete error so `SccacheService` can recognize it and reset the client.
        match classify_error(e, Path::new("/usr/bin/cc")) {
            DistError::FailCompile(e) => {
                let e = e
                    .downcast_ref::<HttpClientError>()
                    .expect("expected the HttpClientError unchanged");
                assert_eq!("unauthorized", e.0);
            }
            other => panic!("expected FailCompile, got {other:?}"),
        }
    }

    #[test]
    fn test_toolchain_too_large_for_the_cache_fails_the_compile() {
        let e = Error::new(lru_disk_cache::Error::FileTooLarge);
        match classify_error(e, Path::new("/usr/bin/cc")) {
            DistError::FailCompile(e) => {
                let message = e.to_string();
                assert!(
                    message.contains("toolchain_cache_size"),
                    "expected the toolchain_cache_size hint, got {e:#}"
                );
                assert!(
                    message.contains("/usr/bin/cc"),
                    "expected the compiler path, got {e:#}"
                );
            }
            other => panic!("expected FailCompile, got {other:?}"),
        }
    }

    #[test]
    fn test_remove_outputs_on_error() {
        let dir = tempfile::tempdir().unwrap();
        let object = dir.path().join("foo.o");
        let depfile = dir.path().join("foo.d");
        let missing = dir.path().join("missing.out");
        fs::write(&object, b"partial object").unwrap();
        fs::write(&depfile, b"partial depfile").unwrap();
        let outputs = [object.clone(), depfile.clone(), missing];

        assert_eq!(1, remove_outputs_on_error(&outputs, Ok(1)).unwrap());
        assert!(object.exists());
        assert!(depfile.exists());

        let error: Result<()> = remove_outputs_on_error(&outputs, Err(anyhow!("write failed")));
        assert_eq!("write failed", error.unwrap_err().to_string());
        assert!(!object.exists());
        assert!(!depfile.exists());
    }

    #[test]
    fn test_other_errors_compile_locally() {
        let result = classify_error(anyhow!("connection refused"), Path::new("/usr/bin/cc"));
        match result {
            DistError::CompileLocally(e) => assert_eq!("connection refused", e.to_string()),
            other => panic!("expected CompileLocally, got {other:?}"),
        }
    }
}
