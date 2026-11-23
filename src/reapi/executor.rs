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

//! Local execution and eligibility reporting for configured REAPI builds.

use super::client::{ConnectOptions, check_connect_options};
use super::connection::{Connection, ServerApis};
use super::digest::DigestCache;
use super::mapping::{CompileLocallyReason, ReapiCompile};
use super::toolchains::{ToolchainFiles, Toolchains};
use crate::compiler::{
    Compilation, CompileExecutor, CompileOutcome, CompileRequest, DistType, PreparedCompile,
    ReapiOutcome,
};
use crate::config::ReapiConfig;
use crate::errors::*;
use crate::mock_command::CommandCreatorSync;
use async_trait::async_trait;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;

const SYSROOT_COPIES_DIR: &str = "reapi-sysroot-copies";
const DIGEST_CACHE_FILE: &str = "reapi-digests.json";
const MAX_READY_WAIT: Duration = Duration::from_secs(3600);

pub(crate) struct ReapiExecutor {
    connection: Option<Arc<Connection>>,
    toolchains: Arc<Toolchains>,
    ready_wait: Duration,
    sysroot_copies_dir: PathBuf,
}

impl ReapiExecutor {
    /// Credentials are read once; changes require a server restart.
    pub(crate) fn new(config: &ReapiConfig) -> Self {
        let connection = match read_connect_options(config) {
            Ok(options) => Some(Connection::new(options)),
            Err(error) => {
                warn!("REAPI: {error:#}; compiling locally");
                None
            }
        };
        let ready_wait = Duration::from_secs(config.ready_wait_secs).min(MAX_READY_WAIT);
        if config.ready_wait_secs > MAX_READY_WAIT.as_secs() {
            warn!(
                "REAPI: ready_wait_secs is capped at {}",
                MAX_READY_WAIT.as_secs()
            );
        }
        Self {
            connection,
            toolchains: Toolchains::new(DigestCache::load(
                config.cache_dir.join(DIGEST_CACHE_FILE),
            )),
            ready_wait,
            sysroot_copies_dir: config.cache_dir.join(SYSROOT_COPIES_DIR),
        }
    }

    async fn prepare_lookup(
        &self,
        compile: &ReapiCompile,
    ) -> std::result::Result<(Arc<ServerApis>, ToolchainFiles), CompileLocallyReason> {
        let connection = self
            .connection
            .as_ref()
            .ok_or(CompileLocallyReason::Misconfigured)?;
        let deadline = Instant::now() + self.ready_wait;
        tokio::try_join!(
            connection.server_apis(deadline),
            self.toolchains.files(&compile.toolchain, deadline)
        )
    }
}

fn read_connect_options(config: &ReapiConfig) -> Result<ConnectOptions> {
    let auth_token = config
        .auth_token_file
        .as_ref()
        .map(|file| {
            std::fs::read_to_string(file).with_context(|| {
                format!(
                    "failed to read the REAPI auth token from {}",
                    file.display()
                )
            })
        })
        .transpose()?;
    let options = ConnectOptions {
        endpoint: config.endpoint.clone(),
        instance_name: config.instance_name.clone(),
        auth_token,
    };
    check_connect_options(&options)?;
    Ok(options)
}

#[async_trait]
impl<T: CommandCreatorSync> CompileExecutor<T> for ReapiExecutor {
    async fn prepare(&self, compilation: Box<dyn Compilation<T>>) -> Result<PreparedCompile<T>> {
        let sysroot_copies_dir = self.sysroot_copies_dir.clone();
        tokio::task::spawn_blocking(move || {
            let local_compile_changes = compilation
                .reapi_local_compile_changes(&sysroot_copies_dir)
                .unwrap_or_default();
            PreparedCompile {
                compilation,
                local_compile_changes,
            }
        })
        .await
        .context("failed to prepare local compilation for REAPI")
    }

    async fn execute(&self, mut request: CompileRequest<'_, T>) -> Result<CompileOutcome> {
        let compilation = request.compilation;
        let (compilation, mapped) = tokio::task::spawn_blocking(move || {
            // Preserve the compilation so an eligibility-check panic can still fall back.
            let mapped = catch_unwind(AssertUnwindSafe(|| compilation.map_for_reapi()));
            (compilation, mapped)
        })
        .await
        .context("failed to check REAPI eligibility")?;
        request.compilation = compilation;
        let reason = match mapped {
            Ok(Ok(compile)) => self.prepare_lookup(&compile).await.err(),
            Err(_) => {
                warn!(
                    "[{}]: REAPI eligibility check panicked; compiling locally",
                    request.output_name
                );
                Some(CompileLocallyReason::MappingPanicked)
            }
            Ok(Err(not_eligible)) => {
                match &not_eligible.detail {
                    Some(detail) => debug!(
                        "[{}]: Compiling locally: {}: {detail:#}",
                        request.output_name, not_eligible.reason
                    ),
                    None => debug!(
                        "[{}]: Compiling locally: {}",
                        request.output_name, not_eligible.reason
                    ),
                }
                Some(not_eligible.reason)
            }
        };
        let execution = match reason {
            Some(reason) => {
                debug!("[{}]: Compiling locally: {reason}", request.output_name);
                DistType::Reapi(ReapiOutcome::CompiledLocally(reason.to_string()))
            }
            None => DistType::NoDist,
        };
        let mut outcome = request.execute_locally().await?;
        outcome.execution = execution;
        Ok(outcome)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::compiler::{
        CCompileCommand, Cacheable, CompileCommand, LocalArg, LocalCompileChanges,
        SingleCompileCommand,
    };
    use crate::dist;
    use crate::mock_command::{MockChild, MockCommandCreator, exit_status};
    use crate::reapi::remote_compile::test::fake_sysroot;
    use crate::reapi::test::FakeServer;
    use crate::reapi::{CompileLocallyReason, NotEligible, PathMapper, ReapiCompile, ToolchainKey};
    use crate::server::SccacheService;
    use crate::test::utils::{new_creator, next_command};
    use std::ffi::OsString;
    use std::path::Path;
    use std::process;
    use std::sync::{Arc, Mutex};
    use test_case::test_case;

    type Creator = Arc<Mutex<MockCommandCreator>>;

    #[derive(Clone, Copy)]
    enum Eligibility {
        Eligible,
        Ineligible,
        Panics,
    }

    struct FakeCompilation(Eligibility, PathBuf);

    impl Compilation<Creator> for FakeCompilation {
        fn generate_compile_commands(
            &self,
            _: &mut dist::PathTransformer,
            _: bool,
        ) -> Result<(
            Box<dyn CompileCommand<Creator>>,
            Option<dist::CompileCommand>,
            Cacheable,
        )> {
            Ok((
                CCompileCommand::new(SingleCompileCommand {
                    executable: "rustc".into(),
                    arguments: vec![],
                    env_vars: vec![],
                    cwd: ".".into(),
                    share_jobserver: false,
                }),
                None,
                Cacheable::Yes,
            ))
        }

        fn map_for_reapi(&self) -> std::result::Result<ReapiCompile, NotEligible> {
            match self.0 {
                Eligibility::Eligible => {}
                Eligibility::Ineligible => return Err(CompileLocallyReason::Staticlib.into()),
                Eligibility::Panics => panic!("map_for_reapi"),
            }
            Ok(ReapiCompile {
                path_mapper: PathMapper::new("/src".into(), "/src/target".into()),
                arguments: vec![],
                mapped_crate_root: None,
                toolchain: ToolchainKey::new(
                    "abc123".into(),
                    self.1.clone(),
                    "x86_64-unknown-linux-gnu".into(),
                ),
                env: Default::default(),
                input_root_files: vec![],
                outputs: vec![],
            })
        }

        fn reapi_local_compile_changes(
            &self,
            sysroot_copies_dir: &Path,
        ) -> Option<LocalCompileChanges> {
            let mut arg = OsString::from("--sysroot=");
            arg.push(sysroot_copies_dir);
            Some(LocalCompileChanges {
                args: vec![LocalArg {
                    hashed_as: arg.clone(),
                    arg,
                }],
                stdout_stderr_mapper: None,
            })
        }

        #[cfg(feature = "dist-client")]
        fn into_dist_packagers(
            self: Box<Self>,
            _: dist::PathTransformer,
        ) -> Result<crate::compiler::DistPackagers> {
            unimplemented!()
        }

        fn outputs<'a>(&'a self) -> Box<dyn Iterator<Item = crate::cache::FileObjectSource> + 'a> {
            Box::new(std::iter::empty())
        }
    }

    fn config(endpoint: String, ready_wait_secs: u64) -> ReapiConfig {
        ReapiConfig {
            endpoint,
            cache_dir: "/cache".into(),
            instance_name: String::new(),
            auth_token_file: None,
            ready_wait_secs,
        }
    }

    fn compile(
        eligibility: Eligibility,
        configure: impl FnOnce(&mut ReapiConfig, &Path),
    ) -> (DistType, process::Output) {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let server = Arc::new(FakeServer::default());
        let mut config = config(runtime.block_on(server.serve()), 10);
        let cache_dir = tempfile::tempdir().unwrap();
        config.cache_dir = cache_dir.path().join("reapi");
        let sysroot = fake_sysroot(cache_dir.path());
        configure(&mut config, cache_dir.path());
        let storage = Arc::new(crate::cache::disk::DiskCache::new(
            cache_dir.path(),
            0,
            runtime.handle(),
            Default::default(),
            crate::cache::CacheMode::ReadWrite,
            vec![],
        ));
        let service = SccacheService::mock_with_storage(storage, runtime.handle().clone());
        let creator = new_creator();
        next_command(&creator, Ok(MockChild::new(exit_status(0), "out", "err")));
        let executor = ReapiExecutor::new(&config);
        let prepared = runtime
            .block_on(CompileExecutor::<Creator>::prepare(
                &executor,
                Box::new(FakeCompilation(eligibility, sysroot)),
            ))
            .unwrap();
        let request = CompileRequest {
            service: &service,
            creator: &creator,
            compilation: prepared.compilation,
            cwd: ".".into(),
            weak_toolchain_key: String::new(),
            output_name: "lib.rs".into(),
            hash_key_options: Default::default(),
            local_compile_changes: prepared.local_compile_changes,
        };
        let outcome = runtime.block_on(executor.execute(request)).unwrap();
        (outcome.execution, outcome.output)
    }

    fn compiled_locally(reason: &str) -> DistType {
        DistType::Reapi(ReapiOutcome::CompiledLocally(reason.to_owned()))
    }

    #[test]
    fn test_an_ineligible_compile_runs_locally_and_counts_why() {
        let (dist_type, output) = compile(Eligibility::Ineligible, |_, _| {});
        assert_eq!(compiled_locally("staticlib crate type"), dist_type);
        assert_eq!(b"out".as_slice(), output.stdout);
    }

    #[test]
    fn test_an_eligible_compile_runs_locally_without_a_reason_once_connected() {
        let (dist_type, output) = compile(Eligibility::Eligible, |_, _| {});
        assert_eq!(DistType::NoDist, dist_type);
        assert_eq!(b"err".as_slice(), output.stderr);
    }

    #[test]
    fn test_an_eligible_compile_that_doesnt_wait_finds_the_server_connecting() {
        let (dist_type, _) = compile(Eligibility::Eligible, |config, _| {
            config.ready_wait_secs = 0;
        });
        assert!(
            matches!(dist_type, DistType::Reapi(ReapiOutcome::CompiledLocally(ref reason))
            if reason == "connecting to the REAPI server" || reason == "hashing the toolchain")
        );
    }

    #[test_case(
        |config, _| config.endpoint = "farm:8980".to_owned() ;
        "bad endpoint"
    )]
    #[test_case(
        |config, dir| config.auth_token_file = Some(dir.join("missing")) ;
        "unreadable token file"
    )]
    #[test_case(
        |config, dir| {
            std::fs::write(dir.join("token"), " \n").unwrap();
            config.auth_token_file = Some(dir.join("token"));
        } ;
        "empty token file"
    )]
    fn test_a_misconfigured_executor_compiles_eligible_compiles_locally(
        configure: fn(&mut ReapiConfig, &Path),
    ) {
        let (dist_type, output) = compile(Eligibility::Eligible, configure);
        assert_eq!(compiled_locally("[reapi] misconfigured"), dist_type);
        assert_eq!(b"out".as_slice(), output.stdout);
        let (dist_type, _) = compile(Eligibility::Ineligible, configure);
        assert_eq!(compiled_locally("staticlib crate type"), dist_type);
    }

    #[test]
    fn test_a_panicking_mapping_still_compiles_locally() {
        let (dist_type, output) = compile(Eligibility::Panics, |_, _| {});
        assert_eq!(
            compiled_locally("mapping the compile for REAPI panicked"),
            dist_type
        );
        assert_eq!(b"out".as_slice(), output.stdout);
    }

    #[test_case("bin/rustc" ; "missing compiler")]
    #[test_case("lib/rustlib/x86_64-unknown-linux-gnu/lib" ; "missing standard library")]
    fn test_missing_toolchain_files_keep_compiles_local(path: &str) {
        let (execution, output) = compile(Eligibility::Eligible, |_, dir| {
            let path = dir.join("sysroot").join(path);
            if path.is_dir() {
                std::fs::remove_dir_all(path).unwrap();
            } else {
                std::fs::remove_file(path).unwrap();
            }
        });
        assert_eq!(compiled_locally("missing rustc or std"), execution);
        assert!(output.status.success());
    }

    #[test]
    fn test_ready_wait_is_capped() {
        let executor = ReapiExecutor::new(&config("grpc://127.0.0.1:1".into(), u64::MAX));
        assert_eq!(executor.ready_wait, MAX_READY_WAIT);
    }

    #[test]
    fn test_invalid_token_file_contents_are_not_in_errors() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = config("grpc://127.0.0.1:1".into(), 0);
        let token_file = dir.path().join("token");
        std::fs::write(&token_file, "secret\nvalue").unwrap();
        config.auth_token_file = Some(token_file);
        let error = read_connect_options(&config).err().unwrap();
        assert!(!format!("{error:#}").contains("secret"));
    }

    #[test]
    fn test_unreachable_server_keeps_the_compile_local() {
        let (dist_type, output) = compile(Eligibility::Eligible, |config, _| {
            config.endpoint = "grpc://127.0.0.1:1".into();
        });
        assert_eq!(
            compiled_locally("failed to connect to the REAPI server"),
            dist_type
        );
        assert!(output.status.success());
    }

    #[test]
    fn test_local_compiles_get_the_sysroot_copies_dir_under_the_reapi_cache_dir() {
        let executor = ReapiExecutor::new(&config("grpc://127.0.0.1:1".into(), 0));
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let changes = runtime
            .block_on(CompileExecutor::<Creator>::prepare(
                &executor,
                Box::new(FakeCompilation(Eligibility::Eligible, "/toolchain".into())),
            ))
            .unwrap()
            .local_compile_changes;
        let mut expected = OsString::from("--sysroot=");
        expected.push(Path::new("/cache").join("reapi-sysroot-copies"));
        let args: Vec<_> = changes.args.into_iter().map(|a| a.arg).collect();
        assert_eq!(vec![expected], args);
    }
}
