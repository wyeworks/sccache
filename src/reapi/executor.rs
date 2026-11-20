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

use crate::compiler::{
    Compilation, CompileExecutor, CompileOutcome, CompileRequest, DistType, PreparedCompile,
    ReapiOutcome,
};
use crate::errors::*;
use crate::mock_command::CommandCreatorSync;
use async_trait::async_trait;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};

const SYSROOT_COPIES_DIR: &str = "reapi-sysroot-copies";

pub(crate) struct ReapiExecutor {
    sysroot_copies_dir: PathBuf,
}

impl ReapiExecutor {
    pub(crate) fn new(reapi_cache_dir: &Path) -> Self {
        Self {
            sysroot_copies_dir: reapi_cache_dir.join(SYSROOT_COPIES_DIR),
        }
    }
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
        let execution = match mapped {
            Ok(Ok(_)) => DistType::NoDist,
            Err(_) => {
                warn!(
                    "[{}]: REAPI eligibility check panicked; compiling locally",
                    request.output_name
                );
                DistType::NoDist
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
                DistType::Reapi(ReapiOutcome::CompiledLocally(
                    not_eligible.reason.to_string(),
                ))
            }
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
    use crate::reapi::{CompileLocallyReason, NotEligible, PathMapper, ReapiCompile};
    use crate::server::SccacheService;
    use crate::test::utils::{new_creator, next_command};
    use std::ffi::OsString;
    use std::process;
    use std::sync::{Arc, Mutex};

    type Creator = Arc<Mutex<MockCommandCreator>>;

    #[derive(Clone, Copy)]
    enum Eligibility {
        Eligible,
        Ineligible,
        Panics,
    }

    struct FakeCompilation(Eligibility);

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
                target_triple: "x86_64-unknown-linux-gnu".to_owned(),
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

    fn compile(eligibility: Eligibility) -> (DistType, process::Output) {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let cache_dir = tempfile::tempdir().unwrap();
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
        let executor = ReapiExecutor::new("/cache".as_ref());
        let prepared = runtime
            .block_on(CompileExecutor::<Creator>::prepare(
                &executor,
                Box::new(FakeCompilation(eligibility)),
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

    #[test]
    fn test_an_ineligible_compile_runs_locally_and_counts_why() {
        let (dist_type, output) = compile(Eligibility::Ineligible);
        assert_eq!(
            DistType::Reapi(ReapiOutcome::CompiledLocally(
                "staticlib crate type".to_owned()
            )),
            dist_type
        );
        assert_eq!(b"out".as_slice(), output.stdout);
    }

    #[test]
    fn test_an_eligible_compile_runs_locally_without_a_reason() {
        let (dist_type, output) = compile(Eligibility::Eligible);
        assert_eq!(DistType::NoDist, dist_type);
        assert_eq!(b"err".as_slice(), output.stderr);
    }

    #[test]
    fn test_a_panicking_eligibility_check_still_compiles_locally() {
        let (dist_type, output) = compile(Eligibility::Panics);
        assert_eq!(DistType::NoDist, dist_type);
        assert_eq!(b"out".as_slice(), output.stdout);
    }

    #[test]
    fn test_local_compiles_get_the_sysroot_copies_dir_under_the_reapi_cache_dir() {
        let executor = ReapiExecutor::new("/cache".as_ref());
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let changes = runtime
            .block_on(CompileExecutor::<Creator>::prepare(
                &executor,
                Box::new(FakeCompilation(Eligibility::Eligible)),
            ))
            .unwrap()
            .local_compile_changes;
        let mut expected = OsString::from("--sysroot=");
        expected.push(Path::new("/cache").join("reapi-sysroot-copies"));
        let args: Vec<_> = changes.args.into_iter().map(|a| a.arg).collect();
        assert_eq!(vec![expected], args);
    }
}
