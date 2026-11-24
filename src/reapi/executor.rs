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

//! Remote cache lookup with local compilation on a miss or an unusable result.

use super::client::{ConnectOptions, check_connect_options};
use super::connection::{Connection, ServerApis};
use super::digest::DigestCache;
use super::lookup_pause::LookupPause;
use super::mapping::{CompileLocallyReason, ReapiCompile};
use super::remote_compile::{
    ActionOptions, action_digest, digest_input_root_files, materialize, materialize_failure_reason,
};
use super::toolchains::{ToolchainFiles, Toolchains};
use crate::compiler::{
    CacheControl, Cacheable, Compilation, CompileExecutor, CompileOutcome, CompileRequest,
    DistType, PreparedCompile, ReapiOutcome,
};
use crate::config::ReapiConfig;
use crate::errors::*;
use crate::mock_command::CommandCreatorSync;
use async_trait::async_trait;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::process;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;

const SYSROOT_COPIES_DIR: &str = "reapi-sysroot-copies";
const DIGEST_CACHE_FILE: &str = "reapi-digests.json";
const MAX_READY_WAIT: Duration = Duration::from_secs(3600);

pub(crate) struct ReapiExecutor {
    connection: Option<Arc<Connection>>,
    toolchains: Arc<Toolchains>,
    digest_cache: Arc<DigestCache>,
    ready_wait: Duration,
    sysroot_copies_dir: PathBuf,
    lookup_pause: LookupPause,
    action_options: Arc<ActionOptions>,
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
        let digest_cache = Arc::new(DigestCache::load(config.cache_dir.join(DIGEST_CACHE_FILE)));
        Self {
            connection,
            toolchains: Toolchains::new(digest_cache.clone()),
            digest_cache,
            ready_wait,
            sysroot_copies_dir: config.cache_dir.join(SYSROOT_COPIES_DIR),
            lookup_pause: LookupPause::default(),
            action_options: Arc::new(ActionOptions::new(config)),
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
        if self.lookup_pause.is_paused() {
            return Err(CompileLocallyReason::ActionCacheLookupsPaused);
        }
        let deadline = Instant::now() + self.ready_wait;
        tokio::try_join!(
            connection.server_apis(deadline),
            self.toolchains.files(&compile.toolchain, deadline)
        )
    }

    async fn look_up(
        &self,
        reapi_compile: ReapiCompile,
        apis: Arc<ServerApis>,
        toolchain: ToolchainFiles,
        out_pretty: &str,
    ) -> std::result::Result<process::Output, CompileLocallyReason> {
        let digest_cache = self.digest_cache.clone();
        let action_options = self.action_options.clone();
        let digested = tokio::task::spawn_blocking(move || {
            let files = digest_input_root_files(&reapi_compile, &digest_cache)?;
            let digest = action_digest(&reapi_compile, &files, &toolchain, &action_options)?;
            Ok::<_, Error>((reapi_compile, digest))
        })
        .await;
        let (reapi_compile, action_digest) = match digested.map_err(Error::from).flatten() {
            Ok(digested) => digested,
            Err(e) => {
                warn!(
                    "[{}]: Compiling locally: failed to hash the inputs: {:#}",
                    out_pretty, e
                );
                return Err(CompileLocallyReason::HashingInputsFailed);
            }
        };
        // Reserve a probe only once hashing and connection setup have finished.
        let permit = self
            .lookup_pause
            .try_lookup()
            .ok_or(CompileLocallyReason::ActionCacheLookupsPaused)?;
        let cached = match apis.action_cache.get_action_result(&action_digest).await {
            Ok(cached) => {
                permit.succeeded();
                cached
            }
            Err(e) => {
                warn!("[{}]: Compiling locally: {:#}", out_pretty, e);
                if let Some(pause) = permit.failed() {
                    warn!(
                        "REAPI: action cache lookups are failing; compiling locally for {pause:?}"
                    );
                }
                return Err(CompileLocallyReason::ActionCacheLookupFailed);
            }
        };
        let result = match cached {
            Some(result) if result.exit_code == 0 => result,
            // Treat cached failures as misses; worker failures may be transient.
            _ => return Err(CompileLocallyReason::NotInActionCache),
        };
        match materialize(&apis.cas, &reapi_compile, &result).await {
            Ok(output) => {
                debug!(
                    "[{}]: REAPI action cache hit {}",
                    out_pretty, action_digest.hash
                );
                Ok(output)
            }
            Err(e) => {
                let reason = materialize_failure_reason(&e);
                // Avoid repeated warnings for unusable cached results.
                let log_level = match reason {
                    CompileLocallyReason::UnusableResult
                    | CompileLocallyReason::WorkerRootInOutput => log::Level::Debug,
                    _ => log::Level::Warn,
                };
                log!(
                    log_level,
                    "[{}]: Compiling locally: action cache result {}: {:#}",
                    out_pretty,
                    action_digest.hash,
                    e
                );
                Err(reason)
            }
        }
    }
}

async fn compile_locally<T: CommandCreatorSync>(
    request: CompileRequest<'_, T>,
    reason: CompileLocallyReason,
) -> Result<CompileOutcome> {
    debug!("[{}]: Compiling locally: {reason}", request.output_name);
    let mut outcome = request.execute_locally().await?;
    outcome.execution = DistType::Reapi(ReapiOutcome::CompiledLocally(reason.to_string()));
    Ok(outcome)
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
        if request.cache_control != CacheControl::Default {
            return compile_locally(request, CompileLocallyReason::CacheBypassed).await;
        }
        let compilation = request.compilation;
        let (compilation, mapped) = tokio::task::spawn_blocking(move || {
            // Preserve the compilation so an eligibility-check panic can still fall back.
            let mapped = catch_unwind(AssertUnwindSafe(|| compilation.map_for_reapi()));
            (compilation, mapped)
        })
        .await
        .context("failed to check REAPI eligibility")?;
        request.compilation = compilation;
        let looked_up = match mapped {
            Ok(Ok(_)) if request.local_compile_changes.args.is_empty() => {
                Err(CompileLocallyReason::LocalCompileUnchanged)
            }
            Ok(Ok(compile)) => match self.prepare_lookup(&compile).await {
                Ok((apis, toolchain)) => {
                    self.look_up(compile, apis, toolchain, &request.output_name)
                        .await
                }
                Err(reason) => Err(reason),
            },
            Err(_) => {
                warn!(
                    "[{}]: REAPI eligibility check panicked; compiling locally",
                    request.output_name
                );
                Err(CompileLocallyReason::MappingPanicked)
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
                Err(not_eligible.reason)
            }
        };
        match looked_up {
            Ok(output) => Ok(CompileOutcome {
                cacheable: Cacheable::Yes,
                execution: DistType::Reapi(ReapiOutcome::ActionCacheHit),
                output,
            }),
            Err(reason) => compile_locally(request, reason).await,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::compiler::{
        CCompileCommand, CacheControl, Cacheable, CompileCommand, LocalArg, LocalCompileChanges,
        SingleCompileCommand,
    };
    use crate::dist;
    use crate::mock_command::{MockChild, MockCommandCreator, exit_status};
    use crate::reapi::lookup_pause::FAILURES_TO_PAUSE;
    use crate::reapi::proto::build::bazel::remote::execution::v2 as remexec;
    use crate::reapi::remote_compile::test::{fake_sysroot, inline_output, worker_result};
    use crate::reapi::test::FakeServer;
    use crate::reapi::{PathMapper, ToolchainKey};
    use crate::server::SccacheService;
    use crate::test::utils::{new_creator, next_command};
    use std::ffi::OsString;
    use std::path::Path;
    use std::sync::Mutex;
    use test_case::test_case;

    type Creator = Arc<Mutex<MockCommandCreator>>;

    const TARGET_TRIPLE: &str = "x86_64-unknown-linux-gnu";
    const RLIB: &str = "target/debug/deps/libfoo.rlib";

    #[derive(Clone, Copy)]
    enum Eligibility {
        Eligible,
        Ineligible,
        Panics,
    }

    /// A compile of `dir/ws/src/lib.rs` into `dir/ws/target/debug/deps/libfoo.rlib` with the
    /// toolchain at `dir/sysroot`. Its local compile gets `--sysroot=<sysroot_copies_dir>`.
    struct FakeCompilation {
        eligibility: Eligibility,
        dir: PathBuf,
    }

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

        fn map_for_reapi(&self) -> std::result::Result<ReapiCompile, crate::reapi::NotEligible> {
            match self.eligibility {
                Eligibility::Eligible => {}
                Eligibility::Ineligible => return Err(CompileLocallyReason::Staticlib.into()),
                Eligibility::Panics => panic!("map_for_reapi"),
            }
            let ws = self.dir.join("ws");
            Ok(ReapiCompile {
                path_mapper: PathMapper::new(ws.clone(), ws.join("target")),
                arguments: vec![],
                mapped_crate_root: None,
                toolchain: ToolchainKey::new(
                    "abc123".to_owned(),
                    self.dir.join("sysroot"),
                    TARGET_TRIPLE.to_owned(),
                ),
                env: Default::default(),
                input_root_files: vec![ws.join("src/lib.rs")],
                outputs: vec![ws.join(RLIB)],
            })
        }

        fn reapi_local_compile_changes(
            &self,
            sysroot_copies_dir: &Path,
        ) -> Option<LocalCompileChanges> {
            let mut arg = OsString::from("--sysroot=");
            arg.push(sysroot_copies_dir);
            Some(LocalCompileChanges {
                extra_hash_key: vec![],
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
            salt: String::new(),
            platform: Default::default(),
        }
    }

    /// An executor that waits up to 10s for a fake server, and a temp dir holding the
    /// toolchain and `ws/src/lib.rs`.
    struct Fixture {
        runtime: tokio::runtime::Runtime,
        server: Arc<FakeServer>,
        dir: tempfile::TempDir,
        config: ReapiConfig,
        eligibility: Eligibility,
        cache_control: CacheControl,
        local_compile_changed: bool,
    }

    impl Fixture {
        fn new(eligibility: Eligibility) -> Self {
            Self::with_runtime(eligibility, tokio::runtime::Runtime::new().unwrap())
        }

        fn clock_controlled() -> Self {
            Self::with_runtime(
                Eligibility::Eligible,
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap(),
            )
        }

        fn with_runtime(eligibility: Eligibility, runtime: tokio::runtime::Runtime) -> Self {
            let server = Arc::new(FakeServer::default());
            let mut config = config(runtime.block_on(server.serve()), 10);
            let dir = tempfile::tempdir().unwrap();
            fake_sysroot(dir.path());
            config.cache_dir = dir.path().join("reapi-cache");
            let lib_rs = dir.path().join("ws/src/lib.rs");
            std::fs::create_dir_all(lib_rs.parent().unwrap()).unwrap();
            std::fs::write(&lib_rs, "pub fn f() {}").unwrap();
            // Cargo creates the output directory before running rustc.
            std::fs::create_dir_all(dir.path().join("ws/target/debug/deps")).unwrap();
            Fixture {
                runtime,
                server,
                dir,
                config,
                eligibility,
                cache_control: CacheControl::Default,
                local_compile_changed: true,
            }
        }

        fn compilation(&self) -> FakeCompilation {
            FakeCompilation {
                eligibility: self.eligibility,
                dir: self.dir.path().to_owned(),
            }
        }

        /// Puts a successful result that writes an rlib holding `rlib`, changed by `change`, in
        /// the fake server's action cache.
        fn put_result_in_action_cache(&self, change: fn(&mut remexec::ActionResult)) {
            let compile = self.compilation().map_for_reapi().unwrap();
            let digest_cache = DigestCache::load(self.dir.path().join("digests.json"));
            let files = digest_input_root_files(&compile, &digest_cache).unwrap();
            let toolchain = crate::reapi::remote_compile::toolchain_files(
                &self.dir.path().join("sysroot"),
                TARGET_TRIPLE,
                &digest_cache,
            )
            .unwrap();
            let action_digest = action_digest(
                &compile,
                &files,
                &toolchain,
                &ActionOptions::new(&self.config),
            )
            .unwrap();
            let rlib_path = compile
                .path_mapper
                .to_input_root(&compile.outputs[0])
                .unwrap();
            let mut result = worker_result(vec![inline_output(&rlib_path, b"rlib")]);
            change(&mut result);
            self.server.insert_action_result(&action_digest, result);
        }

        /// Runs the compile through the executor. A local compile writes `out` to stdout and
        /// `err` to stderr.
        fn compile(&self) -> (DistType, process::Output) {
            self.compile_with(&ReapiExecutor::new(&self.config))
        }

        fn advance_time(&self, duration: Duration) {
            self.runtime.block_on(async {
                tokio::time::pause();
                tokio::time::advance(duration).await;
                tokio::time::resume();
            });
        }

        fn compile_with(&self, executor: &ReapiExecutor) -> (DistType, process::Output) {
            let storage = Arc::new(crate::cache::disk::DiskCache::new(
                self.dir.path(),
                0,
                self.runtime.handle(),
                Default::default(),
                crate::cache::CacheMode::ReadWrite,
                vec![],
            ));
            let service = SccacheService::mock_with_storage(storage, self.runtime.handle().clone());
            let creator = new_creator();
            next_command(&creator, Ok(MockChild::new(exit_status(0), "out", "err")));
            let mut prepared = self
                .runtime
                .block_on(CompileExecutor::<Creator>::prepare(
                    executor,
                    Box::new(self.compilation()),
                ))
                .unwrap();
            if !self.local_compile_changed {
                prepared.local_compile_changes.args.clear();
            }
            let request = CompileRequest {
                service: &service,
                creator: &creator,
                compilation: prepared.compilation,
                cwd: self.dir.path().join("ws"),
                weak_toolchain_key: String::new(),
                output_name: "lib.rs".into(),
                hash_key_options: Default::default(),
                cache_control: self.cache_control,
                local_compile_changes: prepared.local_compile_changes,
            };
            let outcome = self.runtime.block_on(executor.execute(request)).unwrap();
            if outcome.execution == DistType::Reapi(ReapiOutcome::ActionCacheHit) {
                assert_eq!(
                    creator.lock().unwrap().children.len(),
                    1,
                    "a cache hit ran the compiler"
                );
            }
            (outcome.execution, outcome.output)
        }
    }

    /// Compiles with the config changed by `configure`, which gets the fixture's temp dir.
    fn compile(
        eligibility: Eligibility,
        configure: impl FnOnce(&mut ReapiConfig, &Path),
    ) -> (DistType, process::Output) {
        let mut fixture = Fixture::new(eligibility);
        configure(&mut fixture.config, fixture.dir.path());
        fixture.compile()
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
    fn test_a_hit_writes_its_outputs() {
        let fixture = Fixture::new(Eligibility::Eligible);
        fixture.put_result_in_action_cache(|_| {});
        let (dist_type, output) = fixture.compile();
        assert_eq!(DistType::Reapi(ReapiOutcome::ActionCacheHit), dist_type);
        assert!(output.status.success());
        let ws = fixture.dir.path().join("ws");
        assert_eq!(b"rlib".as_slice(), std::fs::read(ws.join(RLIB)).unwrap());
        let expected_stderr = format!("warning: in {}/src/lib.rs\n", ws.display());
        assert_eq!(expected_stderr.as_bytes(), output.stderr);
    }

    #[cfg(unix)]
    #[test]
    fn test_a_second_checkout_uses_the_same_action_cache_entry() {
        let first = Fixture::new(Eligibility::Eligible);
        first.put_result_in_action_cache(|_| {});
        let mut second = Fixture::new(Eligibility::Eligible);
        second.config.endpoint = first.config.endpoint.clone();
        // Install identical toolchain contents under a different local path.
        std::fs::copy(
            first.dir.path().join("sysroot/bin/rustc"),
            second.dir.path().join("sysroot/bin/rustc"),
        )
        .unwrap();
        assert_eq!(
            second.compile().0,
            DistType::Reapi(ReapiOutcome::ActionCacheHit)
        );
        assert_eq!(
            std::fs::read(second.dir.path().join("ws").join(RLIB)).unwrap(),
            b"rlib"
        );
        assert_eq!(first.server.lookup_requests.lock().unwrap().len(), 1);
    }

    #[test]
    fn test_input_hashing_failure_skips_the_remote_lookup() {
        let fixture = Fixture::new(Eligibility::Eligible);
        std::fs::remove_file(fixture.dir.path().join("ws/src/lib.rs")).unwrap();
        assert_eq!(
            fixture.compile().0,
            compiled_locally("failed to hash the inputs")
        );
        assert!(fixture.server.lookup_requests.lock().unwrap().is_empty());
    }

    #[test]
    fn test_action_cache_keys_include_salt_and_platform() {
        let mut fixture = Fixture::new(Eligibility::Eligible);
        fixture.config.salt = "v1".into();
        fixture
            .config
            .platform
            .insert("OSFamily".into(), "linux".into());
        fixture.put_result_in_action_cache(|_| {});
        assert_eq!(
            fixture.compile().0,
            DistType::Reapi(ReapiOutcome::ActionCacheHit)
        );

        fixture.config.salt = "v2".into();
        assert_eq!(
            fixture.compile().0,
            compiled_locally("not in the action cache")
        );

        fixture.config.salt = "v1".into();
        fixture
            .config
            .platform
            .insert("OSFamily".into(), "other".into());
        assert_eq!(
            fixture.compile().0,
            compiled_locally("not in the action cache")
        );
    }

    #[test]
    fn test_a_miss_compiles_locally() {
        let (dist_type, output) = compile(Eligibility::Eligible, |_, _| {});
        assert_eq!(compiled_locally("not in the action cache"), dist_type);
        assert_eq!(b"err".as_slice(), output.stderr);
    }

    #[test]
    fn test_a_failed_lookup_compiles_locally() {
        let fixture = Fixture::new(Eligibility::Eligible);
        *fixture.server.lookup_error.lock().unwrap() = Some(tonic::Code::Unavailable);
        let (dist_type, output) = fixture.compile();
        assert_eq!(compiled_locally("action cache lookup failed"), dist_type);
        assert_eq!(b"out".as_slice(), output.stdout);
    }

    #[test]
    fn test_compiles_resume_after_a_cooldown_and_reset_the_backoff() {
        let fixture = Fixture::clock_controlled();
        fixture.put_result_in_action_cache(|_| {});
        *fixture.server.lookup_error.lock().unwrap() = Some(tonic::Code::Unavailable);
        let executor = ReapiExecutor::new(&fixture.config);
        for _ in 0..FAILURES_TO_PAUSE {
            assert_eq!(
                compiled_locally("action cache lookup failed"),
                fixture.compile_with(&executor).0
            );
        }
        *fixture.server.lookup_error.lock().unwrap() = None;
        let (execution, output) = fixture.compile_with(&executor);
        assert_eq!(
            compiled_locally("action cache lookups paused after failures"),
            execution
        );
        assert_eq!(output.stdout, b"out");
        assert_eq!(fixture.server.lookup_requests.lock().unwrap().len(), 3);
        fixture.advance_time(Duration::from_secs(5));
        assert_eq!(
            DistType::Reapi(ReapiOutcome::ActionCacheHit),
            fixture.compile_with(&executor).0
        );
        assert_eq!(fixture.server.lookup_requests.lock().unwrap().len(), 4);

        *fixture.server.lookup_error.lock().unwrap() = Some(tonic::Code::Unavailable);
        for _ in 0..FAILURES_TO_PAUSE {
            assert_eq!(
                compiled_locally("action cache lookup failed"),
                fixture.compile_with(&executor).0
            );
        }
        *fixture.server.lookup_error.lock().unwrap() = None;
        fixture.server.action_results.lock().unwrap().clear();
        fixture.advance_time(Duration::from_secs(5));
        assert_eq!(
            compiled_locally("not in the action cache"),
            fixture.compile_with(&executor).0
        );
        assert_eq!(fixture.server.lookup_requests.lock().unwrap().len(), 8);
    }

    #[test]
    fn test_cache_misses_reset_consecutive_rpc_failures() {
        let fixture = Fixture::new(Eligibility::Eligible);
        let executor = ReapiExecutor::new(&fixture.config);
        *fixture.server.lookup_error.lock().unwrap() = Some(tonic::Code::Unavailable);
        for _ in 0..FAILURES_TO_PAUSE - 1 {
            assert_eq!(
                compiled_locally("action cache lookup failed"),
                fixture.compile_with(&executor).0
            );
        }
        *fixture.server.lookup_error.lock().unwrap() = None;
        assert_eq!(
            compiled_locally("not in the action cache"),
            fixture.compile_with(&executor).0
        );
        *fixture.server.lookup_error.lock().unwrap() = Some(tonic::Code::Unavailable);
        for _ in 0..FAILURES_TO_PAUSE {
            assert_eq!(
                compiled_locally("action cache lookup failed"),
                fixture.compile_with(&executor).0
            );
        }
        assert_eq!(
            compiled_locally("action cache lookups paused after failures"),
            fixture.compile_with(&executor).0
        );
        assert_eq!(fixture.server.lookup_requests.lock().unwrap().len(), 6);
    }

    #[test]
    fn test_input_hashing_failures_do_not_reserve_the_recovery_probe() {
        let fixture = Fixture::clock_controlled();
        fixture.put_result_in_action_cache(|_| {});
        let executor = ReapiExecutor::new(&fixture.config);
        *fixture.server.lookup_error.lock().unwrap() = Some(tonic::Code::Unavailable);
        for _ in 0..FAILURES_TO_PAUSE {
            fixture.compile_with(&executor);
        }
        let input = fixture.dir.path().join("ws/src/lib.rs");
        std::fs::remove_file(&input).unwrap();
        assert_eq!(
            compiled_locally("action cache lookups paused after failures"),
            fixture.compile_with(&executor).0
        );
        fixture.advance_time(Duration::from_secs(5));
        assert_eq!(
            compiled_locally("failed to hash the inputs"),
            fixture.compile_with(&executor).0
        );
        std::fs::write(input, "pub fn f() {}").unwrap();
        *fixture.server.lookup_error.lock().unwrap() = None;
        assert_eq!(
            DistType::Reapi(ReapiOutcome::ActionCacheHit),
            fixture.compile_with(&executor).0
        );
        assert_eq!(fixture.server.lookup_requests.lock().unwrap().len(), 4);
    }

    #[test_case(|result| result.exit_code = 1, "not in the action cache" ; "cached compiler failure")]
    #[test_case(|result| result.stderr_raw.clear(), "unusable action cache result" ; "invalid metadata")]
    #[test_case(|result| result.output_files[0].contents.clear(), "failed to download the outputs" ; "missing blob")]
    fn test_successful_rpcs_do_not_pause_lookups_when_results_are_unusable(
        change: fn(&mut remexec::ActionResult),
        reason: &str,
    ) {
        let fixture = Fixture::new(Eligibility::Eligible);
        fixture.put_result_in_action_cache(change);
        let executor = ReapiExecutor::new(&fixture.config);
        for _ in 0..=FAILURES_TO_PAUSE {
            let (execution, output) = fixture.compile_with(&executor);
            assert_eq!(compiled_locally(reason), execution);
            assert_eq!(output.stdout, b"out");
        }
        assert_eq!(fixture.server.lookup_requests.lock().unwrap().len(), 4);
    }

    #[test_case::test_case(
        |result| result.exit_code = 1,
        "not in the action cache" ;
        "failed result"
    )]
    #[test_case::test_case(
        |result| result.stderr_raw.clear(),
        "unusable action cache result" ;
        "result without the worker root line"
    )]
    #[test_case::test_case(
        |result| {
            let path = result.output_files[0].path.clone();
            result.output_files[0] = inline_output(&path, b"built in /w/1");
        },
        "worker root in an output" ;
        "worker root in the rlib"
    )]
    #[test_case::test_case(
        // Without inline contents, the client downloads the rlib from the CAS, which lacks it.
        |result| result.output_files[0].contents.clear(),
        "failed to download the outputs" ;
        "rlib missing from the cas"
    )]
    fn test_a_result_that_cant_be_used_compiles_locally(
        change: fn(&mut remexec::ActionResult),
        reason: &str,
    ) {
        let fixture = Fixture::new(Eligibility::Eligible);
        fixture.put_result_in_action_cache(change);
        let (dist_type, output) = fixture.compile();
        assert_eq!(compiled_locally(reason), dist_type);
        assert_eq!(b"out".as_slice(), output.stdout);
    }

    #[test]
    fn test_a_hit_whose_outputs_cant_be_written_compiles_locally() {
        let fixture = Fixture::new(Eligibility::Eligible);
        fixture.put_result_in_action_cache(|_| {});
        std::fs::remove_dir_all(fixture.dir.path().join("ws/target")).unwrap();
        let (dist_type, _) = fixture.compile();
        assert_eq!(compiled_locally("failed to write the outputs"), dist_type);
    }

    #[test_case::test_case(CacheControl::ForceRecache ; "recache")]
    #[test_case::test_case(CacheControl::ForceNoCache ; "no cache")]
    fn test_a_compile_that_bypasses_the_cache_skips_the_lookup(cache_control: CacheControl) {
        let mut fixture = Fixture::new(Eligibility::Eligible);
        fixture.put_result_in_action_cache(|_| {});
        fixture.cache_control = cache_control;
        let (dist_type, _) = fixture.compile();
        assert_eq!(
            compiled_locally("SCCACHE_RECACHE or SCCACHE_NO_CACHE set"),
            dist_type
        );
        assert!(fixture.server.lookup_requests.lock().unwrap().is_empty());
        assert!(fixture.server.read_requests.lock().unwrap().is_empty());
        assert_eq!(
            fixture
                .server
                .capabilities_calls
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    #[test]
    fn test_an_unchanged_local_compile_skips_the_lookup() {
        let mut fixture = Fixture::new(Eligibility::Eligible);
        fixture.put_result_in_action_cache(|_| {});
        fixture.local_compile_changed = false;
        let (dist_type, _) = fixture.compile();
        assert_eq!(
            compiled_locally("local compile without the worker's arguments"),
            dist_type
        );
        assert!(fixture.server.lookup_requests.lock().unwrap().is_empty());
    }

    #[test]
    fn test_an_eligible_compile_with_a_toolchain_without_std_runs_locally() {
        let (dist_type, _) = compile(Eligibility::Eligible, |_, dir| {
            std::fs::remove_dir_all(dir.join("sysroot/lib/rustlib")).unwrap();
        });
        assert_eq!(compiled_locally("missing rustc or std"), dist_type);
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

    #[test_case::test_case(
        |config, _| config.endpoint = "farm:8980".to_owned() ;
        "bad endpoint"
    )]
    #[test_case::test_case(
        |config, dir| config.auth_token_file = Some(dir.join("missing")) ;
        "unreadable token file"
    )]
    #[test_case::test_case(
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
                Box::new(FakeCompilation {
                    eligibility: Eligibility::Eligible,
                    dir: "/".into(),
                }),
            ))
            .unwrap()
            .local_compile_changes;
        let mut expected = OsString::from("--sysroot=");
        expected.push(Path::new("/cache").join("reapi-sysroot-copies"));
        let args: Vec<_> = changes.args.into_iter().map(|a| a.arg).collect();
        assert_eq!(vec![expected], args);
    }
}
