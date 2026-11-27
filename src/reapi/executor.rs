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

//! Remote cache lookup and execution with local fallback.

use super::auth_token::{self, AuthToken};
use super::client::{
    ConnectOptions, check_connect_options, credential_helper_server_uri, rpc_code,
};
use super::connection::{Connection, ServerApis};
use super::credential_helper::{self, CredentialHelper};
use super::digest::DigestCache;
use super::execution::{Execution, MissingActionBlobs, QueuedTooLong};
use super::lookup_pause::LookupPause;
use super::mapping::{CompileLocallyReason, ReapiCompile, ToolchainKey};
use super::remote_compile::{
    ActionOptions, action_blobs, digest_input_root_files, materialize, materialize_failure_reason,
};
use super::toolchains::{ToolchainFiles, Toolchains};
use super::worker_toolchains::WorkerToolchains;
use crate::compiler::{
    CacheControl, Cacheable, Compilation, CompileExecutor, CompileOutcome, CompileRequest,
    DistType, PreparedCompile, ReapiOutcome,
};
use crate::config::{DistToolchainConfig, ReapiConfig, ReapiOnMiss};
use crate::errors::*;
use crate::mock_command::CommandCreatorSync;
use async_trait::async_trait;
use std::collections::HashMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{OnceCell, OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;
use tonic::transport::{Certificate, Identity};

const SYSROOT_COPIES_DIR: &str = "reapi-sysroot-copies";
const DIGEST_CACHE_FILE: &str = "reapi-digests.json";
const MAX_READY_WAIT: Duration = Duration::from_secs(3600);

type ToolchainCheck = OnceCell<std::result::Result<(), CompileLocallyReason>>;

#[derive(Clone, Copy, Default)]
struct ActionCacheCounts {
    lookups: u64,
    misses: u64,
}

pub(crate) struct ReapiExecutor {
    connection: Option<Arc<Connection>>,
    toolchains: Arc<Toolchains>,
    digest_cache: Arc<DigestCache>,
    ready_wait: Duration,
    sysroot_copies_dir: PathBuf,
    lookup_pause: LookupPause,
    action_cache_counts: Mutex<ActionCacheCounts>,
    execution_pause: LookupPause,
    on_miss: ReapiOnMiss,
    linux_toolchain: bool,
    worker_toolchains: WorkerToolchains,
    local_slots: Option<Arc<Semaphore>>,
    remote_slots: Option<Arc<Semaphore>>,
    queue_timeout: Duration,
    executions_refused: AtomicBool,
    toolchain_checks: Mutex<HashMap<ToolchainKey, Arc<ToolchainCheck>>>,
    action_options: Arc<ActionOptions>,
}

const SLOTS_NEVER_CLOSE: &str = "REAPI slot semaphores are never closed";
enum Slot {
    Local(OwnedSemaphorePermit),
    Remote(Option<OwnedSemaphorePermit>),
}

impl ReapiExecutor {
    /// TLS files are read at startup.
    pub(crate) fn new(config: &ReapiConfig, archives: &[DistToolchainConfig]) -> Self {
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
            action_cache_counts: Mutex::default(),
            execution_pause: LookupPause::default(),
            on_miss: config.on_miss,
            linux_toolchain: cfg!(target_os = "linux"),
            worker_toolchains: WorkerToolchains::new(
                archives,
                config.cache_dir.join("reapi-worker-toolchains"),
            ),
            local_slots: config
                .local_slots
                .map(|slots| Arc::new(Semaphore::new(slots.get().min(Semaphore::MAX_PERMITS)))),
            remote_slots: config
                .remote_slots
                .map(|slots| Arc::new(Semaphore::new(slots.get().min(Semaphore::MAX_PERMITS)))),
            queue_timeout: Duration::from_secs(config.queue_timeout_secs.unwrap_or(60).min(3600)),
            executions_refused: AtomicBool::new(false),
            toolchain_checks: Mutex::default(),
            action_options: Arc::new(ActionOptions::new(config)),
        }
    }

    pub(crate) fn action_cache_counts(&self) -> (u64, u64) {
        let counts = self.action_cache_counts.lock().unwrap();
        (counts.lookups, counts.misses)
    }

    pub(crate) fn zero_action_cache_counts(&self) {
        *self.action_cache_counts.lock().unwrap() = ActionCacheCounts::default();
    }

    async fn prepare_lookup(
        &self,
        compile: &mut ReapiCompile,
    ) -> std::result::Result<(Arc<ServerApis>, ToolchainFiles, bool), CompileLocallyReason> {
        let connection = self
            .connection
            .as_ref()
            .ok_or(CompileLocallyReason::Misconfigured)?;
        if self.lookup_pause.is_paused() {
            return Err(CompileLocallyReason::ActionCacheLookupsPaused);
        }
        let deadline = Instant::now() + self.ready_wait;
        let toolchain = async {
            if !self.linux_toolchain
                && let Some(key) = self
                    .worker_toolchains
                    .toolchain(&compile.toolchain, deadline)
                    .await?
            {
                if compile.input_root_files.iter().any(|path| {
                    path.extension()
                        .and_then(|ext| ext.to_str())
                        .is_some_and(|ext| matches!(ext, "dylib" | "so" | "dll"))
                }) {
                    return Err(CompileLocallyReason::ProcMacroForClientOs);
                }
                compile.toolchain = key;
                return Ok((
                    self.toolchains.files(&compile.toolchain, deadline).await?,
                    true,
                ));
            }
            Ok((
                self.toolchains.files(&compile.toolchain, deadline).await?,
                self.linux_toolchain,
            ))
        };
        let (apis, (files, can_execute)) =
            tokio::try_join!(connection.server_apis(deadline), toolchain)?;
        Ok((apis, files, can_execute))
    }

    async fn local_or_remote_slot(&self) -> Slot {
        if let Some(slot) =
            (self.local_slots.clone()).and_then(|slots| slots.try_acquire_owned().ok())
        {
            return Slot::Local(slot);
        }
        let Some(remote_slots) = self.remote_slots.clone() else {
            return Slot::Remote(None);
        };
        match self.local_slots.clone() {
            Some(local_slots) => tokio::select! {
                slot = remote_slots.acquire_owned() => {
                    Slot::Remote(Some(slot.expect(SLOTS_NEVER_CLOSE)))
                }
                slot = local_slots.acquire_owned() => {
                    Slot::Local(slot.expect(SLOTS_NEVER_CLOSE))
                }
            },
            None => Slot::Remote(Some(
                remote_slots.acquire_owned().await.expect(SLOTS_NEVER_CLOSE),
            )),
        }
    }

    /// The next free local slot, so that local compiles don't oversubscribe the cores while
    /// other compiles execute on workers; `None` without `local_slots`.
    async fn local_slot(&self) -> Option<OwnedSemaphorePermit> {
        let local_slots = self.local_slots.clone()?;
        Some(local_slots.acquire_owned().await.expect(SLOTS_NEVER_CLOSE))
    }

    async fn check_toolchain(
        &self,
        apis: &ServerApis,
        execution: &Execution,
        key: &ToolchainKey,
        toolchain: &ToolchainFiles,
        out_pretty: &str,
    ) -> std::result::Result<(), CompileLocallyReason> {
        let ToolchainKey::Rustc(rustc) = key else {
            return Err(CompileLocallyReason::CToolchainUnsupported);
        };
        let check = self
            .toolchain_checks
            .lock()
            .unwrap()
            .entry(key.clone())
            .or_default()
            .clone();
        *check
            .get_or_try_init(|| async {
                let files = toolchain.clone();
                let options = self.action_options.clone();
                let action = tokio::task::spawn_blocking(move || {
                    super::remote_compile::rustc_version_action_blobs(&files, &options)
                })
                .await
                .map_err(Error::from)
                .flatten()
                .map_err(|error| {
                    warn!("[{out_pretty}]: failed to prepare the worker rustc check: {error:#}");
                    CompileLocallyReason::HashingInputsFailed
                })?;
                let response = self
                    .upload_and_execute(
                        apis,
                        execution,
                        &action,
                        super::client::RUSTC_VERSION_MNEMONIC,
                        false,
                        out_pretty,
                    )
                    .await?;
                let result = response
                    .result
                    .ok_or(CompileLocallyReason::ExecutionFailed)?;
                if result.exit_code != 0 {
                    return Ok(Err(CompileLocallyReason::RustcFailsOnWorkers));
                }
                let stdout = super::remote_compile::download_stdout_or_stderr(
                    &apis.cas,
                    &result.stdout_raw,
                    result.stdout_digest.as_ref(),
                )
                .await
                .map_err(|error| {
                    warn!("[{out_pretty}]: failed to download worker rustc version: {error:#}");
                    if is_refused_read(&error) {
                        CompileLocallyReason::CredentialsRefused
                    } else {
                        CompileLocallyReason::DownloadingOutputsFailed
                    }
                })?;
                let stdout = String::from_utf8_lossy(&stdout);
                let commit = stdout
                    .lines()
                    .find_map(|line| line.strip_prefix("commit-hash: "));
                Ok(if commit == Some(rustc.commit_hash.as_str()) {
                    Ok(())
                } else {
                    Err(CompileLocallyReason::RustcCommitDiffersOnWorkers)
                })
            })
            .await?
    }

    async fn upload_and_execute(
        &self,
        apis: &ServerApis,
        execution: &Execution,
        action: &super::remote_compile::ActionBlobs,
        mnemonic: &str,
        skip_cache_lookup: bool,
        out_pretty: &str,
    ) -> std::result::Result<
        super::proto::build::bazel::remote::execution::v2::ExecuteResponse,
        CompileLocallyReason,
    > {
        tokio::time::timeout(Duration::from_secs(600), async {
            for _ in 0..2 {
                apis.cas
                    .ensure_uploaded(action.blobs.clone())
                    .await
                    .map_err(|error| {
                        warn!("[{out_pretty}]: REAPI input upload failed: {error:#}");
                        if let Some(super::cas::ChangedBlob(path)) = error.downcast_ref() {
                            self.digest_cache.forget(path);
                            CompileLocallyReason::InputChangedAfterHashing
                        } else if error.is::<super::cas::UnreadableBlob>() {
                            CompileLocallyReason::UnreadableInput
                        } else {
                            match rpc_code(&error) {
                                Some(tonic::Code::PermissionDenied) => {
                                    CompileLocallyReason::ExecutionsRefused
                                }
                                Some(tonic::Code::Unauthenticated) => {
                                    CompileLocallyReason::CredentialsRefused
                                }
                                _ => CompileLocallyReason::UploadFailed,
                            }
                        }
                    })?;
                match execution
                    .execute_action(
                        &action.action_digest,
                        mnemonic,
                        skip_cache_lookup,
                        self.queue_timeout,
                    )
                    .await
                {
                    Err(error) if error.is::<MissingActionBlobs>() => {
                        apis.cas.forget_present_blobs();
                    }
                    Err(error) => {
                        warn!("[{out_pretty}]: REAPI execution failed: {error:#}");
                        return Err(if error.is::<QueuedTooLong>() {
                            CompileLocallyReason::ExecutionQueuedTooLong
                        } else {
                            match rpc_code(&error) {
                                Some(tonic::Code::Unauthenticated) => {
                                    CompileLocallyReason::CredentialsRefused
                                }
                                Some(tonic::Code::PermissionDenied) => {
                                    CompileLocallyReason::ExecutionsRefused
                                }
                                Some(tonic::Code::DeadlineExceeded) => {
                                    CompileLocallyReason::ExecutionTimedOut
                                }
                                _ => CompileLocallyReason::ExecutionFailed,
                            }
                        });
                    }
                    Ok(response) => return Ok(response),
                }
            }
            Err(CompileLocallyReason::ExecutionFailed)
        })
        .await
        .unwrap_or(Err(CompileLocallyReason::ExecutionTimedOut))
    }

    async fn look_up(
        &self,
        reapi_compile: ReapiCompile,
        apis: Arc<ServerApis>,
        toolchain: ToolchainFiles,
        can_execute: bool,
        local_slot: &mut Option<OwnedSemaphorePermit>,
        out_pretty: &str,
    ) -> std::result::Result<(ReapiOutcome, process::Output), CompileLocallyReason> {
        let digest_cache = self.digest_cache.clone();
        let action_options = self.action_options.clone();
        let toolchain_files = toolchain.clone();
        let digested = tokio::task::spawn_blocking(move || {
            let files = digest_input_root_files(&reapi_compile, &digest_cache)?;
            let action = action_blobs(&reapi_compile, &files, &toolchain, &action_options)?;
            Ok::<_, Error>((reapi_compile, action))
        })
        .await;
        let (reapi_compile, action) = match digested.map_err(Error::from).flatten() {
            Ok(digested) => digested,
            Err(e) => {
                warn!(
                    "[{}]: Compiling locally: failed to hash the inputs: {:#}",
                    out_pretty, e
                );
                return Err(CompileLocallyReason::HashingInputsFailed);
            }
        };
        let action_digest = &action.action_digest;
        // Reserve a probe only once hashing and connection setup have finished.
        let permit = self
            .lookup_pause
            .try_lookup()
            .ok_or(CompileLocallyReason::ActionCacheLookupsPaused)?;
        let lookup = apis
            .action_cache
            .get_action_result(action_digest, reapi_compile.program.action_mnemonic())
            .await;
        {
            let mut counts = self.action_cache_counts.lock().unwrap();
            counts.lookups += 1;
            if matches!(lookup, Ok(None)) {
                counts.misses += 1;
            }
        }
        let cached = match lookup {
            Ok(cached) => {
                permit.succeeded();
                cached
            }
            Err(e) => {
                warn!("[{}]: Compiling locally: {:#}", out_pretty, e);
                if is_refused_read(&e) {
                    if let Some(connection) = &self.connection {
                        connection.credentials_refused(&apis).await;
                    }
                    return Err(CompileLocallyReason::CredentialsRefused);
                }
                if let Some(pause) = permit.failed() {
                    warn!(
                        "REAPI: action cache lookups are failing; compiling locally for {pause:?}"
                    );
                }
                return Err(CompileLocallyReason::ActionCacheLookupFailed);
            }
        };
        let (outcome, result) = match cached {
            Some(result) if result.exit_code == 0 => (ReapiOutcome::ActionCacheHit, result),
            cached => {
                let Some(execution) = &apis.execution else {
                    return Err(CompileLocallyReason::NotInActionCache);
                };
                if self.on_miss == ReapiOnMiss::Local {
                    return Err(CompileLocallyReason::NotInActionCache);
                }
                if !can_execute {
                    return Err(CompileLocallyReason::NonLinuxToolchain);
                }
                if self.executions_refused.load(Ordering::Relaxed) {
                    return Err(CompileLocallyReason::ExecutionsRefused);
                }
                let slot = tokio::time::timeout(self.queue_timeout, self.local_or_remote_slot())
                    .await
                    .map_err(|_| CompileLocallyReason::NoFreeRemoteSlot)?;
                let _remote_slot = match slot {
                    Slot::Local(slot) => {
                        *local_slot = Some(slot);
                        return Err(CompileLocallyReason::LocalSlotFree);
                    }
                    Slot::Remote(slot) => slot,
                };
                let permit = self
                    .execution_pause
                    .try_lookup()
                    .ok_or(CompileLocallyReason::ExecutionsPaused)?;
                let response = async {
                    self.check_toolchain(
                        &apis,
                        execution,
                        &reapi_compile.toolchain,
                        &toolchain_files,
                        out_pretty,
                    )
                    .await?;
                    self.upload_and_execute(
                        &apis,
                        execution,
                        &action,
                        reapi_compile.program.action_mnemonic(),
                        cached.is_some(),
                        out_pretty,
                    )
                    .await
                }
                .await;
                let response = match response {
                    Ok(response) => {
                        permit.succeeded();
                        response
                    }
                    Err(reason) => {
                        if reason == CompileLocallyReason::CredentialsRefused
                            && let Some(connection) = &self.connection
                        {
                            connection.credentials_refused(&apis).await;
                        }
                        if reason == CompileLocallyReason::ExecutionsRefused {
                            self.executions_refused.store(true, Ordering::Relaxed);
                        }
                        if reason == CompileLocallyReason::InputChangedAfterHashing {
                            self.toolchains.forget(&reapi_compile.toolchain).await;
                        }
                        if matches!(
                            reason,
                            CompileLocallyReason::UploadFailed
                                | CompileLocallyReason::ExecutionFailed
                        ) {
                            permit.failed();
                        }
                        return Err(reason);
                    }
                };
                let result = response
                    .result
                    .ok_or(CompileLocallyReason::ExecutionFailed)?;
                if result.exit_code != 0 {
                    return Err(CompileLocallyReason::CompileFailedOnWorker);
                }
                let outcome = if response.cached_result {
                    ReapiOutcome::ActionCacheHit
                } else {
                    ReapiOutcome::Executed
                };
                (outcome, result)
            }
        };
        match materialize(&apis.cas, &reapi_compile, &result).await {
            Ok(output) => {
                debug!("[{}]: REAPI {outcome:?} {}", out_pretty, action_digest.hash);
                Ok((outcome, output))
            }
            Err(e) => {
                if is_refused_read(&e)
                    && let Some(connection) = &self.connection
                {
                    connection.credentials_refused(&apis).await;
                    return Err(CompileLocallyReason::CredentialsRefused);
                }
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

fn is_refused_read(error: &Error) -> bool {
    matches!(
        rpc_code(error),
        Some(tonic::Code::Unauthenticated | tonic::Code::PermissionDenied)
    )
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
    if config.auth_token_file.is_some() && config.credential_helper.is_some() {
        bail!("[reapi] can't have both auth_token_file and credential_helper");
    }
    let auth_token = config
        .auth_token_file
        .clone()
        .map(|file| AuthToken::from_file(file, auth_token::CHECK_INTERVAL))
        .transpose()?
        .map(Arc::new);
    // The sccache server's cwd and PATH are those of whichever client started it, so a
    // relative path could name another program from one run to the next.
    if let Some(program) = &config.credential_helper
        && program.is_relative()
        && program.components().count() > 1
    {
        bail!("[reapi] credential_helper must be an absolute path or a name on PATH");
    }
    let credential_helper = match &config.credential_helper {
        Some(program) => Some(Arc::new(CredentialHelper::new(
            program.clone(),
            &credential_helper_server_uri(&config.endpoint)?,
            credential_helper::HELPER_TIMEOUT,
        ))),
        None => None,
    };
    let tls_ca_certificates = config
        .tls_ca_file
        .as_deref()
        .map(read_certificates)
        .transpose()?;
    let tls_client_identity = match (
        &config.tls_client_certificate_file,
        &config.tls_client_key_file,
    ) {
        (Some(cert_file), Some(key_file)) => Some(Identity::from_pem(
            read_tls_file(cert_file, "client certificate")?,
            read_tls_file(key_file, "client key")?,
        )),
        (None, None) => None,
        _ => bail!(
            "[reapi] needs both tls_client_certificate_file and tls_client_key_file, or neither"
        ),
    };
    let options = ConnectOptions {
        endpoint: config.endpoint.clone(),
        instance_name: config.instance_name.clone(),
        auth_token,
        headers: config
            .headers
            .iter()
            .map(|(name, value)| (name.clone(), value.as_str().to_owned()))
            .collect(),
        credential_helper,
        tool_invocation_id: uuid::Uuid::new_v4().to_string(),
        tls_ca_certificates,
        tls_client_identity,
    };
    check_connect_options(&options)?;
    Ok(options)
}

/// The PEM certificates in `file`. Fails if it holds none, since TLS would then trust no
/// server.
fn read_certificates(file: &Path) -> Result<Certificate> {
    let pem = read_tls_file(file, "CA file")?;
    if !String::from_utf8_lossy(&pem).contains("-----BEGIN CERTIFICATE-----") {
        bail!(
            "the REAPI TLS CA file {} holds no PEM certificate",
            file.display()
        );
    }
    Ok(Certificate::from_pem(pem))
}

fn read_tls_file(file: &Path, what: &str) -> Result<Vec<u8>> {
    std::fs::read(file)
        .with_context(|| format!("failed to read the REAPI TLS {what} {}", file.display()))
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
        let mut local_slot = None;
        if request.cache_control != CacheControl::Default {
            let _slot = self.local_slot().await;
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
            Ok(Ok(mut compile)) => match self.prepare_lookup(&mut compile).await {
                Ok((apis, toolchain, can_execute)) => {
                    self.look_up(
                        compile,
                        apis,
                        toolchain,
                        can_execute,
                        &mut local_slot,
                        &request.output_name,
                    )
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
            Ok((outcome, output)) => Ok(CompileOutcome {
                cacheable: Cacheable::Yes,
                execution: DistType::Reapi(outcome),
                output,
            }),
            Err(reason) => {
                let _slot = match local_slot {
                    Some(slot) => Some(slot),
                    None => self.local_slot().await,
                };
                compile_locally(request, reason).await
            }
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
    use std::sync::atomic::Ordering;
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
                program: crate::reapi::WorkerProgram::Rustc {
                    mapped_crate_root: None,
                },
                toolchain: ToolchainKey::rustc(
                    "abc123".to_owned(),
                    self.dir.join("sysroot"),
                    TARGET_TRIPLE.to_owned(),
                ),
                env: Default::default(),
                input_root_files: vec![ws.join("src/lib.rs")],
                input_root_directories: vec![],
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
            ..Default::default()
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
            Self::with_server(eligibility, runtime, FakeServer::default())
        }

        fn with_server(
            eligibility: Eligibility,
            runtime: tokio::runtime::Runtime,
            server: FakeServer,
        ) -> Self {
            let server = Arc::new(server);
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
                compile.toolchain.as_rustc(),
                &digest_cache,
            )
            .unwrap();
            let action_digest = action_blobs(
                &compile,
                &files,
                &toolchain,
                &ActionOptions::new(&self.config),
            )
            .unwrap()
            .action_digest;
            let rlib_path = compile
                .path_mapper
                .to_input_root(&compile.outputs[0])
                .unwrap();
            let mut result = worker_result(vec![inline_output(&rlib_path, b"rlib")]);
            change(&mut result);
            self.server.insert_action_result(&action_digest, result);
        }

        fn executor(&self) -> ReapiExecutor {
            let mut executor = ReapiExecutor::new(&self.config, &[]);
            let digest_cache = DigestCache::load(self.config.cache_dir.join(DIGEST_CACHE_FILE));
            executor.digest_cache = Arc::new(digest_cache.caching_new_files());
            executor.toolchains = Toolchains::new(executor.digest_cache.clone());
            executor
        }

        /// Runs the compile through the executor. A local compile writes `out` to stdout and
        /// `err` to stderr.
        fn compile(&self) -> (DistType, process::Output) {
            self.compile_with(&self.executor())
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
    fn test_a_cache_miss_uploads_and_executes() {
        let fixture = Fixture::with_server(
            Eligibility::Eligible,
            tokio::runtime::Runtime::new().unwrap(),
            FakeServer {
                executes_actions: true,
                worker_rustc_commit_hash: Mutex::new(Some("abc123".into())),
                worker_outputs: Mutex::new(
                    [(
                        ".sccache-build/debug/deps/libfoo.rlib".to_owned(),
                        b"remote rlib".to_vec(),
                    )]
                    .into(),
                ),
                ..Default::default()
            },
        );
        let mut executor = fixture.executor();
        executor.linux_toolchain = true;
        let (outcome, _) = fixture.compile_with(&executor);
        assert_eq!(outcome, DistType::Reapi(ReapiOutcome::Executed));
        assert!(fixture.server.has_blob(b"pub fn f() {}"));
        assert_eq!(
            std::fs::read(fixture.dir.path().join("ws").join(RLIB)).unwrap(),
            b"remote rlib"
        );
        let (outcome, _) = fixture.compile_with(&executor);
        assert_eq!(outcome, DistType::Reapi(ReapiOutcome::ActionCacheHit));
    }

    #[test_case("ws/src/lib.rs" ; "source file")]
    #[test_case("sysroot/bin/rustc" ; "toolchain file")]
    fn test_a_stale_digest_compiles_locally_then_executes(path: &str) {
        let fixture = Fixture::with_server(
            Eligibility::Eligible,
            tokio::runtime::Runtime::new().unwrap(),
            FakeServer {
                executes_actions: true,
                worker_rustc_commit_hash: Mutex::new(Some("abc123".into())),
                worker_outputs: Mutex::new(
                    [(
                        ".sccache-build/debug/deps/libfoo.rlib".to_owned(),
                        b"remote rlib".to_vec(),
                    )]
                    .into(),
                ),
                ..Default::default()
            },
        );
        let mut executor = fixture.executor();
        executor.linux_toolchain = true;

        let stale = super::super::digest::of_bytes(b"stale contents").hash;
        executor
            .digest_cache
            .cache_stale_hash(&fixture.dir.path().join(path), &stale);
        assert_eq!(
            fixture.compile_with(&executor).0,
            compiled_locally("input changed after it was hashed")
        );
        assert_eq!(
            fixture.compile_with(&executor).0,
            DistType::Reapi(ReapiOutcome::Executed)
        );
    }

    #[test_case(tonic::Code::Unauthenticated ; "unauthenticated")]
    #[test_case(tonic::Code::PermissionDenied ; "permission denied")]
    fn test_worker_probe_download_auth_failure_reconnects(code: tonic::Code) {
        let fixture = Fixture::with_server(
            Eligibility::Eligible,
            tokio::runtime::Runtime::new().unwrap(),
            FakeServer {
                executes_actions: true,
                worker_rustc_commit_hash: Mutex::new(Some("abc123".into())),
                read_error: Some(code),
                ..Default::default()
            },
        );
        let mut executor = fixture.executor();
        executor.linux_toolchain = true;
        for _ in 0..2 {
            assert_eq!(
                fixture.compile_with(&executor).0,
                compiled_locally("REAPI server refused the credentials"),
            );
        }
        assert_eq!(fixture.server.capabilities_calls.load(Ordering::SeqCst), 2);

        // A second refusal with the same credentials stops reconnecting.
        assert_eq!(
            fixture.compile_with(&executor).0,
            compiled_locally("REAPI server refused the credentials"),
        );
        assert_eq!(fixture.server.capabilities_calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn test_a_worker_rustc_mismatch_is_remembered() {
        let fixture = Fixture::with_server(
            Eligibility::Eligible,
            tokio::runtime::Runtime::new().unwrap(),
            FakeServer {
                executes_actions: true,
                worker_rustc_commit_hash: Mutex::new(Some("other".into())),
                ..Default::default()
            },
        );
        let mut executor = fixture.executor();
        executor.linux_toolchain = true;
        for _ in 0..2 {
            let (outcome, _) = fixture.compile_with(&executor);
            assert_eq!(
                outcome,
                compiled_locally("worker rustc has a different commit hash")
            );
        }
        assert_eq!(fixture.server.execute_calls.load(Ordering::SeqCst), 1);
        assert!(!fixture.server.has_blob(b"pub fn f() {}"));
    }

    #[test]
    fn test_a_free_local_slot_takes_precedence_over_remote_execution() {
        let mut fixture = Fixture::with_server(
            Eligibility::Eligible,
            tokio::runtime::Runtime::new().unwrap(),
            FakeServer {
                executes_actions: true,
                ..Default::default()
            },
        );
        fixture.config.local_slots = std::num::NonZeroUsize::new(1);
        let mut executor = fixture.executor();
        executor.linux_toolchain = true;
        for _ in 0..2 {
            assert_eq!(
                fixture.compile_with(&executor).0,
                DistType::Reapi(ReapiOutcome::CompiledLocally(
                    CompileLocallyReason::LocalSlotFree.to_string()
                ))
            );
        }
        assert_eq!(fixture.server.execute_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_a_miss_falls_back_if_the_remote_slot_stays_busy() {
        let mut fixture = Fixture::with_server(
            Eligibility::Eligible,
            tokio::runtime::Runtime::new().unwrap(),
            FakeServer {
                executes_actions: true,
                ..Default::default()
            },
        );
        fixture.config.remote_slots = std::num::NonZeroUsize::new(1);
        fixture.config.queue_timeout_secs = Some(0);
        let mut executor = fixture.executor();
        executor.linux_toolchain = true;
        let _slot = executor
            .remote_slots
            .as_ref()
            .unwrap()
            .try_acquire()
            .unwrap();
        assert_eq!(
            fixture.compile_with(&executor).0,
            DistType::Reapi(ReapiOutcome::CompiledLocally(
                CompileLocallyReason::NoFreeRemoteSlot.to_string()
            ))
        );
        assert_eq!(fixture.server.execute_calls.load(Ordering::SeqCst), 0);
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
        *fixture.server.lookup_error.lock().unwrap() = Some(tonic::Code::Internal);
        let (dist_type, output) = fixture.compile();
        assert_eq!(compiled_locally("action cache lookup failed"), dist_type);
        assert_eq!(b"out".as_slice(), output.stdout);
    }

    #[test]
    fn test_compiles_resume_after_a_cooldown_and_reset_the_backoff() {
        let fixture = Fixture::clock_controlled();
        fixture.put_result_in_action_cache(|_| {});
        *fixture.server.lookup_error.lock().unwrap() = Some(tonic::Code::Internal);
        let executor = fixture.executor();
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

        *fixture.server.lookup_error.lock().unwrap() = Some(tonic::Code::Internal);
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
        let executor = fixture.executor();
        *fixture.server.lookup_error.lock().unwrap() = Some(tonic::Code::Internal);
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
        *fixture.server.lookup_error.lock().unwrap() = Some(tonic::Code::Internal);
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
        let executor = fixture.executor();
        *fixture.server.lookup_error.lock().unwrap() = Some(tonic::Code::Internal);
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
        let executor = fixture.executor();
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
        let executor = ReapiExecutor::new(&config("grpc://127.0.0.1:1".into(), u64::MAX), &[]);
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
        let executor = ReapiExecutor::new(&config("grpc://127.0.0.1:1".into(), 0), &[]);
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
