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

//! Shared background hashing of Rust toolchains, with persistent file digests.

use super::digest::DigestCache;
use super::input_root::InputRootFile;
use super::mapping::{CompileLocallyReason, RustcToolchainKey, ToolchainKey};
use super::remote_compile::{UnusableToolchain, toolchain_files};
use crate::errors::*;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tokio::time::Instant;

const RETRY_AFTER: Duration = Duration::from_secs(60);

/// A toolchain's input root files, paired with their local paths.
pub(super) type ToolchainFiles = Arc<Vec<(InputRootFile, PathBuf)>>;

enum State {
    Hashing,
    Hashed(ToolchainFiles),
    HashingFailed {
        retry_at: Instant,
    },
    /// Compiles with the toolchain run locally until it changes, which changes its key.
    Unusable(CompileLocallyReason),
}

pub(super) struct Toolchains {
    digest_cache: Arc<DigestCache>,
    states: tokio::sync::Mutex<HashMap<ToolchainKey, State>>,
    hash_attempts_ended: watch::Sender<u64>,
    retry_after: Duration,
}

impl Toolchains {
    pub(super) fn new(digest_cache: Arc<DigestCache>) -> Arc<Self> {
        Arc::new(Toolchains {
            digest_cache,
            states: Default::default(),
            hash_attempts_ended: watch::Sender::new(0),
            retry_after: RETRY_AFTER,
        })
    }

    /// Starts or joins hashing, waiting up to `deadline`.
    pub(super) async fn files(
        self: &Arc<Self>,
        key: &ToolchainKey,
        deadline: Instant,
    ) -> std::result::Result<ToolchainFiles, CompileLocallyReason> {
        let mut hash_attempts_ended = self.hash_attempts_ended.subscribe();
        let mut waited = false;
        loop {
            {
                let mut states = self.states.lock().await;
                match states.get(key) {
                    Some(State::Hashed(files)) => return Ok(files.clone()),
                    Some(State::Unusable(reason)) => return Err(*reason),
                    // Leave retries to later compiles after the backoff.
                    Some(State::HashingFailed { retry_at })
                        if waited || Instant::now() < *retry_at =>
                    {
                        return Err(CompileLocallyReason::HashingToolchainFailed);
                    }
                    Some(State::Hashing) => {}
                    None | Some(State::HashingFailed { .. }) => {
                        states.insert(key.clone(), State::Hashing);
                        self.spawn_hash(key.clone());
                    }
                }
            }
            waited = true;
            if Instant::now() >= deadline {
                return Err(CompileLocallyReason::HashingToolchain);
            }
            match tokio::time::timeout_at(deadline, hash_attempts_ended.changed()).await {
                Ok(Ok(())) => continue,
                Ok(Err(_)) => return Err(CompileLocallyReason::HashingToolchainFailed),
                Err(_) => {
                    return Err(CompileLocallyReason::HashingToolchain);
                }
            }
        }
    }

    /// Makes the next compile with `key` hash its files again.
    pub(super) async fn forget(&self, key: &ToolchainKey) {
        let mut states = self.states.lock().await;
        if let Some(State::Hashed(_)) = states.get(key) {
            states.remove(key);
        }
    }

    fn spawn_hash(self: &Arc<Self>, key: ToolchainKey) {
        let this = self.clone();
        tokio::spawn(async move {
            let settling_time = match &key {
                ToolchainKey::Rustc(key) => this.digest_cache.settling_time(key.stamps()),
                ToolchainKey::C(_) => Duration::ZERO,
            };
            if !settling_time.is_zero() {
                tokio::time::sleep(settling_time).await;
            }
            let digest_cache = this.digest_cache.clone();
            let expected_key = key.clone();
            let hashed = tokio::task::spawn_blocking(move || {
                let ToolchainKey::Rustc(expected_key) = expected_key else {
                    return Err(
                        UnusableToolchain(CompileLocallyReason::CToolchainUnsupported).into(),
                    );
                };
                let files = toolchain_files(&expected_key, &digest_cache)?;
                if RustcToolchainKey::new(
                    expected_key.commit_hash.clone(),
                    expected_key.sysroot.clone(),
                    expected_key.target_triple.clone(),
                ) != expected_key
                {
                    bail!("toolchain changed while hashing");
                }
                if let Err(e) = digest_cache.save() {
                    warn!("REAPI: failed to save the digest cache: {e:#}");
                }
                Ok::<_, Error>(files)
            })
            .await;
            let state = match hashed {
                Ok(Ok(files)) => {
                    info!("REAPI: hashed {key}");
                    State::Hashed(Arc::new(files))
                }
                Ok(Err(e)) => match e.downcast_ref::<UnusableToolchain>() {
                    Some(UnusableToolchain(reason)) => {
                        warn!("REAPI: compiles with {key} run locally until it changes: {e:#}");
                        State::Unusable(*reason)
                    }
                    None => {
                        warn!("REAPI: failed to hash {key}: {e:#}");
                        this.hashing_failed()
                    }
                },
                Err(e) => {
                    if e.is_panic() {
                        warn!("REAPI: hashing {key} panicked: {e}");
                    }
                    this.hashing_failed()
                }
            };
            this.states.lock().await.insert(key, state);
            this.hash_attempts_ended
                .send_modify(|count| *count = count.wrapping_add(1));
        });
    }

    fn hashing_failed(&self) -> State {
        State::HashingFailed {
            retry_at: Instant::now() + self.retry_after,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::reapi::remote_compile::test::fake_sysroot;
    use std::path::Path;

    const TARGET_TRIPLE: &str = "x86_64-unknown-linux-gnu";

    fn toolchains(dir: &Path, retry_after: Duration) -> Arc<Toolchains> {
        let digest_cache = DigestCache::load(dir.join("digests.json")).caching_new_files();
        let toolchains = Toolchains::new(Arc::new(digest_cache));
        Arc::new(Toolchains {
            retry_after,
            ..Arc::into_inner(toolchains).unwrap()
        })
    }

    fn key(sysroot: &Path) -> ToolchainKey {
        ToolchainKey::rustc(
            "abc123".to_owned(),
            sysroot.to_owned(),
            TARGET_TRIPLE.to_owned(),
        )
    }

    fn in_secs(secs: u64) -> Instant {
        Instant::now() + Duration::from_secs(secs)
    }

    #[tokio::test]
    async fn test_c_toolchains_stay_local_until_packaging_is_supported() {
        let dir = tempfile::tempdir().unwrap();
        let toolchains = toolchains(dir.path(), RETRY_AFTER);
        let key = ToolchainKey::C(super::super::mapping::CToolchainKey::new(
            dir.path().join("cc"),
        ));
        assert_eq!(
            Some(CompileLocallyReason::CToolchainUnsupported),
            toolchains.files(&key, in_secs(10)).await.err()
        );
    }

    #[tokio::test]
    async fn test_a_toolchain_that_just_changed_is_hashed_once_its_files_settle() {
        let dir = tempfile::tempdir().unwrap();
        let sysroot = fake_sysroot(dir.path());
        let settling_time = Duration::from_millis(500);
        let digest_cache =
            DigestCache::load(dir.path().join("digests.json")).with_min_age_to_cache(settling_time);
        let toolchains = Toolchains::new(Arc::new(digest_cache));
        let started = Instant::now();
        toolchains.files(&key(&sysroot), in_secs(10)).await.unwrap();
        assert!(started.elapsed() >= settling_time);
    }

    #[tokio::test]
    async fn test_a_toolchain_is_hashed_once() {
        let dir = tempfile::tempdir().unwrap();
        let toolchains = toolchains(dir.path(), RETRY_AFTER);
        let key = key(&fake_sysroot(dir.path()));
        assert_eq!(
            Some(CompileLocallyReason::HashingToolchain),
            toolchains.files(&key, Instant::now()).await.err()
        );
        let compiles: Vec<_> = (0..4)
            .map(|_| {
                let (toolchains, key) = (toolchains.clone(), key.clone());
                tokio::spawn(async move { toolchains.files(&key, in_secs(10)).await.unwrap() })
            })
            .collect();
        let first = toolchains.files(&key, in_secs(10)).await.unwrap();
        for compile in compiles {
            assert!(Arc::ptr_eq(&first, &compile.await.unwrap()));
        }
    }

    #[tokio::test]
    async fn test_hashed_digests_are_saved() {
        let dir = tempfile::tempdir().unwrap();
        let sysroot = fake_sysroot(dir.path());
        let rustc = sysroot.join("bin/rustc");
        let std = sysroot.join(format!("lib/rustlib/{TARGET_TRIPLE}/lib/libstd-x.rlib"));
        let toolchains = toolchains(dir.path(), RETRY_AFTER);
        toolchains.files(&key(&sysroot), in_secs(10)).await.unwrap();
        let saved = std::fs::read_to_string(dir.path().join("digests.json")).unwrap();
        for file in [&rustc, &std] {
            assert!(
                saved.contains(file.to_str().unwrap()),
                "{file:?} not in {saved}"
            );
        }
    }

    #[tokio::test]
    async fn test_a_toolchain_without_std_is_unusable_until_it_changes() {
        let dir = tempfile::tempdir().unwrap();
        let sysroot = fake_sysroot(dir.path());
        let std_dir = sysroot.join(format!("lib/rustlib/{TARGET_TRIPLE}"));
        let moved = dir.path().join("std");
        std::fs::rename(&std_dir, &moved).unwrap();
        let toolchains = toolchains(dir.path(), Duration::ZERO);
        let without_std = key(&sysroot);
        assert_eq!(
            Some(CompileLocallyReason::MissingRustcOrStd),
            toolchains.files(&without_std, in_secs(10)).await.err()
        );

        std::fs::rename(&moved, &std_dir).unwrap();
        assert_eq!(
            Some(CompileLocallyReason::MissingRustcOrStd),
            toolchains.files(&without_std, in_secs(10)).await.err(),
            "hashed again under the same key"
        );
        let with_std = key(&sysroot);
        assert_ne!(without_std, with_std);
        assert!(toolchains.files(&with_std, in_secs(10)).await.is_ok());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_a_failed_hashing_is_retried_after_a_while() {
        let dir = tempfile::tempdir().unwrap();
        let sysroot = fake_sysroot(dir.path());
        let library = sysroot.join("lib/libLLVM-broken.so");
        let missing = dir.path().join("library");
        std::os::unix::fs::symlink(&missing, &library).unwrap();
        let original_key = key(&sysroot);
        let toolchains = toolchains(dir.path(), RETRY_AFTER);
        assert_eq!(
            Some(CompileLocallyReason::HashingToolchainFailed),
            toolchains.files(&original_key, in_secs(10)).await.err()
        );
        tokio::time::pause();
        let retry_at = match toolchains.states.lock().await.get(&original_key).unwrap() {
            State::HashingFailed { retry_at } => *retry_at,
            _ => panic!("expected a retryable failure"),
        };
        assert_eq!(
            Some(CompileLocallyReason::HashingToolchainFailed),
            toolchains.files(&original_key, in_secs(10)).await.err()
        );
        tokio::time::advance(RETRY_AFTER).await;
        assert_eq!(
            Some(CompileLocallyReason::HashingToolchain),
            toolchains.files(&original_key, Instant::now()).await.err()
        );
        tokio::time::resume();
        assert_eq!(
            Some(CompileLocallyReason::HashingToolchainFailed),
            toolchains.files(&original_key, in_secs(10)).await.err()
        );
        assert!(matches!(toolchains.states.lock().await.get(&original_key),
            Some(State::HashingFailed { retry_at: next }) if *next > retry_at));
        std::fs::write(&missing, b"library").unwrap();
        let changed = key(&sysroot);
        assert_ne!(original_key, changed);
        assert!(toolchains.files(&changed, in_secs(10)).await.is_ok());
    }

    #[tokio::test]
    async fn test_changed_toolchains_are_not_published_under_a_stale_key() {
        let dir = tempfile::tempdir().unwrap();
        let sysroot = fake_sysroot(dir.path());
        let original = key(&sysroot);
        std::fs::write(sysroot.join("bin/rustc"), b"updated compiler").unwrap();
        let toolchains = toolchains(dir.path(), RETRY_AFTER);
        assert_eq!(
            Some(CompileLocallyReason::HashingToolchainFailed),
            toolchains.files(&original, in_secs(10)).await.err()
        );
        assert!(toolchains.files(&key(&sysroot), in_secs(10)).await.is_ok());
    }

    #[tokio::test]
    async fn test_a_digest_cache_save_failure_does_not_discard_hashed_files() {
        let dir = tempfile::tempdir().unwrap();
        let sysroot = fake_sysroot(dir.path());
        let blocker = dir.path().join("not-a-directory");
        std::fs::write(&blocker, b"file").unwrap();
        let toolchains = Toolchains::new(Arc::new(DigestCache::load(blocker.join("digests.json"))));
        assert!(toolchains.files(&key(&sysroot), in_secs(10)).await.is_ok());
    }

    #[test]
    fn test_deadlines_and_cancelled_waiters_leave_hashing_running() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let key = key(&fake_sysroot(dir.path()));
        let toolchains = toolchains(dir.path(), RETRY_AFTER);
        // Hold the only blocking thread so hashing cannot finish before the assertions.
        let (release, blocked) = std::sync::mpsc::channel();
        let blocker = runtime.spawn_blocking(move || blocked.recv().unwrap());
        runtime.block_on(async {
            assert_eq!(
                Some(CompileLocallyReason::HashingToolchain),
                toolchains.files(&key, Instant::now()).await.err()
            );
            let waiter = {
                let toolchains = toolchains.clone();
                let key = key.clone();
                tokio::spawn(async move { toolchains.files(&key, in_secs(10)).await })
            };
            tokio::task::yield_now().await;
            waiter.abort();
            assert!(waiter.await.err().unwrap().is_cancelled());
            assert!(matches!(
                toolchains.states.lock().await.get(&key),
                Some(State::Hashing)
            ));
            release.send(()).unwrap();
            blocker.await.unwrap();
            let files = toolchains.files(&key, in_secs(10)).await.unwrap();
            let reused = toolchains.files(&key, Instant::now()).await.unwrap();
            assert!(Arc::ptr_eq(&files, &reused));
        });
    }
}
