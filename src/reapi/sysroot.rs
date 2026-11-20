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

//! Symlinked Rust sysroots without rust-src for worker-compatible local outputs.

use crate::errors::*;
use anyhow::ensure;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

const COPY_DIRS: [(&str, &str); 3] = [("", "lib"), ("lib", "rustlib"), ("lib/rustlib", "src")];

/// Omits rust-src so rustc keeps std source paths under `/rustc/<commit>/...`.
/// Links follow toolchain file updates; changes to the directory layout get a new copy.
/// Old copies are retained. This function performs blocking filesystem I/O.
pub(crate) fn sysroot_copy(sysroot: &Path, sysroot_copies_dir: &Path) -> Result<PathBuf> {
    let sysroot = std::fs::canonicalize(sysroot)
        .with_context(|| format!("failed to resolve sysroot {}", sysroot.display()))?;
    let entries = COPY_DIRS
        .iter()
        .map(|(dir, skip)| {
            let mut names = read_names(&sysroot.join(dir))?;
            names.retain(|name| name != skip);
            Ok(names)
        })
        .collect::<Result<Vec<_>>>()?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"sccache-trimmed-sysroot-v1\0");
    hash_name(&mut hasher, sysroot.as_os_str());
    for names in &entries {
        hasher.update(&(names.len() as u64).to_le_bytes());
        for name in names {
            hash_name(&mut hasher, name);
        }
    }
    let name = hasher.finalize().to_hex();
    create_private_dir(sysroot_copies_dir).with_context(|| {
        format!(
            "failed to create private directory {}",
            sysroot_copies_dir.display()
        )
    })?;
    let sysroot_copies_dir = std::fs::canonicalize(sysroot_copies_dir)
        .context("failed to resolve sysroot copies directory")?;
    let copy = sysroot_copies_dir.join(name.as_str());
    match std::fs::symlink_metadata(&copy) {
        Ok(_) => {
            validate_copy(&copy, &sysroot, &entries)?;
            return Ok(copy);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("failed to inspect sysroot copy"),
    }
    let tmp = tempfile::Builder::new()
        .prefix("sysroot-")
        .tempdir_in(&sysroot_copies_dir)
        .context("failed to create temporary sysroot directory")?;
    std::fs::create_dir_all(tmp.path().join("lib/rustlib"))?;
    for ((dir, _), names) in COPY_DIRS.iter().zip(&entries) {
        for name in names {
            let link = tmp.path().join(dir).join(name);
            symlink(&sysroot.join(dir).join(name), &link)
                .with_context(|| format!("failed to link {}", link.display()))?;
        }
    }
    // TempDir cleans up failed attempts, including concurrent creators that lose the rename.
    if let Err(error) = std::fs::rename(tmp.path(), &copy) {
        validate_copy(&copy, &sysroot, &entries).map_err(|_| {
            Error::new(error).context(format!("failed to publish {}", copy.display()))
        })?;
    }
    Ok(copy)
}

fn hash_name(hasher: &mut blake3::Hasher, name: &std::ffi::OsStr) {
    let bytes = name.as_encoded_bytes();
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn read_names(dir: &Path) -> Result<Vec<OsString>> {
    let mut names = std::fs::read_dir(dir)
        .and_then(|entries| {
            entries
                .map(|entry| entry.map(|entry| entry.file_name()))
                .collect::<std::io::Result<Vec<_>>>()
        })
        .with_context(|| format!("failed to read {}", dir.display()))?;
    names.sort();
    Ok(names)
}

fn validate_copy(copy: &Path, sysroot: &Path, entries: &[Vec<OsString>]) -> Result<()> {
    for ((dir, skip), names) in COPY_DIRS.iter().zip(entries) {
        let path = copy.join(dir);
        ensure!(
            std::fs::symlink_metadata(&path)?.is_dir(),
            "invalid sysroot copy directory {}",
            path.display()
        );
        let mut expected = names.clone();
        if *skip != "src" {
            expected.push((*skip).into());
            expected.sort();
        }
        ensure!(
            read_names(&path)? == expected,
            "unexpected entries in sysroot copy {}",
            path.display()
        );
        for name in names {
            let link = path.join(name);
            ensure!(
                std::fs::read_link(&link)? == sysroot.join(dir).join(name),
                "unexpected sysroot link {}",
                link.display()
            );
        }
    }
    Ok(())
}

#[cfg(unix)]
fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    if !std::fs::symlink_metadata(dir)?.is_dir() {
        return Err(std::io::Error::other(
            "sysroot copies directory must not be a symlink",
        ));
    }
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)
}

#[cfg(unix)]
fn symlink(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(src, dst)
}

#[cfg(not(unix))]
fn symlink(_src: &Path, _dst: &Path) -> std::io::Result<()> {
    Err(std::io::ErrorKind::Unsupported.into())
}

#[cfg(all(test, unix))]
mod test {
    use super::*;

    const TARGET_LIB_DIR: &str = "lib/rustlib/aarch64-apple-darwin/lib";

    /// A sysroot with rust-src and one target triple, in `dir`.
    fn fake_sysroot(dir: &Path) -> PathBuf {
        let sysroot = dir.join("toolchain");
        for d in ["bin", "lib/rustlib/src/rust", TARGET_LIB_DIR] {
            std::fs::create_dir_all(sysroot.join(d)).unwrap();
        }
        std::fs::write(sysroot.join("lib/librustc_driver.so"), b"").unwrap();
        sysroot
    }

    #[test]
    fn test_sysroot_copy_has_all_but_rust_src() {
        let dir = tempfile::tempdir().unwrap();
        let sysroot = fake_sysroot(dir.path());
        let sysroot_copies_dir = dir.path().join("sysroot-copies");
        let copy = sysroot_copy(&sysroot, &sysroot_copies_dir).unwrap();
        assert!(copy.starts_with(sysroot_copies_dir.canonicalize().unwrap()));
        assert!(copy.join("bin").is_dir());
        assert!(copy.join("lib/librustc_driver.so").is_file());
        assert!(copy.join(TARGET_LIB_DIR).is_dir());
        assert!(!copy.join("lib/rustlib/src").exists());
    }

    #[test]
    fn test_sysroot_copies_dir_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let sysroot_copies_dir = dir.path().join("sysroot-copies");
        sysroot_copy(&fake_sysroot(dir.path()), &sysroot_copies_dir).unwrap();
        let mode = std::fs::metadata(&sysroot_copies_dir)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(0o700, mode & 0o777);
    }

    #[test]
    fn test_sysroot_copy_is_reused_or_made_again() {
        let dir = tempfile::tempdir().unwrap();
        let sysroot = fake_sysroot(dir.path());
        let sysroot_copies_dir = dir.path().join("sysroot-copies");
        let copy = sysroot_copy(&sysroot, &sysroot_copies_dir).unwrap();
        assert_eq!(copy, sysroot_copy(&sysroot, &sysroot_copies_dir).unwrap());
        std::fs::remove_dir_all(&copy).unwrap();
        assert_eq!(copy, sysroot_copy(&sysroot, &sysroot_copies_dir).unwrap());
        assert!(copy.join("lib/rustlib").is_dir());
    }

    #[test]
    fn test_an_added_target_gives_a_new_sysroot_copy() {
        let dir = tempfile::tempdir().unwrap();
        let sysroot = fake_sysroot(dir.path());
        let sysroot_copies_dir = dir.path().join("sysroot-copies");
        let copy = sysroot_copy(&sysroot, &sysroot_copies_dir).unwrap();
        let added_target_lib_dir = "lib/rustlib/wasm32-unknown-unknown/lib";
        std::fs::create_dir_all(sysroot.join(added_target_lib_dir)).unwrap();
        let new_copy = sysroot_copy(&sysroot, &sysroot_copies_dir).unwrap();
        assert_ne!(copy, new_copy);
        assert!(new_copy.join(added_target_lib_dir).is_dir());
    }

    #[test]
    fn test_reused_copies_dir_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let sysroot = fake_sysroot(dir.path());
        let copies = dir.path().join("copies");
        let copy = sysroot_copy(&sysroot, &copies).unwrap();
        std::fs::set_permissions(&copies, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(copy, sysroot_copy(&sysroot, &copies).unwrap());
        assert_eq!(
            std::fs::metadata(copies).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[test]
    fn test_symlinked_copies_dir_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let sysroot = fake_sysroot(dir.path());
        let other = dir.path().join("other");
        std::fs::create_dir(&other).unwrap();
        let copies = dir.path().join("copies");
        symlink(&other, &copies).unwrap();
        assert!(sysroot_copy(&sysroot, &copies).is_err());
        assert_eq!(std::fs::read_dir(other).unwrap().count(), 0);
    }

    #[test]
    fn test_unexpected_copy_entries_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let sysroot = fake_sysroot(dir.path());
        let copies = dir.path().join("copies");
        let copy = sysroot_copy(&sysroot, &copies).unwrap();
        std::fs::create_dir(copy.join("lib/rustlib/src")).unwrap();
        assert!(sysroot_copy(&sysroot, &copies).is_err());
    }

    #[test]
    fn test_retargeted_copy_links_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let sysroot = fake_sysroot(dir.path());
        let copies = dir.path().join("copies");
        let copy = sysroot_copy(&sysroot, &copies).unwrap();
        let bin = copy.join("bin");
        std::fs::remove_file(&bin).unwrap();
        symlink(&sysroot.join("lib"), &bin).unwrap();
        assert!(sysroot_copy(&sysroot, &copies).is_err());
    }

    #[test]
    fn test_symlinked_copy_directories_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let sysroot = fake_sysroot(dir.path());
        let copies = dir.path().join("copies");
        let copy = sysroot_copy(&sysroot, &copies).unwrap();
        std::fs::remove_dir_all(copy.join("lib")).unwrap();
        symlink(&sysroot.join("lib"), &copy.join("lib")).unwrap();
        assert!(sysroot_copy(&sysroot, &copies).is_err());
    }

    #[test]
    fn test_concurrent_creators_publish_one_complete_copy() {
        let dir = tempfile::tempdir().unwrap();
        let sysroot = fake_sysroot(dir.path());
        let copies = dir.path().join("copies");
        let barrier = std::sync::Barrier::new(8);
        let results = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        barrier.wait();
                        sysroot_copy(&sysroot, &copies).unwrap()
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert!(results.iter().all(|copy| *copy == results[0]));
        assert_eq!(std::fs::read_dir(copies).unwrap().count(), 1);
        assert!(results[0].join(TARGET_LIB_DIR).is_dir());
        assert!(!results[0].join("lib/rustlib/src").exists());
    }

    #[test]
    fn test_toolchain_updates_remain_visible() {
        let dir = tempfile::tempdir().unwrap();
        let sysroot = fake_sysroot(dir.path());
        let copies = dir.path().join("copies");
        let copy = sysroot_copy(&sysroot, &copies).unwrap();
        let library = "lib/librustc_driver.so";
        std::fs::write(sysroot.join(library), b"updated").unwrap();
        assert_eq!(copy, sysroot_copy(&sysroot, &copies).unwrap());
        assert_eq!(std::fs::read(copy.join(library)).unwrap(), b"updated");
    }

    #[test]
    fn test_sysroot_aliases_use_the_same_copy() {
        let dir = tempfile::tempdir().unwrap();
        let sysroot = fake_sysroot(dir.path());
        let alias = dir.path().join("alias");
        symlink(&sysroot, &alias).unwrap();
        let copies = dir.path().join("copies");
        assert_eq!(
            sysroot_copy(&sysroot, &copies).unwrap(),
            sysroot_copy(&alias, &copies).unwrap()
        );
    }

    #[test]
    fn test_relative_paths_produce_usable_absolute_links() {
        let dir = tempfile::tempdir_in(".").unwrap();
        let sysroot = fake_sysroot(dir.path());
        let copy = sysroot_copy(&sysroot, &dir.path().join("copies")).unwrap();
        assert!(copy.is_absolute());
        assert!(copy.join("lib/librustc_driver.so").is_file());
    }
}
