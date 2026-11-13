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

//! Local paths mapped into a REAPI input root, so that actions don't depend on where the checkout
//! lives.
//!
//! Paths under a compile's cwd keep their relative path in the input root, and paths
//! under its build root (cargo's target dir) go under [`BUILD_ROOT_DIR`].

use std::path::{Component, Path, PathBuf};

/// The input root's directory for files under the local build root.
const BUILD_ROOT_DIR: &str = ".sccache-build";

/// Maps local paths under the cwd and build root to input-root-relative paths.
#[derive(Debug)]
pub(crate) struct PathMapper {
    cwd: PathBuf,
    build_root: PathBuf,
}

impl PathMapper {
    pub(crate) fn new(cwd: PathBuf, build_root: PathBuf) -> Self {
        PathMapper { cwd, build_root }
    }

    /// The input-root-relative path for `local`, or `None` if it lies outside both the
    /// build root and the cwd, isn't UTF-8, or contains `..`. Both roots must be absolute
    /// and parent-free. This does not resolve symlinks.
    pub(crate) fn to_input_root(&self, local: &Path) -> Option<String> {
        let cwd = normalize_absolute(&self.cwd)?;
        let build_root = normalize_absolute(&self.build_root)?;
        let absolute = normalize_absolute(&cwd.join(local))?;
        // Checks the build root first, since cargo's target dir is usually inside the
        // workspace root, rustc's cwd for workspace members.
        if let Ok(relative) = absolute.strip_prefix(&build_root) {
            let relative = input_root_path(relative)?;
            return Some(if relative.is_empty() {
                BUILD_ROOT_DIR.to_owned()
            } else {
                format!("{BUILD_ROOT_DIR}/{relative}")
            });
        }
        let relative = absolute.strip_prefix(&cwd).ok()?;
        // It would land in the build root's directory in the input root.
        if relative.starts_with(BUILD_ROOT_DIR) {
            return None;
        }
        let relative = input_root_path(relative)?;
        Some(if relative.is_empty() {
            ".".to_owned()
        } else {
            relative
        })
    }
}

fn normalize_absolute(path: &Path) -> Option<PathBuf> {
    if !path.is_absolute() {
        return None;
    }
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                // A symlink before `..` can change which directory it refers to.
                return None;
            }
            c => out.push(c),
        }
    }
    Some(out)
}

fn input_root_path(path: &Path) -> Option<String> {
    path.components()
        .map(|component| match component {
            Component::Normal(name) => name.to_str(),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()
        .map(|components| components.join("/"))
}

#[cfg(test)]
mod test {
    use super::*;
    use test_case::test_case;

    fn path_mapper() -> PathMapper {
        PathMapper::new("/ws".into(), "/ws/target".into())
    }

    #[cfg(unix)]
    #[test]
    fn test_maps_cwd_and_build_root() {
        let mapper = path_mapper();
        assert_eq!(
            "src/lib.rs",
            mapper.to_input_root(Path::new("src/lib.rs")).unwrap()
        );
        assert_eq!(".", mapper.to_input_root(Path::new("/ws")).unwrap());
        assert_eq!(
            ".sccache-build/debug/deps/libfoo.rmeta",
            mapper
                .to_input_root(Path::new("/ws/target/debug/deps/libfoo.rmeta"))
                .unwrap()
        );
        assert_eq!(
            ".sccache-build/debug/deps",
            mapper
                .to_input_root(Path::new("target/debug/deps"))
                .unwrap()
        );
        assert_eq!(
            None,
            mapper.to_input_root(Path::new("/ws/target/../src/lib.rs"))
        );
        assert_eq!(None, mapper.to_input_root(Path::new("/elsewhere/x.rs")));
        assert_eq!(None, mapper.to_input_root(Path::new("../x.rs")));
        assert_eq!(None, mapper.to_input_root(Path::new(".sccache-build/x.rs")));
    }

    #[cfg(unix)]
    #[test]
    fn test_non_utf8_paths_dont_map() {
        use std::os::unix::ffi::OsStrExt;
        let mapper = path_mapper();
        let name = std::ffi::OsStr::from_bytes(b"\xff.rs");
        assert_eq!(None, mapper.to_input_root(&Path::new("/ws/src").join(name)));
        assert_eq!(
            None,
            mapper.to_input_root(&Path::new("/ws/target").join(name))
        );
    }

    #[test]
    fn test_normalized_roots_and_external_build_root() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path().join("ws/./");
        let build_root = dir.path().join("build/./");
        let mapper = PathMapper::new(cwd.clone(), build_root.clone());
        assert_eq!(Some(".".to_owned()), mapper.to_input_root(&cwd));
        assert_eq!(
            Some(BUILD_ROOT_DIR.to_owned()),
            mapper.to_input_root(&build_root)
        );
        assert_eq!(
            Some("src/lib.rs".to_owned()),
            mapper.to_input_root(Path::new("src/./lib.rs"))
        );
        assert_eq!(
            Some(".sccache-build/debug/lib.rlib".to_owned()),
            mapper.to_input_root(&build_root.join("debug/./lib.rlib"))
        );
    }

    #[test]
    fn test_root_boundaries_and_reserved_namespace() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path().join("ws");
        let mapper = PathMapper::new(cwd.clone(), cwd.join("target"));
        assert_eq!(
            None,
            mapper.to_input_root(&dir.path().join("ws-other/lib.rs"))
        );
        assert_eq!(
            Some("target-other/lib.rlib".to_owned()),
            mapper.to_input_root(Path::new("target-other/lib.rlib"))
        );
        for path in [".sccache-build", ".sccache-build/lib.rlib"] {
            assert_eq!(None, mapper.to_input_root(Path::new(path)));
        }
        for path in [".sccache-build-other/lib.rs", "src/.sccache-build/lib.rs"] {
            assert_eq!(Some(path.to_owned()), mapper.to_input_root(Path::new(path)));
        }
    }

    #[test_case("../lib.rs")]
    #[test_case("src/../lib.rs")]
    #[test_case("target/../src/lib.rs")]
    #[test_case("../../ws/lib.rs")]
    fn test_parent_traversal_is_rejected(path: &str) {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path().join("ws");
        let mapper = PathMapper::new(cwd.clone(), cwd.join("target"));
        assert_eq!(None, mapper.to_input_root(Path::new(path)));
        assert_eq!(None, mapper.to_input_root(&cwd.join(path)));
    }

    #[test]
    fn test_relative_and_parent_containing_roots_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path().join("ws");
        let build_root = cwd.join("target");
        for mapper in [
            PathMapper::new("ws".into(), build_root.clone()),
            PathMapper::new(cwd.clone(), "target".into()),
            PathMapper::new(cwd.join("../ws"), build_root),
            PathMapper::new(cwd.clone(), cwd.join("target/../target")),
        ] {
            assert_eq!(None, mapper.to_input_root(Path::new("src/lib.rs")));
        }
    }

    #[test]
    fn test_mapping_is_independent_of_checkout_location() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a");
        let b = dir.path().join("different/b");
        let first = PathMapper::new(a.clone(), a.join("target"));
        let second = PathMapper::new(b.clone(), b.join("target"));
        for path in ["src/lib.rs", "target/debug/deps/libfoo.rlib"] {
            assert_eq!(
                first.to_input_root(&a.join(path)),
                second.to_input_root(&b.join(path))
            );
        }
    }

    #[test]
    fn test_mapped_paths_form_an_input_root() {
        use crate::reapi::digest;
        use crate::reapi::input_root::{InputRoot, InputRootFile};

        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path().join("ws");
        let mapper = PathMapper::new(cwd.clone(), cwd.join("target"));
        let files: Vec<_> = ["src/lib.rs", "target/debug/deps/libfoo.rlib"]
            .into_iter()
            .map(|path| InputRootFile {
                path: mapper.to_input_root(&cwd.join(path)).unwrap(),
                digest: digest::of_bytes(path.as_bytes()),
                is_executable: false,
            })
            .collect();
        assert_eq!("src/lib.rs", files[0].path);
        assert_eq!(".sccache-build/debug/deps/libfoo.rlib", files[1].path);
        assert!(InputRoot::build(&files).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn test_symlink_parent_traversal_is_not_collapsed() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let cwd = root.join("ws");
        let outside = root.join("outside");
        std::fs::create_dir(&cwd).unwrap();
        std::fs::create_dir_all(outside.join("nested")).unwrap();
        std::fs::write(cwd.join("file.rs"), b"inside").unwrap();
        std::fs::write(outside.join("file.rs"), b"outside").unwrap();
        symlink(outside.join("nested"), cwd.join("link")).unwrap();
        let path = cwd.join("link/../file.rs");
        assert_eq!(outside.join("file.rs"), path.canonicalize().unwrap());
        let mapper = PathMapper::new(cwd.clone(), cwd.join("target"));
        assert_eq!(None, mapper.to_input_root(&path));
        assert_eq!(None, mapper.to_input_root(Path::new("link/../file.rs")));
    }

    #[cfg(windows)]
    #[test]
    fn test_windows_paths_use_input_root_separators() {
        let mapper = PathMapper::new(r"C:\ws".into(), r"C:\ws\target".into());
        assert_eq!(
            Some("src/lib.rs".to_owned()),
            mapper.to_input_root(Path::new(r"C:\ws\src\lib.rs"))
        );
        assert_eq!(
            Some(".sccache-build/debug/lib.rlib".to_owned()),
            mapper.to_input_root(Path::new(r"C:\ws\target\debug\lib.rlib"))
        );
        assert_eq!(None, mapper.to_input_root(Path::new(r"D:\outside\lib.rs")));
        assert_eq!(None, mapper.to_input_root(Path::new(r"C:lib.rs")));
    }
}
