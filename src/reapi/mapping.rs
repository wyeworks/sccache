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

use crate::errors::*;
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

/// The input root's directory for files under the local build root.
pub(super) const BUILD_ROOT_DIR: &str = ".sccache-build";
pub(super) const TOOLCHAIN_DIR: &str = ".sccache-toolchain";

#[derive(Debug)]
pub struct ReapiCompile {
    pub(crate) path_mapper: PathMapper,
    pub(crate) arguments: Vec<String>,
    /// Absolute crate-root arguments must remain absolute on the worker: rustc
    /// preserves their spelling in its outputs. These are passed separately.
    pub(crate) mapped_crate_root: Option<String>,
    pub(crate) target_triple: String,
    pub(crate) env: ActionEnv,
    pub(crate) input_root_files: Vec<PathBuf>,
    pub(crate) outputs: Vec<PathBuf>,
}

#[derive(Debug, Default, PartialEq)]
pub(crate) struct ActionEnv {
    pub(crate) vars: Vec<(String, String)>,
    /// Input-root-relative paths, expanded to absolute worker paths by the command.
    pub(crate) path_vars: Vec<(String, String)>,
    /// Preserve missing option_env! values even if the worker environment defines them.
    pub(crate) unset_vars: Vec<String>,
}

#[derive(Debug)]
pub struct NotEligible {
    pub(crate) reason: CompileLocallyReason,
    pub(crate) detail: Option<Error>,
}

impl NotEligible {
    pub(crate) fn new(reason: CompileLocallyReason, detail: Error) -> Self {
        NotEligible {
            reason,
            detail: Some(detail),
        }
    }
}

impl From<CompileLocallyReason> for NotEligible {
    fn from(reason: CompileLocallyReason) -> Self {
        NotEligible {
            reason,
            detail: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CompileLocallyReason {
    NotRust,
    RustcDriver,
    WindowsClient,
    Staticlib,
    UnexpectedCargoLayout,
    PathOutsideInputRoot,
    SourceOutsideInputRoot,
    AbsolutePathInOption,
    CustomTargetSpec,
    NativeCpu,
    ProfileUse,
    RemapPathPrefix,
    NonUtf8EnvVar,
    UnsupportedEnvVarName,
    UnreadableDependencies,
}

impl std::fmt::Display for CompileLocallyReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NotRust => "not a Rust compile",
            Self::RustcDriver => "not rustc",
            Self::WindowsClient => "Windows client",
            Self::Staticlib => "staticlib crate type",
            Self::UnexpectedCargoLayout => "unexpected cargo dir layout",
            Self::PathOutsideInputRoot => "path outside the cwd and build root",
            Self::SourceOutsideInputRoot => "source file outside the cwd and build root",
            Self::AbsolutePathInOption => "absolute path in a -C or -Z option",
            Self::CustomTargetSpec => "custom target spec",
            Self::NativeCpu => "-C target-cpu=native or -Z tune-cpu=native",
            Self::ProfileUse => "-C profile-use or -C profile-sample-use",
            Self::RemapPathPrefix => "--remap-path-prefix",
            Self::NonUtf8EnvVar => "non-UTF-8 env var",
            Self::UnsupportedEnvVarName => "env var the REAPI command can't pass to rustc",
            Self::UnreadableDependencies => "unreadable dependencies",
        })
    }
}

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
        // These directories are reserved for mapped build outputs and toolchain files.
        if relative.starts_with(BUILD_ROOT_DIR) || relative.starts_with(TOOLCHAIN_DIR) {
            return None;
        }
        let relative = input_root_path(relative)?;
        Some(if relative.is_empty() {
            ".".to_owned()
        } else {
            relative
        })
    }

    /// Checks the inverse mapping before using a server-provided path locally.
    pub(super) fn to_local(&self, path: &str) -> Option<PathBuf> {
        let cwd = normalize_absolute(&self.cwd)?;
        let build_root = normalize_absolute(&self.build_root)?;
        let local = if path == BUILD_ROOT_DIR {
            build_root
        } else if let Some(relative) = path.strip_prefix(&format!("{BUILD_ROOT_DIR}/")) {
            build_root.join(relative)
        } else {
            cwd.join(path)
        };
        let local = normalize_absolute(&local)?;
        (self.to_input_root(&local).as_deref() == Some(path)).then_some(local)
    }

    /// rustc uses the last matching remap, the nested build root must come last.
    pub(crate) fn input_root_remap_args(&self) -> Vec<OsString> {
        let remap = |from: &Path, to: &str| {
            let mut arg = OsString::from("--remap-path-prefix=");
            arg.push(from);
            arg.push("=");
            arg.push(to);
            arg
        };
        vec![
            remap(&self.cwd, "."),
            remap(&self.build_root, BUILD_ROOT_DIR),
        ]
    }

    pub(crate) fn input_root_paths_to_local(&self, text: &[u8]) -> Vec<u8> {
        self.paths_to_local(text, None)
    }

    /// Maps paths under `worker_root`, and input-root-relative paths under
    /// [`BUILD_ROOT_DIR`], in an action's stdout or stderr to local paths. Only the start of
    /// each path changes (the text around it doesn't matter).
    pub(super) fn worker_paths_to_local(&self, text: &[u8], worker_root: &str) -> Vec<u8> {
        if worker_root.is_empty() {
            return text.to_vec();
        }
        self.paths_to_local(text, Some(worker_root.as_bytes()))
    }

    fn paths_to_local(&self, text: &[u8], worker_root: Option<&[u8]>) -> Vec<u8> {
        let cwd = self.cwd.as_os_str().as_encoded_bytes();
        let build_root = self.build_root.as_os_str().as_encoded_bytes();
        let mut out = Vec::with_capacity(text.len());
        let mut i = 0;
        while i < text.len() {
            if !starts_path(&text[..i]) {
                out.push(text[i]);
                i += 1;
                continue;
            }
            let (in_worker_root, path) = match worker_root.and_then(|r| text[i..].strip_prefix(r)) {
                Some([b'/', rest @ ..]) => (true, rest),
                Some(rest) if rest.first().is_none_or(|&b| !is_path_byte(b)) => (true, rest),
                Some(_) | None => (false, &text[i..]),
            };
            let skipped = text.len() - i - path.len();
            if let Some(rest) = path.strip_prefix(BUILD_ROOT_DIR.as_bytes())
                && rest.first().is_none_or(|&b| b == b'/' || !is_path_byte(b))
            {
                out.extend_from_slice(build_root);
                i += skipped + BUILD_ROOT_DIR.len();
            } else if in_worker_root {
                out.extend_from_slice(cwd);
                if worker_root.is_some_and(|r| skipped > r.len()) {
                    out.push(b'/');
                }
                i += skipped;
            } else {
                out.push(text[i]);
                i += 1;
            }
        }
        out
    }
}

fn is_path_byte(b: u8) -> bool {
    !b.is_ascii() || b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-')
}

/// Whether a path can start right after `before`: at the start, after a byte that can't be
/// in a path, or after a terminal color code, which `--color=always` puts before paths.
fn starts_path(before: &[u8]) -> bool {
    match before.last() {
        None => true,
        Some(b'm') => {
            let params = before[..before.len() - 1]
                .iter()
                .rev()
                .take_while(|b| b.is_ascii_digit() || **b == b';')
                .count();
            before[..before.len() - 1 - params].ends_with(b"\x1b[")
        }
        Some(&b) => !is_path_byte(b),
    }
}

pub(crate) fn normalize_absolute(path: &Path) -> Option<PathBuf> {
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

pub(super) fn input_root_path(path: &Path) -> Option<String> {
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
    #[cfg(unix)]
    use crate::reapi::sysroot_copy;
    #[cfg(unix)]
    use crate::test::utils::find_rustc;
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

    #[cfg(unix)]
    #[test]
    fn test_maps_input_root_paths_to_local() {
        let mapper = path_mapper();
        assert_eq!(
            PathBuf::from("/ws/target/debug/deps/libfoo.rlib"),
            mapper
                .to_local(".sccache-build/debug/deps/libfoo.rlib")
                .unwrap()
        );
        assert_eq!(
            PathBuf::from("/ws/src/lib.rs"),
            mapper.to_local("src/lib.rs").unwrap()
        );
    }

    #[cfg(unix)]
    #[test_case(
        "warning: in /up/src/lib.rs\n --> .sccache-build/debug/build/foo-2/out/gen.rs:3:5\n",
        "warning: in /ws/src/lib.rs\n --> /ws/target/debug/build/foo-2/out/gen.rs:3:5\n" ;
        "worker root and build root paths")]
    #[test_case(
        "/up/.sccache-build/debug/deps/libbar.rlib",
        "/ws/target/debug/deps/libbar.rlib" ;
        "build root under the worker root")]
    #[test_case("cd /up: `/up` in /up", "cd /ws: `/ws` in /ws" ; "the worker root itself")]
    #[test_case("\x1b[0m\x1b[1m/up/x", "\x1b[0m\x1b[1m/ws/x" ; "after a color code")]
    #[test_case(
        "/home/up/x /upper/x foo.sccache-build/x",
        "/home/up/x /upper/x foo.sccache-build/x" ;
        "only at the start of a path")]
    fn test_worker_paths_map_to_local(worker_text: &str, local_text: &str) {
        assert_eq!(
            local_text,
            String::from_utf8(path_mapper().worker_paths_to_local(worker_text.as_bytes(), "/up"))
                .unwrap()
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_mapping_worker_paths_keeps_other_bytes() {
        assert_eq!(
            b"\xff /ws/x\xfe".as_slice(),
            path_mapper().worker_paths_to_local(b"\xff /up/x\xfe", "/up")
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
        for path in [
            ".sccache-build",
            ".sccache-build/lib.rlib",
            ".sccache-toolchain",
            ".sccache-toolchain/bin/rustc",
        ] {
            assert_eq!(None, mapper.to_input_root(Path::new(path)));
        }
        for path in [
            ".sccache-build-other/lib.rs",
            "src/.sccache-build/lib.rs",
            ".sccache-toolchain-other/lib.rs",
            "src/.sccache-toolchain/lib.rs",
        ] {
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
    fn test_inverse_mapping_is_checked_and_uses_normalized_roots() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path().join("ws");
        let build = dir.path().join("build");
        let mapper = PathMapper::new(cwd.join("./"), build.join("./"));
        for (remote, local) in [
            (".", cwd.clone()),
            ("src/lib.rs", cwd.join("src/lib.rs")),
            (".sccache-build", build.clone()),
            (
                ".sccache-build/debug/lib.rlib",
                build.join("debug/lib.rlib"),
            ),
        ] {
            assert_eq!(mapper.to_local(remote), Some(local));
        }
        for path in [
            "",
            "../x",
            "a/../x",
            "a/./x",
            "a//x",
            "/outside/x",
            ".sccache-toolchain/bin/rustc",
            ".sccache-build/../x",
            ".sccache-build//x",
        ] {
            assert_eq!(mapper.to_local(path), None, "{path}");
        }
        let mapper = PathMapper::new(cwd.clone(), cwd.join("target"));
        assert_eq!(mapper.to_local("target/x"), None);
    }

    #[cfg(unix)]
    #[test]
    fn test_worker_text_mapping_preserves_unicode_boundaries_and_empty_roots() {
        let mapper = path_mapper();
        let text = "é/up/x /upé/x .sccache-buildé/x /up/日本語.rs";
        assert_eq!(
            mapper.worker_paths_to_local(text.as_bytes(), "/up"),
            "é/up/x /upé/x .sccache-buildé/x /ws/日本語.rs".as_bytes()
        );
        assert_eq!(
            mapper.worker_paths_to_local(b"unchanged /up/x", ""),
            b"unchanged /up/x"
        );
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
    #[test]
    fn test_input_root_remap_puts_the_build_root_last() {
        // `path_mapper()`'s build root is inside its cwd.
        assert_eq!(
            [
                "--remap-path-prefix=/ws=.",
                "--remap-path-prefix=/ws/target=.sccache-build"
            ],
            path_mapper().input_root_remap_args().as_slice()
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_input_root_paths_map_to_local() {
        assert_eq!(
            b"--> /ws/target/debug/build/foo-1/out/gen.rs:3:5 in /up/x".as_slice(),
            path_mapper().input_root_paths_to_local(
                b"--> .sccache-build/debug/build/foo-1/out/gen.rs:3:5 in /up/x"
            )
        );
    }

    // Include the rust-src file rustc probes, even when rust-src isn't installed.
    #[cfg(unix)]
    fn sysroot_with_rust_src(dir: &Path) -> PathBuf {
        let output = std::process::Command::new(find_rustc())
            .args(["--print", "sysroot"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let real = PathBuf::from(String::from_utf8(output.stdout).unwrap().trim());
        let sysroot = dir.join("sysroot");
        for (from, skip) in [("", "lib"), ("lib", "rustlib"), ("lib/rustlib", "src")] {
            std::fs::create_dir_all(sysroot.join(from)).unwrap();
            for entry in std::fs::read_dir(real.join(from)).unwrap() {
                let entry = entry.unwrap();
                if entry.file_name() != skip {
                    std::os::unix::fs::symlink(
                        entry.path(),
                        sysroot.join(from).join(entry.file_name()),
                    )
                    .unwrap();
                }
            }
        }
        let std_root = sysroot.join("lib/rustlib/src/rust/library/std/src/lib.rs");
        std::fs::create_dir_all(std_root.parent().unwrap()).unwrap();
        std::fs::write(std_root, "").unwrap();
        sysroot
    }

    #[cfg(unix)]
    fn compile_remapped(root: &Path, sysroot: &Path) -> Vec<u8> {
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::create_dir_all(root.join("target/debug/deps")).unwrap();
        let out_dir = root.join("target/debug/build/foo/out");
        std::fs::create_dir_all(&out_dir).unwrap();
        std::fs::write(
            out_dir.join("generated.rs"),
            "pub fn generated_source_path() -> &'static str { file!() }\n",
        )
        .unwrap();
        // rustc sees its working directory with symlinks resolved, e.g. macOS's /var as
        // /private/var, and so does cargo.
        let root = &root.canonicalize().unwrap();
        std::fs::write(
            root.join("src/lib.rs"),
            // std's generics, built into the rlib with debuginfo, name std's sources.
            "pub fn source_path() -> &'static str { file!() }\n\
             pub fn strings() -> Vec<String> { vec![format!(\"{}\", 1)] }\n\
             include!(concat!(env!(\"OUT_DIR\"), \"/generated.rs\"));\n",
        )
        .unwrap();
        let path_mapper = PathMapper::new(root.to_owned(), root.join("target"));
        let mut sysroot_arg = OsString::from("--sysroot=");
        sysroot_arg.push(sysroot);
        let status = std::process::Command::new(find_rustc())
            .current_dir(root)
            .env("OUT_DIR", root.join("target/debug/build/foo/out"))
            .args([
                "--crate-name=foo",
                "--crate-type=lib",
                "--edition=2021",
                "-Cdebuginfo=2",
                "-Cmetadata=fixed",
                "--emit=link",
                "-o",
                "target/debug/deps/libfoo.rlib",
                "src/lib.rs",
            ])
            .args(path_mapper.input_root_remap_args())
            .arg(sysroot_arg)
            .status()
            .unwrap();
        assert!(status.success());
        std::fs::read(root.join("target/debug/deps/libfoo.rlib")).unwrap()
    }

    #[cfg(unix)]
    fn names_rust_src(rlib: &[u8]) -> bool {
        memchr::memmem::find(rlib, b"rustlib/src/rust").is_some()
    }

    #[cfg(unix)]
    #[test]
    fn test_remapped_compiles_match_across_checkouts_and_sysroot_copies() {
        let dir = tempfile::tempdir().unwrap();
        let sysroot = sysroot_with_rust_src(dir.path());
        // Outside the checkouts, so the sysroot copies' paths aren't remapped.
        let copy_a = sysroot_copy(&sysroot, &dir.path().join("copies-a")).unwrap();
        let copy_b = sysroot_copy(&sysroot, &dir.path().join("copies-b")).unwrap();
        let a = compile_remapped(&dir.path().join("a/checkout with spaces=one"), &copy_a);
        let b = compile_remapped(&dir.path().join("b/another-checkout"), &copy_b);
        assert!(!names_rust_src(&a), "the rlib names rust-src");
        assert!(a == b, "the rlibs differ");
    }

    #[cfg(unix)]
    #[test]
    fn test_a_sysroot_with_rust_src_puts_it_in_the_rlib() {
        // Shows that the test above would see rust-src if the copy kept it.
        let dir = tempfile::tempdir().unwrap();
        let sysroot = sysroot_with_rust_src(dir.path());
        let rlib = compile_remapped(&dir.path().join("checkout"), &sysroot);
        assert!(names_rust_src(&rlib), "the rlib doesn't name rust-src");
    }

    #[cfg(unix)]
    #[test]
    fn test_local_remapped_rlib_matches_the_worker_command() {
        use crate::reapi::remote_compile::build_command;

        let dir = tempfile::tempdir().unwrap();
        let sysroot = sysroot_with_rust_src(dir.path());
        let copy = sysroot_copy(&sysroot, &dir.path().join("copies")).unwrap();
        let local = dir.path().join("checkout");
        let local_rlib = compile_remapped(&local, &copy);
        let worker = dir.path().join("worker");
        let worker_out = worker.join(".sccache-build/debug/build/foo/out");
        std::fs::create_dir_all(&worker_out).unwrap();
        std::fs::create_dir_all(worker.join("src")).unwrap();
        std::fs::create_dir_all(worker.join(".sccache-build/debug/deps")).unwrap();
        std::fs::copy(local.join("src/lib.rs"), worker.join("src/lib.rs")).unwrap();
        std::fs::copy(
            local.join("target/debug/build/foo/out/generated.rs"),
            worker_out.join("generated.rs"),
        )
        .unwrap();
        std::os::unix::fs::symlink(&copy, worker.join(TOOLCHAIN_DIR)).unwrap();
        let compile = ReapiCompile {
            path_mapper: PathMapper::new(local.clone(), local.join("target")),
            arguments: [
                "--crate-name=foo",
                "--crate-type=lib",
                "--edition=2021",
                "-Cdebuginfo=2",
                "-Cmetadata=fixed",
                "--emit=link",
                "-o",
                ".sccache-build/debug/deps/libfoo.rlib",
                "src/lib.rs",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            mapped_crate_root: None,
            target_triple: String::new(),
            env: ActionEnv {
                path_vars: vec![(
                    "OUT_DIR".into(),
                    ".sccache-build/debug/build/foo/out".into(),
                )],
                ..Default::default()
            },
            input_root_files: vec![],
            outputs: vec![local.join("target/debug/deps/libfoo.rlib")],
        };
        let command = build_command(&compile).unwrap();
        let output = std::process::Command::new(&command.arguments[0])
            .args(&command.arguments[1..])
            .current_dir(&worker)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let remote_rlib =
            std::fs::read(worker.join(".sccache-build/debug/deps/libfoo.rlib")).unwrap();
        assert!(local_rlib == remote_rlib, "local and worker rlibs differ");
    }

    #[cfg(unix)]
    #[test_case(b"x.sccache-build/foo", b"x.sccache-build/foo"; "filename prefix")]
    #[test_case(b"/x/.sccache-build/foo", b"/x/.sccache-build/foo"; "other directory")]
    #[test_case(b".sccache-build-other/foo", b".sccache-build-other/foo"; "similar name")]
    #[test_case(b"\xff.sccache-build/foo", b"\xff.sccache-build/foo"; "non ASCII prefix")]
    #[test_case(b"\x1b[31m.sccache-build/foo\xff", b"\x1b[31m/ws/target/foo\xff"; "color and arbitrary bytes")]
    fn test_local_diagnostic_path_boundaries(text: &[u8], expected: &[u8]) {
        assert_eq!(path_mapper().input_root_paths_to_local(text), expected);
    }
}
