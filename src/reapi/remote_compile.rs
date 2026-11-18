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

//! A Rust compile's REAPI command and toolchain files.

use super::digest::DigestCache;
use super::input_root::InputRootFile;
use super::mapping::{
    BUILD_ROOT_DIR, ReapiCompile, TOOLCHAIN_DIR, input_root_path, normalize_absolute,
};
use super::proto::build::bazel::remote::execution::v2 as remexec;
use crate::errors::*;
use std::collections::HashSet;
use std::fs;
use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};
use walkdir::WalkDir;

/// Starts the stderr line where the worker reports the worker root.
const WORKER_ROOT_MARKER: &str = "sccache-reapi-pwd:";

/// Uses a shell wrapper to expand paths under the worker's physical execution root.
pub(super) fn build_command(compile: &ReapiCompile) -> Result<remexec::Command> {
    // Physical paths must match rustc's paths for remapping and output restoration.
    let mut script = format!(
        "set -e\ncd -P .\nPWD=$(pwd -P)\nprintf '{WORKER_ROOT_MARKER}%s\\n' \"$PWD\" >&2\n"
    );
    // Path-variable and unset names are inserted into shell syntax.
    let mut names = HashSet::new();
    for name in compile
        .env
        .vars
        .iter()
        .chain(&compile.env.path_vars)
        .map(|(name, _)| name)
        .chain(&compile.env.unset_vars)
    {
        if !is_identifier(name) {
            bail!("invalid environment variable name {name:?}");
        }
        if !names.insert(name) {
            bail!("duplicate environment variable name {name:?}");
        }
    }
    let mut unset_vars = compile.env.unset_vars.clone();
    unset_vars.sort();
    if !unset_vars.is_empty() {
        script.push_str(&format!("unset {}\n", unset_vars.join(" ")));
    }
    let mut path_vars = compile.env.path_vars.clone();
    path_vars.sort();
    for (name, path) in &path_vars {
        script.push_str(&format!("export {name}=\"$PWD\"/{}\n", sh_quote(path)));
    }
    let mapped_crate_root_arg = match &compile.mapped_crate_root {
        Some(path) => format!(" \"$PWD\"/{}", sh_quote(path)),
        None => String::new(),
    };
    // Set both paths explicitly for workers that materialize executables through CAS links.
    // rustc uses the last matching remap, so the build-root mapping comes last.
    script.push_str(&format!(
        "export LD_LIBRARY_PATH=\"$PWD\"/{TOOLCHAIN_DIR}/lib DYLD_LIBRARY_PATH=\"$PWD\"/{TOOLCHAIN_DIR}/lib\n\
         exec \"$PWD\"/{TOOLCHAIN_DIR}/bin/rustc --sysroot \"$PWD\"/{TOOLCHAIN_DIR} \"$@\"{mapped_crate_root_arg} \
         --remap-path-prefix=\"$PWD\"=. --remap-path-prefix=\"$PWD\"/{BUILD_ROOT_DIR}={BUILD_ROOT_DIR}\n"
    ));
    let mut arguments = vec![
        "/bin/sh".to_owned(),
        "-c".to_owned(),
        script,
        "rustc".to_owned(),
    ];
    arguments.extend(compile.arguments.iter().cloned());
    // REAPI requires both lists sorted.
    let mut vars = compile.env.vars.clone();
    vars.sort();
    let mut output_paths = command_output_paths(compile)?;
    output_paths.sort();
    output_paths.dedup();
    Ok(remexec::Command {
        arguments,
        environment_variables: vars
            .into_iter()
            .map(|(name, value)| remexec::command::EnvironmentVariable { name, value })
            .collect(),
        output_paths,
        ..Default::default()
    })
}

fn command_output_paths(compile: &ReapiCompile) -> Result<Vec<String>> {
    compile
        .outputs
        .iter()
        .map(|output| {
            compile
                .path_mapper
                .to_input_root(output)
                .filter(|path| path != "." && path != BUILD_ROOT_DIR)
                .with_context(|| format!("invalid output path {}", output.display()))
        })
        .collect()
}

fn is_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// rustc, its shared libraries, and `target_triple`'s std and bundled linker from
/// `sysroot`, as input root files under [`TOOLCHAIN_DIR`] paired with their local paths.
/// Hashing and directory traversal block; call from a blocking thread.
pub(super) fn toolchain_files(
    sysroot: &Path,
    target_triple: &str,
    digest_cache: &DigestCache,
) -> Result<Vec<(InputRootFile, PathBuf)>> {
    let sysroot = normalize_absolute(sysroot)
        .context("the toolchain sysroot must be absolute and contain no parent components")?;
    let mut components = Path::new(target_triple).components();
    if !matches!(components.next(), Some(Component::Normal(_)))
        || components.next().is_some()
        || target_triple.contains(['/', '\\'])
    {
        bail!("invalid toolchain target triple");
    }
    let mut files = vec![];
    let mut add = |local_path: PathBuf, is_executable: bool| -> Result<()> {
        let path_in_sysroot = local_path
            .strip_prefix(&sysroot)
            .with_context(|| format!("{} outside {}", local_path.display(), sysroot.display()))?;
        let path_in_sysroot = input_root_path(path_in_sysroot)
            .with_context(|| format!("non-UTF-8 toolchain path {}", local_path.display()))?;
        // Flatten symlinks while preserving their names in the worker layout.
        let digest = digest_cache.digest_and_pin(&local_path)?;
        let file = InputRootFile {
            path: format!("{TOOLCHAIN_DIR}/{path_in_sysroot}"),
            digest,
            is_executable,
        };
        files.push((file, local_path));
        Ok(())
    };
    let rustc = sysroot.join("bin/rustc");
    if !fs::metadata(&rustc)
        .with_context(|| format!("no rustc in {}", sysroot.display()))?
        .is_file()
    {
        bail!("{} is not a regular file", rustc.display());
    }
    add(rustc, true)?;
    // Sanitizer runtimes alongside these libraries aren't needed to compile rlibs.
    let lib_dir = sysroot.join("lib");
    let listing_context = || format!("failed to list {}", lib_dir.display());
    for entry in fs::read_dir(&lib_dir).with_context(listing_context)? {
        let entry = entry.with_context(listing_context)?;
        let name = entry.file_name();
        let name = name.as_encoded_bytes();
        let is_rustc_library = name.starts_with(b"librustc_driver") || name.starts_with(b"libLLVM");
        if !is_rustc_library {
            continue;
        }
        let path = entry.path();
        if fs::metadata(&path)
            .with_context(|| format!("reading toolchain library {}", path.display()))?
            .is_file()
        {
            add(path, false)?;
        }
    }
    let target_triple_dir = sysroot.join("lib/rustlib").join(target_triple);
    let std_dir = target_triple_dir.join("lib");
    if !fs::metadata(&std_dir)
        .with_context(|| format!("{} has no std for {target_triple}", sysroot.display()))?
        .is_dir()
    {
        bail!("{} has no std for {target_triple}", sysroot.display());
    }
    for entry in WalkDir::new(&std_dir).follow_links(true) {
        let entry =
            entry.with_context(|| format!("walking toolchain directory {}", std_dir.display()))?;
        if entry.file_type().is_file() {
            add(entry.into_path(), false)?;
        }
    }
    // Include rust-lld and any companion files when the target ships a linker.
    let linker_dir = target_triple_dir.join("bin");
    match fs::metadata(&linker_dir) {
        Ok(metadata) => {
            if !metadata.is_dir() {
                bail!("{} is not a directory", linker_dir.display());
            }
            for entry in WalkDir::new(&linker_dir).follow_links(true) {
                let entry = entry.with_context(|| {
                    format!("walking toolchain directory {}", linker_dir.display())
                })?;
                if entry.file_type().is_file() {
                    add(entry.into_path(), true)?;
                }
            }
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => {
            return Err(e)
                .with_context(|| format!("reading toolchain directory {}", linker_dir.display()));
        }
    }
    files.sort_by(|(a, _), (b, _)| a.path.cmp(&b.path));
    Ok(files)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::reapi::{ActionEnv, PathMapper};
    #[cfg(unix)]
    use std::os::unix::fs::{PermissionsExt, symlink};
    #[cfg(unix)]
    use std::process::Command;
    use test_case::test_case;

    const RLIB: &str = ".sccache-build/debug/deps/libfoo.rlib";
    const RMETA: &str = ".sccache-build/debug/deps/libfoo.rmeta";

    fn reapi_compile_in(cwd: &str) -> ReapiCompile {
        #[cfg(windows)]
        let absolute_cwd = format!("C:{cwd}");
        #[cfg(windows)]
        let cwd = absolute_cwd.as_str();
        ReapiCompile {
            path_mapper: PathMapper::new(cwd.into(), format!("{cwd}/target").into()),
            arguments: vec!["--crate-name=foo".to_owned()],
            mapped_crate_root: Some("src/lib.rs".to_owned()),
            target_triple: "x86_64-unknown-linux-gnu".to_owned(),
            env: ActionEnv {
                vars: vec![
                    ("CARGO_PKG_VERSION".to_owned(), "1.0.0".to_owned()),
                    ("CARGO_CRATE_NAME".to_owned(), "foo".to_owned()),
                ],
                path_vars: vec![
                    (
                        "OUT_DIR".to_owned(),
                        ".sccache-build/debug/build/foo-1/out".to_owned(),
                    ),
                    ("CARGO_MANIFEST_DIR".to_owned(), ".".to_owned()),
                ],
                unset_vars: vec!["HOSTNAME".to_owned(), "GIT_HASH".to_owned()],
            },
            input_root_files: vec![],
            outputs: vec![
                format!("{cwd}/target/debug/deps/libfoo.rmeta").into(),
                format!("{cwd}/target/debug/deps/libfoo.rlib").into(),
            ],
        }
    }

    #[test]
    fn test_the_command_doesnt_depend_on_the_checkout_path() {
        assert_eq!(
            build_command(&reapi_compile_in("/home/a/ws")).unwrap(),
            build_command(&reapi_compile_in("/srv/b/ws")).unwrap()
        );
    }

    #[test]
    fn test_the_command_sorts_its_outputs_and_vars() {
        let command = build_command(&reapi_compile_in("/ws")).unwrap();
        assert_eq!([RLIB, RMETA], command.output_paths.as_slice());
        let var_names: Vec<&str> = command
            .environment_variables
            .iter()
            .map(|var| var.name.as_str())
            .collect();
        assert_eq!(
            ["CARGO_CRATE_NAME", "CARGO_PKG_VERSION"],
            var_names.as_slice()
        );
    }

    #[test]
    fn test_the_script_sets_path_vars_under_the_worker_root() {
        let command = build_command(&reapi_compile_in("/ws")).unwrap();
        let script = &command.arguments[2];
        assert!(
            script.contains(
                "unset GIT_HASH HOSTNAME\n\
                 export CARGO_MANIFEST_DIR=\"$PWD\"/'.'\n\
                 export OUT_DIR=\"$PWD\"/'.sccache-build/debug/build/foo-1/out'\n"
            ),
            "{script}"
        );
    }

    #[cfg(unix)]
    #[test_case(true ; "absolute crate root")]
    #[test_case(false ; "relative crate root")]
    fn test_the_command_runs_rustc_with_worker_paths(absolute_crate_root: bool) {
        let dir = tempfile::Builder::new()
            .prefix("worker's $root; ")
            .tempdir()
            .unwrap();
        let worker_root = dir.path().canonicalize().unwrap();
        let alias = worker_root.join("alias");
        symlink(&worker_root, &alias).unwrap();
        let rustc = worker_root.join(".sccache-toolchain/bin/rustc");
        fs::create_dir_all(rustc.parent().unwrap()).unwrap();
        // A fake rustc in a shell that doesn't set GIT_HASH itself, as bash does HOSTNAME.
        fs::write(
            &rustc,
            "#!/bin/sh\nprintf '%s\\n' \"$@\" \"OUT_DIR=$OUT_DIR\" \"GIT_HASH=${GIT_HASH-unset}\" \
             \"LD_LIBRARY_PATH=$LD_LIBRARY_PATH\" \"CARGO_PKG_VERSION=$CARGO_PKG_VERSION\"\n",
        )
        .unwrap();
        fs::set_permissions(&rustc, fs::Permissions::from_mode(0o755)).unwrap();
        let mut compile = reapi_compile_in("/home/a/ws");
        let crate_root = "src/lib '$(touch injected).rs";
        compile.mapped_crate_root = absolute_crate_root.then(|| crate_root.to_owned());
        let arg = "--cfg=value=\"a b;$HOME'$(touch injected)\"";
        compile.arguments.push(arg.to_owned());
        if !absolute_crate_root {
            compile.arguments.push(crate_root.to_owned());
        }
        let out_dir = ".sccache-build/out '$(touch injected)";
        compile.env.path_vars[0].1 = out_dir.to_owned();
        let version = "1.0 ' \" $HOME; $(touch injected)";
        compile.env.vars[0].1 = version.to_owned();
        let command = build_command(&compile).unwrap();
        let output = Command::new(&command.arguments[0])
            .args(&command.arguments[1..])
            .current_dir(&alias)
            .env_clear()
            .envs(
                command
                    .environment_variables
                    .iter()
                    .map(|v| (&v.name, &v.value)),
            )
            .env("PWD", &alias)
            .env("GIT_HASH", "abc")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let w = worker_root.display();
        let crate_root = if absolute_crate_root {
            format!("{w}/{crate_root}")
        } else {
            crate_root.to_owned()
        };
        assert_eq!(
            format!(
                "--sysroot\n{w}/.sccache-toolchain\n--crate-name=foo\n{arg}\n{crate_root}\n\
                 --remap-path-prefix={w}=.\n\
                 --remap-path-prefix={w}/.sccache-build=.sccache-build\n\
                 OUT_DIR={w}/{out_dir}\nGIT_HASH=unset\n\
                 LD_LIBRARY_PATH={w}/.sccache-toolchain/lib\nCARGO_PKG_VERSION={version}\n"
            ),
            String::from_utf8(output.stdout).unwrap()
        );
        assert_eq!(
            format!("{WORKER_ROOT_MARKER}{w}\n"),
            String::from_utf8(output.stderr).unwrap()
        );
        assert!(!worker_root.join("injected").exists());
    }

    #[test]
    fn test_command_ordering_and_duplicate_outputs_are_canonical() {
        let compile = reapi_compile_in("/ws");
        let command = build_command(&compile).unwrap();
        let mut reordered = compile;
        reordered.env.vars.reverse();
        reordered.env.path_vars.reverse();
        reordered.env.unset_vars.reverse();
        reordered.outputs.reverse();
        reordered.outputs.push(reordered.outputs[0].clone());
        assert_eq!(command, build_command(&reordered).unwrap());
    }

    #[test_case("/outside/output" ; "outside root")]
    #[test_case(".sccache-toolchain/output" ; "reserved namespace")]
    #[test_case("target/../output" ; "parent component")]
    #[test_case("." ; "working directory")]
    #[test_case("target" ; "build directory")]
    fn test_invalid_outputs_are_rejected(path: &str) {
        let mut compile = reapi_compile_in("/ws");
        compile.outputs.push(path.into());
        assert!(
            build_command(&compile)
                .unwrap_err()
                .to_string()
                .contains("invalid output path")
        );
    }

    #[test_case("plain")]
    #[test_case("path")]
    #[test_case("unset")]
    fn test_invalid_environment_names_are_rejected_without_values(kind: &str) {
        let mut compile = reapi_compile_in("/ws");
        match kind {
            "plain" => compile
                .env
                .vars
                .push(("INVALID-NAME".into(), "private-value".into())),
            "path" => compile
                .env
                .path_vars
                .push(("INVALID-NAME".into(), "private-value".into())),
            "unset" => compile.env.unset_vars.push("INVALID-NAME".into()),
            _ => unreachable!(),
        }
        let error = build_command(&compile).unwrap_err().to_string();
        assert!(error.contains("INVALID-NAME"), "{error}");
        assert!(!error.contains("private-value"), "{error}");
    }

    #[test]
    fn test_conflicting_environment_inputs_are_rejected_without_values() {
        let mut compile = reapi_compile_in("/ws");
        compile
            .env
            .vars
            .push(("OUT_DIR".into(), "private-value".into()));
        let error = build_command(&compile).unwrap_err().to_string();
        assert!(
            error.contains("duplicate environment variable name"),
            "{error}"
        );
        assert!(!error.contains("private-value"), "{error}");
    }

    #[test]
    fn test_sh_quote() {
        assert_eq!(r"'it'\''s'", sh_quote("it's"));
    }

    fn fake_sysroot(dir: &Path) -> PathBuf {
        let sysroot = dir.join("sysroot");
        for path in [
            "bin/rustc",
            "lib/librustc_driver-x.so",
            "lib/libLLVM.so.1",
            "lib/librustc-stable_rt.asan.so",
            "lib/rustlib/x86_64-unknown-linux-gnu/lib/libstd-x.rlib",
            "lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld",
        ] {
            let contents = path.as_bytes();
            let path = sysroot.join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, contents).unwrap();
        }
        sysroot
    }

    #[cfg(unix)]
    #[test]
    fn test_toolchain_files_are_rustc_its_libraries_std_and_linker() {
        let dir = tempfile::tempdir().unwrap();
        let sysroot = fake_sysroot(dir.path());
        let target_triple_dir = "lib/rustlib/x86_64-unknown-linux-gnu";
        // A std file symlinked from outside the sysroot.
        let linked = dir.path().join("store/libcore-x.rlib");
        fs::create_dir_all(linked.parent().unwrap()).unwrap();
        fs::write(&linked, b"core").unwrap();
        symlink(
            &linked,
            sysroot.join(target_triple_dir).join("lib/libcore-x.rlib"),
        )
        .unwrap();
        let digest_cache = DigestCache::load(dir.path().join("digests"));

        let entries = toolchain_files(&sysroot, "x86_64-unknown-linux-gnu", &digest_cache).unwrap();
        for (file, local_path) in &entries {
            assert_eq!(
                file.digest,
                crate::reapi::digest::of_file(local_path).unwrap()
            );
        }
        let files: Vec<_> = entries
            .into_iter()
            .map(|(file, _)| (file.path, file.is_executable))
            .collect();
        let expected = [
            (".sccache-toolchain/bin/rustc".to_owned(), true),
            (".sccache-toolchain/lib/libLLVM.so.1".to_owned(), false),
            (
                ".sccache-toolchain/lib/librustc_driver-x.so".to_owned(),
                false,
            ),
            (
                format!(".sccache-toolchain/{target_triple_dir}/bin/rust-lld"),
                true,
            ),
            (
                format!(".sccache-toolchain/{target_triple_dir}/lib/libcore-x.rlib"),
                false,
            ),
            (
                format!(".sccache-toolchain/{target_triple_dir}/lib/libstd-x.rlib"),
                false,
            ),
        ];
        assert_eq!(expected.as_slice(), files.as_slice());
    }

    #[test]
    fn test_a_sysroot_without_the_targets_std_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let sysroot = fake_sysroot(dir.path());
        let digest_cache = DigestCache::load(dir.path().join("digests"));
        let e = toolchain_files(&sysroot, "aarch64-apple-darwin", &digest_cache).unwrap_err();
        assert!(e.to_string().contains("has no std"), "{e:#}");
    }

    #[test]
    fn test_a_sysroot_without_rustc_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let sysroot = fake_sysroot(dir.path());
        fs::remove_file(sysroot.join("bin/rustc")).unwrap();
        let digest_cache = DigestCache::load(dir.path().join("digests"));
        let e = toolchain_files(&sysroot, "x86_64-unknown-linux-gnu", &digest_cache).unwrap_err();
        assert!(e.to_string().contains("no rustc"), "{e:#}");
    }

    #[test]
    fn test_toolchain_input_root_is_independent_of_sysroot_location() {
        use crate::reapi::input_root::InputRoot;

        let dir = tempfile::tempdir().unwrap();
        let cache = DigestCache::load(dir.path().join("digests"));
        let root_digest = |location: &str| {
            let sysroot = fake_sysroot(&dir.path().join(location));
            let files: Vec<_> = toolchain_files(&sysroot, "x86_64-unknown-linux-gnu", &cache)
                .unwrap()
                .into_iter()
                .map(|(file, _)| file)
                .collect();
            InputRoot::build(&files).unwrap().digest
        };
        assert_eq!(root_digest("first"), root_digest("second/elsewhere"));
    }

    #[test]
    fn test_toolchain_without_a_linker_excludes_other_targets() {
        let dir = tempfile::tempdir().unwrap();
        let sysroot = fake_sysroot(dir.path());
        fs::remove_dir_all(sysroot.join("lib/rustlib/x86_64-unknown-linux-gnu/bin")).unwrap();
        let other = sysroot.join("lib/rustlib/aarch64-unknown-linux-gnu/lib");
        fs::create_dir_all(&other).unwrap();
        fs::write(other.join("libstd-other.rlib"), b"other target").unwrap();
        let cache = DigestCache::load(dir.path().join("digests"));
        let files = toolchain_files(&sysroot, "x86_64-unknown-linux-gnu", &cache).unwrap();
        assert_eq!(files.len(), 4);
        assert!(files.iter().all(|(file, _)| !file.path.contains("aarch64") && !file.path.ends_with("rust-lld")));
    }

    #[test_case("" ; "empty")]
    #[test_case("." ; "current directory")]
    #[test_case(".." ; "parent directory")]
    #[test_case("../other" ; "parent traversal")]
    #[test_case("/outside" ; "absolute")]
    #[test_case("a/b" ; "slash")]
    #[test_case("a\\b" ; "backslash")]
    fn test_invalid_target_paths_are_rejected(target: &str) {
        let dir = tempfile::tempdir().unwrap();
        let cache = DigestCache::load(dir.path().join("digests"));
        let error = toolchain_files(dir.path(), target, &cache).unwrap_err();
        assert_eq!(error.to_string(), "invalid toolchain target triple");
    }

    #[test]
    fn test_sysroot_must_be_absolute_and_parent_free() {
        let dir = tempfile::tempdir().unwrap();
        let cache = DigestCache::load(dir.path().join("digests"));
        for path in [PathBuf::from("sysroot"), dir.path().join("../sysroot")] {
            let error = toolchain_files(&path, "x86_64-unknown-linux-gnu", &cache).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("must be absolute and contain no parent components"),
                "{error:#}"
            );
        }
    }

    // macOS rejects invalid UTF-8 filenames during fixture creation.
    #[cfg(target_os = "linux")]
    #[test_case("driver")]
    #[test_case("std")]
    fn test_non_utf8_toolchain_files_are_rejected(kind: &str) {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let dir = tempfile::tempdir().unwrap();
        let sysroot = fake_sysroot(dir.path());
        let parent = match kind {
            "driver" => sysroot.join("lib"),
            "std" => sysroot.join("lib/rustlib/x86_64-unknown-linux-gnu/lib"),
            _ => unreachable!(),
        };
        fs::write(
            parent.join(OsStr::from_bytes(b"librustc_driver-\xff.so")),
            b"lib",
        )
        .unwrap();
        let cache = DigestCache::load(dir.path().join("digests"));
        let error = toolchain_files(&sysroot, "x86_64-unknown-linux-gnu", &cache).unwrap_err();
        assert!(
            error.to_string().contains("non-UTF-8 toolchain path"),
            "{error:#}"
        );
    }

    #[cfg(unix)]
    #[test_case("driver")]
    #[test_case("std loop")]
    #[test_case("linker loop")]
    fn test_broken_toolchain_links_are_errors(kind: &str) {
        let dir = tempfile::tempdir().unwrap();
        let sysroot = fake_sysroot(dir.path());
        let target = sysroot.join("lib/rustlib/x86_64-unknown-linux-gnu");
        match kind {
            "driver" => {
                let driver = sysroot.join("lib/librustc_driver-x.so");
                fs::remove_file(&driver).unwrap();
                symlink("missing.so", driver).unwrap();
            }
            "std loop" => symlink(".", target.join("lib/loop")).unwrap(),
            "linker loop" => symlink(".", target.join("bin/loop")).unwrap(),
            _ => unreachable!(),
        }
        let cache = DigestCache::load(dir.path().join("digests"));
        let error = toolchain_files(&sysroot, "x86_64-unknown-linux-gnu", &cache).unwrap_err();
        let expected = if kind == "driver" {
            "reading toolchain library"
        } else {
            "walking toolchain directory"
        };
        assert!(error.to_string().contains(expected), "{error:#}");
    }
}
