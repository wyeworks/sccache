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

//! Rust worker commands, toolchain inputs and output restoration.

use super::cas::Cas;
use super::digest::{self, DigestCache};
use super::input_root::InputRootFile;
use super::mapping::{
    BUILD_ROOT_DIR, ReapiCompile, TOOLCHAIN_DIR, input_root_path, normalize_absolute,
};
use super::proto::build::bazel::remote::execution::v2 as remexec;
use crate::errors::*;
use crate::mock_command::exit_status;
use memchr::memmem;
use std::collections::HashSet;
use std::fs;
use std::io::{self, ErrorKind, Write};
use std::path::{Component, Path, PathBuf};
use std::process;
use tempfile::{NamedTempFile, TempPath};
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

// Embedded worker paths make binary outputs unusable on the client.
struct WorkerRootScanner<W> {
    inner: W,
    finder: memmem::Finder<'static>,
    // Retain the suffix needed to detect matches spanning writes.
    tail: Vec<u8>,
    contains_worker_root: bool,
}

impl<W: Write> WorkerRootScanner<W> {
    fn new(inner: W, worker_root: &str) -> Self {
        WorkerRootScanner {
            inner,
            finder: memmem::Finder::new(worker_root.as_bytes()).into_owned(),
            tail: vec![],
            contains_worker_root: false,
        }
    }
}

impl<W: Write> Write for WorkerRootScanner<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        let written = &buf[..n];
        if !self.contains_worker_root {
            let tail_len = self.finder.needle().len().saturating_sub(1);
            // Check the overlap between the previous suffix and this write.
            self.tail
                .extend_from_slice(&written[..written.len().min(tail_len)]);
            self.contains_worker_root =
                self.finder.find(&self.tail).is_some() || self.finder.find(written).is_some();
            if written.len() >= tail_len {
                self.tail.clear();
                self.tail
                    .extend_from_slice(&written[written.len() - tail_len..]);
            } else {
                self.tail.drain(..self.tail.len().saturating_sub(tail_len));
            }
        }
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

// Bound downloads; stdout and stderr are held in memory.
const MAX_OUTPUT_FILE_BYTES: u64 = 4 << 30;
const MAX_STDOUT_OR_STDERR_BYTES: u64 = 8 << 20;

/// Error for an output file that contains the worker root, such as one from a crate that
/// embeds `env!("CARGO_MANIFEST_DIR")`.
#[derive(Debug)]
pub(super) struct WorkerRootInOutput(PathBuf);

impl std::fmt::Display for WorkerRootInOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} contains the worker root", self.0.display())
    }
}

impl std::error::Error for WorkerRootInOutput {}

/// Invalid result metadata or contents.
#[derive(Debug)]
pub(super) struct UnusableResult(String);

impl std::fmt::Display for UnusableResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for UnusableResult {}

/// Local staging or publication failed.
#[derive(Debug)]
pub(super) struct UnwritableOutputs;

impl std::fmt::Display for UnwritableOutputs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("failed to write the outputs to their local paths")
    }
}

impl std::error::Error for UnwritableOutputs {}

// Keep inline bytes and downloaded files separate until all outputs are checked.
enum OutputContents {
    /// Downloaded to a temporary file in its local directory.
    TempFile(TempPath),
    Inline(Vec<u8>),
}

/// Writes `result`'s output files to their local paths once all are downloaded and
/// checked, and returns its stdout and stderr mapped to local paths.
pub(super) async fn materialize(
    cas: &Cas,
    compile: &ReapiCompile,
    result: &remexec::ActionResult,
) -> Result<process::Output> {
    // An exit code that a process can't return, such as 256, would read as success.
    let exit_code = u8::try_from(result.exit_code)
        .map_err(|_| UnusableResult(format!("result has exit code {}", result.exit_code)))?;
    check_output_paths(compile, result)?;
    check_blob(
        &result.stdout_raw,
        result.stdout_digest.as_ref(),
        MAX_STDOUT_OR_STDERR_BYTES,
        "stdout",
    )?;
    check_blob(
        &result.stderr_raw,
        result.stderr_digest.as_ref(),
        MAX_STDOUT_OR_STDERR_BYTES,
        "stderr",
    )?;
    let stdout =
        download_stdout_or_stderr(cas, &result.stdout_raw, result.stdout_digest.as_ref()).await?;
    let stderr =
        download_stdout_or_stderr(cas, &result.stderr_raw, result.stderr_digest.as_ref()).await?;
    let (worker_root, stderr) = take_worker_root(&stderr)?;
    // Finish every download before returning, including cleanup after a sibling fails.
    let output_contents = futures::future::join_all(
        result
            .output_files
            .iter()
            .map(|file| download_output(cas, compile, file, &worker_root)),
    )
    .await
    .into_iter()
    .collect::<Result<Vec<_>>>()?;
    let stdout = compile
        .path_mapper
        .worker_paths_to_local(&stdout, &worker_root);
    let stderr = compile
        .path_mapper
        .worker_paths_to_local(&stderr, &worker_root);
    tokio::task::spawn_blocking(move || write_outputs(output_contents))
        .await
        .context(UnwritableOutputs)??;
    Ok(process::Output {
        status: exit_status_from_code(exit_code),
        stdout,
        stderr,
    })
}

async fn download_stdout_or_stderr(
    cas: &Cas,
    inline: &[u8],
    digest: Option<&remexec::Digest>,
) -> Result<Vec<u8>> {
    match digest {
        Some(digest) if inline.is_empty() && digest.size_bytes > 0 => {
            cas.download_blob(digest, MAX_STDOUT_OR_STDERR_BYTES).await
        }
        _ => Ok(inline.to_vec()),
    }
}

fn check_blob(
    inline: &[u8],
    digest: Option<&remexec::Digest>,
    max_bytes: u64,
    name: &str,
) -> Result<()> {
    if inline.len() as u64 > max_bytes {
        return Err(UnusableResult(format!(
            "result's inline {name} is larger than {max_bytes} bytes"
        ))
        .into());
    }
    if let Some(digest) = digest {
        digest::check(digest)
            .map_err(|_| UnusableResult(format!("result has an invalid digest for {name}")))?;
        if digest.size_bytes as u64 > max_bytes {
            return Err(UnusableResult(format!(
                "result's {name} is larger than {max_bytes} bytes"
            ))
            .into());
        }
        if !inline.is_empty() && digest::of_bytes(inline) != *digest {
            return Err(
                UnusableResult(format!("result's inline {name} doesn't match its digest")).into(),
            );
        }
    }
    Ok(())
}

fn take_worker_root(stderr: &[u8]) -> Result<(String, Vec<u8>)> {
    let mut worker_root = None;
    let mut rest = Vec::with_capacity(stderr.len());
    for line in stderr.split_inclusive(|&b| b == b'\n') {
        match line.strip_prefix(WORKER_ROOT_MARKER.as_bytes()) {
            Some(reported) if worker_root.is_none() => {
                worker_root = Some(reported.strip_suffix(b"\n").unwrap_or(reported));
            }
            _ => rest.extend_from_slice(line),
        }
    }
    // A worker root that isn't UTF-8 couldn't be found in outputs as written.
    let worker_root = worker_root
        .and_then(|r| std::str::from_utf8(r).ok())
        .filter(|r| {
            r.starts_with('/')
                && r.len() > 1
                && !r.chars().any(char::is_control)
                && r[1..]
                    .split('/')
                    .all(|part| !part.is_empty() && part != "." && part != "..")
        })
        .ok_or_else(|| UnusableResult("result doesn't report the worker root".to_owned()))?;
    Ok((worker_root.to_owned(), rest))
}

/// Fails if `result` has outputs other than the files `compile` declares, or lacks an rlib or
/// rmeta that a successful compile writes.
// Servers may also report symlinks in the fields REAPI 2.1 deprecated.
#[allow(deprecated)]
fn check_output_paths(compile: &ReapiCompile, result: &remexec::ActionResult) -> Result<()> {
    if !result.output_directories.is_empty()
        || !result.output_symlinks.is_empty()
        || !result.output_file_symlinks.is_empty()
        || !result.output_directory_symlinks.is_empty()
    {
        return Err(UnusableResult("result has output directories or symlinks".to_owned()).into());
    }
    let declared_paths: HashSet<String> = command_output_paths(compile)?.into_iter().collect();
    let mut returned_paths = HashSet::new();
    for file in &result.output_files {
        if !declared_paths.contains(&file.path) {
            return Err(UnusableResult(format!(
                "result has undeclared output {}",
                file.path.escape_debug()
            ))
            .into());
        }
        if !returned_paths.insert(file.path.as_str()) {
            return Err(UnusableResult(format!("result has output {} twice", file.path)).into());
        }
        let digest = file.digest.as_ref().ok_or_else(|| {
            UnusableResult(format!("result's output {} has no digest", file.path))
        })?;
        check_blob(
            &file.contents,
            Some(digest),
            MAX_OUTPUT_FILE_BYTES,
            &format!("output {}", file.path),
        )?;
    }
    // rustc writes its rlib and rmeta when it succeeds, so a successful result without one
    // would leave a previous build's file at that path.
    if result.exit_code == 0 {
        for output in &compile.outputs {
            if output
                .extension()
                .is_some_and(|e| e == "rlib" || e == "rmeta")
                && let Some(path) = compile.path_mapper.to_input_root(output)
                && !returned_paths.contains(path.as_str())
            {
                return Err(UnusableResult(format!("result lacks output {path}")).into());
            }
        }
    }
    Ok(())
}

async fn download_output(
    cas: &Cas,
    compile: &ReapiCompile,
    file: &remexec::OutputFile,
    worker_root: &str,
) -> Result<(PathBuf, bool, OutputContents)> {
    let digest = file
        .digest
        .as_ref()
        .ok_or_else(|| UnusableResult(format!("result's output {} has no digest", file.path)))?;
    let local_path = compile
        .path_mapper
        .to_local(&file.path)
        .ok_or_else(|| UnusableResult("result has an invalid local output mapping".to_owned()))?;
    if !file.contents.is_empty() {
        if memmem::find(&file.contents, worker_root.as_bytes()).is_some() {
            return Err(WorkerRootInOutput(local_path).into());
        }
        let contents = OutputContents::Inline(file.contents.clone());
        return Ok((local_path, file.is_executable, contents));
    }
    let dir = local_path
        .parent()
        .with_context(|| format!("output {} has no parent directory", local_path.display()))
        .context(UnwritableOutputs)?
        .to_owned();
    let temp_file = tokio::task::spawn_blocking(move || {
        NamedTempFile::new_in(&dir)
            .with_context(|| format!("failed to create a file in {}", dir.display()))
            .context(UnwritableOutputs)
    })
    .await
    .context(UnwritableOutputs)??;
    let temp_file_path = temp_file.path().to_owned();
    let scanner = WorkerRootScanner::new(io::BufWriter::new(temp_file), worker_root);
    let scanner = cas
        .download_blob_into(digest, MAX_OUTPUT_FILE_BYTES, scanner)
        .await?;
    if scanner.contains_worker_root {
        return Err(WorkerRootInOutput(local_path).into());
    }
    let temp_file = scanner
        .inner
        .into_inner()
        .map_err(|e| e.into_error())
        .with_context(|| format!("failed to write {}", temp_file_path.display()))
        .context(UnwritableOutputs)?;
    let contents = OutputContents::TempFile(temp_file.into_temp_path());
    Ok((local_path, file.is_executable, contents))
}

// Clean up this attempt's published files if a subsequent rename fails.
fn write_outputs(output_contents: Vec<(PathBuf, bool, OutputContents)>) -> Result<()> {
    // Prepare all files and permissions before replacing any declared output.
    let prepared = output_contents
        .into_iter()
        .map(|(path, executable, contents)| {
            let temp_path = match contents {
                OutputContents::TempFile(path) => path,
                OutputContents::Inline(data) => write_output(&path, &data)?,
            };
            set_mode(&temp_path, executable)?;
            Ok((path, temp_path))
        })
        .collect::<Result<Vec<_>>>()
        .context(UnwritableOutputs)?;
    let mut written_paths = vec![];
    for (local_path, temp_path) in prepared {
        let write_result = temp_path
            .persist(&local_path)
            .map_err(|e| Error::new(e.error))
            .with_context(|| format!("failed to write {}", local_path.display()));
        if let Err(e) = write_result {
            remove_outputs(&written_paths);
            return Err(e.context(UnwritableOutputs));
        }
        written_paths.push(local_path);
    }
    Ok(())
}

fn write_output(path: &Path, data: &[u8]) -> Result<TempPath> {
    let dir = path
        .parent()
        .with_context(|| format!("output {} has no parent directory", path.display()))?;
    let mut temp_file = NamedTempFile::new_in(dir)
        .with_context(|| format!("failed to create a file in {}", dir.display()))?;
    temp_file
        .write_all(data)
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(temp_file.into_temp_path())
}

// REAPI carries only the executable bit; restore regular files as 0644 or 0755.
fn set_mode(path: &Path, is_executable: bool) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if is_executable { 0o755 } else { 0o644 };
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .with_context(|| format!("failed to set the mode of {}", path.display()))?;
    }
    #[cfg(not(unix))]
    let _ = (path, is_executable);
    Ok(())
}

fn remove_outputs(paths: &[PathBuf]) {
    for path in paths {
        if let Err(e) = fs::remove_file(path) {
            warn!("REAPI: failed to remove the output {}: {e}", path.display());
        }
    }
}

fn exit_status_from_code(exit_code: u8) -> process::ExitStatus {
    // A Unix wait status holds the exit code in bits 8 to 15.
    #[cfg(unix)]
    let raw_status = i32::from(exit_code) << 8;
    #[cfg(windows)]
    let raw_status = u32::from(exit_code);
    exit_status(raw_status)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::reapi::test::FakeServer;
    use crate::reapi::{ActionEnv, PathMapper};
    #[cfg(unix)]
    use std::os::unix::fs::{PermissionsExt, symlink};
    #[cfg(unix)]
    use std::process::Command;
    use std::sync::Arc;
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

    fn cas_output(path: &str, data: &[u8]) -> remexec::OutputFile {
        remexec::OutputFile {
            path: path.to_owned(),
            digest: Some(digest::of_bytes(data)),
            ..Default::default()
        }
    }

    fn inline_output(path: &str, data: &[u8]) -> remexec::OutputFile {
        remexec::OutputFile {
            contents: data.to_vec(),
            ..cas_output(path, data)
        }
    }

    fn worker_result(output_files: Vec<remexec::OutputFile>) -> remexec::ActionResult {
        remexec::ActionResult {
            output_files,
            stderr_raw: format!("{WORKER_ROOT_MARKER}/w/1\nwarning: in /w/1/src/lib.rs\n")
                .into_bytes(),
            ..Default::default()
        }
    }

    fn rlib_and_rmeta_result() -> remexec::ActionResult {
        worker_result(vec![cas_output(RLIB, b"rlib"), cas_output(RMETA, b"rmeta")])
    }

    async fn materialize_in(
        dir: &Path,
        blobs: &[&[u8]],
        result: remexec::ActionResult,
    ) -> Result<process::Output> {
        let server = Arc::new(FakeServer::default());
        for blob in blobs {
            server.insert_blob(blob);
        }
        materialize_from_server(dir, &server, &result).await
    }

    async fn materialize_from_server(
        dir: &Path,
        server: &Arc<FakeServer>,
        result: &remexec::ActionResult,
    ) -> Result<process::Output> {
        // Cargo creates this directory before invoking rustc.
        fs::create_dir_all(dir.join("target/debug/deps")).unwrap();
        let cas = Cas::new(&server.serve_and_connect().await);
        let mut compile = reapi_compile_in("/ws");
        compile.path_mapper = PathMapper::new(dir.to_owned(), dir.join("target"));
        compile.outputs = vec![
            dir.join("target/debug/deps/libfoo.rlib"),
            dir.join("target/debug/deps/libfoo.rmeta"),
        ];
        materialize(&cas, &compile, result).await
    }

    fn output_names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir.join("target/debug/deps"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    #[test_case(cas_output ; "from the CAS")]
    #[test_case(inline_output ; "inline")]
    #[tokio::test]
    async fn test_outputs_are_written_to_their_local_paths(
        output: fn(&str, &[u8]) -> remexec::OutputFile,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let files = vec![output(RLIB, b"rlib"), output(RMETA, b"rmeta")];
        let output = materialize_in(dir.path(), &[b"rlib", b"rmeta"], worker_result(files))
            .await
            .unwrap();
        assert!(output.status.success());
        let deps = dir.path().join("target/debug/deps");
        assert_eq!(
            b"rlib".as_slice(),
            fs::read(deps.join("libfoo.rlib")).unwrap()
        );
        assert_eq!(
            b"rmeta".as_slice(),
            fs::read(deps.join("libfoo.rmeta")).unwrap()
        );
        // No temp files are left behind.
        assert_eq!(2, fs::read_dir(deps).unwrap().count());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_outputs_get_a_local_compiles_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let mut result = rlib_and_rmeta_result();
        result.output_files[0].is_executable = true;
        materialize_in(dir.path(), &[b"rlib", b"rmeta"], result)
            .await
            .unwrap();
        let deps = dir.path().join("target/debug/deps");
        let mode = |name: &str| fs::metadata(deps.join(name)).unwrap().permissions().mode() & 0o777;
        assert_eq!(0o755, mode("libfoo.rlib"));
        assert_eq!(0o644, mode("libfoo.rmeta"));
    }

    #[tokio::test]
    async fn test_stderr_has_local_paths_without_the_worker_root_line() {
        let dir = tempfile::tempdir().unwrap();
        let output = materialize_in(dir.path(), &[b"rlib", b"rmeta"], rlib_and_rmeta_result())
            .await
            .unwrap();
        assert_eq!(
            format!("warning: in {}/src/lib.rs\n", dir.path().display()),
            String::from_utf8(output.stderr).unwrap()
        );
    }

    #[tokio::test]
    async fn test_stdout_and_stderr_can_come_from_the_cas() {
        let dir = tempfile::tempdir().unwrap();
        let stdout = b"in /w/1/src/lib.rs";
        let stderr = format!("{WORKER_ROOT_MARKER}/w/1\n");
        let result = remexec::ActionResult {
            exit_code: 1,
            stdout_digest: Some(digest::of_bytes(stdout)),
            stderr_raw: vec![],
            stderr_digest: Some(digest::of_bytes(stderr.as_bytes())),
            ..worker_result(vec![])
        };
        let output = materialize_in(dir.path(), &[stdout, stderr.as_bytes()], result)
            .await
            .unwrap();
        assert_eq!(
            format!("in {}/src/lib.rs", dir.path().display()),
            String::from_utf8(output.stdout).unwrap()
        );
        assert!(output.stderr.is_empty());
    }

    #[tokio::test]
    async fn test_a_failed_compile_returns_its_exit_code() {
        let dir = tempfile::tempdir().unwrap();
        let result = remexec::ActionResult {
            exit_code: 1,
            ..worker_result(vec![])
        };
        let output = materialize_in(dir.path(), &[], result).await.unwrap();
        assert_eq!(Some(1), output.status.code());
    }

    #[derive(Debug, Clone, Copy)]
    enum InvalidResult {
        ExitCode(i32),
        UndeclaredOutput(&'static str),
        DuplicateOutput,
        Symlink,
        DeprecatedSymlink,
        OutputDirectory,
        MissingRlib,
        MissingDigest,
        InlineDigestMismatch,
        MissingWorkerRoot,
        EmptyWorkerRoot,
        NonUtf8WorkerRoot,
        MissingRmeta,
        OutputPath(&'static str),
        MalformedOutputDigest,
        NegativeOutputSize,
        OversizedOutput,
        OversizedStdout,
        InlineContentsMismatch,
        StdoutDigestMismatch,
    }

    impl InvalidResult {
        #[allow(deprecated)]
        fn apply(self, result: &mut remexec::ActionResult) {
            match self {
                Self::ExitCode(code) => result.exit_code = code,
                Self::UndeclaredOutput(path) => {
                    result.output_files.push(inline_output(path, b"x"));
                }
                Self::DuplicateOutput => result.output_files.push(cas_output(RLIB, b"rmeta")),
                Self::Symlink | Self::DeprecatedSymlink => {
                    let symlink = remexec::OutputSymlink {
                        path: RLIB.to_owned(),
                        target: "/etc/passwd".to_owned(),
                        ..Default::default()
                    };
                    if matches!(self, Self::Symlink) {
                        result.output_symlinks.push(symlink);
                    } else {
                        result.output_file_symlinks.push(symlink);
                    }
                    result.output_files.remove(0);
                }
                Self::OutputDirectory => {
                    result.output_directories.push(remexec::OutputDirectory {
                        path: ".sccache-build".to_owned(),
                        ..Default::default()
                    });
                }
                Self::MissingRlib => {
                    result.output_files.remove(0);
                }
                Self::MissingRmeta => {
                    result.output_files.pop();
                }
                Self::OutputPath(path) => {
                    result.output_files.last_mut().unwrap().path = path.to_owned();
                }
                Self::MalformedOutputDigest => {
                    let file = result.output_files.last_mut().unwrap();
                    file.digest.as_mut().unwrap().hash = "bad/hash".to_owned();
                }
                Self::NegativeOutputSize => {
                    let file = result.output_files.last_mut().unwrap();
                    file.digest.as_mut().unwrap().size_bytes = -1;
                }
                Self::OversizedOutput => {
                    let file = result.output_files.last_mut().unwrap();
                    file.digest.as_mut().unwrap().size_bytes = MAX_OUTPUT_FILE_BYTES as i64 + 1;
                }
                Self::OversizedStdout => {
                    result.stdout_digest = Some(remexec::Digest {
                        hash: "0".repeat(64),
                        size_bytes: MAX_STDOUT_OR_STDERR_BYTES as i64 + 1,
                    });
                }
                Self::InlineContentsMismatch => {
                    result.output_files.last_mut().unwrap().contents =
                        b"wrong inline bytes".to_vec();
                }
                Self::StdoutDigestMismatch => {
                    result.stdout_raw = b"wrong inline bytes".to_vec();
                    result.stdout_digest = Some(digest::of_bytes(b"other"));
                }
                Self::MissingDigest => result.output_files[0].digest = None,
                Self::InlineDigestMismatch => {
                    let file = &mut result.output_files[0];
                    file.contents = b"rlib".to_vec();
                    file.digest = Some(digest::of_bytes(b"other"));
                }
                Self::MissingWorkerRoot => result.stderr_raw.clear(),
                Self::EmptyWorkerRoot => {
                    result.stderr_raw = format!("{WORKER_ROOT_MARKER}\n").into_bytes();
                }
                Self::NonUtf8WorkerRoot => {
                    result.stderr_raw = [WORKER_ROOT_MARKER.as_bytes(), b"/w/\xff\n"].concat();
                }
            }
        }
    }

    #[test_case(InvalidResult::ExitCode(256), "exit code 256" ; "exit code a process can't return")]
    #[test_case(InvalidResult::UndeclaredOutput("other"), "result has undeclared output other" ; "undeclared output")]
    #[test_case(InvalidResult::UndeclaredOutput("../x"), "result has undeclared output ../x" ; "output outside the input root")]
    #[test_case(InvalidResult::DuplicateOutput, "twice" ; "output returned twice")]
    #[test_case(InvalidResult::Symlink, "symlinks" ; "output symlink")]
    #[test_case(InvalidResult::DeprecatedSymlink, "symlinks" ; "output symlink in a deprecated field")]
    #[test_case(InvalidResult::OutputDirectory, "directories" ; "output directory")]
    #[test_case(InvalidResult::MissingRlib, "result lacks output .sccache-build/debug/deps/libfoo.rlib" ; "missing rlib")]
    #[test_case(InvalidResult::MissingDigest, "has no digest" ; "output without a digest")]
    #[test_case(InvalidResult::InlineDigestMismatch, "doesn't match its digest" ; "inline output that doesn't match its digest")]
    #[test_case(InvalidResult::MissingWorkerRoot, "doesn't report the worker root" ; "no worker root line")]
    #[test_case(InvalidResult::EmptyWorkerRoot, "doesn't report the worker root" ; "empty worker root")]
    #[test_case(InvalidResult::NonUtf8WorkerRoot, "doesn't report the worker root" ; "worker root that isn't UTF-8")]
    #[tokio::test]
    async fn test_unusable_results_write_nothing(case: InvalidResult, expected: &str) {
        let mut result = rlib_and_rmeta_result();
        case.apply(&mut result);
        let dir = tempfile::tempdir().unwrap();
        let e = materialize_in(dir.path(), &[b"rlib", b"rmeta"], result)
            .await
            .unwrap_err();
        assert!(e.is::<UnusableResult>(), "{e:#}");
        assert!(format!("{e:#}").contains(expected), "{e:#}");
        assert!(output_names(dir.path()).is_empty());
    }

    #[tokio::test]
    async fn test_an_output_the_cas_doesnt_have_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let files = vec![
            cas_output(RLIB, b"rlib"),
            cas_output(RMETA, b"not in the CAS"),
        ];
        let e = materialize_in(dir.path(), &[b"rlib"], worker_result(files))
            .await
            .unwrap_err();
        assert!(format!("{e:#}").contains("NotFound"), "{e:#}");
        assert!(output_names(dir.path()).is_empty());
    }

    #[test_case(cas_output(RLIB, b"in /w/1/src") ; "from the CAS")]
    #[test_case(inline_output(RLIB, b"in /w/1/src") ; "inline")]
    #[tokio::test]
    async fn test_an_output_containing_the_worker_root_writes_nothing(rlib: remexec::OutputFile) {
        let dir = tempfile::tempdir().unwrap();
        // The rmeta comes first, so writing it before checking the rlib would leave it behind.
        let files = vec![cas_output(RMETA, b"rmeta"), rlib];
        let e = materialize_in(
            dir.path(),
            &[b"in /w/1/src", b"rmeta"],
            worker_result(files),
        )
        .await
        .unwrap_err();
        assert!(e.is::<WorkerRootInOutput>(), "{e:#}");
        assert!(output_names(dir.path()).is_empty());
    }

    #[tokio::test]
    async fn test_a_failed_write_removes_the_outputs_already_written() {
        let dir = tempfile::tempdir().unwrap();
        // A non-empty directory at the rmeta's path, which a rename can't replace.
        fs::create_dir_all(dir.path().join("target/debug/deps/libfoo.rmeta/x")).unwrap();
        let e = materialize_in(dir.path(), &[b"rlib", b"rmeta"], rlib_and_rmeta_result())
            .await
            .unwrap_err();
        assert!(e.is::<UnwritableOutputs>(), "{e:#}");
        assert_eq!(["libfoo.rmeta"], output_names(dir.path()).as_slice());
    }

    #[test]
    fn test_the_worker_root_line_is_taken_once() {
        let stderr = format!("{WORKER_ROOT_MARKER}/w/1\nwarning: x\n{WORKER_ROOT_MARKER}/w/2\n");
        let (worker_root, rest) = take_worker_root(stderr.as_bytes()).unwrap();
        assert_eq!("/w/1", worker_root);
        assert_eq!(
            format!("warning: x\n{WORKER_ROOT_MARKER}/w/2\n"),
            String::from_utf8(rest).unwrap()
        );
    }

    #[test_case("/w/root "; "trailing space")]
    #[test_case("/w/日本語"; "unicode")]
    fn test_worker_root_marker_preserves_path_bytes(root: &str) {
        let stderr = format!("{WORKER_ROOT_MARKER}{root}\nwarning\n");
        let (actual, rest) = take_worker_root(stderr.as_bytes()).unwrap();
        assert_eq!(actual, root);
        assert_eq!(rest, b"warning\n");
    }

    #[test_case("/"; "filesystem root")]
    #[test_case("relative"; "relative path")]
    #[test_case("/w/../root"; "parent component")]
    #[test_case("/w/./root"; "dot component")]
    #[test_case("/w/root/"; "trailing separator")]
    #[test_case("/w//root"; "empty component")]
    #[test_case("/w/\troot"; "control character")]
    fn test_invalid_worker_root_markers_are_rejected(root: &str) {
        let stderr = format!("{WORKER_ROOT_MARKER}{root}\n");
        assert!(
            take_worker_root(stderr.as_bytes())
                .unwrap_err()
                .is::<UnusableResult>()
        );
    }

    #[test_case(InvalidResult::ExitCode(-1) ; "negative exit")]
    #[test_case(InvalidResult::MissingRmeta ; "missing rmeta")]
    #[test_case(InvalidResult::OutputPath("../outside") ; "traversal")]
    #[test_case(InvalidResult::MalformedOutputDigest ; "malformed hash")]
    #[test_case(InvalidResult::NegativeOutputSize ; "negative size")]
    #[test_case(InvalidResult::OversizedOutput ; "oversized file")]
    #[test_case(InvalidResult::OversizedStdout ; "oversized stream")]
    #[test_case(InvalidResult::InlineContentsMismatch ; "inline mismatch")]
    #[test_case(InvalidResult::StdoutDigestMismatch ; "stream mismatch")]
    #[tokio::test]
    async fn test_invalid_metadata_preserves_outputs_without_cas_reads(case: InvalidResult) {
        let dir = tempfile::tempdir().unwrap();
        let deps = dir.path().join("target/debug/deps");
        fs::create_dir_all(&deps).unwrap();
        fs::write(deps.join("libfoo.rlib"), b"old rlib").unwrap();
        fs::write(deps.join("libfoo.rmeta"), b"old rmeta").unwrap();
        let mut result = rlib_and_rmeta_result();
        case.apply(&mut result);
        let server = Arc::new(FakeServer::default());
        let error = materialize_from_server(dir.path(), &server, &result)
            .await
            .unwrap_err();
        assert!(error.is::<UnusableResult>(), "{error:#}");
        assert!(server.read_requests.lock().unwrap().is_empty());
        assert_eq!(fs::read(deps.join("libfoo.rlib")).unwrap(), b"old rlib");
        assert_eq!(fs::read(deps.join("libfoo.rmeta")).unwrap(), b"old rmeta");
        assert_eq!(output_names(dir.path()), ["libfoo.rlib", "libfoo.rmeta"]);
    }

    #[test_case(true; "stdout")]
    #[test_case(false; "stderr")]
    #[tokio::test]
    async fn test_oversized_inline_streams_are_rejected(stdout: bool) {
        let dir = tempfile::tempdir().unwrap();
        let mut result = rlib_and_rmeta_result();
        let data = vec![b'x'; MAX_STDOUT_OR_STDERR_BYTES as usize + 1];
        if stdout {
            result.stdout_raw = data;
        } else {
            result.stderr_raw = data;
        }
        let server = Arc::new(FakeServer::default());
        let error = materialize_from_server(dir.path(), &server, &result)
            .await
            .unwrap_err();
        assert!(error.is::<UnusableResult>(), "{error:#}");
        assert!(error.to_string().contains("is larger than"));
        assert!(server.read_requests.lock().unwrap().is_empty());
        assert!(output_names(dir.path()).is_empty());
    }

    #[tokio::test]
    async fn test_empty_files_and_stream_digests_need_no_cas_reads() {
        let dir = tempfile::tempdir().unwrap();
        let mut result = worker_result(vec![cas_output(RLIB, b""), cas_output(RMETA, b"")]);
        result.stdout_digest = Some(digest::of_bytes(b""));
        let server = Arc::new(FakeServer::default());
        materialize_from_server(dir.path(), &server, &result)
            .await
            .unwrap();
        assert!(server.read_requests.lock().unwrap().is_empty());
        for file in ["libfoo.rlib", "libfoo.rmeta"] {
            assert!(
                fs::read(dir.path().join("target/debug/deps").join(file))
                    .unwrap()
                    .is_empty()
            );
        }
    }

    #[test]
    fn test_inline_staging_failure_keeps_existing_outputs() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("first");
        fs::write(&first, b"old").unwrap();
        let error = write_outputs(vec![
            (
                first.clone(),
                false,
                OutputContents::Inline(b"new".to_vec()),
            ),
            (
                dir.path().join("missing/second"),
                false,
                OutputContents::Inline(b"second".to_vec()),
            ),
        ])
        .unwrap_err();
        assert!(error.is::<UnwritableOutputs>(), "{error:#}");
        assert_eq!(fs::read(first).unwrap(), b"old");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[tokio::test]
    async fn test_digest_failure_cleans_all_staged_files() {
        let dir = tempfile::tempdir().unwrap();
        let server = Arc::new(FakeServer::default());
        server.insert_blob(b"rlib");
        server.insert_blob(b"rmeta");
        server
            .corrupt_reads
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let error = materialize_from_server(dir.path(), &server, &rlib_and_rmeta_result())
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("instead"), "{error:#}");
        assert!(output_names(dir.path()).is_empty());
    }

    #[test_case(1)]
    #[test_case(255)]
    #[tokio::test]
    async fn test_failed_compile_codes_are_preserved(code: i32) {
        let dir = tempfile::tempdir().unwrap();
        let result = remexec::ActionResult {
            exit_code: code,
            ..worker_result(vec![])
        };
        assert_eq!(
            materialize_in(dir.path(), &[], result)
                .await
                .unwrap()
                .status
                .code(),
            Some(code)
        );
    }

    #[test]
    fn test_a_worker_root_split_across_writes_is_found() {
        let contains_worker_root = |writes: &[&[u8]]| {
            let mut scanner = WorkerRootScanner::new(vec![], "/w/1");
            for write in writes {
                scanner.write_all(write).unwrap();
            }
            assert_eq!(writes.concat(), scanner.inner);
            scanner.contains_worker_root
        };
        assert!(contains_worker_root(&[b"in /", b"w", b"/1/src"]));
        assert!(contains_worker_root(&[b"x/w/1"]));
        assert!(contains_worker_root(&[b"/", b"w", b"/", b"1"]));
        assert!(contains_worker_root(&[b"a/w", b"/1"]));
        assert!(!contains_worker_root(&[b"in /w", b"/2/1"]));
    }

    #[test]
    fn test_worker_root_scanning_handles_short_writes_and_all_chunk_boundaries() {
        struct ShortWriter(Vec<u8>);
        impl Write for ShortWriter {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                let n = bytes.len().min(2);
                self.0.extend_from_slice(&bytes[..n]);
                Ok(n)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        for (data, expected) in [
            (b"prefix /w/1/suffix".as_slice(), true),
            (b"prefix /w/2 suffix /w/".as_slice(), false),
        ] {
            for chunk_size in 1..=data.len() {
                let mut scanner = WorkerRootScanner::new(ShortWriter(vec![]), "/w/1");
                for chunk in data.chunks(chunk_size) {
                    scanner.write_all(chunk).unwrap();
                }
                scanner.flush().unwrap();
                assert_eq!(scanner.inner.0, data);
                assert_eq!(scanner.contains_worker_root, expected);
                assert!(scanner.tail.len() < "/w/1".len());
            }
        }
    }

    #[tokio::test]
    async fn test_cached_results_download_and_restore_their_outputs() {
        use crate::reapi::action_cache::ActionCache;

        let dir = tempfile::tempdir().unwrap();
        let server = Arc::new(FakeServer::default());
        let client = server.serve_and_connect().await;
        let action_cache = ActionCache::new(&client);
        let action_digest = digest::of_bytes(b"compile action");
        assert!(
            action_cache
                .get_action_result(&action_digest)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
        server.insert_blob(b"rlib");
        server.insert_blob(b"rmeta");
        server.insert_action_result(&action_digest, rlib_and_rmeta_result());
        let result = action_cache
            .get_action_result(&action_digest)
            .await
            .unwrap()
            .unwrap();
        let output = materialize_from_server(dir.path(), &server, &result)
            .await
            .unwrap();
        assert!(output.status.success());
        assert_eq!(
            fs::read(dir.path().join("target/debug/deps/libfoo.rlib")).unwrap(),
            b"rlib"
        );
        assert_eq!(output_names(dir.path()), ["libfoo.rlib", "libfoo.rmeta"]);
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
