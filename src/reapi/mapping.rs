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

use super::client::{CPP_COMPILE_MNEMONIC, RUSTC_MNEMONIC};
use super::digest::FileStamp;
use crate::compiler::CCompilerKind;
use crate::dist::simplify_path::simplify_path_and_dirs;
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
    pub(crate) program: WorkerProgram,
    pub(crate) toolchain: ToolchainKey,
    pub(crate) env: ActionEnv,
    pub(crate) input_root_files: Vec<PathBuf>,
    pub(crate) input_root_directories: Vec<String>,
    pub(crate) outputs: Vec<PathBuf>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum WorkerProgram {
    Rustc {
        /// rustc preserves the spelling of absolute crate-root arguments in its outputs.
        mapped_crate_root: Option<String>,
    },
    C,
}

impl WorkerProgram {
    pub(super) fn action_mnemonic(&self) -> &'static str {
        match self {
            WorkerProgram::Rustc { .. } => RUSTC_MNEMONIC,
            WorkerProgram::C => CPP_COMPILE_MNEMONIC,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum ToolchainKey {
    Rustc(RustcToolchainKey),
    C(CToolchainKey),
}

impl ToolchainKey {
    pub(crate) fn rustc(commit_hash: String, sysroot: PathBuf, target_triple: String) -> Self {
        Self::Rustc(RustcToolchainKey::new(commit_hash, sysroot, target_triple))
    }

    #[cfg(test)]
    pub(crate) fn as_rustc(&self) -> &RustcToolchainKey {
        match self {
            Self::Rustc(key) => key,
            Self::C(key) => panic!("expected a Rust toolchain, got {key:?}"),
        }
    }
}

impl std::fmt::Display for ToolchainKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rustc(key) => write!(f, "the toolchain in {}", key.sysroot.display()),
            Self::C(key) => write!(f, "the toolchain of {}", key.driver.display()),
        }
    }
}

/// A local gcc or clang: its driver's canonical path, the files besides the driver that it
/// runs or reads to compile, and the shared libraries they load other than glibc's. The key
/// includes their stamps, which change when one of them is updated in place.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct CToolchainKey {
    pub(crate) kind: CCompilerKind,
    pub(crate) driver: PathBuf,
    pub(crate) internal_files: Vec<InternalFile>,
    pub(crate) libraries: Vec<PathBuf>,
    stamps: Vec<Option<FileStamp>>,
}

impl CToolchainKey {
    /// Lists the libraries and reads the stamps, so call it from a blocking thread.
    pub(crate) fn new(
        kind: CCompilerKind,
        driver: PathBuf,
        internal_files: Vec<InternalFile>,
    ) -> Result<Self> {
        let programs = std::iter::once(&driver).chain(
            (internal_files.iter())
                .filter(|file| file.is_program())
                .map(|file| &file.path),
        );
        let mut libraries = std::collections::BTreeSet::new();
        for program in programs {
            libraries.extend(shared_libraries(program)?);
        }
        Ok(Self::with_libraries(
            kind,
            driver,
            internal_files,
            libraries.into_iter().collect(),
        ))
    }

    /// Reads the stamps, so call it from a blocking thread.
    pub(crate) fn with_libraries(
        kind: CCompilerKind,
        driver: PathBuf,
        internal_files: Vec<InternalFile>,
        libraries: Vec<PathBuf>,
    ) -> Self {
        let stamps = std::iter::once(&driver)
            .chain(internal_files.iter().map(|file| &file.path))
            .chain(&libraries)
            .map(|path| FileStamp::of(path).ok())
            .collect();
        CToolchainKey {
            kind,
            driver,
            internal_files,
            libraries,
            stamps,
        }
    }
    pub(super) fn stamps(&self) -> impl Iterator<Item = &FileStamp> {
        self.stamps.iter().flatten()
    }

    pub(super) fn stamps_match(&self) -> bool {
        std::iter::once(&self.driver)
            .chain(self.internal_files.iter().map(|file| &file.path))
            .chain(&self.libraries)
            .map(|path| FileStamp::of(path).ok())
            .eq(self.stamps.iter().cloned())
    }
}

/// A file that gcc runs or reads to compile.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct InternalFile {
    /// The driver option that prints its path, such as `-print-prog-name=cc1`.
    pub(crate) option: String,
    pub(crate) path: PathBuf,
}

impl InternalFile {
    /// Whether the driver runs the file, rather than reading it.
    pub(crate) fn is_program(&self) -> bool {
        self.option.starts_with("-print-prog-name=")
    }
}

/// Shared libraries of glibc, which must come from the worker: each works only with the loader
/// and the other libraries of its own glibc.
#[cfg(target_os = "linux")]
pub(super) const GLIBC_LIBRARIES: &[&str] = &[
    "libc.so",
    "libm.so",
    "ld-linux",
    "libpthread.so",
    "libdl.so",
    "librt.so",
];

/// The shared libraries that `program` loads, other than glibc's. A script loads none.
#[cfg(target_os = "linux")]
fn shared_libraries(program: &Path) -> Result<Vec<PathBuf>> {
    let mut magic = [0; 4];
    let is_elf = std::fs::File::open(program)
        .and_then(|mut file| std::io::Read::read_exact(&mut file, &mut magic))
        .is_ok_and(|()| magic == *b"\x7fELF");
    if !is_elf {
        return Ok(vec![]);
    }
    let libraries = crate::dist::ldd::find_ldd_libraries(program)
        .with_context(|| format!("failed to list the libraries of {}", program.display()))?;
    Ok(libraries
        .into_iter()
        .filter(|library| {
            let name = library.file_name().unwrap_or_default().to_string_lossy();
            !GLIBC_LIBRARIES.iter().any(|glibc| name.starts_with(glibc))
        })
        .collect())
}

/// Workers run Linux, so another OS's compiler never runs there.
#[cfg(not(target_os = "linux"))]
fn shared_libraries(_program: &Path) -> Result<Vec<PathBuf>> {
    Ok(vec![])
}

/// Identifies a local toolchain for in-memory reuse. File metadata detects updates
/// without hashing the toolchain for every compile; content digests identify it remotely.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct RustcToolchainKey {
    pub(crate) commit_hash: String,
    pub(crate) sysroot: PathBuf,
    pub(crate) target_triple: String,
    pub(super) files: Option<Vec<StampedFile>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) struct StampedFile {
    pub(super) path: PathBuf,
    pub(super) stamp: FileStamp,
    pub(super) is_executable: bool,
}

impl RustcToolchainKey {
    /// Reads the stamps, so call it from a blocking thread.
    pub(crate) fn new(commit_hash: String, sysroot: PathBuf, target_triple: String) -> Self {
        let files = super::remote_compile::list_toolchain_files(&sysroot, &target_triple).ok();
        Self {
            commit_hash,
            sysroot,
            target_triple,
            files,
        }
    }

    pub(super) fn stamps(&self) -> impl Iterator<Item = &FileStamp> {
        self.files.iter().flatten().map(|file| &file.stamp)
    }
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
    UnsupportedCompiler,
    WindowsPaths,
    UnsupportedLanguage,
    LanguageAfterInput,
    NotFromBuildScript,
    CompilerEnvVar,
    ArchOption,
    PrecompiledHeader,
    ProfilingOrCoverage,
    MacroDebugInfo,
    PrefixMapOption,
    OptionReadsFile,
    CompilerInternalsOption,
    VerboseOutput,
    RecordedCommandLine,
    ExtraOutput,
    NonUtf8Argument,
    ColonOrEqualsInPath,
    MissingGccProgram,
    SharedLibrariesNotListed,
    ClangConfigFile,
    SideOutputOption,
    CToolchainUnsupported,
    RustcDriver,
    WindowsClient,
    Staticlib,
    UnexpectedCargoLayout,
    PathOutsideInputRoot,
    SourceOutsideInputRoot,
    DotDotOutOfSymlink,
    AbsolutePathInOption,
    CustomTargetSpec,
    NativeCpu,
    ProfileUse,
    RemapPathPrefix,
    NonUtf8EnvVar,
    UnsupportedEnvVarName,
    UnreadableDependencies,
    MappingPanicked,
    Misconfigured,
    Connecting,
    ConnectFailed,
    IncompatibleServer,
    CredentialsRefused,
    CredentialHelperFailed,
    NonUtf8ToolchainPath,
    MissingRustcOrStd,
    HashingToolchainFailed,
    HashingToolchain,
    NoCommitHash,
    UnwritableOutputs,
    DownloadingOutputsFailed,
    WorkerRootInOutput,
    UnusableResult,
    ActionCacheLookupFailed,
    ActionCacheLookupsPaused,
    NotInActionCache,
    NonLinuxToolchain,
    LocalSlotFree,
    NoFreeRemoteSlot,
    WorkerStdDiffers,
    ProcMacroForClientOs,
    UnusableWorkerToolchain,
    UnpackingWorkerToolchain,
    UploadFailed,
    ExecutionFailed,
    ExecutionQueuedTooLong,
    ExecutionsRefused,
    RustcFailsOnWorkers,
    RustcCommitDiffersOnWorkers,
    UnreadableInput,
    InputChangedAfterHashing,
    ExecutionTimedOut,
    ExecutionsPaused,
    CompileFailedOnWorker,
    HashingInputsFailed,
    LocalCompileUnchanged,
    CacheBypassed,
}

impl std::fmt::Display for CompileLocallyReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::UnsupportedLanguage => "language other than C or C++",
            Self::LanguageAfterInput => "-x after the input",
            Self::NotFromBuildScript => "not run by a cargo build script",
            Self::CompilerEnvVar => "env var that changes what the compiler runs",
            Self::ArchOption => "-arch option",
            Self::PrecompiledHeader => "precompiled header",
            Self::ProfilingOrCoverage => "profiling or coverage option",
            Self::MacroDebugInfo => "debug info with macros",
            Self::PrefixMapOption => "the compile's own -f*-prefix-map",
            Self::OptionReadsFile => "option that reads a file besides the source",
            Self::CompilerInternalsOption => "option passed to the compiler's internal programs",
            Self::VerboseOutput => "verbose compiler output",
            Self::RecordedCommandLine => "option that records the command line",
            Self::ExtraOutput => "output besides the object and the depfile",
            Self::NonUtf8Argument => "non-UTF-8 argument",
            Self::ColonOrEqualsInPath => "`:` or `=` in a toolchain dir or the worker root",
            Self::MissingGccProgram => "gcc without its cc1, cc1plus or as",
            Self::SharedLibrariesNotListed => "failed to list the compiler's shared libraries",
            Self::ClangConfigFile => "clang config file",
            Self::SideOutputOption => "option that writes a file besides the object",
            Self::CToolchainUnsupported => "C toolchain unsupported on workers",
            Self::UnsupportedCompiler => "unsupported compiler",
            Self::WindowsPaths => "Windows paths",
            Self::RustcDriver => "not rustc",
            Self::WindowsClient => "Windows client",
            Self::Staticlib => "staticlib crate type",
            Self::UnexpectedCargoLayout => "unexpected cargo dir layout",
            Self::PathOutsideInputRoot => "path outside the cwd and build root",
            Self::SourceOutsideInputRoot => "source file outside the cwd and build root",
            Self::DotDotOutOfSymlink => "input path that steps out of a symlink with `..`",
            Self::AbsolutePathInOption => "absolute path in an option",
            Self::CustomTargetSpec => "custom target spec",
            Self::NativeCpu => "native CPU option",
            Self::ProfileUse => "-C profile-use or -C profile-sample-use",
            Self::RemapPathPrefix => "--remap-path-prefix",
            Self::NonUtf8EnvVar => "non-UTF-8 env var",
            Self::UnsupportedEnvVarName => "env var the REAPI command can't pass to rustc",
            Self::UnreadableDependencies => "unreadable dependencies",
            Self::MappingPanicked => "mapping the compile for REAPI panicked",
            Self::Misconfigured => "[reapi] misconfigured",
            Self::Connecting => "connecting to the REAPI server",
            Self::ConnectFailed => "failed to connect to the REAPI server",
            Self::IncompatibleServer => "incompatible REAPI server",
            Self::CacheBypassed => "SCCACHE_RECACHE or SCCACHE_NO_CACHE set",
            Self::LocalCompileUnchanged => "local compile without the worker's arguments",
            Self::HashingInputsFailed => "failed to hash the inputs",
            Self::NotInActionCache => "not in the action cache",
            Self::UnpackingWorkerToolchain => "unpacking the worker toolchain",
            Self::UnusableWorkerToolchain => "unusable worker toolchain archive",
            Self::ProcMacroForClientOs => "proc macro for the client's OS",
            Self::WorkerStdDiffers => "worker toolchain's std differs from the local one",
            Self::NoFreeRemoteSlot => "no remote slot freed in time",
            Self::LocalSlotFree => "a local slot is free",
            Self::NonLinuxToolchain => "the local toolchain cannot run on Linux workers",
            Self::UploadFailed => "failed to upload action inputs",
            Self::RustcFailsOnWorkers => "rustc cannot run on the workers",
            Self::RustcCommitDiffersOnWorkers => "worker rustc has a different commit hash",
            Self::InputChangedAfterHashing => "input changed after it was hashed",
            Self::UnreadableInput => "could not read an input for upload",
            Self::ExecutionQueuedTooLong => "execution stayed queued too long",
            Self::ExecutionsRefused => "server refused execution",
            Self::ExecutionFailed => "remote execution failed",
            Self::ExecutionTimedOut => "remote execution timed out",
            Self::ExecutionsPaused => "remote executions are paused",
            Self::CompileFailedOnWorker => "compilation failed on a worker",
            Self::ActionCacheLookupFailed => "action cache lookup failed",
            Self::ActionCacheLookupsPaused => "action cache lookups paused after failures",
            Self::UnusableResult => "unusable action cache result",
            Self::WorkerRootInOutput => "worker root in an output",
            Self::DownloadingOutputsFailed => "failed to download the outputs",
            Self::UnwritableOutputs => "failed to write the outputs",
            Self::NoCommitHash => "rustc without a commit hash",
            Self::HashingToolchain => "hashing the toolchain",
            Self::HashingToolchainFailed => "failed to hash the toolchain",
            Self::MissingRustcOrStd => "missing rustc or std",
            Self::NonUtf8ToolchainPath => "non-UTF-8 toolchain path",
            Self::CredentialHelperFailed => "credential helper failed",
            Self::CredentialsRefused => "REAPI server refused the credentials",
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

    /// Maps a source path while retaining the directories traversed by `..`.
    pub(crate) fn simplify_input(
        &self,
        path: &Path,
        directories: &mut Vec<String>,
    ) -> std::result::Result<Option<PathBuf>, NotEligible> {
        if let Some(normalized) = normalize_absolute(path) {
            return Ok(self.to_input_root(&normalized).map(|_| normalized));
        }
        let outside = || {
            NotEligible::new(
                CompileLocallyReason::SourceOutsideInputRoot,
                anyhow!("{}", path.display()),
            )
        };
        if !path.is_absolute() {
            return Err(outside());
        }

        let mut traversed = Vec::new();
        let normalized = simplify_path_and_dirs(path, &mut traversed).map_err(|error| {
            NotEligible::new(
                CompileLocallyReason::DotDotOutOfSymlink,
                error.context(path.display().to_string()),
            )
        })?;
        self.to_input_root(&normalized).ok_or_else(outside)?;
        let in_build_root = normalized.starts_with(&self.build_root);
        let mut mapped_dirs = Vec::with_capacity(traversed.len());
        for directory in traversed {
            let mapped_dir = self.to_input_root(&directory).ok_or_else(outside)?;
            if mapped_dir == "."
                || mapped_dir == BUILD_ROOT_DIR
                || directory.starts_with(&self.build_root) != in_build_root
                || !directory.is_dir()
            {
                return Err(outside());
            }
            mapped_dirs.push(mapped_dir);
        }
        directories.extend(mapped_dirs);
        Ok(Some(normalized))
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

    #[test_case("bin/rustc" ; "compiler")]
    #[test_case("lib/librustc_driver-x.so" ; "compiler library")]
    #[test_case("lib/rustlib/x86_64-unknown-linux-gnu/lib/libstd-x.rlib" ; "standard library")]
    #[test_case("lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld" ; "linker")]
    fn test_toolchain_key_tracks_file_edits(path: &str) {
        let dir = tempfile::tempdir().unwrap();
        let sysroot = crate::reapi::remote_compile::test::fake_sysroot(dir.path());
        let key = || {
            ToolchainKey::rustc(
                "abc123".into(),
                sysroot.clone(),
                "x86_64-unknown-linux-gnu".into(),
            )
        };
        let original = key();
        assert_eq!(original, key());
        let path = sysroot.join(path);
        let old_metadata = std::fs::metadata(&path).unwrap();
        // Keep the directory and file mtime unchanged, as an in-place edit can.
        std::fs::write(&path, b"changed content, different length").unwrap();
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(old_metadata.modified().unwrap())
            .unwrap();
        assert_ne!(original, key());
    }

    #[test]
    fn test_toolchain_key_tracks_added_targets_and_identity() {
        let dir = tempfile::tempdir().unwrap();
        let sysroot = crate::reapi::remote_compile::test::fake_sysroot(dir.path());
        let key = |commit: &str, target: &str| {
            ToolchainKey::rustc(commit.into(), sysroot.clone(), target.into())
        };
        let original = key("abc123", "target");
        assert_ne!(original, key("new-commit", "target"));
        assert_ne!(original, key("abc123", "other-target"));
        std::fs::create_dir_all(sysroot.join("lib/rustlib/target/lib")).unwrap();
        assert_ne!(original, key("abc123", "target"));
    }

    #[cfg(unix)]
    #[test]
    fn test_parent_paths_cannot_leave_a_symlink_or_a_mapped_root() {
        let temp = tempfile::tempdir().unwrap();
        let cwd = temp.path();
        let build_root = cwd.join("target");
        std::fs::create_dir_all(build_root.join("subdir")).unwrap();
        std::os::unix::fs::symlink("target/subdir", cwd.join("link")).unwrap();
        let mapper = PathMapper::new(cwd.to_owned(), build_root);
        let mut directories = Vec::new();

        for (path, reason) in [
            ("link/../foo.rs", CompileLocallyReason::DotDotOutOfSymlink),
            (
                "target/subdir/../../foo.rs",
                CompileLocallyReason::SourceOutsideInputRoot,
            ),
        ] {
            assert_eq!(
                mapper
                    .simplify_input(&cwd.join(path), &mut directories)
                    .unwrap_err()
                    .reason,
                reason
            );
            assert!(directories.is_empty());
        }
    }

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
        assert!(InputRoot::build(&files, &[]).is_ok());
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
            program: WorkerProgram::Rustc {
                mapped_crate_root: None,
            },
            toolchain: ToolchainKey::rustc("abc123".into(), copy.clone(), String::new()),
            env: ActionEnv {
                path_vars: vec![(
                    "OUT_DIR".into(),
                    ".sccache-build/debug/build/foo/out".into(),
                )],
                ..Default::default()
            },
            input_root_files: vec![],
            input_root_directories: vec![],
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
