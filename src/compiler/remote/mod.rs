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

use crate::compiler::{CacheControl, Cacheable, Compilation, CompileCommand, DistType};
use crate::errors::*;
use crate::mock_command::CommandCreatorSync;
use crate::server::SccacheService;
use async_trait::async_trait;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process;
use std::sync::Arc;

#[cfg(feature = "dist-client")]
mod dist;

#[cfg(feature = "dist-client")]
pub(crate) use self::dist::DistExecutor;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HashKeyOptions {
    /// Preserves preprocessor line information for sccache-dist inputs. Other
    /// remote backends need not enable this preprocessing mode.
    pub may_distribute: bool,
    pub rewrite_includes_only: bool,
}

pub struct CompileRequest<'a, T: CommandCreatorSync> {
    pub service: &'a SccacheService<T>,
    pub creator: &'a T,
    pub compilation: Box<dyn Compilation<T>>,
    pub cwd: PathBuf,
    pub weak_toolchain_key: String,
    pub output_name: String,
    pub hash_key_options: HashKeyOptions,
    pub cache_control: CacheControl,
    pub local_compile_changes: LocalCompileChanges,
}

pub type StdoutStderrMapper = Box<dyn Fn(&[u8]) -> Vec<u8> + Send + Sync>;

#[derive(Clone)]
pub struct LocalArg {
    pub arg: OsString,
    /// Only output-neutral differences, such as equivalent sysroot-copy paths,
    /// may use a different value for the cache key.
    pub hashed_as: OsString,
}

#[derive(Default)]
pub struct LocalCompileChanges {
    pub args: Vec<LocalArg>,
    /// Implicit inputs missing from the compiler's ordinary cache key.
    pub extra_hash_key: Vec<u8>,
    /// Executed output is mapped before caching; cache-hit diagnostics are already mapped.
    pub stdout_stderr_mapper: Option<StdoutStderrMapper>,
}

pub struct PreparedCompile<T: CommandCreatorSync> {
    pub compilation: Box<dyn Compilation<T>>,
    pub local_compile_changes: LocalCompileChanges,
}

impl<T: CommandCreatorSync> CompileRequest<'_, T> {
    pub(crate) async fn execute_locally(self) -> Result<CompileOutcome> {
        let CompileRequest {
            service,
            creator,
            compilation,
            cwd: _,
            weak_toolchain_key: _,
            output_name,
            hash_key_options,
            cache_control: _,
            local_compile_changes,
        } = self;
        let mut path_transformer = crate::dist::PathTransformer::new();
        let (command, _, cacheable) = compilation
            .generate_compile_commands(
                &mut path_transformer,
                hash_key_options.rewrite_includes_only,
            )
            .context("Failed to generate compile commands")?;
        debug!("[{}]: Compiling locally", output_name);
        let output = LocalCompile::new(service, creator, command, local_compile_changes)?
            .run()
            .await?;
        Ok(CompileOutcome {
            cacheable,
            execution: DistType::NoDist,
            output,
        })
    }
}

pub struct CompileOutcome {
    pub cacheable: Cacheable,
    pub execution: DistType,
    pub output: process::Output,
}

struct LocalCompile<'a, T: CommandCreatorSync> {
    service: &'a SccacheService<T>,
    creator: &'a T,
    command: Box<dyn CompileCommand<T>>,
    stdout_stderr_mapper: Option<StdoutStderrMapper>,
}

impl<'a, T: CommandCreatorSync> LocalCompile<'a, T> {
    fn new(
        service: &'a SccacheService<T>,
        creator: &'a T,
        mut command: Box<dyn CompileCommand<T>>,
        changes: LocalCompileChanges,
    ) -> Result<Self> {
        if !changes.args.is_empty() {
            let args: Vec<_> = changes.args.into_iter().map(|arg| arg.arg).collect();
            command.append_arguments(&args)?;
        }
        Ok(Self {
            service,
            creator,
            command,
            stdout_stderr_mapper: changes.stdout_stderr_mapper,
        })
    }

    #[cfg(feature = "dist-client")]
    fn executable(&self) -> PathBuf {
        self.command.get_executable()
    }

    async fn run(self) -> Result<process::Output> {
        let result = self.command.execute(self.service, self.creator).await;
        let Some(mapper) = self.stdout_stderr_mapper else {
            return result;
        };
        let map = |mut output: process::Output| {
            output.stdout = mapper(&output.stdout);
            output.stderr = mapper(&output.stderr);
            output
        };
        match result {
            Ok(output) => Ok(map(output)),
            Err(error) => match error.downcast::<ProcessError>() {
                Ok(ProcessError(output)) => Err(ProcessError(map(output)).into()),
                Err(error) => Err(error),
            },
        }
    }
}

#[async_trait]
pub trait CompileExecutor<T: CommandCreatorSync>: Send + Sync {
    fn hash_key_options(&self) -> HashKeyOptions {
        HashKeyOptions::default()
    }

    /// Runs after input discovery, before the final cache key and lookup. Changes
    /// must preserve the discovered inputs.
    async fn prepare(&self, compilation: Box<dyn Compilation<T>>) -> Result<PreparedCompile<T>> {
        Ok(PreparedCompile {
            compilation,
            local_compile_changes: LocalCompileChanges::default(),
        })
    }

    /// Runs one compile and leaves successful outputs at their local paths. An
    /// infrastructure failure may run the compile locally, but a compiler failure is final.
    /// Remove incomplete remote outputs before falling back or returning an error.
    /// A completed compiler invocation may leave outputs even when it exits nonzero.
    async fn execute(&self, request: CompileRequest<'_, T>) -> Result<CompileOutcome>;
}

struct LocalExecutor;

#[async_trait]
impl<T: CommandCreatorSync> CompileExecutor<T> for LocalExecutor {
    async fn execute(&self, request: CompileRequest<'_, T>) -> Result<CompileOutcome> {
        request.execute_locally().await
    }
}

pub(super) async fn execute_compile<T: CommandCreatorSync>(
    executor: Option<Arc<dyn CompileExecutor<T>>>,
    request: CompileRequest<'_, T>,
) -> Result<CompileOutcome> {
    match executor {
        Some(executor) => executor.execute(request).await,
        None => LocalExecutor.execute(request).await,
    }
}
