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

use crate::compiler::{Cacheable, Compilation, CompileCommand, DistType};
use crate::errors::*;
use crate::mock_command::CommandCreatorSync;
use crate::server::SccacheService;
use async_trait::async_trait;
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
        } = self;
        let mut path_transformer = crate::dist::PathTransformer::new();
        let (command, _, cacheable) = compilation
            .generate_compile_commands(
                &mut path_transformer,
                hash_key_options.rewrite_includes_only,
            )
            .context("Failed to generate compile commands")?;
        debug!("[{}]: Compiling locally", output_name);
        let output = LocalCompile {
            service,
            creator,
            command,
        }
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
}

impl<T: CommandCreatorSync> LocalCompile<'_, T> {
    #[cfg(feature = "dist-client")]
    fn executable(&self) -> PathBuf {
        self.command.get_executable()
    }

    async fn run(self) -> Result<process::Output> {
        self.command.execute(self.service, self.creator).await
    }
}

#[async_trait]
pub trait CompileExecutor<T: CommandCreatorSync>: Send + Sync {
    fn hash_key_options(&self) -> HashKeyOptions {
        HashKeyOptions::default()
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
