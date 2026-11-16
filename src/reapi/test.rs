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

//! Shared test helpers for REAPI modules.

use super::client::{Client, ConnectOptions};
use super::proto::build::bazel::remote::execution::v2 as remexec;
use remexec::action_cache_server::{ActionCache, ActionCacheServer};
use remexec::capabilities_server::{Capabilities, CapabilitiesServer};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tonic::transport::server::TcpIncoming;
use tonic::{Request, Response, Status};

type RpcResult<T> = std::result::Result<Response<T>, Status>;

/// A REAPI server that keeps action results in memory.
#[derive(Default)]
pub(crate) struct FakeServer {
    pub(crate) instance_name: String,
    pub(crate) supports_zstd_bytestream: bool,
    pub(crate) lookup_error: Mutex<Option<tonic::Code>>,
    pub(crate) stalled_lookup: Option<Arc<Notify>>,
    pub(crate) lookup_requests: Mutex<Vec<remexec::GetActionResultRequest>>,
    pub(crate) authorization_headers: Mutex<Vec<Option<String>>>,
    pub(crate) action_results: Mutex<HashMap<(String, i64), remexec::ActionResult>>,
}

impl FakeServer {
    pub(crate) fn insert_action_result(
        &self,
        action_digest: &remexec::Digest,
        result: remexec::ActionResult,
    ) {
        self.action_results.lock().unwrap().insert(
            (action_digest.hash.clone(), action_digest.size_bytes),
            result,
        );
    }

    pub(crate) async fn serve(self: &Arc<Self>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(CapabilitiesServer::from_arc(self.clone()))
                .add_service(ActionCacheServer::from_arc(self.clone()))
                .serve_with_incoming(TcpIncoming::from(listener)),
        );
        format!("grpc://{addr}")
    }

    pub(crate) async fn serve_and_connect(self: &Arc<Self>) -> Client {
        Client::connect(&ConnectOptions {
            endpoint: self.serve().await,
            instance_name: self.instance_name.clone(),
            ..Default::default()
        })
        .await
        .unwrap()
    }
}

#[tonic::async_trait]
impl Capabilities for FakeServer {
    async fn get_capabilities(
        &self,
        _: Request<remexec::GetCapabilitiesRequest>,
    ) -> RpcResult<remexec::ServerCapabilities> {
        let supported_compressors = if self.supports_zstd_bytestream {
            vec![remexec::compressor::Value::Zstd as i32]
        } else {
            vec![]
        };
        Ok(Response::new(remexec::ServerCapabilities {
            cache_capabilities: Some(remexec::CacheCapabilities {
                supported_compressors,
                ..Default::default()
            }),
            ..Default::default()
        }))
    }
}

#[tonic::async_trait]
impl ActionCache for FakeServer {
    async fn get_action_result(
        &self,
        request: Request<remexec::GetActionResultRequest>,
    ) -> RpcResult<remexec::ActionResult> {
        self.authorization_headers.lock().unwrap().push(
            request
                .metadata()
                .get("authorization")
                .map(|header| header.to_str().unwrap().to_owned()),
        );
        let request = request.into_inner();
        self.lookup_requests.lock().unwrap().push(request.clone());
        if let Some(received) = &self.stalled_lookup {
            received.notify_one();
            std::future::pending::<()>().await;
        }
        if let Some(code) = *self.lookup_error.lock().unwrap() {
            return Err(Status::new(code, "lookup_error"));
        }
        if request.instance_name != self.instance_name {
            return Err(Status::invalid_argument(request.instance_name));
        }
        let Some(action_digest) = request.action_digest else {
            return Err(Status::invalid_argument("no action_digest"));
        };
        let action_results = self.action_results.lock().unwrap();
        match action_results.get(&(action_digest.hash, action_digest.size_bytes)) {
            Some(result) => Ok(Response::new(result.clone())),
            None => Err(Status::not_found("no result")),
        }
    }

    async fn update_action_result(
        &self,
        _: Request<remexec::UpdateActionResultRequest>,
    ) -> RpcResult<remexec::ActionResult> {
        Err(Status::unimplemented("UpdateActionResult"))
    }
}
