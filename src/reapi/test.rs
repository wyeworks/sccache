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
use super::digest;
use super::proto::build::bazel::remote::execution::v2 as remexec;
use super::proto::google::bytestream::byte_stream_server::{ByteStream, ByteStreamServer};
use super::proto::google::bytestream::{
    QueryWriteStatusRequest, QueryWriteStatusResponse, ReadRequest, ReadResponse, WriteRequest,
    WriteResponse,
};
use futures::{Stream, StreamExt};
use remexec::action_cache_server::{ActionCache, ActionCacheServer};
use remexec::capabilities_server::{Capabilities, CapabilitiesServer};
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tonic::transport::server::TcpIncoming;
use tonic::{Request, Response, Status, Streaming};

type RpcResult<T> = std::result::Result<Response<T>, Status>;

/// In-memory REAPI server for unit tests.
#[derive(Default)]
pub(crate) struct FakeServer {
    pub(crate) instance_name: String,
    pub(crate) without_caching: bool,
    pub(crate) capabilities_error: Mutex<Option<tonic::Code>>,
    pub(crate) capabilities_calls: AtomicUsize,
    pub(crate) capabilities_started: Notify,
    pub(crate) capabilities_gate: Option<Arc<Notify>>,
    pub(crate) capabilities_authorization_headers: Mutex<Vec<Option<String>>>,
    pub(crate) capabilities_requests: Mutex<Vec<remexec::GetCapabilitiesRequest>>,
    pub(crate) supports_zstd_bytestream: bool,
    pub(crate) corrupt_reads: AtomicBool,
    pub(crate) oversize_reads: AtomicBool,
    pub(crate) truncate_reads: bool,
    pub(crate) read_error: Option<tonic::Code>,
    pub(crate) read_stream_error: Option<tonic::Code>,
    pub(crate) stalled_read: Option<Arc<Notify>>,
    pub(crate) read_override: Mutex<Option<Vec<u8>>>,
    pub(crate) read_requests: Mutex<Vec<ReadRequest>>,
    pub(crate) read_authorization_headers: Mutex<Vec<Option<String>>>,
    pub(crate) lookup_error: Mutex<Option<tonic::Code>>,
    pub(crate) stalled_lookup: Option<Arc<Notify>>,
    pub(crate) lookup_requests: Mutex<Vec<remexec::GetActionResultRequest>>,
    pub(crate) authorization_headers: Mutex<Vec<Option<String>>>,
    pub(crate) action_results: Mutex<HashMap<(String, i64), remexec::ActionResult>>,
    pub(crate) blobs: Mutex<HashMap<(String, i64), Vec<u8>>>,
}

struct ResourceName {
    digest: remexec::Digest,
    is_zstd: bool,
}

impl FakeServer {
    pub(crate) fn insert_blob(&self, data: &[u8]) -> remexec::Digest {
        let digest = digest::of_bytes(data);
        self.blobs
            .lock()
            .unwrap()
            .insert((digest.hash.clone(), digest.size_bytes), data.to_vec());
        digest
    }

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
                .add_service(ByteStreamServer::from_arc(self.clone()))
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

    fn parse_resource_name(
        &self,
        resource_name: &str,
    ) -> std::result::Result<ResourceName, Status> {
        let invalid = || Status::invalid_argument(resource_name.to_owned());
        let blob_name = if self.instance_name.is_empty() {
            resource_name
        } else {
            resource_name
                .strip_prefix(&format!("{}/", self.instance_name))
                .ok_or_else(invalid)?
        };
        let (is_zstd, hash_and_size) =
            if let Some(hash_and_size) = blob_name.strip_prefix("compressed-blobs/zstd/") {
                (true, hash_and_size)
            } else if let Some(hash_and_size) = blob_name.strip_prefix("blobs/") {
                (false, hash_and_size)
            } else {
                return Err(invalid());
            };
        let (hash, size) = hash_and_size.split_once('/').ok_or_else(invalid)?;
        let size_bytes = size.parse().map_err(|_| invalid())?;
        Ok(ResourceName {
            digest: remexec::Digest {
                hash: hash.to_owned(),
                size_bytes,
            },
            is_zstd,
        })
    }
}

#[tonic::async_trait]
impl Capabilities for FakeServer {
    async fn get_capabilities(
        &self,
        request: Request<remexec::GetCapabilitiesRequest>,
    ) -> RpcResult<remexec::ServerCapabilities> {
        self.capabilities_calls.fetch_add(1, Ordering::SeqCst);
        self.capabilities_authorization_headers
            .lock()
            .unwrap()
            .push(
                request
                    .metadata()
                    .get("authorization")
                    .map(|header| header.to_str().unwrap().to_owned()),
            );
        self.capabilities_requests
            .lock()
            .unwrap()
            .push(request.into_inner());
        self.capabilities_started.notify_one();
        if let Some(gate) = &self.capabilities_gate {
            gate.notified().await;
        }
        if let Some(code) = *self.capabilities_error.lock().unwrap() {
            return Err(Status::new(code, "capabilities_error"));
        }
        let supported_compressors = if self.supports_zstd_bytestream {
            vec![remexec::compressor::Value::Zstd as i32]
        } else {
            vec![]
        };
        Ok(Response::new(remexec::ServerCapabilities {
            cache_capabilities: (!self.without_caching).then(|| remexec::CacheCapabilities {
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

#[tonic::async_trait]
impl ByteStream for FakeServer {
    type ReadStream = Pin<Box<dyn Stream<Item = std::result::Result<ReadResponse, Status>> + Send>>;

    async fn read(&self, request: Request<ReadRequest>) -> RpcResult<Self::ReadStream> {
        self.read_authorization_headers.lock().unwrap().push(
            request
                .metadata()
                .get("authorization")
                .map(|header| header.to_str().unwrap().to_owned()),
        );
        let request = request.into_inner();
        self.read_requests.lock().unwrap().push(request.clone());
        if let Some(code) = self.read_error {
            return Err(Status::new(code, "read_error"));
        }
        if request.read_offset != 0 || request.read_limit != 0 {
            return Err(Status::invalid_argument("partial reads not supported"));
        }
        let ResourceName { digest, is_zstd } = self.parse_resource_name(&request.resource_name)?;
        if is_zstd && !self.supports_zstd_bytestream {
            return Err(Status::invalid_argument("compressed-blobs not offered"));
        }
        let Some(mut data) = self
            .blobs
            .lock()
            .unwrap()
            .get(&(digest.hash.clone(), digest.size_bytes))
            .cloned()
        else {
            return Err(Status::not_found(digest.hash));
        };
        if self.corrupt_reads.load(Ordering::SeqCst)
            && let Some(first) = data.first_mut()
        {
            *first ^= 1;
        }
        if self.oversize_reads.load(Ordering::SeqCst) {
            data.push(0);
        }
        if self.truncate_reads {
            data.pop();
        }
        if is_zstd {
            data = zstd::bulk::compress(&data, 1).map_err(|e| Status::internal(e.to_string()))?;
        }
        if let Some(replacement) = &*self.read_override.lock().unwrap() {
            data.clone_from(replacement);
        }
        let mut chunks: Vec<_> = data
            .chunks(1000)
            .map(|chunk| {
                Ok(ReadResponse {
                    data: chunk.to_vec(),
                })
            })
            .collect();
        if let Some(code) = self.read_stream_error {
            chunks.push(Err(Status::new(code, "read_stream_error")));
        }
        let stream: Self::ReadStream = match &self.stalled_read {
            Some(received) => {
                let received = received.clone();
                Box::pin(
                    futures::stream::iter(chunks).chain(futures::stream::once(async move {
                        received.notify_one();
                        std::future::pending().await
                    })),
                )
            }
            None => Box::pin(futures::stream::iter(chunks)),
        };
        Ok(Response::new(stream))
    }

    async fn write(&self, _: Request<Streaming<WriteRequest>>) -> RpcResult<WriteResponse> {
        Err(Status::unimplemented("Write"))
    }

    async fn query_write_status(
        &self,
        _: Request<QueryWriteStatusRequest>,
    ) -> RpcResult<QueryWriteStatusResponse> {
        Err(Status::unimplemented("QueryWriteStatus"))
    }
}
