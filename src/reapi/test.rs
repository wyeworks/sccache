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
use super::execution::{PreconditionFailure, Violation};
use super::proto::build::bazel::remote::execution::v2 as remexec;
use super::proto::google::bytestream::byte_stream_server::{ByteStream, ByteStreamServer};
use super::proto::google::bytestream::{
    QueryWriteStatusRequest, QueryWriteStatusResponse, ReadRequest, ReadResponse, WriteRequest,
    WriteResponse,
};
use super::proto::google::longrunning::{Operation, operation};
use super::proto::google::rpc;
use futures::{Stream, StreamExt};
use prost::Message;
use remexec::action_cache_server::{ActionCache, ActionCacheServer};
use remexec::capabilities_server::{Capabilities, CapabilitiesServer};
use remexec::content_addressable_storage_server::{
    ContentAddressableStorage, ContentAddressableStorageServer,
};
use remexec::execution_server::{Execution, ExecutionServer};
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tokio::sync::{Notify, Semaphore};
use tonic::transport::server::TcpIncoming;
use tonic::{Request, Response, Status, Streaming};

type RpcResult<T> = std::result::Result<Response<T>, Status>;

/// In-memory REAPI server for unit tests.
#[derive(Default)]
pub(crate) struct FakeServer {
    /// The files each execution writes, by output path; only declared ones count.
    pub(crate) worker_outputs: HashMap<String, Vec<u8>>,
    pub(crate) execute_calls: AtomicUsize,
    pub(crate) actions_run: AtomicUsize,
    /// Finishes each Execute with a missing-blobs status in the ExecuteResponse.
    pub(crate) missing_blobs_in_response: bool,
    /// Refuses each Execute with FAILED_PRECONDITION, as when no worker matches the platform.
    pub(crate) without_matching_worker: bool,
    /// Finishes each Execute with an operation error.
    pub(crate) fail_operations: bool,
    /// Breaks this many Execute and WaitExecution streams, after a first, unfinished
    /// operation unless `break_before_operation`.
    pub(crate) streams_to_break: AtomicUsize,
    pub(crate) stream_break: StreamBreak,
    pub(crate) break_before_operation: bool,
    /// Keeps the operations of broken streams for WaitExecution, which otherwise answers
    /// NOT_FOUND, as a server that lost them.
    pub(crate) keep_operations: bool,
    pub(crate) lost_operation_in_stream: bool,
    /// Forgets every blob when it breaks a stream.
    pub(crate) forget_blobs_on_break: bool,
    /// Refuses this many Execute calls with UNAVAILABLE, as when every worker is busy.
    pub(crate) executes_to_refuse: AtomicUsize,
    pub(crate) wait_executions_to_refuse: AtomicUsize,
    pub(crate) wait_execution_calls: AtomicUsize,
    pub(crate) operations: Mutex<HashMap<String, Operation>>,

    pub(crate) instance_name: String,
    pub(crate) max_batch_bytes: i64,
    pub(crate) find_missing_requests: Mutex<Vec<remexec::FindMissingBlobsRequest>>,
    pub(crate) find_missing_error: Option<tonic::Code>,
    pub(crate) find_missing_override: Option<Vec<remexec::Digest>>,
    pub(crate) stalled_find_missing: Option<Arc<Notify>>,
    pub(crate) find_authorization_headers: Mutex<Vec<Option<String>>>,
    pub(crate) batch_requests: Mutex<Vec<remexec::BatchUpdateBlobsRequest>>,
    pub(crate) batch_error: Option<tonic::Code>,
    pub(crate) refused_blob: Mutex<Option<remexec::Digest>>,
    pub(crate) batch_response_change:
        Option<fn(&mut Vec<remexec::batch_update_blobs_response::Response>)>,
    pub(crate) stalled_batch: Option<Arc<Notify>>,
    pub(crate) stalled_write: Option<Arc<Notify>>,
    pub(crate) write_error: Option<tonic::Code>,
    pub(crate) write_requests: Mutex<Vec<WriteRequest>>,
    pub(crate) upload_authorization_headers: Mutex<Vec<Option<String>>>,
    pub(crate) upload_gate: Option<Arc<Semaphore>>,
    pub(crate) active_uploads: AtomicUsize,
    pub(crate) max_active_uploads: AtomicUsize,
    pub(crate) upload_started: Notify,
    pub(crate) find_missing_blobs_calls: AtomicUsize,
    pub(crate) batch_update_blobs_calls: AtomicUsize,
    pub(crate) batched_blob_count: AtomicUsize,
    pub(crate) bytestream_write_resource_names: Mutex<Vec<String>>,
    pub(crate) early_committed_size: Option<i64>,
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

struct UploadGuard<'a>(&'a AtomicUsize);

impl Drop for UploadGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// How the fake server breaks a stream.
#[derive(Clone, Copy)]
pub(crate) enum StreamBreak {
    Status(tonic::Code),
    /// Ends the stream without finishing the operation.
    End,
}

impl Default for StreamBreak {
    fn default() -> Self {
        StreamBreak::Status(tonic::Code::Unavailable)
    }
}

struct ResourceName {
    digest: remexec::Digest,
    is_zstd: bool,
}

impl FakeServer {
    async fn begin_upload(&self) -> UploadGuard<'_> {
        let active = self.active_uploads.fetch_add(1, Ordering::SeqCst) + 1;
        let guard = UploadGuard(&self.active_uploads);
        self.max_active_uploads.fetch_max(active, Ordering::SeqCst);
        self.upload_started.notify_one();
        if let Some(gate) = &self.upload_gate {
            gate.acquire().await.unwrap().forget();
        }
        guard
    }

    pub(crate) fn insert_blob(&self, data: &[u8]) -> remexec::Digest {
        let digest = digest::of_bytes(data);
        self.blobs
            .lock()
            .unwrap()
            .insert((digest.hash.clone(), digest.size_bytes), data.to_vec());
        digest
    }

    pub(crate) fn has_blob(&self, data: &[u8]) -> bool {
        let digest = digest::of_bytes(data);
        self.blobs
            .lock()
            .unwrap()
            .contains_key(&(digest.hash, digest.size_bytes))
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
                .add_service(ContentAddressableStorageServer::from_arc(self.clone()))
                .add_service(ExecutionServer::from_arc(self.clone()))
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
    /// `[<instance>/]uploads/<uuid>/{blobs,compressed-blobs/zstd}/<hash>/<size>`.
    fn parse_write_resource_name(
        &self,
        resource_name: &str,
    ) -> std::result::Result<ResourceName, Status> {
        self.strip_instance_name(resource_name)
            .and_then(|name| name.strip_prefix("uploads/"))
            .and_then(|name| name.split_once('/'))
            .filter(|(upload_id, _)| uuid::Uuid::parse_str(upload_id).is_ok())
            .and_then(|(_, blob_name)| parse_blob_name(blob_name))
            .ok_or_else(|| Status::invalid_argument(resource_name.to_owned()))
    }

    fn strip_instance_name<'a>(&self, resource_name: &'a str) -> Option<&'a str> {
        if self.instance_name.is_empty() {
            Some(resource_name)
        } else {
            resource_name.strip_prefix(&format!("{}/", self.instance_name))
        }
    }
}

/// `{blobs,compressed-blobs/zstd}/<hash>/<size>`.
fn parse_blob_name(blob_name: &str) -> Option<ResourceName> {
    let (is_zstd, hash_and_size) = match blob_name.strip_prefix("compressed-blobs/zstd/") {
        Some(hash_and_size) => (true, hash_and_size),
        None => (false, blob_name.strip_prefix("blobs/")?),
    };
    let (hash, size) = hash_and_size.split_once('/')?;
    Some(ResourceName {
        digest: remexec::Digest {
            hash: hash.to_owned(),
            size_bytes: size.parse().ok()?,
        },
        is_zstd,
    })
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
                max_batch_total_size_bytes: self.max_batch_bytes,
                ..Default::default()
            }),
            ..Default::default()
        }))
    }
}

#[tonic::async_trait]
impl ContentAddressableStorage for FakeServer {
    async fn find_missing_blobs(
        &self,
        request: Request<remexec::FindMissingBlobsRequest>,
    ) -> RpcResult<remexec::FindMissingBlobsResponse> {
        self.find_missing_blobs_calls.fetch_add(1, Ordering::SeqCst);
        self.find_authorization_headers.lock().unwrap().push(
            request
                .metadata()
                .get("authorization")
                .map(|v| v.to_str().unwrap().to_owned()),
        );
        let request = request.into_inner();
        self.find_missing_requests
            .lock()
            .unwrap()
            .push(request.clone());
        if let Some(received) = &self.stalled_find_missing {
            received.notify_one();
            std::future::pending::<()>().await;
        }
        if let Some(code) = self.find_missing_error {
            return Err(Status::new(code, "find_missing_error"));
        }
        if let Some(missing) = &self.find_missing_override {
            return Ok(Response::new(remexec::FindMissingBlobsResponse {
                missing_blob_digests: missing.clone(),
            }));
        }
        if request.instance_name != self.instance_name {
            return Err(Status::invalid_argument(request.instance_name));
        }
        let blobs = self.blobs.lock().unwrap();
        let missing_blob_digests = request
            .blob_digests
            .into_iter()
            .filter(|digest| !blobs.contains_key(&(digest.hash.clone(), digest.size_bytes)))
            .collect();
        Ok(Response::new(remexec::FindMissingBlobsResponse {
            missing_blob_digests,
        }))
    }

    async fn batch_update_blobs(
        &self,
        request: Request<remexec::BatchUpdateBlobsRequest>,
    ) -> RpcResult<remexec::BatchUpdateBlobsResponse> {
        self.batch_update_blobs_calls.fetch_add(1, Ordering::SeqCst);
        self.upload_authorization_headers.lock().unwrap().push(
            request
                .metadata()
                .get("authorization")
                .map(|v| v.to_str().unwrap().to_owned()),
        );
        let _upload = self.begin_upload().await;
        let request = request.into_inner();
        self.batch_requests.lock().unwrap().push(request.clone());
        if let Some(received) = &self.stalled_batch {
            received.notify_one();
            std::future::pending::<()>().await;
        }
        if let Some(code) = self.batch_error {
            return Err(Status::new(code, "batch_error"));
        }
        if request.instance_name != self.instance_name {
            return Err(Status::invalid_argument(request.instance_name));
        }
        self.batched_blob_count
            .fetch_add(request.requests.len(), Ordering::SeqCst);
        let total_bytes: usize = request.requests.iter().map(|r| r.data.len()).sum();
        if self.max_batch_bytes > 0 && total_bytes as i64 > self.max_batch_bytes {
            return Err(Status::invalid_argument("batch too large"));
        }
        let mut responses: Vec<_> = request
            .requests
            .into_iter()
            .map(|request| {
                let digest = request.digest.unwrap_or_default();
                let status = if self.refused_blob.lock().unwrap().as_ref() == Some(&digest) {
                    Some(rpc::Status {
                        code: tonic::Code::Unavailable as i32,
                        message: "refused blob".into(),
                        details: vec![],
                    })
                } else if digest::of_bytes(&request.data) == digest {
                    self.blobs
                        .lock()
                        .unwrap()
                        .insert((digest.hash.clone(), digest.size_bytes), request.data);
                    None
                } else {
                    Some(rpc::Status {
                        code: tonic::Code::InvalidArgument as i32,
                        message: "digest mismatch".to_owned(),
                        details: vec![],
                    })
                };
                remexec::batch_update_blobs_response::Response {
                    digest: Some(digest),
                    status,
                }
            })
            .collect();
        if let Some(change) = self.batch_response_change {
            change(&mut responses);
        }
        Ok(Response::new(remexec::BatchUpdateBlobsResponse {
            responses,
        }))
    }

    async fn batch_read_blobs(
        &self,
        _: Request<remexec::BatchReadBlobsRequest>,
    ) -> RpcResult<remexec::BatchReadBlobsResponse> {
        Err(Status::unimplemented("BatchReadBlobs"))
    }

    type GetTreeStream =
        Pin<Box<dyn Stream<Item = std::result::Result<remexec::GetTreeResponse, Status>> + Send>>;

    async fn get_tree(
        &self,
        _: Request<remexec::GetTreeRequest>,
    ) -> RpcResult<Self::GetTreeStream> {
        Err(Status::unimplemented("GetTree"))
    }

    async fn split_blob(
        &self,
        _: Request<remexec::SplitBlobRequest>,
    ) -> RpcResult<remexec::SplitBlobResponse> {
        Err(Status::unimplemented("SplitBlob"))
    }

    async fn splice_blob(
        &self,
        _: Request<remexec::SpliceBlobRequest>,
    ) -> RpcResult<remexec::SpliceBlobResponse> {
        Err(Status::unimplemented("SpliceBlob"))
    }

    type GetChunkMappingStream = Pin<
        Box<
            dyn Stream<Item = std::result::Result<remexec::GetChunkMappingResponse, Status>> + Send,
        >,
    >;

    async fn get_chunk_mapping(
        &self,
        _: Request<remexec::GetChunkMappingRequest>,
    ) -> RpcResult<Self::GetChunkMappingStream> {
        Err(Status::unimplemented("GetChunkMapping"))
    }

    async fn register_chunk_mapping(
        &self,
        _: Request<Streaming<remexec::RegisterChunkMappingRequest>>,
    ) -> RpcResult<remexec::RegisterChunkMappingResponse> {
        Err(Status::unimplemented("RegisterChunkMapping"))
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

    async fn write(&self, request: Request<Streaming<WriteRequest>>) -> RpcResult<WriteResponse> {
        self.upload_authorization_headers.lock().unwrap().push(
            request
                .metadata()
                .get("authorization")
                .map(|v| v.to_str().unwrap().to_owned()),
        );
        let _upload = self.begin_upload().await;
        if let Some(received) = &self.stalled_write {
            received.notify_one();
            std::future::pending::<()>().await;
        }
        if let Some(code) = self.write_error {
            return Err(Status::new(code, "write_error"));
        }
        let mut stream = request.into_inner();
        let mut resource_name = None;
        let mut data = vec![];
        let mut finished = false;
        while let Some(request) = stream.message().await? {
            self.write_requests.lock().unwrap().push(request.clone());
            if resource_name.is_none() {
                resource_name = Some(request.resource_name.clone());
                self.bytestream_write_resource_names
                    .lock()
                    .unwrap()
                    .push(request.resource_name);
                if let Some(committed_size) = self.early_committed_size {
                    return Ok(Response::new(WriteResponse { committed_size }));
                }
            }
            if request.write_offset != data.len() as i64 {
                return Err(Status::invalid_argument("write_offset"));
            }
            data.extend_from_slice(&request.data);
            if request.finish_write {
                finished = true;
                break;
            }
        }
        if !finished {
            return Err(Status::invalid_argument("no finish_write"));
        }
        let committed_size = data.len() as i64;
        let ResourceName { digest, is_zstd } =
            self.parse_write_resource_name(&resource_name.unwrap_or_default())?;
        if is_zstd {
            data = zstd::bulk::decompress(&data, digest.size_bytes as usize)
                .map_err(|e| Status::invalid_argument(e.to_string()))?;
        }
        if digest::of_bytes(&data) != digest {
            return Err(Status::invalid_argument("digest mismatch"));
        }
        self.blobs
            .lock()
            .unwrap()
            .insert((digest.hash, digest.size_bytes), data);
        Ok(Response::new(WriteResponse { committed_size }))
    }

    async fn query_write_status(
        &self,
        _: Request<QueryWriteStatusRequest>,
    ) -> RpcResult<QueryWriteStatusResponse> {
        Err(Status::unimplemented("QueryWriteStatus"))
    }
}

/// FAILED_PRECONDITION with the MISSING violation REAPI servers send for missing blobs.
fn missing_blob_rpc_status(digest: &remexec::Digest) -> rpc::Status {
    let precondition_failure = PreconditionFailure {
        violations: vec![Violation {
            r#type: "MISSING".to_owned(),
            subject: format!("blobs/{}/{}", digest.hash, digest.size_bytes),
        }],
    };
    let mut status = rpc::Status {
        code: tonic::Code::FailedPrecondition as i32,
        message: "missing blob".to_owned(),
        details: vec![Default::default()],
    };
    status.details[0].type_url = "type.googleapis.com/google.rpc.PreconditionFailure".into();
    status.details[0].value = precondition_failure.encode_to_vec();
    status
}

/// [`missing_blob_rpc_status`] as a call's status.
fn missing_blob_status(digest: &remexec::Digest) -> Status {
    Status::with_details(
        tonic::Code::FailedPrecondition,
        "missing blob",
        missing_blob_rpc_status(digest).encode_to_vec().into(),
    )
}

fn finished_operation(result: operation::Result) -> Operation {
    Operation {
        name: "operation".to_owned(),
        done: true,
        result: Some(result),
        ..Default::default()
    }
}

fn response_operation(response: remexec::ExecuteResponse) -> Operation {
    let mut result = operation::Result::Response(Default::default());
    if let operation::Result::Response(any) = &mut result {
        any.type_url = "type.googleapis.com/build.bazel.remote.execution.v2.ExecuteResponse".into();
        any.value = response.encode_to_vec();
    }
    finished_operation(result)
}

impl FakeServer {
    fn decode_blob<M: Message + Default>(
        &self,
        digest: Option<&remexec::Digest>,
    ) -> std::result::Result<M, Status> {
        let digest = digest.cloned().unwrap_or_default();
        let blobs = self.blobs.lock().unwrap();
        let bytes = blobs
            .get(&(digest.hash.clone(), digest.size_bytes))
            .ok_or_else(|| missing_blob_status(&digest))?;
        M::decode(bytes.as_slice()).map_err(|e| Status::invalid_argument(e.to_string()))
    }

    /// Writes the outputs `command` declares that are in `worker_outputs`.
    fn run(&self, command: &remexec::Command) -> remexec::ActionResult {
        self.actions_run.fetch_add(1, Ordering::SeqCst);
        let output_files = command
            .output_paths
            .iter()
            .filter_map(|path| {
                let data = self.worker_outputs.get(path)?;
                Some(remexec::OutputFile {
                    path: path.clone(),
                    digest: Some(self.insert_blob(data)),
                    ..Default::default()
                })
            })
            .collect();
        remexec::ActionResult {
            output_files,
            ..Default::default()
        }
    }
}

type OperationStream = Pin<Box<dyn Stream<Item = std::result::Result<Operation, Status>> + Send>>;

fn operation_stream(operations: Vec<std::result::Result<Operation, Status>>) -> OperationStream {
    Box::pin(futures::stream::iter(operations))
}

/// Takes one from `counter` if it isn't 0.
fn take_one(counter: &AtomicUsize) -> bool {
    counter
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
        .is_ok()
}

impl FakeServer {
    /// A stream that sends `operation`, or breaks per the switches.
    fn finishing_stream(&self, operation: Operation) -> OperationStream {
        if !take_one(&self.streams_to_break) {
            return operation_stream(vec![Ok(operation)]);
        }
        if self.forget_blobs_on_break {
            self.blobs.lock().unwrap().clear();
        }
        let mut stream = vec![];
        if !self.break_before_operation {
            stream.push(Ok(Operation {
                name: operation.name.clone(),
                ..Default::default()
            }));
        }
        if let StreamBreak::Status(code) = self.stream_break {
            stream.push(Err(Status::new(code, "stream broken")));
        }
        if self.keep_operations {
            self.operations
                .lock()
                .unwrap()
                .insert(operation.name.clone(), operation);
        }
        operation_stream(stream)
    }
}

#[tonic::async_trait]
impl Execution for FakeServer {
    type ExecuteStream = OperationStream;

    async fn execute(
        &self,
        request: Request<remexec::ExecuteRequest>,
    ) -> RpcResult<Self::ExecuteStream> {
        self.execute_calls.fetch_add(1, Ordering::SeqCst);
        if take_one(&self.executes_to_refuse) {
            return Err(Status::unavailable("every worker is busy"));
        }
        let request = request.into_inner();
        if request.instance_name != self.instance_name {
            return Err(Status::invalid_argument(request.instance_name));
        }
        let action_digest = request.action_digest.unwrap_or_default();
        let action: remexec::Action = self.decode_blob(Some(&action_digest))?;
        let command: remexec::Command = self.decode_blob(action.command_digest.as_ref())?;
        if self.without_matching_worker {
            return Err(Status::failed_precondition(
                "no worker matches the platform",
            ));
        }
        if self.missing_blobs_in_response {
            let response = remexec::ExecuteResponse {
                status: Some(missing_blob_rpc_status(&action_digest)),
                ..Default::default()
            };
            return Ok(Response::new(operation_stream(vec![Ok(
                response_operation(response),
            )])));
        }
        if self.fail_operations {
            let error = operation::Result::Error(rpc::Status {
                code: tonic::Code::Internal as i32,
                message: "the worker is on fire".to_owned(),
                details: vec![],
            });
            return Ok(Response::new(operation_stream(vec![Ok(
                finished_operation(error),
            )])));
        }
        let key = (action_digest.hash.clone(), action_digest.size_bytes);
        let cached_result = (!request.skip_cache_lookup)
            .then(|| self.action_results.lock().unwrap().get(&key).cloned())
            .flatten();
        let response = match cached_result {
            Some(result) => remexec::ExecuteResponse {
                result: Some(result),
                cached_result: true,
                ..Default::default()
            },
            None => {
                let result = self.run(&command);
                self.action_results
                    .lock()
                    .unwrap()
                    .insert(key, result.clone());
                remexec::ExecuteResponse {
                    result: Some(result),
                    ..Default::default()
                }
            }
        };
        Ok(Response::new(
            self.finishing_stream(response_operation(response)),
        ))
    }

    type WaitExecutionStream = OperationStream;

    async fn wait_execution(
        &self,
        request: Request<remexec::WaitExecutionRequest>,
    ) -> RpcResult<Self::WaitExecutionStream> {
        self.wait_execution_calls.fetch_add(1, Ordering::SeqCst);
        if take_one(&self.wait_executions_to_refuse) {
            return Err(Status::unavailable("try again"));
        }
        let name = request.into_inner().name;
        let operation = self.operations.lock().unwrap().remove(&name);
        match operation {
            Some(operation) => Ok(Response::new(self.finishing_stream(operation))),
            None if self.lost_operation_in_stream => {
                Ok(Response::new(operation_stream(vec![Err(
                    Status::not_found("no operation"),
                )])))
            }
            None => Err(Status::not_found("no operation")),
        }
    }
}
