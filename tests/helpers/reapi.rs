//! In-memory REAPI farm for Cargo integration tests.

use bazel_remote_apis::build::bazel::remote::execution::v2 as remexec;
use bazel_remote_apis::build::bazel::semver::SemVer;
use bazel_remote_apis::google::bytestream::byte_stream_server::{ByteStream, ByteStreamServer};
use bazel_remote_apis::google::bytestream::{
    QueryWriteStatusRequest, QueryWriteStatusResponse, ReadRequest, ReadResponse, WriteRequest,
    WriteResponse,
};
use remexec::action_cache_server::{ActionCache, ActionCacheServer};
use remexec::capabilities_server::{Capabilities, CapabilitiesServer};
use sha2::{Digest as _, Sha256};
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tonic::transport::{Server, server::TcpIncoming};
use tonic::{Request, Response, Status, Streaming};

type RpcResult<T> = Result<Response<T>, Status>;

#[derive(Default)]
pub struct ReapiTestServer {
    pub capabilities_requests: Mutex<Vec<(String, Option<String>)>>,
    pub lookup_requests: Mutex<Vec<remexec::GetActionResultRequest>>,
    pub read_requests: Mutex<Vec<ReadRequest>>,
    results: Mutex<HashMap<(String, i64), remexec::ActionResult>>,
    blobs: Mutex<HashMap<String, Vec<u8>>>,
}

impl ReapiTestServer {
    pub async fn serve(self: &Arc<Self>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("grpc://{}", listener.local_addr().unwrap());
        tokio::spawn(
            Server::builder()
                .add_service(CapabilitiesServer::from_arc(self.clone()))
                .add_service(ActionCacheServer::from_arc(self.clone()))
                .add_service(ByteStreamServer::from_arc(self.clone()))
                .serve_with_incoming(TcpIncoming::from(listener)),
        );
        endpoint
    }

    pub fn cache_outputs(&self, action: remexec::Digest, files: Vec<(String, Vec<u8>)>) {
        let output_files = files
            .into_iter()
            .map(|(path, bytes)| {
                let digest = remexec::Digest {
                    hash: format!("{:x}", Sha256::digest(&bytes)),
                    size_bytes: bytes.len() as i64,
                };
                self.blobs.lock().unwrap().insert(
                    format!("smoke/blobs/{}/{}", digest.hash, digest.size_bytes),
                    bytes,
                );
                remexec::OutputFile {
                    path,
                    digest: Some(digest),
                    ..Default::default()
                }
            })
            .collect();
        self.results.lock().unwrap().insert(
            (action.hash, action.size_bytes),
            remexec::ActionResult {
                output_files,
                stderr_raw: b"sccache-reapi-pwd:/worker/root\n".to_vec(),
                ..Default::default()
            },
        );
    }
}

fn check_auth<T>(request: &Request<T>) -> Result<(), Status> {
    if request
        .metadata()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        != Some("Bearer test-token")
    {
        return Err(Status::unauthenticated("missing test credentials"));
    }
    Ok(())
}

#[tonic::async_trait]
impl Capabilities for ReapiTestServer {
    async fn get_capabilities(
        &self,
        request: Request<remexec::GetCapabilitiesRequest>,
    ) -> RpcResult<remexec::ServerCapabilities> {
        check_auth(&request)?;
        let auth = request
            .metadata()
            .get("authorization")
            .map(|v| v.to_str().unwrap().to_owned());
        self.capabilities_requests
            .lock()
            .unwrap()
            .push((request.into_inner().instance_name, auth));
        Ok(Response::new(remexec::ServerCapabilities {
            cache_capabilities: Some(Default::default()),
            high_api_version: Some(SemVer {
                major: 2,
                minor: 1,
                ..Default::default()
            }),
            ..Default::default()
        }))
    }
}

#[tonic::async_trait]
impl ActionCache for ReapiTestServer {
    async fn get_action_result(
        &self,
        request: Request<remexec::GetActionResultRequest>,
    ) -> RpcResult<remexec::ActionResult> {
        check_auth(&request)?;
        let request = request.into_inner();
        self.lookup_requests.lock().unwrap().push(request.clone());
        if request.instance_name != "smoke" {
            return Err(Status::invalid_argument("wrong test instance"));
        }
        let digest = request
            .action_digest
            .ok_or_else(|| Status::invalid_argument("missing action digest"))?;
        self.results
            .lock()
            .unwrap()
            .get(&(digest.hash, digest.size_bytes))
            .cloned()
            .map(Response::new)
            .ok_or_else(|| Status::not_found("cache miss"))
    }

    async fn update_action_result(
        &self,
        _: Request<remexec::UpdateActionResultRequest>,
    ) -> RpcResult<remexec::ActionResult> {
        Err(Status::unimplemented("writes are outside this test"))
    }
}

#[tonic::async_trait]
impl ByteStream for ReapiTestServer {
    type ReadStream = Pin<Box<dyn futures::Stream<Item = Result<ReadResponse, Status>> + Send>>;

    async fn read(&self, request: Request<ReadRequest>) -> RpcResult<Self::ReadStream> {
        check_auth(&request)?;
        let request = request.into_inner();
        self.read_requests.lock().unwrap().push(request.clone());
        let bytes = self
            .blobs
            .lock()
            .unwrap()
            .get(&request.resource_name)
            .cloned()
            .ok_or_else(|| Status::not_found("missing test blob"))?;
        let chunks: Vec<_> = bytes
            .chunks(64 * 1024)
            .map(|chunk| {
                Ok(ReadResponse {
                    data: chunk.to_vec(),
                })
            })
            .collect();
        Ok(Response::new(Box::pin(futures::stream::iter(chunks))))
    }

    async fn write(&self, _: Request<Streaming<WriteRequest>>) -> RpcResult<WriteResponse> {
        Err(Status::unimplemented("writes are outside this test"))
    }

    async fn query_write_status(
        &self,
        _: Request<QueryWriteStatusRequest>,
    ) -> RpcResult<QueryWriteStatusResponse> {
        Err(Status::unimplemented("writes are outside this test"))
    }
}
