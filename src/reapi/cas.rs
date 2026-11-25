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

//! CAS uploads and downloads with size limits and digest verification.

use super::client::{
    Client, RPC_TIMEOUT, ReapiChannel, RpcError, status_error, with_retries, with_timeout,
};
use super::digest;
use super::proto::build::bazel::remote::execution::v2 as remexec;
use super::proto::google::bytestream::byte_stream_client::ByteStreamClient;
use super::proto::google::bytestream::{ReadRequest, WriteRequest};
use crate::errors::*;
use futures::StreamExt;
use prost::Message;
use remexec::content_addressable_storage_client::ContentAddressableStorageClient;
use sha2::{Digest as _, Sha256};
use std::collections::HashSet;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;

/// The largest request gRPC servers take by default.
const GRPC_MAX_MESSAGE_BYTES: usize = 4 * 1024 * 1024;
/// Keeps a FindMissingBlobs request near 1 MiB, at about 100 bytes per digest.
const DIGESTS_PER_FIND_MISSING_REQUEST: usize = 10_000;
/// Uploads in flight at once, across [`Cas::ensure_uploaded`] calls.
const UPLOAD_CONCURRENCY: usize = 4;
/// Bounds `present_blobs`; clearing it costs only a FindMissingBlobs call.
const MAX_PRESENT_BLOBS: usize = 100_000;
const BYTESTREAM_WRITE_CHUNK_BYTES: usize = 1024 * 1024;
/// rlib and rmeta files compress well at low levels.
const ZSTD_LEVEL: i32 = 1;

// Download deadlines assume a minimum throughput of 1 MiB/s.
fn download_timeout(bytes: u64) -> Duration {
    RPC_TIMEOUT + Duration::from_secs(bytes / (1024 * 1024))
}

/// Allows each of [`UPLOAD_CONCURRENCY`] uploads an equal share of a 1 MiB/s link.
fn upload_timeout(bytes: u64) -> Duration {
    download_timeout(bytes.saturating_mul(UPLOAD_CONCURRENCY as u64))
}

/// Error for a local file that can't be read to upload it.
#[derive(Debug)]
pub(crate) struct UnreadableBlob(PathBuf);

impl std::fmt::Display for UnreadableBlob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "failed to read {} to upload it", self.0.display())
    }
}

impl std::error::Error for UnreadableBlob {}

#[derive(Debug, Clone)]
pub(crate) enum Blob {
    Bytes(Vec<u8>),
    File(PathBuf),
}

impl Blob {
    fn read(self, digest: &remexec::Digest) -> Result<Vec<u8>> {
        let path = match &self {
            Self::File(path) => Some(path.clone()),
            _ => None,
        };
        let mut reader = VerifiedReader::new(self.open()?, digest.clone());
        let mut bytes = vec![];
        reader.read_to_end(&mut bytes).map_err(|error| match path {
            Some(path) => Error::from(error).context(UnreadableBlob(path)),
            None => error.into(),
        })?;
        Ok(bytes)
    }

    fn open(self) -> Result<Box<dyn Read + Send>> {
        match self {
            Blob::Bytes(bytes) => Ok(Box::new(io::Cursor::new(bytes))),
            Blob::File(path) => {
                let file = std::fs::File::open(&path).with_context(|| UnreadableBlob(path))?;
                Ok(Box::new(file))
            }
        }
    }
}

struct VerifiedReader<R> {
    inner: R,
    expected: remexec::Digest,
    hasher: Sha256,
    size: u64,
}

impl<R: Read> VerifiedReader<R> {
    fn new(inner: R, expected: remexec::Digest) -> Self {
        Self {
            inner,
            expected,
            hasher: Sha256::new(),
            size: 0,
        }
    }
}

impl<R: Read> Read for VerifiedReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        // Bound reads even if a file grew after its digest was computed.
        let remaining = (self.expected.size_bytes as u64).saturating_sub(self.size);
        let limit = buffer
            .len()
            .min(usize::try_from(remaining.saturating_add(1)).unwrap_or(usize::MAX));
        let count = self.inner.read(&mut buffer[..limit])?;
        self.size += count as u64;
        self.hasher.update(&buffer[..count]);
        if self.size > self.expected.size_bytes as u64
            || (count == 0
                && (self.size != self.expected.size_bytes as u64
                    || format!("{:x}", self.hasher.clone().finalize()) != self.expected.hash))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "blob digest mismatch",
            ));
        }
        Ok(count)
    }
}

// Preserve reader and compressor state between blocking tasks as the RPC requests chunks.
enum ChunkReader {
    Unopened {
        blob: Blob,
        digest: remexec::Digest,
        compress: bool,
    },
    Open {
        reader: Box<dyn Read + Send>,
        file: Option<PathBuf>,
    },
}

impl ChunkReader {
    /// The next chunk to send, and `self` to read the rest from. Blocks.
    fn next_chunk(self) -> Result<(Self, Vec<u8>)> {
        let (mut reader, file) = match self {
            ChunkReader::Unopened {
                blob,
                digest,
                compress,
            } => {
                let file = match &blob {
                    Blob::File(path) => Some(path.clone()),
                    Blob::Bytes(_) => None,
                };
                let reader = VerifiedReader::new(blob.open()?, digest);
                let reader: Box<dyn Read + Send> = if compress {
                    Box::new(zstd::stream::read::Encoder::new(reader, ZSTD_LEVEL)?)
                } else {
                    Box::new(reader)
                };
                (reader, file)
            }
            ChunkReader::Open { reader, file } => (reader, file),
        };
        let mut data = Vec::with_capacity(BYTESTREAM_WRITE_CHUNK_BYTES);
        if let Err(e) = (&mut reader)
            .take(BYTESTREAM_WRITE_CHUNK_BYTES as u64)
            .read_to_end(&mut data)
        {
            return Err(match file {
                Some(path) => Error::from(e).context(UnreadableBlob(path)),
                None => e.into(),
            });
        }
        Ok((ChunkReader::Open { reader, file }, data))
    }
}

// Allow at least a 16 MiB window for streaming compression with unknown input size.
fn zstd_window_log_max(size_bytes: u64) -> u32 {
    (u64::BITS - size_bytes.saturating_sub(1).leading_zeros()).max(24)
}

pub(crate) struct Cas {
    instance_name: String,
    bytestream_client: ByteStreamClient<ReapiChannel>,
    cas_client: ContentAddressableStorageClient<ReapiChannel>,
    max_batch_bytes: usize,
    present_blobs: Mutex<HashSet<remexec::Digest>>,
    max_present_blobs: usize,
    upload_permits: tokio::sync::Semaphore,
    supports_zstd_bytestream: bool,
}

fn batch_blob_bytes(digest: &remexec::Digest) -> usize {
    let request = remexec::batch_update_blobs_request::Request {
        digest: Some(digest.clone()),
        ..Default::default()
    };
    let bytes = usize::try_from(digest.size_bytes).unwrap_or(usize::MAX);
    let data_len = if bytes == 0 {
        0
    } else {
        1usize
            .saturating_add(prost::length_delimiter_len(bytes))
            .saturating_add(bytes)
    };
    let request_len = request.encoded_len().saturating_add(data_len);
    1usize
        .saturating_add(prost::length_delimiter_len(request_len))
        .saturating_add(request_len)
}

impl Cas {
    pub(crate) fn new(client: &Client) -> Self {
        Cas {
            instance_name: client.instance_name().to_owned(),
            bytestream_client: ByteStreamClient::new(client.channel()),
            cas_client: ContentAddressableStorageClient::new(client.channel()),
            max_batch_bytes: client.max_batch_bytes().min(GRPC_MAX_MESSAGE_BYTES),
            present_blobs: Mutex::new(HashSet::new()),
            max_present_blobs: MAX_PRESENT_BLOBS,
            upload_permits: tokio::sync::Semaphore::new(UPLOAD_CONCURRENCY),
            supports_zstd_bytestream: client.supports_zstd_bytestream(),
        }
    }

    /// `{blobs,compressed-blobs/zstd}/<hash>/<size>`, in the encoding this CAS's transfers use.
    fn blob_name(&self, digest: &remexec::Digest) -> String {
        let blobs = if self.supports_zstd_bytestream {
            "compressed-blobs/zstd"
        } else {
            "blobs"
        };
        format!("{blobs}/{}/{}", digest.hash, digest.size_bytes)
    }

    fn with_instance_name(&self, name: String) -> String {
        if self.instance_name.is_empty() {
            name
        } else {
            format!("{}/{name}", self.instance_name)
        }
    }

    fn download_resource_name(&self, digest: &remexec::Digest) -> String {
        self.with_instance_name(self.blob_name(digest))
    }

    /// Blobs over `max_bytes` are rejected before any network request.
    pub(crate) async fn download_blob(
        &self,
        digest: &remexec::Digest,
        max_bytes: u64,
    ) -> Result<Vec<u8>> {
        self.download_blob_into(digest, max_bytes, vec![]).await
    }

    /// Downloads a blob into `out` and verifies its size and hash.
    /// Decompression, hashing and writes run on a blocking thread.
    ///
    /// Blobs over `max_bytes` are rejected before downloading. Use temporary files
    /// for disk outputs: errors may leave partial data.
    pub(super) async fn download_blob_into<W: Write + Send + 'static>(
        &self,
        digest: &remexec::Digest,
        max_bytes: u64,
        out: W,
    ) -> Result<W> {
        digest::check(digest)?;
        let size_bytes = digest.size_bytes as u64;
        if size_bytes > max_bytes {
            bail!(
                "blob {}/{} in the REAPI CAS is larger than {max_bytes} bytes",
                digest.hash,
                digest.size_bytes
            );
        }
        if size_bytes == 0 {
            return Ok(out);
        }
        let resource_name = self.download_resource_name(digest);
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(2);
        let supports_zstd_bytestream = self.supports_zstd_bytestream;
        let write_task = tokio::task::spawn_blocking(move || -> Result<(W, remexec::Digest)> {
            let mut hashing_writer = HashingWriter::new(out, size_bytes);
            if supports_zstd_bytestream {
                let mut decoder = zstd::stream::raw::Decoder::new()?;
                decoder.set_parameter(zstd::zstd_safe::DParameter::WindowLogMax(
                    zstd_window_log_max(size_bytes),
                ))?;
                let mut sink = zstd::stream::zio::Writer::new(&mut hashing_writer, decoder);
                while let Some(chunk) = rx.blocking_recv() {
                    sink.write_all(&chunk)?;
                }
                // Check frame completion to catch truncated trailers.
                sink.finish()?;
            } else {
                while let Some(chunk) = rx.blocking_recv() {
                    hashing_writer.write_all(&chunk)?;
                }
            }
            hashing_writer.finish()
        });
        let description = format!(
            "failed to download blob {}/{} from the REAPI CAS",
            digest.hash, digest.size_bytes
        );
        let download_result = with_timeout(&description, download_timeout(size_bytes), async {
            // Only opening the stream is tried again. Its chunks go straight to `out`, so a
            // broken stream isn't read again.
            let mut stream = with_retries(|| async {
                self.bytestream_client
                    .clone()
                    .read(ReadRequest {
                        resource_name: resource_name.clone(),
                        read_offset: 0,
                        read_limit: 0,
                    })
                    .await
                    .map_err(status_error)
            })
            .await?
            .into_inner();
            while let Some(chunk) = stream.message().await.map_err(status_error)? {
                // Writer errors are returned when joining the blocking task below.
                if tx.send(chunk.data).await.is_err() {
                    break;
                }
            }
            Ok(())
        })
        .await;
        drop(tx);
        let write_result = write_task.await?;
        download_result?;
        let (out, received_digest) = write_result.with_context(|| description.clone())?;
        if received_digest != *digest {
            bail!(
                "{description}: the REAPI server sent blob {}/{} instead",
                received_digest.hash,
                received_digest.size_bytes
            );
        }
        Ok(out)
    }
}

impl Cas {
    /// Makes the next uploads look every blob up, after the CAS evicted some.
    pub(crate) fn forget_present_blobs(&self) {
        self.present_blobs.lock().unwrap().clear();
    }

    fn is_known_present(&self, digest: &remexec::Digest) -> bool {
        // The CAS always has the empty blob.
        digest.size_bytes == 0 || self.present_blobs.lock().unwrap().contains(digest)
    }

    /// Uploads whichever of `blobs` the CAS doesn't have, in batches, or through ByteStream
    /// if too large for one. A local file that can't be read fails with [`UnreadableBlob`].
    /// A blob that another call uploads while this one waits for an upload permit isn't
    /// uploaded again.
    pub(crate) async fn ensure_uploaded(&self, blobs: Vec<(remexec::Digest, Blob)>) -> Result<()> {
        for (digest, _) in &blobs {
            digest::check(digest)?;
        }
        let mut seen = HashSet::new();
        let candidates: Vec<(remexec::Digest, Blob)> = blobs
            .into_iter()
            .filter(|(digest, _)| !self.is_known_present(digest) && seen.insert(digest.clone()))
            .collect();
        if candidates.is_empty() {
            return Ok(());
        }
        let digests: Vec<remexec::Digest> = candidates
            .iter()
            .map(|(digest, _)| digest.clone())
            .collect();
        let missing = self.find_missing(&digests).await?;
        // Room for the request's instance name and digest function.
        let empty_batch_bytes = remexec::BatchUpdateBlobsRequest {
            instance_name: self.instance_name.clone(),
            digest_function: remexec::digest_function::Value::Sha256 as i32,
            ..Default::default()
        }
        .encoded_len();
        let mut batches = vec![];
        let mut batch = vec![];
        let mut batch_bytes = empty_batch_bytes;
        let mut large_blobs = vec![];
        for (digest, blob) in candidates.into_iter().filter(|(d, _)| missing.contains(d)) {
            let size = batch_blob_bytes(&digest);
            if empty_batch_bytes.saturating_add(size) > self.max_batch_bytes {
                large_blobs.push((digest, blob));
                continue;
            }
            if batch_bytes.saturating_add(size) > self.max_batch_bytes {
                batches.push(std::mem::take(&mut batch));
                batch_bytes = empty_batch_bytes;
            }
            batch.push((digest, blob));
            batch_bytes += size;
        }
        if !batch.is_empty() {
            batches.push(batch);
        }
        futures::try_join!(
            futures::future::try_join_all(batches.into_iter().map(|batch| {
                self.upload_with_permit(batch, |batch| self.batch_update_blobs(batch))
            })),
            futures::future::try_join_all(large_blobs.into_iter().map(|large_blob| {
                self.upload_with_permit(vec![large_blob], |blobs| async move {
                    for (digest, blob) in blobs {
                        with_retries(|| self.write_blob(digest.clone(), blob.clone())).await?;
                    }
                    Ok(())
                })
            })),
        )?;
        let mut present_blobs = self.present_blobs.lock().unwrap();
        if present_blobs.len() + digests.len() > self.max_present_blobs {
            present_blobs.clear();
        }
        present_blobs.extend(digests.into_iter().take(self.max_present_blobs));
        Ok(())
    }

    /// Waits for an upload permit, then uploads with `upload` whichever of `blobs` aren't
    /// known to be present by then.
    async fn upload_with_permit<F, U>(
        &self,
        blobs: Vec<(remexec::Digest, Blob)>,
        upload: F,
    ) -> Result<()>
    where
        F: FnOnce(Vec<(remexec::Digest, Blob)>) -> U,
        U: Future<Output = Result<()>>,
    {
        let _permit = self
            .upload_permits
            .acquire()
            .await
            .expect("the upload semaphore is never closed");
        let blobs: Vec<_> = blobs
            .into_iter()
            .filter(|(digest, _)| !self.is_known_present(digest))
            .collect();
        if blobs.is_empty() {
            return Ok(());
        }
        let digests: Vec<_> = blobs.iter().map(|(digest, _)| digest.clone()).collect();
        upload(blobs).await?;
        self.remember_present(digests);
        Ok(())
    }

    fn remember_present(&self, digests: Vec<remexec::Digest>) {
        let mut present_blobs = self.present_blobs.lock().unwrap();
        if present_blobs.len() + digests.len() > self.max_present_blobs {
            present_blobs.clear();
        }
        present_blobs.extend(digests.into_iter().take(self.max_present_blobs));
    }

    async fn find_missing(&self, digests: &[remexec::Digest]) -> Result<HashSet<remexec::Digest>> {
        let mut missing = HashSet::new();
        for chunk in digests.chunks(DIGESTS_PER_FIND_MISSING_REQUEST) {
            let request = remexec::FindMissingBlobsRequest {
                instance_name: self.instance_name.clone(),
                blob_digests: chunk.to_vec(),
                digest_function: remexec::digest_function::Value::Sha256 as i32,
            };
            if request.encoded_len() > GRPC_MAX_MESSAGE_BYTES {
                bail!("FindMissingBlobs request exceeds the gRPC message limit");
            }
            let response = with_timeout(
                "failed to ask the REAPI CAS which blobs it lacks",
                RPC_TIMEOUT,
                with_retries(|| async {
                    self.cas_client
                        .clone()
                        .find_missing_blobs(request.clone())
                        .await
                        .map_err(status_error)
                }),
            )
            .await?;
            let requested: HashSet<_> = chunk.iter().collect();
            for digest in response.into_inner().missing_blob_digests {
                if !requested.contains(&digest) {
                    bail!("FindMissingBlobs returned an unrequested digest");
                }
                missing.insert(digest);
            }
        }
        Ok(missing)
    }

    async fn batch_update_blobs(&self, blobs: Vec<(remexec::Digest, Blob)>) -> Result<()> {
        let requests = tokio::task::spawn_blocking(move || {
            blobs
                .into_iter()
                .map(|(digest, blob)| {
                    let data = blob.read(&digest)?;
                    Ok(remexec::batch_update_blobs_request::Request {
                        digest: Some(digest),
                        data,
                        compressor: remexec::compressor::Value::Identity as i32,
                    })
                })
                .collect::<Result<Vec<_>>>()
        })
        .await??;
        let mut unanswered: HashSet<remexec::Digest> = requests
            .iter()
            .filter_map(|request| request.digest.clone())
            .collect();
        let bytes: u64 = requests.iter().map(|r| r.data.len() as u64).sum();
        let request = remexec::BatchUpdateBlobsRequest {
            instance_name: self.instance_name.clone(),
            requests,
            digest_function: remexec::digest_function::Value::Sha256 as i32,
        };
        if request.encoded_len() > self.max_batch_bytes {
            bail!("BatchUpdateBlobs request exceeds the negotiated message limit");
        }
        let description = format!(
            "failed to upload a batch of {} blobs to the REAPI CAS",
            unanswered.len()
        );
        // A blob the server refuses in its answer isn't sent again.
        let response = with_timeout(
            &description,
            upload_timeout(bytes),
            with_retries(|| async {
                self.cas_client
                    .clone()
                    .batch_update_blobs(request.clone())
                    .await
                    .map_err(status_error)
            }),
        )
        .await?
        .into_inner();
        for response in response.responses {
            let digest = response
                .digest
                .context("BatchUpdateBlobs response has no digest")?;
            if !unanswered.remove(&digest) {
                bail!("BatchUpdateBlobs returned a duplicate or unrequested digest");
            }
            if let Some(status) = response.status.filter(|status| status.code != 0) {
                return Err(Error::new(RpcError {
                    code: tonic::Code::from(status.code),
                    message: status.message,
                }))
                .with_context(|| {
                    format!(
                        "{description}: the REAPI server refused blob {}/{}",
                        digest.hash, digest.size_bytes
                    )
                });
            }
        }
        if let Some(digest) = unanswered.iter().next() {
            bail!(
                "{description}: the REAPI server didn't answer for blob {}/{}",
                digest.hash,
                digest.size_bytes
            );
        }
        Ok(())
    }

    fn upload_resource_name(&self, digest: &remexec::Digest) -> String {
        self.with_instance_name(format!(
            "uploads/{}/{}",
            uuid::Uuid::new_v4(),
            self.blob_name(digest)
        ))
    }

    /// Uploads `blob` through ByteStream, a chunk at a time, each read on a blocking thread
    /// when the request stream asks for it.
    async fn write_blob(&self, digest: remexec::Digest, blob: Blob) -> Result<()> {
        let resource_name = self.upload_resource_name(&digest);
        let read_error: Arc<Mutex<Option<Error>>> = Arc::default();
        let sent_bytes = Arc::new(AtomicU64::new(0));
        let finished = Arc::new(AtomicBool::new(false));
        let chunk_reader = ChunkReader::Unopened {
            blob,
            digest: digest.clone(),
            compress: self.supports_zstd_bytestream,
        };
        let requests = futures::stream::unfold(Some(chunk_reader), {
            let (read_error, sent_bytes, finished) =
                (read_error.clone(), sent_bytes.clone(), finished.clone());
            move |chunk_reader| {
                let (read_error, sent_bytes, resource_name, finished) = (
                    read_error.clone(),
                    sent_bytes.clone(),
                    resource_name.clone(),
                    finished.clone(),
                );
                async move {
                    let chunk_reader = chunk_reader?;
                    let next_chunk = tokio::task::spawn_blocking(move || chunk_reader.next_chunk())
                        .await
                        .map_err(Error::from)
                        .flatten();
                    let (chunk_reader, data) = match next_chunk {
                        Ok(next_chunk) => next_chunk,
                        Err(e) => {
                            *read_error.lock().unwrap() = Some(e);
                            return None;
                        }
                    };
                    let offset = sent_bytes.fetch_add(data.len() as u64, Ordering::Relaxed);
                    let finish_write = data.len() < BYTESTREAM_WRITE_CHUNK_BYTES;
                    let request = WriteRequest {
                        // Only the first request names the resource.
                        resource_name: if offset == 0 {
                            resource_name
                        } else {
                            String::new()
                        },
                        write_offset: offset as i64,
                        finish_write,
                        data,
                    };
                    if request.encoded_len() > GRPC_MAX_MESSAGE_BYTES {
                        *read_error.lock().unwrap() = Some(anyhow!(
                            "ByteStream Write request exceeds the gRPC message limit"
                        ));
                        return None;
                    }
                    if finish_write {
                        finished.store(true, Ordering::Release);
                    }
                    Some((request, (!finish_write).then_some(chunk_reader)))
                }
            }
        });
        // Hyper polls bodies in a separate task; dropping `_cancel` stops it on timeout or cancellation.
        let (_cancel, cancelled) = futures::channel::oneshot::channel::<()>();
        let requests = requests.take_until(cancelled);
        let description = format!(
            "failed to upload blob {}/{} to the REAPI CAS",
            digest.hash, digest.size_bytes
        );
        let response = with_timeout(
            &description,
            upload_timeout(digest.size_bytes as u64),
            async {
                self.bytestream_client
                    .clone()
                    .write(requests)
                    .await
                    .map_err(status_error)
            },
        )
        .await;
        // Duplicate uploads may finish early; local read errors matter only if the RPC failed.
        let committed_size = match response {
            Ok(response) => response.into_inner().committed_size,
            Err(e) => return Err(read_error.lock().unwrap().take().unwrap_or(e)),
        };
        let stream_finished = finished.load(Ordering::Acquire);
        let sent_bytes = sent_bytes.load(Ordering::Relaxed);
        let valid_size = if self.supports_zstd_bytestream {
            committed_size == -1 || (stream_finished && committed_size == sent_bytes as i64)
        } else {
            committed_size == digest.size_bytes
        };
        if !valid_size {
            bail!(
                "{description}: the REAPI server committed {committed_size} of {sent_bytes} bytes"
            );
        }
        Ok(())
    }
}

/// Writes beyond `max_len` are rejected before reaching the inner writer.
struct HashingWriter<W> {
    inner: W,
    hasher: Sha256,
    len: u64,
    max_len: u64,
}

impl<W: Write> HashingWriter<W> {
    fn new(inner: W, max_len: u64) -> Self {
        HashingWriter {
            inner,
            hasher: Sha256::new(),
            len: 0,
            max_len,
        }
    }

    fn finish(mut self) -> Result<(W, remexec::Digest)> {
        self.inner.flush()?;
        let digest = remexec::Digest {
            hash: format!("{:x}", self.hasher.finalize()),
            size_bytes: self.len as i64,
        };
        Ok((self.inner, digest))
    }
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.len + buf.len() as u64 > self.max_len {
            return Err(io::Error::other(format!(
                "the blob is more than {} bytes",
                self.max_len
            )));
        }
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        self.len += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::reapi::client::{ConnectOptions, RETRIES, rpc_code};
    use crate::reapi::test::FakeServer;
    use rand::{RngCore, SeedableRng};
    use std::sync::Arc;
    use std::sync::atomic::Ordering;
    use test_case::test_case;
    use tokio::sync::Notify;

    const MAX_BYTES: u64 = 1 << 20;

    // Use random data to exercise multiple ByteStream chunks even with compression.
    fn incompressible_bytes() -> Vec<u8> {
        incompressible_bytes_of_len(64 * 1024)
    }

    fn incompressible_bytes_of_len(len: usize) -> Vec<u8> {
        let mut data = vec![0; len];
        rand::rngs::StdRng::seed_from_u64(0).fill_bytes(&mut data);
        data
    }

    async fn cas_and_server(supports_zstd_bytestream: bool) -> (Cas, Arc<FakeServer>) {
        cas_with(FakeServer {
            supports_zstd_bytestream,
            ..Default::default()
        })
        .await
    }

    /// A server whose batches take 64 KiB.
    async fn cas_with_small_batches(server: FakeServer) -> (Cas, Arc<FakeServer>) {
        cas_with(FakeServer {
            max_batch_bytes: 64 * 1024,
            ..server
        })
        .await
    }

    fn blob(data: &[u8]) -> (remexec::Digest, Blob) {
        (digest::of_bytes(data), Blob::Bytes(data.to_vec()))
    }

    async fn cas_with(server: FakeServer) -> (Cas, Arc<FakeServer>) {
        let server = Arc::new(server);
        (Cas::new(&server.serve_and_connect().await), server)
    }

    #[tokio::test]
    async fn test_uploads_only_what_the_cas_lacks() {
        let (cas, server) = cas_with(FakeServer {
            instance_name: "main".to_owned(),
            ..Default::default()
        })
        .await;
        server.insert_blob(b"present");
        cas.ensure_uploaded(vec![blob(b"present"), blob(b"new"), blob(b"new")])
            .await
            .unwrap();
        assert!(server.has_blob(b"new"));
        assert_eq!(1, server.batch_update_blobs_calls.load(Ordering::SeqCst));
        // "new" is uploaded once.
        assert_eq!(1, server.batched_blob_count.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn test_known_present_blobs_are_not_looked_up_again() {
        let (cas, server) = cas_with(FakeServer::default()).await;
        server.insert_blob(b"present");
        cas.ensure_uploaded(vec![blob(b"present"), blob(b"new")])
            .await
            .unwrap();
        cas.ensure_uploaded(vec![blob(b"present"), blob(b"new")])
            .await
            .unwrap();
        assert_eq!(1, server.find_missing_blobs_calls.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn test_a_full_set_of_present_blobs_is_cleared() {
        let (mut cas, server) = cas_with(FakeServer::default()).await;
        cas.max_present_blobs = 1;
        cas.ensure_uploaded(vec![blob(b"a")]).await.unwrap();
        cas.ensure_uploaded(vec![blob(b"b")]).await.unwrap();
        cas.ensure_uploaded(vec![blob(b"b")]).await.unwrap();
        assert_eq!(2, server.find_missing_blobs_calls.load(Ordering::SeqCst));
        // Adding "b" cleared "a".
        cas.ensure_uploaded(vec![blob(b"a")]).await.unwrap();
        assert_eq!(3, server.find_missing_blobs_calls.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn test_a_blob_another_call_uploaded_is_not_uploaded_again() {
        let (mut cas, server) = cas_with_small_batches(FakeServer::default()).await;
        cas.upload_permits = tokio::sync::Semaphore::new(1);
        let blobs = vec![blob(b"small"), blob(&incompressible_bytes())];
        let (first, second) = futures::join!(
            cas.ensure_uploaded(blobs.clone()),
            cas.ensure_uploaded(blobs)
        );
        first.unwrap();
        second.unwrap();
        assert_eq!(1, server.batched_blob_count.load(Ordering::SeqCst));
        let resource_names = server.bytestream_write_resource_names.lock().unwrap();
        assert_eq!(1, resource_names.len());
    }

    #[tokio::test]
    async fn test_batches_stay_under_the_server_limit() {
        let (cas, server) = cas_with(FakeServer {
            max_batch_bytes: 3 * 1024,
            ..Default::default()
        })
        .await;
        let blobs: Vec<Vec<u8>> = (0..3u8).map(|i| vec![i; 1000]).collect();
        let to_upload: Vec<_> = blobs.iter().map(|data| blob(data)).collect();
        cas.ensure_uploaded(to_upload).await.unwrap();
        assert!(blobs.iter().all(|data| server.has_blob(data)));
        // Two blobs of 1000 bytes and their overhead fit in 3 KiB; three don't.
        assert_eq!(2, server.batch_update_blobs_calls.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn test_batches_leave_room_for_the_instance_name() {
        let (cas, server) = cas_with(FakeServer {
            instance_name: "i".repeat(200),
            max_batch_bytes: 3 * 1024,
            ..Default::default()
        })
        .await;
        // The encoded request fits in 3 KiB only without the instance name.
        cas.ensure_uploaded(vec![blob(&[0; 1400]), blob(&[1; 1400])])
            .await
            .unwrap();
        assert_eq!(2, server.batch_update_blobs_calls.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn test_batches_stay_under_the_grpc_limit() {
        let (cas, server) = cas_with(FakeServer {
            max_batch_bytes: 16 * 1024 * 1024,
            ..Default::default()
        })
        .await;
        // The fake server, like most, takes requests of up to 4 MiB.
        let blobs: Vec<Vec<u8>> = (0..3u8).map(|i| vec![i; 1536 * 1024]).collect();
        let to_upload: Vec<_> = blobs.iter().map(|data| blob(data)).collect();
        cas.ensure_uploaded(to_upload).await.unwrap();
        assert!(blobs.iter().all(|data| server.has_blob(data)));
        assert_eq!(2, server.batch_update_blobs_calls.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn test_a_blob_that_fits_only_without_its_overhead_goes_through_bytestream() {
        let (cas, server) = cas_with(FakeServer {
            max_batch_bytes: 3 * 1024,
            ..Default::default()
        })
        .await;
        let large = vec![9; 3 * 1024 - 10];
        cas.ensure_uploaded(vec![blob(&large)]).await.unwrap();
        assert!(server.has_blob(&large));
        assert_eq!(0, server.batch_update_blobs_calls.load(Ordering::SeqCst));
        assert_eq!(
            1,
            server.bytestream_write_resource_names.lock().unwrap().len()
        );
    }

    #[test_case(false ; "uncompressed")]
    #[test_case(true ; "zstd")]
    #[tokio::test]
    async fn test_large_blobs_go_through_bytestream(supports_zstd_bytestream: bool) {
        let (cas, server) = cas_with_small_batches(FakeServer {
            instance_name: "main".to_owned(),
            supports_zstd_bytestream,
            ..Default::default()
        })
        .await;
        // Several chunks even compressed.
        let large = incompressible_bytes_of_len(3 * BYTESTREAM_WRITE_CHUNK_BYTES + 10);
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("large");
        std::fs::write(&file, &large).unwrap();
        cas.ensure_uploaded(vec![(digest::of_bytes(&large), Blob::File(file))])
            .await
            .unwrap();
        assert!(server.has_blob(&large));
        assert_eq!(0, server.batch_update_blobs_calls.load(Ordering::SeqCst));
        let resource_names = server.bytestream_write_resource_names.lock().unwrap();
        assert_eq!(1, resource_names.len());
        assert_eq!(
            supports_zstd_bytestream,
            resource_names[0].contains("/compressed-blobs/zstd/"),
            "{resource_names:?}"
        );
    }

    #[tokio::test]
    async fn test_an_upload_of_whole_chunks_finishes() {
        let (cas, server) = cas_with_small_batches(FakeServer::default()).await;
        // The last request carries no data, only `finish_write`.
        let data = incompressible_bytes_of_len(2 * BYTESTREAM_WRITE_CHUNK_BYTES);
        cas.ensure_uploaded(vec![blob(&data)]).await.unwrap();
        assert!(server.has_blob(&data));
        let requests = server.write_requests.lock().unwrap();
        assert_eq!(requests.len(), 3);
        assert!(!requests[0].resource_name.is_empty());
        assert!(
            requests[1..]
                .iter()
                .all(|request| request.resource_name.is_empty())
        );
        assert_eq!(
            requests.iter().map(|r| r.write_offset).collect::<Vec<_>>(),
            vec![
                0,
                BYTESTREAM_WRITE_CHUNK_BYTES as i64,
                2 * BYTESTREAM_WRITE_CHUNK_BYTES as i64
            ]
        );
        assert_eq!(
            requests.iter().map(|r| r.finish_write).collect::<Vec<_>>(),
            vec![false, false, true]
        );
        assert!(requests[2].data.is_empty());
    }

    const EARLY_FINISH_BYTES: usize = 3 * BYTESTREAM_WRITE_CHUNK_BYTES;

    #[test_case(false, EARLY_FINISH_BYTES as i64 ; "uncompressed")]
    #[test_case(true, -1 ; "zstd")]
    #[tokio::test]
    async fn test_a_write_the_server_ends_early_succeeds(
        supports_zstd_bytestream: bool,
        committed_size: i64,
    ) {
        let (cas, server) = cas_with_small_batches(FakeServer {
            supports_zstd_bytestream,
            early_committed_size: Some(committed_size),
            ..Default::default()
        })
        .await;
        let data = incompressible_bytes_of_len(EARLY_FINISH_BYTES);
        cas.ensure_uploaded(vec![blob(&data)]).await.unwrap();
        assert_eq!(
            1,
            server.bytestream_write_resource_names.lock().unwrap().len()
        );
    }

    #[test_case(-1 ; "minus one uncompressed")]
    #[test_case(1000 ; "part of the blob")]
    #[tokio::test]
    async fn test_a_wrong_committed_size_fails_the_upload(committed_size: i64) {
        let (cas, _) = cas_with_small_batches(FakeServer {
            early_committed_size: Some(committed_size),
            ..Default::default()
        })
        .await;
        let data = incompressible_bytes_of_len(EARLY_FINISH_BYTES);
        let e = cas.ensure_uploaded(vec![blob(&data)]).await.unwrap_err();
        assert!(format!("{e:#}").contains("committed"), "{e:#}");
    }

    #[test_case(100 ; "in a batch")]
    #[test_case(100 * 1024 ; "through bytestream")]
    #[tokio::test]
    async fn test_an_unreadable_file_fails_the_upload(size: usize) {
        let (cas, _) = cas_with_small_batches(FakeServer::default()).await;
        let dir = tempfile::tempdir().unwrap();
        let missing = (
            digest::of_bytes(&vec![0; size]),
            Blob::File(dir.path().join("missing")),
        );
        let e = cas.ensure_uploaded(vec![missing]).await.unwrap_err();
        assert!(e.is::<UnreadableBlob>(), "{e:#}");
    }

    #[tokio::test]
    async fn test_a_refused_blob_fails_the_upload() {
        let (cas, server) = cas_with(FakeServer::default()).await;
        *server.refused_blob.lock().unwrap() = Some(digest::of_bytes(b"one"));
        let e = cas.ensure_uploaded(vec![blob(b"one")]).await.unwrap_err();
        assert_eq!(Some(tonic::Code::Unavailable), rpc_code(&e));
        assert_eq!(1, server.batch_update_blobs_calls.load(Ordering::SeqCst));
        assert!(cas.ensure_uploaded(vec![blob(b"one")]).await.is_err());
        assert_eq!(2, server.find_missing_blobs_calls.load(Ordering::SeqCst));
    }

    #[test_case("FindMissingBlobs" ; "find missing blobs")]
    #[test_case("BatchUpdateBlobs" ; "batch update blobs")]
    #[tokio::test]
    async fn test_upload_calls_are_tried_again_while_the_server_is_busy(method: &'static str) {
        let (cas, server) = cas_with(FakeServer::default()).await;
        server.answer_busy(method, RETRIES as usize);
        cas.ensure_uploaded(vec![blob(b"new")]).await.unwrap();
        assert!(server.has_blob(b"new"));
        assert!(server.gave_every_busy_answer());
    }

    #[tokio::test]
    async fn test_bytestream_writes_are_tried_again_while_the_server_is_busy() {
        let (cas, server) = cas_with_small_batches(FakeServer::default()).await;
        let large = incompressible_bytes_of_len(BYTESTREAM_WRITE_CHUNK_BYTES + 10);
        server.answer_busy("Write", RETRIES as usize);
        cas.ensure_uploaded(vec![(digest::of_bytes(&large), Blob::Bytes(large.clone()))])
            .await
            .unwrap();
        assert!(server.has_blob(&large));
        assert!(server.gave_every_busy_answer());
    }

    #[tokio::test]
    async fn test_downloads_are_tried_again_while_the_server_is_busy() {
        let (cas, server) = cas_and_server(false).await;
        let data = incompressible_bytes();
        let digest = server.insert_blob(&data);
        server.answer_busy("Read", RETRIES as usize);
        assert_eq!(data, cas.download_blob(&digest, MAX_BYTES).await.unwrap());
        assert!(server.gave_every_busy_answer());
    }

    #[tokio::test]
    async fn test_empty_blob_needs_no_upload() {
        let (cas, server) = cas_with(FakeServer::default()).await;
        cas.ensure_uploaded(vec![blob(b"")]).await.unwrap();
        assert_eq!(0, server.find_missing_blobs_calls.load(Ordering::SeqCst));
    }

    #[test_case(false ; "batch")]
    #[test_case(true ; "bytestream")]
    #[tokio::test]
    async fn test_upload_requests_use_instance_digest_function_and_credentials(streaming: bool) {
        let server = Arc::new(FakeServer {
            instance_name: "tenant/builds".into(),
            max_batch_bytes: 2048,
            ..Default::default()
        });
        let client = Client::connect(&ConnectOptions {
            endpoint: server.serve().await,
            instance_name: server.instance_name.clone(),
            auth_token: Some(Arc::new(
                crate::reapi::auth_token::AuthToken::fixed(" token ").unwrap(),
            )),
            ..Default::default()
        })
        .await
        .unwrap();
        let cas = Cas::new(&client);
        let data = vec![7; if streaming { 3000 } else { 100 }];
        cas.ensure_uploaded(vec![blob(&data)]).await.unwrap();
        assert_eq!(
            *server.find_authorization_headers.lock().unwrap(),
            vec![Some("Bearer token".into())]
        );
        assert_eq!(
            *server.upload_authorization_headers.lock().unwrap(),
            vec![Some("Bearer token".into())]
        );
        {
            let requests = server.find_missing_requests.lock().unwrap();
            assert_eq!(requests[0].instance_name, "tenant/builds");
            assert_eq!(
                requests[0].digest_function,
                remexec::digest_function::Value::Sha256 as i32
            );
        }
        if !streaming {
            let requests = server.batch_requests.lock().unwrap();
            assert_eq!(requests[0].instance_name, "tenant/builds");
            assert_eq!(
                requests[0].digest_function,
                remexec::digest_function::Value::Sha256 as i32
            );
            assert_eq!(
                requests[0].requests[0].compressor,
                remexec::compressor::Value::Identity as i32
            );
        }
        assert_eq!(
            data,
            cas.download_blob(&digest::of_bytes(&data), MAX_BYTES)
                .await
                .unwrap()
        );
    }

    #[test_case(remexec::Digest { hash: "bad".into(), size_bytes: 1 } ; "invalid hash")]
    #[test_case(remexec::Digest { hash: "0".repeat(64), size_bytes: -1 } ; "negative size")]
    #[test_case(remexec::Digest { hash: "0".repeat(64), size_bytes: 0 } ; "invalid empty digest")]
    #[tokio::test]
    async fn test_invalid_upload_digests_are_rejected_before_rpc(digest: remexec::Digest) {
        let (cas, server) = cas_with(FakeServer::default()).await;
        assert!(
            cas.ensure_uploaded(vec![(digest, Blob::Bytes(vec![]))])
                .await
                .is_err()
        );
        assert_eq!(server.find_missing_blobs_calls.load(Ordering::SeqCst), 0);
        assert!(server.batch_requests.lock().unwrap().is_empty());
        assert!(server.write_requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_find_missing_rejects_unrequested_digests() {
        let (cas, server) = cas_with(FakeServer {
            find_missing_override: Some(vec![digest::of_bytes(b"other")]),
            ..Default::default()
        })
        .await;
        for _ in 0..2 {
            let error = cas.ensure_uploaded(vec![blob(b"new")]).await.unwrap_err();
            assert!(format!("{error:#}").contains("unrequested digest"));
        }
        assert_eq!(server.find_missing_blobs_calls.load(Ordering::SeqCst), 2);
        assert!(server.batch_requests.lock().unwrap().is_empty());
    }

    #[test_case(|responses| responses.clear(), "didn't answer" ; "missing response")]
    #[test_case(|responses| responses[0].digest = None, "no digest" ; "missing digest")]
    #[test_case(|responses| responses.push(responses[0].clone()), "duplicate or unrequested" ; "duplicate response")]
    #[test_case(|responses| responses[0].digest = Some(digest::of_bytes(b"other")), "duplicate or unrequested" ; "wrong digest")]
    #[tokio::test]
    async fn test_invalid_batch_responses_are_not_remembered(
        change: fn(&mut Vec<remexec::batch_update_blobs_response::Response>),
        message: &str,
    ) {
        let (cas, server) = cas_with(FakeServer {
            batch_response_change: Some(change),
            ..Default::default()
        })
        .await;
        let error = cas.ensure_uploaded(vec![blob(b"new")]).await.unwrap_err();
        assert!(format!("{error:#}").contains(message), "{error:#}");
        // The server stored the bytes; a fresh presence check is still required after the bad acknowledgement.
        cas.ensure_uploaded(vec![blob(b"new")]).await.unwrap();
        assert_eq!(server.find_missing_blobs_calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_a_partial_batch_failure_can_be_retried() {
        let (cas, server) = cas_with(FakeServer::default()).await;
        *server.refused_blob.lock().unwrap() = Some(digest::of_bytes(b"second"));
        assert!(
            cas.ensure_uploaded(vec![blob(b"first"), blob(b"second")])
                .await
                .is_err()
        );
        assert!(server.has_blob(b"first"));
        assert!(!server.has_blob(b"second"));
        *server.refused_blob.lock().unwrap() = None;
        cas.ensure_uploaded(vec![blob(b"first"), blob(b"second")])
            .await
            .unwrap();
        assert!(server.has_blob(b"second"));
        assert_eq!(server.find_missing_blobs_calls.load(Ordering::SeqCst), 2);
        assert_eq!(server.batched_blob_count.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn test_batch_planning_accounts_for_protobuf_framing() {
        for size in [0, 1, 127, 128, 16_383, 16_384, 4 * 1024 * 1024] {
            let data = vec![0; size];
            let digest = digest::of_bytes(&data);
            let request = remexec::batch_update_blobs_request::Request {
                digest: Some(digest.clone()),
                data,
                ..Default::default()
            };
            let expected =
                1 + prost::length_delimiter_len(request.encoded_len()) + request.encoded_len();
            assert_eq!(batch_blob_bytes(&digest), expected);
        }
    }

    #[tokio::test]
    async fn test_one_large_call_does_not_exceed_the_presence_cache_limit() {
        let (mut cas, server) = cas_with(FakeServer::default()).await;
        cas.max_present_blobs = 1;
        cas.ensure_uploaded(vec![blob(b"first"), blob(b"second")])
            .await
            .unwrap();
        cas.ensure_uploaded(vec![blob(b"second")]).await.unwrap();
        assert_eq!(server.find_missing_blobs_calls.load(Ordering::SeqCst), 2);
    }

    #[test_case(false, 0 ; "uncompressed zero")]
    #[test_case(false, BYTESTREAM_WRITE_CHUNK_BYTES as i64 ; "uncompressed partial chunk")]
    #[test_case(true, 0 ; "zstd zero")]
    #[test_case(true, BYTESTREAM_WRITE_CHUNK_BYTES as i64 ; "zstd partial chunk")]
    #[tokio::test]
    async fn test_incomplete_stream_acknowledgements_are_rejected(
        compressed: bool,
        committed: i64,
    ) {
        let (cas, _) = cas_with_small_batches(FakeServer {
            supports_zstd_bytestream: compressed,
            early_committed_size: Some(committed),
            ..Default::default()
        })
        .await;
        let data = incompressible_bytes_of_len(EARLY_FINISH_BYTES);
        let error = cas.ensure_uploaded(vec![blob(&data)]).await.unwrap_err();
        assert!(format!("{error:#}").contains("committed"), "{error:#}");
    }

    #[test_case(100 ; "batch")]
    #[test_case(100 * 1024 ; "stream")]
    #[tokio::test]
    async fn test_changed_file_contents_are_rejected(size: usize) {
        let (cas, server) = cas_with_small_batches(FakeServer::default()).await;
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("input");
        let original = vec![1; size];
        std::fs::write(&file, vec![2; size]).unwrap();
        assert!(
            cas.ensure_uploaded(vec![(digest::of_bytes(&original), Blob::File(file))])
                .await
                .is_err()
        );
        assert!(!server.has_blob(&original));
    }

    #[test_case(|ready| FakeServer { stalled_find_missing: Some(ready), ..Default::default() }, 100 ; "find missing")]
    #[test_case(|ready| FakeServer { stalled_batch: Some(ready), ..Default::default() }, 100 ; "batch update")]
    #[test_case(|ready| FakeServer { stalled_write: Some(ready), ..Default::default() }, 100 * 1024 ; "bytestream")]
    #[tokio::test]
    async fn test_stalled_upload_calls_time_out(
        make_server: fn(Arc<Notify>) -> FakeServer,
        size: usize,
    ) {
        let ready = Arc::new(Notify::new());
        let (cas, _) = cas_with_small_batches(make_server(ready.clone())).await;
        let mut upload =
            tokio::spawn(async move { cas.ensure_uploaded(vec![blob(&vec![0; size])]).await });
        tokio::select! {
            _ = ready.notified() => {},
            result = &mut upload => panic!("upload finished before the stalled RPC: {result:?}"),
        }
        tokio::time::pause();
        tokio::time::advance(upload_timeout(size as u64) + Duration::from_secs(1)).await;
        tokio::time::resume();
        let error = upload.await.unwrap().unwrap_err();
        assert!(format!("{error:#}").contains("timed out"), "{error:#}");
    }

    #[tokio::test]
    async fn test_upload_concurrency_is_shared_across_calls_and_transports() {
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let (cas, server) = cas_with(FakeServer {
            max_batch_bytes: 6144,
            upload_gate: Some(gate.clone()),
            ..Default::default()
        })
        .await;
        let cas = Arc::new(cas);
        let mut tasks = vec![];
        for start in [0, 4] {
            let cas = cas.clone();
            tasks.push(tokio::spawn(async move {
                let mut uploads: Vec<_> =
                    (start..start + 4).map(|i| blob(&vec![i; 4000])).collect();
                uploads.push(blob(&vec![start + 100; 100 * 1024]));
                cas.ensure_uploaded(uploads).await
            }));
        }
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let started = server.upload_started.notified();
                if server.active_uploads.load(Ordering::SeqCst) == UPLOAD_CONCURRENCY {
                    break;
                }
                started.await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            server.max_active_uploads.load(Ordering::SeqCst),
            UPLOAD_CONCURRENCY
        );
        gate.add_permits(10);
        for task in tasks {
            task.await.unwrap().unwrap();
        }
        assert_eq!(
            server.max_active_uploads.load(Ordering::SeqCst),
            UPLOAD_CONCURRENCY
        );
        assert_eq!(server.batch_update_blobs_calls.load(Ordering::SeqCst), 8);
        assert_eq!(
            server.bytestream_write_resource_names.lock().unwrap().len(),
            2
        );
    }

    #[tokio::test]
    async fn test_presence_queries_are_split_at_the_digest_limit() {
        let (cas, server) = cas_with(FakeServer::default()).await;
        let uploads: Vec<_> = (0..=DIGESTS_PER_FIND_MISSING_REQUEST)
            .map(|i| {
                let data = i.to_le_bytes();
                server.insert_blob(&data);
                blob(&data)
            })
            .collect();
        cas.ensure_uploaded(uploads).await.unwrap();
        let requests = server.find_missing_requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(
            requests[0].blob_digests.len(),
            DIGESTS_PER_FIND_MISSING_REQUEST
        );
        assert_eq!(requests[1].blob_digests.len(), 1);
        assert!(server.batch_requests.lock().unwrap().is_empty());
    }

    #[test_case(FakeServer { find_missing_error: Some(tonic::Code::Internal), ..Default::default() }, 100 ; "find missing")]
    #[test_case(FakeServer { batch_error: Some(tonic::Code::Internal), ..Default::default() }, 100 ; "batch update")]
    #[test_case(FakeServer { write_error: Some(tonic::Code::Internal), ..Default::default() }, 100 * 1024 ; "bytestream")]
    #[tokio::test]
    async fn test_upload_rpc_errors_leave_presence_unknown(server: FakeServer, size: usize) {
        let (cas, server) = cas_with_small_batches(server).await;
        for _ in 0..2 {
            let error = cas
                .ensure_uploaded(vec![blob(&vec![0; size])])
                .await
                .unwrap_err();
            assert!(format!("{error:#}").contains("Internal"), "{error:#}");
        }
        assert_eq!(server.find_missing_blobs_calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_empty_blob_needs_no_download() {
        let (cas, server) = cas_and_server(false).await;
        assert!(
            cas.download_blob(&digest::of_bytes(b""), MAX_BYTES)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(server.read_requests.lock().unwrap().is_empty());
    }

    #[test_case(false ; "uncompressed")]
    #[test_case(true ; "zstd")]
    #[tokio::test]
    async fn test_a_download_gives_the_blob(supports_zstd_bytestream: bool) {
        let (cas, server) = cas_and_server(supports_zstd_bytestream).await;
        let data = incompressible_bytes();
        let digest = server.insert_blob(&data);
        assert_eq!(data, cas.download_blob(&digest, MAX_BYTES).await.unwrap());
    }

    #[tokio::test]
    async fn test_a_highly_compressible_blob_is_downloaded() {
        let (cas, server) = cas_and_server(true).await;
        let data = vec![0; MAX_BYTES as usize];
        let digest = server.insert_blob(&data);
        assert_eq!(data, cas.download_blob(&digest, MAX_BYTES).await.unwrap());
    }

    #[test_case(false ; "uncompressed")]
    #[test_case(true ; "zstd")]
    #[tokio::test]
    async fn test_a_corrupted_blob_is_an_error(supports_zstd_bytestream: bool) {
        let (cas, server) = cas_and_server(supports_zstd_bytestream).await;
        let digest = server.insert_blob(&incompressible_bytes());
        server.corrupt_reads.store(true, Ordering::SeqCst);
        let e = cas.download_blob(&digest, MAX_BYTES).await.unwrap_err();
        assert!(format!("{e:#}").contains("instead"), "{e:#}");
    }

    #[test_case(false ; "uncompressed")]
    #[test_case(true ; "zstd")]
    #[tokio::test]
    async fn test_a_blob_longer_than_its_digest_is_an_error(supports_zstd_bytestream: bool) {
        let (cas, server) = cas_and_server(supports_zstd_bytestream).await;
        let digest = server.insert_blob(&incompressible_bytes());
        server.oversize_reads.store(true, Ordering::SeqCst);
        let e = cas.download_blob(&digest, MAX_BYTES).await.unwrap_err();
        assert!(format!("{e:#}").contains("the blob is more than"), "{e:#}");
    }

    #[tokio::test]
    async fn test_a_blob_larger_than_max_bytes_is_not_downloaded() {
        let (cas, server) = cas_and_server(false).await;
        let digest = server.insert_blob(b"blob");
        let e = cas.download_blob(&digest, 3).await.unwrap_err();
        assert!(e.to_string().contains("larger than 3 bytes"), "{e}");
        assert!(server.read_requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_a_write_error_fails_the_download() {
        struct FailingWriter;
        impl Write for FailingWriter {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::other("disk full"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let (cas, server) = cas_and_server(false).await;
        let digest = server.insert_blob(&incompressible_bytes());
        let e = cas
            .download_blob_into(&digest, MAX_BYTES, FailingWriter)
            .await
            .err()
            .unwrap();
        assert!(format!("{e:#}").contains("disk full"), "{e:#}");
    }

    #[tokio::test]
    async fn test_downloads_use_the_instance_name() {
        let server = Arc::new(FakeServer {
            instance_name: "main".to_owned(),
            ..Default::default()
        });
        let cas = Cas::new(&server.serve_and_connect().await);
        let digest = server.insert_blob(b"blob");
        assert_eq!(
            b"blob".to_vec(),
            cas.download_blob(&digest, MAX_BYTES).await.unwrap()
        );
    }

    #[test_case(false ; "uncompressed")]
    #[test_case(true ; "zstd")]
    #[tokio::test]
    async fn test_downloads_send_resource_names_and_auth(supports_zstd_bytestream: bool) {
        let server = Arc::new(FakeServer {
            instance_name: "team/main".to_owned(),
            supports_zstd_bytestream,
            ..Default::default()
        });
        let client = Client::connect(&ConnectOptions {
            endpoint: server.serve().await,
            instance_name: server.instance_name.clone(),
            auth_token: Some(Arc::new(
                crate::reapi::auth_token::AuthToken::fixed("test-token").unwrap(),
            )),
            ..Default::default()
        })
        .await
        .unwrap();
        let cas = Cas::new(&client);
        let digest = server.insert_blob(b"blob");
        assert_eq!(
            b"blob",
            cas.download_blob(&digest, 4).await.unwrap().as_slice()
        );
        let prefix = if supports_zstd_bytestream {
            "compressed-blobs/zstd"
        } else {
            "blobs"
        };
        assert_eq!(
            vec![ReadRequest {
                resource_name: format!("team/main/{prefix}/{}/4", digest.hash),
                read_offset: 0,
                read_limit: 0,
            }],
            *server.read_requests.lock().unwrap()
        );
        assert_eq!(
            vec![Some("Bearer test-token".to_owned())],
            *server.read_authorization_headers.lock().unwrap()
        );
    }

    #[tokio::test]
    async fn test_invalid_digests_are_rejected_without_a_request() {
        let (cas, server) = cas_and_server(false).await;
        for invalid in [
            remexec::Digest {
                hash: "../../secret".to_owned(),
                size_bytes: 1,
            },
            remexec::Digest {
                hash: digest::of_bytes(b"x").hash,
                size_bytes: -1,
            },
            remexec::Digest {
                hash: digest::of_bytes(b"x").hash,
                size_bytes: 0,
            },
        ] {
            let error = cas.download_blob(&invalid, MAX_BYTES).await.unwrap_err();
            assert!(
                error.to_string().contains("invalid REAPI digest"),
                "{error:#}"
            );
            assert!(!format!("{error:#}").contains("secret"));
        }
        assert!(server.read_requests.lock().unwrap().is_empty());
    }

    #[test_case(false ; "uncompressed")]
    #[test_case(true ; "zstd")]
    #[tokio::test]
    async fn test_a_shorter_blob_is_an_error(supports_zstd_bytestream: bool) {
        let server = Arc::new(FakeServer {
            supports_zstd_bytestream,
            truncate_reads: true,
            ..Default::default()
        });
        let cas = Cas::new(&server.serve_and_connect().await);
        let digest = server.insert_blob(&incompressible_bytes());
        let error = cas.download_blob(&digest, MAX_BYTES).await.unwrap_err();
        assert!(format!("{error:#}").contains("instead"), "{error:#}");
    }

    #[tokio::test]
    async fn test_an_unfinished_zstd_frame_is_rejected() {
        let (cas, server) = cas_and_server(true).await;
        let data = incompressible_bytes();
        let digest = server.insert_blob(&data);
        let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 1).unwrap();
        encoder.include_checksum(true).unwrap();
        encoder.write_all(&data).unwrap();
        let mut encoded = encoder.finish().unwrap();
        // The payload is intact; the missing checksum byte must still fail validation.
        encoded.pop();
        *server.read_override.lock().unwrap() = Some(encoded);
        let error = cas.download_blob(&digest, MAX_BYTES).await.unwrap_err();
        assert!(
            format!("{error:#}").contains("incomplete frame"),
            "{error:#}"
        );
    }

    #[tokio::test]
    async fn test_malformed_zstd_is_an_error() {
        let (cas, server) = cas_and_server(true).await;
        let digest = server.insert_blob(b"blob");
        *server.read_override.lock().unwrap() = Some(b"not a zstd frame".to_vec());
        let error = cas.download_blob(&digest, MAX_BYTES).await.unwrap_err();
        assert!(
            format!("{error:#}").contains("failed to download blob"),
            "{error:#}"
        );
    }

    #[test_case(tonic::Code::Unavailable ; "unavailable")]
    #[test_case(tonic::Code::Unauthenticated ; "unauthenticated")]
    #[test_case(tonic::Code::PermissionDenied ; "permission denied")]
    #[tokio::test]
    async fn test_read_errors_have_context(code: tonic::Code) {
        let server = Arc::new(FakeServer {
            read_error: Some(code),
            ..Default::default()
        });
        let cas = Cas::new(&server.serve_and_connect().await);
        let digest = digest::of_bytes(b"blob");
        let error = cas.download_blob(&digest, MAX_BYTES).await.unwrap_err();
        assert_eq!(
            format!(
                "failed to download blob {}/4 from the REAPI CAS: {code:?}: \"read_error\"",
                digest.hash
            ),
            format!("{error:#}")
        );
    }

    #[tokio::test]
    async fn test_a_stream_error_is_not_a_successful_download() {
        let server = Arc::new(FakeServer {
            read_stream_error: Some(tonic::Code::Unavailable),
            ..Default::default()
        });
        let cas = Cas::new(&server.serve_and_connect().await);
        let digest = server.insert_blob(&incompressible_bytes());
        let error = cas.download_blob(&digest, MAX_BYTES).await.unwrap_err();
        assert!(
            format!("{error:#}").contains("Unavailable: \"read_stream_error\""),
            "{error:#}"
        );
    }

    #[test_case(false ; "uncompressed")]
    #[test_case(true ; "zstd")]
    #[tokio::test]
    async fn test_downloads_can_write_to_a_file(supports_zstd_bytestream: bool) {
        let (cas, server) = cas_and_server(supports_zstd_bytestream).await;
        let data = incompressible_bytes();
        let digest = server.insert_blob(&data);
        let output = tempfile::NamedTempFile::new().unwrap();
        let output = cas
            .download_blob_into(&digest, MAX_BYTES, output)
            .await
            .unwrap();
        assert_eq!(data, std::fs::read(output.path()).unwrap());
    }

    #[test_case(false ; "uncompressed")]
    #[test_case(true ; "zstd")]
    #[tokio::test]
    async fn test_a_failed_download_drops_its_temporary_output(supports_zstd_bytestream: bool) {
        let (cas, server) = cas_and_server(supports_zstd_bytestream).await;
        let digest = server.insert_blob(&incompressible_bytes());
        server.corrupt_reads.store(true, Ordering::SeqCst);
        let output = tempfile::NamedTempFile::new().unwrap();
        let path = output.path().to_owned();
        assert!(
            cas.download_blob_into(&digest, MAX_BYTES, output)
                .await
                .is_err()
        );
        assert!(!path.exists());
    }

    #[test_case(false ; "uncompressed")]
    #[test_case(true ; "zstd")]
    #[tokio::test]
    async fn test_a_stalled_stream_times_out_and_drops_its_output(supports_zstd_bytestream: bool) {
        let received = Arc::new(Notify::new());
        let server = Arc::new(FakeServer {
            supports_zstd_bytestream,
            stalled_read: Some(received.clone()),
            ..Default::default()
        });
        let cas = Cas::new(&server.serve_and_connect().await);
        let digest = server.insert_blob(b"blob");
        let output = tempfile::NamedTempFile::new().unwrap();
        let path = output.path().to_owned();
        let mut download =
            tokio::spawn(async move { cas.download_blob_into(&digest, MAX_BYTES, output).await });
        tokio::select! {
            _ = received.notified() => {}
            _ = &mut download => panic!("the download finished before the stalled stream was polled"),
        }
        tokio::time::pause();
        tokio::time::advance(download_timeout(4)).await;
        // Resume real time so the blocking writer can finish.
        tokio::time::resume();
        let error = tokio::time::timeout(Duration::from_secs(5), download)
            .await
            .expect("the download should time out")
            .unwrap()
            .unwrap_err();
        assert!(error.to_string().contains("timed out after"), "{error:#}");
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn test_a_blob_the_cas_doesnt_have_is_an_error() {
        let (cas, _server) = cas_and_server(false).await;
        let e = cas
            .download_blob(&digest::of_bytes(b"absent"), MAX_BYTES)
            .await
            .unwrap_err();
        assert!(format!("{e:#}").contains("NotFound"), "{e:#}");
    }

    #[test]
    fn test_zstd_window_log_max() {
        assert_eq!(24, zstd_window_log_max(0));
        assert_eq!(24, zstd_window_log_max(1 << 24));
        assert_eq!(25, zstd_window_log_max((1 << 24) + 1));
        assert_eq!(27, zstd_window_log_max(100 << 20));
    }

    #[test]
    fn test_short_writes_are_hashed_once() {
        #[derive(Default)]
        struct ShortWriter(Vec<u8>);

        impl Write for ShortWriter {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                let count = bytes.len().min(2);
                self.0.extend_from_slice(&bytes[..count]);
                Ok(count)
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let mut writer = HashingWriter::new(ShortWriter::default(), 5);
        writer.write_all(b"hello").unwrap();
        let (out, digest) = writer.finish().unwrap();
        assert_eq!(b"hello", out.0.as_slice());
        assert_eq!(digest::of_bytes(b"hello"), digest);
    }

    #[tokio::test]
    async fn test_a_flush_error_fails_the_download() {
        struct FailingFlush;

        impl Write for FailingFlush {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                Ok(bytes.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                Err(io::Error::other("flush failed"))
            }
        }

        let (cas, server) = cas_and_server(false).await;
        let digest = server.insert_blob(b"blob");
        let error = cas
            .download_blob_into(&digest, MAX_BYTES, FailingFlush)
            .await
            .err()
            .unwrap();
        assert!(format!("{error:#}").contains("flush failed"), "{error:#}");
    }
}
