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

//! CAS downloads with size limits and SHA-256 verification.

use super::client::{AuthChannel, Client, RPC_TIMEOUT, status_error, with_timeout};
use super::digest;
use super::proto::build::bazel::remote::execution::v2 as remexec;
use super::proto::google::bytestream::ReadRequest;
use super::proto::google::bytestream::byte_stream_client::ByteStreamClient;
use crate::errors::*;
use sha2::{Digest as _, Sha256};
use std::io::{self, Write};
use std::time::Duration;
use tokio::sync::mpsc;

// Download deadlines assume a minimum throughput of 1 MiB/s.
fn download_timeout(bytes: u64) -> Duration {
    RPC_TIMEOUT + Duration::from_secs(bytes / (1024 * 1024))
}

// Allow at least a 16 MiB window for streaming compression with unknown input size.
fn zstd_window_log_max(size_bytes: u64) -> u32 {
    (u64::BITS - size_bytes.saturating_sub(1).leading_zeros()).max(24)
}

pub(crate) struct Cas {
    instance_name: String,
    bytestream_client: ByteStreamClient<AuthChannel>,
    supports_zstd_bytestream: bool,
}

impl Cas {
    pub(crate) fn new(client: &Client) -> Self {
        Cas {
            instance_name: client.instance_name().to_owned(),
            bytestream_client: ByteStreamClient::new(client.channel()),
            supports_zstd_bytestream: client.supports_zstd_bytestream(),
        }
    }

    fn download_resource_name(&self, digest: &remexec::Digest) -> String {
        let blobs = if self.supports_zstd_bytestream {
            "compressed-blobs/zstd"
        } else {
            "blobs"
        };
        let blob_name = format!("{blobs}/{}/{}", digest.hash, digest.size_bytes);
        if self.instance_name.is_empty() {
            blob_name
        } else {
            format!("{}/{blob_name}", self.instance_name)
        }
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
            let mut stream = self
                .bytestream_client
                .clone()
                .read(ReadRequest {
                    resource_name,
                    read_offset: 0,
                    read_limit: 0,
                })
                .await
                .map_err(status_error)?
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
    use crate::reapi::client::ConnectOptions;
    use crate::reapi::test::FakeServer;
    use rand::{RngCore, SeedableRng};
    use std::sync::Arc;
    use std::sync::atomic::Ordering;
    use test_case::test_case;
    use tokio::sync::Notify;

    const MAX_BYTES: u64 = 1 << 20;

    // Use random data to exercise multiple ByteStream chunks even with compression.
    fn incompressible_bytes() -> Vec<u8> {
        let mut data = vec![0; 64 * 1024];
        rand::rngs::StdRng::seed_from_u64(0).fill_bytes(&mut data);
        data
    }

    async fn cas_and_server(supports_zstd_bytestream: bool) -> (Cas, Arc<FakeServer>) {
        let server = Arc::new(FakeServer {
            supports_zstd_bytestream,
            ..Default::default()
        });
        (Cas::new(&server.serve_and_connect().await), server)
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
            auth_token: Some("test-token".to_owned()),
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
                "failed to download blob {}/4 from the REAPI CAS: {code:?}: read_error",
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
            format!("{error:#}").contains("Unavailable: read_stream_error"),
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
