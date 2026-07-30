//! vminitd's SandboxContext gRPC client, over the in-house VMM's vsock.
//!
//! Apple Containers boot `vminitd` as guest PID 1, serving a gRPC API on
//! vsock port 1024. This module is the host-side client for the subset of
//! that API mvm's activation path needs: `Mkdir`, `WriteFile`,
//! `CreateProcess`, `StartProcess`, `WaitProcess`, `KillProcess`, and
//! `Mount` (see `apple_container_backend` for the flow that composes them).
//!
//! # Transport choice
//!
//! gRPC runs over HTTP/2, so the transport is [`h2`] on the supervisor's
//! host UDS for the guest's vsock port, bridged into a single-threaded
//! tokio runtime owned by the client so the rest of the backend stays
//! blocking. A hand-rolled HTTP/2 client for exactly unary POSTs was
//! considered and rejected: HPACK *decoding* of response headers (dynamic
//! tables + Huffman) is the part that cannot honestly be minimized, and
//! getting it wrong fails silently against a different gRPC server
//! implementation. `h2` and `http` were already in the dependency tree
//! (via the S3 client), so the added closure is `prost` + `prost-types`
//! only. The protobuf wire types are hand-written `prost` derives — no
//! `protoc`/`prost-build` enters the build pipeline, and the vendored
//! proto (`vm/proto/sandbox_context.proto`) stays the human reference.
//!
//! # Wire format (gRPC over HTTP/2)
//!
//! Each call is a unary POST to
//! `/com.apple.containerization.sandbox.v3.SandboxContext/<Method>` with
//! `content-type: application/grpc` and `te: trailers`. The body is the
//! gRPC envelope — a 1-byte compression flag (0), a 4-byte big-endian
//! length, then the protobuf message — and the terminal status arrives as
//! HTTP/2 trailers (`grpc-status`, optionally `grpc-message`,
//! percent-encoded).

use std::path::Path;

use anyhow::{Context, Result};
use bytes::Bytes;
use prost::Message;
use thiserror::Error;

/// Port that vminitd listens on inside the Apple Container VM.
pub const VMINITD_VSOCK_PORT: u32 = 1024;

/// gRPC path prefix for the SandboxContext service (proto `package`).
const SERVICE_PATH: &str = "/com.apple.containerization.sandbox.v3.SandboxContext";

/// Request bodies are chunked at this size so a multi-MiB file write (the
/// guest-agent binary) flows through h2's window management without
/// overrunning the send buffer.
const DATA_CHUNK: usize = 64 * 1024;

/// Typed failures from the vminitd channel: the HTTP/2 transport broke, or
/// the server answered with a non-zero gRPC status.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum VminitdError {
    /// The connection, framing, or I/O failed (`{0}` carries the detail).
    #[error("vminitd transport failed: {0}")]
    Transport(String),
    /// The server answered with a non-zero `grpc-status` and (usually) a
    /// `grpc-message`.
    #[error("vminitd gRPC status {code}: {message}")]
    GrpcStatus { code: i64, message: String },
}

// ---------------------------------------------------------------------------
// Protobuf wire types (hand-written derives over the vendored proto schema)
// ---------------------------------------------------------------------------

/// `MkdirRequest`.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct MkdirRequest {
    #[prost(string, tag = "1")]
    pub path: String,
    #[prost(bool, tag = "2")]
    pub all: bool,
    #[prost(uint32, tag = "3")]
    pub perms: u32,
}

/// `MkdirResponse`.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct MkdirResponse {}

/// `WriteFileRequest.WriteFileFlags`.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct WriteFileFlags {
    #[prost(bool, tag = "1")]
    pub create_parent_dirs: bool,
    #[prost(bool, tag = "2")]
    pub append: bool,
    #[prost(bool, tag = "3")]
    pub create_if_missing: bool,
}

/// `WriteFileRequest`.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct WriteFileRequest {
    #[prost(string, tag = "1")]
    pub path: String,
    #[prost(bytes = "vec", tag = "2")]
    pub data: Vec<u8>,
    #[prost(uint32, tag = "3")]
    pub mode: u32,
    #[prost(message, required, tag = "4")]
    pub flags: WriteFileFlags,
}

/// `WriteFileResponse`.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct WriteFileResponse {}

/// `CreateProcessRequest`. `configuration` is the serialized OCI runtime
/// spec JSON the guest's `vmexec` consumes.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct CreateProcessRequest {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, optional, tag = "2")]
    pub container_id: Option<String>,
    #[prost(uint32, optional, tag = "3")]
    pub stdin: Option<u32>,
    #[prost(uint32, optional, tag = "4")]
    pub stdout: Option<u32>,
    #[prost(uint32, optional, tag = "5")]
    pub stderr: Option<u32>,
    #[prost(string, optional, tag = "6")]
    pub oci_runtime_path: Option<String>,
    #[prost(bytes = "vec", tag = "7")]
    pub configuration: Vec<u8>,
    #[prost(bytes = "vec", optional, tag = "8")]
    pub options: Option<Vec<u8>>,
}

/// `CreateProcessResponse`.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct CreateProcessResponse {}

/// `StartProcessRequest`.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct StartProcessRequest {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, optional, tag = "2")]
    pub container_id: Option<String>,
}

/// `StartProcessResponse`.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct StartProcessResponse {
    #[prost(int32, tag = "1")]
    pub pid: i32,
}

/// `WaitProcessRequest`.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct WaitProcessRequest {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, optional, tag = "2")]
    pub container_id: Option<String>,
}

/// `WaitProcessResponse`.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct WaitProcessResponse {
    #[prost(int32, tag = "1")]
    pub exit_code: i32,
    #[prost(message, optional, tag = "2")]
    pub exited_at: Option<prost_types::Timestamp>,
}

/// `KillProcessRequest`.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct KillProcessRequest {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, optional, tag = "2")]
    pub container_id: Option<String>,
    #[prost(int32, tag = "3")]
    pub signal: i32,
}

/// `KillProcessResponse`.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct KillProcessResponse {
    #[prost(int32, tag = "1")]
    pub result: i32,
}

/// `MountRequest`.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct MountRequest {
    #[prost(string, tag = "1")]
    pub mount_type: String,
    #[prost(string, tag = "2")]
    pub source: String,
    #[prost(string, tag = "3")]
    pub destination: String,
    #[prost(string, repeated, tag = "4")]
    pub options: Vec<String>,
}

/// `MountResponse`.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct MountResponse {}

// ---------------------------------------------------------------------------
// The client
// ---------------------------------------------------------------------------

/// A connected vminitd gRPC client: one HTTP/2 connection over the
/// supervisor's host UDS for the guest's vsock port, driven by a
/// single-threaded tokio runtime owned here so the rest of the backend
/// stays blocking.
pub struct VminitdClient {
    runtime: tokio::runtime::Runtime,
    send_request: h2::client::SendRequest<Bytes>,
}

impl VminitdClient {
    /// Connect to the supervisor's host UDS at `sock` (the listener the
    /// supervisor bound for the guest's vsock port) and complete the HTTP/2
    /// client handshake.
    pub fn connect(sock: &Path) -> Result<Self> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("build vminitd tokio runtime")?;
        let (send_request, connection) = runtime.block_on(async {
            let std_stream = std::os::unix::net::UnixStream::connect(sock)
                .with_context(|| format!("connect to vminitd socket {}", sock.display()))?;
            std_stream
                .set_nonblocking(true)
                .context("set vminitd socket non-blocking")?;
            let stream = tokio::net::UnixStream::from_std(std_stream)
                .context("wrap vminitd socket for tokio")?;
            h2::client::handshake(stream)
                .await
                .context("HTTP/2 handshake with vminitd")
        })?;
        runtime.spawn(async move {
            let _ = connection.await;
        });
        Ok(Self {
            runtime,
            send_request,
        })
    }

    /// Test-only constructor over an already-handshaken h2 sender, so
    /// in-process mock servers (duplex streams, no UDS) can drive the full
    /// client.
    #[cfg(test)]
    pub(crate) fn new_for_test(
        runtime: tokio::runtime::Runtime,
        send_request: h2::client::SendRequest<Bytes>,
    ) -> Self {
        Self {
            runtime,
            send_request,
        }
    }

    /// One unary gRPC call: protobuf-encode `req`, POST it to `method`, and
    /// decode the response protobuf. A non-zero `grpc-status` becomes a
    /// typed [`VminitdError::GrpcStatus`].
    fn unary<M, R>(&mut self, method: &str, req: &M) -> Result<R, VminitdError>
    where
        M: Message,
        R: Message + Default,
    {
        // Split the field borrows so the runtime can drive a future that
        // mutably borrows the h2 sender.
        let runtime = &self.runtime;
        let send_request = &mut self.send_request;
        runtime.block_on(unary_async(send_request, method, req))
    }

    /// Create a directory inside the guest (`Mkdir`).
    pub fn mkdir(&mut self, path: &str, all: bool, perms: u32) -> Result<(), VminitdError> {
        let req = MkdirRequest {
            path: path.to_string(),
            all,
            perms,
        };
        let _: MkdirResponse = self.unary("Mkdir", &req)?;
        Ok(())
    }

    /// Write a file inside the guest (`WriteFile`), creating parents and the
    /// file itself as needed (whole-file write, not append).
    pub fn write_file(&mut self, path: &str, data: &[u8], mode: u32) -> Result<(), VminitdError> {
        let req = WriteFileRequest {
            path: path.to_string(),
            data: data.to_vec(),
            mode,
            flags: WriteFileFlags {
                create_parent_dirs: true,
                append: false,
                create_if_missing: true,
            },
        };
        let _: WriteFileResponse = self.unary("WriteFile", &req)?;
        Ok(())
    }

    /// Register a guest process without starting it (`CreateProcess`).
    /// `configuration` is the serialized OCI runtime spec JSON.
    pub fn create_process(&mut self, id: &str, configuration: Vec<u8>) -> Result<(), VminitdError> {
        let req = CreateProcessRequest {
            id: id.to_string(),
            container_id: None,
            stdin: None,
            stdout: None,
            stderr: None,
            oci_runtime_path: None,
            configuration,
            options: None,
        };
        let _: CreateProcessResponse = self.unary("CreateProcess", &req)?;
        Ok(())
    }

    /// Start a registered guest process (`StartProcess`), returning its pid.
    pub fn start_process(&mut self, id: &str) -> Result<i32, VminitdError> {
        let req = StartProcessRequest {
            id: id.to_string(),
            container_id: None,
        };
        let resp: StartProcessResponse = self.unary("StartProcess", &req)?;
        Ok(resp.pid)
    }

    /// Block until a guest process exits (`WaitProcess`), returning its
    /// exit code.
    pub fn wait_process(&mut self, id: &str) -> Result<i32, VminitdError> {
        let req = WaitProcessRequest {
            id: id.to_string(),
            container_id: None,
        };
        let resp: WaitProcessResponse = self.unary("WaitProcess", &req)?;
        Ok(resp.exit_code)
    }

    /// Signal a guest process (`KillProcess`).
    pub fn signal_process(&mut self, id: &str, signal: i32) -> Result<(), VminitdError> {
        let req = KillProcessRequest {
            id: id.to_string(),
            container_id: None,
            signal,
        };
        let _: KillProcessResponse = self.unary("KillProcess", &req)?;
        Ok(())
    }

    /// Mount a filesystem inside the guest (`Mount`).
    pub fn mount(
        &mut self,
        mount_type: &str,
        source: &str,
        destination: &str,
        options: &[String],
    ) -> Result<(), VminitdError> {
        let req = MountRequest {
            mount_type: mount_type.to_string(),
            source: source.to_string(),
            destination: destination.to_string(),
            options: options.to_vec(),
        };
        let _: MountResponse = self.unary("Mount", &req)?;
        Ok(())
    }
}

/// The async core of [`VminitdClient::unary`], as a free function so the
/// blocking wrapper can drive it while holding disjoint field borrows.
async fn unary_async<M, R>(
    send_request: &mut h2::client::SendRequest<Bytes>,
    method: &str,
    req: &M,
) -> Result<R, VminitdError>
where
    M: Message,
    R: Message + Default,
{
    let path = format!("{SERVICE_PATH}/{method}");
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri(path)
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(())
        .map_err(|e| VminitdError::Transport(format!("build request: {e}")))?;
    let (response, mut send_stream) = send_request
        .send_request(request, false)
        .map_err(|e| VminitdError::Transport(format!("send request: {e}")))?;

    let mut body = Vec::with_capacity(5 + req.encoded_len());
    body.push(0u8); // no compression
    let len = u32::try_from(req.encoded_len())
        .map_err(|e| VminitdError::Transport(format!("request too large: {e}")))?;
    body.extend_from_slice(&len.to_be_bytes());
    req.encode(&mut body)
        .map_err(|e| VminitdError::Transport(format!("encode request: {e}")))?;
    for (i, chunk) in body.chunks(DATA_CHUNK).enumerate() {
        let last = (i + 1) * DATA_CHUNK >= body.len();
        send_stream
            .send_data(Bytes::copy_from_slice(chunk), last)
            .map_err(|e| VminitdError::Transport(format!("send data: {e}")))?;
    }

    let mut response = response
        .await
        .map_err(|e| VminitdError::Transport(format!("response: {e}")))?;
    if let Some(status) = grpc_status(response.headers())
        && status != 0
    {
        return Err(grpc_error(status, response.headers()));
    }

    let mut buf = Vec::new();
    while let Some(chunk) = response
        .body_mut()
        .data()
        .await
        .transpose()
        .map_err(|e| VminitdError::Transport(e.to_string()))?
    {
        buf.extend_from_slice(&chunk);
    }
    let trailers = response
        .body_mut()
        .trailers()
        .await
        .map_err(|e| VminitdError::Transport(format!("trailers: {e}")))?;
    if let Some(trailers) = trailers.as_ref()
        && let Some(status) = grpc_status(trailers)
        && status != 0
    {
        return Err(grpc_error(status, trailers));
    }

    if buf.len() < 5 {
        return Err(VminitdError::Transport(format!(
            "short gRPC envelope ({} bytes)",
            buf.len()
        )));
    }
    let declared = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
    if declared != buf.len() - 5 {
        return Err(VminitdError::Transport(format!(
            "gRPC envelope length mismatch: declared {declared}, got {} bytes",
            buf.len() - 5
        )));
    }
    R::decode(&buf[5..]).map_err(|e| VminitdError::Transport(format!("decode response: {e}")))
}

/// Extract a `grpc-status` header value as an integer.
fn grpc_status(headers: &http::HeaderMap) -> Option<i64> {
    headers
        .get("grpc-status")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
}

/// Build the typed error for a non-zero gRPC status, percent-decoding the
/// `grpc-message` when present.
fn grpc_error(code: i64, headers: &http::HeaderMap) -> VminitdError {
    let message = headers
        .get("grpc-message")
        .and_then(|v| v.to_str().ok())
        .map(percent_decode)
        .unwrap_or_default();
    VminitdError::GrpcStatus { code, message }
}

/// Percent-decode a `grpc-message` value (the gRPC spec percent-encodes
/// non-ASCII bytes as `%HH`).
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Serialize one value into a gRPC envelope (flag byte + BE length + body).
/// Used by the test server so both halves agree byte-for-byte.
#[cfg(test)]
pub(crate) fn grpc_envelope(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + body.len());
    out.push(0u8);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// What the mock server records per accepted call.
    #[derive(Debug, Clone)]
    struct RecordedCall {
        path: String,
        body: Vec<u8>,
    }

    /// A scripted response: the protobuf body to return plus the grpc-status.
    struct MockResponse {
        body: Vec<u8>,
        status: &'static str,
        message: Option<&'static str>,
    }

    impl MockResponse {
        fn ok(body: Vec<u8>) -> Self {
            Self {
                body,
                status: "0",
                message: None,
            }
        }

        fn error(code: &'static str, message: &'static str) -> Self {
            Self {
                body: Vec::new(),
                status: code,
                message: Some(message),
            }
        }
    }

    /// A test client built directly over an h2 duplex stream (the
    /// production path connects a UDS via [`VminitdClient::connect`]).
    fn client_on(
        runtime: &tokio::runtime::Runtime,
        stream: tokio::io::DuplexStream,
    ) -> h2::client::SendRequest<Bytes> {
        let (send_request, connection) = runtime
            .block_on(h2::client::handshake(stream))
            .expect("client handshake");
        runtime.spawn(async move {
            let _ = connection.await;
        });
        send_request
    }

    /// Spawn an h2 gRPC server on one end of a duplex pair, answering each
    /// incoming unary call from `script` and recording `(path, body)`.
    fn spawn_mock_server(
        runtime: &tokio::runtime::Runtime,
        stream: tokio::io::DuplexStream,
        script: Vec<MockResponse>,
        calls: Arc<Mutex<Vec<RecordedCall>>>,
    ) -> tokio::task::JoinHandle<()> {
        runtime.spawn(async move {
            let mut connection = h2::server::handshake(stream)
                .await
                .expect("server handshake");
            let mut script = script.into_iter();
            while let Some(accepted) = connection.accept().await {
                let (request, mut respond) = accepted.expect("accept request");
                let path = request.uri().path().to_string();
                let mut body = request.into_body();
                let mut data = Vec::new();
                while let Some(chunk) = body.data().await {
                    data.extend_from_slice(&chunk.expect("read request body"));
                }
                calls
                    .lock()
                    .expect("calls lock")
                    .push(RecordedCall { path, body: data });

                let Some(resp) = script.next() else {
                    return;
                };
                let response = http::Response::builder()
                    .status(http::StatusCode::OK)
                    .header("content-type", "application/grpc")
                    .body(())
                    .expect("build response");
                let mut send = respond
                    .send_response(response, false)
                    .expect("send response");
                if resp.status == "0" {
                    send.send_data(Bytes::from(grpc_envelope(&resp.body)), false)
                        .expect("send data");
                }
                let mut trailers = http::HeaderMap::new();
                trailers.insert("grpc-status", resp.status.parse().expect("status value"));
                if let Some(message) = resp.message {
                    trailers.insert("grpc-message", message.parse().expect("message value"));
                }
                send.send_trailers(trailers).expect("send trailers");
            }
        })
    }

    fn test_runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime")
    }

    #[test]
    fn activation_sequence_round_trips_exact_frames() {
        let runtime = test_runtime();
        let (client_stream, server_stream) = tokio::io::duplex(1 << 20);
        let calls = Arc::new(Mutex::new(Vec::new()));
        let script = vec![
            MockResponse::ok(MkdirResponse {}.encode_to_vec()),
            MockResponse::ok(WriteFileResponse {}.encode_to_vec()),
            MockResponse::ok(WriteFileResponse {}.encode_to_vec()),
            MockResponse::ok(CreateProcessResponse {}.encode_to_vec()),
            MockResponse::ok(StartProcessResponse { pid: 4242 }.encode_to_vec()),
        ];
        let server = spawn_mock_server(&runtime, server_stream, script, calls.clone());
        let send_request = client_on(&runtime, client_stream);
        let mut client = VminitdClient {
            runtime: test_runtime(),
            send_request,
        };
        // The client's own runtime must drive the same futures: move the
        // shared runtime into the client (it owns the connection + server).
        client.runtime = runtime;

        client.mkdir("/run/mvm", true, 0o700).expect("mkdir");
        client
            .write_file("/run/mvm/mvm-guest-agent", b"agent-bytes", 0o755)
            .expect("write agent");
        client
            .write_file("/run/mvm/activation.json", b"{}", 0o644)
            .expect("write activation");
        client
            .create_process("mvm-guest-agent", b"{\"ociVersion\":\"\"}".to_vec())
            .expect("create process");
        let pid = client
            .start_process("mvm-guest-agent")
            .expect("start process");
        assert_eq!(pid, 4242);

        let calls = calls.lock().expect("calls lock");
        assert_eq!(calls.len(), 5);
        let paths: Vec<&str> = calls.iter().map(|c| c.path.as_str()).collect();
        assert_eq!(
            paths,
            vec![
                "/com.apple.containerization.sandbox.v3.SandboxContext/Mkdir",
                "/com.apple.containerization.sandbox.v3.SandboxContext/WriteFile",
                "/com.apple.containerization.sandbox.v3.SandboxContext/WriteFile",
                "/com.apple.containerization.sandbox.v3.SandboxContext/CreateProcess",
                "/com.apple.containerization.sandbox.v3.SandboxContext/StartProcess",
            ]
        );

        // The exact wire bytes of the first call: Mkdir /run/mvm all=1 perms=0700.
        let mkdir_req = MkdirRequest::decode(&calls[0].body[5..]).expect("decode mkdir");
        assert_eq!(mkdir_req.path, "/run/mvm");
        assert!(mkdir_req.all);
        assert_eq!(mkdir_req.perms, 0o700);

        let agent_write = WriteFileRequest::decode(&calls[1].body[5..]).expect("decode write");
        assert_eq!(agent_write.path, "/run/mvm/mvm-guest-agent");
        assert_eq!(agent_write.data, b"agent-bytes");
        assert_eq!(agent_write.mode, 0o755);
        assert!(agent_write.flags.create_parent_dirs);
        assert!(agent_write.flags.create_if_missing);
        assert!(!agent_write.flags.append);

        let create_req = CreateProcessRequest::decode(&calls[3].body[5..]).expect("decode create");
        assert_eq!(create_req.id, "mvm-guest-agent");
        assert_eq!(create_req.configuration, b"{\"ociVersion\":\"\"}".to_vec());
        assert!(create_req.container_id.is_none());

        server.abort();
    }

    #[test]
    fn grpc_error_status_surfaces_typed_with_message() {
        let runtime = test_runtime();
        let (client_stream, server_stream) = tokio::io::duplex(1 << 20);
        let calls = Arc::new(Mutex::new(Vec::new()));
        let script = vec![MockResponse::error("12", "unimplemented")];
        let server = spawn_mock_server(&runtime, server_stream, script, calls);
        let send_request = client_on(&runtime, client_stream);
        let mut client = VminitdClient {
            runtime: test_runtime(),
            send_request,
        };
        client.runtime = runtime;

        let err = client.mkdir("/run/mvm", true, 0o700).unwrap_err();
        assert_eq!(
            err,
            VminitdError::GrpcStatus {
                code: 12,
                message: "unimplemented".to_string()
            }
        );
        server.abort();
    }

    #[test]
    fn disconnect_mid_call_is_a_transport_error() {
        let runtime = test_runtime();
        let (client_stream, server_stream) = tokio::io::duplex(1 << 20);
        // Server handshakes then vanishes without answering.
        runtime.spawn(async move {
            let mut connection = h2::server::handshake(server_stream)
                .await
                .expect("server handshake");
            let _ = connection.accept().await;
        });
        let send_request = client_on(&runtime, client_stream);
        let mut client = VminitdClient {
            runtime: test_runtime(),
            send_request,
        };
        client.runtime = runtime;

        let err = client.mkdir("/run/mvm", true, 0o700).unwrap_err();
        assert!(
            matches!(err, VminitdError::Transport(_)),
            "expected Transport, got {err:?}"
        );
    }

    #[test]
    fn percent_decode_handles_escaped_and_plain() {
        assert_eq!(percent_decode("unimplemented"), "unimplemented");
        assert_eq!(percent_decode("bad%20path%2Fhere"), "bad path/here");
        assert_eq!(percent_decode("100%25"), "100%");
        assert_eq!(percent_decode("trailing%"), "trailing%");
    }

    #[test]
    fn grpc_envelope_layout_is_flag_len_body() {
        let env = grpc_envelope(b"abc");
        assert_eq!(env, vec![0, 0, 0, 0, 3, b'a', b'b', b'c']);
    }
}
