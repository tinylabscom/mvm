//! The host-local listeners the guest reaches the endpoint through: a Unix
//! socket, and on Linux an AF_VSOCK socket. One framed request per connection.

use std::sync::Arc;

use mvm_core::substitution_wire::WireRequest;
use tokio::net::{UnixListener, UnixStream};

#[cfg(target_os = "linux")]
use super::vsock;
use super::{MAX_FRAME_BYTES, SubstitutionService};
use crate::framing::{FrameError, read_json_frame, write_json_frame};
use crate::supervisor::accept_loop::{
    AcceptAction, classify_accept_error, record_listener_stopped,
};

// The wire envelope (`WireRequest`/`WireResponse`) lives in
// `mvm_core::substitution_wire` so the in-guest client and this server share
// one contract (imported at the top of this file).

impl SubstitutionService {
    /// Accept loop: one routed request per connection, framed JSON, a task per
    /// connection. Runs until the listener fails in a way it cannot recover from;
    /// transient accept errors are retried.
    pub async fn serve(self: Arc<Self>, listener: UnixListener) {
        let mut transient = 0u32;
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    transient = 0;
                    let me = Arc::clone(&self);
                    tokio::spawn(async move {
                        if let Err(e) = me.handle_connection(stream).await {
                            tracing::warn!(error = %e, "substitution endpoint connection failed");
                        }
                    });
                }
                Err(e) => match classify_accept_error(&e, transient) {
                    AcceptAction::Retry(delay) => {
                        tracing::warn!(error = %e, "substitution endpoint accept failed; retrying");
                        transient = transient.saturating_add(1);
                        tokio::time::sleep(delay).await;
                    }
                    AcceptAction::Fatal => {
                        tracing::error!(error = %e, "substitution endpoint accept failed; stopping");
                        record_listener_stopped(
                            self.recorder.as_deref(),
                            "substitution-uds",
                            &e.to_string(),
                        )
                        .await;
                        return;
                    }
                },
            }
        }
    }

    /// Accept loop over a host **AF_VSOCK** listener — the QEMU (`vhost-vsock`)
    /// guest→host path. Firecracker/libkrun route guest→host through a per-port
    /// UDS instead and use [`Self::serve`]. Both `accept(2)` and the per-
    /// connection framing run with **blocking** I/O on `spawn_blocking` threads
    /// (tokio's async reactor doesn't interplay reliably with an AF_VSOCK fd);
    /// the async forward leg is driven via `Handle::block_on`. No new dep.
    #[cfg(target_os = "linux")]
    pub async fn serve_vsock(self: Arc<Self>, listener: vsock::VsockListener) {
        let mut transient = 0u32;
        loop {
            let listen_fd = listener.raw_fd();
            let accepted = tokio::task::spawn_blocking(move || vsock::accept(listen_fd)).await;
            let conn_fd = match accepted {
                Ok(Ok(fd)) => {
                    transient = 0;
                    fd
                }
                Ok(Err(e)) => match classify_accept_error(&e, transient) {
                    AcceptAction::Retry(delay) => {
                        tracing::warn!(error = %e, "vsock substitution accept failed; retrying");
                        transient = transient.saturating_add(1);
                        tokio::time::sleep(delay).await;
                        continue;
                    }
                    AcceptAction::Fatal => {
                        tracing::error!(error = %e, "vsock substitution accept failed; stopping");
                        record_listener_stopped(
                            self.recorder.as_deref(),
                            "substitution-vsock",
                            &e.to_string(),
                        )
                        .await;
                        return;
                    }
                },
                // A panic in the accept task is a bug in this process, not host
                // pressure that will clear. Retrying would hide it.
                Err(e) => {
                    tracing::error!(error = %e, "vsock accept task panicked; stopping");
                    record_listener_stopped(
                        self.recorder.as_deref(),
                        "substitution-vsock",
                        &e.to_string(),
                    )
                    .await;
                    return;
                }
            };
            let me = Arc::clone(&self);
            tokio::spawn(async move {
                if let Err(e) = me.handle_vsock_connection(conn_fd).await {
                    tracing::warn!(error = %e, "vsock substitution connection failed");
                }
            });
        }
    }

    async fn handle_connection(&self, mut stream: UnixStream) -> Result<(), FrameError> {
        let wire: WireRequest = read_json_frame(&mut stream, MAX_FRAME_BYTES).await?;
        let resp = self.process(wire).await;
        write_json_frame(&mut stream, &resp).await
    }

    /// Handle one vsock connection: the raw socket I/O is blocking, so the
    /// frame read/write run on `spawn_blocking` threads, while `process` (the
    /// substitution + forward leg — the prod forward needs the tokio reactor)
    /// runs on the runtime. We do NOT `block_on` the forward from a blocking
    /// thread: a `spawn_blocking` thread is still inside the runtime context,
    /// so tokio's `block_on` panics there.
    #[cfg(target_os = "linux")]
    async fn handle_vsock_connection(&self, conn_fd: std::os::fd::RawFd) -> std::io::Result<()> {
        use std::os::fd::FromRawFd;
        // SAFETY: `conn_fd` is an owned connected stream socket from `accept`.
        let stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(conn_fd) };
        let (mut stream, wire) = tokio::task::spawn_blocking(move || {
            let mut s = stream;
            let wire: WireRequest = vsock::read_frame_sync(&mut s)?;
            std::io::Result::Ok((s, wire))
        })
        .await
        .map_err(std::io::Error::other)??;
        let resp = self.process(wire).await;
        tokio::task::spawn_blocking(move || vsock::write_frame_sync(&mut stream, &resp))
            .await
            .map_err(std::io::Error::other)?
    }
}

#[cfg(test)]
mod server_tests {
    use crate::framing::{read_json_frame, write_json_frame};
    use crate::supervisor::network_endpoint_proxy::MAX_FRAME_BYTES;
    use crate::supervisor::network_endpoint_proxy::test_support::service_with;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as B64;
    use mvm_core::substitution_wire::{WireRequest, WireResponse};
    use std::sync::Arc;
    use tokio::net::{UnixListener, UnixStream};

    /// End-to-end over a **real AF_VSOCK** connection (Linux vsock loopback,
    /// `VMADDR_CID_LOCAL`) — proving `serve_vsock` + the framed substitution
    /// path work over the actual transport, not just a UnixStream pair.
    /// Gracefully skips where vsock/loopback is unavailable (CI, macOS) so it
    /// only asserts where it can really run (a vsock-capable Linux box).
    #[cfg(target_os = "linux")]
    #[test]
    fn substitutes_over_real_af_vsock_loopback() {
        use super::vsock::VsockListener;
        use std::io::{Read, Write};
        use std::os::fd::FromRawFd;

        // serve_vsock's accept loop parks an un-cancellable spawn_blocking(accept);
        // a plain #[tokio::test] would hang on runtime drop waiting for it to
        // return. Build the runtime by hand and force teardown with
        // shutdown_timeout once the round-trip + assertions are done.
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            const AF_VSOCK: libc::c_int = 40;
            const VMADDR_CID_LOCAL: u32 = 1;
            // A double of a kernel ABI type that is free to disagree with
            // the kernel cannot falsify anything the real type does, so it
            // carries the same contract as the production copy above.
            #[repr(C)]
            struct SockaddrVm {
                svm_family: libc::sa_family_t,
                svm_reserved1: u16,
                svm_port: u32,
                svm_cid: u32,
                svm_flags: u8,
                svm_zero: [u8; 3],
            }
            const _: () = {
                use std::mem::{align_of, offset_of, size_of};

                assert!(size_of::<SockaddrVm>() == 16);
                assert!(align_of::<SockaddrVm>() == 4);
                assert!(offset_of!(SockaddrVm, svm_family) == 0);
                assert!(offset_of!(SockaddrVm, svm_reserved1) == 2);
                assert!(offset_of!(SockaddrVm, svm_port) == 4);
                assert!(offset_of!(SockaddrVm, svm_cid) == 8);
                assert!(offset_of!(SockaddrVm, svm_flags) == 12);
                assert!(offset_of!(SockaddrVm, svm_zero) == 13);
            };

            let port = 54000 + (std::process::id() % 2000);
            let listener = match VsockListener::bind(port) {
                Ok(l) => l,
                Err(e) => {
                    eprintln!(
                        "SKIP substitutes_over_real_af_vsock_loopback: AF_VSOCK bind failed ({e})"
                    );
                    return;
                }
            };
            let (service, ph, forwarder, _dir) = service_with("sk-live-zzz", &["api.openai.com"]);
            let server = tokio::spawn(Arc::clone(&service).serve_vsock(listener));

            // Client: connect over vsock loopback, send a framed WireRequest with the
            // placeholder, read the framed WireResponse. `None` = transport
            // unavailable → skip rather than assert.
            let client = tokio::task::spawn_blocking(move || -> Option<WireResponse> {
                let fd = unsafe { libc::socket(AF_VSOCK, libc::SOCK_STREAM, 0) };
                if fd < 0 {
                    return None;
                }
                let addr = SockaddrVm {
                    svm_family: AF_VSOCK as libc::sa_family_t,
                    svm_reserved1: 0,
                    svm_port: port,
                    svm_cid: VMADDR_CID_LOCAL,
                    svm_flags: 0,
                    svm_zero: [0; 3],
                };
                let rc = unsafe {
                    libc::connect(
                        fd,
                        std::ptr::addr_of!(addr).cast::<libc::sockaddr>(),
                        std::mem::size_of::<SockaddrVm>() as libc::socklen_t,
                    )
                };
                if rc < 0 {
                    unsafe { libc::close(fd) };
                    return None;
                }
                let mut s = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
                // Bound the round-trip so a regression fails fast instead of hanging.
                s.set_read_timeout(Some(std::time::Duration::from_secs(15)))
                    .ok();
                s.set_write_timeout(Some(std::time::Duration::from_secs(15)))
                    .ok();
                let wire = WireRequest {
                    method: "POST".into(),
                    url: "https://api.openai.com/v1".into(),
                    headers: vec![("authorization".into(), format!("Bearer {ph}"))],
                    body_b64: String::new(),
                };
                let body = serde_json::to_vec(&wire).unwrap();
                s.write_all(&(body.len() as u32).to_be_bytes()).unwrap();
                s.write_all(&body).unwrap();
                s.flush().unwrap();
                let mut len = [0u8; 4];
                s.read_exact(&mut len).unwrap();
                let n = u32::from_be_bytes(len) as usize;
                let mut buf = vec![0u8; n];
                s.read_exact(&mut buf).unwrap();
                Some(serde_json::from_slice(&buf).unwrap())
            });
            // vsock does not reliably honor SO_RCVTIMEO, so the in-client read
            // timeout can't be trusted — bound the round-trip here so a server-side
            // regression fails fast instead of hanging until libtest's watchdog.
            let resp = match tokio::time::timeout(std::time::Duration::from_secs(20), client).await
            {
                Ok(joined) => joined.unwrap(),
                Err(_) => {
                    panic!("vsock loopback round-trip timed out (20s): serve_vsock did not reply")
                }
            };

            let Some(resp) = resp else {
                eprintln!(
                    "SKIP substitutes_over_real_af_vsock_loopback: vsock loopback unavailable"
                );
                server.abort();
                return;
            };

            // The destination (mock forwarder) saw the REAL credential over real vsock.
            let seen = forwarder.seen.lock().unwrap().clone().unwrap();
            assert_eq!(
                seen.headers[0],
                ("authorization".into(), "Bearer sk-live-zzz".into())
            );
            match resp {
                WireResponse::Ok { status, .. } => assert_eq!(status, 200),
                WireResponse::Refused { message } => panic!("unexpected refusal: {message}"),
            }
            server.abort();
        });
        rt.shutdown_timeout(std::time::Duration::from_millis(50));
    }

    #[tokio::test]
    async fn endpoint_substitutes_then_forwards_over_uds() {
        let (service, ph, forwarder, dir) = service_with("sk-live-zzz", &["api.openai.com"]);
        let sock = dir.path().join("subst.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let server = tokio::spawn(Arc::clone(&service).serve(listener));

        let mut client = UnixStream::connect(&sock).await.unwrap();
        let wire = WireRequest {
            method: "POST".into(),
            url: "https://api.openai.com/v1".into(),
            headers: vec![("authorization".into(), format!("Bearer {ph}"))],
            body_b64: B64.encode(b"{}"),
        };
        write_json_frame(&mut client, &wire).await.unwrap();
        let resp: WireResponse = read_json_frame(&mut client, MAX_FRAME_BYTES).await.unwrap();

        // The forwarder (i.e. the destination) saw the REAL credential.
        let seen = forwarder.seen.lock().unwrap().clone().unwrap();
        assert_eq!(
            seen.headers[0],
            ("authorization".into(), "Bearer sk-live-zzz".into())
        );
        match resp {
            WireResponse::Ok {
                status, body_b64, ..
            } => {
                assert_eq!(status, 200);
                assert_eq!(B64.decode(body_b64).unwrap(), b"pong");
            }
            WireResponse::Refused { message } => panic!("unexpected refusal: {message}"),
        }
        server.abort();
    }
}
