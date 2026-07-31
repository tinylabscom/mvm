//! `RemoteResolver` — a [`SecretResolver`] that fetches a secret's raw value
//! from a remote fleet-secrets daemon (mvmd's tenant vault) over a Unix
//! domain socket, instead of [`super::LocalResolver`]'s on-disk store.
//!
//! The wire contract (`ResolveWireRequest`/`ResolveWireResponse`,
//! length-prefixed JSON) lives in `mvm_core::substitution_wire` so mvmd's
//! socket server and this client serialize the exact same bytes — a drifted
//! copy on either side would silently break fleet secret resolution.
//!
//! Synchronous and dyn-safe, matching [`SecretResolver`]: each `resolve`
//! call opens a fresh blocking connection, sends one request, reads one
//! response, and closes. No connection pooling — that's a follow-up, not
//! this seam.

#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use base64::Engine;
use mvm_core::substitution_wire::{ResolveWireRequest, ResolveWireResponse};
use mvm_sdk::ir::{AuthType, SecretRef};
use secrecy::SecretBox;

use super::resolver::{ResolveError, SecretResolver};

/// Cap on a resolver response frame. A credential value, not a bulk
/// payload — generous enough for any real secret while still bounding an
/// adversarial or malfunctioning peer.
const MAX_FRAME_BYTES: usize = 1 << 20; // 1 MiB

/// Fetches a secret's value from a remote fleet-secrets daemon over a Unix
/// socket. The client-side half of the mvmd tenant-vault seam: `resolve`
/// mirrors `LocalResolver`'s fail-closed `allowed_hosts` check, but the
/// value source is a UDS round trip instead of the local `SecretStore`.
pub struct RemoteResolver {
    uds_path: PathBuf,
    timeout: Duration,
}

impl RemoteResolver {
    pub fn new(uds_path: impl Into<PathBuf>, timeout: Duration) -> Self {
        Self {
            uds_path: uds_path.into(),
            timeout,
        }
    }

    /// One request/response round trip over a fresh connection. All I/O and
    /// framing errors are folded into `io::Error` so the caller has a single
    /// error type to map onto `ResolveError::Backend`.
    fn round_trip(&self, req: &ResolveWireRequest) -> io::Result<ResolveWireResponse> {
        let mut stream = UnixStream::connect(&self.uds_path)?;
        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(self.timeout))?;
        write_frame(&mut stream, req)?;
        read_frame(&mut stream)
    }
}

impl SecretResolver for RemoteResolver {
    fn resolve(&self, r: &SecretRef) -> Result<SecretBox<Vec<u8>>, ResolveError> {
        // Mirror `LocalResolver`: an unbound secret must never resolve
        // (claim 12, fail-closed) — refuse before ever touching the socket.
        if r.allowed_hosts.is_empty() {
            return Err(ResolveError::Unbound {
                name: r.name.clone(),
            });
        }

        let req = ResolveWireRequest {
            name: r.name.clone(),
            allowed_hosts: r.allowed_hosts.clone(),
            auth_type: auth_type_label(r.auth_type).to_string(),
        };

        let resp = self
            .round_trip(&req)
            .map_err(|source| ResolveError::Backend {
                name: r.name.clone(),
                source: source.into(),
            })?;

        match resp {
            ResolveWireResponse::Ok { value_b64 } => {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(value_b64)
                    .map_err(|source| ResolveError::Backend {
                        name: r.name.clone(),
                        source: source.into(),
                    })?;
                Ok(SecretBox::new(Box::new(bytes)))
            }
            ResolveWireResponse::Refused { message } => Err(ResolveError::Backend {
                name: r.name.clone(),
                source: anyhow::anyhow!(message),
            }),
        }
    }
}

fn auth_type_label(t: AuthType) -> &'static str {
    match t {
        AuthType::Sigv4 => "sigv4",
        AuthType::Hmac => "hmac",
        AuthType::Bearer => "bearer",
        AuthType::Basic => "basic",
    }
}

/// Write a length-prefixed JSON frame: 4-byte BE length + JSON body.
/// Blocking I/O — `RemoteResolver` is a sync `SecretResolver`, so this
/// stays sync rather than pulling a tokio runtime into the resolve path.
fn write_frame<T: serde::Serialize>(w: &mut impl Write, value: &T) -> io::Result<()> {
    let body =
        serde_json::to_vec(value).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let len = u32::try_from(body.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "frame too large"))?;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(&body)?;
    w.flush()
}

/// Read a length-prefixed JSON frame, enforcing `MAX_FRAME_BYTES`.
fn read_frame<T: serde::de::DeserializeOwned>(r: &mut impl Read) -> io::Result<T> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    serde_json::from_slice(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use mvm_sdk::ir::SecretMount;
    use secrecy::ExposeSecret;
    use std::os::unix::net::UnixListener;
    use std::thread;
    use tempfile::tempdir;

    fn secret_ref_with_hosts(hosts: &[&str]) -> SecretRef {
        SecretRef {
            name: "STRIPE".into(),
            mount: SecretMount::Env {
                var: "STRIPE_KEY".into(),
            },
            auth_type: AuthType::Bearer,
            allowed_hosts: hosts.iter().map(|h| h.to_string()).collect(),
            sigv4: None,
        }
    }

    /// Spawn a throwaway UDS server that accepts one connection, reads one
    /// framed `ResolveWireRequest`, and replies with `response`. The
    /// listener is bound (and thus already accepting) before this returns,
    /// so the caller can connect immediately with no race. The backing
    /// tempdir is moved into the server thread and only drops (removing the
    /// socket file) once the one exchange completes.
    fn spawn_server(response: ResolveWireResponse) -> PathBuf {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("resolver.sock");
        let listener = UnixListener::bind(&path).expect("bind uds");
        thread::spawn(move || {
            let _dir = dir;
            if let Ok((mut stream, _)) = listener.accept() {
                let _req: io::Result<ResolveWireRequest> = read_frame(&mut stream);
                let _ = write_frame(&mut stream, &response);
            }
        });
        path
    }

    #[test]
    fn remote_resolver_fetches_value_over_uds() {
        let value_b64 = base64::engine::general_purpose::STANDARD.encode(b"sk_live_x");
        let path = spawn_server(ResolveWireResponse::Ok { value_b64 });

        let resolver = RemoteResolver::new(path, Duration::from_secs(5));
        let secret = resolver
            .resolve(&secret_ref_with_hosts(&["api.stripe.com"]))
            .unwrap();
        assert_eq!(secret.expose_secret().as_slice(), b"sk_live_x");
    }

    #[test]
    fn remote_resolver_maps_invalid_base64_to_resolve_error_without_panicking() {
        let path = spawn_server(ResolveWireResponse::Ok {
            value_b64: "!!not-valid-base64!!".into(),
        });

        let resolver = RemoteResolver::new(path, Duration::from_secs(5));
        let err = resolver
            .resolve(&secret_ref_with_hosts(&["api.stripe.com"]))
            .unwrap_err();
        assert!(matches!(err, ResolveError::Backend { .. }));
    }

    #[test]
    fn remote_resolver_maps_refusal_to_resolve_error() {
        let path = spawn_server(ResolveWireResponse::Refused {
            message: "secret not bound".into(),
        });

        let resolver = RemoteResolver::new(path, Duration::from_secs(5));
        let err = resolver
            .resolve(&secret_ref_with_hosts(&["api.stripe.com"]))
            .unwrap_err();
        assert!(matches!(err, ResolveError::Backend { .. }));
    }

    #[test]
    fn remote_resolver_maps_connect_failure_to_resolve_error_without_panicking() {
        let dir = tempdir().expect("tempdir");
        // Never bound — nothing is listening at this path.
        let path = dir.path().join("nobody-home.sock");

        let resolver = RemoteResolver::new(path, Duration::from_secs(5));
        let err = resolver
            .resolve(&secret_ref_with_hosts(&["api.stripe.com"]))
            .unwrap_err();
        assert!(matches!(err, ResolveError::Backend { .. }));
    }

    #[test]
    fn remote_resolver_rejects_unbound_ref_without_connecting() {
        // A path that isn't bound: if `resolve` tried to connect, it would
        // hit connection-refused/backend-error instead of `Unbound`.
        let path = PathBuf::from("/nonexistent/nobody-home.sock");
        let resolver = RemoteResolver::new(path, Duration::from_secs(5));
        let err = resolver.resolve(&secret_ref_with_hosts(&[])).unwrap_err();
        assert!(matches!(err, ResolveError::Unbound { .. }));
    }
}
