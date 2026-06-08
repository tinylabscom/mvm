//! Plan 129 / ADR-067 §1 — host substitution endpoint: request preparation.
//!
//! The guest's SDK client routes a secret-bearing request to this host-local
//! endpoint carrying an opaque placeholder. [`prepare_request`] is the
//! security-critical core: it locates the placeholder in each header, resolves
//! it against the session registry, binding-checks the request's destination
//! (claim 12), and substitutes the real credential — yielding a request ready
//! for the host to make the real TLS to the destination (the forward leg,
//! a separate transport step).
//!
//! Substitution happens HERE, on the host, never in the guest: the guest only
//! ever held the opaque placeholder. The prepared request carries the real
//! credential because it must reach the wire — the confinement is that this
//! host component is the only place it exists in the clear.

use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use tokio::net::{UnixListener, UnixStream};
use url::Url;

use mvm_core::crypto::secret_store::SecretStore;
use mvm_core::plan::SecretBinding;
use mvm_core::substitution_wire::{WireRequest, WireResponse};
use mvm_sdk::ir::AuthType;

use crate::framing::{FrameError, read_json_frame, write_json_frame};
use crate::keyholder::{
    AssembleError, BindingStore, HandedPlaceholders, LocalResolver, SecretResolver,
    SubstituteError, SubstitutionEndpoint, SubstitutionRegistry, assemble_registry,
    find_placeholder,
};
use crate::supervisor::audit_recorder::Recorder;
use crate::supervisor::secret_audit::emit_secret_substituted;
use crate::supervisor::tools::http_hardening::hardened_client_builder;

/// 16 MiB cap on a single routed request/response frame.
const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

/// A request the guest routed to the substitution endpoint. Header values may
/// carry an opaque placeholder where a credential goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyRequest {
    pub method: String,
    /// The real destination URL (e.g. `https://api.openai.com/v1/...`).
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// A request with every placeholder substituted to its real credential, ready
/// for the forward leg to send to the destination over real TLS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Errors from preparing a routed request for forwarding.
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("request url `{0}` is not a valid absolute URL with a host")]
    BadUrl(String),
    #[error(transparent)]
    Substitute(#[from] SubstituteError),
}

/// Substitute every placeholder in `req`'s headers against `endpoint`,
/// binding-checked to the request's destination host. Returns a request whose
/// headers carry the real credentials, ready to forward.
///
/// Refuses — before the request is forwarded — if a placeholder's destination
/// is not bound for that secret (claim 12) or the placeholder is unknown. The
/// destination host is taken from the request URL, so a guest can't point a
/// secret at `api.openai.com` in the binding but send the bytes elsewhere: the
/// bind-check uses the URL we will actually dial.
pub fn prepare_request(
    endpoint: &SubstitutionEndpoint<'_>,
    req: ProxyRequest,
) -> Result<PreparedRequest, ProxyError> {
    let dest = destination_host(&req.url)?;
    let mut headers = Vec::with_capacity(req.headers.len());
    for (name, value) in req.headers {
        let new_value = match find_placeholder(&value) {
            Some(ph) => {
                let ph = ph.to_string();
                // `substitute` carries the claim-12 bind-check: an unbound
                // destination or unknown token errors here, before forwarding.
                endpoint.substitute(&ph, &dest, &value)?.to_string()
            }
            None => value,
        };
        headers.push((name, new_value));
    }
    Ok(PreparedRequest {
        method: req.method,
        url: req.url,
        headers,
        body: req.body,
    })
}

/// The destination host (no port) from an absolute URL.
fn destination_host(url: &str) -> Result<String, ProxyError> {
    Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .ok_or_else(|| ProxyError::BadUrl(url.to_string()))
}

// ============================================================================
// Transport — the host-local listener + the real-TLS forward leg (D-T2)
// ============================================================================

// The wire envelope (`WireRequest`/`WireResponse`) lives in
// `mvm_core::substitution_wire` so the in-guest client and this server share
// one contract (imported at the top of this file).

/// The response from the real destination.
pub struct ForwardResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Errors from the forward leg.
#[derive(Debug, thiserror::Error)]
pub enum ForwardError {
    #[error("forward failed: {0}")]
    Failed(String),
}

/// Errors from building a [`SubstitutionService`] from an admitted plan.
#[derive(Debug, thiserror::Error)]
pub enum FromPlanError {
    #[error(transparent)]
    Assemble(#[from] AssembleError),
    #[error(transparent)]
    Forward(#[from] ForwardError),
}

/// Forwards a prepared (credential-substituted) request to the real
/// destination and returns its response — the real-TLS leg of the endpoint.
/// A trait so the listener can be tested with a mock that records the
/// credential it received without a network call.
#[async_trait]
pub trait Forwarder: Send + Sync {
    async fn forward(&self, req: PreparedRequest) -> Result<ForwardResponse, ForwardError>;
}

/// Production forwarder: a hardened reqwest client (TLS 1.3 min, SSRF-filtered
/// resolver, no redirects — `hardened_client_builder`) makes the real request.
pub struct ReqwestForwarder {
    client: reqwest::Client,
}

impl ReqwestForwarder {
    pub fn new(timeout_secs: u64) -> Result<Self, ForwardError> {
        let client = hardened_client_builder(timeout_secs)
            .build()
            .map_err(|e| ForwardError::Failed(e.to_string()))?;
        Ok(Self { client })
    }
}

#[async_trait]
impl Forwarder for ReqwestForwarder {
    async fn forward(&self, req: PreparedRequest) -> Result<ForwardResponse, ForwardError> {
        let method = reqwest::Method::from_bytes(req.method.as_bytes())
            .map_err(|e| ForwardError::Failed(format!("bad method: {e}")))?;
        let mut rb = self.client.request(method, &req.url);
        for (k, v) in &req.headers {
            rb = rb.header(k, v);
        }
        if !req.body.is_empty() {
            rb = rb.body(req.body);
        }
        let resp = rb
            .send()
            .await
            .map_err(|e| ForwardError::Failed(e.to_string()))?;
        let status = resp.status().as_u16();
        let headers = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or_default().to_string()))
            .collect();
        let body = resp
            .bytes()
            .await
            .map_err(|e| ForwardError::Failed(e.to_string()))?
            .to_vec();
        Ok(ForwardResponse {
            status,
            headers,
            body,
        })
    }
}

/// The running host substitution endpoint: the admission-minted placeholder
/// registry, the secret resolver, and the forward leg. Placeholders are minted
/// at admission (ADR-067 §4), so the registry is read-only while serving.
pub struct SubstitutionService {
    registry: Arc<SubstitutionRegistry>,
    resolver: Arc<dyn SecretResolver>,
    forwarder: Arc<dyn Forwarder>,
    /// Optional chain-signed audit recorder. When set, each substitution emits
    /// a `secret.substituted` entry (metadata only — claim 13).
    recorder: Option<Recorder>,
}

impl SubstitutionService {
    pub fn new(
        registry: Arc<SubstitutionRegistry>,
        resolver: Arc<dyn SecretResolver>,
        forwarder: Arc<dyn Forwarder>,
    ) -> Self {
        Self {
            registry,
            resolver,
            forwarder,
            recorder: None,
        }
    }

    /// Attach a chain-signed audit recorder; each substitution then emits a
    /// `secret.substituted` entry (metadata only — claim 13).
    pub fn with_recorder(mut self, recorder: Recorder) -> Self {
        self.recorder = Some(recorder);
        self
    }

    /// Assemble a ready-to-serve service from an admitted plan's secret
    /// bindings: build the registry ([`assemble_registry`]), a [`LocalResolver`]
    /// over the tenant's secret store, and a hardened-reqwest forwarder.
    /// Returns the service plus the `(guest name, placeholder)` pairs the
    /// supervisor injects into the guest. The caller binds the listener and
    /// calls [`Self::serve`].
    pub fn from_plan(
        plan_secrets: &[SecretBinding],
        tenant: &str,
        bindings: &dyn BindingStore,
        secret_store: Arc<dyn SecretStore>,
        forward_timeout_secs: u64,
    ) -> Result<(Arc<Self>, HandedPlaceholders), FromPlanError> {
        let (registry, handed) = assemble_registry(plan_secrets, tenant, bindings)?;
        let resolver: Arc<dyn SecretResolver> = Arc::new(LocalResolver::new(tenant, secret_store));
        let forwarder: Arc<dyn Forwarder> = Arc::new(ReqwestForwarder::new(forward_timeout_secs)?);
        let service = Arc::new(Self::new(Arc::new(registry), resolver, forwarder));
        Ok((service, handed))
    }

    /// Accept loop: one routed request per connection, framed JSON, a task per
    /// connection. Runs until the listener errors.
    pub async fn serve(self: Arc<Self>, listener: UnixListener) {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let me = Arc::clone(&self);
                    tokio::spawn(async move {
                        if let Err(e) = me.handle_connection(stream).await {
                            tracing::warn!(error = %e, "substitution endpoint connection failed");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "substitution endpoint accept failed; stopping");
                    return;
                }
            }
        }
    }

    /// Accept loop over a host **AF_VSOCK** listener — the QEMU (`vhost-vsock`)
    /// guest→host path. Firecracker/libkrun route guest→host through a per-port
    /// UDS instead and use [`Self::serve`]. The accepted vsock fd is a
    /// `SOCK_STREAM` socket wrapped as a tokio `UnixStream` (same read/write
    /// syscalls), so it reuses [`Self::handle_connection`]. Blocking `accept(2)`
    /// runs on a `spawn_blocking` thread — no new async-vsock dependency.
    #[cfg(target_os = "linux")]
    pub async fn serve_vsock(self: Arc<Self>, listener: vsock::VsockListener) {
        loop {
            let listen_fd = listener.raw_fd();
            let accepted = tokio::task::spawn_blocking(move || vsock::accept(listen_fd)).await;
            let conn_fd = match accepted {
                Ok(Ok(fd)) => fd,
                Ok(Err(e)) => {
                    tracing::warn!(error = %e, "vsock substitution accept failed; stopping");
                    return;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "vsock accept task panicked; stopping");
                    return;
                }
            };
            let stream = match vsock::into_tokio_stream(conn_fd) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(error = %e, "wrap vsock connection; dropping");
                    continue;
                }
            };
            let me = Arc::clone(&self);
            tokio::spawn(async move {
                if let Err(e) = me.handle_connection(stream).await {
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

    async fn process(&self, wire: WireRequest) -> WireResponse {
        let body = match B64.decode(wire.body_b64.as_bytes()) {
            Ok(b) => b,
            Err(e) => {
                return WireResponse::Refused {
                    message: format!("bad body encoding: {e}"),
                };
            }
        };
        let req = ProxyRequest {
            method: wire.method,
            url: wire.url,
            headers: wire.headers,
            body,
        };
        // Per-request endpoint: two refs, cheap; the registry is read-only
        // after admission minted its placeholders.
        let registry: &SubstitutionRegistry = &self.registry;
        let endpoint = SubstitutionEndpoint::new(registry, self.resolver.as_ref());
        // Capture audit metadata (name + auth-type per substituted secret, and
        // the destination) before `prepare_request` consumes `req`. resolve_meta
        // touches no value, so this is claim-13 safe.
        let destination = destination_host(&req.url).ok();
        let substituted: Vec<(String, AuthType)> = req
            .headers
            .iter()
            .filter_map(|(_, v)| find_placeholder(v))
            .filter_map(|ph| endpoint.resolve_meta(ph))
            .collect();
        let prepared = match prepare_request(&endpoint, req) {
            Ok(p) => p,
            Err(e) => {
                return WireResponse::Refused {
                    message: e.to_string(),
                };
            }
        };
        match self.forwarder.forward(prepared).await {
            Ok(r) => {
                self.audit_substitutions(&substituted, destination.as_deref())
                    .await;
                WireResponse::Ok {
                    status: r.status,
                    headers: r.headers,
                    body_b64: B64.encode(r.body),
                }
            }
            Err(e) => WireResponse::Refused {
                message: e.to_string(),
            },
        }
    }

    /// Emit one `secret.substituted` audit entry per substituted secret (claim
    /// 13 — metadata only). Best-effort: an audit failure is logged, never
    /// fails the request. No-op when no recorder is wired.
    async fn audit_substitutions(
        &self,
        substituted: &[(String, AuthType)],
        destination: Option<&str>,
    ) {
        let (Some(recorder), Some(dest)) = (&self.recorder, destination) else {
            return;
        };
        for (name, auth_type) in substituted {
            if let Err(e) = emit_secret_substituted(recorder, name, dest, *auth_type).await {
                tracing::warn!(error = %e, secret = %name, "secret.substituted audit emit failed");
            }
        }
    }
}

/// Host-side AF_VSOCK listener for the QEMU (`vhost-vsock`) guest→host
/// substitution path. Firecracker/libkrun bridge guest→host through a per-port
/// UDS — those use the `UnixListener` `serve`. Raw libc (no async-vsock dep);
/// blocking `accept` is driven from the async loop via `spawn_blocking`.
#[cfg(target_os = "linux")]
pub mod vsock {
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

    const AF_VSOCK: libc::c_int = 40;
    /// Bind to any guest CID so any guest on this host can reach the endpoint.
    const VMADDR_CID_ANY: u32 = u32::MAX;

    // Kernel uapi `struct sockaddr_vm`: family u16 + reserved u16 + port u32 +
    // cid u32 + 4-byte pad = 16.
    #[repr(C)]
    struct SockaddrVm {
        svm_family: libc::sa_family_t,
        svm_reserved1: u16,
        svm_port: u32,
        svm_cid: u32,
        svm_zero: [u8; 4],
    }
    const _: () = assert!(std::mem::size_of::<SockaddrVm>() == 16);

    /// A bound, listening host AF_VSOCK socket on a vsock port.
    pub struct VsockListener {
        fd: OwnedFd,
    }

    impl VsockListener {
        /// Bind + listen on AF_VSOCK `(VMADDR_CID_ANY, port)`.
        pub fn bind(port: u32) -> io::Result<Self> {
            // SAFETY: standard socket/bind/listen on AF_VSOCK; `addr` is fully
            // initialized and sized exactly. The fd is adopted by `OwnedFd`
            // immediately, closing on drop / on the error paths.
            unsafe {
                let fd = libc::socket(AF_VSOCK, libc::SOCK_STREAM, 0);
                if fd < 0 {
                    return Err(io::Error::last_os_error());
                }
                let owned = OwnedFd::from_raw_fd(fd);
                let addr = SockaddrVm {
                    svm_family: AF_VSOCK as libc::sa_family_t,
                    svm_reserved1: 0,
                    svm_port: port,
                    svm_cid: VMADDR_CID_ANY,
                    svm_zero: [0; 4],
                };
                if libc::bind(
                    fd,
                    std::ptr::addr_of!(addr).cast::<libc::sockaddr>(),
                    std::mem::size_of::<SockaddrVm>() as libc::socklen_t,
                ) < 0
                {
                    return Err(io::Error::last_os_error());
                }
                if libc::listen(fd, 128) < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(Self { fd: owned })
            }
        }

        pub fn raw_fd(&self) -> RawFd {
            self.fd.as_raw_fd()
        }
    }

    /// Blocking `accept(2)` on a listening AF_VSOCK fd, returning the
    /// connection fd. Run via `spawn_blocking` from the async serve loop.
    pub fn accept(listen_fd: RawFd) -> io::Result<RawFd> {
        // SAFETY: accept(2) on a listening AF_VSOCK fd; peer addr not needed.
        let cfd = unsafe { libc::accept(listen_fd, std::ptr::null_mut(), std::ptr::null_mut()) };
        if cfd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(cfd)
    }

    /// Adopt an accepted vsock connection fd as a non-blocking tokio
    /// `UnixStream` (a `SOCK_STREAM` socket — same read/write syscalls).
    pub fn into_tokio_stream(conn_fd: RawFd) -> io::Result<tokio::net::UnixStream> {
        // SAFETY: `conn_fd` is an owned connected stream socket from `accept`.
        let std_stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(conn_fd) };
        std_stream.set_nonblocking(true)?;
        tokio::net::UnixStream::from_std(std_stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyholder::{LocalResolver, SubstitutionRegistry};
    use mvm_core::crypto::secret_store::{FileSecretStore, SecretStore};
    use mvm_sdk::ir::{AuthType, SecretMount, SecretRef};
    use secrecy::SecretBox;
    use std::sync::Arc;
    use tempfile::tempdir;

    fn resolver_with(name: &str, value: &str) -> (tempfile::TempDir, LocalResolver) {
        let dir = tempdir().unwrap();
        let store = FileSecretStore::with_dir(dir.path());
        store
            .put("local", name, &SecretBox::new(Box::new(value.to_string())))
            .unwrap();
        let store: Arc<dyn SecretStore> = Arc::new(store);
        (dir, LocalResolver::new("local", store))
    }

    fn bearer_ref(name: &str, hosts: &[&str]) -> SecretRef {
        SecretRef {
            name: name.into(),
            mount: SecretMount::Env { var: "K".into() },
            auth_type: AuthType::Bearer,
            allowed_hosts: hosts.iter().map(|h| h.to_string()).collect(),
        }
    }

    #[test]
    fn prepares_request_with_real_credential_for_a_bound_host() {
        let (_dir, resolver) = resolver_with("openai", "sk-live-zzz");
        let mut reg = SubstitutionRegistry::new();
        let ph = reg.mint(bearer_ref("openai", &["api.openai.com"]));
        let endpoint = SubstitutionEndpoint::new(&reg, &resolver);

        let req = ProxyRequest {
            method: "POST".into(),
            url: "https://api.openai.com/v1/chat".into(),
            headers: vec![
                ("authorization".into(), format!("Bearer {}", ph.as_str())),
                ("content-type".into(), "application/json".into()),
            ],
            body: b"{}".to_vec(),
        };
        let prepared = prepare_request(&endpoint, req).unwrap();
        assert_eq!(
            prepared.headers[0],
            ("authorization".into(), "Bearer sk-live-zzz".into())
        );
        // A header without a placeholder is untouched.
        assert_eq!(prepared.headers[1].1, "application/json");
    }

    #[test]
    fn refuses_a_request_to_an_unbound_host() {
        let (_dir, resolver) = resolver_with("openai", "sk-live-zzz");
        let mut reg = SubstitutionRegistry::new();
        let ph = reg.mint(bearer_ref("openai", &["api.openai.com"]));
        let endpoint = SubstitutionEndpoint::new(&reg, &resolver);

        let req = ProxyRequest {
            method: "POST".into(),
            url: "https://evil.example.com/x".into(),
            headers: vec![("authorization".into(), format!("Bearer {}", ph.as_str()))],
            body: vec![],
        };
        let err = prepare_request(&endpoint, req).unwrap_err();
        assert!(matches!(err, ProxyError::Substitute(_)));
    }

    #[test]
    fn passes_through_a_request_without_a_placeholder() {
        let (_dir, resolver) = resolver_with("openai", "sk-live-zzz");
        let reg = SubstitutionRegistry::new();
        let endpoint = SubstitutionEndpoint::new(&reg, &resolver);

        let req = ProxyRequest {
            method: "GET".into(),
            url: "https://api.openai.com/v1".into(),
            headers: vec![("authorization".into(), "Bearer ya29.real-token".into())],
            body: vec![],
        };
        let prepared = prepare_request(&endpoint, req.clone()).unwrap();
        assert_eq!(prepared.headers, req.headers);
    }

    #[test]
    fn rejects_a_url_without_a_host() {
        let (_dir, resolver) = resolver_with("openai", "sk-live-zzz");
        let reg = SubstitutionRegistry::new();
        let endpoint = SubstitutionEndpoint::new(&reg, &resolver);
        let req = ProxyRequest {
            method: "GET".into(),
            url: "not a url".into(),
            headers: vec![],
            body: vec![],
        };
        assert!(matches!(
            prepare_request(&endpoint, req).unwrap_err(),
            ProxyError::BadUrl(_)
        ));
    }
}

#[cfg(test)]
mod server_tests {
    use super::*;
    use crate::keyholder::LocalResolver;
    use mvm_core::crypto::secret_store::{FileSecretStore, SecretStore};
    use mvm_sdk::ir::{AuthType, SecretMount, SecretRef};
    use secrecy::SecretBox;
    use std::sync::Mutex;
    use tempfile::tempdir;

    /// Records the request it was handed so a test can prove the destination
    /// (not the guest) received the real credential — without a network call.
    struct MockForwarder {
        seen: Mutex<Option<PreparedRequest>>,
    }

    #[async_trait]
    impl Forwarder for MockForwarder {
        async fn forward(&self, req: PreparedRequest) -> Result<ForwardResponse, ForwardError> {
            *self.seen.lock().unwrap() = Some(req);
            Ok(ForwardResponse {
                status: 200,
                headers: vec![("x-mock".into(), "1".into())],
                body: b"pong".to_vec(),
            })
        }
    }

    fn bearer_ref(name: &str, hosts: &[&str]) -> SecretRef {
        SecretRef {
            name: name.into(),
            mount: SecretMount::Env { var: "K".into() },
            auth_type: AuthType::Bearer,
            allowed_hosts: hosts.iter().map(|h| h.to_string()).collect(),
        }
    }

    /// Build a service over a file store seeded with `openai`=value, a registry
    /// holding one minted placeholder for `hosts`, and a `MockForwarder`.
    /// Returns the service, the minted placeholder string, and the forwarder.
    fn service_with(
        value: &str,
        hosts: &[&str],
    ) -> (
        Arc<SubstitutionService>,
        String,
        Arc<MockForwarder>,
        tempfile::TempDir,
    ) {
        let dir = tempdir().unwrap();
        let store = FileSecretStore::with_dir(dir.path());
        store
            .put(
                "local",
                "openai",
                &SecretBox::new(Box::new(value.to_string())),
            )
            .unwrap();
        let resolver: Arc<dyn SecretResolver> =
            Arc::new(LocalResolver::new("local", Arc::new(store)));
        let mut reg = SubstitutionRegistry::new();
        let ph = reg.mint(bearer_ref("openai", hosts)).as_str().to_string();
        let forwarder = Arc::new(MockForwarder {
            seen: Mutex::new(None),
        });
        let service = Arc::new(SubstitutionService::new(
            Arc::new(reg),
            resolver,
            forwarder.clone(),
        ));
        (service, ph, forwarder, dir)
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

    #[test]
    fn from_plan_builds_a_service_and_handed_placeholders() {
        use crate::keyholder::{FileBindingStore, SecretBindingMeta};
        use mvm_core::plan::{SecretBinding, SecretSource};

        let dir = tempdir().unwrap();
        // Binding metadata (`secret set`) + the value store.
        let bindings = FileBindingStore::with_dir(dir.path().join("bindings"));
        bindings
            .put(
                "local",
                "openai",
                &SecretBindingMeta {
                    auth_type: AuthType::Bearer,
                    allowed_hosts: vec!["api.openai.com".into()],
                },
            )
            .unwrap();
        let store = FileSecretStore::with_dir(dir.path().join("secrets"));
        store
            .put(
                "local",
                "openai",
                &SecretBox::new(Box::new("sk".to_string())),
            )
            .unwrap();
        let secret_store: Arc<dyn SecretStore> = Arc::new(store);

        let plan = [SecretBinding {
            name: "OPENAI_API_KEY".into(),
            source: SecretSource::Keystore {
                address: "openai".into(),
            },
        }];
        let (_service, handed) =
            SubstitutionService::from_plan(&plan, "local", &bindings, secret_store, 30).unwrap();
        assert_eq!(handed.len(), 1);
        assert_eq!(handed[0].0, "OPENAI_API_KEY");
        assert!(handed[0].1.as_str().starts_with("mvm-secret-"));
    }

    #[tokio::test]
    async fn endpoint_refuses_unbound_destination_and_never_forwards() {
        let (service, ph, forwarder, dir) = service_with("sk-live-zzz", &["api.openai.com"]);
        let sock = dir.path().join("subst.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let server = tokio::spawn(Arc::clone(&service).serve(listener));

        let mut client = UnixStream::connect(&sock).await.unwrap();
        let wire = WireRequest {
            method: "POST".into(),
            url: "https://evil.example.com/x".into(),
            headers: vec![("authorization".into(), format!("Bearer {ph}"))],
            body_b64: String::new(),
        };
        write_json_frame(&mut client, &wire).await.unwrap();
        let resp: WireResponse = read_json_frame(&mut client, MAX_FRAME_BYTES).await.unwrap();

        assert!(matches!(resp, WireResponse::Refused { .. }));
        // claim 12: an unbound destination never reaches the forward leg.
        assert!(forwarder.seen.lock().unwrap().is_none());
        server.abort();
    }

    #[tokio::test]
    async fn emits_secret_substituted_audit_on_success() {
        use crate::supervisor::audit_file::FileAuditSigner;
        use crate::supervisor::audit_recorder::Recorder;
        use ed25519_dalek::SigningKey;
        use mvm_core::plan::TenantId;

        let dir = tempdir().unwrap();
        let store = FileSecretStore::with_dir(dir.path().join("secrets"));
        store
            .put(
                "local",
                "openai",
                &SecretBox::new(Box::new("sk-live-zzz".to_string())),
            )
            .unwrap();
        let resolver: Arc<dyn SecretResolver> =
            Arc::new(LocalResolver::new("local", Arc::new(store)));
        let mut reg = SubstitutionRegistry::new();
        let ph = reg
            .mint(bearer_ref("openai", &["api.openai.com"]))
            .as_str()
            .to_string();
        let forwarder = Arc::new(MockForwarder {
            seen: Mutex::new(None),
        });

        let chain = dir.path().join("audit.jsonl");
        let signer =
            FileAuditSigner::open_file(SigningKey::from_bytes(&[9u8; 32]), &chain).unwrap();
        let recorder = Recorder::new(Arc::new(signer), TenantId("local".into()));

        let service = Arc::new(
            SubstitutionService::new(Arc::new(reg), resolver, forwarder).with_recorder(recorder),
        );
        let sock = dir.path().join("subst.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let server = tokio::spawn(Arc::clone(&service).serve(listener));

        let mut client = UnixStream::connect(&sock).await.unwrap();
        let wire = WireRequest {
            method: "POST".into(),
            url: "https://api.openai.com/v1".into(),
            headers: vec![("authorization".into(), format!("Bearer {ph}"))],
            body_b64: String::new(),
        };
        write_json_frame(&mut client, &wire).await.unwrap();
        // The audit emit completes before the Ok response is written, so the
        // chain entry is on disk by the time we read the reply.
        let _resp: WireResponse = read_json_frame(&mut client, MAX_FRAME_BYTES).await.unwrap();

        let logged = std::fs::read_to_string(&chain).unwrap();
        assert!(logged.contains("secret.substituted"), "got: {logged}");
        assert!(logged.contains("openai"));
        assert!(logged.contains("api.openai.com"));
        // claim 13: the value never reaches the audit chain.
        assert!(
            !logged.contains("sk-live-zzz"),
            "audit chain must not carry the secret value: {logged}"
        );
        server.abort();
    }
}
