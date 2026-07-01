//! `GatewayBackend` — the remote `MvmClient` over mvmd-gateway's REST API.
//!
//! A dumb courier with zero enforcement authority: it presents credentials and
//! ships intent; the gateway is the authority for every decision. Transport is
//! fail-closed — cleartext is refused to anything but a loopback sidecar, so a
//! bearer token can never leave the host in the clear to a remote fleet.

use async_trait::async_trait;
use reqwest::{StatusCode, Url};

use crate::client::MvmClient;
use crate::dto::{LogOpts, MachineFilter, MachineId, MachineSpec, MachineState, MachineStatus};
use crate::error::{MvmError, Result};

/// How to reach a gateway: its base URL and the bearer token to present.
pub struct GatewayConfig {
    pub base_url: String,
    pub token: String,
}

/// Fail-closed transport check. `https` is allowed anywhere; `http` is allowed
/// only to a loopback host (the local sidecar — the single cleartext
/// exception). Everything else is refused before a request is sent.
pub fn endpoint_guard(url: &Url) -> Result<()> {
    match url.scheme() {
        "https" => Ok(()),
        "http" if is_loopback(url) => Ok(()),
        "http" => Err(MvmError::Backend {
            reason: format!("refusing cleartext http to non-loopback host: {url}"),
        }),
        other => Err(MvmError::Backend {
            reason: format!("unsupported url scheme: {other}"),
        }),
    }
}

fn is_loopback(url: &Url) -> bool {
    match url.host_str() {
        Some("localhost") => true,
        Some(h) => h
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false),
        None => false,
    }
}

/// The remote `MvmClient`. Holds a TLS-validating HTTP client, the gateway base
/// URL, and the bearer token. Construction is fail-closed — a cleartext remote
/// base URL is rejected here, before any request or token exposure.
pub struct GatewayBackend {
    http: reqwest::Client,
    base: Url,
    token: String,
}

// Hand-written so the bearer token never lands in a debug line or log.
impl std::fmt::Debug for GatewayBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayBackend")
            .field("base", &self.base.as_str())
            .field("token", &"<redacted>")
            .finish()
    }
}

impl GatewayBackend {
    pub fn new(config: GatewayConfig) -> Result<Self> {
        let base = Url::parse(&config.base_url).map_err(|e| MvmError::Backend {
            reason: format!("invalid gateway base url: {e}"),
        })?;
        endpoint_guard(&base)?;
        let http = reqwest::Client::builder()
            .build()
            .map_err(|e| MvmError::Backend {
                reason: format!("building http client: {e}"),
            })?;
        Ok(Self {
            http,
            base,
            token: config.token,
        })
    }

    /// Resolve an API path against the base URL, re-checking the transport guard
    /// so a redirect or misjoin can't downgrade to cleartext.
    fn endpoint(&self, path: &str) -> Result<Url> {
        let url = self.base.join(path).map_err(|e| MvmError::Backend {
            reason: format!("bad api path {path}: {e}"),
        })?;
        endpoint_guard(&url)?;
        Ok(url)
    }

    /// Attach the bearer credential. Endpoint-bound: only ever sent to `base`.
    fn authed(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        req.bearer_auth(&self.token)
    }
}

/// Map a non-success HTTP status onto a facade error. `None` means success.
fn status_error(status: StatusCode, id: &str) -> Option<MvmError> {
    if status.is_success() {
        return None;
    }
    Some(match status {
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => MvmError::Unauthorized {
            reason: format!("gateway rejected credential ({status})"),
        },
        StatusCode::NOT_FOUND => MvmError::NotFound { id: id.to_string() },
        other => MvmError::Backend {
            reason: format!("gateway returned {other}"),
        },
    })
}

/// Inbound mirror of the gateway's sandbox record — only the fields the facade
/// needs. Tolerant of extra fields since it's a server response we don't own.
#[derive(serde::Deserialize)]
struct SandboxDto {
    sandbox_id: String,
    name: String,
    #[serde(default)]
    status: String,
}

/// The gateway's paginated list envelope (`{ data: [...], metadata: {...} }`).
#[derive(serde::Deserialize)]
struct SandboxPage {
    data: Vec<SandboxDto>,
}

/// The gateway's single-item envelope (`{ data: {...}, metadata: {...} }`).
#[derive(serde::Deserialize)]
struct SandboxEnvelope {
    data: SandboxDto,
}

/// Body for `POST /api/v1/sandboxes`. Only the fields the create endpoint
/// accepts; region/labels/ports default server-side.
#[derive(serde::Serialize)]
struct CreateSandboxBody<'a> {
    name: &'a str,
    image: &'a str,
    memory_mib: u32,
    vcpus: u32,
}

/// Map the gateway's status string onto the facade status. Unknown values fail
/// safe to `Failed` rather than a misleading `Running`.
fn map_status(s: &str) -> MachineStatus {
    match s.to_ascii_lowercase().as_str() {
        "running" => MachineStatus::Running,
        "starting" | "pending" | "creating" | "provisioning" => MachineStatus::Starting,
        "stopped" | "created" | "sleeping" | "terminated" | "exited" => MachineStatus::Stopped,
        _ => MachineStatus::Failed,
    }
}

impl From<SandboxDto> for MachineState {
    fn from(s: SandboxDto) -> Self {
        MachineState {
            id: MachineId(s.sandbox_id),
            name: s.name,
            status: map_status(&s.status),
        }
    }
}

fn filter_machines(machines: Vec<MachineState>, filter: &MachineFilter) -> Vec<MachineState> {
    machines
        .into_iter()
        .filter(|m| filter.name.as_ref().is_none_or(|n| *n == m.name))
        .filter(|m| filter.status.is_none_or(|s| s == m.status))
        .collect()
}

#[async_trait]
impl MvmClient for GatewayBackend {
    async fn list_machines(&self, filter: MachineFilter) -> Result<Vec<MachineState>> {
        let url = self.endpoint("/api/v1/sandboxes")?;
        let resp = self
            .authed(self.http.get(url))
            .send()
            .await
            .map_err(|e| MvmError::Backend {
                reason: format!("list request failed: {e}"),
            })?;
        if let Some(e) = status_error(resp.status(), "") {
            return Err(e);
        }
        let page: SandboxPage = resp.json().await.map_err(|e| MvmError::Backend {
            reason: format!("parsing sandbox list: {e}"),
        })?;
        let machines = page.data.into_iter().map(MachineState::from).collect();
        Ok(filter_machines(machines, &filter))
    }

    async fn run_machine(&self, spec: MachineSpec) -> Result<MachineState> {
        // The create-sandbox endpoint has no env field; refuse rather than
        // silently drop env the workload would expect.
        if !spec.env.is_empty() {
            return Err(MvmError::InvalidSpec {
                reason: "gateway create-sandbox does not accept env vars; bake them into the image or leave env empty".into(),
            });
        }
        let url = self.endpoint("/api/v1/sandboxes")?;
        let body = CreateSandboxBody {
            name: &spec.name,
            image: &spec.image,
            memory_mib: spec.memory_mib,
            vcpus: spec.cpus,
        };
        let resp = self
            .authed(self.http.post(url))
            .json(&body)
            .send()
            .await
            .map_err(|e| MvmError::Backend {
                reason: format!("create request failed: {e}"),
            })?;
        if let Some(e) = status_error(resp.status(), &spec.name) {
            return Err(e);
        }
        let env: SandboxEnvelope = resp.json().await.map_err(|e| MvmError::Backend {
            reason: format!("parsing create response: {e}"),
        })?;
        Ok(env.data.into())
    }

    async fn stop_machine(&self, id: &MachineId) -> Result<()> {
        let url = self.endpoint(&format!("/api/v1/sandboxes/{}/stop", id.0))?;
        let resp =
            self.authed(self.http.post(url))
                .send()
                .await
                .map_err(|e| MvmError::Backend {
                    reason: format!("stop request failed: {e}"),
                })?;
        match status_error(resp.status(), &id.0) {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    async fn machine_logs(&self, id: &MachineId, opts: LogOpts) -> Result<Vec<u8>> {
        let mut url = self.endpoint(&format!("/api/v1/sandboxes/{}/logs", id.0))?;
        if let Some(n) = opts.tail_lines {
            url.query_pairs_mut().append_pair("tail", &n.to_string());
        }
        let resp = self
            .authed(self.http.get(url))
            .send()
            .await
            .map_err(|e| MvmError::Backend {
                reason: format!("logs request failed: {e}"),
            })?;
        if let Some(e) = status_error(resp.status(), &id.0) {
            return Err(e);
        }
        let bytes = resp.bytes().await.map_err(|e| MvmError::Backend {
            reason: format!("reading logs body: {e}"),
        })?;
        Ok(bytes.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guard(u: &str) -> Result<()> {
        endpoint_guard(&Url::parse(u).unwrap())
    }

    #[test]
    fn https_is_allowed_anywhere() {
        assert!(guard("https://fleet.example.com/api").is_ok());
    }

    #[test]
    fn http_to_loopback_is_allowed() {
        assert!(guard("http://127.0.0.1:9090/api").is_ok());
        assert!(guard("http://localhost:9090/api").is_ok());
        assert!(guard("http://[::1]:9090/api").is_ok());
    }

    #[test]
    fn http_to_non_loopback_is_refused() {
        let err = guard("http://fleet.example.com/api").unwrap_err();
        assert!(matches!(err, MvmError::Backend { .. }));
    }

    #[test]
    fn non_http_scheme_is_refused() {
        assert!(guard("ftp://host/x").is_err());
    }

    fn cfg(base: &str) -> GatewayConfig {
        GatewayConfig {
            base_url: base.into(),
            token: "mvmd_org_deadbeef".into(),
        }
    }

    #[test]
    fn construction_refuses_cleartext_remote() {
        let err = GatewayBackend::new(cfg("http://fleet.example.com")).unwrap_err();
        assert!(matches!(err, MvmError::Backend { .. }));
    }

    #[test]
    fn construction_accepts_https_and_loopback() {
        assert!(GatewayBackend::new(cfg("https://fleet.example.com")).is_ok());
        assert!(GatewayBackend::new(cfg("http://127.0.0.1:9090")).is_ok());
    }

    #[test]
    fn endpoint_join_preserves_guard() {
        let be = GatewayBackend::new(cfg("https://fleet.example.com")).unwrap();
        let url = be.endpoint("/api/v1/sandboxes").unwrap();
        assert_eq!(url.as_str(), "https://fleet.example.com/api/v1/sandboxes");
    }

    #[test]
    fn debug_redacts_the_token() {
        let be = GatewayBackend::new(cfg("https://fleet.example.com")).unwrap();
        let s = format!("{be:?}");
        assert!(
            !s.contains("mvmd_org_deadbeef"),
            "token must not appear in Debug"
        );
        assert!(s.contains("<redacted>"));
    }

    #[test]
    fn map_status_covers_known_and_unknown() {
        assert_eq!(map_status("running"), MachineStatus::Running);
        assert_eq!(map_status("Pending"), MachineStatus::Starting);
        assert_eq!(map_status("stopped"), MachineStatus::Stopped);
        assert_eq!(map_status("wat"), MachineStatus::Failed);
    }

    #[test]
    fn sandbox_page_json_maps_to_machines() {
        // Shape mirrors the gateway's SandboxRecord + paginated envelope.
        let json = r#"{"data":[{"sandbox_id":"sbx-1","name":"web","status":"running","image":"x","memory_mib":128,"vcpus":1,"tenant_id":"t","pool_id":"default","workspace_id":"w","created_at":"now"}],"metadata":{}}"#;
        let page: SandboxPage = serde_json::from_str(json).unwrap();
        let machines: Vec<MachineState> = page.data.into_iter().map(MachineState::from).collect();
        assert_eq!(machines.len(), 1);
        assert_eq!(machines[0].id, MachineId("sbx-1".into()));
        assert_eq!(machines[0].name, "web");
        assert_eq!(machines[0].status, MachineStatus::Running);
    }

    #[test]
    fn filter_by_status_narrows_the_list() {
        let ms = vec![
            MachineState {
                id: MachineId("1".into()),
                name: "a".into(),
                status: MachineStatus::Running,
            },
            MachineState {
                id: MachineId("2".into()),
                name: "b".into(),
                status: MachineStatus::Stopped,
            },
        ];
        let f = MachineFilter {
            name: None,
            status: Some(MachineStatus::Running),
        };
        let out = filter_machines(ms, &f);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "a");
    }

    #[tokio::test]
    async fn run_refuses_env_the_gateway_cannot_honor() {
        let be = GatewayBackend::new(cfg("https://fleet.example.com")).unwrap();
        let spec = MachineSpec {
            name: "w".into(),
            image: "i".into(),
            cpus: 1,
            memory_mib: 64,
            env: vec![("A".into(), "B".into())],
        };
        // The env guard fires before any request, so no server is needed.
        let err = be.run_machine(spec).await.unwrap_err();
        assert!(matches!(err, MvmError::InvalidSpec { .. }));
    }

    #[test]
    fn create_response_envelope_maps_to_machine() {
        // Mirrors ApiResponse<SandboxRecord> = { data: {...}, metadata: {...} }.
        let json = r#"{"data":{"sandbox_id":"sbx-9","name":"api","status":"starting","image":"x","memory_mib":256,"vcpus":2,"tenant_id":"t","pool_id":"default","workspace_id":"w","created_at":"now"},"metadata":{"request_id":"r","timestamp":"now"}}"#;
        let env: SandboxEnvelope = serde_json::from_str(json).unwrap();
        let m: MachineState = env.data.into();
        assert_eq!(m.id, MachineId("sbx-9".into()));
        assert_eq!(m.status, MachineStatus::Starting);
    }

    #[test]
    fn status_error_maps_codes() {
        assert!(status_error(StatusCode::OK, "m1").is_none());
        assert!(matches!(
            status_error(StatusCode::UNAUTHORIZED, "m1"),
            Some(MvmError::Unauthorized { .. })
        ));
        assert!(matches!(
            status_error(StatusCode::NOT_FOUND, "m1"),
            Some(MvmError::NotFound { id }) if id == "m1"
        ));
        assert!(matches!(
            status_error(StatusCode::INTERNAL_SERVER_ERROR, "m1"),
            Some(MvmError::Backend { .. })
        ));
    }
}
