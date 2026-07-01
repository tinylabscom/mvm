//! `GatewayBackend` — the remote `MvmClient` over mvmd-gateway's REST API.
//!
//! A dumb courier with zero enforcement authority: it presents credentials and
//! ships intent; the gateway is the authority for every decision. Transport is
//! fail-closed — cleartext is refused to anything but a loopback sidecar, so a
//! bearer token can never leave the host in the clear to a remote fleet.

use async_trait::async_trait;
use reqwest::{StatusCode, Url};

use crate::client::MvmClient;
use crate::dto::{LogOpts, MachineFilter, MachineId, MachineSpec, MachineState};
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

#[async_trait]
impl MvmClient for GatewayBackend {
    async fn list_machines(&self, _filter: MachineFilter) -> Result<Vec<MachineState>> {
        // Mapping the gateway's sandbox response into MachineState is deferred
        // until the gateway serves the shared typed DTO contract; guessing the
        // untyped JSON shape now would be fragile and untestable here.
        Err(MvmError::Backend {
            reason: "gateway list mapping pending typed DTO contract".into(),
        })
    }

    async fn run_machine(&self, _spec: MachineSpec) -> Result<MachineState> {
        Err(MvmError::Backend {
            reason: "gateway run mapping pending typed DTO contract".into(),
        })
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
