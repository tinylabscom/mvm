//! `GatewayBackend` — the remote `MvmClient` over mvmd-gateway's REST API.
//!
//! A dumb courier with zero enforcement authority: it presents credentials and
//! ships intent; the gateway is the authority for every decision. Transport is
//! fail-closed — cleartext is refused to anything but a loopback sidecar, so a
//! bearer token can never leave the host in the clear to a remote fleet.

use async_trait::async_trait;
use mvm_http::{StatusCode, Url};

use crate::client::MvmClient;
use crate::client::dto::{
    LogOpts, MachineFilter, MachineId, MachineSpec, MachineState, MachineStatus, PauseOpts,
    PauseOutcome, ReconfigureRequest, ResumeOpts, ResumeOutcome,
};
use crate::client::error::{MvmError, Result};
use mvm_contract::protocol::capability_negotiation::{
    BackendCapabilityReport, ClientOperationCapabilities,
};

fn gateway_operations() -> ClientOperationCapabilities {
    ClientOperationCapabilities::builder()
        .list(true)
        .inspect(true)
        .run(true)
        .stop(true)
        .remove(true)
        .logs(true)
        .reconfigure(true)
        .build()
}

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
    http: mvm_http::Client,
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
        let http = mvm_http::Client::builder()
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

    /// Build an API endpoint from path components so tenant and resource IDs
    /// are percent-encoded rather than interpolated into a URL string.
    fn endpoint_components(&self, components: &[&str]) -> Result<Url> {
        let mut url = self.base.clone();
        url.set_path("/");
        url.set_query(None);
        url.set_fragment(None);
        {
            let mut segments = url.path_segments_mut().map_err(|()| MvmError::Backend {
                reason: "gateway base URL cannot carry API path segments".into(),
            })?;
            segments.pop_if_empty();
            segments.extend(components);
        }
        endpoint_guard(&url)?;
        Ok(url)
    }

    /// Attach the bearer credential. Endpoint-bound: only ever sent to `base`.
    fn authed(&self, req: mvm_http::RequestBuilder) -> mvm_http::RequestBuilder {
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
        StatusCode::CONFLICT => MvmError::Conflict {
            reason: format!("gateway rejected conflicting state for {id}"),
        },
        StatusCode::UNPROCESSABLE_ENTITY | StatusCode::BAD_REQUEST => MvmError::Rejected {
            reason: format!("gateway rejected the request for {id} ({status})"),
        },
        StatusCode::SERVICE_UNAVAILABLE | StatusCode::GATEWAY_TIMEOUT => MvmError::Unavailable {
            reason: format!("gateway could not serve {id} ({status})"),
        },
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

/// Body for `POST /api/v1/sandboxes/{id}/reconfigure`. Patch semantics:
/// only set fields are serialized (the gateway leaves the rest unchanged).
#[derive(serde::Serialize)]
struct ReconfigureBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    net: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    allow_host: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cpus: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    memory_mib: Option<u32>,
}

/// A tenant block volume returned by mvmd.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct RemoteVolume {
    pub volume_id: String,
    pub tenant_id: String,
    pub name: String,
    pub size_gib: u32,
    #[serde(default)]
    pub storage_class: String,
    #[serde(default)]
    pub from_snapshot_id: Option<String>,
    #[serde(default)]
    pub bucket_id: Option<String>,
    #[serde(default)]
    pub current_checkpoint_id: Option<String>,
    #[serde(default)]
    pub attached_instance_id: Option<String>,
}

/// One immutable remote volume checkpoint returned by mvmd.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct RemoteVolumeSnapshot {
    pub snapshot_id: String,
    pub volume_id: String,
    pub name: String,
    pub size_gib: u32,
    pub status: String,
    #[serde(default)]
    pub bucket_id: Option<String>,
    #[serde(default)]
    pub checkpoint_id: String,
}

/// One exclusive remote volume attachment returned by mvmd.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct RemoteVolumeAttachment {
    pub volume_id: String,
    pub tenant_id: String,
    pub instance_id: String,
    #[serde(default)]
    pub device_path: String,
    #[serde(default)]
    pub read_only: bool,
    #[serde(default)]
    pub fencing_token: u64,
}

/// Validated request for creating or restoring a remote volume.
pub struct RemoteVolumeCreate {
    name: String,
    size_gib: u32,
    storage_class: Option<String>,
    from_snapshot_id: Option<String>,
    bucket_id: Option<String>,
}

impl RemoteVolumeCreate {
    /// Begin constructing a remote volume request.
    #[must_use]
    pub fn builder(name: impl Into<String>, size_gib: u32) -> RemoteVolumeCreateBuilder {
        RemoteVolumeCreateBuilder {
            name: name.into(),
            size_gib,
            storage_class: None,
            from_snapshot_id: None,
            bucket_id: None,
        }
    }
}

/// Builder for [`RemoteVolumeCreate`].
pub struct RemoteVolumeCreateBuilder {
    name: String,
    size_gib: u32,
    storage_class: Option<String>,
    from_snapshot_id: Option<String>,
    bucket_id: Option<String>,
}

/// Request for attaching a remote volume to one instance.
pub struct RemoteVolumeMount {
    volume_id: String,
    instance_id: String,
    device_path: String,
    read_only: bool,
}

impl RemoteVolumeMount {
    /// Construct a mount request; callers may opt into writable access.
    #[must_use]
    pub fn new(
        volume_id: impl Into<String>,
        instance_id: impl Into<String>,
        device_path: impl Into<String>,
    ) -> Self {
        Self {
            volume_id: volume_id.into(),
            instance_id: instance_id.into(),
            device_path: device_path.into(),
            read_only: true,
        }
    }

    #[must_use]
    pub fn writable(mut self, writable: bool) -> Self {
        self.read_only = !writable;
        self
    }
}

impl RemoteVolumeCreateBuilder {
    #[must_use]
    pub fn storage_class(mut self, value: impl Into<String>) -> Self {
        self.storage_class = Some(value.into());
        self
    }

    #[must_use]
    pub fn from_snapshot(mut self, value: impl Into<String>) -> Self {
        self.from_snapshot_id = Some(value.into());
        self
    }

    #[must_use]
    pub fn bucket(mut self, value: impl Into<String>) -> Self {
        self.bucket_id = Some(value.into());
        self
    }

    pub fn build(self) -> Result<RemoteVolumeCreate> {
        if self.name.trim().is_empty() {
            return Err(MvmError::InvalidSpec {
                reason: "remote volume name must not be empty".into(),
            });
        }
        if self.size_gib == 0 {
            return Err(MvmError::InvalidSpec {
                reason: "remote volume size must be at least 1 GiB".into(),
            });
        }
        Ok(RemoteVolumeCreate {
            name: self.name,
            size_gib: self.size_gib,
            storage_class: self.storage_class,
            from_snapshot_id: self.from_snapshot_id,
            bucket_id: self.bucket_id,
        })
    }
}

#[derive(serde::Serialize)]
struct CreateRemoteVolumeBody<'a> {
    name: &'a str,
    size_gib: u32,
    encrypted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    storage_class: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    from_snapshot_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bucket_id: Option<&'a str>,
}

#[derive(serde::Serialize)]
struct CreateRemoteSnapshotBody<'a> {
    name: &'a str,
}

#[derive(serde::Serialize)]
struct AttachRemoteVolumeBody<'a> {
    instance_id: &'a str,
    device_path: &'a str,
    read_only: bool,
}

impl GatewayBackend {
    async fn decode_json<T: serde::de::DeserializeOwned>(
        response: mvm_http::Response,
        id: &str,
        operation: &str,
    ) -> Result<T> {
        if let Some(error) = status_error(response.status(), id) {
            return Err(error);
        }
        response.json().await.map_err(|error| MvmError::Backend {
            reason: format!("parsing {operation} response: {error}"),
        })
    }

    /// Create a remote tenant volume.
    pub async fn create_remote_volume(
        &self,
        tenant_id: &str,
        request: &RemoteVolumeCreate,
    ) -> Result<RemoteVolume> {
        let url = self.endpoint_components(&["api", "v1", "tenants", tenant_id, "volumes"])?;
        let body = CreateRemoteVolumeBody {
            name: &request.name,
            size_gib: request.size_gib,
            encrypted: true,
            storage_class: request.storage_class.as_deref(),
            from_snapshot_id: request.from_snapshot_id.as_deref(),
            bucket_id: request.bucket_id.as_deref(),
        };
        let response = self
            .authed(self.http.post(url))
            .json(&body)
            .send()
            .await
            .map_err(|error| MvmError::Unavailable {
                reason: format!("remote volume create failed: {error}"),
            })?;
        Self::decode_json(response, &request.name, "remote volume create").await
    }

    /// List all remote volumes visible in a tenant.
    pub async fn list_remote_volumes(&self, tenant_id: &str) -> Result<Vec<RemoteVolume>> {
        let url = self.endpoint_components(&["api", "v1", "tenants", tenant_id, "volumes"])?;
        let response = self
            .authed(self.http.get(url))
            .send()
            .await
            .map_err(|error| MvmError::Unavailable {
                reason: format!("remote volume list failed: {error}"),
            })?;
        Self::decode_json(response, tenant_id, "remote volume list").await
    }

    /// Delete a detached remote volume.
    pub async fn delete_remote_volume(&self, tenant_id: &str, volume_id: &str) -> Result<()> {
        let url =
            self.endpoint_components(&["api", "v1", "tenants", tenant_id, "volumes", volume_id])?;
        let response = self
            .authed(self.http.delete(url))
            .send()
            .await
            .map_err(|error| MvmError::Unavailable {
                reason: format!("remote volume delete failed: {error}"),
            })?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(());
        }
        match status_error(response.status(), volume_id) {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Attach a remote volume through mvmd's exclusive-writer boundary.
    pub async fn attach_remote_volume(
        &self,
        tenant_id: &str,
        request: &RemoteVolumeMount,
    ) -> Result<RemoteVolumeAttachment> {
        let url = self.endpoint_components(&[
            "api",
            "v1",
            "tenants",
            tenant_id,
            "volumes",
            &request.volume_id,
            "attach",
        ])?;
        let body = AttachRemoteVolumeBody {
            instance_id: &request.instance_id,
            device_path: &request.device_path,
            read_only: request.read_only,
        };
        let response = self
            .authed(self.http.post(url))
            .json(&body)
            .send()
            .await
            .map_err(|error| MvmError::Unavailable {
                reason: format!("remote volume attach failed: {error}"),
            })?;
        Self::decode_json(response, &request.volume_id, "remote volume attach").await
    }

    /// Return one remote volume's current attachment.
    pub async fn remote_volume_attachment(
        &self,
        tenant_id: &str,
        volume_id: &str,
    ) -> Result<RemoteVolumeAttachment> {
        let url = self.endpoint_components(&[
            "api", "v1", "tenants", tenant_id, "volumes", volume_id, "attach",
        ])?;
        let response = self
            .authed(self.http.get(url))
            .send()
            .await
            .map_err(|error| MvmError::Unavailable {
                reason: format!("remote attachment read failed: {error}"),
            })?;
        Self::decode_json(response, volume_id, "remote attachment read").await
    }

    /// Detach one remote volume idempotently.
    pub async fn detach_remote_volume(&self, tenant_id: &str, volume_id: &str) -> Result<()> {
        let url = self.endpoint_components(&[
            "api", "v1", "tenants", tenant_id, "volumes", volume_id, "attach",
        ])?;
        let response = self
            .authed(self.http.delete(url))
            .send()
            .await
            .map_err(|error| MvmError::Unavailable {
                reason: format!("remote volume detach failed: {error}"),
            })?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(());
        }
        match status_error(response.status(), volume_id) {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Create an immutable checkpoint for a remote volume.
    pub async fn create_remote_volume_snapshot(
        &self,
        tenant_id: &str,
        volume_id: &str,
        snapshot_name: &str,
    ) -> Result<RemoteVolumeSnapshot> {
        let url = self.endpoint_components(&[
            "api",
            "v1",
            "tenants",
            tenant_id,
            "volumes",
            volume_id,
            "snapshots",
        ])?;
        let response = self
            .authed(self.http.post(url))
            .json(&CreateRemoteSnapshotBody {
                name: snapshot_name,
            })
            .send()
            .await
            .map_err(|error| MvmError::Unavailable {
                reason: format!("remote checkpoint failed: {error}"),
            })?;
        Self::decode_json(response, volume_id, "remote checkpoint").await
    }

    /// Restore a pinned checkpoint into a new remote volume.
    pub async fn restore_remote_volume(
        &self,
        tenant_id: &str,
        source_volume_id: &str,
        snapshot_id: &str,
        target_name: &str,
    ) -> Result<RemoteVolume> {
        let url = self.endpoint_components(&[
            "api",
            "v1",
            "tenants",
            tenant_id,
            "volumes",
            source_volume_id,
            "snapshots",
            snapshot_id,
        ])?;
        let response = self
            .authed(self.http.get(url))
            .send()
            .await
            .map_err(|error| MvmError::Unavailable {
                reason: format!("remote checkpoint lookup failed: {error}"),
            })?;
        let snapshot: RemoteVolumeSnapshot =
            Self::decode_json(response, snapshot_id, "remote checkpoint lookup").await?;
        if snapshot.status != "ready" || snapshot.checkpoint_id.is_empty() {
            return Err(MvmError::Conflict {
                reason: "remote checkpoint is not ready for restore".into(),
            });
        }
        let mut builder = RemoteVolumeCreate::builder(target_name, snapshot.size_gib)
            .from_snapshot(snapshot.snapshot_id);
        if let Some(bucket_id) = snapshot.bucket_id {
            builder = builder.bucket(bucket_id);
        }
        self.create_remote_volume(tenant_id, &builder.build()?)
            .await
    }
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
            ..Default::default()
        }
    }
}

fn filter_machines(machines: Vec<MachineState>, filter: &MachineFilter) -> Vec<MachineState> {
    machines.into_iter().filter(|m| filter.matches(m)).collect()
}

#[async_trait]
impl MvmClient for GatewayBackend {
    async fn backend_capabilities(&self) -> Result<BackendCapabilityReport> {
        // A gateway needs a capability endpoint, not a negotiation one:
        // negotiation is pure, so the caller runs it locally on this answer.
        let url = self.endpoint("/api/v1/backend/capabilities")?;
        let resp = self
            .authed(self.http.get(url))
            .send()
            .await
            .map_err(|e| MvmError::Backend {
                reason: format!("capability request failed: {e}"),
            })?;
        if let Some(e) = status_error(resp.status(), "") {
            return Err(e);
        }
        let report: BackendCapabilityReport = resp.json().await.map_err(|e| MvmError::Backend {
            reason: format!("decode capability report: {e}"),
        })?;
        Ok(report.with_operations(gateway_operations()))
    }

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

    async fn inspect_machine(&self, id: &MachineId) -> Result<MachineState> {
        let url = self.endpoint(&format!("/api/v1/sandboxes/{}", id.0))?;
        let resp = self
            .authed(self.http.get(url))
            .send()
            .await
            .map_err(|e| MvmError::Backend {
                reason: format!("inspect request failed: {e}"),
            })?;
        if let Some(e) = status_error(resp.status(), &id.0) {
            return Err(e);
        }
        let env: SandboxEnvelope = resp.json().await.map_err(|e| MvmError::Backend {
            reason: format!("parsing inspect response: {e}"),
        })?;
        Ok(env.data.into())
    }

    async fn create_machine(&self, _spec: MachineSpec) -> Result<MachineState> {
        // The cloud sandbox model boots on create; there is no
        // create-without-start endpoint. Refuse rather than fake a stopped state.
        Err(MvmError::Backend {
            reason: "gateway sandboxes boot on create; create-without-start is not supported (use run_machine)".into(),
        })
    }

    async fn run_machine(&self, spec: MachineSpec) -> Result<MachineState> {
        // The create-sandbox endpoint has no env field; refuse rather than
        // silently drop env the workload would expect.
        // A campaign declaration names a file on the *host's* filesystem. A
        // remote backend has no access to it, and resolving the path against
        // its own filesystem would run a different campaign than the one the
        // caller wrote — so refuse rather than silently drop or mis-resolve it.
        if spec.assurance_campaign.is_some() {
            return Err(MvmError::InvalidSpec {
                reason: "an assurance campaign declaration is host-local and cannot be run \
                         against a remote backend"
                    .into(),
            });
        }
        if !spec.env.is_empty() {
            return Err(MvmError::InvalidSpec {
                reason: "gateway create-sandbox does not accept env vars; bake them into the image or leave env empty".into(),
            });
        }
        let url = self.endpoint("/api/v1/sandboxes")?;
        // The remote sandbox API names an image with a string. Written form,
        // not a tagged enum: the token the caller declared is the token the
        // remote sees, so the two ends describe one image the same way.
        let image = spec.image.to_string();
        let body = CreateSandboxBody {
            name: &spec.name,
            image: &image,
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

    async fn start_machine(&self, _id: &MachineId) -> Result<MachineState> {
        // Sandboxes boot on create; there is no idle "created" state to start
        // from. Refuse rather than fake a running state.
        Err(MvmError::Backend {
            reason:
                "gateway sandboxes have no separate start; they boot on create (use run_machine)"
                    .into(),
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

    async fn remove_machine(&self, id: &MachineId) -> Result<()> {
        let url = self.endpoint(&format!("/api/v1/sandboxes/{}", id.0))?;
        let resp = self
            .authed(self.http.delete(url))
            .send()
            .await
            .map_err(|e| MvmError::Backend {
                reason: format!("remove request failed: {e}"),
            })?;
        // A 404 means already gone — remove is idempotent.
        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(());
        }
        match status_error(resp.status(), &id.0) {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    async fn pause_machine(&self, _id: &MachineId, _opts: PauseOpts) -> Result<PauseOutcome> {
        // Instance-snapshot pause/resume is a host-local operation (sealing the
        // vmstate + memory under a host key); the gateway exposes no snapshot
        // endpoint. Refuse rather than fake an outcome — remote pause/resume is
        // wired only when a fleet consumer needs it.
        Err(MvmError::Backend {
            reason: "gateway pause is not wired (remote instance snapshot unsupported)".into(),
        })
    }

    async fn resume_machine(&self, _id: &MachineId, _opts: ResumeOpts) -> Result<ResumeOutcome> {
        // Symmetric with `pause_machine`: no remote snapshot restore endpoint yet.
        Err(MvmError::Backend {
            reason: "gateway resume is not wired (remote instance snapshot unsupported)".into(),
        })
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

    async fn exec_machine(
        &self,
        _id: &MachineId,
        _command: Vec<String>,
    ) -> Result<crate::client::dto::ExecResult> {
        // The gateway's exec is a streaming endpoint; buffering it into a single
        // ExecResult is a separate slice, so this is deferred rather than guessed.
        Err(MvmError::Backend {
            reason: "gateway exec is streaming; buffered exec not yet wired".into(),
        })
    }

    async fn reconfigure_machine(
        &self,
        id: &MachineId,
        cfg: ReconfigureRequest,
    ) -> Result<MachineState> {
        let url = self.endpoint(&format!("/api/v1/sandboxes/{}/reconfigure", id.0))?;
        let body = ReconfigureBody {
            net: cfg.net,
            allow_host: cfg.allow_host,
            cpus: cfg.cpus,
            memory_mib: cfg.memory_mib,
        };
        let resp = self
            .authed(self.http.post(url))
            .json(&body)
            .send()
            .await
            .map_err(|e| MvmError::Backend {
                reason: format!("reconfigure request failed: {e}"),
            })?;
        if let Some(e) = status_error(resp.status(), &id.0) {
            return Err(e);
        }
        let env: SandboxEnvelope = resp.json().await.map_err(|e| MvmError::Backend {
            reason: format!("parsing reconfigure response: {e}"),
        })?;
        Ok(env.data.into())
    }

    async fn set_ttl(&self, _id: &MachineId, _expires_at: Option<String>) -> Result<()> {
        // The fleet's TTL lives in its own control plane; this client has no
        // remote TTL endpoint yet. Refuse rather than fake success.
        Err(MvmError::Backend {
            reason: "gateway set-ttl is not wired (no remote TTL endpoint)".into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Once, mpsc};
    use std::time::Duration;

    #[test]
    fn gateway_operation_report_omits_unwired_facade_calls() {
        let operations = gateway_operations();
        assert!(operations.list && operations.inspect && operations.run);
        assert!(operations.stop && operations.remove && operations.logs);
        assert!(operations.reconfigure);
        assert!(!operations.create);
        assert!(!operations.start);
        assert!(!operations.pause);
        assert!(!operations.resume);
        assert!(!operations.exec);
        assert!(!operations.set_ttl);
    }

    fn install_rustls_provider() {
        static INSTALL: Once = Once::new();
        INSTALL.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

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
        install_rustls_provider();
        GatewayConfig {
            base_url: base.into(),
            token: "mvmd_org_deadbeef".into(),
        }
    }

    fn serve_one_json(
        response_body: &'static str,
    ) -> (String, mpsc::Receiver<String>, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (sender, receiver) = mpsc::channel();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            let mut buffer = [0u8; 4096];
            loop {
                let count = stream.read(&mut buffer).unwrap();
                if count == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..count]);
                let Some(header_end) = request.windows(4).position(|part| part == b"\r\n\r\n")
                else {
                    continue;
                };
                let headers = String::from_utf8_lossy(&request[..header_end]);
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .and_then(|value| value.parse::<usize>().ok())
                    })
                    .unwrap_or_default();
                if request.len() >= header_end + 4 + content_length {
                    break;
                }
            }
            sender.send(String::from_utf8(request).unwrap()).unwrap();
            write!(
                stream,
                "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            )
            .unwrap();
        });
        (format!("http://{address}"), receiver, handle)
    }

    #[test]
    fn construction_refuses_cleartext_remote() {
        let err = GatewayBackend::new(cfg("http://fleet.example.com")).unwrap_err();
        assert!(matches!(err, MvmError::Backend { .. }));
    }

    #[test]
    fn construction_accepts_https_and_loopback() {
        install_rustls_provider();
        assert!(GatewayBackend::new(cfg("https://fleet.example.com")).is_ok());
        assert!(GatewayBackend::new(cfg("http://127.0.0.1:9090")).is_ok());
    }

    #[test]
    fn endpoint_join_preserves_guard() {
        install_rustls_provider();
        let be = GatewayBackend::new(cfg("https://fleet.example.com")).unwrap();
        let url = be.endpoint("/api/v1/sandboxes").unwrap();
        assert_eq!(url.as_str(), "https://fleet.example.com/api/v1/sandboxes");
    }

    #[test]
    fn debug_redacts_the_token() {
        install_rustls_provider();
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
                ..Default::default()
            },
            MachineState {
                id: MachineId("2".into()),
                name: "b".into(),
                status: MachineStatus::Stopped,
                ..Default::default()
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
            image: "i".parse().unwrap(),
            cpus: 1,
            memory_mib: 64,
            env: vec![("A".into(), "B".into())],
            grants: None,
            assurance_campaign: None,
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
            status_error(StatusCode::CONFLICT, "m1"),
            Some(MvmError::Conflict { .. })
        ));
        assert!(matches!(
            status_error(StatusCode::UNPROCESSABLE_ENTITY, "m1"),
            Some(MvmError::Rejected { .. })
        ));
        assert!(matches!(
            status_error(StatusCode::SERVICE_UNAVAILABLE, "m1"),
            Some(MvmError::Unavailable { .. })
        ));
        assert!(matches!(
            status_error(StatusCode::INTERNAL_SERVER_ERROR, "m1"),
            Some(MvmError::Backend { .. })
        ));
    }

    #[test]
    fn reconfigure_targets_the_reconfigure_endpoint() {
        install_rustls_provider();
        let be = GatewayBackend::new(GatewayConfig {
            base_url: "https://fleet.example.com".into(),
            token: "t".into(),
        })
        .unwrap();
        let url = be.endpoint("/api/v1/sandboxes/abc/reconfigure").unwrap();
        assert_eq!(
            url.as_str(),
            "https://fleet.example.com/api/v1/sandboxes/abc/reconfigure"
        );
    }

    #[tokio::test]
    async fn pause_and_resume_fail_closed_until_wired() {
        install_rustls_provider();
        let be = GatewayBackend::new(cfg("https://fleet.example.com")).unwrap();
        let id = MachineId("sbx-1".into());
        // No request is sent — the stub refuses before touching the network.
        assert!(matches!(
            be.pause_machine(&id, PauseOpts::default()).await,
            Err(MvmError::Backend { .. })
        ));
        assert!(matches!(
            be.resume_machine(&id, ResumeOpts::default()).await,
            Err(MvmError::Backend { .. })
        ));
    }

    #[test]
    fn reconfigure_body_serializes_only_set_fields() {
        let body = ReconfigureBody {
            net: Some(true),
            allow_host: None,
            cpus: Some(2),
            memory_mib: None,
        };
        let json = serde_json::to_string(&body).unwrap();
        assert_eq!(json, r#"{"net":true,"cpus":2}"#);
    }

    #[test]
    fn remote_volume_path_components_are_encoded() {
        install_rustls_provider();
        let backend = GatewayBackend::new(cfg("https://fleet.example.com")).unwrap();
        let url = backend
            .endpoint_components(&["api", "v1", "tenants", "tenant/escape", "volumes"])
            .unwrap();
        assert_eq!(
            url.as_str(),
            "https://fleet.example.com/api/v1/tenants/tenant%2Fescape/volumes"
        );
    }

    #[test]
    fn remote_volume_create_builder_validates_and_omits_absent_fields() {
        assert!(RemoteVolumeCreate::builder("data", 0).build().is_err());
        let request = RemoteVolumeCreate::builder("data", 4).build().unwrap();
        let body = CreateRemoteVolumeBody {
            name: &request.name,
            size_gib: request.size_gib,
            encrypted: true,
            storage_class: request.storage_class.as_deref(),
            from_snapshot_id: request.from_snapshot_id.as_deref(),
            bucket_id: request.bucket_id.as_deref(),
        };
        assert_eq!(
            serde_json::to_string(&body).unwrap(),
            r#"{"name":"data","size_gib":4,"encrypted":true}"#
        );
    }

    #[test]
    fn remote_volume_response_is_backward_compatible() {
        let volume: RemoteVolume = serde_json::from_str(
            r#"{"volume_id":"vol-1","tenant_id":"tenant-1","name":"data","size_gib":8}"#,
        )
        .unwrap();
        assert_eq!(volume.volume_id, "vol-1");
        assert!(volume.bucket_id.is_none());
        assert!(volume.attached_instance_id.is_none());
    }

    #[tokio::test]
    async fn remote_volume_create_sends_authenticated_tenant_request() {
        install_rustls_provider();
        let response = r#"{"volume_id":"vol-1","tenant_id":"tenant-a","name":"data","size_gib":8,"bucket_id":"bucket-1"}"#;
        let (base_url, request_receiver, server) = serve_one_json(response);
        let backend = GatewayBackend::new(GatewayConfig {
            base_url,
            token: "secret-bearer".into(),
        })
        .unwrap();
        let request = RemoteVolumeCreate::builder("data", 8)
            .bucket("bucket-1")
            .build()
            .unwrap();

        let volume = backend
            .create_remote_volume("tenant-a", &request)
            .await
            .unwrap();
        assert_eq!(volume.volume_id, "vol-1");
        let raw_request = request_receiver
            .recv_timeout(Duration::from_secs(5))
            .unwrap();
        assert!(raw_request.starts_with("POST /api/v1/tenants/tenant-a/volumes HTTP/1.1"));
        assert!(raw_request.contains("authorization: Bearer secret-bearer"));
        assert!(raw_request.contains(r#""bucket_id":"bucket-1""#));
        server.join().unwrap();
    }
}
