//! The canonical host-wide machine inventory contract.
//!
//! One typed record unifies the two stores that describe a microVM — the
//! persisted machine-spec registry and the live backend listing — so the CLI
//! and non-CLI consumers (local UIs, SDK facades) read identical semantics
//! instead of each assembling their own join. Like the rest of the client
//! DTOs, the record is REST-satisfiable plain data and carries **no host key
//! material, no secret values, and no host filesystem paths**: volume
//! attachments are summarized by guest mount only, and secrets appear only as
//! a count of references.
//!
//! The join itself needs the runtime's persisted spec type, so it lives one
//! crate up in `mvm-client`'s `inventory` module; this module owns the wire
//! shape and the visibility semantics both sides share.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::dto::{MachineId, MachineStatus, PortMapping};
use crate::domain::instance::InstanceReadiness;

/// Where a listed microVM's definition lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MachineKind {
    /// Backed by a persisted spec: survives a stop, restartable by name.
    Persistent,
    /// Live only. It leaves nothing behind once it exits.
    Transient,
}

impl MachineKind {
    /// The snake_case wire/display label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Persistent => "persistent",
            Self::Transient => "transient",
        }
    }
}

/// Fail-closed dev/prod workload posture.
///
/// Only an explicit `"dev"` is ever dev; a missing, unknown, or malformed
/// posture is production, so a stale or hostile record can never *open* a
/// dev-only path — it can only keep it shut. Deserialization enforces the
/// same rule: any string other than `"dev"` becomes [`WorkloadPosture::Prod`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadPosture {
    Dev,
    #[default]
    Prod,
}

impl WorkloadPosture {
    /// Resolve a posture label fail-closed: exactly `"dev"` is dev,
    /// everything else — including unknown labels — is prod.
    pub fn from_label(label: &str) -> Self {
        if label == "dev" {
            Self::Dev
        } else {
            Self::Prod
        }
    }

    /// The snake_case wire/display label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Dev => "dev",
            Self::Prod => "prod",
        }
    }

    /// Whether dev-only paths (interactive exec, console) may open.
    pub fn is_dev(self) -> bool {
        matches!(self, Self::Dev)
    }
}

impl<'de> Deserialize<'de> for WorkloadPosture {
    // Hand-rolled so an unknown posture value deserializes fail-closed to
    // `Prod` instead of failing the whole record or — worse — being mapped
    // to dev by a permissive consumer.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let label = String::deserialize(deserializer)?;
        Ok(Self::from_label(&label))
    }
}

/// How a summarized volume is attached to the guest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VolumeAttachmentKind {
    /// Live host-directory share (virtio-fs).
    DirShare,
    /// Persistent disk image (virtio-blk).
    Disk,
}

/// A machine's volume attachment, summarized for listing. Deliberately omits
/// the host-side path — the inventory record never carries host filesystem
/// locations; `machine inspect` remains the place to see the full spec.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VolumeAttachment {
    /// Guest mount point (or attach target) of the volume.
    pub guest_mount: String,
    pub kind: VolumeAttachmentKind,
    pub read_only: bool,
    /// Whether the disk volume is routed through in-guest encryption.
    #[serde(default)]
    pub encrypted: bool,
}

/// One machine in the unified host inventory: the typed join of a persisted
/// spec (when one exists) and the live backend state (when booted).
///
/// Field notes:
/// - `build_mode` keeps that wire name (not "posture") because SDK facades
///   already parse `build_mode` out of the machine listing to gate the
///   dev-only exec path; it deserializes fail-closed (see
///   [`WorkloadPosture`]) and defaults to prod when absent.
/// - `secret_ref_count` is a count of secret *references* only. Secret
///   values, key material, and host paths never ride in this record.
/// - Optional fields default so an older serialized record still loads;
///   unknown fields fail closed like every other client DTO.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineInventoryRecord {
    /// Stable identity: the live backend id when booted, else the machine
    /// name (which is the registry identity of a non-booted definition).
    pub id: MachineId,
    pub name: String,
    pub kind: MachineKind,
    pub status: MachineStatus,
    /// Free-text detail behind a non-happy `status` (e.g. a failure reason).
    #[serde(default)]
    pub status_detail: Option<String>,
    /// Fail-closed dev/prod posture; wire name kept for SDK compatibility.
    #[serde(default)]
    pub build_mode: WorkloadPosture,
    /// What the machine was made from: the spec's image/manifest reference
    /// for a persistent machine, the backend's flake ref/profile otherwise.
    #[serde(default)]
    pub source: Option<String>,
    /// Backend that owns the live VM (e.g. `"firecracker"`). `None` when
    /// not booted.
    #[serde(default)]
    pub backend: Option<String>,
    /// vCPU count. `0` when unknown.
    #[serde(default)]
    pub cpus: u32,
    /// Guest memory in MiB. `0` when unknown.
    #[serde(default)]
    pub memory_mib: u32,
    /// Finer-grained host-observed readiness, when tracked.
    #[serde(default)]
    pub readiness: Option<InstanceReadiness>,
    /// Active host:guest port forwardings.
    #[serde(default)]
    pub ports: Vec<PortMapping>,
    /// Caller-supplied metadata tags.
    #[serde(default)]
    pub tags: BTreeMap<String, String>,
    /// RFC 3339 TTL expiry, when set.
    #[serde(default)]
    pub expires_at: Option<String>,
    /// RFC 3339 creation time of the persistent definition, when recorded.
    #[serde(default)]
    pub created_at: Option<String>,
    /// RFC 3339 time of the last lifecycle start, when recorded.
    #[serde(default)]
    pub last_started_at: Option<String>,
    /// Volume attachments, summarized without host paths.
    #[serde(default)]
    pub volumes: Vec<VolumeAttachment>,
    /// Number of secret references bound to this machine. A count only —
    /// never names-with-values, never the values themselves.
    #[serde(default)]
    pub secret_ref_count: u32,
}

impl MachineInventoryRecord {
    /// Start building a record. `name` and `kind` are required; everything
    /// else defaults to the fail-closed empty shape (stopped, prod posture,
    /// no live detail) and is overridable on the returned builder.
    pub fn builder(name: impl Into<String>, kind: MachineKind) -> MachineInventoryRecordBuilder {
        let name = name.into();
        MachineInventoryRecordBuilder {
            record: MachineInventoryRecord {
                id: MachineId(name.clone()),
                name,
                kind,
                status: MachineStatus::Stopped,
                status_detail: None,
                build_mode: WorkloadPosture::Prod,
                source: None,
                backend: None,
                cpus: 0,
                memory_mib: 0,
                readiness: None,
                ports: Vec::new(),
                tags: BTreeMap::new(),
                expires_at: None,
                created_at: None,
                last_started_at: None,
                volumes: Vec::new(),
                secret_ref_count: 0,
            },
        }
    }

    /// Whether the machine's TTL has elapsed at `now`. A missing or
    /// unparseable `expires_at` is "no TTL" (never expired).
    pub fn is_expired(&self, now: chrono::DateTime<chrono::Utc>) -> bool {
        self.expires_at
            .as_deref()
            .and_then(crate::util::time::parse_iso8601)
            .map(|t| t < now)
            .unwrap_or(false)
    }
}

/// Fluent builder for [`MachineInventoryRecord`]; obtain one from
/// [`MachineInventoryRecord::builder`]. `build` is infallible — the required
/// identity fields were supplied up front and every other field has a safe
/// fail-closed default.
#[derive(Debug, Clone)]
pub struct MachineInventoryRecordBuilder {
    record: MachineInventoryRecord,
}

impl MachineInventoryRecordBuilder {
    /// Override the stable id (defaults to the machine name).
    #[must_use]
    pub fn id(mut self, id: MachineId) -> Self {
        self.record.id = id;
        self
    }

    #[must_use]
    pub fn status(mut self, status: MachineStatus) -> Self {
        self.record.status = status;
        self
    }

    #[must_use]
    pub fn status_detail(mut self, detail: impl Into<String>) -> Self {
        self.record.status_detail = Some(detail.into());
        self
    }

    #[must_use]
    pub fn build_mode(mut self, posture: WorkloadPosture) -> Self {
        self.record.build_mode = posture;
        self
    }

    #[must_use]
    pub fn source(mut self, source: Option<String>) -> Self {
        self.record.source = source;
        self
    }

    #[must_use]
    pub fn backend(mut self, backend: Option<String>) -> Self {
        self.record.backend = backend;
        self
    }

    #[must_use]
    pub fn cpus(mut self, cpus: u32) -> Self {
        self.record.cpus = cpus;
        self
    }

    #[must_use]
    pub fn memory_mib(mut self, memory_mib: u32) -> Self {
        self.record.memory_mib = memory_mib;
        self
    }

    #[must_use]
    pub fn readiness(mut self, readiness: Option<InstanceReadiness>) -> Self {
        self.record.readiness = readiness;
        self
    }

    #[must_use]
    pub fn ports(mut self, ports: Vec<PortMapping>) -> Self {
        self.record.ports = ports;
        self
    }

    #[must_use]
    pub fn tags(mut self, tags: BTreeMap<String, String>) -> Self {
        self.record.tags = tags;
        self
    }

    #[must_use]
    pub fn expires_at(mut self, expires_at: Option<String>) -> Self {
        self.record.expires_at = expires_at;
        self
    }

    #[must_use]
    pub fn created_at(mut self, created_at: Option<String>) -> Self {
        self.record.created_at = created_at;
        self
    }

    #[must_use]
    pub fn last_started_at(mut self, last_started_at: Option<String>) -> Self {
        self.record.last_started_at = last_started_at;
        self
    }

    #[must_use]
    pub fn volumes(mut self, volumes: Vec<VolumeAttachment>) -> Self {
        self.record.volumes = volumes;
        self
    }

    #[must_use]
    pub fn secret_ref_count(mut self, count: u32) -> Self {
        self.record.secret_ref_count = count;
        self
    }

    /// Finish building. Infallible — identity was required up front.
    #[must_use]
    pub fn build(self) -> MachineInventoryRecord {
        self.record
    }
}

/// Visibility query over the inventory. The default is the *active*
/// inventory: a persistent definition always lists (stopped or not — it
/// exists whether or not it is booted, and hiding it would lose the only
/// record of it), while a stopped transient machine is leftover state and
/// stays hidden unless explicitly included. Expired machines are hidden
/// until asked for; tag constraints must all match.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryQuery {
    /// Include transient machines that are no longer running.
    #[serde(default)]
    pub include_stopped_transient: bool,
    /// Include machines whose TTL has elapsed but that are not yet reaped.
    #[serde(default)]
    pub include_expired: bool,
    /// Tag constraints; every `key=value` pair must match the record's tags.
    #[serde(default)]
    pub tags: BTreeMap<String, String>,
}

impl InventoryQuery {
    /// The default active inventory (stopped transients and expired hidden).
    pub fn active() -> Self {
        Self::default()
    }

    /// Everything, including stopped transients and expired machines.
    pub fn all() -> Self {
        Self {
            include_stopped_transient: true,
            include_expired: true,
            tags: BTreeMap::new(),
        }
    }

    /// Whether `record` is visible under this query at `now`.
    ///
    /// Only [`MachineStatus::Stopped`] counts as "no longer running" — a
    /// paused or failed machine stays visible by default so its state is
    /// observable rather than silently folding away.
    pub fn matches(
        &self,
        record: &MachineInventoryRecord,
        now: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        let stopped = record.status == MachineStatus::Stopped;
        if !self.include_stopped_transient && record.kind == MachineKind::Transient && stopped {
            return false;
        }
        let tags_match = self
            .tags
            .iter()
            .all(|(k, v)| record.tags.get(k).map(String::as_str) == Some(v.as_str()));
        if !tags_match {
            return false;
        }
        if !self.include_expired && record.is_expired(now) {
            return false;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> chrono::DateTime<chrono::Utc> {
        crate::util::time::parse_iso8601("2026-07-31T12:00:00Z").unwrap()
    }

    fn full_record() -> MachineInventoryRecord {
        MachineInventoryRecord::builder("web", MachineKind::Persistent)
            .id(MachineId("m1".into()))
            .status(MachineStatus::Failed)
            .status_detail("boom")
            .build_mode(WorkloadPosture::Dev)
            .source(Some("alpine:latest".into()))
            .backend(Some("firecracker".into()))
            .cpus(2)
            .memory_mib(512)
            .readiness(Some(InstanceReadiness::AgentReady))
            .ports(vec![PortMapping {
                host: 8080,
                guest: 80,
            }])
            .tags(BTreeMap::from([("env".to_string(), "prod".to_string())]))
            .expires_at(Some("2099-01-01T00:00:00Z".into()))
            .created_at(Some("2026-07-01T00:00:00Z".into()))
            .last_started_at(Some("2026-07-02T00:00:00Z".into()))
            .volumes(vec![VolumeAttachment {
                guest_mount: "/data".into(),
                kind: VolumeAttachmentKind::Disk,
                read_only: false,
                encrypted: true,
            }])
            .secret_ref_count(3)
            .build()
    }

    #[test]
    fn record_serde_round_trips_with_all_fields() {
        let record = full_record();
        let json = serde_json::to_string(&record).unwrap();
        let back: MachineInventoryRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, back);
    }

    #[test]
    fn minimal_record_deserializes_with_fail_closed_defaults() {
        // Only the identity fields present: every added field must fall back
        // to its default — and the posture default must be prod, never dev.
        let json = r#"{"id":"m1","name":"web","kind":"transient","status":"running"}"#;
        let record: MachineInventoryRecord = serde_json::from_str(json).unwrap();
        assert_eq!(record.kind, MachineKind::Transient);
        assert_eq!(record.build_mode, WorkloadPosture::Prod);
        assert!(record.status_detail.is_none());
        assert!(record.volumes.is_empty());
        assert_eq!(record.secret_ref_count, 0);
        assert!(record.tags.is_empty());
    }

    #[test]
    fn record_rejects_unknown_field_fail_closed() {
        let json = r#"{"id":"m1","name":"web","kind":"transient","status":"running","rogue":1}"#;
        assert!(serde_json::from_str::<MachineInventoryRecord>(json).is_err());
    }

    #[test]
    fn record_never_carries_secret_or_host_path_shaped_fields() {
        // The wire shape must not grow value-bearing or host-path fields;
        // pin the serialized key set so an accidental addition is loud.
        let value = serde_json::to_value(full_record()).unwrap();
        let keys: Vec<&str> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        for forbidden in ["secret", "secrets", "host_path", "rootfs", "key"] {
            assert!(
                !keys.contains(&forbidden),
                "forbidden key {forbidden:?} in {keys:?}"
            );
        }
        // The volume summary carries the guest mount only.
        let volume = &value["volumes"][0];
        assert!(volume.get("host").is_none() && volume.get("host_path").is_none());
    }

    #[test]
    fn posture_deserializes_fail_closed() {
        // Explicit dev stays dev; prod stays prod.
        assert_eq!(
            serde_json::from_str::<WorkloadPosture>("\"dev\"").unwrap(),
            WorkloadPosture::Dev
        );
        assert_eq!(
            serde_json::from_str::<WorkloadPosture>("\"prod\"").unwrap(),
            WorkloadPosture::Prod
        );
        // Unknown / malformed labels are production, never dev.
        for unknown in ["\"debug\"", "\"DEV\"", "\"\"", "\"development\""] {
            assert_eq!(
                serde_json::from_str::<WorkloadPosture>(unknown).unwrap(),
                WorkloadPosture::Prod,
                "label {unknown} must fail closed to prod"
            );
        }
    }

    #[test]
    fn posture_labels_round_trip_and_default_is_prod() {
        assert_eq!(WorkloadPosture::default(), WorkloadPosture::Prod);
        assert_eq!(WorkloadPosture::from_label("dev"), WorkloadPosture::Dev);
        assert_eq!(WorkloadPosture::from_label("weird"), WorkloadPosture::Prod);
        assert_eq!(WorkloadPosture::Dev.label(), "dev");
        assert_eq!(WorkloadPosture::Prod.label(), "prod");
        assert!(WorkloadPosture::Dev.is_dev());
        assert!(!WorkloadPosture::Prod.is_dev());
        // Serialized form matches the label, so round-trips are stable.
        assert_eq!(
            serde_json::to_string(&WorkloadPosture::Dev).unwrap(),
            "\"dev\""
        );
    }

    #[test]
    fn kind_serde_is_snake_case_and_labels_match() {
        assert_eq!(
            serde_json::to_string(&MachineKind::Persistent).unwrap(),
            "\"persistent\""
        );
        assert_eq!(MachineKind::Persistent.label(), "persistent");
        assert_eq!(MachineKind::Transient.label(), "transient");
    }

    #[test]
    fn volume_attachment_serde_round_trips_and_rejects_unknown_fields() {
        let attachment = VolumeAttachment {
            guest_mount: "/data".into(),
            kind: VolumeAttachmentKind::DirShare,
            read_only: true,
            encrypted: false,
        };
        let json = serde_json::to_string(&attachment).unwrap();
        assert_eq!(
            serde_json::from_str::<VolumeAttachment>(&json).unwrap(),
            attachment
        );
        assert!(
            serde_json::from_str::<VolumeAttachment>(
                r#"{"guest_mount":"/d","kind":"disk","read_only":false,"host":"/tmp"}"#
            )
            .is_err(),
            "a host-path-shaped field must be rejected"
        );
    }

    #[test]
    fn query_serde_round_trips_defaults_and_rejects_unknown_fields() {
        let query: InventoryQuery = serde_json::from_str("{}").unwrap();
        assert_eq!(query, InventoryQuery::active());
        let all = InventoryQuery::all();
        let json = serde_json::to_string(&all).unwrap();
        assert_eq!(serde_json::from_str::<InventoryQuery>(&json).unwrap(), all);
        assert!(serde_json::from_str::<InventoryQuery>(r#"{"rogue":true}"#).is_err());
    }

    fn record(kind: MachineKind, status: MachineStatus) -> MachineInventoryRecord {
        MachineInventoryRecord::builder("m", kind)
            .status(status)
            .build()
    }

    #[test]
    fn stopped_persistent_definition_stays_visible_by_default() {
        let stopped = record(MachineKind::Persistent, MachineStatus::Stopped);
        assert!(InventoryQuery::active().matches(&stopped, now()));
    }

    #[test]
    fn stopped_transient_is_hidden_unless_included() {
        let stopped = record(MachineKind::Transient, MachineStatus::Stopped);
        assert!(!InventoryQuery::active().matches(&stopped, now()));
        assert!(InventoryQuery::all().matches(&stopped, now()));
    }

    #[test]
    fn paused_failed_and_running_transients_stay_visible_by_default() {
        for status in [
            MachineStatus::Paused,
            MachineStatus::Failed,
            MachineStatus::Running,
            MachineStatus::Starting,
        ] {
            let r = record(MachineKind::Transient, status);
            assert!(
                InventoryQuery::active().matches(&r, now()),
                "{status:?} must stay visible"
            );
        }
    }

    #[test]
    fn expired_machine_is_hidden_unless_included() {
        let expired = MachineInventoryRecord::builder("m", MachineKind::Transient)
            .status(MachineStatus::Running)
            .expires_at(Some("2026-07-31T11:00:00Z".into()))
            .build();
        assert!(!InventoryQuery::active().matches(&expired, now()));
        let show = InventoryQuery {
            include_expired: true,
            ..InventoryQuery::active()
        };
        assert!(show.matches(&expired, now()));
    }

    #[test]
    fn unparseable_expiry_is_never_expired() {
        let r = MachineInventoryRecord::builder("m", MachineKind::Transient)
            .status(MachineStatus::Running)
            .expires_at(Some("not-a-date".into()))
            .build();
        assert!(!r.is_expired(now()));
        assert!(InventoryQuery::active().matches(&r, now()));
    }

    #[test]
    fn tag_constraints_must_all_match() {
        let mut r = record(MachineKind::Transient, MachineStatus::Running);
        r.tags.insert("env".into(), "prod".into());

        let mut query = InventoryQuery::active();
        query.tags.insert("env".into(), "prod".into());
        assert!(query.matches(&r, now()));

        query.tags.insert("team".into(), "core".into());
        assert!(!query.matches(&r, now()), "a missing tag drops the record");

        let mut wrong = InventoryQuery::active();
        wrong.tags.insert("env".into(), "dev".into());
        assert!(!wrong.matches(&r, now()), "a mismatched value drops it");
    }
}
