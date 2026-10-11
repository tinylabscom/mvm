//! The machine-readable host-ABI contract: one registry row per dotted
//! method.
//!
//! This registry is the single source of truth the SDK stub generators read.
//! `emit_host_abi_schema` renders every row's request and reply types into
//! one JSON Schema document; `emit_host_abi_methods` renders the method
//! table (dotted name, schema key, classification, summary). The language
//! bindings consume the generated stubs, so no binding hand-maintains a
//! method list, and a method added here reaches both SDKs on the next
//! `cargo xtask gen-stubs`.
//!
//! The registry must name exactly the methods the library answers at
//! runtime; the unit tests below hold the two lists to each other.

use mvm_agentd::vsock::{FsStat, ProcInfo};
use mvm_core::client::dto::{MachineFilter, MachineState, PauseOutcome, ResumeOutcome};
use serde::Serialize;

use crate::dispatch::{
    BACKEND_CAPABILITIES, Empty as DispatchEmpty, ExecReply, ExecRequest, LogsReply, LogsRequest,
    MACHINE_EXEC, MACHINE_INSPECT, MACHINE_INVENTORY, MACHINE_LIST, MACHINE_LOGS, MACHINE_PAUSE,
    MACHINE_RECONFIGURE, MACHINE_RESUME, MACHINE_RM, MACHINE_SET_TTL, MACHINE_START, MACHINE_STOP,
    MachineRef, PauseRequest, ReconfigurePatchRequest, RemoveRequest as DispatchRemoveRequest,
    ResumeRequest, SetTtlRequest, StopRequest, TELEMETRY_RECORDS, TELEMETRY_STATUS,
    TelemetryRecordsRequest,
};
use crate::entrypoint::{
    ENTRYPOINT_CALL, EntrypointCallReply, EntrypointCallRequest, MACHINE_PROMPT,
    MachinePromptReply, MachinePromptRequest, SESSION_CALL, SESSION_INFO, SESSION_START,
    SESSION_STOP, SessionCallRequest, SessionInfoReply, SessionRef, SessionStartReply,
    SessionStartRequest,
};
use crate::guest::{
    AcceptedReply, CP, CopyRequest, DataReply, FS_LIST, FS_MKDIR, FS_READ, FS_REMOVE, FS_RENAME,
    FS_STAT, FS_WRITE, ListReply, MachineRequest, MkdirRequest, PROC_KILL, PROC_LIST, PROC_SIGNAL,
    PROC_START, PROC_STDIN, PROC_WAIT, PathRequest, ProcessRequest, ReadRequest, RemoveRequest,
    RemovedReply, RenameRequest, SignalRequest, StartRequest, StartedReply, StatRequest,
    StdinRequest, WaitReply, WaitRequest, WriteRequest, WrittenReply,
};
use crate::launch::{CreateRequest, MACHINE_CREATE, MACHINE_RUN, RunReply, RunRequest};
use crate::manifest::{INFO as MANIFEST_INFO, LIST as MANIFEST_LIST, VERIFY as MANIFEST_VERIFY};
use crate::stream::{
    CloseRequest, Empty as StreamEmpty, LOGS_CLOSE, LOGS_NEXT, LOGS_OPEN, LogsOpenRequest,
    NextReply, NextRequest, OpenReply, OpenRequest, STREAM_CLOSE, STREAM_NEXT, STREAM_OPEN,
};

/// How a method is classified for admission policy. `DevOnly` methods are
/// the guest-agent verbs a sealed image refuses; the classification travels
/// with the generated table so a binding can say why a refusal happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Classification {
    /// Safe to offer on a production-admitted machine.
    ProdSafe,
    /// Development-only guest-agent verb.
    DevOnly,
}

/// A type's JSON Schema root plus the `$ref` definitions it names. Kept
/// split so the emitter can merge every row's definitions into one document
/// and rewrite nothing.
#[derive(Debug)]
pub struct SchemaAndDefs {
    /// The schema root: inline for primitive shapes, `$ref` for named ones.
    pub root: serde_json::Value,
    /// `(name, schema)` pairs this root references.
    pub defs: Vec<(String, serde_json::Value)>,
}

/// The schema of `T`, split into root and definitions.
fn schema_of<T: schemars::JsonSchema>() -> SchemaAndDefs {
    let schema = schemars::schema_for!(T);
    let defs = schema
        .definitions
        .iter()
        .map(|(name, def)| {
            (
                name.clone(),
                serde_json::to_value(def).expect("a schema definition always serializes"),
            )
        })
        .collect();
    let mut root = serde_json::to_value(&schema).expect("a generated schema always serializes");
    if let Some(obj) = root.as_object_mut() {
        // Definitions merge into the document's own map; keeping a copy on
        // every root would fight the merge.
        obj.remove("definitions");
        obj.remove("$schema");
    }
    SchemaAndDefs { root, defs }
}

/// The schema of a homogeneous array of `T`.
fn array_of<T: schemars::JsonSchema>() -> SchemaAndDefs {
    let item = schema_of::<T>();
    SchemaAndDefs {
        root: serde_json::json!({ "type": "array", "items": item.root }),
        defs: item.defs,
    }
}

/// One dotted method, its wire types, and its classification.
#[derive(Debug)]
pub struct MethodDef {
    /// The dotted name a call carries (`machine.list`).
    pub name: &'static str,
    /// The identifier-safe key the generated stubs use (`machine_list`).
    pub key: &'static str,
    /// One-line description, rendered as the generated constant's doc.
    pub summary: &'static str,
    /// Admission classification.
    pub classification: Classification,
    /// The request schema.
    pub request: fn() -> SchemaAndDefs,
    /// The reply schema.
    pub reply: fn() -> SchemaAndDefs,
}

/// The report behind `backend.capabilities` is owned by the capability
/// negotiation module; it is deliberately not re-modeled here, so the ABI
/// schema stays small and the two cannot drift. A binding reads the reply
/// as untyped JSON.
fn any_json() -> SchemaAndDefs {
    // An untyped object rather than the boolean `true` schema: the pinned
    // datamodel-codegen version cannot parse a boolean subschema, and an
    // unbounded object is the honest shape for an opaque report.
    SchemaAndDefs {
        root: serde_json::json!({
            "type": "object",
            "description": "Opaque report; the shape is owned by the capability negotiation module.",
        }),
        defs: Vec::new(),
    }
}

/// The records behind `machine.inventory` are owned by the client inventory
/// module and read as untyped JSON, like the capability report: re-modeling
/// them here would be a second definition that could drift.
fn inventory_records() -> SchemaAndDefs {
    SchemaAndDefs {
        root: serde_json::json!({
            "type": "array",
            "items": {
                "type": "object",
                "description": "A machine inventory record; the shape is owned by the client inventory module. `name` and `build_mode` (`dev` or `prod`) are always present.",
            },
        }),
        defs: Vec::new(),
    }
}

/// The status behind `telemetry.status` is owned by the telemetry contract
/// (`mvm_core::protocol::telemetry::served`) and read as untyped JSON, like
/// the capability report: a tagged object whose `collection` is
/// `not_provisioned` or `provisioned`.
fn telemetry_status() -> SchemaAndDefs {
    SchemaAndDefs {
        root: serde_json::json!({
            "type": "object",
            "description": "A TelemetryStatus; the shape is owned by the telemetry contract. `collection` is always present: `not_provisioned`, or `provisioned` with `vm_name`, `state` (`kind`: connecting | collecting | degraded | stopped), `shed`, `records_bytes`, and `snapshot_age_ms` when known.",
        }),
        defs: Vec::new(),
    }
}

/// The page behind `telemetry.records`, likewise owned by the telemetry
/// contract: `records` (each `record` with its `received_at_ms`),
/// `next_cursor`, `undecodable`, and `exhausted`.
fn telemetry_page() -> SchemaAndDefs {
    SchemaAndDefs {
        root: serde_json::json!({
            "type": "object",
            "description": "A TelemetryReadResponse; the shape is owned by the telemetry contract. `records`, `next_cursor` (`offset`), `undecodable`, and `exhausted` are always present.",
        }),
        defs: Vec::new(),
    }
}

/// The persisted manifest and snapshot retain their client-owned report shape.
fn manifest_info() -> SchemaAndDefs {
    SchemaAndDefs {
        root: serde_json::json!({
            "type": "object",
            "required": ["slot_hash", "persisted", "snapshot"],
            "properties": {
                "slot_hash": {"type": "string"},
                "persisted": {
                    "type": "object",
                    "description": "PersistedManifest report owned by mvm-core."
                },
                "snapshot": {
                    "type": ["object", "null"],
                    "description": "Optional SnapshotInfo report owned by mvm-core."
                }
            },
            "additionalProperties": false
        }),
        defs: Vec::new(),
    }
}

/// Every method the ABI answers, in dotted-name order within each family.
pub const REGISTRY: &[MethodDef] = &[
    MethodDef {
        name: "agent_sessions.list",
        key: "agent_sessions_list",
        summary: "Lists durable local agent sessions.",
        classification: Classification::DevOnly,
        request: schema_of::<mvm_client::checkpoint::wire::Empty>,
        reply: array_of::<mvm_client::agent_sessions::SessionReport>,
    },
    MethodDef {
        name: "agent_sessions.show",
        key: "agent_sessions_show",
        summary: "Reads a durable agent session.",
        classification: Classification::DevOnly,
        request: schema_of::<crate::agent_sessions::ShowRequest>,
        reply: schema_of::<mvm_client::agent_sessions::SessionReport>,
    },
    MethodDef {
        name: "agent_sessions.open",
        key: "agent_sessions_open",
        summary: "Records a durable agent session with explicit execution intent.",
        classification: Classification::DevOnly,
        request: schema_of::<
            mvm_client::checkpoint::wire::Mutation<mvm_client::agent_sessions::OpenRequest>,
        >,
        reply: schema_of::<mvm_client::agent_sessions::SessionReport>,
    },
    MethodDef {
        name: "agent_sessions.park",
        key: "agent_sessions_park",
        summary: "Parks a durable agent session.",
        classification: Classification::DevOnly,
        request: schema_of::<
            mvm_client::checkpoint::wire::Mutation<mvm_client::agent_sessions::ParkRequest>,
        >,
        reply: schema_of::<mvm_client::agent_sessions::TransitionReport>,
    },
    MethodDef {
        name: "agent_sessions.renew",
        key: "agent_sessions_renew",
        summary: "Renews a parked durable agent session.",
        classification: Classification::DevOnly,
        request: schema_of::<
            mvm_client::checkpoint::wire::Mutation<mvm_client::agent_sessions::RenewRequest>,
        >,
        reply: schema_of::<mvm_client::agent_sessions::TransitionReport>,
    },
    MethodDef {
        name: "agent_sessions.resume",
        key: "agent_sessions_resume",
        summary: "Re-admits a durable agent session using the configured host signer.",
        classification: Classification::DevOnly,
        request: schema_of::<
            mvm_client::checkpoint::wire::Mutation<mvm_client::agent_sessions::ResumeRequest>,
        >,
        reply: schema_of::<mvm_client::agent_sessions::TransitionReport>,
    },
    MethodDef {
        name: "checkpoints.list",
        key: "checkpoints_list",
        summary: "Lists the local checkpoint catalog.",
        classification: Classification::DevOnly,
        request: schema_of::<mvm_client::checkpoint::wire::Empty>,
        reply: array_of::<mvm_core::checkpoint::CheckpointMeta>,
    },
    MethodDef {
        name: "checkpoints.info",
        key: "checkpoints_info",
        summary: "Reads checkpoint metadata.",
        classification: Classification::DevOnly,
        request: schema_of::<mvm_client::checkpoint::wire::IdRequest>,
        reply: schema_of::<mvm_core::checkpoint::CheckpointMeta>,
    },
    MethodDef {
        name: "checkpoints.diff",
        key: "checkpoints_diff",
        summary: "Compares checkpoint manifests without decrypting content.",
        classification: Classification::DevOnly,
        request: schema_of::<mvm_client::checkpoint::wire::DiffRequest>,
        reply: schema_of::<mvm_client::checkpoint::CheckpointDiff>,
    },
    MethodDef {
        name: "checkpoints.verify",
        key: "checkpoints_verify",
        summary: "Verifies checkpoint lineage against the signed audit chain.",
        classification: Classification::DevOnly,
        request: schema_of::<mvm_client::checkpoint::wire::IdRequest>,
        reply: schema_of::<mvm_client::checkpoint::wire::Empty>,
    },
    MethodDef {
        name: "checkpoints.timeline",
        key: "checkpoints_timeline",
        summary: "Reads a checkpoint or image lineage timeline.",
        classification: Classification::DevOnly,
        request: schema_of::<mvm_client::checkpoint::wire::TimelineRequest>,
        reply: schema_of::<mvm_client::checkpoint::Timeline>,
    },
    MethodDef {
        name: "checkpoints.remove",
        key: "checkpoints_remove",
        summary: "Removes an unpinned leaf checkpoint with explicit execution intent.",
        classification: Classification::DevOnly,
        request: schema_of::<
            mvm_client::checkpoint::wire::Mutation<mvm_client::checkpoint::wire::IdRequest>,
        >,
        reply: schema_of::<mvm_client::checkpoint::wire::Empty>,
    },
    MethodDef {
        name: "checkpoints.capture",
        key: "checkpoints_capture",
        summary: "Captures machine state under its admitted key domain.",
        classification: Classification::DevOnly,
        request: schema_of::<
            mvm_client::checkpoint::wire::Mutation<mvm_client::checkpoint::CaptureRequest>,
        >,
        reply: schema_of::<mvm_core::checkpoint::CheckpointMeta>,
    },
    MethodDef {
        name: "checkpoints.restore",
        key: "checkpoints_restore",
        summary: "Restores a full-machine checkpoint with tenant and lineage checks.",
        classification: Classification::DevOnly,
        request: schema_of::<
            mvm_client::checkpoint::wire::Mutation<mvm_client::checkpoint::RestoreRequest>,
        >,
        reply: schema_of::<mvm_client::checkpoint::RestoreReport>,
    },
    MethodDef {
        name: "checkpoints.fork",
        key: "checkpoints_fork",
        summary: "Forks checkpoint state through client-owned admission and attenuation.",
        classification: Classification::DevOnly,
        request: schema_of::<
            mvm_client::checkpoint::wire::Mutation<mvm_client::checkpoint::wire::ForkRequest>,
        >,
        reply: schema_of::<mvm_client::checkpoint::ForkReport>,
    },
    MethodDef {
        name: "replay.run_session",
        key: "replay_run_session",
        summary: "Previews or executes verified session replay on a fresh admitted fork.",
        classification: Classification::DevOnly,
        request: schema_of::<mvm_client::checkpoint::wire::ReplayRequest>,
        reply: schema_of::<mvm_client::replay::SessionReplayRunReport>,
    },
    MethodDef {
        name: crate::workspace::REVIEW,
        key: "workspace_review",
        summary: "Recover interrupted work and review a registered workspace without approving changes.",
        classification: Classification::ProdSafe,
        request: schema_of::<mvm_client::workspace_apply::WorkspaceRequest>,
        reply: schema_of::<crate::workspace::ReviewReply>,
    },
    MethodDef {
        name: crate::workspace::APPLY,
        key: "workspace_apply",
        summary: "Apply only a freshly revalidated fingerprint with explicit approval.",
        classification: Classification::ProdSafe,
        request: schema_of::<mvm_client::workspace_apply::wire::ApplyRequest>,
        reply: schema_of::<crate::workspace::ApplyReply>,
    },
    MethodDef {
        name: crate::workspace::UNDO,
        key: "workspace_undo",
        summary: "Explicitly undo registered workspace history, reporting recoveries.",
        classification: Classification::ProdSafe,
        request: schema_of::<mvm_client::workspace_apply::wire::HistoryRequest>,
        reply: schema_of::<crate::workspace::HistoryReply>,
    },
    MethodDef {
        name: crate::workspace::REDO,
        key: "workspace_redo",
        summary: "Explicitly redo registered workspace history, reporting recoveries.",
        classification: Classification::ProdSafe,
        request: schema_of::<mvm_client::workspace_apply::wire::HistoryRequest>,
        reply: schema_of::<crate::workspace::HistoryReply>,
    },
    MethodDef {
        name: crate::artifact::INSPECT,
        key: "artifact_inspect",
        summary: "Inspect a published local artifact.",
        classification: Classification::ProdSafe,
        request: schema_of::<mvm_client::artifact::ArtifactRequest>,
        reply: schema_of::<mvm_client::artifact::report::ArtifactReport>,
    },
    MethodDef {
        name: crate::artifact::VALIDATE,
        key: "artifact_validate",
        summary: "Validate a published local artifact.",
        classification: Classification::ProdSafe,
        request: schema_of::<mvm_client::artifact::ArtifactRequest>,
        reply: schema_of::<mvm_client::artifact::report::ValidationReport>,
    },
    MethodDef {
        name: crate::artifact::CONFIGURE_FIRECRACKER,
        key: "artifact_configure_firecracker",
        summary: "Write a Firecracker configuration for a local artifact.",
        classification: Classification::ProdSafe,
        request: schema_of::<mvm_client::artifact::ArtifactRequest>,
        reply: schema_of::<mvm_client::artifact::report::BackendConfigReport>,
    },
    MethodDef {
        name: crate::audit::LIST,
        key: "audit_sessions_list",
        summary: "List sessions only after verifying the configured tenant chain.",
        classification: Classification::ProdSafe,
        request: schema_of::<mvm_client::audit::sessions::ListRequest>,
        reply: schema_of::<mvm_client::audit::sessions::ListReport>,
    },
    MethodDef {
        name: crate::audit::SHOW,
        key: "audit_sessions_show",
        summary: "Show verified session events without accepting trust-key overrides.",
        classification: Classification::ProdSafe,
        request: schema_of::<mvm_client::audit::sessions::ShowRequest>,
        reply: schema_of::<mvm_client::audit::sessions::ShowReport>,
    },
    MethodDef {
        name: crate::audit::VERIFY,
        key: "audit_sessions_verify",
        summary: "Report session verification including absent and unsealed sessions.",
        classification: Classification::ProdSafe,
        request: schema_of::<mvm_client::audit::sessions::VerifyRequest>,
        reply: schema_of::<mvm_client::audit::sessions::SessionVerification>,
    },
    MethodDef {
        name: crate::audit::POSTURE,
        key: "posture_inspect",
        summary: "Inspect security posture using only the configured host context.",
        classification: Classification::ProdSafe,
        request: schema_of::<crate::audit::PostureRequest>,
        reply: schema_of::<mvm_client::audit::posture::PostureReport>,
    },
    MethodDef {
        name: crate::volume::LIST,
        key: "volume_list",
        summary: "List managed volumes after lifecycle recovery.",
        classification: Classification::ProdSafe,
        request: schema_of::<mvm_client::volume::wire::Empty>,
        reply: array_of::<mvm_client::volume::VolumeRecord>,
    },
    MethodDef {
        name: crate::volume::INSPECT,
        key: "volume_inspect",
        summary: "Inspect a managed volume without key material.",
        classification: Classification::ProdSafe,
        request: schema_of::<mvm_client::volume::wire::NameRequest>,
        reply: schema_of::<mvm_client::volume::VolumeRecord>,
    },
    MethodDef {
        name: crate::volume::CREATE,
        key: "volume_create",
        summary: "Create a locked managed encrypted block volume.",
        classification: Classification::ProdSafe,
        request: schema_of::<mvm_client::volume::wire::CreateRequest>,
        reply: schema_of::<mvm_client::volume::VolumeRecord>,
    },
    MethodDef {
        name: crate::volume::UNLOCK,
        key: "volume_unlock",
        summary: "Unlock a volume through the configured client key provider.",
        classification: Classification::ProdSafe,
        request: schema_of::<mvm_client::volume::wire::NameRequest>,
        reply: schema_of::<mvm_client::volume::VolumeRecord>,
    },
    MethodDef {
        name: crate::volume::LOCK,
        key: "volume_lock",
        summary: "Seal a managed volume through its authoritative lifecycle.",
        classification: Classification::ProdSafe,
        request: schema_of::<mvm_client::volume::wire::NameRequest>,
        reply: schema_of::<mvm_client::volume::VolumeRecord>,
    },
    MethodDef {
        name: crate::volume::MOUNT,
        key: "volume_mount",
        summary: "Register a read-only-by-default volume or encrypted host snapshot.",
        classification: Classification::ProdSafe,
        request: schema_of::<mvm_client::volume::wire::MountRequest>,
        reply: schema_of::<mvm_client::volume::AttachmentRecord>,
    },
    MethodDef {
        name: crate::volume::DETACH,
        key: "volume_detach",
        summary: "Detach a registered volume.",
        classification: Classification::ProdSafe,
        request: schema_of::<mvm_client::volume::wire::DetachRequest>,
        reply: schema_of::<mvm_client::volume::AttachmentRecord>,
    },
    MethodDef {
        name: crate::volume::ATTACHMENTS,
        key: "volume_attachments",
        summary: "List registered attachments for a machine.",
        classification: Classification::ProdSafe,
        request: schema_of::<mvm_client::volume::wire::MachineRequest>,
        reply: array_of::<mvm_client::volume::AttachmentRecord>,
    },
    MethodDef {
        name: crate::volume::SNAPSHOT,
        key: "volume_snapshot",
        summary: "Snapshot a locked managed volume without exporting key material.",
        classification: Classification::ProdSafe,
        request: schema_of::<mvm_client::volume::wire::SnapshotRequest>,
        reply: schema_of::<mvm_client::volume::wire::Empty>,
    },
    MethodDef {
        name: crate::volume::RESTORE,
        key: "volume_restore",
        summary: "Restore a locked managed volume from a verified local snapshot.",
        classification: Classification::ProdSafe,
        request: schema_of::<mvm_client::volume::wire::SnapshotRequest>,
        reply: schema_of::<mvm_client::volume::wire::Empty>,
    },
    MethodDef {
        name: crate::manifest::REMOVE,
        key: "manifest_remove",
        summary: "Remove a local built slot, optionally deleting its source manifest.",
        classification: Classification::ProdSafe,
        request: schema_of::<mvm_client::manifest::RemoveRequest>,
        reply: schema_of::<mvm_client::manifest::RemoveReport>,
    },
    MethodDef {
        name: crate::manifest::PRUNE,
        key: "manifest_prune",
        summary: "Preview or explicitly remove orphaned local manifest slots.",
        classification: Classification::ProdSafe,
        request: schema_of::<mvm_client::manifest::PruneRequest>,
        reply: schema_of::<mvm_client::manifest::PruneReport>,
    },
    MethodDef {
        name: crate::manifest::EXPORT_OCI,
        key: "manifest_export_oci",
        summary: "Export an existing local OCI archive.",
        classification: Classification::ProdSafe,
        request: schema_of::<mvm_client::manifest::ExportOciRequest>,
        reply: schema_of::<mvm_client::manifest::ExportOciReport>,
    },
    MethodDef {
        name: crate::storage::INFO,
        key: "storage_info",
        summary: "Inspect the host thin pool.",
        classification: Classification::ProdSafe,
        request: schema_of::<mvm_client::storage::InfoRequest>,
        reply: schema_of::<mvm_client::storage::InfoReport>,
    },
    MethodDef {
        name: crate::storage::GC,
        key: "storage_gc",
        summary: "Preview or explicitly collect host thin-pool volumes.",
        classification: Classification::ProdSafe,
        request: schema_of::<mvm_client::storage::GcRequest>,
        reply: schema_of::<mvm_client::storage::GcReport>,
    },
    MethodDef {
        name: crate::bundle::EXPORT,
        key: "bundle_export",
        summary: "Export registered artifacts signed by the host key.",
        classification: Classification::ProdSafe,
        request: schema_of::<mvm_client::bundle::ExportRequest>,
        reply: schema_of::<mvm_client::bundle::ExportReport>,
    },
    MethodDef {
        name: crate::dispatch::MAINTENANCE_RECONCILE,
        key: "maintenance_reconcile",
        summary: "Preview host-local registry drift, or explicitly apply repairs.",
        classification: Classification::ProdSafe,
        request: schema_of::<mvm_client::maintenance::ReconcileRequest>,
        reply: schema_of::<mvm_client::maintenance::ReconcileReport>,
    },
    MethodDef {
        name: MANIFEST_INFO,
        key: "manifest_info",
        summary: "Inspect a built manifest slot and its optional snapshot.",
        classification: Classification::ProdSafe,
        request: schema_of::<mvm_client::manifest::InfoRequest>,
        reply: manifest_info,
    },
    MethodDef {
        name: MANIFEST_LIST,
        key: "manifest_list",
        summary: "List built manifest slots with orphan and tag-intersection filters.",
        classification: Classification::ProdSafe,
        request: schema_of::<mvm_client::manifest::ListRequest>,
        reply: array_of::<mvm_client::manifest::SlotRow>,
    },
    MethodDef {
        name: MANIFEST_VERIFY,
        key: "manifest_verify",
        summary: "Verify built manifest artifact checksums; signature verification is refused.",
        classification: Classification::ProdSafe,
        request: schema_of::<mvm_client::manifest::VerifyRequest>,
        reply: schema_of::<mvm_client::manifest::VerifiedSlot>,
    },
    MethodDef {
        name: BACKEND_CAPABILITIES,
        key: "backend_capabilities",
        summary: "Reports what the backend can do.",
        classification: Classification::ProdSafe,
        request: schema_of::<DispatchEmpty>,
        reply: any_json,
    },
    MethodDef {
        name: ENTRYPOINT_CALL,
        key: "entrypoint_call",
        summary: "Calls a workload's entrypoint in a transient microVM, admitted under a signed plan.",
        classification: Classification::ProdSafe,
        request: schema_of::<EntrypointCallRequest>,
        reply: schema_of::<EntrypointCallReply>,
    },
    MethodDef {
        name: MACHINE_CREATE,
        key: "machine_create",
        summary: "Persists a machine definition without booting it.",
        classification: Classification::ProdSafe,
        request: schema_of::<CreateRequest>,
        reply: schema_of::<MachineState>,
    },
    MethodDef {
        name: MACHINE_EXEC,
        key: "machine_exec",
        summary: "Runs one non-interactive command in a machine.",
        classification: Classification::ProdSafe,
        request: schema_of::<ExecRequest>,
        reply: schema_of::<ExecReply>,
    },
    MethodDef {
        name: MACHINE_INSPECT,
        key: "machine_inspect",
        summary: "Inspects one machine.",
        classification: Classification::ProdSafe,
        request: schema_of::<MachineRef>,
        reply: schema_of::<MachineState>,
    },
    MethodDef {
        name: MACHINE_INVENTORY,
        key: "machine_inventory",
        summary: "Lists every machine on this host with its dev/prod posture.",
        classification: Classification::ProdSafe,
        request: schema_of::<DispatchEmpty>,
        reply: inventory_records,
    },
    MethodDef {
        name: MACHINE_LIST,
        key: "machine_list",
        summary: "Lists machines, optionally filtered.",
        classification: Classification::ProdSafe,
        request: schema_of::<MachineFilter>,
        reply: array_of::<MachineState>,
    },
    MethodDef {
        name: MACHINE_LOGS,
        key: "machine_logs",
        summary: "Returns captured console output, base64-encoded.",
        classification: Classification::ProdSafe,
        request: schema_of::<LogsRequest>,
        reply: schema_of::<LogsReply>,
    },
    MethodDef {
        name: MACHINE_RM,
        key: "machine_rm",
        summary: "Removes a machine, stopping it first when needed.",
        classification: Classification::ProdSafe,
        request: schema_of::<DispatchRemoveRequest>,
        reply: schema_of::<crate::guest::Empty>,
    },
    MethodDef {
        name: LOGS_CLOSE,
        key: "machine_logs_stream_close",
        summary: "Closes a captured-output stream. Idempotent.",
        classification: Classification::ProdSafe,
        request: schema_of::<CloseRequest>,
        reply: schema_of::<StreamEmpty>,
    },
    MethodDef {
        name: LOGS_NEXT,
        key: "machine_logs_stream_next",
        summary: "Returns the captured output that has arrived.",
        classification: Classification::ProdSafe,
        request: schema_of::<NextRequest>,
        reply: schema_of::<NextReply>,
    },
    MethodDef {
        name: LOGS_OPEN,
        key: "machine_logs_stream_open",
        summary: "Opens a stream over a machine's captured output, replayed then followed.",
        classification: Classification::ProdSafe,
        request: schema_of::<LogsOpenRequest>,
        reply: schema_of::<OpenReply>,
    },
    MethodDef {
        name: MACHINE_PAUSE,
        key: "machine_pause",
        summary: "Pauses a running machine, sealing a snapshot where the backend uses one.",
        classification: Classification::ProdSafe,
        request: schema_of::<PauseRequest>,
        reply: schema_of::<PauseOutcome>,
    },
    MethodDef {
        name: MACHINE_PROMPT,
        key: "machine_prompt",
        summary: "Sends one prompt to a running machine's resident agent, granted by its plan, \
                  journaled, recorded encrypted and chain-audited.",
        classification: Classification::ProdSafe,
        request: schema_of::<MachinePromptRequest>,
        reply: schema_of::<MachinePromptReply>,
    },
    MethodDef {
        name: MACHINE_RECONFIGURE,
        key: "machine_reconfigure",
        summary: "Patches a machine's resources and relaunches it when running.",
        classification: Classification::ProdSafe,
        request: schema_of::<ReconfigurePatchRequest>,
        reply: schema_of::<MachineState>,
    },
    MethodDef {
        name: MACHINE_RESUME,
        key: "machine_resume",
        summary: "Resumes a paused machine, refusing a replayed snapshot.",
        classification: Classification::ProdSafe,
        request: schema_of::<ResumeRequest>,
        reply: schema_of::<ResumeOutcome>,
    },
    MethodDef {
        name: MACHINE_RUN,
        key: "machine_run",
        summary: "Boots a machine through the admitted local launch.",
        classification: Classification::ProdSafe,
        request: schema_of::<RunRequest>,
        reply: schema_of::<RunReply>,
    },
    MethodDef {
        name: MACHINE_SET_TTL,
        key: "machine_set_ttl",
        summary: "Sets or clears the time the idle reaper removes a machine at.",
        classification: Classification::ProdSafe,
        request: schema_of::<SetTtlRequest>,
        reply: schema_of::<crate::guest::Empty>,
    },
    MethodDef {
        name: MACHINE_START,
        key: "machine_start",
        summary: "Boots a persisted machine definition.",
        classification: Classification::ProdSafe,
        request: schema_of::<MachineRef>,
        reply: schema_of::<MachineState>,
    },
    MethodDef {
        name: MACHINE_STOP,
        key: "machine_stop",
        summary: "Stops a machine. Idempotent.",
        classification: Classification::ProdSafe,
        request: schema_of::<StopRequest>,
        reply: schema_of::<crate::guest::Empty>,
    },
    MethodDef {
        name: SESSION_CALL,
        key: "session_call",
        summary: "Calls the entrypoint in a running session's microVM.",
        classification: Classification::ProdSafe,
        request: schema_of::<SessionCallRequest>,
        reply: schema_of::<EntrypointCallReply>,
    },
    MethodDef {
        name: SESSION_INFO,
        key: "session_info",
        summary: "Reports a session's record.",
        classification: Classification::ProdSafe,
        request: schema_of::<SessionRef>,
        reply: schema_of::<SessionInfoReply>,
    },
    MethodDef {
        name: SESSION_START,
        key: "session_start",
        summary: "Boots a warm session for a workload, admitted under a signed plan.",
        classification: Classification::ProdSafe,
        request: schema_of::<SessionStartRequest>,
        reply: schema_of::<SessionStartReply>,
    },
    MethodDef {
        name: SESSION_STOP,
        key: "session_stop",
        summary: "Stops a session and tears down its microVM.",
        classification: Classification::ProdSafe,
        request: schema_of::<SessionRef>,
        reply: schema_of::<crate::guest::Empty>,
    },
    MethodDef {
        name: CP,
        key: "guest_cp",
        summary: "Copies a file between the host and the guest.",
        classification: Classification::DevOnly,
        request: schema_of::<CopyRequest>,
        reply: schema_of::<crate::guest::Empty>,
    },
    MethodDef {
        name: FS_LIST,
        key: "guest_fs_list",
        summary: "Lists a directory in the guest.",
        classification: Classification::DevOnly,
        request: schema_of::<PathRequest>,
        reply: schema_of::<ListReply>,
    },
    MethodDef {
        name: FS_MKDIR,
        key: "guest_fs_mkdir",
        summary: "Creates a directory in the guest.",
        classification: Classification::DevOnly,
        request: schema_of::<MkdirRequest>,
        reply: schema_of::<crate::guest::Empty>,
    },
    MethodDef {
        name: FS_READ,
        key: "guest_fs_read",
        summary: "Reads a file from the guest, base64-encoded.",
        classification: Classification::DevOnly,
        request: schema_of::<ReadRequest>,
        reply: schema_of::<DataReply>,
    },
    MethodDef {
        name: FS_REMOVE,
        key: "guest_fs_remove",
        summary: "Removes a path in the guest.",
        classification: Classification::DevOnly,
        request: schema_of::<RemoveRequest>,
        reply: schema_of::<RemovedReply>,
    },
    MethodDef {
        name: FS_RENAME,
        key: "guest_fs_rename",
        summary: "Moves a path in the guest.",
        classification: Classification::DevOnly,
        request: schema_of::<RenameRequest>,
        reply: schema_of::<crate::guest::Empty>,
    },
    MethodDef {
        name: FS_STAT,
        key: "guest_fs_stat",
        summary: "Stats a path in the guest.",
        classification: Classification::DevOnly,
        request: schema_of::<StatRequest>,
        reply: schema_of::<FsStat>,
    },
    MethodDef {
        name: FS_WRITE,
        key: "guest_fs_write",
        summary: "Writes a file in the guest, base64-encoded.",
        classification: Classification::DevOnly,
        request: schema_of::<WriteRequest>,
        reply: schema_of::<WrittenReply>,
    },
    MethodDef {
        name: PROC_KILL,
        key: "guest_proc_kill",
        summary: "Kills a tracked guest process.",
        classification: Classification::DevOnly,
        request: schema_of::<ProcessRequest>,
        reply: schema_of::<crate::guest::Empty>,
    },
    MethodDef {
        name: PROC_LIST,
        key: "guest_proc_list",
        summary: "Lists tracked guest processes.",
        classification: Classification::DevOnly,
        request: schema_of::<MachineRequest>,
        reply: array_of::<ProcInfo>,
    },
    MethodDef {
        name: PROC_SIGNAL,
        key: "guest_proc_signal",
        summary: "Signals a tracked guest process.",
        classification: Classification::DevOnly,
        request: schema_of::<SignalRequest>,
        reply: schema_of::<crate::guest::Empty>,
    },
    MethodDef {
        name: PROC_START,
        key: "guest_proc_start",
        summary: "Starts a process in the guest.",
        classification: Classification::DevOnly,
        request: schema_of::<StartRequest>,
        reply: schema_of::<StartedReply>,
    },
    MethodDef {
        name: PROC_STDIN,
        key: "guest_proc_stdin",
        summary: "Writes a tracked process's stdin, base64-encoded.",
        classification: Classification::DevOnly,
        request: schema_of::<StdinRequest>,
        reply: schema_of::<AcceptedReply>,
    },
    MethodDef {
        name: STREAM_CLOSE,
        key: "guest_proc_stream_close",
        summary: "Closes a process output stream. Idempotent.",
        classification: Classification::DevOnly,
        request: schema_of::<CloseRequest>,
        reply: schema_of::<StreamEmpty>,
    },
    MethodDef {
        name: STREAM_NEXT,
        key: "guest_proc_stream_next",
        summary: "Returns the process output that has arrived, and how it ended.",
        classification: Classification::DevOnly,
        request: schema_of::<NextRequest>,
        reply: schema_of::<NextReply>,
    },
    MethodDef {
        name: STREAM_OPEN,
        key: "guest_proc_stream_open",
        summary: "Opens a stream over a guest process's output.",
        classification: Classification::DevOnly,
        request: schema_of::<OpenRequest>,
        reply: schema_of::<OpenReply>,
    },
    MethodDef {
        name: PROC_WAIT,
        key: "guest_proc_wait",
        summary: "Waits for a guest process to end, returning its output.",
        classification: Classification::DevOnly,
        request: schema_of::<WaitRequest>,
        reply: schema_of::<WaitReply>,
    },
    MethodDef {
        name: TELEMETRY_RECORDS,
        key: "telemetry_records",
        summary: "Reads one cursor-paged page of a machine's collected telemetry records.",
        classification: Classification::ProdSafe,
        request: schema_of::<TelemetryRecordsRequest>,
        reply: telemetry_page,
    },
    MethodDef {
        name: TELEMETRY_STATUS,
        key: "telemetry_status",
        summary: "Reports whether telemetry collection was provisioned for a machine and how its collector stands.",
        classification: Classification::ProdSafe,
        request: schema_of::<MachineRef>,
        reply: telemetry_status,
    },
];

/// `machine_list` -> `MachineList`: the title the generated wrapper class
/// carries.
fn title_of(key: &str) -> String {
    key.split('_')
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect()
}

/// Assemble the whole ABI into one JSON Schema document: a root object keyed
/// by method key, each property referencing that method's named request and
/// reply definitions, with every referenced type merged at the top level.
///
/// Request and reply schemas are registered under per-method names
/// (`MachineListRequest`, `MachineListReply`) rather than embedded inline,
/// because the pinned generators name an inline nested schema after the
/// property (`Request`, `Request1`), which is neither stable nor meaningful
/// across regenerations.
///
/// Fails when two types share a definition name with different shapes —
/// that is a naming collision the emitters must surface, not silently pick
/// one side of.
pub fn schema_document() -> anyhow::Result<serde_json::Value> {
    let mut properties = serde_json::Map::new();
    let mut definitions = serde_json::Map::new();
    let mut required = Vec::new();

    let insert_def = |name: String,
                      schema: serde_json::Value,
                      definitions: &mut serde_json::Map<String, serde_json::Value>|
     -> anyhow::Result<()> {
        match definitions.get(&name) {
            Some(existing) if *existing == schema => Ok(()),
            Some(_) => anyhow::bail!("two ABI types collide on the schema name `{name}`"),
            None => {
                definitions.insert(name, schema);
                Ok(())
            }
        }
    };

    for method in REGISTRY {
        let title = title_of(method.key);
        let request = (method.request)();
        let reply = (method.reply)();
        for (name, schema) in request.defs.into_iter().chain(reply.defs) {
            insert_def(name, schema, &mut definitions)?;
        }
        insert_def(format!("{title}Request"), request.root, &mut definitions)?;
        insert_def(format!("{title}Reply"), reply.root, &mut definitions)?;
        let mut wrapper = serde_json::Map::new();
        wrapper.insert("title".into(), title.into());
        wrapper.insert("type".into(), "object".into());
        wrapper.insert("additionalProperties".into(), false.into());
        wrapper.insert("required".into(), serde_json::json!(["request", "reply"]));
        wrapper.insert(
            "properties".into(),
            serde_json::json!({
                "request": { "$ref": format!("#/definitions/{}Request", title_of(method.key)) },
                "reply": { "$ref": format!("#/definitions/{}Reply", title_of(method.key)) },
            }),
        );
        properties.insert(method.key.to_string(), wrapper.into());
        required.push(method.key);
    }

    let mut doc = serde_json::Map::new();
    doc.insert(
        "$schema".into(),
        "http://json-schema.org/draft-07/schema#".into(),
    );
    doc.insert("title".into(), "HostAbi".into());
    doc.insert("type".into(), "object".into());
    doc.insert("additionalProperties".into(), false.into());
    doc.insert("required".into(), required.into());
    doc.insert("properties".into(), properties.into());
    doc.insert("definitions".into(), definitions.into());
    Ok(doc.into())
}

/// The method-table manifest the per-language constant renderers consume.
pub fn method_manifest() -> serde_json::Value {
    serde_json::json!({
        "version": 0,
        "abi_major": crate::MVM_HOSTLIB_ABI_MAJOR,
        "abi_minor": crate::MVM_HOSTLIB_ABI_MINOR,
        "methods": REGISTRY.iter().map(|m| serde_json::json!({
            "name": m.name,
            "key": m.key,
            "classification": m.classification,
            "summary": m.summary,
        })).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The registry and the runtime dispatch tables must name exactly the
    /// same methods; a method added to one and not the other is a binding
    /// that advertises what the library refuses, or the reverse.
    #[test]
    fn registry_names_match_the_runtime_method_tables() {
        let mut registry: Vec<&str> = REGISTRY.iter().map(|m| m.name).collect();
        registry.sort_unstable();
        let mut runtime: Vec<&str> = crate::dispatch::METHODS
            .iter()
            .chain(crate::guest::METHODS.iter())
            .chain(crate::launch::METHODS.iter())
            .chain(crate::manifest::METHODS.iter())
            .chain(crate::storage::METHODS.iter())
            .chain(crate::bundle::METHODS.iter())
            .chain(crate::artifact::METHODS.iter())
            .chain(crate::audit::METHODS.iter())
            .chain(crate::volume::METHODS.iter())
            .chain(crate::workspace::METHODS.iter())
            .chain(crate::agent_sessions::METHODS.iter())
            .chain(crate::checkpoints::METHODS.iter())
            .chain(crate::replay::METHODS.iter())
            .chain(crate::entrypoint::METHODS.iter())
            .chain(crate::stream::METHODS.iter())
            .chain(crate::stream::LOG_METHODS.iter())
            .copied()
            .collect();
        runtime.sort_unstable();
        assert_eq!(registry, runtime);
    }

    #[test]
    fn host_local_requests_have_strict_schemas_and_safe_defaults() {
        for method in REGISTRY.iter().filter(|method| {
            crate::manifest::METHODS.contains(&method.name)
                || crate::storage::METHODS.contains(&method.name)
                || crate::bundle::METHODS.contains(&method.name)
                || crate::artifact::METHODS.contains(&method.name)
                || crate::audit::METHODS.contains(&method.name)
                || crate::volume::METHODS.contains(&method.name)
                || crate::workspace::METHODS.contains(&method.name)
                || crate::agent_sessions::METHODS.contains(&method.name)
                || crate::checkpoints::METHODS.contains(&method.name)
                || crate::replay::METHODS.contains(&method.name)
        }) {
            assert_eq!(
                (method.request)().root["additionalProperties"],
                false,
                "{}",
                method.name
            );
        }
        let prune = schema_of::<mvm_client::manifest::PruneRequest>();
        assert_eq!(prune.root["properties"]["dry_run"]["default"], true);
        let gc = schema_of::<mvm_client::storage::GcRequest>();
        assert_eq!(gc.root["properties"]["apply"]["default"], false);
        let mount = schema_of::<mvm_client::volume::wire::MountRequest>();
        assert_eq!(mount.root["properties"]["access"]["default"], "read-only");
        let apply = schema_of::<mvm_client::workspace_apply::wire::ApplyRequest>();
        let required = apply.root["required"].as_array().unwrap();
        assert!(required.contains(&serde_json::json!("expected_fingerprint")));
        assert!(required.contains(&serde_json::json!("approved")));
        assert!(apply.root["properties"].get("plan").is_none());
    }

    #[test]
    fn keys_are_unique_and_dotted_names_are_unique() {
        let mut keys: Vec<&str> = REGISTRY.iter().map(|m| m.key).collect();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), REGISTRY.len(), "duplicate schema key");
        let mut names: Vec<&str> = REGISTRY.iter().map(|m| m.name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), REGISTRY.len(), "duplicate method name");
    }

    #[test]
    fn keys_are_identifier_safe() {
        for method in REGISTRY {
            assert!(
                method
                    .key
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "{} is not identifier-safe",
                method.key
            );
            assert!(method.key.starts_with(|c: char| c.is_ascii_lowercase()));
        }
    }

    #[test]
    fn schema_document_covers_every_method_and_merges_definitions() {
        let doc = schema_document().expect("the ABI schema assembles");
        let obj = doc.as_object().expect("an object document");
        let properties = obj["properties"].as_object().expect("properties");
        let definitions = obj["definitions"].as_object().expect("definitions");
        for method in REGISTRY {
            let title = title_of(method.key);
            for side in ["Request", "Reply"] {
                let name = format!("{title}{side}");
                let refr = properties[method.key]["properties"][side.to_lowercase()]["$ref"]
                    .as_str()
                    .expect("a named reference");
                assert_eq!(refr, format!("#/definitions/{name}"), "{}", method.name);
                assert!(definitions.contains_key(&name), "{name} is defined");
            }
        }
    }

    #[test]
    fn title_of_camel_cases_keys() {
        assert_eq!(title_of("machine_list"), "MachineList");
        assert_eq!(title_of("guest_proc_start"), "GuestProcStart");
    }

    #[test]
    fn the_manifest_carries_the_abi_version_and_every_method() {
        let manifest = method_manifest();
        assert_eq!(manifest["abi_major"], crate::MVM_HOSTLIB_ABI_MAJOR);
        assert_eq!(manifest["abi_minor"], crate::MVM_HOSTLIB_ABI_MINOR);
        assert_eq!(
            manifest["methods"].as_array().expect("methods").len(),
            REGISTRY.len()
        );
    }
}
