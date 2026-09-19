//! `emit_broker_schema` — emit the host-services broker JSON Schema to
//! stdout: the `ServiceCall`/`ServiceResponse` envelope + the typed
//! `host.audit.v1` / `host.time.v1` / `host.cost.v1` payloads. This is the
//! single source of truth the in-guest SDK's type codegen consumes (the
//! broker analog of `emit_protocol_schema` for the agent verbs).
//!
//! In-guest workloads call these services over vsock `BROKER_PORT`; this
//! schema covers only the broker wire types, not the host↔agent
//! `GuestRequest`/`GuestResponse` verbs, so a generated broker client stays
//! free of the unrelated agent surface.
//!
//! Built only under `--features schema` (`required-features` in
//! `Cargo.toml`), so `schemars` never enters the default closure — the
//! runtime-free invariant holds.

use schemars::JsonSchema;

use mvm_core::protocol::broker::{ServiceCall, ServiceResponse};
use mvm_core::protocol::host_audit::{
    EmitBatchRequest, EmitBatchResponse, EmitRequest, EmitResponse,
};
use mvm_core::protocol::host_cost::CostReport;
use mvm_core::protocol::host_time::TimeNowResponse;

/// Schema root: every broker wire type under one document so the shared
/// `$defs` (`ServiceErrorCode`, `CorrelationId`, `EmitBatchEntryStatus`, …)
/// are emitted once and the generated clients reference one definition set.
#[derive(JsonSchema)]
struct BrokerServices {
    #[schemars(rename = "service_call")]
    _service_call: ServiceCall,
    #[schemars(rename = "service_response")]
    _service_response: ServiceResponse,
    #[schemars(rename = "emit_request")]
    _emit_request: EmitRequest,
    #[schemars(rename = "emit_response")]
    _emit_response: EmitResponse,
    #[schemars(rename = "emit_batch_request")]
    _emit_batch_request: EmitBatchRequest,
    #[schemars(rename = "emit_batch_response")]
    _emit_batch_response: EmitBatchResponse,
    #[schemars(rename = "time_now_response")]
    _time_now_response: TimeNowResponse,
    #[schemars(rename = "cost_report")]
    _cost_report: CostReport,
}

fn main() {
    let schema = schemars::schema_for!(BrokerServices);
    // Pretty-printed for a reviewable diff; deterministic because
    // schemars 0.8 backs `definitions` with a `BTreeMap` (sorted keys).
    let json = serde_json::to_string_pretty(&schema).expect("serialize broker schema");
    println!("{json}");
}
