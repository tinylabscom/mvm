//! `emit_protocol_schema` — emit the host↔guest RPC
//! protocol JSON Schema to stdout: `GuestRequest` (the verbs the host
//! sends the agent) + `GuestResponse` (what the agent returns). This is
//! the single source of truth the SDK RPC-client codegen consumes, the
//! protocol-surface analog of `mvm-sdk`'s `emit_workload_schema` (the IR).
//!
//! Built only under `--features schema` (`required-features` in
//! `Cargo.toml`), so `schemars` never enters the default / prod agent
//! closure — the lean-agent invariant holds.

use schemars::JsonSchema;

/// Schema root: both wire directions under one document so the shared
/// `$defs` (`FsResult`, `ProcResult`, `EntrypointEvent`, …) are emitted
/// once and the generated clients reference a single definition set.
#[derive(JsonSchema)]
#[allow(dead_code)]
struct Protocol {
    request: mvm_guest::vsock::GuestRequest,
    response: mvm_guest::vsock::GuestResponse,
}

fn main() {
    let schema = schemars::schema_for!(Protocol);
    // Pretty-printed for a reviewable diff; deterministic because
    // schemars 0.8 backs `definitions` with a `BTreeMap` (sorted keys).
    let json = serde_json::to_string_pretty(&schema).expect("serialize protocol schema");
    println!("{json}");
}
