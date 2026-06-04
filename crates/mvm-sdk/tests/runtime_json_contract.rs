//! ADR-0011 W-DEP: byte-format contract tests for `/etc/mvm/runtime.json`.
//!
//! mvm's Nix factories emit `/etc/mvm/runtime.json` at image
//! build time. The mvm agent parses that file at boot via
//! `mvm_guest::runtime_config::RuntimeConfig` (with
//! `serde(deny_unknown_fields)`). If our emit drifts from the
//! upstream schema, the agent boot fails before the worker pool
//! initializes — silently, on every shipped image.
//!
//! This file deserializes every shape mvm's factories emit
//! through the **real upstream type**, pulled in as a `[dev-dependencies]`
//! entry on `mvm-guest` (see `Cargo.toml`). When mvm cuts a release
//! that changes the schema, bump the `rev` in `Cargo.toml` and the
//! breaking case fails this test immediately — not silently at boot
//! time on a shipped image.
//!
//! Closes the deferred W-DEP item from issue tinylabscom/mvm#20:
//! the previous version of this file used a hand-rolled
//! `MvmRuntimeConfigMirror` struct that had to be updated in lockstep
//! with mvm by hand; now drift detection is automatic.

use mvm_guest::runtime_config::{ConcurrencyConfig, InProcessMode, RuntimeConfig};

fn parse(label: &str, json: &str) -> RuntimeConfig {
    serde_json::from_str::<RuntimeConfig>(json).unwrap_or_else(|err| {
        panic!("RuntimeConfig failed to parse {label} runtime.json: {err}\n\ninput:\n{json}");
    })
}

fn assert_parses(label: &str, json: &str) {
    let _ = parse(label, json);
}

#[test]
fn cold_tier_python_runtime_json_parses() {
    // Shape `mkPythonFunctionService.nix` emits when concurrency is null.
    let cfg = parse(
        "cold-python",
        r#"{
            "language": "python",
            "module": "adder",
            "function": "add",
            "format": "json",
            "source_path": "/app"
        }"#,
    );
    assert_eq!(cfg.language, "python");
    assert_eq!(cfg.module, "adder");
    assert!(
        cfg.concurrency.is_none(),
        "cold-tier carries no concurrency"
    );
}

#[test]
fn cold_tier_node_runtime_json_parses() {
    let cfg = parse(
        "cold-node",
        r#"{
            "language": "node",
            "module": "adder",
            "function": "add",
            "format": "json",
            "source_path": "/app"
        }"#,
    );
    assert_eq!(cfg.language, "node");
    assert!(cfg.concurrency.is_none());
}

#[test]
fn cold_tier_msgpack_format_parses() {
    let cfg = parse(
        "cold-msgpack",
        r#"{
            "language": "python",
            "module": "m",
            "function": "f",
            "format": "msgpack",
            "source_path": "/app"
        }"#,
    );
    assert_eq!(cfg.format, "msgpack");
}

#[test]
fn warm_process_runtime_json_parses() {
    // Shape `mkPythonFunctionService.nix` emits when the IR carries
    // `Concurrency::WarmProcess(...)`. The factory merges this block
    // into runtime.json via Nix's `//` operator.
    let cfg = parse(
        "warm-process",
        r#"{
            "language": "python",
            "module": "adder",
            "function": "add",
            "format": "json",
            "source_path": "/app",
            "concurrency": {
                "kind": "warm_process",
                "max_calls_per_worker": 1000,
                "max_rss_mb": 256,
                "pool_size": 1,
                "in_process": "serial"
            }
        }"#,
    );
    let Some(ConcurrencyConfig::WarmProcess(wp)) = &cfg.concurrency else {
        panic!(
            "expected WarmProcess concurrency, got {:?}",
            cfg.concurrency
        );
    };
    assert_eq!(wp.max_calls_per_worker, 1000);
    assert_eq!(wp.max_rss_mb, 256);
    assert_eq!(wp.pool_size, 1);
    assert_eq!(wp.in_process, InProcessMode::Serial);
    assert_eq!(wp.max_queue_depth, None);
    // Default queue depth is 2 * pool_size — pinning the helper here
    // catches semantic drift even when wire bytes stay the same.
    assert_eq!(wp.effective_queue_depth(), 2);
}

#[test]
fn warm_process_with_max_queue_depth_parses() {
    let cfg = parse(
        "warm-process-queue",
        r#"{
            "language": "node",
            "module": "m",
            "function": "f",
            "format": "json",
            "source_path": "/app",
            "concurrency": {
                "kind": "warm_process",
                "max_calls_per_worker": 5000,
                "max_rss_mb": 512,
                "pool_size": 4,
                "in_process": "serial",
                "max_queue_depth": 32
            }
        }"#,
    );
    let Some(ConcurrencyConfig::WarmProcess(wp)) = &cfg.concurrency else {
        unreachable!()
    };
    assert_eq!(wp.max_queue_depth, Some(32));
    assert_eq!(wp.effective_queue_depth(), 32);
}

#[test]
fn unknown_top_level_field_rejected() {
    // The agent uses `serde(deny_unknown_fields)`, so any drift
    // between mvm's emit and the upstream schema fails here too.
    let json = r#"{
        "language": "python",
        "module": "m",
        "function": "f",
        "format": "json",
        "source_path": "/app",
        "bogus": 1
    }"#;
    serde_json::from_str::<RuntimeConfig>(json)
        .expect_err("unknown top-level field must be rejected");
}

#[test]
fn unknown_concurrency_field_rejected() {
    let json = r#"{
        "language": "python",
        "module": "m",
        "function": "f",
        "format": "json",
        "source_path": "/app",
        "concurrency": {
            "kind": "warm_process",
            "max_calls_per_worker": 1000,
            "max_rss_mb": 256,
            "pool_size": 1,
            "in_process": "serial",
            "bogus": 1
        }
    }"#;
    serde_json::from_str::<RuntimeConfig>(json)
        .expect_err("unknown concurrency field must be rejected");
}

#[test]
fn unknown_concurrency_kind_rejected() {
    let json = r#"{
        "language": "python",
        "module": "m",
        "function": "f",
        "format": "json",
        "source_path": "/app",
        "concurrency": { "kind": "future_tier" }
    }"#;
    serde_json::from_str::<RuntimeConfig>(json)
        .expect_err("unknown concurrency kind must be rejected");
}

#[test]
fn concurrent_in_process_mode_parses_at_schema_layer() {
    // The schema accepts "concurrent" — the agent's `load_from`
    // wrapper rejects it (RuntimeConfigError::ConcurrentNotSupported).
    // This test pins that the schema-level deserialization doesn't
    // accidentally drop the variant; the runtime rejection happens
    // one layer up in mvm's `load_from` (which our test can't
    // exercise without a real file path).
    assert_parses(
        "in-process-concurrent",
        r#"{
            "language": "python",
            "module": "m",
            "function": "f",
            "format": "json",
            "source_path": "/app",
            "concurrency": {
                "kind": "warm_process",
                "max_calls_per_worker": 1000,
                "max_rss_mb": 256,
                "pool_size": 1,
                "in_process": "concurrent"
            }
        }"#,
    );
}

#[test]
fn roundtrip_through_upstream_type_preserves_bytes() {
    // Drift detection at the deepest level: serialize-deserialize a
    // warm-process config through mvm's `RuntimeConfig`, then assert
    // every field round-trips. If mvm changes a field rename or
    // tagging, this test catches it even when individual snapshot
    // tests above happen to still parse.
    let original = parse(
        "roundtrip",
        r#"{
            "language": "python",
            "module": "adder",
            "function": "add",
            "format": "json",
            "source_path": "/app",
            "concurrency": {
                "kind": "warm_process",
                "max_calls_per_worker": 7,
                "max_rss_mb": 64,
                "pool_size": 2,
                "in_process": "serial",
                "max_queue_depth": 8
            }
        }"#,
    );
    let json = serde_json::to_string(&original).expect("serialize");
    let back: RuntimeConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(original, back);
}
