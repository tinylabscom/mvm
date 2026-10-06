//! Whether a boot is provisioned for host-side telemetry collection, and the
//! on-disk names the embedded collector shares with its readers.
//!
//! There is no collector process: the collector runs as a thread inside the
//! per-VM network endpoint, so it lives and dies with the one host process
//! every workload boot already has. Provisioning is a single decision made
//! by the spawner and consumed twice — the endpoint config grows a telemetry
//! section, and the guest cmdline grows the `mvm.telemetry=1` assertion that
//! tells the agent to serve its listener. One decision, so the guest can
//! never assert a listener the host did not provision for.

/// Where the embedded collector keeps its coverage-status snapshot, in the
/// VM state dir.
pub const TELEMETRY_COLLECTOR_STATUS_FILE: &str = "telemetry-collector-status.json";
/// Where the embedded collector appends received records, size-capped.
pub const TELEMETRY_RECORDS_FILE: &str = "telemetry-records.jsonl";
/// Default byte cap for the records file. Deliberately modest: retention is
/// its own workstream, and this file exists so collection is observable, not
/// as a durable store.
pub const DEFAULT_RECORDS_BYTE_CAP: u64 = 8 * 1024 * 1024;

/// Whether this host opts boots into telemetry collection.
///
/// A configured OTLP exporter implies collection — nobody configures an
/// export endpoint hoping nothing is collected. The explicit variable covers
/// collection with no export at all, which the plan requires to work:
/// collection is a product feature, not a side effect of OTLP configuration.
pub fn telemetry_collection_enabled() -> bool {
    collection_enabled_from(
        std::env::var("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
            .ok()
            .as_deref(),
        std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok().as_deref(),
        std::env::var("MVM_TELEMETRY_COLLECT").ok().as_deref(),
    )
}

/// The pure decision, split from the environment so it is testable without
/// process-global state.
pub fn collection_enabled_from(
    otlp_traces_endpoint: Option<&str>,
    otlp_endpoint: Option<&str>,
    explicit_collect: Option<&str>,
) -> bool {
    let configured = |v: Option<&str>| v.is_some_and(|v| !v.trim().is_empty());
    configured(otlp_traces_endpoint) || configured(otlp_endpoint) || explicit_collect == Some("1")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_otlp_endpoint_implies_collection() {
        assert!(collection_enabled_from(
            Some("https://collector.example.com"),
            None,
            None
        ));
        assert!(collection_enabled_from(
            None,
            Some("https://collector.example.com"),
            None
        ));
    }

    #[test]
    fn the_explicit_variable_enables_collection_without_export() {
        assert!(collection_enabled_from(None, None, Some("1")));
    }

    #[test]
    fn nothing_configured_means_no_collection() {
        assert!(!collection_enabled_from(None, None, None));
        assert!(!collection_enabled_from(Some(""), Some("  "), Some("0")));
    }
}
