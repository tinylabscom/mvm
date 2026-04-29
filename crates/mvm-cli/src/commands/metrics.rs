//! `mvmctl metrics` — emit Prometheus-style metrics.

use anyhow::Result;

pub(super) fn cmd_metrics(json: bool) -> Result<()> {
    let metrics = mvm_core::observability::metrics::global();
    if json {
        let snap = metrics.snapshot();
        println!("{}", serde_json::to_string_pretty(&snap)?);
    } else {
        print!("{}", metrics.prometheus_exposition());
    }
    Ok(())
}
