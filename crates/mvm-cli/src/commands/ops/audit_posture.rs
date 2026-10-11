//! Rendering for the client-owned, read-only audit posture operation.

use anyhow::Result;
use mvm_client::audit::posture::{PostureReport, PostureStatus, build_report};

pub(super) fn run(json: bool) -> Result<()> {
    let home = mvm_core::config::mvm_home_strict().ok();
    let report = build_report(home.as_deref());
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        render_human(&report);
    }
    let (_, _, fail) = report.summary_counts();
    if fail > 0 {
        anyhow::bail!("{fail} posture check(s) failed");
    }
    Ok(())
}

fn render_human(report: &PostureReport) {
    let (ok, warn, fail) = report.summary_counts();
    eprintln!(
        "mvmctl trust audit posture — security self-test ({} ok / {} warn / {} fail)",
        ok, warn, fail
    );
    for c in &report.checks {
        let sigil = match c.status {
            PostureStatus::Ok => "✓",
            PostureStatus::Warn => "!",
            PostureStatus::Fail => "✗",
        };
        eprintln!("  {sigil} {}: {}", c.name, c.detail);
    }
}
