//! Probe health monitoring: user-declared probe commands run on a background
//! loop, cached, and surfaced as `ProbeResult`s.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use mvm_agentd::probes::{ProbeEntry, ProbeOutputFormat, ProbeResult};

use crate::health::run_shell_with_timeout;
use crate::monitoring::utc_now;
use crate::state::ProbeState;

/// Run a single probe command.
fn run_probe(entry: &ProbeEntry) -> ProbeResult {
    let timeout = Duration::from_secs(entry.timeout_secs);
    let output = run_shell_with_timeout(&entry.cmd, timeout);

    match output {
        Ok(out) if out.status.success() => {
            let json_output = if entry.output_format == ProbeOutputFormat::Json {
                let stdout = String::from_utf8_lossy(&out.stdout);
                serde_json::from_str(stdout.trim()).ok()
            } else {
                None
            };
            ProbeResult {
                name: entry.name.clone(),
                healthy: true,
                detail: "ok".to_string(),
                output: json_output,
                checked_at: utc_now(),
            }
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let detail = if stderr.trim().is_empty() {
                format!("exit code {}", out.status.code().unwrap_or(-1))
            } else {
                stderr.trim().to_string()
            };
            ProbeResult {
                name: entry.name.clone(),
                healthy: false,
                detail,
                output: None,
                checked_at: utc_now(),
            }
        }
        Err(e) => ProbeResult {
            name: entry.name.clone(),
            healthy: false,
            detail: format!("failed to execute: {}", e),
            output: None,
            checked_at: utc_now(),
        },
    }
}

/// Background loop that periodically runs all loaded probes.
pub(crate) fn probe_health_loop(state: Arc<Mutex<ProbeState>>) {
    let count = state.lock().map(|s| s.probes.len()).unwrap_or(0);
    let mut last_checked: Vec<Option<std::time::Instant>> = vec![None; count];

    loop {
        let entries: Vec<(usize, ProbeEntry)> = {
            let Ok(s) = state.lock() else {
                std::thread::sleep(Duration::from_secs(1));
                continue;
            };
            s.probes
                .iter()
                .enumerate()
                .map(|(i, ph)| (i, ph.entry.clone()))
                .collect()
        };

        for (idx, entry) in &entries {
            let interval = Duration::from_secs(entry.interval_secs);
            let should_check = match last_checked.get(*idx).copied().flatten() {
                Some(last) => last.elapsed() >= interval,
                None => true,
            };
            if !should_check {
                continue;
            }

            let result = run_probe(entry);
            if !result.healthy {
                eprintln!(
                    "mvm-guest-agent: probe '{}' failed: {}",
                    entry.name, result.detail
                );
            }
            if let Ok(mut s) = state.lock()
                && let Some(ph) = s.probes.get_mut(*idx)
            {
                ph.last_result = Some(result);
            }
            last_checked[*idx] = Some(std::time::Instant::now());
        }

        std::thread::sleep(Duration::from_secs(1));
    }
}

/// Build probe reports from cached results.
pub(crate) fn build_probe_reports(probe_state: &Arc<Mutex<ProbeState>>) -> Vec<ProbeResult> {
    let Ok(s) = probe_state.lock() else {
        return vec![];
    };
    s.probes
        .iter()
        .filter_map(|ph| ph.last_result.clone())
        .collect()
}
