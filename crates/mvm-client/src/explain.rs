//! A run's attestation, read back from the chain-signed audit log.
//!
//! Reads the same tamper-evident `<audit_dir>/<tenant>.jsonl` chain the audit
//! verifier reads, selects the entries bound to one run, and assembles its
//! lifecycle, outcome, backend, source provenance and egress refusals —
//! recording whether the chain still verifies rather than refusing to answer
//! when it does not. Read-only: nothing here writes or signs.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;
use serde::Serialize;

use mvm_hostd::supervisor::PlanAuditEntry;

use crate::audit::follow::{ChainLine, parse_chain_line};
use crate::egress_denials::{DeniedDestination, denials_in_window};

/// Explain run `run_id` from tenant `tenant`'s chain in this host's audit
/// directory, verified under this host's signing key.
pub fn explain_local_run(tenant: &str, run_id: &str) -> Result<RunExplanation> {
    let dir = mvm_hostd::audit::emitter::default_audit_dir()?;
    let path = mvm_hostd::audit::emitter::audit_path_for_tenant(&dir, tenant);
    let signer = mvm_hostd::audit::host_keypair::load_or_init()
        .context("loading host signer to verify audit chain")?;
    collect_run(&path, &signer.verifying, tenant, run_id)
}

/// One audit-chain event rendered for a single run, stripped of the
/// chain-signing envelope (prev_hash / signature) — those are a
/// tamper-evidence detail, not part of the run's story.
#[derive(Debug, Clone, Serialize)]
pub struct EventRecord {
    pub timestamp: DateTime<Utc>,
    pub event: String,
    pub labels: BTreeMap<String, String>,
}

/// The rendered attestation for one run: its identity, its full
/// lifecycle of chain-signed events, and whether the chain that
/// carries them still verifies clean.
#[derive(Debug, Clone, Serialize)]
pub struct RunExplanation {
    pub run_id: String,
    pub tenant: String,
    pub plan_id: String,
    pub image_name: String,
    pub image_sha256: String,
    pub events: Vec<EventRecord>,
    /// The machine's egress refusals while this run held its name, counted by
    /// destination and reason, each with its remedy.
    pub egress_denials: Vec<DeniedDestination>,
    /// Every entry of this run was authenticated (host signature and chain
    /// link). See `history_verified` for what that did not cover.
    pub chain_verified: bool,
    /// The whole chain was walked from its first entry, so the history before
    /// these entries was attested too. False when the run was found in the live
    /// segment and only its own entries were authenticated, which is what keeps
    /// `explain` fast on a long-lived host; `mvmctl trust audit verify` walks
    /// everything.
    pub history_verified: bool,
    /// Total verified entry count across the whole chain file (not just
    /// this run's events). Rendering-only; not part of the JSON contract.
    #[serde(skip)]
    pub chain_entry_count: usize,
    pub verify_error: Option<String>,
}

impl RunExplanation {
    /// The terminal-event-derived outcome: exit code, failure class +
    /// message, or "still open" when no terminal event was recorded.
    pub fn outcome(&self) -> String {
        if let Some(ev) = self.events.iter().rev().find(|e| e.event == "plan.exited") {
            let code = ev
                .labels
                .get("exit_code")
                .cloned()
                .unwrap_or_else(|| "?".to_string());
            return format!("exited with code {code}");
        }
        if let Some(ev) = self.events.iter().rev().find(|e| e.event == "plan.failed") {
            let class = ev
                .labels
                .get("error_class")
                .map(String::as_str)
                .unwrap_or("unknown");
            let message = ev
                .labels
                .get("error_message")
                .map(String::as_str)
                .unwrap_or("");
            return format!("failed ({class}): {message}");
        }
        "launched, no terminal event recorded".to_string()
    }

    /// The most recent `backend` label across this run's events.
    pub fn backend(&self) -> Option<String> {
        self.events
            .iter()
            .rev()
            .find_map(|e| e.labels.get("backend").cloned())
    }

    /// Renders the `plan.oci_provenance` event's labels, if the run
    /// admitted an OCI-sourced image.
    pub fn provenance_summary(&self) -> Option<String> {
        let ev = self
            .events
            .iter()
            .find(|e| e.event == "plan.oci_provenance")?;
        Some(label_join(&ev.labels))
    }
}

/// Read the chain-signed audit log at `path`, select the entries bound
/// to `run_id` (by exact plan id, plan id prefix, or workload image
/// name), and render the run's attestation. Pure aside from the
/// filesystem read at `path` — no global `~/.mvm` state — so tests can
/// point it at a tempdir.
pub fn collect_run(
    path: &Path,
    verifying_key: &VerifyingKey,
    tenant: &str,
    run_id: &str,
) -> Result<RunExplanation> {
    if !path.exists() {
        bail!(
            "no audit chain for tenant '{tenant}' at {}; runs appear after the next launch",
            path.display()
        );
    }

    let audit_dir = path
        .parent()
        .with_context(|| format!("audit chain path {} has no parent", path.display()))?;
    let base = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .with_context(|| format!("audit chain path {} has no file stem", path.display()))?;
    // A chain that has never rotated is one small file: walk it all. Only a
    // rotated chain, where the walk grows with everything ever written, takes
    // the fast path.
    let rotated = mvm_core::audit_verify::set::segment_shape(audit_dir, base)
        .is_ok_and(|shape| !shape.sealed.is_empty());
    if rotated
        && let Some(entries) =
            authenticate_run_in_live_segment(audit_dir, base, verifying_key, run_id)
    {
        let count = entries.len();
        return explain_entries(&entries, run_id, tenant, Ok(count), false);
    }
    let (all_entries, verification) =
        match mvm_core::audit_verify::set::verify_segment_entries(audit_dir, base, verifying_key) {
            Ok(entries) => {
                let count = entries.len();
                (entries, Ok(count))
            }
            Err(error) => {
                let content = std::fs::read_to_string(path)
                    .with_context(|| format!("reading audit chain {}", path.display()))?;
                let entries = content
                    .lines()
                    .filter_map(|line| match parse_chain_line(line) {
                        ChainLine::Entry(entry) => Some(*entry),
                        ChainLine::Foreign(_) => None,
                    })
                    .collect();
                (entries, Err(error))
            }
        };

    explain_entries(
        &all_entries,
        run_id,
        tenant,
        verification.map_err(|e| e.to_string()),
        true,
    )
}

/// Find `run_id` in the live audit segment and authenticate just the entries that
/// bear on it: its own, and the endpoint's refusals under the machine it ran on.
///
/// The full walk costs a signature check per entry ever written, so on a host
/// that has run for a while `explain` takes many seconds. Each entry here still
/// carries its host signature and chain link; what is not re-attested is the
/// history before it. `None` means the run is not wholly in the live segment or
/// something did not authenticate, and the caller walks the whole chain.
fn authenticate_run_in_live_segment(
    dir: &Path,
    tenant: &str,
    key: &VerifyingKey,
    run_id: &str,
) -> Option<Vec<PlanAuditEntry>> {
    use mvm_core::audit_verify::live::authenticate_live_entries as live;
    if run_id.is_empty() {
        return None;
    }
    let mut entries = live(dir, tenant, key, run_id, |_| true).ok()?.entries;
    let plan_ids: BTreeSet<&str> = entries
        .iter()
        .filter(|e| {
            e.plan_id.0 == run_id || e.plan_id.0.starts_with(run_id) || e.image_name == run_id
        })
        .map(|e| e.plan_id.0.as_str())
        .collect();
    let [plan_id] = plan_ids.into_iter().collect::<Vec<_>>()[..] else {
        return None;
    };
    let plan_id = plan_id.to_string();
    // A run that began before the last rotation has its start in a retired
    // segment, which this read does not see; explaining it from here would
    // silently drop its beginning.
    if !entries
        .iter()
        .any(|e| e.plan_id.0 == plan_id && e.event == "plan.admitted")
    {
        return None;
    }
    let image_name = entries
        .iter()
        .find(|e| e.plan_id.0 == plan_id)?
        .image_name
        .clone();
    let machine = booted_machine(&entries, &plan_id)
        .unwrap_or(&image_name)
        .to_string();
    // The run's own entries first, so a run named by its image still gets all of them.
    for needle in [plan_id.as_str(), machine.as_str()] {
        for entry in live(dir, tenant, key, needle, |_| true).ok()?.entries {
            if !entries.contains(&entry) {
                entries.push(entry);
            }
        }
    }
    // Every line from the run's first entry to the end of the segment must be
    // linked to the one before it, or a removed refusal would go unnoticed.
    mvm_core::audit_verify::live::authenticate_live_tail(dir, tenant, key, &plan_id).ok()?;
    entries.sort_by_key(|e| e.timestamp);
    Some(entries)
}

/// Render `run_id` from `all_entries`, which are authenticated, with the state
/// of the chain they came from.
fn explain_entries(
    all_entries: &[PlanAuditEntry],
    run_id: &str,
    tenant: &str,
    verification: std::result::Result<usize, String>,
    history_verified: bool,
) -> Result<RunExplanation> {
    let matches: Vec<&PlanAuditEntry> = all_entries
        .iter()
        .filter(|e| {
            e.plan_id.0 == run_id || e.plan_id.0.starts_with(run_id) || e.image_name == run_id
        })
        .collect();

    if matches.is_empty() {
        bail!(
            "no run {run_id:?} found in the audit chain for tenant {tenant:?}; \
             try `mvmctl trust audit tail` to list recent runs"
        );
    }

    let distinct_plan_ids: BTreeSet<&str> = matches.iter().map(|e| e.plan_id.0.as_str()).collect();
    let candidates: Vec<&str> = distinct_plan_ids.into_iter().collect();
    let [plan_id] = candidates.as_slice() else {
        bail!(
            "run id {run_id:?} matches multiple runs: {}; pass a more specific plan id",
            candidates.join(", ")
        );
    };
    let plan_id = (*plan_id).to_string();

    let final_events: Vec<&PlanAuditEntry> = all_entries
        .iter()
        .filter(|e| e.plan_id.0 == plan_id)
        .collect();
    let Some(&first) = final_events.first() else {
        bail!("run {run_id:?} resolved to plan {plan_id:?}, which has no audit entries");
    };
    let image_name = first.image_name.clone();
    let image_sha256 = first.image_sha256.clone();

    let events: Vec<EventRecord> = final_events
        .into_iter()
        .map(|e| EventRecord {
            timestamp: e.timestamp,
            event: e.event.clone(),
            labels: e.labels.clone(),
        })
        .collect();

    let machine = booted_machine(all_entries, &plan_id).unwrap_or(&image_name);
    let egress_denials = run_denials(all_entries, &plan_id, machine);

    let (chain_verified, chain_entry_count, verify_error) = match verification {
        Ok(count) => (true, count, None),
        Err(e) => (false, 0, Some(e.to_string())),
    };

    Ok(RunExplanation {
        run_id: run_id.to_string(),
        tenant: tenant.to_string(),
        plan_id,
        image_name,
        image_sha256,
        events,
        egress_denials,
        chain_verified,
        history_verified: history_verified && chain_verified,
        chain_entry_count,
        verify_error,
    })
}

/// The machine the run booted on, when its start record names one. A warm claim
/// runs on its standby's machine, not under the run's own name, and the
/// endpoint attributes its refusals to that machine.
fn booted_machine<'a>(entries: &'a [PlanAuditEntry], plan_id: &str) -> Option<&'a str> {
    entries
        .iter()
        .find(|e| e.plan_id.0 == plan_id && e.event == "plan.start_mode")
        .and_then(|e| e.labels.get("machine"))
        .map(String::as_str)
}

/// The refusals the per-VM endpoint recorded for this run's machine.
///
/// The endpoint holds no plan, so its entries are joined to the run by the
/// machine name they carry — the run's image name — and bounded in time: from
/// the run's first entry to its terminal one, or, for a run with no terminal
/// entry, to the next admission under the same name. A name reused by a later
/// run therefore never lends this one its refusals.
fn run_denials(entries: &[PlanAuditEntry], plan_id: &str, vm_name: &str) -> Vec<DeniedDestination> {
    let own = || entries.iter().filter(|e| e.plan_id.0 == plan_id);
    let Some(from) = own().map(|e| e.timestamp).min() else {
        return Vec::new();
    };
    let terminal = own()
        .filter(|e| e.event == "plan.exited" || e.event == "plan.failed")
        .map(|e| e.timestamp)
        .max();
    let next_admission = entries
        .iter()
        .filter(|e| {
            e.event == "plan.admitted"
                && e.image_name == vm_name
                && e.plan_id.0 != plan_id
                && e.timestamp > from
        })
        .map(|e| e.timestamp)
        .min();
    denials_in_window(entries, vm_name, from, terminal.or(next_admission)).destinations()
}

/// `key=value key=value`, sorted by key: the form the audit tail prints labels in.
pub fn label_join(labels: &BTreeMap<String, String>) -> String {
    labels
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use mvm_core::plan::ExecutionPlan;
    use mvm_hostd::audit::emitter::AuditEmitter;
    use rand::Rng;

    fn fixture_plan(tenant: &str, plan_id: &str) -> ExecutionPlan {
        mvm_core::plan::test_support::PlanFixture::new()
            .tenant(tenant)
            .plan_id(plan_id)
            .build()
    }

    #[test]
    fn collect_run_gathers_admitted_launched_exited_and_verifies_clean() {
        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-explain-1");

        emitter.emit_admitted(&plan, "host:test").unwrap();
        emitter.emit_launched(&plan, "firecracker").unwrap();
        emitter.emit_exited(&plan, 0, "firecracker").unwrap();

        let path = dir.path().join("local.jsonl");
        let explanation = collect_run(&path, &vk, "local", "plan-explain-1").unwrap();

        assert_eq!(explanation.plan_id, "plan-explain-1");
        assert_eq!(explanation.tenant, "local");
        assert_eq!(explanation.events.len(), 3);
        assert_eq!(explanation.events[0].event, "plan.admitted");
        assert_eq!(explanation.events[1].event, "plan.launched");
        assert_eq!(explanation.events[2].event, "plan.exited");
        assert!(explanation.chain_verified);
        assert_eq!(explanation.chain_entry_count, 3);
        assert!(explanation.verify_error.is_none());
        assert_eq!(explanation.outcome(), "exited with code 0");
        assert_eq!(explanation.backend().as_deref(), Some("firecracker"));
    }

    /// Record a refusal the way the per-VM endpoint does: unbound, attributed
    /// to the machine by name, into the same tenant chain.
    fn endpoint_refusal(dir: &Path, key: &SigningKey, vm: &str, target: &str, reason: &str) {
        use mvm_hostd::supervisor::audit::audit_recorder::{EventCategory, Recorder};
        let signer = mvm_hostd::supervisor::audit::audit_file::FileAuditSigner::open(
            key.clone(),
            dir.to_path_buf(),
        )
        .unwrap();
        let recorder = Recorder::new(
            std::sync::Arc::new(signer),
            mvm_core::plan::TenantId("local".into()),
        )
        .with_vm_name(vm);
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(recorder.record_unbound(
                EventCategory::Host,
                "host.flow.denied",
                [
                    ("class".to_string(), "tcp".to_string()),
                    ("target".to_string(), target.to_string()),
                    ("reason".to_string(), reason.to_string()),
                ],
            ))
            .unwrap();
    }

    /// On a chain that has rotated, `explain` authenticates the run's own
    /// entries in the live segment instead of walking every segment, says so,
    /// and still reports the run's refusals.
    #[test]
    fn a_rotated_chain_explains_a_recent_run_from_the_live_segment() {
        let dir = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set(mvm_core::config::AUDIT_SEGMENT_BYTES_ENV, "16384");
        let key = SigningKey::from_bytes(&[13; 32]);
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key.clone(), dir.path()).unwrap();
        // Fill until the first rotation, so the run below starts in a fresh live segment.
        let mut n = 0;
        while mvm_core::audit_verify::set::segment_shape(dir.path(), "local")
            .map_or(true, |shape| shape.sealed.is_empty())
        {
            let old = fixture_plan("local", &format!("plan-old-{n}"));
            emitter.emit_admitted(&old, "host:test").unwrap();
            emitter.emit_exited(&old, 0, "hvf").unwrap();
            n += 1;
        }
        let plan = fixture_plan("local", "plan-recent-1");
        emitter.emit_admitted(&plan, "host:test").unwrap();
        emitter.emit_launched(&plan, "hvf").unwrap();
        endpoint_refusal(
            dir.path(),
            &key,
            "vm-test",
            "example.com:443",
            "policy_denied",
        );

        let path = dir.path().join("local.jsonl");
        let shape = mvm_core::audit_verify::set::segment_shape(dir.path(), "local").unwrap();
        assert!(!shape.sealed.is_empty(), "the chain must have rotated");
        let explanation = collect_run(&path, &vk, "local", "plan-recent-1").unwrap();
        assert!(explanation.chain_verified);
        assert!(!explanation.history_verified);
        assert_eq!(explanation.events.len(), 2);
        assert_eq!(explanation.egress_denials.len(), 1);

        let old = collect_run(&path, &vk, "local", "plan-old-0").unwrap();
        assert!(
            old.history_verified,
            "a run outside the live segment is walked in full"
        );
    }

    /// A refusal removed from the live segment must not pass for a clean record,
    /// even when the line after it is not one the run's own lookups would parse.
    #[test]
    fn a_refusal_removed_from_the_live_segment_is_not_reported_as_authentic() {
        let dir = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set(mvm_core::config::AUDIT_SEGMENT_BYTES_ENV, "16384");
        let key = SigningKey::from_bytes(&[15; 32]);
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key.clone(), dir.path()).unwrap();
        let mut n = 0;
        while mvm_core::audit_verify::set::segment_shape(dir.path(), "local")
            .map_or(true, |shape| shape.sealed.is_empty())
        {
            let old = fixture_plan("local", &format!("plan-old-{n}"));
            emitter.emit_admitted(&old, "host:test").unwrap();
            emitter.emit_exited(&old, 0, "hvf").unwrap();
            n += 1;
        }
        let plan = fixture_plan("local", "plan-tamper-1");
        emitter.emit_admitted(&plan, "host:test").unwrap();
        emitter.emit_launched(&plan, "hvf").unwrap();
        endpoint_refusal(
            dir.path(),
            &key,
            "vm-test",
            "example.com:443",
            "policy_denied",
        );
        endpoint_refusal(
            dir.path(),
            &key,
            "vm-other",
            "other.example:443",
            "policy_denied",
        );
        let path = dir.path().join("local.jsonl");
        let clean = collect_run(&path, &vk, "local", "plan-tamper-1").unwrap();
        assert!(clean.chain_verified && !clean.history_verified);
        assert_eq!(clean.egress_denials.len(), 1);

        let content = std::fs::read_to_string(&path).unwrap();
        let kept: Vec<&str> = content
            .lines()
            .filter(|line| !line.contains("example.com:443"))
            .collect();
        assert_eq!(kept.len() + 1, content.lines().count());
        std::fs::write(&path, kept.join("\n") + "\n").unwrap();

        let tampered = collect_run(&path, &vk, "local", "plan-tamper-1").unwrap();
        assert!(
            !tampered.chain_verified,
            "a removed refusal must not verify"
        );
    }

    /// A run whose start is in a retired segment is not explained from the live
    /// one, which would drop its beginning: the whole chain is walked instead.
    #[test]
    fn a_run_that_straddles_a_rotation_is_walked_in_full() {
        let dir = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set(mvm_core::config::AUDIT_SEGMENT_BYTES_ENV, "4096");
        let key = SigningKey::from_bytes(&[14; 32]);
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let mut n = 0;
        while mvm_core::audit_verify::set::segment_shape(dir.path(), "local")
            .is_ok_and(|shape| shape.sealed.is_empty())
            || n == 0
        {
            let old = fixture_plan("local", &format!("plan-old-{n}"));
            emitter.emit_admitted(&old, "host:test").unwrap();
            n += 1;
        }
        // The run is admitted, another run fills the live segment until it
        // rotates, and only then does the first run launch.
        let plan = fixture_plan("local", "plan-straddle-1");
        emitter.emit_admitted(&plan, "host:test").unwrap();
        let sealed = |dir: &Path| {
            mvm_core::audit_verify::set::segment_shape(dir, "local")
                .map_or(0, |shape| shape.sealed.len())
        };
        let before = sealed(dir.path());
        let other = fixture_plan("local", "plan-other-1");
        while sealed(dir.path()) == before {
            emitter.emit_launched(&other, "hvf").unwrap();
        }
        emitter.emit_launched(&plan, "hvf").unwrap();

        let path = dir.path().join("local.jsonl");
        let explanation = collect_run(&path, &vk, "local", "plan-straddle-1").unwrap();
        assert!(explanation.history_verified);
        assert_eq!(explanation.events.len(), 2);
    }

    /// A warm claim runs on its standby's machine; its refusals are recorded
    /// under that name and still belong to the run that claimed it.
    #[test]
    fn a_warm_claimed_runs_denials_are_found_under_its_standbys_machine() {
        let dir = tempfile::tempdir().unwrap();
        let key = SigningKey::from_bytes(&[12; 32]);
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key.clone(), dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-warm-1");
        emitter.emit_admitted(&plan, "host:test").unwrap();
        emitter.emit_launched(&plan, "hvf").unwrap();
        emitter
            .emit_start_mode(&plan, "warm", None, "vm-standby-1")
            .unwrap();
        endpoint_refusal(
            dir.path(),
            &key,
            "vm-standby-1",
            "example.com:443",
            "policy_denied",
        );
        endpoint_refusal(
            dir.path(),
            &key,
            "vm-standby-2",
            "someone-else.example:443",
            "policy_denied",
        );
        emitter.emit_exited(&plan, 0, "hvf").unwrap();

        let path = dir.path().join("local.jsonl");
        let explanation = collect_run(&path, &vk, "local", "plan-warm-1").unwrap();
        let denied = &explanation.egress_denials;
        assert_eq!(denied.len(), 1, "{denied:?}");
        assert_eq!(denied[0].destination, "example.com:443");
    }

    /// `explain` shows the machine's refusals from its own run and no other:
    /// not a different machine's, and not a later run's under the same name.
    #[test]
    fn collect_run_reports_the_runs_egress_denials_and_no_one_elses() {
        let dir = tempfile::tempdir().unwrap();
        let key = SigningKey::from_bytes(&[11; 32]);
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key.clone(), dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-denied-1");
        emitter.emit_admitted(&plan, "host:test").unwrap();
        emitter.emit_launched(&plan, "firecracker").unwrap();
        endpoint_refusal(
            dir.path(),
            &key,
            "vm-test",
            "api.example.com:443",
            "policy_denied",
        );
        endpoint_refusal(
            dir.path(),
            &key,
            "vm-test",
            "api.example.com:443",
            "policy_denied",
        );
        endpoint_refusal(
            dir.path(),
            &key,
            "vm-test",
            "169.254.169.254:80",
            "cloud_metadata",
        );
        endpoint_refusal(
            dir.path(),
            &key,
            "vm-other",
            "other.example:443",
            "policy_denied",
        );
        emitter.emit_exited(&plan, 7, "firecracker").unwrap();
        let later = fixture_plan("local", "plan-denied-2");
        emitter.emit_admitted(&later, "host:test").unwrap();
        endpoint_refusal(
            dir.path(),
            &key,
            "vm-test",
            "later.example:443",
            "policy_denied",
        );

        let path = dir.path().join("local.jsonl");
        let explanation = collect_run(&path, &vk, "local", "plan-denied-1").unwrap();
        assert!(explanation.chain_verified, "{:?}", explanation.verify_error);
        let denied = &explanation.egress_denials;
        assert_eq!(denied.len(), 2, "{denied:?}");
        assert_eq!(denied[0].destination, "api.example.com:443");
        assert_eq!(denied[0].count, 2);
        assert_eq!(
            denied[0].hint,
            "allow with --allow-host api.example.com:443"
        );
        assert_eq!(denied[1].reason, "cloud_metadata");
        assert!(
            !denied[1].hint.contains("--allow-host"),
            "{}",
            denied[1].hint
        );

        let json = serde_json::to_value(&explanation).unwrap();
        assert_eq!(json["egress_denials"][0]["count"], 2);
        assert_eq!(json["egress_denials"][1]["remedy"]["kind"], "never");

        // The later run under the same name sees only its own.
        let later = collect_run(&path, &vk, "local", "plan-denied-2").unwrap();
        assert_eq!(later.egress_denials.len(), 1);
        assert_eq!(later.egress_denials[0].destination, "later.example:443");
    }

    #[test]
    fn collect_run_matches_by_plan_id_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-abcdef123456");
        emitter.emit_admitted(&plan, "host:test").unwrap();

        let path = dir.path().join("local.jsonl");
        let explanation = collect_run(&path, &vk, "local", "plan-abcdef").unwrap();
        assert_eq!(explanation.plan_id, "plan-abcdef123456");
    }

    #[test]
    fn collect_run_matches_by_image_name() {
        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-img-match");
        emitter.emit_admitted(&plan, "host:test").unwrap();

        let path = dir.path().join("local.jsonl");
        // PlanFixture's image name is fixed at "vm-test".
        let explanation = collect_run(&path, &vk, "local", "vm-test").unwrap();
        assert_eq!(explanation.plan_id, "plan-img-match");
    }

    #[test]
    fn collect_run_errors_on_ambiguous_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        emitter
            .emit_admitted(&fixture_plan("local", "plan-dup-aaa"), "host:test")
            .unwrap();
        emitter
            .emit_admitted(&fixture_plan("local", "plan-dup-bbb"), "host:test")
            .unwrap();

        let path = dir.path().join("local.jsonl");
        let err = collect_run(&path, &vk, "local", "plan-dup").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("multiple runs"), "{msg}");
        assert!(msg.contains("plan-dup-aaa"), "{msg}");
        assert!(msg.contains("plan-dup-bbb"), "{msg}");
    }

    #[test]
    fn collect_run_errors_when_no_match() {
        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        emitter
            .emit_admitted(&fixture_plan("local", "plan-real"), "host:test")
            .unwrap();

        let path = dir.path().join("local.jsonl");
        let err = collect_run(&path, &vk, "local", "no-such-run").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("no run"), "{msg}");
        assert!(msg.contains("no-such-run"), "{msg}");
    }

    #[test]
    fn collect_run_errors_when_chain_file_missing() {
        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let vk = key.verifying_key();
        let path = dir.path().join("local.jsonl");
        let err = collect_run(&path, &vk, "local", "anything").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("no audit chain"), "{msg}");
    }

    #[test]
    fn collect_run_reports_tampered_chain_loudly_but_still_returns_the_run() {
        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-tamper");
        emitter.emit_admitted(&plan, "host:test").unwrap();
        emitter.emit_launched(&plan, "firecracker").unwrap();

        let path = dir.path().join("local.jsonl");
        let content = std::fs::read_to_string(&path).unwrap();
        // Flip a byte inside the event name — signature no longer matches.
        let tampered = content.replacen("plan.launched", "plan.fakeville", 1);
        std::fs::write(&path, tampered).unwrap();

        let explanation = collect_run(&path, &vk, "local", "plan-tamper").unwrap();
        assert!(!explanation.chain_verified);
        assert!(explanation.verify_error.is_some());
        // The run's own events are still surfaced — a drift must be loud,
        // not hidden by refusing to render anything.
        assert!(!explanation.events.is_empty());
    }

    #[test]
    fn label_join_renders_key_value_pairs_sorted() {
        let mut labels = BTreeMap::new();
        labels.insert("b".to_string(), "2".to_string());
        labels.insert("a".to_string(), "1".to_string());
        assert_eq!(label_join(&labels), "a=1 b=2");
    }
}
