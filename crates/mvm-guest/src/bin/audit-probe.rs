//! `audit-probe` — in-guest driver that exercises `host.audit.v1` from inside
//! a booted microVM.
//!
//! Test fixture only. It is the in-guest counterpart to the host-side
//! round-trip test: a workload that calls [`mvm_guest::host_audit::emit`],
//! dialing `connect_host_vsock(BROKER_PORT)`, so the entry travels the full
//! spine — guest → backend vsock splice → per-VM `mvm-broker` →
//! `mvm-audit-signer` → the per-VM `<tenant>.<vm>.workload.jsonl` chain. A
//! fixture image bakes it at `/usr/local/bin/audit-probe` and runs it as the
//! entrypoint; the host then verifies the chain.
//!
//! Modes (first argv, default `emit`):
//!
//! - `emit` — append one normal record; exit 0 on success.
//! - `oversized` — append a record over the host's 4 KiB per-record cap; success means the host refused it with `BadRequest`.
//! - `rate` — burst more emits than the 20/s token bucket allows; success means at least one came back `RateLimited`.
//! - `all` — run `emit`, then `oversized`, then `rate` in sequence.
//!
//! It cannot express a `category`: [`mvm_core::protocol::host_audit::EmitRequest`]
//! has no such field, so the host's forced `workload_audit` stamp is the only
//! category a workload entry can carry — the verifier confirms that host-side.
//!
//! Output contract: one `audit-probe: <mode> ...` line per step on stdout (the
//! guest console the backend captures to `console.log`). Exit code is 0 when
//! every requested step met its success condition, non-zero otherwise, so the
//! entrypoint's exit status is itself an assertion.
//!
//! Not shipped in production: `nix/packages/mvm-guest-agent.nix` selects only
//! the agent + seccomp bins, and only the opt-in `withAuditProbe` mkGuest flag
//! bakes this binary — prod rootfs builds never include it.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("audit-probe runs inside Linux microVM guests only");
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
fn main() {
    std::process::exit(linux::run());
}

#[cfg(target_os = "linux")]
mod linux {
    use mvm_core::protocol::host_audit::EmitRequest;
    use mvm_guest::host_audit::{self, AuditError};

    /// Broker dial timeout, seconds.
    const TIMEOUT_SECS: u64 = 5;
    /// Records to burst in `rate` mode — comfortably over the 20/s bucket so at
    /// least one must be refused once the initial capacity drains.
    const RATE_BURST: usize = 40;
    /// Attempts the first `emit` makes before giving up — covers the brief
    /// boot window before the BROKER_PORT host-listen splice is wired.
    const AUDIT_CONNECT_RETRIES: usize = 20;

    /// Build the workload record for `action`/`seq`. Pure so the field shape is
    /// unit-testable without a broker. `ts` is a workload field the host passes
    /// through verbatim (it stamps its own authoritative time), so a fixed
    /// value keeps the fixture deterministic.
    pub(crate) fn build_record(action: &str, seq: usize) -> EmitRequest {
        EmitRequest {
            ts: "2026-06-16T00:00:00Z".to_string(),
            fields: serde_json::json!({
                "probe": "audit-probe",
                "action": action,
                "seq": seq,
            }),
        }
    }

    /// `emit`: one normal record must land. Prints the returned chain head.
    /// Retries on transport errors so the very first guest dial doesn't lose a
    /// race against the supervisor wiring up the BROKER_PORT host-listen splice
    /// at boot — a real workload that emits early would hit the same window.
    fn run_emit() -> bool {
        let record = build_record("probe-emit", 0);
        for attempt in 0..AUDIT_CONNECT_RETRIES {
            match host_audit::emit(&record, TIMEOUT_SECS) {
                Ok(resp) => {
                    println!("audit-probe: emit ok chain_head={}", resp.chain_head);
                    return true;
                }
                // Transport/Unavailable means the broker leg isn't reachable
                // yet (boot race) — back off briefly and retry.
                Err(e @ (AuditError::Transport(_) | AuditError::Unavailable(_)))
                    if attempt + 1 < AUDIT_CONNECT_RETRIES =>
                {
                    println!("audit-probe: emit retry {attempt} (transport not ready: {e})");
                    std::thread::sleep(std::time::Duration::from_millis(250));
                }
                Err(e) => {
                    println!("audit-probe: emit FAILED err={e}");
                    return false;
                }
            }
        }
        false
    }

    /// `oversized`: a record past the 4 KiB cap. Success = the host refuses it
    /// with `BadRequest` (the cap is enforced host-side; the guest cannot
    /// bypass it).
    fn run_oversized() -> bool {
        let big = "x".repeat(5000);
        let record = EmitRequest {
            ts: "2026-06-16T00:00:00Z".to_string(),
            fields: serde_json::json!({ "probe": "audit-probe", "blob": big }),
        };
        match host_audit::emit(&record, TIMEOUT_SECS) {
            Err(AuditError::BadRequest(msg)) => {
                println!("audit-probe: oversized bad_request=true msg={msg}");
                true
            }
            Ok(resp) => {
                println!(
                    "audit-probe: oversized UNEXPECTED_OK chain_head={}",
                    resp.chain_head
                );
                false
            }
            Err(e) => {
                println!("audit-probe: oversized UNEXPECTED_ERR err={e}");
                false
            }
        }
    }

    /// `rate`: burst past the token bucket. Success = at least one emit returns
    /// `RateLimited`.
    fn run_rate() -> bool {
        let mut accepted = 0usize;
        let mut limited = 0usize;
        let mut other = 0usize;
        for seq in 0..RATE_BURST {
            match host_audit::emit(&build_record("probe-rate", seq), TIMEOUT_SECS) {
                Ok(_) => accepted += 1,
                Err(AuditError::RateLimited) => limited += 1,
                Err(_) => other += 1,
            }
        }
        println!(
            "audit-probe: rate emitted={RATE_BURST} accepted={accepted} limited={limited} other={other}"
        );
        limited > 0
    }

    pub(crate) fn run() -> i32 {
        let mode = std::env::args()
            .nth(1)
            .unwrap_or_else(|| "emit".to_string());
        let ok = match mode.as_str() {
            "emit" => run_emit(),
            "oversized" => run_oversized(),
            "rate" => run_rate(),
            "all" => {
                // Run every step; the entrypoint exit status is 0 only if all pass.
                // `emit` first so a clean single entry is in the chain before the
                // burst, then the negative-path checks.
                let e = run_emit();
                let o = run_oversized();
                let r = run_rate();
                e && o && r
            }
            other => {
                println!("audit-probe: unknown mode {other:?}");
                false
            }
        };
        if ok { 0 } else { 1 }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn build_record_carries_no_category_and_tags_the_action() {
            let r = build_record("probe-emit", 7);
            // The workload cannot express a category — the field does not exist
            // on EmitRequest, so the host's workload_audit stamp is the only one.
            assert!(r.fields.get("category").is_none());
            assert_eq!(r.fields["probe"], "audit-probe");
            assert_eq!(r.fields["action"], "probe-emit");
            assert_eq!(r.fields["seq"], 7);
        }
    }
}
