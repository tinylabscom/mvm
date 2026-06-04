//! In-guest egress lockdown — Plan 73 Followup B.2.y / ADR-047.
//!
//! Defense-in-depth on top of `mvm-egress-proxy`: even if a
//! build step ignores `HTTP_PROXY` / `HTTPS_PROXY` env vars, its
//! packets get DROPped before leaving the VM because of an
//! `OUTPUT`-chain default-deny rule. Only loopback traffic (so
//! the in-VM proxy is reachable from `localhost:8443`) and
//! outbound traffic owned by the proxy's uid are allowed out.
//!
//! Called from `mvm-host-vm-init`'s boot sequence after the
//! basic `setup_network()`. Failure is **fatal** — without the
//! lockdown, the builder VM's egress allowlist is unenforced and
//! ADR-002's Claim 9 transitive trust onto the builder VM has no
//! defense layer.

use std::process::Command;

/// Dedicated uid the in-VM `mvm-egress-proxy` runs under. The
/// iptables `--uid-owner` rule keys off this value, so it must
/// match the uid the proxy actually executes as
/// (`crates/mvm-host-vm-init/src/proxy.rs` passes the same
/// constant to `Command::uid` before exec). Picked between
/// `mk-guest.nix`'s `entrypointUid` (default 1000) and
/// `agentUid` (default 1900) to avoid collisions.
pub const PROXY_UID: u32 = 1801;

/// Adapter trait so unit tests can inject a recording / failing
/// fake without binding a real iptables runtime. Each call
/// corresponds to one iptables invocation.
pub trait IptablesRunner {
    fn run(&self, args: &[&str]) -> Result<(), String>;
}

/// Production runner — shells out to `iptables` on `$PATH`. The
/// builder-vm rootfs ships busybox iptables via the flake's
/// `builderPackages` set.
pub struct SystemIptables;

impl IptablesRunner for SystemIptables {
    fn run(&self, args: &[&str]) -> Result<(), String> {
        let output = Command::new("iptables")
            .args(args)
            .output()
            .map_err(|e| format!("spawn iptables {args:?}: {e}"))?;
        if !output.status.success() {
            return Err(format!(
                "iptables {args:?} exited {} (stderr: {})",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim(),
            ));
        }
        Ok(())
    }
}

/// Install the three `OUTPUT`-chain rules that lock down egress
/// to the proxy uid only. Order matters:
///
/// 1. Loopback ACCEPT — the proxy listens on `127.0.0.1:8443`
///    and must remain reachable from other guest processes.
/// 2. Owner-match ACCEPT — only the proxy's uid gets outbound.
/// 3. Default-deny — set the `OUTPUT` chain's policy to DROP so
///    anything that doesn't match the prior ACCEPTs is dropped.
///
/// Returns an error on the first rule that fails to install. A
/// partial-install state is left behind on failure (e.g., rules
/// 1 and 2 installed but policy not yet flipped) — the caller
/// must treat the error as fatal and refuse to run the workload,
/// because that partial state is more permissive than the
/// pre-call baseline (no rules) and just leaving it in place
/// would let unrestricted egress continue.
pub fn install_egress_lockdown(runner: &dyn IptablesRunner, proxy_uid: u32) -> Result<(), String> {
    let uid_str = proxy_uid.to_string();
    runner.run(&["-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"])?;
    runner.run(&[
        "-A",
        "OUTPUT",
        "-m",
        "owner",
        "--uid-owner",
        &uid_str,
        "-j",
        "ACCEPT",
    ])?;
    runner.run(&["-P", "OUTPUT", "DROP"])?;
    Ok(())
}

/// Plan 89 W3 part 12 — re-install the egress lockdown from a
/// known-good in-binary recipe.
///
/// `install_egress_lockdown` runs once at boot. In the persistent
/// builder VM jobs share the kernel's iptables state across
/// dispatches — a build that runs `iptables -I OUTPUT 1 -j
/// ACCEPT` (or exploits a `CAP_NET_ADMIN` leak via the new mount
/// namespace from `unshare --mount`) poisons every subsequent
/// job. The persistent dispatch loop calls this between
/// dispatches to reset the chain.
///
/// Implementation: flush the OUTPUT chain, then re-install the 3
/// baseline rules. Cheap (~10 ms per the plan's estimate) and
/// deterministic. The OUTPUT chain's *policy* survives `-F`, so
/// the brief window between flush and rule re-install is fail-
/// closed if the policy was DROP already; `install_egress_lockdown`
/// re-asserts the policy to DROP regardless.
///
/// On any rule failure the chain is left in whatever partial
/// state the failure produced. Callers should treat the error as
/// a hard signal that iptables is broken and refuse to run the
/// dispatched job — that's safer than letting a possibly-too-
/// permissive chain reach the build. See the F7 entry in the
/// Plan 89 security-scan findings table.
pub fn reapply_egress_lockdown(runner: &dyn IptablesRunner, proxy_uid: u32) -> Result<(), String> {
    runner.run(&["-F", "OUTPUT"])?;
    install_egress_lockdown(runner, proxy_uid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct RecordingRunner {
        invocations: RefCell<Vec<Vec<String>>>,
        fail_at: Option<usize>,
    }

    impl RecordingRunner {
        fn new() -> Self {
            Self {
                invocations: RefCell::new(Vec::new()),
                fail_at: None,
            }
        }

        fn fail_at(idx: usize) -> Self {
            Self {
                invocations: RefCell::new(Vec::new()),
                fail_at: Some(idx),
            }
        }
    }

    impl IptablesRunner for RecordingRunner {
        fn run(&self, args: &[&str]) -> Result<(), String> {
            let mut invocations = self.invocations.borrow_mut();
            let idx = invocations.len();
            invocations.push(args.iter().map(|s| s.to_string()).collect());
            if Some(idx) == self.fail_at {
                Err(format!("forced failure at invocation {idx}"))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn emits_three_rules_in_order() {
        let runner = RecordingRunner::new();
        install_egress_lockdown(&runner, 1801).expect("happy path");
        let invocations = runner.invocations.borrow();
        assert_eq!(invocations.len(), 3);

        // Rule 1: loopback ACCEPT.
        assert!(invocations[0].iter().any(|a| a == "-o"));
        assert!(invocations[0].iter().any(|a| a == "lo"));
        assert!(invocations[0].iter().any(|a| a == "ACCEPT"));

        // Rule 2: owner-match ACCEPT for our uid.
        assert!(invocations[1].iter().any(|a| a == "--uid-owner"));
        assert!(invocations[1].iter().any(|a| a == "1801"));
        assert!(invocations[1].iter().any(|a| a == "ACCEPT"));

        // Rule 3: OUTPUT chain default policy DROP.
        assert!(invocations[2].iter().any(|a| a == "-P"));
        assert!(invocations[2].iter().any(|a| a == "OUTPUT"));
        assert!(invocations[2].iter().any(|a| a == "DROP"));
    }

    #[test]
    fn stops_at_first_failure() {
        let runner = RecordingRunner::fail_at(0);
        let result = install_egress_lockdown(&runner, 1801);
        assert!(result.is_err());
        assert_eq!(runner.invocations.borrow().len(), 1);
    }

    #[test]
    fn stops_at_middle_failure() {
        let runner = RecordingRunner::fail_at(1);
        let result = install_egress_lockdown(&runner, 1801);
        assert!(result.is_err());
        assert_eq!(
            runner.invocations.borrow().len(),
            2,
            "rule 2 attempted, rule 3 (DROP policy) not reached",
        );
    }

    #[test]
    fn uses_provided_uid() {
        let runner = RecordingRunner::new();
        install_egress_lockdown(&runner, 9999).expect("happy path");
        assert!(
            runner.invocations.borrow()[1].iter().any(|a| a == "9999"),
            "uid passed through to --uid-owner",
        );
    }

    #[test]
    fn proxy_uid_constant_avoids_known_uids() {
        // 0 = root (would defeat the rule); 1000 = mkGuest's
        // default entrypointUid; 1900 = its default agentUid.
        assert_ne!(PROXY_UID, 0);
        assert_ne!(PROXY_UID, 1000);
        assert_ne!(PROXY_UID, 1900);
    }

    /// Plan 89 W3 part 12 — re-apply emits one flush then the
    /// three baseline rules, in that order. Catches the case
    /// where someone reorders to install-then-flush (which would
    /// wipe what they just installed).
    #[test]
    fn reapply_flushes_then_reinstalls() {
        let runner = RecordingRunner::new();
        reapply_egress_lockdown(&runner, 1801).expect("happy path");
        let invocations = runner.invocations.borrow();
        assert_eq!(invocations.len(), 4, "expected -F + 3 baseline rules");

        // 1: flush OUTPUT chain.
        assert!(invocations[0].iter().any(|a| a == "-F"));
        assert!(invocations[0].iter().any(|a| a == "OUTPUT"));

        // 2-4: identical to the install_egress_lockdown sequence
        // — re-uses the same code path.
        assert!(invocations[1].iter().any(|a| a == "-o"));
        assert!(invocations[1].iter().any(|a| a == "lo"));
        assert!(invocations[2].iter().any(|a| a == "--uid-owner"));
        assert!(invocations[2].iter().any(|a| a == "1801"));
        assert!(invocations[3].iter().any(|a| a == "-P"));
        assert!(invocations[3].iter().any(|a| a == "DROP"));
    }

    /// Plan 89 W3 part 12 — a flush failure short-circuits before
    /// the re-install runs. The caller is supposed to fail closed
    /// on the returned Err; this test pins the "we don't continue
    /// past flush" guarantee.
    #[test]
    fn reapply_stops_at_flush_failure() {
        let runner = RecordingRunner::fail_at(0);
        let result = reapply_egress_lockdown(&runner, 1801);
        assert!(result.is_err());
        assert_eq!(
            runner.invocations.borrow().len(),
            1,
            "only the flush was attempted",
        );
    }

    /// Plan 89 W3 part 12 — if any of the install rules fails
    /// after the flush, the chain ends up in a partial state.
    /// `reapply_egress_lockdown` surfaces the error so the
    /// dispatch loop can refuse the next job. We pin the
    /// invocation count so we know the partial state is exactly
    /// "flushed + one rule installed" (rule 2 attempted, rule 3
    /// not reached).
    #[test]
    fn reapply_stops_at_install_failure() {
        // fail_at(2) skips invocation 0 (flush) and 1 (loopback
        // accept), and fails invocation 2 (owner-match accept).
        let runner = RecordingRunner::fail_at(2);
        let result = reapply_egress_lockdown(&runner, 1801);
        assert!(result.is_err());
        assert_eq!(runner.invocations.borrow().len(), 3);
    }
}
