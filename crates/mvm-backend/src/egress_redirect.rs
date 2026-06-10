//! Plan 129 — per-VM transparent egress redirect for the Firecracker TAP path.
//! Installs an nft `nat prerouting` REDIRECT scoped to the guest's TAP
//! interface so the guest's outbound HTTP (:80) is steered to the host-side
//! substitution terminator (recoverable via SO_ORIGINAL_DST). iifname-scoping
//! means ONLY traffic arriving on this guest's tap is redirected — the host's
//! own egress never is. nft (box is nft-only); needs CAP_NET_ADMIN (the FC
//! launch path is already privileged). RAII: Drop tears the table down.
//!
//! Lives in `mvm-backend` (not `mvm-hostd`) because the Firecracker launch path
//! here is its sole consumer and `mvm-hostd → mvm-backend` already; pulling it
//! up into `mvm-hostd` would cycle. The module is self-contained (nft + argv),
//! so co-locating it with the backend that wires it costs nothing.

use anyhow::{Context, Result, bail};
use std::process::Command;

/// Per-VM terminator port = base + slot index, so concurrent slots never share
/// a host-side terminator port. `u16` is wide enough; slot index is `u8`.
pub const TERMINATOR_PORT_BASE: u16 = 18080;

/// Derive this VM's terminator port from its 0-based slot index. The `u8`
/// `slot_index` caps the sum at 18080+255, so the `u16` add can't overflow.
pub fn terminator_port_for(slot_index: u8) -> u16 {
    TERMINATOR_PORT_BASE + slot_index as u16
}

/// RAII handle for a per-VM nft redirect table. `Drop` tears it down so an
/// early return in the caller never strands a half-built table.
pub struct EgressRedirect {
    table: String,
}

/// nft table names are restricted to `[A-Za-z0-9_]` — map every other char in
/// `vm_name` to `_` so an arbitrary VM name yields a valid, collision-stable
/// table identifier.
fn redirect_table_name(vm: &str) -> String {
    let sanitized: String = vm
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    format!("mvm_egress_{sanitized}")
}

/// Guest destination ports steered to the terminator. `:80` is the Stage 1b
/// cleartext path; `:443` is the Stage 2 TLS-termination path — the terminator
/// recovers which one via `SO_ORIGINAL_DST` and branches accordingly.
pub const REDIRECTED_DPORTS: [u16; 2] = [80, 443];

/// The pure, unit-tested core: exact argv tokens for one redirect rule matching
/// `dport`. argv form needs NO quotes around the iface — quoting is shell-only.
pub fn nft_rule_argv(table: &str, tap_iface: &str, dport: u16, term_port: u16) -> Vec<String> {
    vec![
        "add".into(),
        "rule".into(),
        "ip".into(),
        table.into(),
        "prerouting".into(),
        "iifname".into(),
        tap_iface.into(),
        "tcp".into(),
        "dport".into(),
        dport.to_string(),
        "redirect".into(),
        "to".into(),
        format!(":{term_port}"),
    ]
}

/// Run `nft` directly. The FC parent context that calls this is already
/// privileged (CAP_NET_ADMIN) — do NOT add sudo.
fn nft(args: &[&str]) -> Result<()> {
    let status = Command::new("nft")
        .args(args)
        .status()
        .with_context(|| format!("spawn nft {args:?}"))?;
    if !status.success() {
        bail!("nft {args:?} failed: {status}");
    }
    Ok(())
}

impl EgressRedirect {
    /// Idempotently install the per-VM redirect table+chain+rule. Fails closed:
    /// any step error tears down the partial table before propagating.
    pub fn install(vm_name: &str, tap_iface: &str, term_port: u16) -> Result<Self> {
        let table = redirect_table_name(vm_name);

        // Drop any stale same-name table from a prior crashed run (ignore failure —
        // the common case is "no such table").
        let _ = nft(&["delete", "table", "ip", &table]);

        let r = (|| -> Result<()> {
            nft(&["add", "table", "ip", &table])?;
            // priority -100 = the standard nat prerouting hook point; the brace
            // body is one argv token (nft parses it itself).
            nft(&[
                "add",
                "chain",
                "ip",
                &table,
                "prerouting",
                "{ type nat hook prerouting priority -100 ; }",
            ])?;
            // One REDIRECT rule per steered dport (:80 cleartext, :443 TLS) into
            // the same per-VM table — the terminator demuxes via SO_ORIGINAL_DST.
            for dport in REDIRECTED_DPORTS {
                let rule = nft_rule_argv(&table, tap_iface, dport, term_port);
                let rule_ref: Vec<&str> = rule.iter().map(String::as_str).collect();
                nft(&rule_ref)?;
            }
            Ok(())
        })();

        if let Err(e) = r {
            let _ = nft(&["delete", "table", "ip", &table]);
            return Err(e);
        }
        Ok(Self { table })
    }

    pub fn teardown(&self) -> Result<()> {
        nft(&["delete", "table", "ip", &self.table])
    }

    /// Forget the RAII guard without tearing the table down. The FC launch path
    /// installs the redirect for a VM that *keeps running* after
    /// `run_from_build` returns, so the table must outlive the handle; `stop_vm`
    /// removes it by name via [`teardown_by_name`]. Calling this is the
    /// deliberate, safe leak of the nft table (not the process).
    pub fn persist(self) {
        // Drop-skip: `into_inner`-style consume so `Drop` never runs.
        std::mem::forget(self);
    }
}

/// Remove a VM's redirect table by name, reconstructing it from `vm_name`.
/// Idempotent: a missing table (VM had no secrets, or already cleaned) is not
/// an error. Used by the FC `stop_vm` teardown, which has only the VM name —
/// not the live [`EgressRedirect`] handle (it was `persist`ed at launch).
pub fn teardown_by_name(vm_name: &str) -> Result<()> {
    let table = redirect_table_name(vm_name);
    // `nft delete table` errors on a missing table; swallow that one case so a
    // secret-free VM (no table installed) stops cleanly. Any other failure
    // (e.g. nft missing) propagates so the caller can log it.
    let output = Command::new("nft")
        .args(["delete", "table", "ip", &table])
        .output()
        .with_context(|| format!("spawn nft delete table ip {table}"))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("No such file or directory") || stderr.contains("does not exist") {
        return Ok(());
    }
    bail!("nft delete table ip {table} failed: {stderr}");
}

impl Drop for EgressRedirect {
    fn drop(&mut self) {
        let _ = self.teardown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nft_rule_argv_exact_tokens() {
        let got = nft_rule_argv("mvm_egress_demo", "tap-demo", 80, 18080);
        let want: Vec<String> = vec![
            "add",
            "rule",
            "ip",
            "mvm_egress_demo",
            "prerouting",
            "iifname",
            "tap-demo",
            "tcp",
            "dport",
            "80",
            "redirect",
            "to",
            ":18080",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        assert_eq!(got, want);
    }

    #[test]
    fn install_redirects_both_80_and_443_to_the_terminator() {
        // Stage 2: the terminator handles both cleartext (:80) and TLS (:443);
        // the redirect must steer BOTH guest ports to the same terminator port
        // (SO_ORIGINAL_DST recovers which one it was). Assert the per-port rule
        // argv for each — the pure core the side-effecting install emits.
        let p443 = nft_rule_argv("mvm_egress_demo", "tap-demo", 443, 18080);
        assert_eq!(p443[9], "443");
        assert_eq!(p443.last().unwrap(), ":18080");
        let p80 = nft_rule_argv("mvm_egress_demo", "tap-demo", 80, 18080);
        assert_eq!(p80[9], "80");
        assert_eq!(p80.last().unwrap(), ":18080");
        // Same table + iface + target port; only the matched dport differs.
        assert_eq!(&p80[..9], &p443[..9]);
        assert_eq!(REDIRECTED_DPORTS, [80, 443]);
    }

    #[test]
    fn redirect_table_name_sanitizes_non_identifier_chars() {
        assert_eq!(
            redirect_table_name("vm.with-weird/chars"),
            "mvm_egress_vm_with_weird_chars"
        );
    }

    #[test]
    fn redirect_table_name_keeps_alnum_and_underscore() {
        assert_eq!(redirect_table_name("vm_01AZ"), "mvm_egress_vm_01AZ");
    }

    #[test]
    fn terminator_port_offsets_from_base_by_slot_index() {
        assert_eq!(terminator_port_for(0), TERMINATOR_PORT_BASE);
        assert_eq!(terminator_port_for(1), TERMINATOR_PORT_BASE + 1);
        assert_eq!(terminator_port_for(7), TERMINATOR_PORT_BASE + 7);
        assert_eq!(terminator_port_for(255), TERMINATOR_PORT_BASE + 255);
    }
}
