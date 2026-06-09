//! Plan 129 — per-VM transparent egress redirect for the Firecracker TAP path.
//! Installs an nft `nat prerouting` REDIRECT scoped to the guest's TAP
//! interface so the guest's outbound HTTP (:80) is steered to the host-side
//! substitution terminator (recoverable via SO_ORIGINAL_DST). iifname-scoping
//! means ONLY traffic arriving on this guest's tap is redirected — the host's
//! own egress never is. nft (box is nft-only); needs CAP_NET_ADMIN (the FC
//! launch path is already privileged). RAII: Drop tears the table down.

use anyhow::{Context, Result, bail};
use std::process::Command;

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

/// The pure, unit-tested core: exact argv tokens for the redirect rule.
/// argv form needs NO quotes around the iface — quoting is shell-only.
pub fn nft_rule_argv(table: &str, tap_iface: &str, term_port: u16) -> Vec<String> {
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
        "80".into(),
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
            let rule = nft_rule_argv(&table, tap_iface, term_port);
            let rule_ref: Vec<&str> = rule.iter().map(String::as_str).collect();
            nft(&rule_ref)
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
        let got = nft_rule_argv("mvm_egress_demo", "tap-demo", 18080);
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
}
