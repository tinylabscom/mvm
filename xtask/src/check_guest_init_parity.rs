//! `xtask check-guest-init-parity`
//!
//! Guest init parity: a workload guest is brought up by one of two inits —
//! the guest agent's
//! activation path when the universal initramfs boots it as PID 1. Both must run
//! the same post-mount setup, and they do it by calling one shared
//! `provision_guest_environment`.
//!
//! This gate exists because that parity was silently lost once. The universal
//! initramfs replaced the per-rootfs init but carried over only its mounting: the
//! workload booted with `lo` down, no resolver, and nothing listening on the
//! loopback proxy port, while still being handed the proxy environment
//! variables. Every egress attempt failed as `Network unreachable` rather than
//! as a policy denial, and nothing in CI noticed — the guest booted, so the only
//! signal was a workload that could not reach anything.
//!
//! Three assertions:
//!
//! - **A — both inits call the shared bootstrap.** Neither may open-code the
//!   steps or skip them. A third init added later trips this too, because the
//!   entry-point list is the ledger.
//! - **B — the shared bootstrap still performs every step.** Each required step
//!   is named in `provision_guest_environment`, so deleting one is a gate
//!   failure rather than a silent capability loss in the guest.
//! - **C — the agent runs it before dropping privilege.** The steps mount, write
//!   into the workload root, and change interface state; all of that needs root.
//!   Ordering it after the drop would fail at runtime, in the guest, where it is
//!   expensive to see.

use anyhow::{Result, bail};
use std::path::Path;

/// The shared entry point both inits must call.
const SHARED_BOOTSTRAP: &str = "provision_guest_environment";

/// Where the shared steps live.
const BOOTSTRAP_RS: &str = "crates/mvm-agentd/src/guest_bootstrap.rs";

/// The agent's PID-1 activation path, which also carries the ordering rule.
const AGENT_INIT_RS: &str = "crates/mvm-agentd/src/bin/mvm-guest-agent/init.rs";

/// Every guest init entry point. There is one — the universal initramfs agent —
/// and adding another means adding it here, which is what keeps the parity
/// check real rather than aspirational.
const GUEST_INITS: &[&str] = &[AGENT_INIT_RS];

/// Steps `provision_guest_environment` must still perform.
///
/// Each was skipped by the universal path at some point, and each failure is
/// quiet: the guest boots either way. Naming them here turns a deletion into a
/// build failure.
const REQUIRED_STEPS: &[(&str, &str)] = &[
    (
        "ensure_runtime_dirs",
        "the runtime dirs the rest writes into",
    ),
    (
        "mount_mediated_tools",
        "stand-ins for tools a NIC-less guest cannot run",
    ),
    (
        "provision_egress_ca",
        "the CA the egress substitution presents",
    ),
    ("provision_verb_grant", "the plan-bound verb grant"),
    ("netinit", "the guest network defense install"),
    (
        "start_vsock_egress",
        "loopback, resolver, and the egress client",
    ),
];

/// The privilege drop the bootstrap must precede.
const PRIVILEGE_DROP: &str = "drop_privilege";

/// The agent reaches the shared bootstrap through a small `cfg`-split wrapper,
/// so the Linux-only call site is written down rather than erased on other
/// targets. Assertion C follows that one hop.
const AGENT_WRAPPER: &str = "bootstrap_guest_environment";

pub fn run(workspace: &Path) -> Result<()> {
    let mut checked = 0usize;

    // A — both inits reach the shared bootstrap.
    for init in GUEST_INITS {
        let path = workspace.join(init);
        let src = std::fs::read_to_string(&path)
            .map_err(|e| anyhow::anyhow!("read {}: {e}", path.display()))?;
        if !src.contains(SHARED_BOOTSTRAP) {
            bail!(
                "check-guest-init-parity: {init} does not call `{SHARED_BOOTSTRAP}`.\n\
                 Every guest init runs the same post-mount setup through that one\n\
                 function. An init that skips it boots a workload with no egress\n\
                 path, no resolver, and no verb grant — which looks like a healthy\n\
                 boot and fails later as `Network unreachable`."
            );
        }
        checked += 1;
    }

    // B — the shared bootstrap still does the work.
    let bootstrap_path = workspace.join(BOOTSTRAP_RS);
    let bootstrap = std::fs::read_to_string(&bootstrap_path)
        .map_err(|e| anyhow::anyhow!("read {}: {e}", bootstrap_path.display()))?;
    let body = fn_body(&bootstrap, SHARED_BOOTSTRAP).ok_or_else(|| {
        anyhow::anyhow!("check-guest-init-parity: no `fn {SHARED_BOOTSTRAP}` in {BOOTSTRAP_RS}")
    })?;
    for (step, why) in REQUIRED_STEPS {
        if !body.contains(step) {
            bail!(
                "check-guest-init-parity: `{SHARED_BOOTSTRAP}` no longer performs `{step}`\n\
                 ({why}). If the step moved, point this gate at its new home; if it\n\
                 was dropped, the guest loses that capability silently."
            );
        }
    }

    // C — the agent bootstraps while it is still root.
    let agent_path = workspace.join(AGENT_INIT_RS);
    let agent = std::fs::read_to_string(&agent_path)
        .map_err(|e| anyhow::anyhow!("read {}: {e}", agent_path.display()))?;
    let activation = fn_body(&agent, "apply_activation").ok_or_else(|| {
        anyhow::anyhow!("check-guest-init-parity: no `fn apply_activation` in {AGENT_INIT_RS}")
    })?;
    match (
        activation.find(AGENT_WRAPPER),
        activation.find(PRIVILEGE_DROP),
    ) {
        (Some(bootstrap_at), Some(drop_at)) if bootstrap_at > drop_at => bail!(
            "check-guest-init-parity: `apply_activation` bootstraps the guest after\n\
             `{PRIVILEGE_DROP}`. The steps mount, write into the workload root, and\n\
             bring up an interface — all of which need root."
        ),
        (None, _) => bail!(
            "check-guest-init-parity: `apply_activation` does not reach `{AGENT_WRAPPER}`.\n\
             Activation is the agent's only pre-workload hook; setup skipped here is\n\
             skipped entirely."
        ),
        _ => {}
    }
    // ...and the wrapper must actually reach the shared bootstrap, so the hop
    // cannot become a no-op on the target that matters.
    let wrapper = fn_body(&agent, AGENT_WRAPPER).ok_or_else(|| {
        anyhow::anyhow!("check-guest-init-parity: no `fn {AGENT_WRAPPER}` in {AGENT_INIT_RS}")
    })?;
    if !wrapper.contains(SHARED_BOOTSTRAP) {
        bail!(
            "check-guest-init-parity: `{AGENT_WRAPPER}` no longer calls `{SHARED_BOOTSTRAP}`.\n\
             The wrapper exists only to carry the Linux-only call; an empty one\n\
             silently restores the regression this gate guards."
        );
    }

    println!(
        "check-guest-init-parity: clean ({checked} guest inits share one bootstrap; \
         {} steps intact; agent bootstraps before the privilege drop)",
        REQUIRED_STEPS.len()
    );
    Ok(())
}

/// Return the brace-matched body of `fn <name>`, so a token found elsewhere in
/// the file (a doc comment, an unrelated helper) cannot satisfy an assertion.
fn fn_body<'a>(src: &'a str, name: &str) -> Option<&'a str> {
    let needle = format!("fn {name}");
    let start = src.find(&needle)?;
    let open = src[start..].find('{')? + start;
    let mut depth = 0usize;
    for (offset, ch) in src[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&src[open..=open + offset]);
                }
            }
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fn_body_returns_only_the_named_function() {
        let src = "fn a() { alpha(); }\nfn b() { beta(); }\n";
        let body = fn_body(src, "b").unwrap();
        assert!(body.contains("beta"));
        assert!(!body.contains("alpha"));
    }

    #[test]
    fn fn_body_matches_nested_braces() {
        let src = "fn a() { if x { inner(); } tail(); }\n";
        let body = fn_body(src, "a").unwrap();
        assert!(body.contains("inner"));
        assert!(body.trim_end().ends_with('}'));
        assert!(body.contains("tail"));
    }

    #[test]
    fn fn_body_is_none_for_an_absent_function() {
        assert!(fn_body("fn a() {}", "missing").is_none());
    }

    /// The gate has to hold on the tree it ships with, or it is decoration.
    #[test]
    fn gate_passes_on_this_workspace() {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("workspace root")
            .to_path_buf();
        run(&workspace).expect("guest init parity holds on this tree");
    }
}
