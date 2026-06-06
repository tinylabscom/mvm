//! `xtask check-guest-agent-in-all-images`
//!
//! Plan 124 B2 / ADR-066 §6 — the universal-agent invariant. Every
//! bootable mvm image must fork `mvm-guest-agent` in its launch path, so
//! the *same* agent runs in every VM type (workload, dev, builder). This
//! gate is the tripwire: if a launcher's agent-fork is deleted, the
//! corresponding marker vanishes and CI fails here.
//!
//! There are two distinct launch mechanisms:
//!   1. **mkGuest `/init`** (`nix/lib/mk-guest.nix`) — the workload and
//!      dev-shell images. Forks the agent via `setpriv … -- "$MVM_AGENT_BIN"`.
//!   2. **`mvm-host-vm-init`** — PID 1 of the libkrun builder VM. Forks
//!      the agent via `fork_guest_agent()` (Plan 124 B1).
//!
//! Source-grep, not a build: the launch paths are a Nix shell script and
//! a `cfg(linux)` Rust binary, neither of which this gate can execute on
//! a contributor host. Same shape as `check-claim-catalog` (witness must
//! exist) and `check-guest-agent-runtime-free`.

use anyhow::{Context, Result, bail};
use std::path::Path;

/// `(image launch path, file relative to workspace, marker proving the
/// agent is forked there)`. The marker is chosen to be specific to the
/// fork mechanism — removing the fork removes the marker.
const AGENT_LAUNCHERS: &[(&str, &str, &str)] = &[
    // mkGuest's /init resolves the agent into `$MVM_AGENT_BIN` and execs
    // it under setpriv; the var exists only in the agent-fork block.
    (
        "workload + dev-shell microVM (mkGuest /init)",
        "nix/lib/mk-guest.nix",
        "MVM_AGENT_BIN",
    ),
    // The builder VM's PID 1 forks the agent via this fn (Plan 124 B1).
    (
        "builder VM PID 1 (mvm-host-vm-init)",
        "crates/mvm-build/src/bin/mvm-host-vm-init.rs",
        "fork_guest_agent",
    ),
];

pub fn run(workspace: &Path) -> Result<()> {
    let mut missing: Vec<String> = Vec::new();

    for (desc, rel, marker) in AGENT_LAUNCHERS {
        let path = workspace.join(rel);
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("reading agent launcher {rel} ({desc})"))?;
        if !launcher_forks_agent(&content, marker) {
            missing.push(format!("{desc} — `{rel}` no longer contains `{marker}`"));
        }
    }

    if !missing.is_empty() {
        bail!(
            "check-guest-agent-in-all-images: a bootable image's launch path no longer forks \
             mvm-guest-agent (ADR-066 §6 universal-agent invariant):\n  - {}\n\
             Every VM type (workload, dev, builder) must run the agent — restore the fork or \
             update this gate's marker if the launch mechanism was deliberately rewritten.",
            missing.join("\n  - ")
        );
    }

    eprintln!(
        "check-guest-agent-in-all-images: clean ({} launch paths fork mvm-guest-agent)",
        AGENT_LAUNCHERS.len()
    );
    Ok(())
}

/// A launcher forks the agent iff its source carries the fork marker.
fn launcher_forks_agent(content: &str, marker: &str) -> bool {
    content.contains(marker)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn present_marker_passes() {
        let src = r#"MVM_AGENT_BIN=/usr/local/bin/mvm-guest-agent
            setpriv --reuid=990 -- "$MVM_AGENT_BIN" &"#;
        assert!(launcher_forks_agent(src, "MVM_AGENT_BIN"));
    }

    #[test]
    fn missing_marker_is_flagged() {
        // A launcher that boots straight to the entrypoint, no agent fork.
        let src = "exec /usr/bin/myapp";
        assert!(!launcher_forks_agent(src, "fork_guest_agent"));
    }

    #[test]
    fn every_declared_launcher_has_a_distinct_marker() {
        // Guards the table itself: no copy-paste duplicate (file, marker).
        let mut seen = std::collections::HashSet::new();
        for (_, rel, marker) in AGENT_LAUNCHERS {
            assert!(
                seen.insert((*rel, *marker)),
                "duplicate launcher ({rel}, {marker})"
            );
        }
        assert_eq!(AGENT_LAUNCHERS.len(), 2, "workload/dev-shell + builder VM");
    }
}
