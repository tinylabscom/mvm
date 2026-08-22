//! `xtask check-one-guest-protocol`
//!
//! One protocol between a guest and its host endpoint, mechanically enforced.
//!
//! Everything a workload guest sends its host on the NetworkFlow port crosses
//! one authenticated, sequence-numbered FlowMux session. That is what makes the
//! channel a single place to authorize, substitute and audit — and a second
//! protocol beside it is not a feature, it is the hole.
//!
//! This gate exists because of a specific outage. The guest's egress client was
//! made FlowMux-only while every host spawn site still selected the old
//! protocol; each half was internally consistent, every test stayed green, and
//! guest egress was dead on `main` until someone ran a VM. Nothing compared the
//! two sides, so nothing failed. These two checks are that comparison:
//!
//! 1. **No line-marker protocol.** The old channel began with an
//!    unauthenticated ASCII line — `MVM_DNS/1`, `MVM_ICMP/1`,
//!    `MVM_SOCKS5_UDP/1`, `MVM_HTTP_FORWARD/1`, or a bare `host:port` — and
//!    dispatched on it. A guest cannot speak that any more and the host cannot
//!    serve it; a marker constant coming back means one of them learned to.
//!
//! 2. **No second dialer.** Every guest-side caller that opens the egress port
//!    must construct a FlowMux client. Checked against the file's own text
//!    rather than an allowlist of paths, because an allowlist is silenced by
//!    adding a name to it. Several dialers is fine — the egress client, the
//!    addon resolver and the blocking one-shot client each own a session — so
//!    long as every one of them speaks the same protocol.
//!
//! What this gate deliberately does **not** cover, because neither is a guest
//! talking to its host:
//!
//! * `substitution_client::relay` and the `Wire` mode it speaks. Its one
//!   consumer is the wasm tier's `mvm:egress` host import, which runs in the
//!   *host* process and connects to the endpoint's Unix socket — host-internal
//!   IPC between two host processes. No guest selects it or can reach it.
//! * The broker port. Host services (claims 12/13) are a separate channel with
//!   its own binding-gated dispatch; "one transport" is about egress.

use anyhow::{Result, bail};
use std::path::{Path, PathBuf};

/// The line markers the retired protocol dispatched on.
///
/// Matched as string literals rather than identifiers so a reintroduction
/// cannot slip through by renaming the constant that holds one.
const RETIRED_MARKERS: &[&str] = &[
    "MVM_DNS/1",
    "MVM_ICMP/1",
    "MVM_SOCKS5_UDP/1",
    "MVM_HTTP_FORWARD/1",
];

/// The FlowMux client constructors. A guest file that opens the egress port
/// must use one of these.
///
/// Checked against the file's own text rather than kept as an allowlist of
/// paths: an allowlist is silenced by adding a name to it, which is precisely
/// the move someone makes while introducing the thing this gate exists to
/// catch. There is more than one legitimate dialer — the egress client, the
/// addon resolver, and the blocking one-shot client each own a session — so
/// what matters is not how many there are but that every one of them speaks
/// FlowMux.
const FLOWMUX_CLIENTS: &[&str] = &["SyncFlowMux", "FlowMuxClient", "FlowMuxReconnectClient"];

/// Where a guest's own code lives. Host crates are out of scope: this gate is
/// about what crosses the guest→host boundary.
const GUEST_ROOTS: &[&str] = &["crates/mvm-agentd/src"];

/// Host files that serve the guest→host channel.
const HOST_ROOTS: &[&str] = &[
    "crates/mvm-hostd/src/supervisor",
    "crates/mvm-hostd/src/bin",
];

/// Files that may name a marker while not implementing one.
///
/// Core compatibility codecs and the remaining pure ICMP handler may still
/// declare marker constants. They are listed so that a real dispatch site
/// cannot hide among them.
const MARKER_DECLARATION_SITES: &[&str] = &[
    "crates/mvm-core/src/guest_netd.rs",
    "crates/mvm-core/src/socks5_udp.rs",
    "crates/mvm-hostd/src/supervisor/icmp_handler.rs",
];

pub fn run(root: &Path) -> Result<()> {
    let mut violations = Vec::new();
    check_no_marker_dispatch(root, &mut violations)?;
    check_no_second_dialer(root, &mut violations)?;

    if violations.is_empty() {
        println!("check-one-guest-protocol: one guest→host protocol; no second dialer");
        return Ok(());
    }
    bail!(
        "check-one-guest-protocol found {} violation(s):\n{}\n\n\
         A guest reaches its host endpoint over one authenticated FlowMux session.\n\
         If a new caller genuinely needs the egress port, make it a FlowMux client\n\
         (`mvm_agentd::flowmux_sync::SyncFlowMux`) rather than adding framing beside it.",
        violations.len(),
        violations.join("\n")
    )
}

/// No file outside the declaration sites may mention a retired marker.
fn check_no_marker_dispatch(root: &Path, violations: &mut Vec<String>) -> Result<()> {
    let allowed: Vec<PathBuf> = MARKER_DECLARATION_SITES
        .iter()
        .map(|p| root.join(p))
        .collect();

    for dir in GUEST_ROOTS.iter().chain(HOST_ROOTS.iter()) {
        let base = root.join(dir);
        if !base.exists() {
            bail!("check-one-guest-protocol: watched path {dir} does not exist");
        }
        for file in rust_files(&base)? {
            if allowed.iter().any(|a| a == &file) {
                continue;
            }
            let text = std::fs::read_to_string(&file)?;
            for (index, line) in text.lines().enumerate() {
                // A doc comment may name a retired protocol to say it is gone.
                if is_comment(line) {
                    continue;
                }
                for marker in RETIRED_MARKERS {
                    if line.contains(marker) {
                        violations.push(format!(
                            "  {}:{}: names the retired line marker {marker}",
                            display(root, &file),
                            index + 1
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

/// Only a FlowMux client may open the egress port from the guest.
fn check_no_second_dialer(root: &Path, violations: &mut Vec<String>) -> Result<()> {
    for dir in GUEST_ROOTS {
        for file in rust_files(&root.join(dir))? {
            // The dial helper itself and the port constant's own module.
            if file.starts_with(root.join("crates/mvm-agentd/src/vsock")) {
                continue;
            }
            let text = std::fs::read_to_string(&file)?;
            let opens_egress_port = text.lines().any(|line| {
                !is_comment(line)
                    && (line.contains("EGRESS_PORT") || line.contains("EGRESS_VSOCK_PORT"))
            });
            if !opens_egress_port {
                continue;
            }
            if FLOWMUX_CLIENTS.iter().any(|client| text.contains(client)) {
                continue;
            }
            violations.push(format!(
                "  {}: opens the egress port without using a FlowMux client ({})",
                display(root, &file),
                FLOWMUX_CLIENTS.join(", ")
            ));
        }
    }
    Ok(())
}

fn is_comment(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with('*')
}

fn display(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
}

fn rust_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    if !dir.exists() {
        return Ok(out);
    }
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        for entry in std::fs::read_dir(&current)? {
            let path = entry?.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    out.sort();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_comment_naming_a_retired_marker_is_not_a_violation() {
        // Prose has to be able to say the protocol is gone.
        assert!(is_comment("    //! `MVM_ICMP/1` is retired"));
        assert!(is_comment("// MVM_DNS/1"));
        assert!(is_comment(" * MVM_DNS/1"));
        assert!(!is_comment("let x = \"MVM_DNS/1\";"));
    }

    #[test]
    fn the_marker_list_is_the_retired_set() {
        // If a marker is dropped from this list the gate silently stops
        // watching it, so the list is asserted rather than assumed.
        assert_eq!(RETIRED_MARKERS.len(), 4);
        assert!(RETIRED_MARKERS.contains(&"MVM_ICMP/1"));
        assert!(RETIRED_MARKERS.contains(&"MVM_HTTP_FORWARD/1"));
    }

    #[test]
    fn the_client_list_names_every_flowmux_constructor() {
        // A dialer proves itself by using one of these. Dropping one would
        // make a legitimate client look like a second protocol; adding an
        // unrelated name would let a real one through.
        assert_eq!(FLOWMUX_CLIENTS.len(), 3);
        assert!(FLOWMUX_CLIENTS.contains(&"SyncFlowMux"));
        assert!(FLOWMUX_CLIENTS.contains(&"FlowMuxReconnectClient"));
    }
}
