//! Guard that the beginner `machine` docs keep their boundary statements and
//! never imply a capability mvm doesn't provide by default (host Nix, GPU,
//! ICMP, unsupported architectures). Content drifts faster than code; this
//! pins the load-bearing claims so a future doc edit can't silently widen them.

use std::path::PathBuf;

/// Repo root, derived from this crate's manifest dir (`<root>/crates/mvm-cli`).
fn docs_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root is two levels above crates/mvm-cli")
        .join("public/src/content/docs")
}

fn read(rel: &str) -> String {
    let path = docs_dir().join(rel);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
        .to_lowercase()
}

/// The limitations page must keep covering every boundary topic, so deleting a
/// constraint is a red test, not a silent regression.
#[test]
fn limitations_page_covers_every_boundary_topic() {
    let doc = read("guides/machine-limitations.md");
    for topic in [
        "host nix",     // no-host-Nix invariant
        "deny-all",     // default-deny egress
        "icmp",         // ICMP/ping not supported
        "ssh",          // SSH banned / agent-socket-only
        "add-dir",      // volume share shape
        "gpu",          // no GPU
        "architecture", // host/guest arch scope
        "preview",      // portable artifacts are preview
    ] {
        assert!(
            doc.contains(topic),
            "machine-limitations.md must keep covering {topic:?}"
        );
    }
}

/// The scenario guide must lead beginners to the limitations and stay honest
/// about the deny-all default.
#[test]
fn scenario_guide_links_limitations_and_states_no_network_default() {
    let doc = read("getting-started/machine-scenarios.md");
    assert!(
        doc.contains("/guides/machine-limitations/"),
        "scenario guide must link the limitations page"
    );
    assert!(
        doc.contains("machine run"),
        "scenario guide must show machine run"
    );
    assert!(
        doc.contains("deny-all") || doc.contains("no network"),
        "scenario guide must state the default is no egress"
    );
}

/// Neither beginner page may assert a capability is available that mvm does not
/// provide by default. Affirmative-only phrases that have no legitimate use in
/// these docs (a negation like "GPU acceleration is not available" must not
/// trip them) — the positive-presence test above carries the bulk of the guard.
#[test]
fn beginner_machine_docs_imply_no_unavailable_capabilities() {
    let forbidden = [
        "host nix is required",          // host Nix is never required
        "gpu acceleration is available", // no GPU
        "gpu passthrough is supported",
        "ping works from inside", // ICMP is not forwarded
    ];
    for rel in [
        "getting-started/machine-scenarios.md",
        "guides/machine-limitations.md",
    ] {
        let doc = read(rel);
        for phrase in forbidden {
            assert!(
                !doc.contains(phrase),
                "{rel} must not imply {phrase:?} — it is not available by default"
            );
        }
    }
}
