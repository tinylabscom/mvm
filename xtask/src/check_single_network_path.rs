//! Permanent guard for the one workload-networking architecture.
//!
//! A workload gets one `NetworkFlow` channel, every production runner starts
//! the same per-VM endpoint, and that endpoint is the only host component that
//! may originate workload egress or own admitted ingress listeners. This check
//! replaces the temporary L3 freeze and backend-specific vsock ratchets.

use anyhow::{Context, Result, bail};
use regex::Regex;
use std::collections::BTreeSet;
use std::path::Path;

use crate::fs_walk::for_each_file;
use crate::rust_source::blank_comments_and_strings;

const BACKEND_RS: &str = "crates/mvm-runtime/src/backend.rs";
const APPLE_CONTAINER_RS: &str = "crates/mvm-runtime/src/apple_container_backend.rs";
const SPAWNER_RS: &str = "crates/mvm-runtime/src/workload_runner/runner/spawner.rs";
const SPAWN_RS: &str = "crates/mvm-vmm/src/host/network_endpoint_spawn.rs";
const ENDPOINT_BIN: &str = "crates/mvm-hostd/src/bin/mvm-network-endpoint.rs";
const SPEC_MAP_RS: &str = "crates/mvm-vmm/src/host/spec_map.rs";
const RUNNER_RS: &str = "crates/mvm-runtime/src/workload_runner/runner.rs";

const RUNNERS: &[(&str, &str)] = &[
    ("FcRunner", "FcDriver"),
    ("HvfRunner", "HvfDriver"),
    ("LibkrunRunner", "LibkrunDriver"),
    ("QemuRunner", "QemuDriver"),
];

const RETIRED_SYMBOLS: &[&str] = &[
    "L3Vsock",
    "NetworkControl",
    "NetworkData",
    "spawn_netd",
    "host_datapath",
    "mvm-netd",
    "mvm-net-agent",
    "smoltcp",
    "L3NetworkSpec",
    "L3IngressMapping",
    "NetworkLease",
    "StartPortForward",
    "PortForwardStarted",
    "PORT_FORWARD_BASE",
    "IngressTcp",
    "start_port_forward_on",
    "run_port_forwarder",
];

const NIC_SYMBOLS: &[&str] = &[
    "virtio_net",
    "virtio-net",
    "VIRTIO_ID_NET",
    "add_net",
    "tap0",
    "passt",
    "gvproxy",
    "network-interfaces",
    "iface_id",
    "host_dev_name",
];

const NIC_GUARDED_PATHS: &[&str] = &[
    "crates/mvm-agentd/src",
    "crates/mvm-backends/src/driver/fc.rs",
    "crates/mvm-backends/src/driver/hvf.rs",
    "crates/mvm-backends/src/driver/hvf_restore.rs",
    "crates/mvm-backends/src/driver/libkrun.rs",
    "crates/mvm-backends/src/driver/qemu.rs",
    "crates/mvm-runtime/src/backend.rs",
    "crates/mvm-runtime/src/apple_container_backend.rs",
    "crates/mvm-runtime/src/workload_runner",
    "crates/mvm-vmm/src/vmm",
    "crates/mvm-vmm/src/vsock_egress_bridge",
    "crates/mvm-vmm/src/driver/spec.rs",
    "crates/mvm-vmm/src/host/spec_map.rs",
    ENDPOINT_BIN,
    "crates/mvm-hostd/src/supervisor/flowmux.rs",
    "crates/mvm-hostd/src/supervisor/flowmux",
    "crates/mvm-net/src",
];

/// The only production mentions of the retired input spelling are strict
/// compatibility decoders that return a migration error.
const LEGACY_INPUT_BOUNDARIES: &[&str] = &[
    "crates/mvm-contract/src/ir/workload.rs",
    "crates/mvm-sdk/src/decorator/value.rs",
];

const ENDPOINT_SOCKET_OWNERS: &[&str] = &[
    ENDPOINT_BIN,
    "crates/mvm-hostd/src/supervisor/dns_resolver.rs",
    "crates/mvm-hostd/src/supervisor/flowmux.rs",
    "crates/mvm-hostd/src/supervisor/flowmux/",
    "crates/mvm-hostd/src/supervisor/terminator/",
    "crates/mvm-http/src/client.rs",
];

/// Host network users that do not carry workload traffic. Each exemption is
/// exact and purpose-labelled so the list cannot silently widen by directory.
const INFRA_SOCKET_EXEMPTIONS: &[(&str, &str)] = &[(
    "crates/mvm-hostd/src/supervisor/l7_proxy.rs",
    "standalone supervisor proxy component outside the admitted workload runner",
)];

const SOCKET_TOKENS: &[&str] = &[
    "TcpStream::connect(",
    "TcpStream::connect_timeout(",
    "TcpListener::bind(",
    "UdpSocket::bind(",
];

pub fn run(workspace: &Path) -> Result<()> {
    check_runner_shape(workspace)?;
    check_single_endpoint_implementation(workspace)?;
    check_network_flow_channels(workspace)?;
    check_retired_symbols(workspace)?;
    check_socket_owners(workspace)?;
    check_single_peer_resolver(workspace)?;
    eprintln!(
        "check-single-network-path: clean — one endpoint implementation, one NetworkFlow channel per backend, no retired L3/NIC path, one workload socket owner, and one peer resolver"
    );
    Ok(())
}

fn read(workspace: &Path, rel: &str) -> Result<String> {
    std::fs::read_to_string(workspace.join(rel)).with_context(|| format!("read {rel}"))
}

fn production_code(source: &str) -> String {
    let before_tests = source.split("#[cfg(test)]").next().unwrap_or(source);
    blank_comments_and_strings(before_tests)
}

fn check_runner_shape(workspace: &Path) -> Result<()> {
    let backend = production_code(&read(workspace, BACKEND_RS)?);
    for (alias, driver) in RUNNERS {
        let pattern = format!(
            r"type\s+{alias}\s*=\s*WorkloadRunner\s*<\s*{driver}\s*,\s*RealNetworkEndpointSpawner\s*,\s*RealBrokerRegistrar\s*>"
        );
        if !Regex::new(&pattern)
            .expect("static runner regex")
            .is_match(&backend)
        {
            bail!(
                "check-single-network-path: {alias} must remain WorkloadRunner<{driver}, RealNetworkEndpointSpawner, RealBrokerRegistrar>"
            );
        }
    }

    let apple = production_code(&read(workspace, APPLE_CONTAINER_RS)?);
    if !Regex::new(r"runner\s*:\s*HvfRunner\b")
        .expect("static apple runner regex")
        .is_match(&apple)
        || ![
            r"self\s*\.\s*runner\s*\.\s*start\s*\(",
            r"self\s*\.\s*runner\s*\.\s*start_with_mode\s*\(",
            r"self\s*\.\s*runner\s*\.\s*warm_start\s*\(",
        ]
        .iter()
        .all(|pattern| {
            Regex::new(pattern)
                .expect("static delegation regex")
                .is_match(&apple)
        })
    {
        bail!(
            "check-single-network-path: apple-container must hold HvfRunner and delegate every launch path to it"
        );
    }
    Ok(())
}

fn check_single_endpoint_implementation(workspace: &Path) -> Result<()> {
    let mut spawn_defs = Vec::new();
    for_each_file(
        &workspace.join("crates"),
        Some("rs"),
        &mut |path, source| {
            let code = production_code(source);
            for (index, line) in code.lines().enumerate() {
                if line.contains("pub fn spawn_network_endpoint") {
                    spawn_defs.push(format!("{}:{}", display(workspace, path), index + 1));
                }
            }
        },
    )?;
    let owners = spawn_defs
        .iter()
        .map(|hit| hit.split(':').next().unwrap_or(hit).to_string())
        .collect::<Vec<_>>();
    if owners != [SPAWN_RS] {
        bail!(
            "check-single-network-path: expected exactly one production spawn_network_endpoint definition in {SPAWN_RS}, found {:?}",
            spawn_defs
        );
    }

    let spawner = production_code(&read(workspace, SPAWNER_RS)?);
    if spawner
        .matches("impl NetworkEndpointSpawner for RealNetworkEndpointSpawner")
        .count()
        != 1
        || spawner
            .matches("spawn_network_endpoint(SubstitutionSpawnParams")
            .count()
            != 1
    {
        bail!(
            "check-single-network-path: RealNetworkEndpointSpawner must have one implementation calling the one endpoint spawn seam"
        );
    }
    let endpoint = production_code(&read(workspace, ENDPOINT_BIN)?);
    if !endpoint.contains("FlowMuxSession::accept_with(") {
        bail!(
            "check-single-network-path: {ENDPOINT_BIN} no longer serves the authenticated FlowMux session"
        );
    }
    Ok(())
}

fn check_network_flow_channels(workspace: &Path) -> Result<()> {
    let mapper = production_code(&read(workspace, SPEC_MAP_RS)?);
    let binding = "service: GuestService::NetworkFlow";
    if mapper.matches(binding).count() != 1 {
        bail!(
            "check-single-network-path: {SPEC_MAP_RS} must project exactly one NetworkFlow channel, found {}",
            mapper.matches(binding).count()
        );
    }
    let runner = production_code(&read(workspace, RUNNER_RS)?);
    if !runner.contains("let spec = workload_spec(") || !runner.contains("self.driver.boot(&spec)")
    {
        bail!(
            "check-single-network-path: WorkloadRunner must map and boot the shared workload spec for every runner alias"
        );
    }
    Ok(())
}

/// Files permitted to decide a peer target.
///
/// The peer namespace and the host-name namespace share one input, and the
/// branch between them lives in exactly one place: `EgressGate::decide_target`.
/// A second copy of that branch is how one of the two paths quietly stops being
/// gated — the copy gets a new caller, the caller drifts, and nothing says so.
const PEER_BRANCH_OWNER: &str = "crates/mvm-vmm/src/vsock_egress_bridge/egress_gate.rs";

/// The connect sites that route a guest target through the gate. Both must go
/// through `decide_target`; neither may call `decide_peer` or re-derive the
/// branch itself.
const PEER_BRANCH_CALLERS: &[&str] = &[
    "crates/mvm-hostd/src/supervisor/flowmux.rs",
    "crates/mvm-hostd/src/supervisor/flowmux/session.rs",
];

/// Deliberate non-callers: production code that sees a target but must not
/// resolve a peer through it. The substitution proxy refuses peer destinations
/// outright rather than falling through, so it names the peer suffix without
/// dispatching on it.
const PEER_REFUSAL_SITES: &[&str] = &["crates/mvm-hostd/src/supervisor/network_endpoint_proxy.rs"];

fn check_single_peer_resolver(workspace: &Path) -> Result<()> {
    // The branch itself exists exactly once, in the gate.
    let owner = production_code(&read(workspace, PEER_BRANCH_OWNER)?);
    let branches = owner.matches("PeerName::is_peer_target").count();
    if branches != 1 {
        bail!(
            "check-single-network-path: {PEER_BRANCH_OWNER} must contain exactly one \
             peer/host branch (`PeerName::is_peer_target`), found {branches}. The branch \
             is the single decision point; a second one is a second policy."
        );
    }
    if !owner.contains("pub fn decide_target") {
        bail!(
            "check-single-network-path: {PEER_BRANCH_OWNER} must expose `decide_target` \
             as the one entry point every workload connect goes through"
        );
    }

    // Every connect site goes through it, and none reaches past it.
    for rel in PEER_BRANCH_CALLERS {
        let src = production_code(&read(workspace, rel)?);
        if !src.contains("gate.decide_target(") {
            bail!(
                "check-single-network-path: {rel} must decide its guest target via \
                 `gate.decide_target(..)`. A connect site that resolves a target another \
                 way is outside the gate."
            );
        }
        if src.contains("decide_peer(") {
            bail!(
                "check-single-network-path: {rel} calls `decide_peer` directly, bypassing \
                 the peer/host branch in {PEER_BRANCH_OWNER}. Call `decide_target`."
            );
        }
        if src.contains("is_peer_target") {
            bail!(
                "check-single-network-path: {rel} re-derives the peer/host branch. The \
                 branch belongs to {PEER_BRANCH_OWNER} alone."
            );
        }
    }

    // A refusal site may name the suffix; it may not resolve through it.
    for rel in PEER_REFUSAL_SITES {
        let src = production_code(&read(workspace, rel)?);
        if src.contains("decide_peer(") || src.contains("decide_target(") {
            bail!(
                "check-single-network-path: {rel} resolves a peer target. It is a refusal \
                 site: peer traffic goes over FlowMux, not the substitution proxy. If that \
                 is meant to change, change it deliberately and move this entry."
            );
        }
    }
    Ok(())
}

fn check_retired_symbols(workspace: &Path) -> Result<()> {
    let retired = Regex::new(&format!(r"\b({})\b", RETIRED_SYMBOLS.join("|")))
        .context("compile retired symbol regex")?;
    let mut hits = Vec::new();
    for_each_file(
        &workspace.join("crates"),
        Some("rs"),
        &mut |path, source| {
            let rel = display(workspace, path);
            if is_test_path(&rel) {
                return;
            }
            collect_regex_hits(&rel, &production_code(source), &retired, &mut hits);
        },
    )?;

    for guarded in NIC_GUARDED_PATHS {
        let path = workspace.join(guarded);
        if !path.exists() {
            hits.push(format!("{guarded}: guarded path is missing"));
            continue;
        }
        scan_path(workspace, &path, &mut |rel, code| {
            for token in NIC_SYMBOLS {
                if contains_token(code, token) {
                    hits.push(format!("{rel}: contains retired guest-NIC token `{token}`"));
                }
            }
        })?;
    }

    let mut legacy_seen = BTreeSet::new();
    for_each_file(
        &workspace.join("crates"),
        Some("rs"),
        &mut |path, source| {
            let rel = display(workspace, path);
            if is_test_path(&rel) {
                return;
            }
            let before_tests = source.split("#[cfg(test)]").next().unwrap_or(source);
            if before_tests.contains("raw_ip_stack") {
                if LEGACY_INPUT_BOUNDARIES.contains(&rel.as_str()) {
                    legacy_seen.insert(rel);
                } else {
                    hits.push(format!(
                        "{rel}: raw_ip_stack may only appear in strict legacy-input decoders"
                    ));
                }
            }
        },
    )?;
    for expected in LEGACY_INPUT_BOUNDARIES {
        if !legacy_seen.contains(*expected) {
            hits.push(format!(
                "{expected}: stale legacy-input exception; delete it from the gate"
            ));
        }
    }

    if !hits.is_empty() {
        bail!(
            "check-single-network-path: retired networking surface found:\n  {}",
            hits.join("\n  ")
        );
    }
    Ok(())
}

fn check_socket_owners(workspace: &Path) -> Result<()> {
    let roots = [
        workspace.join("crates/mvm-hostd/src"),
        workspace.join("crates/mvm-http/src"),
    ];
    let mut violations = Vec::new();
    let mut exemptions_seen = BTreeSet::new();
    for root in roots {
        scan_path(workspace, &root, &mut |rel, code| {
            if !SOCKET_TOKENS.iter().any(|token| code.contains(token)) {
                return;
            }
            if path_allowed(rel, ENDPOINT_SOCKET_OWNERS) {
                return;
            }
            if let Some((path, _purpose)) = INFRA_SOCKET_EXEMPTIONS
                .iter()
                .find(|(path, _)| *path == rel)
            {
                exemptions_seen.insert(*path);
                return;
            }
            violations.push(format!(
                "{rel}: opens an Internet socket outside mvm-network-endpoint"
            ));
        })?;
    }
    for (path, purpose) in INFRA_SOCKET_EXEMPTIONS {
        if !exemptions_seen.contains(path) {
            violations.push(format!(
                "{path}: stale infrastructure socket exemption ({purpose})"
            ));
        }
    }
    if !violations.is_empty() {
        bail!(
            "check-single-network-path: socket ownership violation(s):\n  {}",
            violations.join("\n  ")
        );
    }
    Ok(())
}

fn scan_path(workspace: &Path, path: &Path, visit: &mut dyn FnMut(&str, &str)) -> Result<()> {
    if path.is_file() {
        let source = std::fs::read_to_string(path)?;
        let rel = display(workspace, path);
        if !is_test_path(&rel) {
            visit(&rel, &production_code(&source));
        }
        return Ok(());
    }
    for_each_file(path, Some("rs"), &mut |file, source| {
        let rel = display(workspace, file);
        if !is_test_path(&rel) {
            visit(&rel, &production_code(source));
        }
    })
}

fn collect_regex_hits(rel: &str, code: &str, re: &Regex, hits: &mut Vec<String>) {
    for (index, line) in code.lines().enumerate() {
        for found in re.find_iter(line) {
            hits.push(format!("{rel}:{}: `{}`", index + 1, found.as_str()));
        }
    }
}

fn contains_token(code: &str, token: &str) -> bool {
    if token == "passt" {
        Regex::new(r"\bpasst\b")
            .expect("static passt regex")
            .is_match(code)
    } else {
        code.contains(token)
    }
}

fn path_allowed(rel: &str, allowed: &[&str]) -> bool {
    allowed
        .iter()
        .any(|entry| rel == *entry || entry.ends_with('/') && rel.starts_with(entry))
}

fn is_test_path(rel: &str) -> bool {
    rel.contains("/tests/")
        || rel.ends_with("/tests.rs")
        || rel.contains("/test_support/")
        || rel.contains("/benches/")
        || rel.contains("/examples/")
}

fn display(workspace: &Path, path: &Path) -> String {
    path.strip_prefix(workspace)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_code_drops_comments_strings_and_test_modules() {
        let code = production_code(
            "fn live() { use_net(); } // virtio_net\nconst S: &str = \"smoltcp\";\n#[cfg(test)]\nfn test_only() { TcpStream::connect(addr); }",
        );
        assert!(code.contains("use_net"));
        assert!(!code.contains("virtio_net"));
        assert!(!code.contains("smoltcp"));
        assert!(!code.contains("TcpStream::connect"));
    }

    #[test]
    fn synthetic_forbidden_symbol_is_detected() {
        let re = Regex::new(&format!(r"\b({})\b", RETIRED_SYMBOLS.join("|"))).unwrap();
        let mut hits = Vec::new();
        collect_regex_hits(
            "crates/probe/src/lib.rs",
            "fn regression() { let _ = NetworkControl::default(); }",
            &re,
            &mut hits,
        );
        assert_eq!(hits.len(), 1);
        assert!(hits[0].contains("NetworkControl"));
    }

    #[test]
    fn synthetic_legacy_port_forward_protocol_is_detected() {
        let re = Regex::new(&format!(r"\b({})\b", RETIRED_SYMBOLS.join("|"))).unwrap();
        let mut hits = Vec::new();
        collect_regex_hits(
            "crates/probe/src/lib.rs",
            "fn regression() { let _ = GuestRequest::StartPortForward { guest_port: 80 }; }",
            &re,
            &mut hits,
        );
        assert_eq!(hits.len(), 1);
        assert!(hits[0].contains("StartPortForward"));
    }

    #[test]
    fn endpoint_and_exact_infra_socket_cases_are_the_only_allowed_shapes() {
        assert!(path_allowed(ENDPOINT_BIN, ENDPOINT_SOCKET_OWNERS));
        assert!(path_allowed(
            "crates/mvm-hostd/src/supervisor/flowmux/tcp_relay.rs",
            ENDPOINT_SOCKET_OWNERS
        ));
        assert!(!path_allowed(
            "crates/mvm-hostd/src/supervisor/new_dialer.rs",
            ENDPOINT_SOCKET_OWNERS
        ));
        assert!(
            INFRA_SOCKET_EXEMPTIONS
                .iter()
                .any(|(path, _)| *path == "crates/mvm-hostd/src/supervisor/l7_proxy.rs")
        );
    }

    #[test]
    fn legacy_input_exceptions_are_exact_files() {
        assert!(LEGACY_INPUT_BOUNDARIES.contains(&"crates/mvm-contract/src/ir/workload.rs"));
        assert!(!path_allowed(
            "crates/mvm-contract/src/ir/workload/new.rs",
            LEGACY_INPUT_BOUNDARIES
        ));
    }
}
