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
use crate::rust_source::{
    blank_comments_and_strings, blank_ranges, cfg_test_item_ranges, strip_cfg_test_items,
};

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
    "crates/mvm-http/src/client.rs",
];

/// Host network users that do not carry workload traffic. Each exemption is
/// exact and purpose-labelled so the list cannot silently widen by directory.
const INFRA_SOCKET_EXEMPTIONS: &[(&str, &str)] = &[(
    "crates/mvm-hostd/src/supervisor/l7_proxy.rs",
    "standalone supervisor proxy component outside the admitted workload runner",
)];

/// The builder crate: its guest inits run inside every builder VM, and its
/// host half launches those VMs.
const BUILDER_CRATE_SRC: &str = "crates/mvm-build/src";

/// A builder guest has no NIC. Its one way out is the loopback proxy the
/// vsock egress client binds, and the host endpoint behind that client is
/// where the builder's egress policy is decided. The only TCP connection a
/// builder may therefore open itself is the readiness probe of that proxy,
/// dialed at the address parsed from the egress client's listen constant.
const BUILDER_PROBE_BINDING: &str =
    r"let\s+Ok\(\s*proxy_addr\s*\)\s*=\s*[A-Z_]*EGRESS_PROXY_LISTEN_ADDR\s*\.\s*parse";
const BUILDER_PROBE_DIAL: &str = r"TcpStream::connect(?:_timeout)?\(\s*&proxy_addr\b";
const BUILDER_DIAL_TOKENS: &[&str] = &["TcpStream::connect(", "TcpStream::connect_timeout("];
const BUILDER_LISTEN_TOKENS: &[&str] = &["TcpListener::bind(", "UdpSocket::bind("];

/// The guest-side proxy that used to front dependency installs, dialing
/// upstream itself. The host-binary manifests are what put a binary into
/// `mvmctl`'s embedded payload and the builder rootfs, so a name here must
/// never reappear in one.
const RETIRED_BUILDER_BINARIES: &[&str] = &["mvm-egress-proxy"];
const BUILDER_BINARY_MANIFESTS: &[&str] = &[
    "crates/mvm-build/src/host_payload_manifest.rs",
    "nix/lib/mvm-host-binaries.nix",
];

/// Builder-crate sources that open sockets and are allowed to, each exact and
/// purpose-labelled. An entry that stops opening a socket, or disappears, is
/// reported stale so the list only shrinks.
const BUILDER_SOCKET_EXEMPTIONS: &[(&str, &str)] = &[(
    "crates/mvm-build/src/egress_proxy/proxy.rs",
    "the retired guest proxy's source, kept while the image repository still compiles its \
     cargo target; the retired-binary check keeps it out of every host-binary manifest",
)];

/// QEMU takes its devices as string arguments, which `production_code`
/// blanks, so its launch code is read with only comments removed.
const QEMU_BUILDER_RS: &str = "crates/mvm-build/src/qemu_builder.rs";
const QEMU_NIC_ARGS: &[&str] = &[
    "\"-netdev\"",
    "\"-nic\"",
    "\"-net\"",
    "virtio-net",
    "user,id=",
];

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
    check_flow_audit_labels(workspace)?;
    check_builder_egress(workspace)?;
    eprintln!(
        "check-single-network-path: clean — one endpoint implementation, one NetworkFlow channel per backend, no retired L3/NIC path, one workload socket owner, one peer resolver, payload-free flow audit labels, and no builder egress but the vsock egress client"
    );
    Ok(())
}

fn read(workspace: &Path, rel: &str) -> Result<String> {
    std::fs::read_to_string(workspace.join(rel)).with_context(|| format!("read {rel}"))
}

fn production_code(source: &str) -> String {
    strip_cfg_test_items(&blank_comments_and_strings(source))
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

/// The connect sites that route a guest target through the gate. Each must go
/// through `decide_target`.
const PEER_BRANCH_CALLERS: &[&str] = &["crates/mvm-hostd/src/supervisor/flowmux/open_flow.rs"];

/// The module tree those connect sites live in. No file here may call
/// `decide_peer` or re-derive the branch itself — stated over the whole tree
/// rather than over the one file that calls `decide_target`, so splitting the
/// connect path into a new sibling cannot move a second branch out from under
/// the check.
const PEER_BRANCH_NON_DERIVERS: &[&str] = &[
    "crates/mvm-hostd/src/supervisor/flowmux.rs",
    "crates/mvm-hostd/src/supervisor/flowmux",
];

/// Deliberate non-callers: production code that sees a target but must not
/// resolve a peer through it. The substitution proxy refuses peer destinations
/// outright rather than falling through, so it names the peer suffix without
/// dispatching on it.
///
/// The proxy is a module tree: the facade plus every file under its directory.
/// Naming only the facade would pass while reading nothing, because the facade
/// holds no request path at all.
const PEER_REFUSAL_SITES: &[&str] = &[
    "crates/mvm-hostd/src/supervisor/network_endpoint_proxy.rs",
    "crates/mvm-hostd/src/supervisor/network_endpoint_proxy",
];

/// What marks the proxy's one peer refusal.
const PEER_REFUSAL_MARKER: &str = "PeerName::is_peer_target";

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

    // Every connect site goes through it.
    for rel in PEER_BRANCH_CALLERS {
        let src = production_code(&read(workspace, rel)?);
        if !src.contains("gate.decide_target(") {
            bail!(
                "check-single-network-path: {rel} must decide its guest target via \
                 `gate.decide_target(..)`. A connect site that resolves a target another \
                 way is outside the gate."
            );
        }
    }

    // And nothing in the tree they live in reaches past it.
    let mut derived = Vec::new();
    for rel in PEER_BRANCH_NON_DERIVERS {
        let path = workspace.join(rel);
        if !path.exists() {
            bail!("check-single-network-path: {rel} is missing");
        }
        scan_path(workspace, &path, &mut |file, code| {
            if code.contains("decide_peer(") {
                derived.push(format!(
                    "{file} calls `decide_peer` directly, bypassing the peer/host branch \
                     in {PEER_BRANCH_OWNER}. Call `decide_target`."
                ));
            }
            if code.contains("is_peer_target") {
                derived.push(format!(
                    "{file} re-derives the peer/host branch. The branch belongs to \
                     {PEER_BRANCH_OWNER} alone."
                ));
            }
        })?;
    }
    if !derived.is_empty() {
        bail!("check-single-network-path:\n  {}", derived.join("\n  "));
    }

    // A refusal site may name the suffix; it may not resolve through it.
    let mut sources = Vec::new();
    for rel in PEER_REFUSAL_SITES {
        let path = workspace.join(rel);
        if !path.exists() {
            bail!("check-single-network-path: {rel} is missing");
        }
        scan_path(workspace, &path, &mut |file, code| {
            sources.push((file.to_string(), code.to_string()));
        })?;
    }
    let violations = peer_refusal_violations(&sources);
    if !violations.is_empty() {
        bail!("check-single-network-path:\n  {}", violations.join("\n  "));
    }
    Ok(())
}

/// Check the substitution proxy's files, already reduced to production code.
///
/// Two halves. No file may resolve a peer target. And exactly one file must
/// carry the refusal: zero means the refusal is gone — or has slid behind a
/// `#[cfg(test)]` that `production_code` stops reading at, so the first half
/// is no longer looking at it — and two means a second request path has grown
/// its own copy.
fn peer_refusal_violations(sources: &[(String, String)]) -> Vec<String> {
    let mut violations = Vec::new();
    let mut refusing = Vec::new();
    for (file, code) in sources {
        if code.contains("decide_peer(") || code.contains("decide_target(") {
            violations.push(format!(
                "{file} resolves a peer target. It is a refusal site: peer traffic goes over \
                 FlowMux, not the substitution proxy. If that is meant to change, change it \
                 deliberately and move this entry."
            ));
        }
        if code.contains(PEER_REFUSAL_MARKER) {
            refusing.push(file.as_str());
        }
    }
    if refusing.len() != 1 {
        violations.push(format!(
            "the substitution proxy ({}) must refuse peer destinations in exactly one file \
             (`{PEER_REFUSAL_MARKER}`), found {}: [{}]. One request-preparation seam owns the \
             refusal; none means it was removed or moved out of the scanned production code.",
            PEER_REFUSAL_SITES.join(", "),
            refusing.len(),
            refusing.join(", ")
        ));
    }
    violations
}

/// Label keys a connect-path audit entry may carry.
///
/// Every one is metadata about *which* flow was decided, never anything from
/// inside it. The chain records that a workload dialed `db.mvm.peer:5432` and
/// what the verdict was; it does not record a byte the workload sent. Claim 12
/// makes the same promise for the stream plane's entries, and it is worth
/// exactly as much here.
const FLOW_AUDIT_LABEL_KEYS: &[&str] = &[
    "stream_id",
    "class",
    "route",
    "target",
    "reason",
    "resolved_ips",
    // The DNS question's name and record type. These name the destination
    // being resolved, which is the same class of fact as `target` -- what the
    // workload asked to reach, not anything it sent. A DNS query has no body
    // to leak; if that ever changes, this entry is the thing to revisit.
    "qname",
    "qtype",
    // How a flow to a bound destination was served: terminated on the host so
    // the credential could be substituted, or not at all. It is a fact about
    // the shape of the decision, not about the request -- the label is one of
    // a fixed pair of words chosen by the host, and no byte of the flow
    // reaches it.
    "termination",
];

/// Where the connect paths that emit flow audit entries live. The whole
/// FlowMux module tree, not the one file that happens to hold them today, so
/// moving a connect path into a sibling cannot move its labels out from under
/// the allow-list.
const FLOW_AUDIT_SITES: &[&str] = &[
    "crates/mvm-hostd/src/supervisor/flowmux.rs",
    "crates/mvm-hostd/src/supervisor/flowmux",
];

fn check_flow_audit_labels(workspace: &Path) -> Result<()> {
    // Matches the `("key".to_string(), ..)` label entries the audit maps are
    // built from. Deliberately source-level: the property is about which keys
    // can ever be constructed, which no runtime test can establish.
    let key =
        Regex::new(r#"\(\s*"([a-z_]+)"\.to_string\(\)\s*,"#).context("compile label regex")?;
    let allowed: std::collections::BTreeSet<&str> = FLOW_AUDIT_LABEL_KEYS.iter().copied().collect();

    for (rel, raw) in collect_raw_sources(workspace, FLOW_AUDIT_SITES)? {
        // NOT `production_code`: that blanks string literals, and the label
        // keys *are* string literals — reading them through it finds nothing
        // and the gate passes on anything. Strip the test module only.
        let src = raw.split("#[cfg(test)]").next().unwrap_or(&raw).to_string();
        for block in src.split("emit_audit(").skip(1) {
            // Bound to the end of this call's label map.
            let block = block.split("]),").next().unwrap_or(block);
            for cap in key.captures_iter(block) {
                let found = &cap[1];
                if !allowed.contains(found) {
                    bail!(
                        "check-single-network-path: {rel} builds a flow audit label `{found}`, \
                         which is not in the payload-free allow-list ({}). A flow audit entry \
                         records which flow was decided, never anything from inside it. If the \
                         new label is genuinely metadata, add it to FLOW_AUDIT_LABEL_KEYS and \
                         say why in the review.",
                        FLOW_AUDIT_LABEL_KEYS.join(", ")
                    );
                }
            }
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

/// The builder reaches the network one way: its guest's vsock egress client.
///
/// Three halves. No builder code dials a TCP peer except the readiness probe
/// of that client's loopback proxy, and none binds a listener of its own — a
/// guest-local proxy is how dependency installs once dialed upstream directly,
/// past the host gate. No host-binary manifest names the retired proxy
/// binary. And the QEMU builder attaches no NIC, so there is no route for a
/// direct dial to take even if one came back.
fn check_builder_egress(workspace: &Path) -> Result<()> {
    let mut sources = Vec::new();
    scan_path(
        workspace,
        &workspace.join(BUILDER_CRATE_SRC),
        &mut |rel, code| {
            sources.push((rel.to_string(), code.to_string()));
        },
    )?;
    let mut violations = Vec::new();
    for (path, purpose) in BUILDER_SOCKET_EXEMPTIONS {
        let opens = sources.iter().any(|(rel, code)| {
            rel == path
                && BUILDER_DIAL_TOKENS
                    .iter()
                    .chain(BUILDER_LISTEN_TOKENS)
                    .any(|token| code.contains(token))
        });
        if !opens {
            violations.push(format!(
                "{path}: stale builder socket exemption ({purpose}); delete it from the gate"
            ));
        }
    }
    sources.retain(|(rel, _)| {
        !BUILDER_SOCKET_EXEMPTIONS
            .iter()
            .any(|(path, _)| rel == path)
    });
    violations.extend(builder_socket_violations(&sources));

    for rel in BUILDER_BINARY_MANIFESTS {
        let raw = read(workspace, rel)?;
        violations.extend(retired_builder_binary_violations(rel, &raw));
    }

    let qemu = read(workspace, QEMU_BUILDER_RS)?;
    violations.extend(qemu_nic_violations(QEMU_BUILDER_RS, &qemu));

    if !violations.is_empty() {
        bail!(
            "check-single-network-path: builder egress bypasses the vsock egress client:\n  {}",
            violations.join("\n  ")
        );
    }
    Ok(())
}

/// Check builder production code, already reduced by `production_code`.
fn builder_socket_violations(sources: &[(String, String)]) -> Vec<String> {
    let binding = Regex::new(BUILDER_PROBE_BINDING).expect("static probe binding regex");
    let probe = Regex::new(BUILDER_PROBE_DIAL).expect("static probe dial regex");
    let mut violations = Vec::new();
    for (rel, code) in sources {
        for token in BUILDER_LISTEN_TOKENS {
            if code.contains(token) {
                violations.push(format!(
                    "{rel}: calls `{token}..)`. A builder guest runs no network listener of \
                     its own; the vsock egress client owns the loopback proxy."
                ));
            }
        }
        let dials: usize = BUILDER_DIAL_TOKENS
            .iter()
            .map(|token| code.matches(token).count())
            .sum();
        if dials == 0 {
            continue;
        }
        let probes = probe.find_iter(code).count();
        if probes != dials || !binding.is_match(code) {
            violations.push(format!(
                "{rel}: opens {dials} TCP connection(s), of which {probes} dial `&proxy_addr` \
                 parsed from the egress client's listen address. A builder has no NIC: the only \
                 connection it may open itself is the readiness probe of the vsock egress \
                 client, and everything else goes through that client."
            ));
        }
    }
    violations
}

fn retired_builder_binary_violations(rel: &str, raw: &str) -> Vec<String> {
    RETIRED_BUILDER_BINARIES
        .iter()
        .filter(|name| raw.contains(*name))
        .map(|name| {
            format!(
                "{rel}: names `{name}`, the retired guest-side proxy that dialed upstream \
                 directly. Builder jobs reach the network through the vsock egress client."
            )
        })
        .collect()
}

/// QEMU launch arguments that would give the builder guest a NIC.
///
/// Read with test items blanked but string literals kept, because the
/// arguments are literals. Whole-line comments are dropped.
fn qemu_nic_violations(rel: &str, raw: &str) -> Vec<String> {
    let without_tests = blank_ranges(raw, &cfg_test_item_ranges(&blank_comments_and_strings(raw)));
    let code: String = without_tests
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    QEMU_NIC_ARGS
        .iter()
        .filter(|arg| code.contains(*arg))
        .map(|arg| {
            format!(
                "{rel}: passes `{arg}` to QEMU. The builder VM has no NIC; its egress is the \
                 vsock device and the host endpoint behind it."
            )
        })
        .collect()
}

/// Read every non-test Rust source under each entry, verbatim.
///
/// An entry is a file or a directory. Verbatim because the callers that need
/// this are reading string literals, which `production_code` blanks.
fn collect_raw_sources(workspace: &Path, entries: &[&str]) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    for entry in entries {
        let path = workspace.join(entry);
        if path.is_file() {
            let rel = display(workspace, &path);
            if !is_test_path(&rel) {
                out.push((rel, std::fs::read_to_string(&path)?));
            }
            continue;
        }
        if !path.is_dir() {
            bail!("check-single-network-path: {entry} is missing");
        }
        for_each_file(&path, Some("rs"), &mut |file, source| {
            let rel = display(workspace, file);
            if !is_test_path(&rel) {
                out.push((rel, source.to_string()));
            }
        })?;
    }
    Ok(out)
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
        assert!(!path_allowed(
            "crates/mvm-hostd/src/supervisor/terminator/flow.rs",
            ENDPOINT_SOCKET_OWNERS
        ));
        assert!(
            INFRA_SOCKET_EXEMPTIONS
                .iter()
                .any(|(path, _)| *path == "crates/mvm-hostd/src/supervisor/l7_proxy.rs")
        );
    }

    fn proxy_file(name: &str, code: &str) -> (String, String) {
        (
            format!("crates/mvm-hostd/src/supervisor/network_endpoint_proxy/{name}"),
            code.to_string(),
        )
    }

    #[test]
    fn one_proxy_file_refusing_peers_and_none_resolving_is_clean() {
        let sources = [
            proxy_file(
                "prepare.rs",
                "if PeerName::is_peer_target(host) { refuse() }",
            ),
            proxy_file("pipeline.rs", "fn process() {}"),
        ];
        assert!(peer_refusal_violations(&sources).is_empty());
    }

    #[test]
    fn a_proxy_file_resolving_a_peer_target_is_named() {
        let sources = [
            proxy_file(
                "prepare.rs",
                "if PeerName::is_peer_target(host) { refuse() }",
            ),
            proxy_file("pipeline.rs", "let v = gate.decide_target(host);"),
        ];
        let violations = peer_refusal_violations(&sources);
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert!(violations[0].contains("pipeline.rs resolves a peer target"));
    }

    #[test]
    fn a_missing_peer_refusal_fails_rather_than_passing_vacuously() {
        let sources = [proxy_file("prepare.rs", "fn prepare_flow() {}")];
        let violations = peer_refusal_violations(&sources);
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert!(violations[0].contains("found 0"));
    }

    #[test]
    fn a_second_peer_refusal_is_a_second_request_path() {
        let sources = [
            proxy_file("prepare.rs", "PeerName::is_peer_target(a)"),
            proxy_file("pipeline.rs", "PeerName::is_peer_target(b)"),
        ];
        let violations = peer_refusal_violations(&sources);
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert!(violations[0].contains("found 2"));
    }

    fn builder_file(name: &str, source: &str) -> (String, String) {
        (
            format!("crates/mvm-build/src/bin/{name}"),
            production_code(source),
        )
    }

    const PROBE: &str = r#"
fn probe() {
    let Ok(proxy_addr) = EGRESS_PROXY_LISTEN_ADDR.parse::<SocketAddr>() else { return };
    if TcpStream::connect_timeout(&proxy_addr, Duration::from_millis(200)).is_ok() {}
}
"#;

    #[test]
    fn the_egress_client_readiness_probe_is_the_one_dial_a_builder_may_make() {
        let sources = [
            builder_file("init.rs", PROBE),
            builder_file(
                "stage0.rs",
                &PROBE.replace("EGRESS_PROXY_LISTEN_ADDR", "VSOCK_EGRESS_PROXY_LISTEN_ADDR"),
            ),
            builder_file("quiet.rs", "fn nothing() {}"),
        ];
        assert!(builder_socket_violations(&sources).is_empty());
    }

    #[test]
    fn a_builder_dialing_upstream_itself_is_named() {
        let direct =
            format!("{PROBE}\nfn forward(host: &str) {{ let _ = TcpStream::connect(host); }}\n");
        let violations = builder_socket_violations(&[builder_file("proxy.rs", &direct)]);
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert!(violations[0].contains("opens 2 TCP connection(s), of which 1"));
    }

    #[test]
    fn a_proxy_address_not_parsed_from_the_egress_client_is_not_a_probe() {
        let spoofed = "fn f() { let proxy_addr = upstream(); \
                       TcpStream::connect(&proxy_addr); }";
        let violations = builder_socket_violations(&[builder_file("init.rs", spoofed)]);
        assert_eq!(violations.len(), 1, "{violations:?}");
    }

    #[test]
    fn a_guest_local_listener_in_the_builder_is_named() {
        let listener = "fn serve() { let l = TcpListener::bind(addr); }";
        let violations = builder_socket_violations(&[builder_file("proxy.rs", listener)]);
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert!(violations[0].contains("TcpListener::bind("));
    }

    #[test]
    fn a_dial_inside_a_test_module_is_not_production() {
        let tested =
            format!("{PROBE}\n#[cfg(test)]\nmod tests {{ fn t() {{ TcpStream::connect(x); }} }}\n");
        assert!(builder_socket_violations(&[builder_file("init.rs", &tested)]).is_empty());
    }

    #[test]
    fn production_code_after_an_inline_test_module_is_still_read() {
        let late = "#[cfg(test)]\nmod tests { }\nfn after() { TcpStream::connect(host); }";
        let violations = builder_socket_violations(&[builder_file("init.rs", late)]);
        assert_eq!(violations.len(), 1, "{violations:?}");
    }

    #[test]
    fn the_retired_proxy_binary_in_a_manifest_is_named() {
        let manifest = "[[bin]]\nname = \"mvm-egress-proxy\"\n";
        assert_eq!(
            retired_builder_binary_violations("crates/mvm-build/Cargo.toml", manifest).len(),
            1
        );
        assert!(
            retired_builder_binary_violations("crates/mvm-build/Cargo.toml", "[[bin]]\n")
                .is_empty()
        );
    }

    #[test]
    fn a_qemu_nic_argument_is_named_and_a_comment_or_test_is_not() {
        let clean = "// no virtio-net here\nfn launch() { cmd.arg(\"-device\").arg(\"vhost-vsock-pci\"); }\n\
                     #[cfg(test)]\nmod tests { fn t() { assert!(!a.contains(\"-netdev\")); } }\n";
        assert!(qemu_nic_violations(QEMU_BUILDER_RS, clean).is_empty());
        let nic = "fn launch() { cmd.args([\"-netdev\", \"user,id=n0\"]); }";
        assert_eq!(qemu_nic_violations(QEMU_BUILDER_RS, nic).len(), 2);
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
