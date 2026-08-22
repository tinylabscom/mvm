//! Steps for `features/suites/s2_egress_vsock/one_transport.feature`.
//!
//! The point of these is to compare the two *sides* of the guest↔host egress
//! contract, not to re-test either side alone. They drive the real host writer
//! (`mvm_vmm::host::flowmux_identity`) and the real guest reader
//! (`mvm_agentd::flowmux_drive`) against each other in-process.

use cucumber::{given, then, when};

use crate::world::CliWorld;

fn host_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[11u8; 32])
}

fn mint(world: &mut CliWorld) -> std::path::PathBuf {
    use mvm_vmm::host::flowmux_identity::FlowMuxIdentityMaterial;

    let dir = world
        .one_transport_dir
        .get_or_insert_with(|| tempfile::tempdir().expect("tempdir"));
    let n = world.one_transport_drives.len();
    let path = dir.path().join(format!("identity-{n}.ext4"));
    let material =
        FlowMuxIdentityMaterial::mint(format!("session-{n}"), &host_key()).expect("mint identity");
    material.write_drive(&path).expect("write identity drive");
    world.one_transport_drives.push(path.clone());
    world.one_transport_material.push(material);
    path
}

#[given("a host-minted FlowMux identity drive")]
#[given("a second host-minted FlowMux identity drive")]
fn given_minted_drive(world: &mut CliWorld) {
    mint(world);
}

#[when("the guest identity reader inspects it")]
fn when_guest_reads(world: &mut CliWorld) {
    let path = world
        .one_transport_drives
        .last()
        .expect("a drive was minted");
    world.one_transport_image = Some(std::fs::read(path).expect("read the drive"));
}

#[then("the drive carries the guest signing key")]
fn then_drive_has_guest_key(world: &mut CliWorld) {
    // By NAME, which is how the guest actually looks it up -- and naming it
    // here is the whole point: the regression was a guest reading a path no
    // host code wrote. Asserting on the key bytes would need a private-key
    // accessor that should not exist.
    let image = world.one_transport_image.as_ref().expect("drive read");
    assert!(
        contains_window(
            image,
            mvm_agentd::flowmux_drive::GUEST_SIGNING_KEY_FILE.as_bytes()
        ),
        "the drive must carry a file named {}, which is what the guest opens",
        mvm_agentd::flowmux_drive::GUEST_SIGNING_KEY_FILE
    );
}

#[then("the drive carries the host-signer trust anchor")]
fn then_drive_has_anchor(world: &mut CliWorld) {
    let image = world.one_transport_image.as_ref().expect("drive read");
    assert!(
        contains_window(
            image,
            mvm_agentd::flowmux_drive::HOST_SIGNER_PUB_FILE.as_bytes()
        ),
        "the drive must carry a file named {}",
        mvm_agentd::flowmux_drive::HOST_SIGNER_PUB_FILE
    );
    assert!(
        contains_window(image, &host_key().verifying_key().to_bytes()),
        "and it must be the anchor for the key the endpoint signs with"
    );
}

#[then("the guest finds the drive by the label the host stamped")]
fn then_guest_finds_by_label(world: &mut CliWorld) {
    let image = world.one_transport_image.as_ref().expect("drive read");
    assert_eq!(
        mvm_agentd::flowmux_drive::ext4_volume_label_from_superblock(image).as_deref(),
        Some(mvm_agentd::flowmux_drive::IDENTITY_DRIVE_LABEL),
        "the guest's own decoder must recognise the host's label"
    );
}

#[then("the two drives carry different guest keys")]
fn then_drives_differ(world: &mut CliWorld) {
    assert_eq!(world.one_transport_material.len(), 2, "two mints expected");
    let a = &world.one_transport_material[0];
    let b = &world.one_transport_material[1];
    assert_ne!(
        a.spawn_config().guest_verifying_key_base64,
        b.spawn_config().guest_verifying_key_base64,
        "a per-boot identity must not repeat across boots"
    );
}

#[when("the host persists the half a warm child inherits")]
fn when_persist_inheritable(world: &mut CliWorld) {
    let dir = world.one_transport_dir.as_ref().expect("tempdir");
    let material = world.one_transport_material.last().expect("minted");
    material
        .persist_inheritable(dir.path())
        .expect("persist inheritable identity");
    let path = dir
        .path()
        .join(mvm_vmm::host::flowmux_identity::PUBLIC_IDENTITY_FILE);
    world.one_transport_persisted = Some(std::fs::read(&path).expect("read persisted identity"));
}

#[then("the persisted identity carries no guest signing key")]
fn then_no_guest_key_persisted(world: &mut CliWorld) {
    // The inheritable file exists so a warm child's endpoint can pin the key
    // its restored guest holds. It needs the PUBLIC half only.
    let raw = world.one_transport_persisted.as_ref().expect("persisted");
    let text = String::from_utf8_lossy(raw);
    assert!(
        !text.contains(mvm_agentd::flowmux_drive::GUEST_SIGNING_KEY_FILE),
        "the persisted identity must not reference the signing key at all"
    );
    assert!(
        text.contains("guest_verifying_key_base64"),
        "it must carry the verifying key, which is what a child pins"
    );
}

#[then("the persisted identity carries no host signing key")]
fn then_no_host_key_persisted(world: &mut CliWorld) {
    let raw = world.one_transport_persisted.as_ref().expect("persisted");
    let text = String::from_utf8_lossy(raw);
    let material = world.one_transport_material.last().expect("minted");
    assert!(
        !text.contains(&material.spawn_config().host_signing_key_base64),
        "the host signer's private key must not be copied into per-VM state"
    );
}

#[when("the host builds an endpoint config with a FlowMux identity")]
fn when_config_with_identity(world: &mut CliWorld) {
    world.one_transport_modes.push(endpoint_mode(true));
}

#[when("the host builds an endpoint config without a FlowMux identity")]
fn when_config_without_identity(world: &mut CliWorld) {
    world.one_transport_modes.push(endpoint_mode(false));
}

#[then(expr = "the endpoint is told to serve {string}")]
fn then_mode_is(world: &mut CliWorld, expected: String) {
    let mode = world
        .one_transport_modes
        .first()
        .expect("a config was built");
    assert_eq!(mode.0, expected);
}

#[then("the endpoint config carries the guest verifying key")]
fn then_config_carries_guest_key(world: &mut CliWorld) {
    let mode = world
        .one_transport_modes
        .first()
        .expect("a config was built");
    assert!(
        mode.1,
        "a flow_mux config must hand the endpoint the key it pins the guest to"
    );
}

#[then(expr = "no endpoint config selects {string}")]
fn then_no_config_selects(world: &mut CliWorld, forbidden: String) {
    assert!(
        !world.one_transport_modes.is_empty(),
        "configs were built first"
    );
    for (mode, _) in &world.one_transport_modes {
        assert_ne!(
            mode, &forbidden,
            "the retired protocol must not be selectable"
        );
    }
}

/// Build an endpoint config the way the production spawner does and report
/// `(egress_mode, carries_guest_key)`.
fn endpoint_mode(with_identity: bool) -> (String, bool) {
    use mvm_vmm::host::flowmux_identity::FlowMuxIdentityMaterial;
    use mvm_vmm::host::network_endpoint_spawn::endpoint_config_for_identity;

    let identity = with_identity.then(|| {
        FlowMuxIdentityMaterial::mint("session-cfg", &host_key())
            .expect("mint")
            .spawn_config()
            .clone()
    });
    let cfg = endpoint_config_for_identity(identity);
    let mode = cfg["egress_mode"].as_str().unwrap_or_default().to_string();
    let carries = cfg
        .get("flowmux_identity")
        .and_then(|i| i.get("guest_verifying_key_base64"))
        .is_some();
    (mode, carries)
}

fn contains_window(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

// ── one protocol, mechanically ───────────────────────────────────────────

#[when("the one-protocol gate inspects the tree")]
fn when_gate_runs(_world: &mut CliWorld) {
    // The gate itself runs in CI as `xtask check-one-guest-protocol`; what
    // this scenario asserts is the property it enforces, against the same
    // sources, so the feature file states the rule rather than the tool.
}

#[then("it finds no retired line-marker protocol")]
fn then_no_line_markers(_world: &mut CliWorld) {
    let root = workspace_root();
    let markers = [
        "MVM_DNS/1",
        "MVM_ICMP/1",
        "MVM_SOCKS5_UDP/1",
        "MVM_HTTP_FORWARD/1",
    ];
    for file in rust_files(&root.join("crates/mvm-agentd/src")) {
        let text = std::fs::read_to_string(&file).expect("read guest source");
        for line in text.lines().filter(|l| !is_comment(l)) {
            for marker in markers {
                assert!(
                    !line.contains(marker),
                    "{} still speaks the retired marker {marker}",
                    file.display()
                );
            }
        }
    }
}

#[then("every guest dialer of the egress port is a FlowMux client")]
fn then_every_dialer_is_flowmux(_world: &mut CliWorld) {
    let root = workspace_root();
    let clients = ["SyncFlowMux", "FlowMuxClient", "FlowMuxReconnectClient"];
    for file in rust_files(&root.join("crates/mvm-agentd/src")) {
        if file.starts_with(root.join("crates/mvm-agentd/src/vsock")) {
            continue;
        }
        let text = std::fs::read_to_string(&file).expect("read guest source");
        let dials = text.lines().any(|l| {
            !is_comment(l) && (l.contains("EGRESS_PORT") || l.contains("EGRESS_VSOCK_PORT"))
        });
        if !dials {
            continue;
        }
        assert!(
            clients.iter().any(|c| text.contains(c)),
            "{} opens the egress port without a FlowMux client",
            file.display()
        );
    }
}

#[when("the wire contract is enumerated")]
fn when_contract_enumerated(_world: &mut CliWorld) {}

#[then("a typed HTTP flow is part of it")]
fn then_http_flow_in_contract(_world: &mut CliWorld) {
    use mvm_contract::protocol::network_flow::{FlowClass, Opcode};
    assert_eq!(Opcode::OpenHttp.class(), FlowClass::Http);
    assert!(Opcode::OpenHttp.is_open(), "OpenHttp must open a flow");
    assert!(
        Opcode::HttpComplete.is_terminal(),
        "an HTTP exchange must end"
    );
}

#[then("a one-shot ICMP echo is part of it")]
fn then_icmp_in_contract(_world: &mut CliWorld) {
    use mvm_contract::protocol::network_flow::{FlowClass, Opcode};
    assert_eq!(Opcode::IcmpEcho.class(), FlowClass::Icmp);
    assert!(Opcode::IcmpEcho.is_open(), "IcmpEcho must open a flow");
    assert!(
        Opcode::IcmpReply.is_terminal() && Opcode::IcmpRefused.is_terminal(),
        "an echo is answered once and done"
    );
}

// ── declared ingress stays on the authenticated transport ────────────────────────

fn exact_tcp_ingress() -> mvm_core::plan::IngressMapping {
    use mvm_core::plan::{IngressMapping, IngressProtocol, IngressTransform};

    IngressMapping::builder()
        .mapping_id(17)
        .protocol(IngressProtocol::Tcp)
        .host_addr("127.0.0.1")
        .host_port(8443)
        .guest_addr("127.0.0.1")
        .guest_port(8080)
        .transform(IngressTransform::Opaque)
        .build()
        .expect("valid exact ingress mapping")
}

#[given("a signed exact TCP ingress mapping")]
fn given_signed_exact_tcp_ingress(_world: &mut CliWorld) {
    exact_tcp_ingress()
        .validate()
        .expect("mapping is admissible");
}

#[then("the mapping targets only guest loopback")]
fn then_ingress_targets_loopback(_world: &mut CliWorld) {
    let mapping = exact_tcp_ingress();
    assert_eq!(mapping.guest_addr, "127.0.0.1");
    assert!(
        mvm_core::plan::IngressMapping::builder()
            .mapping_id(18)
            .protocol(mvm_core::plan::IngressProtocol::Tcp)
            .host_addr("127.0.0.1")
            .host_port(8444)
            .guest_addr("10.0.2.15")
            .guest_port(8080)
            .transform(mvm_core::plan::IngressTransform::Opaque)
            .build()
            .is_err()
    );
}

fn established_tcp_ingress_validator() -> mvm_contract::protocol::network_flow::SessionValidator {
    use mvm_contract::protocol::network_flow::{
        Direction, FrameFacts, IngressFlowKind, Opcode, SessionValidator,
    };

    let mut validator = SessionValidator::new_with_ingress([(17, IngressFlowKind::Tcp)]);
    validator
        .admit(&FrameFacts::new(Direction::GuestToHost, Opcode::Hello, 0))
        .expect("guest authenticates the FlowMux session");
    validator
        .admit(&FrameFacts::new(
            Direction::HostToGuest,
            Opcode::HelloAck,
            0,
        ))
        .expect("host acknowledges the authenticated FlowMux session");
    validator
}

#[then("an admitted host-initiated stream names only that mapping")]
fn then_ingress_names_admitted_mapping(_world: &mut CliWorld) {
    use mvm_contract::protocol::network_flow::{Direction, FrameFacts, Opcode};

    let mut validator = established_tcp_ingress_validator();
    validator
        .admit(
            &FrameFacts::new(Direction::HostToGuest, Opcode::InboundOpen, 2)
                .with_ingress_mapping(17),
        )
        .expect("signed host mapping opens on an even stream");
}

#[then("an undeclared host-initiated stream is refused")]
fn then_undeclared_ingress_is_refused(_world: &mut CliWorld) {
    use mvm_contract::protocol::network_flow::{Direction, FrameFacts, Opcode};

    let mut validator = established_tcp_ingress_validator();
    assert!(
        validator
            .admit(
                &FrameFacts::new(Direction::HostToGuest, Opcode::InboundOpen, 2)
                    .with_ingress_mapping(99),
            )
            .is_err()
    );
}

fn tls_ingress() -> mvm_core::plan::IngressMapping {
    use mvm_core::plan::{IngressMapping, IngressProtocol, IngressTransform};

    IngressMapping::builder()
        .mapping_id(19)
        .protocol(IngressProtocol::Tcp)
        .host_addr("127.0.0.1")
        .host_port(9443)
        .guest_addr("127.0.0.1")
        .guest_port(8080)
        .transform(IngressTransform::Tls)
        .tls_secret("INGRESS_TLS_PEM")
        .build()
        .expect("valid TLS ingress mapping")
}

fn tls_binding() -> mvm_core::plan::SecretBinding {
    mvm_core::plan::SecretBinding {
        name: "INGRESS_TLS_PEM".to_string(),
        source: mvm_core::plan::SecretSource::Keystore {
            address: "ingress/tls".to_string(),
        },
    }
}

#[given("a signed TLS ingress mapping with a same-plan keystore reference")]
fn given_signed_tls_ingress(_world: &mut CliWorld) {
    tls_ingress().validate().expect("TLS mapping is structural");
}

#[then("the TLS ingress material binding is admitted")]
fn then_tls_material_is_admitted(_world: &mut CliWorld) {
    mvm_core::plan::validate_ingress_material(&[tls_ingress()], &[tls_binding()])
        .expect("same-plan keystore material is admissible");
}

#[then("the serialized mapping contains only the secret reference")]
fn then_tls_serialization_is_reference_only(_world: &mut CliWorld) {
    let serialized = serde_json::to_string(&tls_ingress()).expect("serialize mapping");
    assert!(serialized.contains("INGRESS_TLS_PEM"));
    assert!(!serialized.contains("PRIVATE KEY"));
    assert!(!serialized.contains("key_pem"));
}

// ── substitution must be live before a placeholder is handed out ─────────

#[given("an endpoint config carrying a secret")]
fn given_secret_bearing_config(world: &mut CliWorld) {
    world.one_transport_state = Some(tempfile::tempdir().expect("tempdir"));
}

#[then("it refuses to serve without a substitution service")]
fn then_refuses_without_substitution(_world: &mut CliWorld) {
    // The endpoint binary owns the refusal; the property is that a config with
    // secrets and no assembled service is not servable.
    assert!(
        secrets_without_substitution_is_refused(),
        "a secret-bearing endpoint with no substitution service must refuse"
    );
}

#[then("it is admitted with one")]
fn then_admitted_with_substitution(_world: &mut CliWorld) {
    assert!(secrets_with_substitution_is_admitted());
}

// ── readiness fails closed ───────────────────────────────────────────────

#[given("a per-VM state dir whose endpoint is running")]
fn given_live_endpoint(world: &mut CliWorld) {
    use mvm_vmm::host::network_endpoint_spawn::SUBST_PID_FILE;
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join(SUBST_PID_FILE),
        std::process::id().to_string(),
    )
    .expect("write pid");
    world.one_transport_state = Some(dir);
}

#[given("an allow-host endpoint that authenticates after agent readiness")]
fn given_delayed_authenticated_endpoint(world: &mut CliWorld) {
    use mvm_vmm::host::network_endpoint_spawn::{
        SUBST_PID_FILE, SUBST_SESSION_FILE, SUBST_SESSION_READY_SOCKET,
    };
    use std::io::Write as _;

    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join(SUBST_PID_FILE),
        std::process::id().to_string(),
    )
    .expect("write pid");
    let listener =
        std::os::unix::net::UnixListener::bind(dir.path().join(SUBST_SESSION_READY_SOCKET))
            .expect("bind session readiness socket");
    let marker = dir.path().join(SUBST_SESSION_FILE);
    std::thread::spawn(move || {
        let (mut waiter, _) = listener.accept().expect("accept launch waiter");
        std::fs::write(marker, b"1").expect("record authenticated session");
        waiter.write_all(&[1]).expect("wake launch waiter");
    });
    world.one_transport_state = Some(dir);
}

#[given("a per-VM state dir with no endpoint")]
fn given_no_endpoint(world: &mut CliWorld) {
    world.one_transport_state = Some(tempfile::tempdir().expect("tempdir"));
}

#[then("a launch is refused because no guest authenticated")]
fn then_launch_refused(world: &mut CliWorld) {
    use mvm_vmm::host::network_endpoint_spawn::refuse_launch_without_endpoint_session;
    let dir = world.one_transport_state.as_ref().expect("state dir");
    let err = refuse_launch_without_endpoint_session("vm-bdd", dir.path())
        .expect_err("a launch with no session must be refused");
    assert!(
        err.to_string().contains("no guest ever authenticated"),
        "unexpected: {err}"
    );
}

#[then("a launch is admitted once a session is recorded")]
fn then_launch_admitted_after_session(world: &mut CliWorld) {
    use mvm_vmm::host::network_endpoint_spawn::{
        SUBST_SESSION_FILE, refuse_launch_without_endpoint_session,
    };
    let dir = world.one_transport_state.as_ref().expect("state dir");
    std::fs::write(dir.path().join(SUBST_SESSION_FILE), b"1").expect("record session");
    refuse_launch_without_endpoint_session("vm-bdd", dir.path()).expect("admitted");
}

#[then("the launch is admitted without the FlowMux identity-drive error")]
fn then_launch_waits_for_session(world: &mut CliWorld) {
    use mvm_vmm::host::network_endpoint_spawn::wait_for_endpoint_session;

    let dir = world.one_transport_state.as_ref().expect("state dir");
    wait_for_endpoint_session("vm-bdd", dir.path())
        .expect("the authenticated-session event admits the launch");
}

#[then("the launch is admitted")]
fn then_launch_admitted(world: &mut CliWorld) {
    use mvm_vmm::host::network_endpoint_spawn::refuse_launch_without_endpoint_session;
    let dir = world.one_transport_state.as_ref().expect("state dir");
    refuse_launch_without_endpoint_session("vm-bdd", dir.path())
        .expect("a boot with nothing to mediate must not be refused");
}

/// A config carrying one bound secret, as the spawner would hand it over.
fn secret_bearing_config() -> mvm_hostd::supervisor::network_endpoint::EndpointConfig {
    use mvm_core::plan::{SecretBinding, SecretSource};
    use mvm_hostd::supervisor::network_endpoint::{EndpointConfig, EndpointTransport};

    EndpointConfig {
        tenant_id: "local".into(),
        instance_id: "test".into(),
        secrets: vec![SecretBinding {
            name: "OPENAI_API_KEY".into(),
            source: SecretSource::Keystore {
                address: "openai".into(),
            },
        }],
        transport: EndpointTransport::Uds {
            path: "/tmp/mvm-one-transport-bdd.sock".into(),
        },
        redaction: mvm_core::policy::RedactionPolicy::default(),
        reversible_replacement: mvm_core::policy::ReversibleReplacementPolicy::default(),
        network_limits: mvm_core::plan::NetworkLimits::default(),
        ingress: Vec::new(),
        forward_timeout_secs: 30,
        proxy_https: None,
        proxy_http: None,
        no_proxy: None,
        secret_store_dir: None,
        binding_store_dir: None,
        terminator_listen: None,
        tls_intermediate: None,
        network_policy: None,
        egress_mode: Default::default(),
        session_marker: None,
        session_ready_socket: None,
        resolver: Default::default(),
        connector_uds_path: None,
        flowmux_identity: None,
    }
}

fn secrets_without_substitution_is_refused() -> bool {
    mvm_hostd::supervisor::network_endpoint::refuse_secrets_without_substitution(
        &secret_bearing_config(),
        false,
    )
    .is_err()
}

fn secrets_with_substitution_is_admitted() -> bool {
    mvm_hostd::supervisor::network_endpoint::refuse_secrets_without_substitution(
        &secret_bearing_config(),
        true,
    )
    .is_ok()
}

fn workspace_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf()
}

fn is_comment(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("//") || t.starts_with("/*") || t.starts_with('*')
}

fn rust_files(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&current) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    out
}
