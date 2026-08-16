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
