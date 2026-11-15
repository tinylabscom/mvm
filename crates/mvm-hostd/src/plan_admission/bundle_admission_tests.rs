#![cfg(test)]

use super::admit::{BundleAdmissionContext, admit_for_run, admit_signed_plan_for_run};
use super::bundle_environment::BundleEnvironmentRefused;
use super::nonce_ledger::InMemoryNonceLedger;
use super::test_support::{fixture_input, host_with_ceiling};
use super::*;
use anyhow::Result;
use mvm_core::plan::{SynthesisInput, Variant, sign_plan, synthesize_plan};
use mvm_core::vm_backend::VmStartConfig;
use rand::Rng;

// ── Claim 9: admit-time bundle re-verify ─────────────────────
//
// Tests exercise the boundary between `synthesize_plan`'s
// `bundle_pin` (the input) and `admit_for_run`'s
// `BundleAdmissionContext` (the verifier seam). The mvm_plan
// bundle module already tests every BundleVerifyError /
// PlanBundleError variant in isolation; these tests prove the
// wiring fires when admit_for_run sees a pinned plan.

use mvm_core::plan::bundle::{
    BundleResolveError, BundleResolver, KeyId as BundleKeyId, PlanArtifact, TrustStore,
    bundle_sha256, key_id_from_pubkey, write_bundle,
};
use std::collections::HashMap;

struct FixedResolver(Vec<u8>);
impl BundleResolver for FixedResolver {
    fn resolve(&self, _bundle_sha256: &str) -> Result<Vec<u8>, BundleResolveError> {
        Ok(self.0.clone())
    }
}

struct MapTrust(HashMap<BundleKeyId, ed25519_dalek::VerifyingKey>);
impl TrustStore for MapTrust {
    fn lookup(&self, key_id: &BundleKeyId) -> Option<ed25519_dalek::VerifyingKey> {
        self.0.get(key_id).copied()
    }
}

/// Build a minimal signed bundle around `(kernel, rootfs)` bytes.
/// Returns the archive plus the matching `PlanArtifact` pin.
fn make_test_bundle(
    sk: &ed25519_dalek::SigningKey,
    kernel: &[u8],
    rootfs: &[u8],
) -> (Vec<u8>, PlanArtifact) {
    make_test_bundle_for_arch(
        sk,
        kernel,
        rootfs,
        &mvm_core::arch::GuestArch::host().to_string(),
    )
}

/// [`make_test_bundle`] with an explicit declared architecture, so the
/// cross-arch refusal can be exercised from either host.
fn make_test_bundle_for_arch(
    sk: &ed25519_dalek::SigningKey,
    kernel: &[u8],
    rootfs: &[u8],
    arch: &str,
) -> (Vec<u8>, PlanArtifact) {
    make_test_bundle_with_members(sk, kernel, rootfs, arch, Vec::new())
}

// Synthetic, locally signed admission fixtures, not released image or VM evidence.
fn make_test_bundle_with_members(
    sk: &ed25519_dalek::SigningKey,
    kernel: &[u8],
    rootfs: &[u8],
    arch: &str,
    members: Vec<mvm_core::plan::bundle::BundleMember>,
) -> (Vec<u8>, PlanArtifact) {
    use mvm_core::plan::bundle::{
        ARTIFACTS_DIR, ArtifactRole, BUNDLE_SCHEMA_VERSION, BundleArtifact, BundleManifest,
        sha256_hex,
    };
    let key_id = key_id_from_pubkey(&sk.verifying_key());
    let make_art = |name: &str, role: ArtifactRole, bytes: &[u8]| BundleArtifact {
        name: name.to_string(),
        role,
        path: format!("{ARTIFACTS_DIR}/{name}"),
        sha256: sha256_hex(bytes),
        size_bytes: bytes.len() as u64,
    };
    let manifest = BundleManifest {
        schema_version: BUNDLE_SCHEMA_VERSION,
        publisher: "test".to_string(),
        key_id: key_id.clone(),
        arch: arch.to_string(),
        kernel_version: None,
        profile: None,
        workload_label: None,
        created_at: "2026-05-13T00:00:00Z".to_string(),
        labels: std::collections::BTreeMap::new(),
        artifacts: vec![
            make_art("vmlinux", ArtifactRole::Kernel, kernel),
            make_art("rootfs.ext4", ArtifactRole::Rootfs, rootfs),
        ],
        members,
        verity: None,
        resources: None,
    };
    let archive = write_bundle(
        &manifest,
        sk,
        vec![
            (format!("{ARTIFACTS_DIR}/vmlinux"), kernel.to_vec()),
            (format!("{ARTIFACTS_DIR}/rootfs.ext4"), rootfs.to_vec()),
        ],
    )
    .expect("write_bundle");

    // Recover the signature bytes from the archive for the pin.
    let mut sig_bytes: Vec<u8> = Vec::new();
    let mut a = tar::Archive::new(std::io::Cursor::new(&archive));
    for entry in a.entries().unwrap() {
        let mut entry = entry.unwrap();
        if entry.path().unwrap().to_string_lossy() == "manifest.sig" {
            std::io::Read::read_to_end(&mut entry, &mut sig_bytes).unwrap();
            break;
        }
    }
    let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().unwrap();
    let pin = PlanArtifact::new(bundle_sha256(&archive), &sig_arr, key_id);
    (archive, pin)
}

fn input_with_pin<'a>(vm_name: &'a str, pin: &PlanArtifact) -> SynthesisInput<'a> {
    let mut input = fixture_input(vm_name);
    input.bundle_pin = Some(pin.clone());
    input
}

#[test]
fn direct_and_external_admission_refuse_unenforced_environment_requirements() {
    use mvm_core::plan::bundle::BundleMember;
    let (_env, _home) = host_with_ceiling(Default::default());
    let dir = tempfile::tempdir().unwrap();
    let sk = ed25519_dalek::SigningKey::from_bytes(&[37; 32]);
    let arch = mvm_core::arch::GuestArch::host().to_string();
    let fleet = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
    let mut config = mvm_core::user_config::load(None);
    config.trusted_plan_signers = vec![mvm_core::user_config::TrustedPlanSigner {
        signer_id: "requirements-fleet".into(),
        ed25519_pubkey_hex: hex::encode(fleet.verifying_key().as_bytes()),
    }];
    mvm_core::user_config::save(&config, None).unwrap();
    for (field, value, refused_field) in [
        (
            "entrypoint",
            serde_json::json!({"argv": ["/usr/bin/agent"], "working_dir": "/workspace"}),
            "entrypoint.working_dir",
        ),
        (
            "volumes",
            serde_json::json!([{"name": "workspace", "guest_path": "/workspace"}]),
            "volumes",
        ),
        (
            "services",
            serde_json::json!([{"name": "indexer", "argv": ["/usr/bin/indexer"]}]),
            "services",
        ),
    ] {
        let mut document = serde_json::json!({
            "descriptor_version": 1,
            "target": format!("{arch}-linux"),
            "entrypoint": { "argv": ["/usr/bin/agent"] },
        });
        document[field] = value;
        let mut members = vec![BundleMember::Environment(
            serde_json::from_value(document).unwrap(),
        )];
        if field == "volumes" {
            let BundleMember::Environment(environment) = &mut members[0] else {
                panic!("environment fixture");
            };
            environment.capabilities =
                vec![mvm_contract::plan::environment::EnvironmentCapability::HostVolumes];
            members.push(BundleMember::SecurityPosture(
                mvm_core::plan::BundleSecurityPosture {
                    profile: mvm_core::security::AgentProfile::Dev,
                    verity_protected: false,
                    requires_auth: true,
                    allows_volumes: true,
                    allows_egress: false,
                },
            ));
        }
        let (archive, pin) =
            make_test_bundle_with_members(&sk, b"kernel", b"rootfs", &arch, members);
        let trust = MapTrust(HashMap::from([(
            key_id_from_pubkey(&sk.verifying_key()),
            sk.verifying_key(),
        )]));
        let resolver = FixedResolver(archive);
        let ctx = BundleAdmissionContext {
            resolver: &resolver,
            trust: &trust,
            image: None,
        };
        let input = input_with_pin("vm-requirements", &pin);
        let error = admit_for_run(
            &input,
            &SystemClock,
            &InMemoryNonceLedger::new(),
            Some(dir.path()),
            Some(&ctx),
            RunPosture::without_backend(Variant::Dev),
        )
        .expect_err("self-synthesized plans must meet signed requirements");
        assert!(format!("{error:#}").contains(refused_field), "{error:#}");
        let signed = sign_plan(
            &synthesize_plan(&input).unwrap(),
            &fleet,
            "requirements-fleet",
        );
        let ledger = InMemoryNonceLedger::new();
        for _ in 0..2 {
            let error = admit_signed_plan_for_run(
                &signed,
                &SystemClock,
                &ledger,
                Some(&ctx),
                RunPosture::without_backend(Variant::Dev),
            )
            .expect_err("external plans cannot bypass signed requirements");
            assert!(format!("{error:#}").contains(refused_field), "{error:#}");
        }
    }
}

#[test]
fn signed_environment_policy_refuses_missing_or_wider_actual_runtime() {
    use mvm_core::network_policy::NetworkPolicy;
    use mvm_core::plan::bundle::BundleMember;
    let (_env, _home) = host_with_ceiling(Default::default());
    let dir = tempfile::tempdir().unwrap();
    let sk = ed25519_dalek::SigningKey::from_bytes(&[37; 32]);
    let arch = mvm_core::arch::GuestArch::host().to_string();
    let environment = serde_json::from_value(serde_json::json!({
        "descriptor_version": 1,
        "target": format!("{arch}-linux"),
        "entrypoint": { "argv": ["/usr/bin/agent"] },
        "policy": { "allow_hosts": ["api.anthropic.com:443"] }
    }))
    .unwrap();
    let (archive, pin) = make_test_bundle_with_members(
        &sk,
        b"kernel",
        b"rootfs",
        &arch,
        vec![BundleMember::Environment(environment)],
    );
    let trust = MapTrust(HashMap::from([(
        key_id_from_pubkey(&sk.verifying_key()),
        sk.verifying_key(),
    )]));
    let resolver = FixedResolver(archive);
    let ctx = BundleAdmissionContext {
        resolver: &resolver,
        trust: &trust,
        image: None,
    };
    let input = input_with_pin("vm-policy", &pin);
    let fleet = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
    let mut config = mvm_core::user_config::load(None);
    config.trusted_plan_signers = vec![mvm_core::user_config::TrustedPlanSigner {
        signer_id: "policy-fleet".into(),
        ed25519_pubkey_hex: hex::encode(fleet.verifying_key().as_bytes()),
    }];
    mvm_core::user_config::save(&config, None).unwrap();
    let signed = sign_plan(&synthesize_plan(&input).unwrap(), &fleet, "policy-fleet");
    let wider = VmStartConfig {
        network_policy: NetworkPolicy::unrestricted(),
        ..Default::default()
    };
    for runtime in [None, Some(&wider)] {
        let posture = RunPosture::without_backend(Variant::Dev).with_runtime(runtime);
        let error = admit_for_run(
            &input,
            &SystemClock,
            &InMemoryNonceLedger::new(),
            Some(dir.path()),
            Some(&ctx),
            posture,
        )
        .expect_err("signed policy requires an actual bounded runtime");
        assert!(
            error.downcast_ref::<BundleEnvironmentRefused>().is_some(),
            "{error:#}"
        );
        assert!(
            format!("{error:#}").contains("actual launch network"),
            "{error:#}"
        );
        let ledger = InMemoryNonceLedger::new();
        for _ in 0..2 {
            let error =
                admit_signed_plan_for_run(&signed, &SystemClock, &ledger, Some(&ctx), posture)
                    .expect_err("external plans cannot bypass the runtime ceiling");
            assert!(
                error.downcast_ref::<BundleEnvironmentRefused>().is_some(),
                "{error:#}"
            );
            assert!(
                !format!("{error:#}").contains("replay protection"),
                "{error:#}"
            );
        }
    }
}

#[test]
fn direct_host_admission_enforces_signed_environment_slots() {
    use mvm_core::plan::bundle::BundleMember;
    let (_env, _home) = host_with_ceiling(Default::default());
    let dir = tempfile::tempdir().unwrap();
    let sk = ed25519_dalek::SigningKey::from_bytes(&[37; 32]);
    let arch = mvm_core::arch::GuestArch::host().to_string();
    let environment = serde_json::from_value(serde_json::json!({
        "descriptor_version": 1,
        "target": format!("{arch}-linux"),
        "entrypoint": { "argv": ["/usr/bin/agent"] },
        "secret_slots": [
            { "name": "AGENT_TOKEN", "required": true },
            { "name": "OPTIONAL_KEY", "required": false }
        ]
    }))
    .unwrap();
    let (archive, pin) = make_test_bundle_with_members(
        &sk,
        b"kernel",
        b"rootfs",
        &arch,
        vec![BundleMember::Environment(environment)],
    );
    let trust = MapTrust(HashMap::from([(
        key_id_from_pubkey(&sk.verifying_key()),
        sk.verifying_key(),
    )]));
    let resolver = FixedResolver(archive);
    let ctx = BundleAdmissionContext {
        resolver: &resolver,
        trust: &trust,
        image: None,
    };
    let mut input = input_with_pin("vm-environment", &pin);
    let error = admit_for_run(
        &input,
        &SystemClock,
        &InMemoryNonceLedger::new(),
        Some(dir.path()),
        Some(&ctx),
        RunPosture::without_backend(Variant::Dev),
    )
    .expect_err("direct host admission must refuse missing mandatory slot");
    assert!(format!("{error:#}").contains("AGENT_TOKEN"), "{error:#}");
    input.secrets = vec![mvm_core::plan::SecretBinding {
        name: "AGENT_TOKEN".into(),
        source: mvm_core::plan::SecretSource::Keystore {
            address: "agent-token".into(),
        },
        destinations: Vec::new(),
        approval_required: false,
    }];
    let admitted = admit_for_run(
        &input,
        &SystemClock,
        &InMemoryNonceLedger::new(),
        Some(dir.path()),
        Some(&ctx),
        RunPosture::without_backend(Variant::Dev),
    )
    .expect("bound required slot admits without binding optional slot");
    assert_eq!(admitted.plan().secrets.len(), 1);

    // Exercise the independently authenticated external-plan entry point,
    // not just the host's synthesis/signing wrapper.
    let fleet = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
    let mut config = mvm_core::user_config::load(None);
    config.trusted_plan_signers = vec![mvm_core::user_config::TrustedPlanSigner {
        signer_id: "environment-fleet".into(),
        ed25519_pubkey_hex: hex::encode(fleet.verifying_key().as_bytes()),
    }];
    mvm_core::user_config::save(&config, None).unwrap();
    let bound = sign_plan(admitted.plan(), &fleet, "environment-fleet");
    admit_signed_plan_for_run(
        &bound,
        &SystemClock,
        &InMemoryNonceLedger::new(),
        Some(&ctx),
        RunPosture::without_backend(Variant::Dev),
    )
    .expect("externally signed bound required slot admits");
    input.secrets.clear();
    let missing = synthesize_plan(&input).unwrap();
    let signed = sign_plan(&missing, &fleet, "environment-fleet");
    let ledger = InMemoryNonceLedger::new();
    let error = admit_signed_plan_for_run(
        &signed,
        &SystemClock,
        &ledger,
        Some(&ctx),
        RunPosture::without_backend(Variant::Dev),
    )
    .expect_err("externally signed plan must also bind mandatory slot");
    assert!(format!("{error:#}").contains("AGENT_TOKEN"), "{error:#}");
    let retry = admit_signed_plan_for_run(
        &signed,
        &SystemClock,
        &ledger,
        Some(&ctx),
        RunPosture::without_backend(Variant::Dev),
    )
    .expect_err("a rejected descriptor must not spend the nonce");
    assert!(format!("{retry:#}").contains("AGENT_TOKEN"), "{retry:#}");
    assert!(
        !format!("{retry:#}").contains("replay protection"),
        "{retry:#}"
    );
}

#[test]
fn admit_with_clean_pinned_bundle_passes() {
    // Generate the publisher key out of band, build a bundle,
    // enrol the pubkey in the trust store, hand admit_for_run a
    // matching pin + context.
    let (_env, _home) = host_with_ceiling(Default::default());
    let dir = tempfile::tempdir().unwrap();
    let sk = {
        let mut __ed_seed = [0u8; 32];
        rand::rng().fill_bytes(&mut __ed_seed);
        ed25519_dalek::SigningKey::from_bytes(&__ed_seed)
    };
    let (archive, pin) = make_test_bundle(&sk, b"kernel-bytes", b"rootfs-bytes");
    let mut map = HashMap::new();
    let key_id = key_id_from_pubkey(&sk.verifying_key());
    map.insert(key_id, sk.verifying_key());
    let trust = MapTrust(map);
    let resolver = FixedResolver(archive);
    let ctx = BundleAdmissionContext {
        resolver: &resolver,
        trust: &trust,
        image: None,
    };
    let admitted = admit_for_run(
        &input_with_pin("vm-pinned", &pin),
        &SystemClock,
        &InMemoryNonceLedger::new(),
        Some(dir.path()),
        Some(&ctx),
        RunPosture::without_backend(Variant::Dev),
    )
    .expect("clean pin admits");
    assert!(admitted.plan().bundle.is_some());
}

#[test]
fn admit_with_pin_but_no_context_refuses() {
    // Publisher misconfiguration: plan carries a pin but the
    // boot path didn't wire a BundleAdmissionContext. The
    // admit path refuses rather than silently skipping the
    // re-verify step (fail closed, not fail open).
    let (_env, _home) = host_with_ceiling(Default::default());
    let dir = tempfile::tempdir().unwrap();
    let sk = {
        let mut __ed_seed = [0u8; 32];
        rand::rng().fill_bytes(&mut __ed_seed);
        ed25519_dalek::SigningKey::from_bytes(&__ed_seed)
    };
    let (_archive, pin) = make_test_bundle(&sk, b"k", b"r");
    let err = admit_for_run(
        &input_with_pin("vm-no-ctx", &pin),
        &SystemClock,
        &InMemoryNonceLedger::new(),
        Some(dir.path()),
        None,
        RunPosture::without_backend(Variant::Dev),
    )
    .expect_err("must refuse without context");
    let msg = format!("{err:#}");
    assert!(msg.contains("BundleAdmissionContext"), "got: {msg}");
}

/// A pinned bundle built for the other architecture is refused at the trust
/// boundary, before any backend sees it. Without this the plan admits and
/// fails deep in boot with an unrelated-looking kernel error.
#[test]
fn admit_with_cross_arch_pinned_bundle_refuses() {
    let other = match mvm_core::arch::GuestArch::host() {
        mvm_core::arch::GuestArch::X86_64 => "aarch64",
        mvm_core::arch::GuestArch::Aarch64 => "x86_64",
    };
    let (_env, _home) = host_with_ceiling(Default::default());
    let dir = tempfile::tempdir().unwrap();
    let sk = {
        let mut __ed_seed = [0u8; 32];
        rand::rng().fill_bytes(&mut __ed_seed);
        ed25519_dalek::SigningKey::from_bytes(&__ed_seed)
    };
    let (archive, pin) = make_test_bundle_for_arch(&sk, b"kernel-bytes", b"rootfs-bytes", other);
    let mut map = HashMap::new();
    map.insert(key_id_from_pubkey(&sk.verifying_key()), sk.verifying_key());
    let trust = MapTrust(map);
    let resolver = FixedResolver(archive);
    let ctx = BundleAdmissionContext {
        resolver: &resolver,
        trust: &trust,
        image: None,
    };
    let err = admit_for_run(
        &input_with_pin("vm-cross-arch", &pin),
        &SystemClock,
        &InMemoryNonceLedger::new(),
        Some(dir.path()),
        Some(&ctx),
        RunPosture::without_backend(Variant::Dev),
    )
    .expect_err("a foreign-arch bundle must not be admitted");
    let msg = format!("{err:#}");
    assert!(msg.contains("but this host is"), "{msg}");
    assert!(msg.contains(other), "{msg}");
}

#[test]
fn admit_with_unknown_publisher_in_trust_store_refuses() {
    let (_env, _home) = host_with_ceiling(Default::default());
    let dir = tempfile::tempdir().unwrap();
    let sk = {
        let mut __ed_seed = [0u8; 32];
        rand::rng().fill_bytes(&mut __ed_seed);
        ed25519_dalek::SigningKey::from_bytes(&__ed_seed)
    };
    let (archive, pin) = make_test_bundle(&sk, b"k", b"r");
    // Empty trust store — publisher's key_id is unknown locally.
    let trust = MapTrust(HashMap::new());
    let resolver = FixedResolver(archive);
    let ctx = BundleAdmissionContext {
        resolver: &resolver,
        trust: &trust,
        image: None,
    };
    let err = admit_for_run(
        &input_with_pin("vm-untrusted", &pin),
        &SystemClock,
        &InMemoryNonceLedger::new(),
        Some(dir.path()),
        Some(&ctx),
        RunPosture::without_backend(Variant::Dev),
    )
    .expect_err("must refuse unknown publisher");
    let msg = format!("{err:#}");
    // The error chain bubbles up the BundleVerifyError::UnknownKey
    // variant from the read_and_verify pass.
    assert!(
        err.chain().any(|e| e.to_string().contains("key_id")),
        "expected key_id mention; got: {msg}"
    );
}

#[test]
fn admit_with_pin_mismatching_archive_refuses() {
    // Resolver returns a different archive than the pin describes.
    // The bundle_sha256 cross-check catches it before the
    // signature verify even runs.
    let (_env, _home) = host_with_ceiling(Default::default());
    let dir = tempfile::tempdir().unwrap();
    let sk = {
        let mut __ed_seed = [0u8; 32];
        rand::rng().fill_bytes(&mut __ed_seed);
        ed25519_dalek::SigningKey::from_bytes(&__ed_seed)
    };
    let (_archive_a, pin_a) = make_test_bundle(&sk, b"kA", b"rA");
    let (archive_b, _pin_b) = make_test_bundle(&sk, b"kB", b"rB");
    let mut map = HashMap::new();
    map.insert(key_id_from_pubkey(&sk.verifying_key()), sk.verifying_key());
    let trust = MapTrust(map);
    let resolver = FixedResolver(archive_b);
    let ctx = BundleAdmissionContext {
        resolver: &resolver,
        trust: &trust,
        image: None,
    };
    let err = admit_for_run(
        &input_with_pin("vm-pin-drift", &pin_a),
        &SystemClock,
        &InMemoryNonceLedger::new(),
        Some(dir.path()),
        Some(&ctx),
        RunPosture::without_backend(Variant::Dev),
    )
    .expect_err("must refuse pin drift");
    assert!(
        err.chain().any(|e| e.to_string().contains("sha256")),
        "expected sha256 mismatch chain; got {err:#}"
    );
}
