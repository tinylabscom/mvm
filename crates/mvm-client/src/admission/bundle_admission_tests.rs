//! Admission with a pinned bundle, end to end: the archive is verified against
//! the trust store under an isolated `MVM_HOME`, the pin is signed into the
//! plan, and the supervisor's admit-time re-verify runs against the same bytes.

use ed25519_dalek::SigningKey;
use mvm_core::util::test_env::TestEnv;

use super::admit_plan_tests::{pinning_params, write_rootfs};
use super::policy::bundle_pin_tests::make_bundle_for_pin;
use super::*;

/// Enrol the publisher of `sk` in `<MVM_HOME>/trusted-publishers/`, the
/// directory `FsTrustStore::default_path` resolves.
fn trust_publisher(mvm_home: &std::path::Path, sk: &SigningKey) {
    let key_id = mvm_core::plan::bundle::key_id_from_pubkey(&sk.verifying_key());
    let dir = mvm_home.join("trusted-publishers");
    std::fs::create_dir_all(&dir).expect("trust store dir");
    std::fs::write(
        dir.join(format!("{}.pub", key_id.0)),
        sk.verifying_key().to_bytes(),
    )
    .expect("enrol publisher");
}

/// A bundle carrying only a kernel and a rootfs makes no claim about which
/// backend may boot it, so admission must not demand one. The image-set
/// contract applies to bundles that embed an image set and to nothing else:
/// asking every bundle for a backend would refuse a plain pinned bundle on
/// any caller that resolves its backend after admission, and handing the
/// supervisor an image contract for a set that does not exist has no backend
/// to describe.
#[test]
fn a_bundle_without_an_image_set_admits_before_a_backend_is_chosen() {
    let home = tempfile::tempdir().expect("mvm home");
    let mut env = TestEnv::new();
    env.isolate_mvm_home(home.path());

    let sk = SigningKey::from_bytes(&[7; 32]);
    trust_publisher(home.path(), &sk);
    let (archive, key_id) = make_bundle_for_pin(&sk);
    let bundle_path = home.path().join("plain.mvmpkg");
    std::fs::write(&bundle_path, &archive).expect("write bundle");

    let rootfs = write_rootfs(home.path(), b"bundle-pinned rootfs");
    let keys_dir = home.path().join("keys");
    let audit_dir = home.path().join("audit");
    let ledger = InMemoryNonceLedger::new();
    let mut params = pinning_params(&rootfs, &ledger);
    params.keys_dir = Some(&keys_dir);
    params.audit_dir = Some(&audit_dir);
    params.bundle_pin = Some(&bundle_path);
    assert!(params.backend_kind.is_none());

    let ctx = admit_plan_for_boot(params).expect("a plain bundle admits without a backend");

    let pin = ctx
        .admitted
        .plan()
        .bundle
        .as_ref()
        .expect("the signed plan carries the bundle pin");
    assert_eq!(pin.bundle_sha256, mvm_core::plan::bundle_sha256(&archive));
    assert_eq!(pin.key_id, key_id);
}
