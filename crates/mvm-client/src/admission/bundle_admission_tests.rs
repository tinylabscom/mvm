//! Admission with a pinned bundle, end to end: the archive is verified against
//! the trust store under an isolated `MVM_HOME`, the pin is signed into the
//! plan, and the supervisor's admit-time re-verify runs against the same bytes.

#![cfg(test)]

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

    // The boot must run the bundle it pins, so the rootfs carries the bundle's
    // own rootfs bytes.
    let rootfs = write_rootfs(home.path(), b"rootfs-bytes");
    let keys_dir = home.path().join("keys");
    let audit_dir = home.path().join("audit");
    let ledger = InMemoryNonceLedger::new();
    let mut params = pinning_params(&rootfs, &ledger);
    params.keys_dir = Some(&keys_dir);
    params.audit_dir = Some(&audit_dir);
    params.bundle_pin = Some(BundlePin::boots(&bundle_path));
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

/// A bundle installed into the registry under the isolated `MVM_HOME`, the way
/// `mvmctl bundle install` (and `bundle fetch`) leaves it.
struct InstalledFixture {
    home: tempfile::TempDir,
    _env: TestEnv,
    sha256: String,
}

impl InstalledFixture {
    fn new() -> Self {
        let home = tempfile::tempdir().expect("mvm home");
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let sk = SigningKey::from_bytes(&[9; 32]);
        trust_publisher(home.path(), &sk);
        let (archive, _) = make_bundle_for_pin(&sk);
        let trust = mvm_core::plan::FsTrustStore::default_path().expect("trust store");
        let installed = mvm_core::plan::BundleRegistry::default_path()
            .expect("registry")
            .install(&archive, &trust, false)
            .expect("install bundle");
        Self {
            home,
            _env: env,
            sha256: installed.sha256,
        }
    }

    fn install_dir(&self) -> std::path::PathBuf {
        mvm_core::config::bundles_dir().join(&self.sha256)
    }

    fn audit_dir(&self) -> std::path::PathBuf {
        self.home.path().join("audit")
    }

    /// Admit a boot of `--manifest <sha256>`: the artifacts and the pin come
    /// from the same resolution the transient run and entrypoint boots use.
    fn admit(&self) -> Result<AdmissionContext> {
        self.admit_with_kernel(true)
    }

    /// `with_kernel = false` is a tier that boots no kernel of the bundle's,
    /// so admission hashes none; the extracted copy is still checked.
    fn admit_with_kernel(&self, with_kernel: bool) -> Result<AdmissionContext> {
        let (_, kernel, _, rootfs, _) =
            mvm_runtime::vm::template::lifecycle::template_artifacts_for_boot(&self.sha256)?;
        let archive = mvm_runtime::vm::template::lifecycle::installed_bundle_archive(&self.sha256)?
            .expect("an installed bundle names its archive");
        let rootfs = std::path::PathBuf::from(rootfs);
        let kernel = std::path::PathBuf::from(kernel);
        let keys_dir = self.home.path().join("keys");
        let audit_dir = self.audit_dir();
        let ledger = InMemoryNonceLedger::new();
        let mut params = pinning_params(&rootfs, &ledger);
        params.kernel_path = with_kernel.then_some(kernel.as_path());
        params.keys_dir = Some(&keys_dir);
        params.audit_dir = Some(&audit_dir);
        params.bundle_pin = Some(BundlePin::boots(&archive));
        admit_plan_for_boot(params)
    }

    fn chain(&self) -> String {
        std::fs::read_to_string(self.audit_dir().join("local.jsonl")).unwrap_or_default()
    }

    fn flip_first_byte(&self, relative: &str) {
        let path = self.install_dir().join(relative);
        let mut bytes = std::fs::read(&path).expect("read installed file");
        bytes[0] ^= 0xff;
        std::fs::write(&path, bytes).expect("rewrite installed file");
    }

    /// Refuse, and record the refusal against the plan that pinned the bundle.
    fn assert_refused_and_audited(&self, err: &anyhow::Error, names: &str) {
        let message = format!("{err:#}");
        assert!(message.contains(names), "{message}");
        let chain = self.chain();
        assert!(chain.contains("plan.admitted"), "{chain}");
        assert!(chain.contains("plan.failed"), "{chain}");
        assert!(
            chain.contains(super::bundle_binding::BUNDLE_VERIFY_CLASS),
            "the refusal is classed as a bundle verification failure: {chain}"
        );
    }
}

/// An untouched installed bundle boots under a plan that pins it.
#[test]
fn an_installed_bundle_admits_with_its_pin_signed_into_the_plan() {
    let fixture = InstalledFixture::new();

    let ctx = fixture
        .admit()
        .expect("an untampered installed bundle admits");

    let pin = ctx
        .admitted
        .plan()
        .bundle
        .as_ref()
        .expect("a boot from an installed bundle pins it");
    assert_eq!(pin.bundle_sha256, fixture.sha256);
    assert!(!fixture.chain().contains("plan.failed"));
}

/// The extracted root filesystem is what boots. One flipped byte after install
/// is refused, though the archive beside it still verifies.
#[test]
fn an_installed_rootfs_changed_after_install_is_refused_at_admission() {
    let fixture = InstalledFixture::new();
    fixture.flip_first_byte("artifacts/rootfs.ext4");

    let err = fixture
        .admit()
        .expect_err("a tampered installed rootfs must not boot");

    fixture.assert_refused_and_audited(&err, "root filesystem");
}

#[test]
fn an_installed_kernel_changed_after_install_is_refused_at_admission() {
    let fixture = InstalledFixture::new();
    fixture.flip_first_byte("artifacts/vmlinux");

    let err = fixture
        .admit()
        .expect_err("a tampered installed kernel must not boot");

    fixture.assert_refused_and_audited(&err, "kernel");
}

/// Every extracted artifact is held to the signed manifest, not only the two
/// admission hashes for the plan: with no kernel pinned, a changed installed
/// kernel is still refused.
#[test]
fn every_installed_artifact_is_checked_not_only_the_ones_the_plan_pins() {
    let fixture = InstalledFixture::new();
    fixture.flip_first_byte("artifacts/vmlinux");

    let err = fixture
        .admit_with_kernel(false)
        .expect_err("a tampered installed artifact must not boot");

    fixture.assert_refused_and_audited(&err, "installed artifact");
}

/// The boot resolver reads the extracted `manifest.json`, which nothing signs
/// on its own. An edit that still parses is refused against the signed copy.
#[test]
fn an_installed_manifest_changed_after_install_is_refused_at_admission() {
    let fixture = InstalledFixture::new();
    let path = fixture.install_dir().join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).expect("read manifest")).expect("parse");
    manifest["profile"] = serde_json::Value::String("edited-after-install".to_string());
    std::fs::write(&path, serde_json::to_vec(&manifest).expect("encode")).expect("write");

    let err = fixture
        .admit()
        .expect_err("an edited installed manifest must not boot");

    fixture.assert_refused_and_audited(&err, "installed manifest");
}

/// The cached archive is the pin's source of truth; a changed archive fails
/// verification before a plan is synthesized, so nothing is admitted.
#[test]
fn a_cached_archive_changed_after_install_is_refused_before_a_plan_exists() {
    let fixture = InstalledFixture::new();
    let archive = mvm_core::config::bundles_dir().join(format!("{}.mvmpkg", fixture.sha256));
    let mut bytes = std::fs::read(&archive).expect("read archive");
    let last = bytes.len() / 2;
    bytes[last] ^= 0xff;
    std::fs::write(&archive, bytes).expect("rewrite archive");

    let err = fixture
        .admit()
        .expect_err("a tampered archive must not boot");

    assert!(format!("{err:#}").contains("verifying bundle"), "{err:#}");
    assert!(!fixture.chain().contains("plan.admitted"));
}

#[test]
fn a_missing_cached_archive_is_refused() {
    let fixture = InstalledFixture::new();
    std::fs::remove_file(
        mvm_core::config::bundles_dir().join(format!("{}.mvmpkg", fixture.sha256)),
    )
    .expect("remove archive");

    let err = fixture
        .admit()
        .expect_err("an installed bundle without its archive must not boot");

    assert!(
        format!("{err:#}").contains("reading bundle archive"),
        "{err:#}"
    );
}

/// A publisher removed from the trust store after install no longer vouches
/// for the bundle, so its boots stop.
#[test]
fn an_installed_bundle_whose_publisher_is_no_longer_trusted_is_refused() {
    let fixture = InstalledFixture::new();
    std::fs::remove_dir_all(fixture.home.path().join("trusted-publishers"))
        .expect("untrust publisher");

    let err = fixture
        .admit()
        .expect_err("an untrusted publisher's bundle must not boot");

    assert!(format!("{err:#}").contains("verifying bundle"), "{err:#}");
}

/// A VM booted from the installed bundle, its plan persisted the way a boot
/// leaves it, so a fork or restore of it can read which bundle it ran.
struct BundleBootedParent {
    fixture: InstalledFixture,
    vm_name: &'static str,
}

impl BundleBootedParent {
    fn new() -> Self {
        let fixture = InstalledFixture::new();
        let ctx = fixture.admit().expect("the parent boots its bundle");
        let vm_name = "bundle-parent";
        mvm_hostd::audit::plan_persist::write_plan(vm_name, ctx.admitted.plan())
            .expect("persist the parent's plan");
        Self { fixture, vm_name }
    }

    /// Admit a child the way fork and restore do: the child boots its own
    /// copy of the parent's disk, which is no member of the bundle, under the
    /// pin it inherits from the parent's plan.
    fn admit_child(&self) -> Result<AdmissionContext> {
        let inherited = InheritedBundle::of_parent_vm(self.vm_name)?
            .expect("a bundle-booted parent's plan names its bundle");
        let child_dir = self.fixture.home.path().join("child");
        std::fs::create_dir_all(&child_dir).expect("child dir");
        let rootfs = write_rootfs(&child_dir, b"the parent's disk, as captured");
        let keys_dir = self.fixture.home.path().join("keys");
        let audit_dir = self.fixture.audit_dir();
        let ledger = InMemoryNonceLedger::new();
        let mut params = pinning_params(&rootfs, &ledger);
        params.vm_name = "bundle-child";
        params.keys_dir = Some(&keys_dir);
        params.audit_dir = Some(&audit_dir);
        params.bundle_pin = Some(inherited.pin());
        admit_plan_for_boot(params)
    }

    fn archive(&self) -> std::path::PathBuf {
        mvm_core::config::bundles_dir().join(format!("{}.mvmpkg", self.fixture.sha256))
    }
}

/// The child inherits the parent's pin: its own plan names the parent's
/// bundle, though the disk it boots is the parent's captured state.
#[test]
fn a_child_of_a_bundle_booted_parent_is_admitted_under_the_parents_bundle() {
    let parent = BundleBootedParent::new();

    let ctx = parent
        .admit_child()
        .expect("an untouched bundle admits the child");

    let pin = ctx
        .admitted
        .plan()
        .bundle
        .as_ref()
        .expect("the child's plan pins the parent's bundle");
    assert_eq!(pin.bundle_sha256, parent.fixture.sha256);
}

/// Files of the bundle changed after the parent booted refuse the child, and
/// the refusal is recorded against the child's plan.
#[test]
fn a_bundle_changed_after_the_parent_booted_refuses_its_child() {
    let parent = BundleBootedParent::new();
    parent.fixture.flip_first_byte("artifacts/rootfs.ext4");

    let err = parent
        .admit_child()
        .expect_err("a tampered bundle must not admit a child");

    parent
        .fixture
        .assert_refused_and_audited(&err, "installed artifact");
}

/// An archive replaced by a different bundle, even one a trusted publisher
/// signed, is not the bundle the parent ran.
#[test]
fn a_parent_archive_replaced_by_another_trusted_bundle_refuses_the_child() {
    let parent = BundleBootedParent::new();
    let other = SigningKey::from_bytes(&[3; 32]);
    trust_publisher(parent.fixture.home.path(), &other);
    let (replacement, _) = make_bundle_for_pin(&other);
    std::fs::write(parent.archive(), replacement).expect("replace archive");

    let err = parent
        .admit_child()
        .expect_err("a different bundle must not stand in for the parent's");

    parent
        .fixture
        .assert_refused_and_audited(&err, "the bundle changed after the parent booted");
}

/// A bundle uninstalled since the parent booted refuses its child rather than
/// letting it boot unpinned.
#[test]
fn a_bundle_uninstalled_after_the_parent_booted_refuses_its_child() {
    let parent = BundleBootedParent::new();
    std::fs::remove_file(parent.archive()).expect("remove archive");

    let err = parent
        .admit_child()
        .expect_err("a child of an uninstalled bundle must not boot");

    assert!(
        format!("{err:#}").contains("reading bundle archive"),
        "{err:#}"
    );
}

/// A parent that booted no bundle, or left no plan behind, gives its child no
/// pin, so those forks admit exactly as before.
#[test]
fn a_parent_without_a_bundle_gives_its_child_no_pin() {
    let home = tempfile::tempdir().expect("mvm home");
    let mut env = TestEnv::new();
    env.isolate_mvm_home(home.path());

    assert_eq!(InheritedBundle::of_parent_vm("never-booted").unwrap(), None);

    let rootfs = write_rootfs(home.path(), b"plain rootfs");
    let keys_dir = home.path().join("keys");
    let audit_dir = home.path().join("audit");
    let ledger = InMemoryNonceLedger::new();
    let mut params = pinning_params(&rootfs, &ledger);
    params.keys_dir = Some(&keys_dir);
    params.audit_dir = Some(&audit_dir);
    let ctx = admit_plan_for_boot(params).expect("an unpinned boot admits");
    assert!(ctx.admitted.plan().bundle.is_none());
    mvm_hostd::audit::plan_persist::write_plan("plain-parent", ctx.admitted.plan())
        .expect("persist plan");

    assert_eq!(InheritedBundle::of_parent_vm("plain-parent").unwrap(), None);
}

/// A parent plan that exists but cannot be read is not evidence of "no
/// bundle"; reading it as such would admit the child unpinned.
#[test]
fn an_unreadable_parent_plan_refuses_rather_than_dropping_the_pin() {
    let home = tempfile::tempdir().expect("mvm home");
    let mut env = TestEnv::new();
    env.isolate_mvm_home(home.path());
    let path = mvm_hostd::audit::plan_persist::plan_path("corrupt-parent").expect("plan path");
    std::fs::create_dir_all(path.parent().expect("state dir")).expect("state dir");
    std::fs::write(&path, b"{ not a plan").expect("write corrupt plan");
    std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
        .expect("tighten plan");

    let err = InheritedBundle::of_parent_vm("corrupt-parent")
        .expect_err("an unreadable plan must not read as unpinned");

    assert!(
        format!("{err:#}").contains("refusing to admit a child"),
        "{err:#}"
    );
}
