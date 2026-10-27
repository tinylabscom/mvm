//! Live HVF witness: `build_and_export_bundle` from a library process reaches
//! the driver-backed builder instead of refusing it as unregistered.
//!
//! `mvmctl` registers the HVF and Firecracker builder constructors at startup;
//! [`build_and_export_bundle`] registers them itself, so a plain test process
//! resolves the HVF builder exactly as the CLI does. What the process cannot
//! supply is the builder boot payload `mvmctl` embeds, so the published
//! (payload-ABI) builder image is refused before it boots — and the refusal
//! names the missing payload, never the registration.
//!
//! Ignored by default: drive it with `-- --ignored` on an Apple Silicon host
//! with a provisioned builder image (`mvmctl bootstrap`, or a warm default
//! cache to seed from) and the pinned guest toolchain. Without those it skips
//! cleanly, so the suite stays green everywhere else. The refusal fires while
//! the boot is being staged, before any `mvm-hvf-supervisor` is needed.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use mvm_build::builder_backend_select::{BuilderBackendChoice, resolve_choice};
use mvm_client::builder_bundle::{BuilderBundleRequest, build_and_export_bundle};
use mvm_client::bundle::{BundleSigner, HostBundleSigner};

/// The least a bundle request carries: a workspace, a flake attribute, and
/// where artifacts and the bundle would land. Nothing here is read by the
/// witness path — the refusal precedes the guest build — so every directory
/// is a stub.
fn request(root: &std::path::Path) -> BuilderBundleRequest {
    let workspace = root.join("workspace");
    let out = root.join("out");
    let bins = root.join("bins");
    for dir in [&workspace, &out, &bins] {
        std::fs::create_dir_all(dir).expect("request directories");
    }
    std::fs::write(workspace.join("flake.nix"), "{}\n").expect("stub flake");
    BuilderBundleRequest {
        workspace_root: workspace,
        flake_ref: "/work".to_string(),
        attr_path: "packages.aarch64-linux.default".to_string(),
        artifact_out: out,
        host_nix_store: None,
        host_bin_dir: bins,
        arch_label: "aarch64".to_string(),
        profile: None,
        label: Some("builder-registration-witness".to_string()),
        bundle_out: root.join("dist").join("witness.mvmpkg"),
        debug_out: None,
    }
}

/// The signer the export would use if a build ever completed. On the witness
/// path it is never asked: the refusal fires before any signing.
struct StubSigner(ed25519_dalek::SigningKey);

impl BundleSigner for StubSigner {
    fn publisher_id(&self) -> String {
        "test:builder-registration-witness".to_string()
    }

    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.0.verifying_key()
    }

    fn sign(&self, canonical_manifest: &[u8]) -> anyhow::Result<[u8; 64]> {
        Ok(ed25519_dalek::Signer::sign(&self.0, canonical_manifest).to_bytes())
    }
}

#[test]
#[ignore = "live HVF witness: needs a provisioned builder image and the pinned guest toolchain; run with -- --ignored"]
fn a_library_process_reaches_the_hvf_builder_and_is_refused_for_the_payload() {
    // A builder boot mints the guest's identity from the host signer, which
    // `mvmctl` creates on first use; the witness creates it the same way.
    let _host_signer = HostBundleSigner::load().expect("host signer");

    let tmp = tempfile::tempdir().expect("witness workspace");
    let request = request(tmp.path());
    let signer = StubSigner(ed25519_dalek::SigningKey::from_bytes(&[7; 32]));

    let outcome = build_and_export_bundle(&request, &signer);

    let Err(err) = outcome else {
        // The stronger witness: this host's builder image carried its own
        // binaries, so the library process booted a builder and sealed a
        // bundle outright.
        println!(
            "the build booted a builder and sealed {}",
            request.bundle_out.display()
        );
        assert!(request.bundle_out.is_file());
        return;
    };
    let chain = format!("{err:#}");
    println!("build_and_export_bundle refused the build with:\n{chain}");

    // Prerequisite gaps are a clean skip, not a failed witness...
    for (needle, explanation) in [
        (
            "builder VM image not found",
            "no builder image is cached on this host; run `mvmctl bootstrap` once",
        ),
        (
            "requires the runtime overlay but it could not be resolved",
            "the pinned guest toolchain (rust targets + zig) is incomplete on this host",
        ),
    ] {
        if chain.contains(needle) {
            eprintln!("skipping: {explanation}");
            return;
        }
    }

    // ...and the registration refusal this test guards can never read as one.
    assert!(
        !chain.contains("is not available on this host"),
        "the builder was refused as unavailable, not reached: {chain}"
    );
    assert!(
        !chain.contains("builder is registered"),
        "the builder was refused as unregistered: {chain}"
    );
    assert!(
        chain
            .contains("boots only with the builder boot payload, which this process does not have"),
        "the refusal names the missing payload: {chain}"
    );
    assert!(
        chain.contains("declares boot ABI"),
        "the refusal names the ABI the image declared: {chain}"
    );
    if resolve_choice(None) == BuilderBackendChoice::Hvf {
        assert!(
            chain.contains("hvf builder run"),
            "the HVF builder ran the request before the refusal: {chain}"
        );
    }
}
