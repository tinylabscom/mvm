use mvm_client::prepared_image::{
    PreparedImageContext, PreparedImageErrorKind, PreparedImageTrust, PreparedOciSelection, select,
};

#[test]
fn prepared_selection_refuses_acquisition_and_unsupported_sources() {
    let home = tempfile::tempdir().unwrap();
    let mut env = mvm_core::util::test_env::TestEnv::new();
    env.isolate_mvm_home(home.path());
    env.remove("MVM_DIRECT_BOOT");
    let context = PreparedImageContext {
        backend: "hvf".into(),
    };
    let error = select("127.0.0.1:1/not-prepared:latest", &context).unwrap_err();
    assert_eq!(error.kind, PreparedImageErrorKind::NotPrepared);
    assert_eq!(error.code(), "PREPARED_IMAGE_NOT_PREPARED");
    assert!(!home.path().join("cache/oci/index.json").exists());
    for reference in ["oci-archive:/tmp/image.tar", "rootfs-dir:/tmp/root", "-"] {
        assert_eq!(
            select(reference, &context).unwrap_err().kind,
            PreparedImageErrorKind::UnsupportedMode
        );
    }
}

#[test]
fn prepared_selection_refuses_non_vm_backends() {
    let context = PreparedImageContext {
        backend: "wasm".into(),
    };
    assert_eq!(
        select("alpine:3.20", &context).unwrap_err().kind,
        PreparedImageErrorKind::UnsupportedMode
    );
}

#[test]
fn prepared_transient_and_production_requests_refuse_before_resolution() {
    let expected = PreparedOciSelection {
        canonical_reference: "127.0.0.1:1/not-prepared:latest".into(),
        manifest_digest: format!("sha256:{}", "0".repeat(64)),
        rootfs_sha256: "0".repeat(64),
        verity_sha256: "0".repeat(64),
        roothash: "0".repeat(64),
        guest_sidecar_sha256: "0".repeat(64),
        runtime_identity: "expected-runtime".into(),
        platform: "linux/arm64".into(),
        backend: "hvf".into(),
        layer_digests: Vec::new(),
        trust: PreparedImageTrust::DevelopmentDigestOnly,
    };
    for (mode, profile) in [
        (mvm_client::LifecycleMode::Transient, "standard"),
        (mvm_client::LifecycleMode::Persistent, "prod"),
    ] {
        let error = mvm_client::LaunchRequest::builder_for(
            mode,
            mvm_client::LaunchSource::PreparedImage {
                selection: expected.clone(),
            },
        )
        .name("unsupported-prepared")
        .profile(profile)
        .build()
        .unwrap_err();
        assert!(matches!(
            error,
            mvm_client::MvmError::PreparedImage { ref refusal }
                if refusal.kind == PreparedImageErrorKind::UnsupportedMode
        ));
        assert_eq!(error.code(), "PREPARED_IMAGE_UNSUPPORTED");
    }
}
