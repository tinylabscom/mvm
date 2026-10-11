//! Build-recorder regressions exercising the real signed audit chain.

#![cfg(test)]

use super::{ImageNodeInputs, ImageNodeOutcome, record_image_node};
use crate::checkpoint::SignedChainAnchor;
use mvm_core::checkpoint::ContentBlob;
use mvm_core::image_lineage::{ImageBuildIdentity, ImageCanonicalId, ImageProvenance};
use mvm_hostd::audit::{emitter::AuditEmitter, host_keypair::load_or_init};
use mvm_runtime::image_lineage::{ImageStore, verify_image_lineage};

#[test]
fn build_path_nodes_verify_against_the_real_signed_chain() {
    let mut env = mvm_core::util::test_env::TestEnv::new();
    let tmp = tempfile::tempdir().unwrap();
    env.isolate_mvm_home(tmp.path());

    let store = ImageStore::open();
    let signer = load_or_init().unwrap();
    let emitter = AuditEmitter::new(signer.signing).unwrap();
    let plan = mvm_core::plan::test_support::PlanFixture::new()
        .tenant("local")
        .plan_id("plan-build-path")
        .build();

    let inputs = |revision: &str| ImageNodeInputs {
        build_identity: ImageBuildIdentity::Flake {
            slot_hash: "slot-a".into(),
        },
        canonical: ImageCanonicalId::Flake {
            revision_hash: revision.into(),
        },
        artifacts: vec![ContentBlob {
            name: "rootfs.ext4".into(),
            sha256: revision.into(),
        }],
        provenance: ImageProvenance::Build {
            input_ref: ".#app".into(),
            lock_digest: Some("sha256:lock".into()),
        },
    };

    let genesis = match record_image_node(
        &store,
        &emitter,
        &plan,
        &inputs("rev-1"),
        1,
        &SignedChainAnchor::load().unwrap(),
    )
    .unwrap()
    {
        ImageNodeOutcome::Created(d) => d,
        other => panic!("expected Created, got {other:?}"),
    };
    // Rebuilding the same revision must not append a second node.
    assert!(matches!(
        record_image_node(
            &store,
            &emitter,
            &plan,
            &inputs("rev-1"),
            2,
            &SignedChainAnchor::load().unwrap(),
        )
        .unwrap(),
        ImageNodeOutcome::AlreadyCurrent(_)
    ));
    let child = match record_image_node(
        &store,
        &emitter,
        &plan,
        &inputs("rev-2"),
        3,
        &SignedChainAnchor::load().unwrap(),
    )
    .unwrap()
    {
        ImageNodeOutcome::Created(d) => d,
        other => panic!("expected Created, got {other:?}"),
    };
    assert_eq!(
        store.by_digest(&child).unwrap().unwrap().parent.as_ref(),
        Some(&genesis)
    );
    let anchor = SignedChainAnchor::load().unwrap();
    verify_image_lineage(&store, &child, &anchor).unwrap();
    assert_eq!(
        store
            .head_for(&ImageBuildIdentity::Flake {
                slot_hash: "slot-a".into()
            })
            .unwrap()
            .unwrap()
            .node_digest,
        child
    );
}

#[test]
fn oci_pull_nodes_verify_against_the_real_signed_chain() {
    let mut env = mvm_core::util::test_env::TestEnv::new();
    let tmp = tempfile::tempdir().unwrap();
    env.isolate_mvm_home(tmp.path());

    let store = ImageStore::open();
    let signer = load_or_init().unwrap();
    let emitter = AuditEmitter::new(signer.signing).unwrap();
    let plan = mvm_core::plan::test_support::PlanFixture::new()
        .tenant("local")
        .plan_id("plan-oci-pull")
        .build();

    let inputs = |digest_hex: &str| ImageNodeInputs {
        build_identity: ImageBuildIdentity::Oci {
            registry: "docker.io".into(),
            repository: "library/alpine".into(),
        },
        canonical: ImageCanonicalId::Oci {
            resolved_digest: format!("sha256:{}", digest_hex.repeat(64)),
        },
        artifacts: vec![ContentBlob {
            name: "rootfs.ext4".into(),
            sha256: digest_hex.into(),
        }],
        provenance: ImageProvenance::Oci {
            resolved_digest: format!("sha256:{}", digest_hex.repeat(64)),
            layer_digests: vec![format!("sha256:{}", "e".repeat(64))],
        },
    };

    let genesis = match record_image_node(
        &store,
        &emitter,
        &plan,
        &inputs("a"),
        1,
        &SignedChainAnchor::load().unwrap(),
    )
    .unwrap()
    {
        ImageNodeOutcome::Created(d) => d,
        other => panic!("expected Created, got {other:?}"),
    };
    assert!(matches!(
        record_image_node(
            &store,
            &emitter,
            &plan,
            &inputs("a"),
            2,
            &SignedChainAnchor::load().unwrap(),
        )
        .unwrap(),
        ImageNodeOutcome::AlreadyCurrent(_)
    ));
    let child = match record_image_node(
        &store,
        &emitter,
        &plan,
        &inputs("b"),
        3,
        &SignedChainAnchor::load().unwrap(),
    )
    .unwrap()
    {
        ImageNodeOutcome::Created(d) => d,
        other => panic!("expected Created, got {other:?}"),
    };
    assert_eq!(
        store.by_digest(&child).unwrap().unwrap().parent.as_ref(),
        Some(&genesis)
    );
    let anchor = SignedChainAnchor::load().unwrap();
    verify_image_lineage(&store, &child, &anchor).unwrap();
}
