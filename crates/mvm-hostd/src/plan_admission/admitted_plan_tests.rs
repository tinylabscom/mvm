#![cfg(test)]

use super::test_support::*;
use super::*;

#[test]
fn signed_runtime_identity_without_launch_evidence_is_not_admitted() {
    let mut plan = mvm_core::plan::test_support::PlanFixture::new().build();
    let digests = mvm_core::plan::RuntimeArtifactDigests {
        overlay_sha256: "a".repeat(64),
        overlay_verity_sha256: "b".repeat(64),
        overlay_roothash: "c".repeat(64),
        initramfs_sha256: "d".repeat(64),
    };
    plan.runtime_identity = Some(mvm_core::plan::RuntimeIdentity {
        archive_sha256: "f".repeat(64),
        version: "0.28.0".into(),
        arch: mvm_core::arch::GuestArch::host().to_string(),
        declaration: digests.clone(),
        selected: digests,
        signer_identity: "release@example.org".into(),
        signer_issuer: "https://issuer.example.org".into(),
    });
    let error = RunPosture::without_backend(Variant::Dev)
        .verify_launch_runtime(&plan)
        .expect_err("plan data cannot substitute for a verified launch-owned set");
    assert!(error.to_string().contains("no verified launch evidence"));
}

#[test]
fn release_proof_without_a_launch_owned_set_cannot_be_admitted() {
    let plan = mvm_core::plan::test_support::PlanFixture::new().build();
    let config = VmStartConfig {
        runtime_release_proof: Some(mvm_core::protocol::runtime_release::RuntimeReleaseProof {
            archive: "/untrusted/runtime.tar.gz".into(),
            checksum: "/untrusted/runtime.tar.gz.sha256".into(),
            signature_bundle: "/untrusted/runtime.tar.gz.bundle".into(),
            archive_sha256: "a".repeat(64),
            version: "0.28.0".into(),
            arch: mvm_core::arch::GuestArch::host(),
        }),
        ..Default::default()
    };
    let error = RunPosture::without_backend(Variant::Dev)
        .with_runtime(Some(&config))
        .verify_launch_runtime(&plan)
        .expect_err("a path-based proof cannot replace a verified runtime set");
    assert!(
        error
            .to_string()
            .contains("requires verified launch evidence")
    );
}

#[test]
fn a_verified_legacy_fork_keeps_its_existing_admission_path() {
    use mvm_core::checkpoint::{
        CheckpointClass, CheckpointId, CheckpointMeta, ContentBlob, HVF_FRAME_BLOB,
    };
    use mvm_vmm::runtime_artifacts::{RuntimeArtifact, RuntimeArtifacts};

    let (_env, home) = host_with_ceiling(Default::default());
    let fixture = tempfile::tempdir().expect("signed legacy fixture");
    let selected = mvm_runtime::signed_legacy_runtime_fixture(fixture.path(), home.path(), false);
    let (config, binding) =
        mvm_runtime::runtime_evidence::retained_legacy_runtime_fixture(&selected)
            .expect("retain legacy fixture before checkpoint capture");
    let observe = |path: &str| RuntimeArtifact {
        path: path.into(),
        sha256: mvm_core::crypto::image_verify::sha256_file(std::path::Path::new(path))
            .expect("fixture digest"),
    };
    let actual = RuntimeArtifacts {
        kernel: None,
        initramfs: config.initrd_path.as_deref().map(observe),
        disks: vec![observe(&config.rootfs_path)],
        kernel_cmdline: "console=hvc0".into(),
        firecracker_drives: None,
    };
    let store = mvm_runtime::checkpoint::CheckpointStore::at(home.path().join("checkpoints"));
    let id = CheckpointId::new("legacy-fork");
    let content = store.content_dir(&id);
    std::fs::create_dir_all(&content).expect("checkpoint content directory");
    let bytes = serde_json::to_vec(&actual).expect("runtime observation");
    std::fs::write(content.join("runtime-artifacts.json"), &bytes)
        .expect("checkpoint runtime evidence");
    let meta = CheckpointMeta::builder(id, CheckpointClass::VmFull, &config.name)
        .runtime_launch_binding(Some(binding))
        .content(vec![
            ContentBlob {
                name: "runtime-artifacts.json".into(),
                sha256: mvm_core::crypto::image_verify::sha256_reader(bytes.as_slice())
                    .expect("evidence digest"),
            },
            ContentBlob {
                name: HVF_FRAME_BLOB.into(),
                sha256: "ab".repeat(32),
            },
        ])
        .build();
    let retained = mvm_runtime::checkpoint::verify_checkpoint_runtime(&store, &meta)
        .expect("authenticated retained legacy generation");
    assert!(retained.identity().is_none());
    let plan = mvm_core::plan::test_support::PlanFixture::new().build();
    RunPosture::without_backend(Variant::Dev)
        .with_runtime(Some(&config))
        .with_verified_retained(Some(&retained))
        .verify_launch_runtime(&plan)
        .expect("legacy fork uses its prior verifier, not the warm-claim-only comparator");

    let mut invalid = config.clone();
    invalid
        .legacy_bundle_runtime
        .as_mut()
        .expect("legacy proof")
        .pin
        .bundle_sha256 = "0".repeat(64);
    assert!(
        RunPosture::without_backend(Variant::Dev)
            .with_runtime(Some(&invalid))
            .with_verified_retained(Some(&retained))
            .verify_launch_runtime(&plan)
            .is_err(),
        "a changed legacy proof still refuses"
    );
}

/// The root of this module, for the unforgeability check below.
const SOURCE: &str = include_str!("../plan_admission.rs");

/// A source file up to its first test module.
fn production_half(source: &str) -> &str {
    source
        .split_once("\n#[cfg(test)]\nmod ")
        .map_or(source, |(production, _)| production)
}

/// The production half of every file in this module tree — each file up to its
/// test modules, and none of the test files — so the checks below cannot be
/// satisfied by a string literal written here.
fn production_source() -> &'static str {
    static PRODUCTION: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    PRODUCTION.get_or_init(|| {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/plan_admission");
        let mut files: Vec<_> = std::fs::read_dir(&dir)
            .expect("the module directory is readable")
            .map(|entry| entry.expect("a directory entry").path())
            .filter(|path| {
                let name = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("");
                name.ends_with(".rs") && !name.ends_with("_tests.rs") && name != "test_support.rs"
            })
            .collect();
        files.sort();
        let mut production = production_half(SOURCE).to_owned();
        for file in files {
            let source = std::fs::read_to_string(&file).expect("a module source file");
            production.push('\n');
            production.push_str(production_half(&source));
        }
        production
    })
}

/// The body of the `AdmittedPlan` declaration, plus the derives above it.
fn admitted_plan_declaration() -> (&'static str, &'static str) {
    let (before, after) = production_source()
        .split_once("pub struct AdmittedPlan {")
        .expect("the type is declared in this file");
    let derives = before
        .rfind("#[derive(")
        .map(|at| &before[at..])
        .unwrap_or_default();
    let body = after
        .split_once("\n}")
        .expect("the declaration is brace-terminated")
        .0;
    (derives, body)
}

/// Every `impl ... for AdmittedPlan` line, i.e. trait impls on the type.
fn trait_impls_on_admitted_plan() -> Vec<&'static str> {
    production_source()
        .lines()
        .map(str::trim_start)
        .filter(|line| line.starts_with("impl") && line.contains("for AdmittedPlan"))
        .collect()
}

#[test]
fn an_admitted_plan_cannot_be_fabricated_outside_this_module() {
    // Downstream consumers — the share enforcer, the workload input gate —
    // treat a value of this type as proof that admission ran, so a caller
    // able to mint one has the authority admission was supposed to hold.
    // What stops them is a set of *absences* in this declaration, and an
    // absence is exactly what no runtime assertion can observe: the honest
    // form is a compile-fail test, and this workspace has no harness for
    // one. So the source is the assertion, and each branch below names the
    // public path it keeps closed.
    let (derives, body) = admitted_plan_declaration();

    // 1. No `pub` field: a struct literal needs every field named, and a
    //    private one makes the literal unwritable outside this module.
    //    Privacy also means no `&mut` reaches a field, so a caller holding
    //    a legitimately-admitted plan cannot afterwards push a service
    //    grant into it that admission never saw.
    for field in ["plan", "plan_id", "signer_id", "signed", "extensions"] {
        assert!(
            body.contains(&format!("\n    {field}: ")),
            "`AdmittedPlan.{field}` must stay private — a pub field is a forge"
        );
    }

    // 2. No derive that reconstitutes one: `Clone` would let a caller
    //    duplicate a legitimate plan (harmless alone, but it is the first
    //    half of clone-then-mutate), `Default` and `Deserialize` would
    //    each build one from nothing at all.
    for derive in ["Clone", "Default", "Deserialize", "Serialize"] {
        assert!(
            !derives.contains(derive),
            "`AdmittedPlan` must not derive {derive} — it is a second way to obtain one"
        );
    }

    // 3. No trait impl offering a conversion in: `From`/`TryFrom`, a
    //    hand-written `Default`, a `Deserialize` impl.
    assert!(
        trait_impls_on_admitted_plan().is_empty(),
        "no trait may be implemented for AdmittedPlan without re-checking \
         whether it hands out a construction path: {:?}",
        trait_impls_on_admitted_plan()
    );

    // 4. The one convenience constructor is compiled out of production.
    assert!(
        SOURCE.contains("#[cfg(test)]\n    pub(crate) fn for_test("),
        "the test constructor must stay `#[cfg(test)]` and crate-private"
    );

    // 5. And `finish_admission` is the only place that writes the literal.
    let literals = production_source().matches("Ok(AdmittedPlan {").count();
    assert_eq!(
        literals, 1,
        "exactly one production construction site, inside finish_admission"
    );
}
