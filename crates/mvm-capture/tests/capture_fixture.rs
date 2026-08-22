//! End-to-end capture test using the repository fixture project.
//!
//! This test does not depend on the developer's host state: it uses a checked-in
//! Rust project with stable contents and asserts on the shape of the capture
//! report, the resolved workload, and the rendered Nix artifacts.

use std::path::PathBuf;

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/capture/rust-hello")
        .canonicalize()
        .expect("fixture exists")
}

#[test]
fn capture_report_is_versioned_and_contains_manifests() {
    let opts = mvm_capture::collect::CollectOptions {
        project_path: fixture_root(),
        explicit_commands: vec!["cargo run".to_owned()],
        ..Default::default()
    };
    let report = mvm_capture::collect::collect_project(&opts).expect("collect succeeds");

    assert_eq!(
        report.schema_version,
        mvm_capture::report::CAPTURE_SCHEMA_VERSION
    );
    assert!(!report.observations.is_empty());

    assert!(
        report.observations.iter().any(|o| {
            o.kind == mvm_capture::report::ObservationKind::ProjectManifest
                && o.path.as_deref() == Some("Cargo.toml")
        }),
        "Cargo.toml observed"
    );
    assert!(
        report.observations.iter().any(|o| {
            o.kind == mvm_capture::report::ObservationKind::Lockfile
                && o.path.as_deref() == Some("Cargo.lock")
        }),
        "Cargo.lock observed"
    );
}

#[test]
fn secret_value_is_not_emitted_in_report() {
    let project = tempfile::tempdir().expect("secret fixture directory");
    std::fs::write(
        project.path().join(".env"),
        "DATABASE_URL=postgres://admin:super_secret_value_12345@db/app\n",
    )
    .expect("write secret fixture");
    let opts = mvm_capture::collect::CollectOptions {
        project_path: project.path().to_path_buf(),
        ..Default::default()
    };
    let report = mvm_capture::collect::collect_project(&opts).expect("collect succeeds");
    let json = serde_json::to_string_pretty(&report).expect("serializable");

    assert!(
        !json.contains("super_secret_value_12345"),
        "secret literal must not appear in serialized report"
    );
    assert!(
        !json.contains("postgres://admin"),
        "secret-bearing .env content must not appear in serialized report"
    );

    let env_obs = report.observations.iter().find(|o| {
        o.kind == mvm_capture::report::ObservationKind::ConfigurationFile
            && o.evidence.sensitivity == mvm_capture::report::Sensitivity::Secret
    });
    assert!(env_obs.is_some(), ".env observed");
    let env_obs = env_obs.unwrap();
    assert!(
        env_obs.evidence.content_hash.is_none(),
        "content hash redacted for secret file"
    );
    assert!(env_obs.path.is_none(), "path redacted for secret file");
}

#[test]
fn resolve_produces_canonical_workload_with_unresolved_items() {
    let opts = mvm_capture::collect::CollectOptions {
        project_path: fixture_root(),
        explicit_commands: vec!["cargo run".to_owned()],
        ..Default::default()
    };
    let report = mvm_capture::collect::collect_project(&opts).expect("collect succeeds");
    let result = mvm_capture::resolve::resolve_report(&report).expect("resolve succeeds");

    assert_eq!(result.workload.id, "captured-project");
    assert_eq!(result.workload.apps.len(), 1);
    let app = &result.workload.apps[0];
    let packages = match &app.image {
        mvm_contract::ir::Image::NixPackages { packages } => packages,
        _ => panic!("expected NixPackages image"),
    };
    assert!(
        packages.iter().any(|p| p == "cargo"),
        "cargo package inferred"
    );
    assert!(
        packages.iter().any(|p| p == "rustc"),
        "rustc package inferred"
    );

    // Native package observations remain unresolved because Debian package
    // names are not nixpkgs attributes.
    assert!(
        !result.unresolved.is_empty() || cfg!(not(target_os = "linux")),
        "there should be at least one unresolved item on Linux"
    );
}

#[test]
fn rendered_nix_contains_expected_flake_and_launch_json() {
    let opts = mvm_capture::collect::CollectOptions {
        project_path: fixture_root(),
        explicit_commands: vec!["cargo run".to_owned()],
        ..Default::default()
    };
    let report = mvm_capture::collect::collect_project(&opts).expect("collect succeeds");
    let result = mvm_capture::resolve::resolve_report(&report).expect("resolve succeeds");

    let out = tempfile::tempdir().expect("tempdir");
    mvm_sdk::compile::compile(&result.workload, out.path(), &fixture_root())
        .expect("compile renders Nix artifacts");

    let flake = out.path().join("flake.nix");
    let launch = out.path().join("launch.json");
    let workload_json = out.path().join("workload.json");

    assert!(flake.exists(), "flake.nix rendered");
    assert!(launch.exists(), "launch.json rendered");
    assert!(workload_json.exists(), "workload.json rendered");

    let flake_text = std::fs::read_to_string(&flake).expect("read flake.nix");
    assert!(
        flake_text.contains("launch = builtins.fromJSON"),
        "flake reads launch.json"
    );

    let launch_text = std::fs::read_to_string(&launch).expect("read launch.json");
    assert!(
        !launch_text.contains("super_secret_value_12345"),
        "secret value must not leak into launch.json"
    );
}
