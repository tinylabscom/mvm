//! End-to-end CLI tests for the template registry.
//!
//! These exercises `mvmctl template` and `mvmctl generate template` against a
//! local `file://` registry so they stay fast and offline.

use std::process::Command;

use assert_cmd::cargo::CommandCargoExt;

/// Build a local registry directory with one template and return its path.
fn setup_local_registry() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    let reg = tmp.path().join("registry");
    let tpl = reg.join("templates/demo");
    std::fs::create_dir_all(&tpl).unwrap();

    let index = serde_json::json!({
        "schema_version": 1,
        "templates": [{
            "name": "demo",
            "description": "demo remote template",
            "path": "templates/demo",
            "mvm_version": ">=0.1.0"
        }]
    });
    std::fs::write(reg.join("index.json"), index.to_string()).unwrap();

    std::fs::write(
        tpl.join("template.toml"),
        r#"name = "demo"
description = "demo remote template"
default_vcpus = 2
default_memory_mib = 512
tags = ["demo"]
files = ["app.py"]
"#,
    )
    .unwrap();

    std::fs::write(
        tpl.join("flake.nix"),
        r#"{ pkgs }:
{
  mkGuest = { ... }: {
    entrypoint = "hello";
  };
}
"#,
    )
    .unwrap();

    std::fs::write(
        tpl.join("app.py"),
        r#"import mvm

@mvm.app(
    image=mvm.python_image(python="3.12"),
    resources=mvm.resources(cpu=1, memory_mb=256),
)
def main() -> str:
    return "hello"
"#,
    )
    .unwrap();

    tmp
}

#[test]
fn template_list_shows_bundled_presets() {
    #[allow(deprecated)]
    let out = Command::cargo_bin("mvmctl")
        .unwrap()
        .args(["template", "list"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "template list must exit 0, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("minimal"),
        "list must include the minimal bundled preset:\n{stdout}"
    );
    assert!(
        stdout.contains("python"),
        "list must include the python bundled preset:\n{stdout}"
    );
}

#[test]
fn template_info_shows_bundled_python() {
    #[allow(deprecated)]
    let out = Command::cargo_bin("mvmctl")
        .unwrap()
        .args(["template", "info", "python"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "template info python must exit 0, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("source:      bundled"),
        "python must resolve from the bundled catalog:\n{stdout}"
    );
}

#[test]
fn generate_template_fetches_and_scaffolds_remote_template() {
    let reg = setup_local_registry();
    let mvm_home = tempfile::tempdir().unwrap();
    let out_dir = tempfile::tempdir().unwrap();
    let project_dir = out_dir.path().join("demo");

    let registry_url = format!("file://{}", reg.path().join("registry").display());

    #[allow(deprecated)]
    let out = Command::cargo_bin("mvmctl")
        .unwrap()
        .env("MVM_TEMPLATE_REGISTRY", &registry_url)
        .env("MVM_HOME", mvm_home.path())
        .args([
            "generate",
            "template",
            "demo",
            &project_dir.to_string_lossy(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "generate template demo must exit 0, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let generated_flake = project_dir.join("flake.nix");
    let generated_manifest = project_dir.join("mvm.toml");
    assert!(
        generated_flake.is_file(),
        "remote flake.nix must be scaffolded"
    );
    assert!(
        generated_manifest.is_file(),
        "mvm.toml must be scaffolded from template metadata"
    );
    let generated_app = project_dir.join("app.py");
    assert!(
        generated_app.is_file(),
        "declared extra files must be copied from the remote template"
    );

    let manifest = std::fs::read_to_string(generated_manifest).unwrap();
    assert!(
        manifest.contains("name = \"demo\""),
        "manifest must use the project directory name:\n{manifest}"
    );
    assert!(
        manifest.contains("vcpus = 2"),
        "manifest must use the template vcpu default:\n{manifest}"
    );
    assert!(
        manifest.contains("mem = \"512M\""),
        "manifest must use the template memory default:\n{manifest}"
    );

    // A second run should succeed idempotently.
    #[allow(deprecated)]
    let out2 = Command::cargo_bin("mvmctl")
        .unwrap()
        .env("MVM_TEMPLATE_REGISTRY", registry_url)
        .env("MVM_HOME", mvm_home.path())
        .args([
            "generate",
            "template",
            "demo",
            &project_dir.to_string_lossy(),
        ])
        .output()
        .unwrap();
    assert!(
        out2.status.success(),
        "re-running generate template demo must be idempotent, stderr: {}",
        String::from_utf8_lossy(&out2.stderr)
    );
}
