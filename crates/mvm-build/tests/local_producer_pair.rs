//! Explicit cross-language acceptance against the pinned image producer.
//!
//! These tests invoke only Python's producer, never mvmctl, a builder or a VMM.
//! Execute the ignored test with explicit dependency paths for real evidence.

use std::path::{Path, PathBuf};
use std::process::Command;

use mvm_build::builder_vm::BUILDER_VM_CACHE_CONTRACT_VERSION;
use mvm_build::image_source::{
    EmitRequest, LocalImageCheckout, LocalSetRequest, OutputFile, OutputFormat, TargetContract,
    emit_local_manifest, probe_identity,
};
use mvm_core::arch::GuestArch;
use mvm_core::image_set::{
    BaseImageContractRange, HostProtocolSupport, ImageSetError, LocalCheckouts,
    LocalImageSetVerification, MvmCheckoutRule, verify_local_image_set,
};
use mvm_core::util::test_env::TestEnv;
use serde_json::Value;

const PRODUCER_COMMIT: &str = "1249f1606fc1f15218a8ea15d0b3f08e0bac60dc";
const ROOT_FILES: &[OutputFile] = &[OutputFile {
    name: "rootfs.ext4",
    role: "default_tenant_workload_rootfs",
    format: OutputFormat::Fixed("ext4"),
}];
const ROOTLESS_FILES: &[OutputFile] = &[OutputFile {
    name: "rootfs.ext4",
    role: "rootless_tenant_workload_rootfs",
    format: OutputFormat::Fixed("ext4"),
}];
const PREPARE: &str = r#"
import json
import sys
from pathlib import Path
from importlib.metadata import version
from dulwich.object_store import iter_tree_contents
from dulwich.repo import Repo

producer, parent, state, arch, role, expected_commit, cache_contract = sys.argv[1:]
producer, parent = Path(producer), Path(parent)
for package, expected in [("dulwich", "0.24.10"), ("ext4", "1.4.1")]:
    if version(package) != expected:
        raise SystemExit(f"pair acceptance requires {package}=={expected}")
with Repo(str(producer)) as repo:
    if repo.head().decode("ascii") != expected_commit:
        raise SystemExit("pair acceptance requires the exact pinned producer commit")
    pinned = {
        entry.path.decode("utf-8"): repo[entry.sha].data
        for entry in iter_tree_contents(repo.object_store, repo[repo.head()].tree)
        if entry.path.startswith(b"scripts/") and entry.path.endswith(b".py")
    }
    actual = {
        path.relative_to(producer).as_posix(): path
        for path in (producer / "scripts").rglob("*.py")
    }
    if actual.keys() != pinned.keys():
        raise SystemExit("producer Python source inventory differs from the pinned commit")
    for name, path in actual.items():
        current = producer
        for part in path.relative_to(producer).parts:
            current = current / part
            if current.is_symlink():
                raise SystemExit(f"producer source is symlinked: {name}")
        if not path.is_file() or path.read_bytes() != pinned[name]:
            raise SystemExit(f"producer source differs from the pinned commit: {name}")
# Never import from the admitted checkout: -B still reads cached bytecode.
# Construct a private source-only tree from the pinned Git blobs instead.
execution_source = parent / "reference-source"
for name, content in pinned.items():
    destination = execution_source / name
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(content)
sys.path.insert(0, str(execution_source / "scripts"))
sys.path.insert(0, str(execution_source / "scripts/tests"))
from test_local_mvm import images_checkout, eml

root = images_checkout(parent / "images", boot_abi="2\n")
if state == "dirty":
    with (root / "flake.nix").open("ab") as source:
        source.write(b"\n# cross-language acceptance edit\n")
built = parent / "built"
artifact = built / "rootfs.ext4"
if not artifact.is_file():
    raise SystemExit("pair acceptance requires the supplied supported-format ext4 fixture")
args = eml.parse_args([
    "--images-checkout", str(root), "--arch", arch,
    "--builder-cache-contract", cache_contract, "--out", str(parent / "python-set"),
    "--artifact", role, "ext4", str(artifact),
])
eml.emit(args)
(parent / "identity.json").write_text(json.dumps(eml.repo_identity(root)))
"#;

fn required_path(name: &str) -> PathBuf {
    std::env::var_os(name)
        .map(PathBuf::from)
        .unwrap_or_else(|| panic!("{name} must explicitly name the pair-validation dependency"))
}

fn json(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).expect("read pair evidence"))
        .expect("parse pair evidence")
}

fn supported_rootfs() -> Vec<u8> {
    use mvm_fs::ext4::{Node, Owner};
    // The existing Rust reader supports 256-byte inodes. Do not imply
    // support for the producer's legacy 128-byte-inode test fixture.
    let mut nodes = ["/etc", "/etc/mvm"]
        .into_iter()
        .map(|path| Node::Dir {
            path: path.into(),
            mode: 0o755,
            xattrs: Vec::new(),
            owner: Owner::ROOT,
        })
        .collect::<Vec<_>>();
    nodes.push(Node::File {
        path: "/etc/mvm/base-image-contract".into(),
        mode: 0o444,
        data: b"1\n".to_vec(),
        xattrs: Vec::new(),
        owner: Owner::ROOT,
    });
    mvm_fs::ext4::build_image(nodes, &Default::default())
        .expect("build supported ext4 pair fixture")
}

#[test]
#[ignore = "requires MVM_IMAGES_PAIR_CHECKOUT and MVM_IMAGES_PAIR_PYTHON; execute explicitly"]
fn pinned_reference_uses_verified_source_and_ignores_cached_bytecode() {
    let producer = required_path("MVM_IMAGES_PAIR_CHECKOUT");
    let python = required_path("MVM_IMAGES_PAIR_PYTHON");
    for (kind, reason) in [
        (
            "modified",
            Some("producer source differs from the pinned commit"),
        ),
        (
            "untracked",
            Some("producer Python source inventory differs"),
        ),
        ("bytecode", None),
    ] {
        let parent = tempfile::tempdir().expect("private reference refusal fixture");
        let cloned = parent.path().join("producer");
        let home = parent.path().join("home");
        let xdg = parent.path().join("xdg");
        let built = parent.path().join("built");
        std::fs::create_dir(&built).expect("create reference fixture output");
        std::fs::write(built.join("rootfs.ext4"), supported_rootfs())
            .expect("write reference ext4 fixture");
        let cloned_result = Command::new(&python)
            .env_clear()
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", &xdg)
            .env("PATH", "")
            .args([
                "-I",
                "-B",
                "-c",
                r#"
import sys
import importlib.util
import py_compile
from pathlib import Path
from dulwich import porcelain
source, destination, kind = sys.argv[1:]
porcelain.clone(source, destination)
root = Path(destination)
if kind == "modified":
    source = root / "scripts/emit-local-manifest.py"
    source.write_bytes(source.read_bytes() + b"\n# altered reference\n")
elif kind == "untracked":
    (root / "scripts/untracked_pair_shadow.py").write_text("raise RuntimeError('shadow')\n")
else:
    poison = root.parent / "poison.py"
    poison.write_text("raise RuntimeError('UNCHECKED_CACHE_EXECUTED')\n")
    cache = Path(importlib.util.cache_from_source(str(root / "scripts/tests/test_local_mvm.py")))
    cache.parent.mkdir(parents=True, exist_ok=True)
    py_compile.compile(str(poison), cfile=str(cache), doraise=True,
                       invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH)
    assert cache.read_bytes()[4:8] == b"\x01\x00\x00\x00"
"#,
            ])
            .arg(&producer)
            .arg(&cloned)
            .arg(kind)
            .output()
            .expect("construct an in-process reference refusal fixture");
        assert!(
            cloned_result.status.success(),
            "{}",
            String::from_utf8_lossy(&cloned_result.stderr)
        );
        let result = Command::new(&python)
            .env_clear()
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", &xdg)
            .env("PATH", "")
            .env("SOURCE_DATE_EPOCH", "1")
            .args(["-I", "-B", "-c", PREPARE])
            .arg(&cloned)
            .arg(parent.path())
            .args([
                "clean",
                "x86_64",
                "default_tenant_workload_rootfs",
                PRODUCER_COMMIT,
            ])
            .arg(BUILDER_VM_CACHE_CONTRACT_VERSION.to_string())
            .output()
            .expect("invoke pinned reference admission");
        if let Some(reason) = reason {
            assert!(!result.status.success(), "{kind} producer must be refused");
            assert!(
                String::from_utf8_lossy(&result.stderr).contains(reason),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            assert!(!parent.path().join("python-set").exists());
        } else {
            assert!(
                result.status.success(),
                "cached bytecode must not execute: {}",
                String::from_utf8_lossy(&result.stderr)
            );
            assert_eq!(
                json(&parent.path().join("python-set/image-set.json"))["schema_version"],
                3
            );
        }
    }
}

#[test]
#[ignore = "requires MVM_IMAGES_PAIR_CHECKOUT and MVM_IMAGES_PAIR_PYTHON; execute explicitly"]
fn pinned_python_and_rust_producers_admit_identical_schema3_sets() {
    let producer = required_path("MVM_IMAGES_PAIR_CHECKOUT");
    let python = required_path("MVM_IMAGES_PAIR_PYTHON");
    let mut environment = TestEnv::new();
    for (key, _) in std::env::vars_os() {
        if key
            .to_string_lossy()
            .to_ascii_uppercase()
            .starts_with("GIT_")
        {
            environment.remove(key);
        }
    }
    environment.set("PATH", "");
    environment.set("SOURCE_DATE_EPOCH", "1");
    for (arch, files) in [
        (GuestArch::X86_64, ROOT_FILES),
        (GuestArch::Aarch64, ROOT_FILES),
        (GuestArch::X86_64, ROOTLESS_FILES),
        (GuestArch::Aarch64, ROOTLESS_FILES),
    ] {
        for state in ["clean", "dirty"] {
            let parent = tempfile::tempdir().expect("private pair fixture");
            let home = parent.path().join("home");
            let xdg = parent.path().join("xdg");
            environment.set("HOME", &home);
            environment.set("XDG_CONFIG_HOME", &xdg);
            let built = parent.path().join("built");
            std::fs::create_dir(&built).expect("create built fixture directory");
            std::fs::write(built.join("rootfs.ext4"), supported_rootfs())
                .expect("write supported ext4 bytes for both producers");
            let result = Command::new(&python)
                .env_clear()
                .env("HOME", &home)
                .env("XDG_CONFIG_HOME", &xdg)
                .env("PATH", "")
                .env("SOURCE_DATE_EPOCH", "1")
                .args(["-I", "-B", "-c", PREPARE])
                .arg(&producer)
                .arg(parent.path())
                .arg(state)
                .arg(arch.to_string())
                .arg(files[0].role)
                .arg(PRODUCER_COMMIT)
                .arg(BUILDER_VM_CACHE_CONTRACT_VERSION.to_string())
                .output()
                .expect("invoke the explicit Python producer interpreter");
            assert!(
                result.status.success(),
                "{state} Python production failed:\n{}",
                String::from_utf8_lossy(&result.stderr)
            );
            let images = parent.path().join("images");
            let identity = probe_identity(&images).expect("observe fixture in Rust");
            assert_eq!(
                serde_json::to_value(&identity).expect("serialize Rust identity"),
                json(&parent.path().join("identity.json")),
                "{state} checkout identity differs across languages"
            );
            let contract = TargetContract {
                files,
                capabilities: &[],
                set_roles: &[],
                needs_host_binaries: false,
            };
            let rust_set = parent.path().join("rust-set");
            emit_local_manifest(&EmitRequest {
                images_root: &images,
                legacy_mvm_root: None,
                arch,
                builder_cache_contract: BUILDER_VM_CACHE_CONTRACT_VERSION,
                built: &built,
                out: &rust_set,
                contract: &contract,
            })
            .expect("emit a typed Rust set from the actual built ext4");
            let python_set = parent.path().join("python-set");
            assert_eq!(
                json(&rust_set.join("image-set.json")),
                json(&python_set.join("image-set.json")),
                "{state} schema-3 manifest differs across languages"
            );
            let checkout = LocalImageCheckout::open(&images).expect("select images-only checkout");
            let current = LocalCheckouts {
                images: checkout.identity().clone(),
                mvm: None,
            };
            let protocols = HostProtocolSupport {
                base_image_contract: BaseImageContractRange::SUPPORTED,
                builder_cache_contract: BUILDER_VM_CACHE_CONTRACT_VERSION,
                builder_boot_abi: mvm_build::builder_boot::payload_supported_abis(),
            };
            for set_dir in [&python_set, &rust_set] {
                // This test binary has no signed runtime payload provider.
                // Preserve that production refusal instead of faking one.
                let refusal = checkout
                    .read_local_image_set(&LocalSetRequest {
                        // Schema 3 must never read a paired mvm source checkout.
                        mvm_checkout: &parent.path().join("absent-mvm-checkout"),
                        set_dir,
                        arch,
                        roles: &[],
                        mvm_rule: MvmCheckoutRule::Current,
                    })
                    .expect_err("payload-less library must refuse boot ABI 2");
                assert!(matches!(
                    refusal.refusal(),
                    Some(ImageSetError::BuilderBootAbiUnsupported { .. })
                ));
                // Exercise the actual strict parser/artifact verifier with the
                // compiled payload-capable protocol range. This is format
                // interoperability evidence, never an installed-runtime boot.
                let manifest_bytes = std::fs::read(set_dir.join("image-set.json"))
                    .expect("read produced manifest bytes");
                let verification =
                    LocalImageSetVerification::new(&manifest_bytes, set_dir, &current, arch)
                        .with_host_protocols(&protocols);
                let admitted = verify_local_image_set(&verification)
                    .expect("strict schema-3 parser and staged-artifact verification");
                assert_eq!(admitted.manifest.schema_version, 3);
                for artifact in &admitted.artifacts {
                    mvm_build::published_image_set::verify_base_image_contract(
                        &artifact.path,
                        &admitted.manifest.compatibility,
                    )
                    .expect("strict marker verification of admitted staged ext4 bytes");
                }
            }
        }
    }
}
