//! Data-only independent reference and in-process producer/consumer coverage.
//! See fixtures/local-producer-v2.md for reference provenance and limitations.
use std::io::Read;
use std::path::Path;

use mvm_build::image_source::{
    EmitRequest, OutputFile, OutputFormat, TargetContract, emit_local_manifest, probe_identity,
};
use mvm_core::arch::GuestArch;
use mvm_core::image_set::{
    BaseImageContractRange, HostProtocolSupport, LocalCheckouts, LocalImageSetVerification,
    RepoIdentity, verify_local_image_set,
};
use mvm_core::util::test_env::TestEnv;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[path = "../src/image_source/tests/repository.rs"]
mod repository;

const DATA: &[u8] = include_bytes!("fixtures/local-producer-v2.json");
// An explicit protocol fixture, not an installed-runtime compatibility claim.
const CACHE_CONTRACT: u32 = 1;
const DATA_HASH: &str = "834dd9f9a4ecdb57934fce5efa993297c46152ef43cd2bcd5e4b16a1281e25df";
const MANIFESTS: &[u8] = include_bytes!("fixtures/local-producer-manifests.json");
const MANIFESTS_HASH: &str = "9057fd0265d35d547ae8d0bad0f6e8f2d0d1783434941701f3f9044806ad635f";
const ROOTFS: &[u8] = include_bytes!("fixtures/local-producer-rootfs.json");

fn reference_rootfs(bytes: &[u8]) -> Result<Vec<u8>, String> {
    if hex::encode(Sha256::digest(bytes))
        != "d9855dd4f4e5bf1d9005fc553c750a0b9ca31a325c9d8a1c2d151ffe70108a96"
    {
        return Err("rootfs packet hash mismatch".into());
    }
    let data: Value = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    if data["version"] != 1
        || data["format"] != "ext4"
        || data["encoding"] != "zlib-hex"
        || data["size"] != 36864
        || data["compressed_size"] != 285
    {
        return Err("unsupported rootfs fixture or bounds".into());
    }
    let encoded = data["data"].as_str().ok_or("missing rootfs bytes")?;
    if encoded.len() != 570 {
        return Err("compressed fixture exceeds exact bound".into());
    }
    let compressed = hex::decode(encoded).map_err(|e| e.to_string())?;
    if hex::encode(Sha256::digest(&compressed))
        != "f0ec33287174cad091375c671830d9ad1db9d835b25584f6c380bec42052526b"
        || data["compressed_sha256"] != hex::encode(Sha256::digest(&compressed))
    {
        return Err("compressed fixture hash mismatch".into());
    }
    let mut decoded = Vec::new();
    flate2::read::ZlibDecoder::new(compressed.as_slice())
        .take(36865)
        .read_to_end(&mut decoded)
        .map_err(|e| e.to_string())?;
    if decoded.len() != 36864
        || hex::encode(Sha256::digest(&decoded))
            != "17a0d044d997f556f231fed641fbe41ccf82638857aa11fdb6cc9a48f11765f9"
        || data["sha256"] != hex::encode(Sha256::digest(&decoded))
    {
        return Err("rootfs fixture size/hash mismatch".into());
    }
    Ok(decoded)
}

const DEFAULT_FILES: &[OutputFile] = &[OutputFile {
    name: "rootfs.ext4",
    role: "default_tenant_workload_rootfs",
    format: OutputFormat::Fixed("ext4"),
}];
const ROOTLESS_FILES: &[OutputFile] = &[OutputFile {
    name: "rootfs.ext4",
    role: "rootless_tenant_workload_rootfs",
    format: OutputFormat::Fixed("ext4"),
}];

fn manifests(bytes: &[u8]) -> Result<Value, String> {
    if hex::encode(Sha256::digest(bytes)) != MANIFESTS_HASH {
        return Err("manifest reference hash mismatch".into());
    }
    serde_json::from_slice(bytes).map_err(|e| e.to_string())
}

fn reference(bytes: &[u8]) -> Result<Value, String> {
    if hex::encode(Sha256::digest(bytes)) != DATA_HASH {
        return Err("reference packet hash mismatch".into());
    }
    let data: Value = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    if data["version"] != 1
        || data["producer"]["revision"] != "f5ed15188114f2e3b7e27717640f0cbd37f53914"
        || data["producer"]["sha256"]
            != "45b93439cdebeba9c2d84749ec7c9afcfbe2c46802a756d84febb8b441583387"
        || data["producer"]["path"] != "scripts/emit-local-manifest.py"
        || data["vectors"].as_array().map(Vec::len) != Some(4)
    {
        return Err("reference provenance or inventory mismatch".into());
    }
    Ok(data)
}

fn environment() -> TestEnv {
    let mut env = TestEnv::new();
    for (key, _) in std::env::vars_os() {
        if key
            .to_string_lossy()
            .to_ascii_uppercase()
            .starts_with("GIT_")
        {
            env.remove(key);
        }
    }
    env.set("PATH", "");
    env.set("SOURCE_DATE_EPOCH", "1");
    env
}

fn write(root: &Path, name: &str, bytes: &[u8]) {
    let path = root.join(name);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, bytes).unwrap();
}

#[test]
fn neutral_reference_refuses_tampering_before_interpreting_data() {
    reference(DATA).unwrap();
    manifests(MANIFESTS).unwrap();
    reference_rootfs(ROOTFS).unwrap();
    for pointer in [
        "/version",
        "/size",
        "/compressed_size",
        "/sha256",
        "/compressed_sha256",
        "/data",
    ] {
        let mut altered: Value = serde_json::from_slice(ROOTFS).unwrap();
        *altered.pointer_mut(pointer).unwrap() = json!("tampered");
        assert!(
            reference_rootfs(&serde_json::to_vec(&altered).unwrap()).is_err(),
            "{pointer}"
        );
    }
    for pointer in [
        "/version",
        "/producer/revision",
        "/producer/sha256",
        "/producer/path",
        "/vectors",
        "/repository/dirty/fingerprint",
    ] {
        let mut altered: Value = serde_json::from_slice(DATA).unwrap();
        *altered.pointer_mut(pointer).unwrap() = json!("tampered");
        assert!(
            reference(&serde_json::to_vec(&altered).unwrap()).is_err(),
            "{pointer}"
        );
    }
    for pointer in [
        "/0/name",
        "/0/manifest/schema_version",
        "/0/manifest/members/0/artifacts/0/name",
        "/0/manifest/producer/local_checkouts/images/commit",
    ] {
        let mut altered: Value = serde_json::from_slice(MANIFESTS).unwrap();
        *altered.pointer_mut(pointer).unwrap() = json!("../tampered");
        assert!(
            manifests(&serde_json::to_vec(&altered).unwrap()).is_err(),
            "{pointer}"
        );
    }
}

#[test]
#[cfg(unix)]
fn in_process_repository_matches_independent_python_v2_output() {
    let mut env = environment();
    let temp = tempfile::tempdir().unwrap();
    env.set("HOME", temp.path().join("home"));
    env.set("XDG_CONFIG_HOME", temp.path().join("xdg"));
    let root = temp.path().join("repo");
    write(&root, "a.txt", b"tracked\n");
    repository::commit_all(&root, "fixture");
    let data = reference(DATA).unwrap();
    let clean = probe_identity(&root).unwrap();
    assert_eq!(
        clean.commit.as_str(),
        data["repository"]["commit"].as_str().unwrap()
    );
    assert_eq!(
        serde_json::to_value(&clean.worktree).unwrap(),
        json!({"state":"clean"})
    );
    write(&root, "a.txt", b"tracked\nchanged\n");
    write(&root, "u.txt", b"untracked\n");
    std::os::unix::fs::symlink("a.txt", root.join("link")).unwrap();
    let dirty = probe_identity(&root).unwrap();
    assert_eq!(
        serde_json::to_value(&dirty.worktree).unwrap(),
        data["repository"]["dirty"]
    );
    write(&root, "u.txt", b"changed again\n");
    assert_ne!(probe_identity(&root).unwrap(), dirty);
}

fn supported_rootfs() -> Vec<u8> {
    use mvm_fs::ext4::{Node, Owner};
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
    mvm_fs::ext4::build_image(nodes, &Default::default()).unwrap()
}

#[test]
fn in_process_producer_and_strict_consumer_preserve_schema3_contract() {
    let mut env = environment();
    let temp = tempfile::tempdir().unwrap();
    env.set("HOME", temp.path().join("home"));
    env.set("XDG_CONFIG_HOME", temp.path().join("xdg"));
    let images = temp.path().join("images");
    for name in [
        "flake.nix",
        "flake.lock",
        "kernel/flake.nix",
        "images/builder-vm/image.nix",
        "images/default-tenant/image.nix",
        "images/rootless-tenant/image.nix",
    ] {
        write(&images, name, format!("# {name}\n").as_bytes());
    }
    write(&images, "kernel/flake.lock", b"{\"nodes\": {}}\n");
    write(&images, "images/builder-vm/boot-abi.nix", b"2\n");
    write(&images, "images/base-image-contract.nix", b"1\n");
    repository::commit_all(&images, "fixture");
    let built = temp.path().join("built");
    let rootfs = reference_rootfs(ROOTFS).unwrap();
    assert_eq!(
        rootfs,
        supported_rootfs(),
        "neutral capture must remain the deterministic mvm_fs output"
    );
    write(&built, "rootfs.ext4", &rootfs);
    let captures = manifests(MANIFESTS).unwrap();
    let protocols = HostProtocolSupport {
        base_image_contract: BaseImageContractRange::SUPPORTED,
        builder_cache_contract: CACHE_CONTRACT,
        builder_boot_abi: mvm_build::builder_boot::payload_supported_abis(),
    };
    for dirty in [false, true] {
        if dirty {
            write(&images, "flake.nix", b"changed\n");
        }
        for arch in [GuestArch::X86_64, GuestArch::Aarch64] {
            for profile in ["default", "rootless"] {
                let files = if profile == "default" {
                    DEFAULT_FILES
                } else {
                    ROOTLESS_FILES
                };
                let contract = TargetContract {
                    files,
                    capabilities: &[],
                    set_roles: &[],
                    needs_host_binaries: false,
                };
                let out = temp.path().join(format!("{dirty}-{arch}-{profile}"));
                emit_local_manifest(&EmitRequest {
                    images_root: &images,
                    legacy_mvm_root: None,
                    arch,
                    builder_cache_contract: CACHE_CONTRACT,
                    built: &built,
                    out: &out,
                    contract: &contract,
                })
                .unwrap();
                let bytes = std::fs::read(out.join("image-set.json")).unwrap();
                let manifest: Value = serde_json::from_slice(&bytes).unwrap();
                let name = format!("{dirty}-{arch}-{profile}");
                let expected = captures
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|case| case["name"] == name)
                    .unwrap()["manifest"]
                    .clone();
                // Both independent producers consume the exact neutral artifact.
                // No expected manifest field is replaced or normalized.
                let artifact = &manifest["members"][0]["artifacts"][0];
                assert_eq!(artifact["sha256"], hex::encode(Sha256::digest(&rootfs)));
                assert_eq!(artifact["size"], rootfs.len() as u64);
                assert_eq!(manifest, expected, "{name}: independent reference output");
                assert_eq!(manifest["schema_version"], 3);
                assert_eq!(manifest["compatibility"]["base_image_contract"], 1);
                assert_eq!(manifest["producer"].as_object().unwrap().len(), 1);
                assert_eq!(
                    manifest["producer"]["local_checkouts"]
                        .as_object()
                        .unwrap()
                        .len(),
                    1
                );
                assert!(manifest.get("mvm_source_commit").is_none());
                let current = LocalCheckouts {
                    images: probe_identity(&images).unwrap(),
                    mvm: None,
                };
                let verification = LocalImageSetVerification::new(&bytes, &out, &current, arch)
                    .with_host_protocols(&protocols);
                let admitted = verify_local_image_set(&verification).unwrap();
                for (pointer, invalid) in [
                    ("/members/0/artifacts/0/name", json!("../escape.ext4")),
                    ("/members/0/artifacts/0/sha256", json!("0".repeat(64))),
                    (
                        "/producer/local_checkouts/images/commit",
                        json!("0".repeat(40)),
                    ),
                    (
                        "/producer/local_checkouts/mvm",
                        manifest["producer"]["local_checkouts"]["images"].clone(),
                    ),
                ] {
                    let mut altered = manifest.clone();
                    if pointer.ends_with("/mvm") {
                        altered["producer"]["local_checkouts"]["mvm"] = invalid;
                    } else {
                        *altered.pointer_mut(pointer).unwrap() = invalid;
                    }
                    let altered_bytes = serde_json::to_vec(&altered).unwrap();
                    assert!(
                        verify_local_image_set(
                            &LocalImageSetVerification::new(&altered_bytes, &out, &current, arch)
                                .with_host_protocols(&protocols)
                        )
                        .is_err(),
                        "{name}: {pointer}"
                    );
                }
                write(&images, "mutation-witness", b"changed after production\n");
                let changed = LocalCheckouts {
                    images: probe_identity(&images).unwrap(),
                    mvm: None,
                };
                assert!(
                    verify_local_image_set(
                        &LocalImageSetVerification::new(&bytes, &out, &changed, arch)
                            .with_host_protocols(&protocols)
                    )
                    .is_err()
                );
                std::fs::remove_file(images.join("mutation-witness")).unwrap();
                for artifact in admitted.artifacts {
                    assert_eq!(std::fs::read(&artifact.path).unwrap(), rootfs);
                    mvm_build::published_image_set::verify_base_image_contract(
                        &artifact.path,
                        &admitted.manifest.compatibility,
                    )
                    .unwrap();
                    std::fs::write(&artifact.path, b"mutated").unwrap();
                }
                assert!(verify_local_image_set(&verification).is_err());
                let mut old = manifest.clone();
                old["producer"]["local_checkouts"]["images"]["worktree"] =
                    json!({"state":"dirty","fingerprint_version":1,"fingerprint":"a".repeat(64)});
                assert!(
                    serde_json::from_value::<RepoIdentity>(
                        old["producer"]["local_checkouts"]["images"].clone()
                    )
                    .is_err()
                );
            }
        }
    }
}
