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
const DATA_HASH: &str = "d447325e8bf9e4c6a55cb266a04dd2b6268cacae0bac7b90f679367dff84fcbd";
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
        "/observation_cases",
        "/mutation/body",
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

fn raw_reference_shape(case: &Value) -> Result<(), String> {
    let expected = case["expected"]
        .as_array()
        .ok_or("missing raw observations")?;
    if expected.len() != 3
        || case["steps"].as_array().map(Vec::len) != Some(3)
        || case.get("unsupported_on_capture").is_some()
        || expected[0]["worktree"] != json!({"state":"clean"})
        || expected
            .iter()
            .any(|identity| serde_json::from_value::<RepoIdentity>(identity.clone()).is_err())
        || expected[1]["worktree"]["state"] != "dirty"
        || expected[2]["worktree"]["state"] != "dirty"
        || expected[0]["commit"] != expected[1]["commit"]
        || expected[0]["commit"] != expected[2]["commit"]
        || expected[1] == expected[2]
    {
        return Err("raw-name reference requires three complete distinct supported states".into());
    }
    Ok(())
}

#[test]
fn raw_name_reference_requires_complete_supported_shape() {
    let data = reference(DATA).unwrap();
    let raw = data["observation_cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "non-utf8-name")
        .unwrap();
    raw_reference_shape(raw).unwrap();
    for variant in ["truncated", "unsupported", "duplicate", "malformed"] {
        let mut altered = raw.clone();
        match variant {
            "truncated" => altered["expected"].as_array_mut().unwrap().truncate(1),
            "unsupported" => altered["unsupported_on_capture"] = json!("EILSEQ"),
            "duplicate" => altered["expected"][2] = altered["expected"][1].clone(),
            "malformed" => altered["expected"][2]["worktree"]["fingerprint_version"] = json!(1),
            _ => unreachable!(),
        }
        assert!(raw_reference_shape(&altered).is_err(), "{variant}");
    }
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

fn matrix_path(root: &Path, encoded: &Value) -> std::path::PathBuf {
    let bytes = hex::decode(encoded.as_str().unwrap()).unwrap();
    assert!(!bytes.starts_with(b"/") && !bytes.contains(&0));
    assert!(
        bytes
            .split(|b| *b == b'/')
            .all(|part| !part.is_empty() && part != b"." && part != b".." && part != b".git")
    );
    #[cfg(unix)]
    let name = {
        use std::os::unix::ffi::OsStringExt;
        std::ffi::OsString::from_vec(bytes)
    };
    #[cfg(not(unix))]
    let name = std::ffi::OsString::from(String::from_utf8(bytes).unwrap());
    root.join(name)
}

fn matrix_files(root: &Path, files: &Value) -> std::io::Result<()> {
    for file in files.as_array().unwrap() {
        let path = matrix_path(root, &file[0]);
        let body = hex::decode(file[2].as_str().unwrap()).unwrap();
        std::fs::create_dir_all(path.parent().unwrap())?;
        match file[1].as_str().unwrap() {
            "file" => std::fs::write(path, body)?,
            "symlink" => {
                #[cfg(unix)]
                {
                    use std::os::unix::ffi::OsStringExt;
                    if std::fs::symlink_metadata(&path).is_ok() {
                        std::fs::remove_file(&path)?;
                    }
                    std::os::unix::fs::symlink(std::ffi::OsString::from_vec(body), path)?;
                }
                #[cfg(not(unix))]
                panic!("Unix-only recipe entered on unsupported platform");
            }
            other => panic!("unsupported fixture file kind: {other}"),
        }
    }
    Ok(())
}

fn shared_observation_matrix(unix_cases: bool) {
    let mut env = environment();
    let temp = tempfile::tempdir().unwrap();
    env.set("HOME", temp.path().join("home"));
    env.set("XDG_CONFIG_HOME", temp.path().join("xdg"));
    let data = reference(DATA).unwrap();
    for case in data["observation_cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| case["unix"] == unix_cases)
    {
        let name = case["name"].as_str().unwrap();
        if name == "non-utf8-name" {
            raw_reference_shape(case).unwrap();
        }
        let common = temp.path().join(name);
        matrix_files(&common, &case["initial"]).unwrap();
        repository::commit_all(&common, "fixture");
        let root = if case["linked"] == true {
            let linked = temp.path().join(format!("{name}-linked"));
            std::fs::create_dir(&linked).unwrap();
            let admin = common.join(".git/worktrees/witness");
            std::fs::create_dir_all(&admin).unwrap();
            let head = std::fs::read(common.join(".git/refs/heads/main")).unwrap();
            std::fs::write(admin.join("HEAD"), head).unwrap();
            std::fs::write(admin.join("commondir"), b"../..\n").unwrap();
            std::fs::write(
                admin.join("gitdir"),
                format!("{}\n", linked.join(".git").display()),
            )
            .unwrap();
            std::fs::write(
                linked.join(".git"),
                format!("gitdir: {}\n", admin.display()),
            )
            .unwrap();
            std::fs::copy(common.join(".git/index"), admin.join("index")).unwrap();
            matrix_files(&linked, &case["initial"]).unwrap();
            linked
        } else {
            common.clone()
        };
        let common_before = probe_identity(&common).unwrap();
        let mut observed = Vec::new();
        #[cfg(target_os = "macos")]
        let mut unsupported = false;
        #[cfg(not(target_os = "macos"))]
        let unsupported = false;
        for step in case["steps"].as_array().unwrap() {
            if let Err(error) = matrix_files(&root, &step["files"]) {
                #[cfg(target_os = "macos")]
                if name == "non-utf8-name" && error.raw_os_error() == Some(libc::EILSEQ) {
                    assert_eq!(
                        observed.len(),
                        1,
                        "EILSEQ must be the first raw-name creation"
                    );
                    unsupported = true;
                    eprintln!("UNSUPPORTED filesystem: non-utf8-name (actual EILSEQ)");
                    break;
                }
                panic!("{name}: {error}");
            }
            if step["stage"] == true {
                assert_eq!(case["linked"], false);
                repository::stage(&root);
            }
            observed.push(serde_json::to_value(probe_identity(&root).unwrap()).unwrap());
        }
        if name == "ignored-files" {
            assert_eq!(observed[0], observed[1]);
            assert_eq!(observed[1], observed[2]);
            assert_ne!(observed[2], observed[3]);
        } else {
            assert!(observed.windows(2).all(|pair| pair[0] != pair[1]), "{name}");
        }
        if unsupported {
            assert_eq!(
                observed.as_slice(),
                &case["expected"].as_array().unwrap()[..observed.len()],
                "{name}: completed prefix must match independent Linux observations"
            );
        } else {
            assert_eq!(
                serde_json::to_value(observed).unwrap(),
                case["expected"],
                "{name}"
            );
        }
        if case["linked"] == true {
            assert_eq!(probe_identity(&common).unwrap(), common_before);
        }
    }
}

#[test]
fn shared_portable_repository_observation_matrix() {
    shared_observation_matrix(false);
}

#[test]
#[cfg(unix)]
fn shared_unix_repository_observation_matrix() {
    shared_observation_matrix(true);
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
                let data = reference(DATA).unwrap();
                let mutation = matrix_path(&images, &data["mutation"]["path"]);
                let original = std::fs::read(&mutation).unwrap();
                std::fs::write(
                    &mutation,
                    hex::decode(data["mutation"]["body"].as_str().unwrap()).unwrap(),
                )
                .unwrap();
                let changed = LocalCheckouts {
                    images: probe_identity(&images).unwrap(),
                    mvm: None,
                };
                assert_ne!(changed.images, current.images);
                assert_eq!(
                    serde_json::to_value(&changed.images).unwrap(),
                    data["mutation"]["after"]
                );
                assert!(
                    verify_local_image_set(
                        &LocalImageSetVerification::new(&bytes, &out, &changed, arch)
                            .with_host_protocols(&protocols)
                    )
                    .is_err()
                );
                std::fs::write(mutation, original).unwrap();
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
