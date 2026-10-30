//! Private diagnostic producer preparation; never a production witness.

use super::*;
use anyhow::ensure;
use mvm_core::plan::EnvironmentDescriptor;
use mvm_core::transcript::secure_cleanup::CaptureDirectory;
use serde::Deserialize;
use sha2::{Digest, Sha256};

const INPUT_PIN: &str = "4d2c82dc2a0e57fbc2412f087ed650aacbc0afcd2edc5d345b2b647fad62dc70";
const SCRIPT_PIN: &str = "6b2a07c140cd25dc58fd80844b767d22083a6e5f9296073c4108ac9f5603a684";
const PAYLOADS: [&str; 6] = [
    "vendor-manifest.json",
    "vendor-manifest.json.sig",
    "vendor-public-key.asc",
    "foreground-vendor-provenance",
    "foreground-diagnostic-script",
    "foreground-diagnostic-config.json",
];

#[derive(Deserialize)]
struct InputManifest {
    files: Vec<FileBinding>,
    vendor_original_sha256: String,
    baked_sha256: String,
    vendor_signer_fingerprint: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileBinding {
    name: String,
    sha256: String,
    bytes: u64,
}

// The operator pins this request independently, including the original sealed
// workload identities. All names are single members of the private input root.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    runtime_version: String,
    rootfs: FileBinding,
    guest_sidecar: FileBinding,
    verity: FileBinding,
    roothash: FileBinding,
    environment: FileBinding,
    runtime_archive: FileBinding,
    runtime_checksum: FileBinding,
    runtime_bundle: FileBinding,
    runtime_checksum_bundle: FileBinding,
}

fn check_digest(bytes: &[u8], expected: &str) -> Result<()> {
    ensure!(
        expected.len() == 64 && hex::encode(Sha256::digest(bytes)) == expected,
        "diagnostic approved content digest mismatch"
    );
    Ok(())
}

fn private_root(path: &Path) -> Result<CaptureDirectory> {
    ensure!(
        path.is_absolute()
            && path.components().all(|part| matches!(
                part,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            ))
            && path.canonicalize()? == path,
        "diagnostic root must be canonical, absolute, and without aliases"
    );
    Ok(CaptureDirectory::for_writer(path)?)
}

fn read_bound(lease: &CaptureDirectory, binding: &FileBinding) -> Result<Vec<u8>> {
    read_bound_with_limit(lease, binding, 1024 * 1024)
}

fn read_bound_with_limit(
    lease: &CaptureDirectory,
    binding: &FileBinding,
    maximum: usize,
) -> Result<Vec<u8>> {
    ensure!(binding.bytes <= maximum as u64, "input exceeds its bound");
    let bytes = lease.read_private_member(&binding.name, maximum)?;
    ensure!(bytes.len() as u64 == binding.bytes, "input length mismatch");
    check_digest(&bytes, &binding.sha256)?;
    Ok(bytes)
}

fn verify_file(root: &Path, binding: &FileBinding) -> Result<PathBuf> {
    use std::os::unix::fs::MetadataExt as _;
    ensure!(
        !binding.name.is_empty()
            && Path::new(&binding.name).components().count() == 1
            && matches!(
                Path::new(&binding.name).components().next(),
                Some(std::path::Component::Normal(_))
            ),
        "diagnostic input must be one contained filename"
    );
    let path = root.join(&binding.name);
    let meta = std::fs::symlink_metadata(&path)?;
    mvm_core::private_fs::require_current_owner(&meta)?;
    ensure!(
        meta.is_file()
            && meta.nlink() == 1
            && matches!(meta.mode() & 0o7777, 0o400 | 0o600)
            && meta.len() == binding.bytes
            && sha256_file(&path)? == binding.sha256,
        "diagnostic input path, mode, size, or digest mismatch"
    );
    Ok(path)
}

fn runtime_version(version: &str) -> Result<()> {
    ensure!(
        version == env!("CARGO_PKG_VERSION"),
        "diagnostic requires the genuine runtime for this exact CLI version"
    );
    Ok(())
}

fn diagnostic_architecture(arch: GuestArch) -> Result<()> {
    ensure!(
        arch == GuestArch::Aarch64,
        "approved Claude diagnostic payloads require an ARM64 host and runtime"
    );
    Ok(())
}

fn authenticated_assets(proof: &RuntimeReleaseProof) -> Result<PreparedPortableBootAssets> {
    diagnostic_architecture(GuestArch::host())?;
    runtime_version(&proof.version)?;
    verify_runtime_release_proof(proof, env!("CARGO_PKG_VERSION"), GuestArch::host())?;
    PreparedPortableBootAssets::from_set(
        PublishedImageSet::acquire_workload()?,
        GuestArch::host(),
        proof,
    )
}

fn validate_environment(environment: &EnvironmentDescriptor, sidecar: &[u8]) -> Result<()> {
    environment.validate()?;
    let pack = environment
        .pack
        .as_ref()
        .context("diagnostic pack identity required")?;
    let resources = environment
        .resources
        .as_ref()
        .context("diagnostic resources required")?;
    let metadata: serde_json::Value = serde_json::from_slice(sidecar)?;
    ensure!(
        pack.name == "agent/claude-wire-diagnostic"
            && pack.version == "2.1.273"
            && environment.target.arch_label() == GuestArch::Aarch64.to_string()
            && resources.cpu_cores == 1
            && resources.memory_mb == 4096
            && environment.volumes.is_empty()
            && environment.services.is_empty()
            && environment.capabilities.is_empty()
            && environment.secret_slots.len() == 1
            && environment.secret_slots[0].name == "ANTHROPIC_API_KEY"
            && environment.secret_slots[0].required
            && environment
                .policy
                .as_ref()
                .is_some_and(|policy| policy.allow_hosts.is_empty())
            && serde_json::to_value(&environment.entrypoint.argv)? == metadata["entrypointArgv"],
        "diagnostic identity, resources, offline policy, extras, or sealed entrypoint mismatch"
    );
    Ok(())
}

fn approved_payloads(
    lease: &CaptureDirectory,
    approved_pin: &str,
) -> Result<Vec<(String, Vec<u8>)>> {
    let bytes = lease.read_private_member("input-manifest.json", 65536)?;
    check_digest(&bytes, approved_pin)?;
    let manifest: InputManifest = serde_json::from_slice(&bytes)?;
    ensure!(
        manifest.vendor_original_sha256
            == "0ea64e932c6fac35ce4e992140612157fe1cecab052d59539873b350a594d3c6"
            && manifest.baked_sha256
                == "7544d5d74f38f78b7d5457728dea4bf3f467befda7c1a892021dcfbfda1ab4e1"
            && manifest.vendor_signer_fingerprint == "31DDDE24DDFAB679F42D7BD2BAA929FF1A7ECACE"
            && manifest.files.len() == PAYLOADS.len(),
        "diagnostic approval identities differ"
    );
    let mut payloads = Vec::new();
    for name in PAYLOADS {
        let matches: Vec<_> = manifest
            .files
            .iter()
            .filter(|file| file.name == name)
            .collect();
        let [binding] = matches.as_slice() else {
            bail!("missing or duplicate approved supplemental artifact {name}");
        };
        let bytes = read_bound(lease, binding)?;
        if name == "foreground-diagnostic-script" {
            check_digest(&bytes, SCRIPT_PIN)?;
            ensure!(
                bytes == include_bytes!("entrypoint/foreground_diagnostic.sh"),
                "diagnostic script differs from checked-in source"
            );
        }
        payloads.push((name.to_owned(), bytes));
    }
    // The immutable approval pin records the parent's GPG and transformation
    // evidence. Parsing this JSON is not independent signature verification.
    Ok(payloads)
}

#[test]
#[ignore = "DIAGNOSTIC ONLY: requires approved private inputs and genuine signed CLI runtime; creates disposable publisher key"]
fn signed_release_exports_diagnostic_pack() -> Result<()> {
    diagnostic_architecture(GuestArch::host())?;
    let required = |name| -> Result<PathBuf> {
        Ok(PathBuf::from(
            std::env::var_os(name).with_context(|| format!("{name} required"))?,
        ))
    };
    let root = required("MVM_DIAGNOSTIC_INPUT_ROOT")?;
    let lease = private_root(&root)?;
    let request_bytes = lease.read_private_member("diagnostic-request.json", 65536)?;
    check_digest(
        &request_bytes,
        &std::env::var("MVM_DIAGNOSTIC_APPROVED_REQUEST_SHA256")?,
    )?;
    let request: Request = serde_json::from_slice(&request_bytes)?;
    runtime_version(&request.runtime_version)?;
    let payloads = approved_payloads(&lease, INPUT_PIN)?;
    let rootfs = verify_file(&root, &request.rootfs)?;
    let sidecar = verify_file(&root, &request.guest_sidecar)?;
    ensure!(
        sidecar == mvm_bundler::guest_sidecar_path(utf8(&rootfs)?)?,
        "sealed sidecar must remain beside original rootfs"
    );
    let verity = read_bound_with_limit(&lease, &request.verity, 64 * 1024 * 1024)?;
    let roothash = String::from_utf8(read_bound(&lease, &request.roothash)?)?;
    let hash = roothash
        .strip_suffix('\n')
        .context("raw root hash requires one LF")?;
    mvm_core::packs::Sha256Hex::new(hash)?;
    ensure!(
        roothash == format!("{hash}\n"),
        "noncanonical raw root hash"
    );
    let environment: EnvironmentDescriptor =
        serde_json::from_slice(&read_bound(&lease, &request.environment)?)?;
    validate_environment(&environment, &read_bound(&lease, &request.guest_sidecar)?)?;
    let archive = verify_file(&root, &request.runtime_archive)?;
    let checksum = verify_file(&root, &request.runtime_checksum)?;
    let signature_bundle = verify_file(&root, &request.runtime_bundle)?;
    let checksum_bundle = verify_file(&root, &request.runtime_checksum_bundle)?;
    ensure!(
        checksum_bundle == mvm_build::guest_runtime::evidence::checksum_bundle_path(&checksum),
        "runtime checksum signature bundle name mismatch"
    );
    let proof = RuntimeReleaseProof {
        archive,
        checksum,
        signature_bundle,
        archive_sha256: request.runtime_archive.sha256.clone(),
        version: request.runtime_version.clone(),
        arch: GuestArch::host(),
    };
    // Explicit home isolation is checked before any acquisition, without
    // consulting ambient fallback homes or a shared publisher key directory.
    let fixture = required("MVM_DIAGNOSTIC_FIXTURE_ROOT")?;
    let fixture_lease = private_root(&fixture)?;
    ensure!(
        fixture_lease.read_private_member("diagnostic-owned", 64)?
            == b"disposable-diagnostic-publisher-v1\n",
        "owned disposable fixture marker required"
    );
    ensure!(
        fixture != root && !fixture.starts_with(&root),
        "separate fixture required"
    );
    for (variable, leaf) in [("MVM_HOME", "mvm"), ("HOME", "home")] {
        let path = required(variable)?;
        ensure!(path == fixture.join(leaf), "explicit fixture home required");
        drop(private_root(&path)?);
    }
    ensure!(
        !fixture.join("diagnostic-publisher-keys").exists()
            && !fixture.join("diagnostic-output").exists(),
        "diagnostic publisher keys and output must be new"
    );
    let assets = authenticated_assets(&proof)?;
    // Only an authenticated, prepared runtime may reach output/key creation.
    let output = fixture.join("diagnostic-output");
    std::fs::create_dir(&output)?;
    mvm_core::private_fs::set_mode(&output, 0o700)?;
    let snapshot = tempfile::tempdir_in(&output)?;
    mvm_core::private_fs::set_mode(snapshot.path(), 0o700)?;
    let mut extras = Vec::new();
    for (name, bytes) in &payloads {
        let path = snapshot.path().join(name);
        std::fs::write(&path, bytes)?;
        mvm_core::private_fs::set_mode(&path, 0o600)?;
        extras.push((name.as_str(), path));
    }
    let extras: Vec<_> = extras
        .iter()
        .map(|(name, path)| (*name, path.as_path()))
        .collect();
    let bundle = output.join("claude-wire-diagnostic.mvmpkg");
    let mut inputs = mvm_bundler::BundleExportInputs::new(
        utf8(&assets.kernel)?,
        utf8(&rootfs)?,
        &assets.runtime.arch,
        &bundle,
    )
    .initrd(utf8(&assets.initrd)?)
    .verity(&verity, hash)
    .resources(1, 4096)
    .label("agent/claude-wire-diagnostic@2.1.273")
    .posture(mvm_bundler::PostureInputs::new(
        mvm_core::security::AgentProfile::Dev,
    ))
    .environment(environment);
    inputs.supplemental_artifacts = &extras;
    // Recheck original path bindings immediately before signing.
    verify_file(&root, &request.rootfs)?;
    verify_file(&root, &request.guest_sidecar)?;
    let keys = fixture.join("diagnostic-publisher-keys");
    std::fs::create_dir(&keys)?;
    mvm_core::private_fs::set_mode(&keys, 0o700)?;
    let signer = crate::bundle::HostBundleSigner::load_at(&keys)?;
    assets.stage(&inputs, &signer)?.publish()?;
    println!("DIAGNOSTIC ONLY: {}", bundle.display());
    Ok(())
}

#[test]
fn diagnostic_payload_preflight_accepts_private_copies_of_all_six_members() {
    if let Some(path) = std::env::var_os("MVM_DIAGNOSTIC_PREFLIGHT_INPUT_ROOT") {
        let lease = private_root(Path::new(&path)).unwrap();
        assert_eq!(approved_payloads(&lease, INPUT_PIN).unwrap().len(), 6);
    }
    let directory = tempfile::tempdir().unwrap();
    mvm_core::private_fs::set_mode(directory.path(), 0o700).unwrap();
    let root = directory.path().canonicalize().unwrap();
    let lease = private_root(&root).unwrap();
    let mut files = Vec::new();
    let mut expected = Vec::new();
    for name in PAYLOADS {
        let bytes = if name == "foreground-diagnostic-script" {
            include_bytes!("entrypoint/foreground_diagnostic.sh").to_vec()
        } else {
            format!("synthetic hermetic payload for {name}\n").into_bytes()
        };
        let path = root.join(name);
        std::fs::write(&path, &bytes).unwrap();
        mvm_core::private_fs::set_mode(&path, 0o600).unwrap();
        files.push(serde_json::json!({
            "name": name, "sha256": hex::encode(Sha256::digest(&bytes)), "bytes": bytes.len(),
        }));
        expected.push((name.to_owned(), bytes));
    }
    let manifest = serde_json::to_vec(&serde_json::json!({
        "files": files,
        "vendor_original_sha256": "0ea64e932c6fac35ce4e992140612157fe1cecab052d59539873b350a594d3c6",
        "baked_sha256": "7544d5d74f38f78b7d5457728dea4bf3f467befda7c1a892021dcfbfda1ab4e1",
        "vendor_signer_fingerprint": "31DDDE24DDFAB679F42D7BD2BAA929FF1A7ECACE",
    })).unwrap();
    std::fs::write(root.join("input-manifest.json"), &manifest).unwrap();
    mvm_core::private_fs::set_mode(root.join("input-manifest.json"), 0o600).unwrap();
    let pin = hex::encode(Sha256::digest(&manifest));
    assert_eq!(approved_payloads(&lease, &pin).unwrap(), expected);
    mvm_core::private_fs::set_mode(root.join(PAYLOADS[0]), 0o400).unwrap();
    assert!(approved_payloads(&lease, &pin).is_err());
    mvm_core::private_fs::set_mode(root.join(PAYLOADS[0]), 0o600).unwrap();
    std::fs::write(root.join(PAYLOADS[0]), b"changed").unwrap();
    assert!(approved_payloads(&lease, &pin).is_err());
}

#[test]
fn diagnostic_verity_read_accepts_large_sidecar_and_refuses_oversize_before_open() {
    let directory = tempfile::tempdir().unwrap();
    mvm_core::private_fs::set_mode(directory.path(), 0o700).unwrap();
    let root = directory.path().canonicalize().unwrap();
    let lease = private_root(&root).unwrap();
    let bytes = vec![0x5a; 12_357_632];
    std::fs::write(root.join("rootfs.verity"), &bytes).unwrap();
    mvm_core::private_fs::set_mode(root.join("rootfs.verity"), 0o600).unwrap();
    let mut binding = FileBinding {
        name: "rootfs.verity".into(),
        sha256: hex::encode(Sha256::digest(&bytes)),
        bytes: bytes.len() as u64,
    };
    assert!(read_bound(&lease, &binding).is_err());
    assert_eq!(
        read_bound_with_limit(&lease, &binding, 64 * 1024 * 1024).unwrap(),
        bytes
    );
    binding.bytes = 64 * 1024 * 1024 + 1;
    binding.name = "not-created".into();
    let error = read_bound_with_limit(&lease, &binding, 64 * 1024 * 1024).unwrap_err();
    assert_eq!(error.to_string(), "input exceeds its bound");
}

#[test]
fn diagnostic_preflight_rejects_version_and_digest_without_output() {
    assert!(runtime_version(env!("CARGO_PKG_VERSION")).is_ok());
    assert!(runtime_version("0.25.0").is_err());
    assert!(check_digest(b"payload", &"0".repeat(64)).is_err());
    assert!(check_digest(b"payload", &hex::encode(Sha256::digest(b"payload"))).is_ok());
    check_digest(
        include_bytes!("entrypoint/foreground_diagnostic.sh"),
        SCRIPT_PIN,
    )
    .unwrap();
}

#[test]
fn diagnostic_architecture_accepts_only_the_pinned_arm64_platform() {
    diagnostic_architecture(GuestArch::Aarch64).unwrap();
    assert!(diagnostic_architecture(GuestArch::X86_64).is_err());
}

#[test]
fn diagnostic_missing_runtime_proof_cannot_create_key_or_output() {
    let directory = tempfile::tempdir().unwrap();
    let proof = RuntimeReleaseProof {
        archive: directory.path().join("missing.tar.gz"),
        checksum: directory.path().join("missing.sha256"),
        signature_bundle: directory.path().join("missing.bundle"),
        archive_sha256: "0".repeat(64),
        version: env!("CARGO_PKG_VERSION").into(),
        arch: GuestArch::host(),
    };
    let error = authenticated_assets(&proof)
        .err()
        .expect("missing genuine proof");
    assert!(!error.to_string().is_empty());
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
}

#[test]
fn diagnostic_preflight_checks_identity_resources_extras_and_sealed_entrypoint() {
    let value = serde_json::json!({
        "descriptor_version": 1,
        "pack": {"name": "agent/claude-wire-diagnostic", "version": "2.1.273"},
        "target": "aarch64-linux",
        "entrypoint": {"argv": ["/unchanged-sealed-entrypoint"], "working_dir": "/srv"},
        "resources": {"cpu_cores": 1, "memory_mb": 4096},
        "secret_slots": [{"name":"ANTHROPIC_API_KEY","required":true}],
        "policy": {"allow_hosts": []},
    });
    let sidecar = br#"{"entrypointArgv":["/unchanged-sealed-entrypoint"]}"#;
    let environment = serde_json::from_value(value.clone()).unwrap();
    validate_environment(&environment, sidecar).unwrap();
    for (pointer, replacement) in [
        ("/pack/name", serde_json::json!("agent/claude")),
        ("/pack/version", serde_json::json!("2.1.274")),
        ("/target", serde_json::json!("x86_64-linux")),
        ("/resources/cpu_cores", serde_json::json!(2)),
        ("/resources/memory_mb", serde_json::json!(1024)),
        ("/secret_slots/0/name", serde_json::json!("OTHER_TOKEN")),
        ("/secret_slots/0/required", serde_json::json!(false)),
        ("/entrypoint/argv", serde_json::json!(["/diagnostic-exec"])),
        (
            "/policy/allow_hosts",
            serde_json::json!(["example.com:443"]),
        ),
    ] {
        let mut bad = value.clone();
        *bad.pointer_mut(pointer).unwrap() = replacement;
        assert!(validate_environment(&serde_json::from_value(bad).unwrap(), sidecar).is_err());
    }
    for (field, extra) in [
        (
            "services",
            serde_json::json!([{"name":"extra","argv":["/extra"]}]),
        ),
        ("capabilities", serde_json::json!(["egress"])),
    ] {
        let mut extras = value.clone();
        extras[field] = extra;
        assert!(validate_environment(&serde_json::from_value(extras).unwrap(), sidecar).is_err());
    }
}

#[test]
fn diagnostic_preflight_rejects_paths_modes_links_and_substitution() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    mvm_core::private_fs::set_mode(dir.path(), 0o700).unwrap();
    let root = dir.path().canonicalize().unwrap();
    let lease = private_root(&root).unwrap();
    let mut binding = FileBinding {
        name: "input".into(),
        sha256: hex::encode(Sha256::digest(b"approved")),
        bytes: 8,
    };
    std::fs::write(root.join("input"), b"approved").unwrap();
    mvm_core::private_fs::set_mode(root.join("input"), 0o600).unwrap();
    assert!(verify_file(&root, &binding).is_ok());
    assert!(read_bound(&lease, &binding).is_ok());
    binding.name = "../input".into();
    assert!(verify_file(&root, &binding).is_err());
    assert!(read_bound(&lease, &binding).is_err());
    binding.name = "input".into();
    mvm_core::private_fs::set_mode(root.join("input"), 0o644).unwrap();
    assert!(verify_file(&root, &binding).is_err());
    assert!(read_bound(&lease, &binding).is_err());
    mvm_core::private_fs::set_mode(root.join("input"), 0o600).unwrap();
    symlink(root.join("input"), root.join("alias")).unwrap();
    binding.name = "alias".into();
    assert!(verify_file(&root, &binding).is_err());
    assert!(read_bound(&lease, &binding).is_err());
    binding.name = "input".into();
    std::fs::write(root.join("input"), b"tampered").unwrap();
    assert!(verify_file(&root, &binding).is_err());
    assert!(read_bound(&lease, &binding).is_err());
    assert!(!root.join("diagnostic-publisher-keys").exists());
    assert!(!root.join("diagnostic-output").exists());
}
