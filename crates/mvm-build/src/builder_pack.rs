//! Reusable producer that turns real builder artifacts (a `vmlinux` kernel and a
//! `rootfs.ext4` image) into a signed, cache-promotable Builder pack.
//!
//! This is the inverse of the verify/materialize path in `mvm_core::packs`: it
//! lays the two artifacts out under a pack root, hashes them, and assembles a
//! signed [`PackManifest`] via [`PackBuilder`] so a host running the pack-verify
//! inputs on an hvf machine accepts it and `mvm_core::pack_cache::promote` can
//! content-address it. The producer is pure — every timestamp is an input, so a
//! caller (release CI, a test) controls the bytes and the result is
//! deterministic. Wall-clock stamping belongs to the caller, not here.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;
use mvm_core::arch::GuestArch;
use mvm_core::packs::{
    HostCapability, PackBackend, PackBuilder, PackInputs, PackKind, PackManifest,
    PackManifestError, PackMetadata, PackOutputHashes, PackProvenanceMeta, PackTrustMeta,
    PolicyCompatibility, ReproducibilityStatus, SbomReference, Sha256Hex, SignatureValidity,
    TransparencyLogReference, host_pack_policy_hash,
};
use thiserror::Error;

/// In-pack path of the builder kernel. The consumer's materializer reads it back
/// under this name.
pub const KERNEL_FILE: &str = "vmlinux";
/// In-pack path of the builder rootfs image.
pub const ROOTFS_FILE: &str = "rootfs.ext4";
/// In-pack path of a runtime pack's dm-verity hash tree, carried so the launch
/// can boot the rootfs verity-sealed (runtime tamper detection, not just the
/// download-time content hash).
pub const VERITY_FILE: &str = "rootfs.verity";
/// In-pack path of the rootfs's dm-verity root hash — the value the launch pins
/// on the kernel cmdline.
pub const ROOTHASH_FILE: &str = "rootfs.roothash";
/// Self-describing manifest written next to the artifacts so a produced pack dir
/// can be published as-is. Distinct from the cache's own `.pack-manifest.json`
/// sidecar, and never a declared pack file.
pub const MANIFEST_FILE: &str = "manifest.json";
/// In-pack path of the optional seeded Nix store closure (a `nix-store
/// --export` NAR of the dev-shell toolchain). Present only when the producer
/// is given a closure to bundle; a pack without one stays valid.
pub const CLOSURE_FILE: &str = "nix-closure.nar";

/// The `vsock` capability every mvm builder pack requires of its host — the
/// single control-plane transport an hvf builder VM exposes.
const VSOCK_CAPABILITY: &str = "vsock";

/// Inputs to [`build_builder_pack`]. A named config so the producer never grows a
/// long positional constructor: the two artifact paths and the target arch, the
/// channel the pack is published to, and the provenance/trust/signature metadata
/// the caller supplies. Every timestamp is an input, keeping the producer pure.
#[derive(Debug, Clone)]
pub struct BuildBuilderPackParams {
    /// Source `vmlinux` on disk; copied into the pack as [`KERNEL_FILE`].
    pub vmlinux: PathBuf,
    /// Source `rootfs.ext4` on disk; copied into the pack as [`ROOTFS_FILE`].
    pub rootfs: PathBuf,
    /// Optional seeded Nix store closure NAR on disk; copied into the pack as
    /// [`CLOSURE_FILE`] and hashed into `outputs.closure_hash` when present.
    /// `None` leaves the pack exactly as before this field existed — closure
    /// seeding is an accelerator, never a requirement.
    pub closure: Option<PathBuf>,
    /// Architecture the artifacts target. Drives the manifest arch and the
    /// policy hash the host checks.
    pub target_arch: GuestArch,
    /// Publish channel; becomes `TrustMetadata.channel_identity`, the value the
    /// host's allowed-channel set must contain.
    pub channel: String,
    /// Identity of the builder that produced the artifacts.
    pub builder_identity: String,
    /// Identity of the environment the build ran in.
    pub build_environment_identity: String,
    /// When the artifacts were built.
    pub build_timestamp: DateTime<Utc>,
    /// Whether the build was reproduced.
    pub reproducibility: ReproducibilityStatus,
    /// SBOM enumerating the pack's contents.
    pub sbom: SbomReference,
    /// When the pack's trust metadata expires.
    pub expires_at: DateTime<Utc>,
    /// Where a consumer looks up revocations for this signer.
    pub revocation_channel: String,
    /// Optional mirror identity.
    pub mirror_identity: Option<String>,
    /// Optional transparency-log anchor for the signature.
    pub transparency_log: Option<TransparencyLogReference>,
    /// Validity window stamped onto the produced signature.
    pub signature: SignatureValidity,
}

/// Inputs to [`build_keyless_runtime_pack`]. Mirrors [`BuildBuilderPackParams`]
/// but carries a runtime pack's artifacts (`vmlinux` + a verity-sealed workload
/// `rootfs.ext4` + its dm-verity hash tree + root hash) instead of the builder
/// VM's disk image. Carrying the verity tree and root hash keeps claim 3
/// (a tampered rootfs fails to boot) on a pack-sourced launch — the pack's
/// content hash attests the bytes once, dm-verity re-checks every block at read
/// time. Every timestamp is an input, keeping the producer pure.
#[derive(Debug, Clone)]
pub struct BuildRuntimePackParams {
    /// Source `vmlinux` on disk; copied into the pack as [`KERNEL_FILE`].
    pub vmlinux: PathBuf,
    /// Source workload rootfs on disk; copied into the pack as [`ROOTFS_FILE`].
    pub rootfs: PathBuf,
    /// Source dm-verity hash tree; copied into the pack as [`VERITY_FILE`].
    pub verity: PathBuf,
    /// Source dm-verity root-hash file; copied into the pack as [`ROOTHASH_FILE`].
    pub roothash: PathBuf,
    /// Architecture the artifacts target.
    pub target_arch: GuestArch,
    /// Publish channel; becomes `TrustMetadata.channel_identity`.
    pub channel: String,
    /// Identity of the builder that produced the artifacts.
    pub builder_identity: String,
    /// Identity of the environment the build ran in.
    pub build_environment_identity: String,
    /// When the artifacts were built.
    pub build_timestamp: DateTime<Utc>,
    /// Whether the build was reproduced.
    pub reproducibility: ReproducibilityStatus,
    /// SBOM enumerating the pack's contents.
    pub sbom: SbomReference,
    /// When the pack's trust metadata expires.
    pub expires_at: DateTime<Utc>,
    /// Where a consumer looks up revocations for this signer.
    pub revocation_channel: String,
    /// Optional mirror identity.
    pub mirror_identity: Option<String>,
    /// Optional transparency-log anchor for the signature.
    pub transparency_log: Option<TransparencyLogReference>,
    /// Validity window stamped onto the produced signature.
    pub signature: SignatureValidity,
}

#[derive(Debug, Error)]
pub enum BuilderPackError {
    #[error("builder pack i/o error at {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("builder pack assembly failed: {0}")]
    Manifest(#[from] PackManifestError),
    #[error("builder pack manifest serialization failed: {0}")]
    Serialize(#[source] serde_json::Error),
}

fn io_at(path: &Path) -> impl Fn(std::io::Error) -> BuilderPackError + '_ {
    move |source| BuilderPackError::Io {
        path: path.display().to_string(),
        source,
    }
}

/// Copy `vmlinux` + `rootfs.ext4` into `out_dir`, hash them into the typed
/// `kernel_hash` / `builder_image_hash` outputs a `Builder` pack requires, sign
/// the manifest, and write it to `out_dir/manifest.json`. Returns the signed
/// manifest.
///
/// The returned pack verifies against a host built by the hvf pack-verify inputs:
/// `kind = Builder`, `backend_compatibility = [hvf]`, `required_host_capabilities
/// = [vsock]`, and `policy_compatibility.policy_hash =
/// sha256(target_arch.nix_system())` — the value the host derives and checks.
pub fn build_builder_pack(
    params: &BuildBuilderPackParams,
    signing_key: &SigningKey,
    out_dir: &Path,
) -> Result<PackManifest, BuilderPackError> {
    fs::create_dir_all(out_dir).map_err(io_at(out_dir))?;

    let kernel_dest = out_dir.join(KERNEL_FILE);
    copy_file(&params.vmlinux, &kernel_dest)?;
    let rootfs_dest = out_dir.join(ROOTFS_FILE);
    copy_file(&params.rootfs, &rootfs_dest)?;

    // Hash the copies (identical bytes to the sources) so the typed outputs are
    // the honest sha256 of exactly what lands in the pack.
    let kernel_hash = sha256_file(&kernel_dest)?;
    let builder_image_hash = sha256_file(&rootfs_dest)?;
    let (files, closure_hash) = stage_closure(&params.closure, out_dir)?;

    let manifest = PackBuilder::new(out_dir, builder_metadata(params), signing_key)
        .files(files)
        .output_hashes(PackOutputHashes {
            kernel_hash: Some(kernel_hash),
            builder_image_hash: Some(builder_image_hash),
            closure_hash,
            ..Default::default()
        })
        .build()?;

    // Serialize the signed manifest alongside the artifacts so the pack dir is
    // self-describing for publishing. Not a declared pack file — the verifier
    // and the cache only touch the two artifacts.
    let manifest_bytes =
        serde_json::to_vec_pretty(&manifest).map_err(BuilderPackError::Serialize)?;
    let manifest_path = out_dir.join(MANIFEST_FILE);
    fs::write(&manifest_path, &manifest_bytes).map_err(io_at(&manifest_path))?;

    Ok(manifest)
}

/// A keyless (Sigstore-authority) Builder pack: the manifest plus the path of
/// the file its signable bytes were written to. That file is what a release
/// pipeline hands to `cosign sign-blob` — the resulting detached bundle, not
/// an in-manifest signature, is the pack's authority.
#[derive(Debug, Clone)]
pub struct KeylessBuilderPack {
    pub manifest: PackManifest,
    pub manifest_path: PathBuf,
}

/// Keyless counterpart to [`build_builder_pack`]: same artifact layout and typed
/// output hashes, but the manifest is assembled via `PackBuilder::new_keyless`
/// (no ed25519 key, no in-manifest signature) and the file written to
/// `out_dir/manifest.json` is `manifest.canonical_bytes()` verbatim — the exact
/// bytes a release pipeline signs out of band and a keyless verifier re-derives
/// at verify time. This function never signs anything.
pub fn build_keyless_builder_pack(
    params: &BuildBuilderPackParams,
    identity: &str,
    out_dir: &Path,
) -> Result<KeylessBuilderPack, BuilderPackError> {
    fs::create_dir_all(out_dir).map_err(io_at(out_dir))?;

    let kernel_dest = out_dir.join(KERNEL_FILE);
    copy_file(&params.vmlinux, &kernel_dest)?;
    let rootfs_dest = out_dir.join(ROOTFS_FILE);
    copy_file(&params.rootfs, &rootfs_dest)?;

    let kernel_hash = sha256_file(&kernel_dest)?;
    let builder_image_hash = sha256_file(&rootfs_dest)?;
    let (files, closure_hash) = stage_closure(&params.closure, out_dir)?;

    let manifest = PackBuilder::new_keyless(out_dir, builder_metadata(params), identity)
        .files(files)
        .output_hashes(PackOutputHashes {
            kernel_hash: Some(kernel_hash),
            builder_image_hash: Some(builder_image_hash),
            closure_hash,
            ..Default::default()
        })
        .build()?;

    // Not pretty-printed: this file's bytes are exactly what gets signed, so it
    // must match `manifest.canonical_bytes()` byte-for-byte rather than a
    // re-serialization a verifier would need to normalize.
    let manifest_bytes = manifest.canonical_bytes()?;
    let manifest_path = out_dir.join(MANIFEST_FILE);
    fs::write(&manifest_path, &manifest_bytes).map_err(io_at(&manifest_path))?;

    Ok(KeylessBuilderPack {
        manifest,
        manifest_path,
    })
}

/// A keyless (Sigstore-authority) Runtime pack: the manifest plus the path of
/// the file its signable bytes were written to, exactly as [`KeylessBuilderPack`]
/// but for a runtime pack (kernel + verity-sealed rootfs + verity tree + root hash).
#[derive(Debug, Clone)]
pub struct KeylessRuntimePack {
    pub manifest: PackManifest,
    pub manifest_path: PathBuf,
}

/// Keyless counterpart of the builder producer for a `Runtime` pack: copies
/// `vmlinux` + the workload `rootfs.ext4` + its dm-verity hash tree + root hash
/// into `out_dir`, hashes the kernel + rootfs into the typed `kernel_hash` /
/// `agent_rootfs_hash` outputs a `Runtime` pack requires, assembles the manifest
/// via `PackBuilder::new_keyless` (no ed25519 key, no in-manifest signature), and
/// writes `manifest.canonical_bytes()` verbatim to `out_dir/manifest.json` — the
/// exact bytes a release pipeline signs out of band and a keyless verifier
/// re-derives at verify time. The verity tree + root hash ride as attested pack
/// files so the launch can boot the rootfs verity-sealed. Never signs anything.
pub fn build_keyless_runtime_pack(
    params: &BuildRuntimePackParams,
    identity: &str,
    out_dir: &Path,
) -> Result<KeylessRuntimePack, BuilderPackError> {
    fs::create_dir_all(out_dir).map_err(io_at(out_dir))?;

    let kernel_dest = out_dir.join(KERNEL_FILE);
    copy_file(&params.vmlinux, &kernel_dest)?;
    let rootfs_dest = out_dir.join(ROOTFS_FILE);
    copy_file(&params.rootfs, &rootfs_dest)?;
    copy_file(&params.verity, &out_dir.join(VERITY_FILE))?;
    copy_file(&params.roothash, &out_dir.join(ROOTHASH_FILE))?;

    let kernel_hash = sha256_file(&kernel_dest)?;
    let rootfs_hash = sha256_file(&rootfs_dest)?;

    let manifest = PackBuilder::new_keyless(out_dir, runtime_metadata(params), identity)
        .files([KERNEL_FILE, ROOTFS_FILE, VERITY_FILE, ROOTHASH_FILE])
        .output_hashes(PackOutputHashes {
            kernel_hash: Some(kernel_hash),
            agent_rootfs_hash: Some(rootfs_hash),
            ..Default::default()
        })
        .build()?;

    let manifest_bytes = manifest.canonical_bytes()?;
    let manifest_path = out_dir.join(MANIFEST_FILE);
    fs::write(&manifest_path, &manifest_bytes).map_err(io_at(&manifest_path))?;

    Ok(KeylessRuntimePack {
        manifest,
        manifest_path,
    })
}

/// Assemble the [`PackMetadata`] a produced Builder pack carries. The hash-derived
/// outputs and the signature bundle are the builder's job; this is everything the
/// caller supplies plus the fixed hvf/vsock host contract.
fn builder_metadata(params: &BuildBuilderPackParams) -> PackMetadata {
    PackMetadata {
        kind: PackKind::Builder,
        target_arch: params.target_arch,
        backend_compatibility: vec![PackBackend::Hvf],
        required_host_capabilities: vec![HostCapability(VSOCK_CAPABILITY.to_string())],
        policy_compatibility: PolicyCompatibility {
            // Shared with the host verifier so the two sides cannot drift.
            policy_hash: host_pack_policy_hash(params.target_arch),
            local_rebuild_required: false,
            allowed_channels: vec![params.channel.clone()],
        },
        inputs: empty_inputs(),
        provenance: PackProvenanceMeta {
            builder_identity: params.builder_identity.clone(),
            build_environment_identity: params.build_environment_identity.clone(),
            build_timestamp: params.build_timestamp,
            reproducibility: params.reproducibility.clone(),
            sbom: params.sbom.clone(),
        },
        trust: PackTrustMeta {
            expires_at: params.expires_at,
            revocation_channel: params.revocation_channel.clone(),
            channel_identity: params.channel.clone(),
            mirror_identity: params.mirror_identity.clone(),
            transparency_log: params.transparency_log.clone(),
        },
        signature: params.signature.clone(),
    }
}

/// Assemble the [`PackMetadata`] a produced Runtime pack carries — the same
/// hvf/vsock host contract as a builder pack, but `kind = Runtime` so the
/// verifier requires the runtime output hashes (kernel + agent-rootfs).
fn runtime_metadata(params: &BuildRuntimePackParams) -> PackMetadata {
    PackMetadata {
        kind: PackKind::Runtime,
        target_arch: params.target_arch,
        backend_compatibility: vec![PackBackend::Hvf],
        required_host_capabilities: vec![HostCapability(VSOCK_CAPABILITY.to_string())],
        policy_compatibility: PolicyCompatibility {
            policy_hash: host_pack_policy_hash(params.target_arch),
            local_rebuild_required: false,
            allowed_channels: vec![params.channel.clone()],
        },
        inputs: empty_inputs(),
        provenance: PackProvenanceMeta {
            builder_identity: params.builder_identity.clone(),
            build_environment_identity: params.build_environment_identity.clone(),
            build_timestamp: params.build_timestamp,
            reproducibility: params.reproducibility.clone(),
            sbom: params.sbom.clone(),
        },
        trust: PackTrustMeta {
            expires_at: params.expires_at,
            revocation_channel: params.revocation_channel.clone(),
            channel_identity: params.channel.clone(),
            mirror_identity: params.mirror_identity.clone(),
            transparency_log: params.transparency_log.clone(),
        },
        signature: params.signature.clone(),
    }
}

/// No dependency inputs recorded yet — the artifacts are attested by their
/// hashes. Empty vectors carry no OCI reference, so the verifier's mutable-ref
/// gate never fires.
fn empty_inputs() -> PackInputs {
    PackInputs {
        flake_locks: Vec::new(),
        derivations: Vec::new(),
        nar_hashes: Vec::new(),
        oci_images: Vec::new(),
        setup_commands: Vec::new(),
        source_revisions: Vec::new(),
        toolchain_versions: std::collections::BTreeMap::new(),
    }
}

fn copy_file(src: &Path, dest: &Path) -> Result<(), BuilderPackError> {
    fs::copy(src, dest).map_err(io_at(src))?;
    Ok(())
}

/// Copy an optional closure NAR into `out_dir` as [`CLOSURE_FILE`] and hash it.
/// Returns the kernel+rootfs file set extended with the closure when present,
/// plus the resulting `closure_hash` — or the bare two-file set and `None`
/// when `closure` is absent, leaving the pack exactly as before this field
/// existed.
fn stage_closure(
    closure: &Option<PathBuf>,
    out_dir: &Path,
) -> Result<(Vec<&'static str>, Option<Sha256Hex>), BuilderPackError> {
    match closure {
        Some(src) => {
            let dest = out_dir.join(CLOSURE_FILE);
            copy_file(src, &dest)?;
            let hash = sha256_file(&dest)?;
            Ok((vec![KERNEL_FILE, ROOTFS_FILE, CLOSURE_FILE], Some(hash)))
        }
        None => Ok((vec![KERNEL_FILE, ROOTFS_FILE], None)),
    }
}

/// Resolve the optional seeded closure NAR alongside a resolved builder
/// image's per-arch cache dir (`builder_vm_cache_dir()/<arch>/`), the same
/// dir every builder backend reads `vmlinux`/`rootfs.ext4` from. `None` is
/// the common case today — a pack without a closure leaves the dir exactly
/// as it was before this field existed, and every builder backend boots
/// unchanged.
///
/// Shared by every builder-image resolver (hvf, libkrun, qemu) so the "does
/// this arch dir carry a seeded closure" check has one definition instead of
/// drifting per backend.
pub fn closure_nar_path(arch_dir: &Path) -> Option<PathBuf> {
    let nar = arch_dir.join(CLOSURE_FILE);
    nar.is_file().then_some(nar)
}

/// Stream a file through SHA-256 so an arbitrarily large rootfs is never held in
/// memory. Returns the lowercase-hex digest as a validated [`Sha256Hex`].
fn sha256_file(path: &Path) -> Result<Sha256Hex, BuilderPackError> {
    use sha2::{Digest, Sha256};
    let mut file = fs::File::open(path).map_err(io_at(path))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(io_at(path))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let hex = hex::encode(hasher.finalize());
    Ok(Sha256Hex::new(hex)?)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::fs;

    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as B64;
    use chrono::{TimeZone, Utc};
    use ed25519_dalek::SigningKey;
    use mvm_core::pack_cache::{PackVerifyCtx, promote, resolve_pack};
    use mvm_core::pack_trust::{PackTrustConfig, TrustedPublisher};
    use mvm_core::packs::{
        LocalPackPolicy, PackKind, PackManifest, PackVerifyError, ReproducibilityStatus,
        SbomReference, Sha256Hex, SignatureValidity, verify_pack_at,
    };
    use tempfile::TempDir;

    use super::*;

    fn utc(y: i32, m: u32, d: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, 0, 0, 0)
            .single()
            .expect("valid test timestamp")
    }

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[23u8; 32])
    }

    const KERNEL_BYTES: &[u8] = b"builder-vmlinux-bytes";
    const ROOTFS_BYTES: &[u8] = b"builder-rootfs-ext4-bytes";
    const CHANNEL: &str = "stable";

    /// Write synthetic `vmlinux` + `rootfs.ext4` sources under `src` and return
    /// producer params pointing at them. Plain bytes are fine — a Builder pack
    /// has no ext4-magic requirement at verify time (that gate is the
    /// materializer's, not the pack verifier's).
    fn params_in(src: &TempDir) -> BuildBuilderPackParams {
        let vmlinux = src.path().join("vmlinux.src");
        let rootfs = src.path().join("rootfs.src");
        fs::write(&vmlinux, KERNEL_BYTES).expect("write kernel src");
        fs::write(&rootfs, ROOTFS_BYTES).expect("write rootfs src");
        BuildBuilderPackParams {
            vmlinux,
            rootfs,
            closure: None,
            target_arch: GuestArch::host(),
            channel: CHANNEL.to_string(),
            builder_identity: "ci-builder".to_string(),
            build_environment_identity: "github-actions".to_string(),
            build_timestamp: utc(2026, 6, 23),
            reproducibility: ReproducibilityStatus::Reproduced,
            sbom: SbomReference {
                uri: "https://example.test/sbom.spdx.json".to_string(),
                sha256: Sha256Hex::from_bytes(b"sbom"),
            },
            expires_at: utc(2026, 12, 31),
            revocation_channel: "https://example.test/revocations.json".to_string(),
            mirror_identity: None,
            transparency_log: None,
            signature: SignatureValidity {
                signed_at: utc(2026, 6, 24),
                expires_at: utc(2026, 12, 31),
            },
        }
    }

    /// Write synthetic `vmlinux` + `rootfs` + verity tree + root hash sources and
    /// return runtime producer params pointing at them.
    fn runtime_params_in(src: &TempDir) -> BuildRuntimePackParams {
        let vmlinux = src.path().join("vmlinux.src");
        let rootfs = src.path().join("rootfs.src");
        let verity = src.path().join("verity.src");
        let roothash = src.path().join("roothash.src");
        fs::write(&vmlinux, KERNEL_BYTES).expect("write kernel src");
        fs::write(&rootfs, ROOTFS_BYTES).expect("write rootfs src");
        fs::write(&verity, b"verity-hash-tree-bytes").expect("write verity src");
        fs::write(&roothash, b"deadbeefroothash").expect("write roothash src");
        BuildRuntimePackParams {
            vmlinux,
            rootfs,
            verity,
            roothash,
            target_arch: GuestArch::host(),
            channel: CHANNEL.to_string(),
            builder_identity: "ci-builder".to_string(),
            build_environment_identity: "github-actions".to_string(),
            build_timestamp: utc(2026, 6, 23),
            reproducibility: ReproducibilityStatus::Reproduced,
            sbom: SbomReference {
                uri: "https://example.test/sbom.spdx.json".to_string(),
                sha256: Sha256Hex::from_bytes(b"sbom"),
            },
            expires_at: utc(2026, 12, 31),
            revocation_channel: "https://example.test/revocations.json".to_string(),
            mirror_identity: None,
            transparency_log: None,
            signature: SignatureValidity {
                signed_at: utc(2026, 6, 24),
                expires_at: utc(2026, 12, 31),
            },
        }
    }

    #[test]
    fn keyless_runtime_pack_has_runtime_kind_outputs_and_no_signature() {
        let src = TempDir::new().expect("src");
        let out = TempDir::new().expect("out");
        let produced =
            build_keyless_runtime_pack(&runtime_params_in(&src), KEYLESS_IDENTITY, out.path())
                .expect("produce runtime pack");
        let m = &produced.manifest;
        assert_eq!(m.kind, PackKind::Runtime);
        let files: Vec<&str> = m.outputs.files.iter().map(|f| f.path.as_str()).collect();
        // The pack carries kernel + rootfs + the verity tree + root hash, so the
        // launch can boot the rootfs verity-sealed.
        assert!(files.contains(&KERNEL_FILE));
        assert!(files.contains(&ROOTFS_FILE));
        assert!(files.contains(&VERITY_FILE));
        assert!(files.contains(&ROOTHASH_FILE));
        // A Runtime pack requires kernel + (initramfs | agent-rootfs) hashes.
        assert!(m.outputs.kernel_hash.is_some());
        assert!(m.outputs.agent_rootfs_hash.is_some());
        // Keyless: no in-manifest signature, and the written file is the exact
        // signable bytes (canonical), so an out-of-band signature stays valid.
        assert!(m.provenance.signature_bundle.signatures.is_empty());
        let on_disk = fs::read(&produced.manifest_path).expect("read manifest file");
        assert_eq!(on_disk, m.canonical_bytes().expect("canonical bytes"));
    }

    /// The host policy an hvf machine derives for the running arch — the one the
    /// produced pack must satisfy.
    fn host_policy(channels: &[&str]) -> LocalPackPolicy {
        LocalPackPolicy {
            host_arch: GuestArch::host(),
            backend: PackBackend::Hvf,
            host_capabilities: BTreeSet::from([HostCapability(VSOCK_CAPABILITY.to_string())]),
            policy_hash: Sha256Hex::from_bytes(GuestArch::host().nix_system().as_bytes()),
            allowed_channels: channels.iter().map(|c| c.to_string()).collect(),
            now: utc(2026, 6, 24),
        }
    }

    /// Operator trust config trusting `key` on the given channels. `pubkey_base64`
    /// is the format the on-disk config uses; verify feeds this as both trust
    /// store and revocation checker.
    fn trust_config(key: &SigningKey, channels: &[&str]) -> PackTrustConfig {
        PackTrustConfig {
            publishers: vec![TrustedPublisher {
                pubkey_base64: B64.encode(key.verifying_key().to_bytes()),
                channels: channels.iter().map(|c| c.to_string()).collect(),
            }],
            revocations: vec![],
            ..Default::default()
        }
    }

    #[test]
    fn produced_pack_verifies_against_trusting_config() {
        let src = TempDir::new().expect("src tempdir");
        let out = TempDir::new().expect("out tempdir");
        let key = signing_key();
        let manifest =
            build_builder_pack(&params_in(&src), &key, out.path()).expect("produce pack");

        let policy = host_policy(&[CHANNEL]);
        let config = trust_config(&key, &[CHANNEL]);
        let verified = verify_pack_at(&manifest, out.path(), &policy, &config, &config)
            .expect("produced pack verifies against trusting config");

        assert_eq!(verified.file_count, 2);
        assert_eq!(
            verified.signer_key_id,
            mvm_core::plan::bundle::key_id_from_pubkey(&key.verifying_key())
        );
        // Artifacts landed under their in-pack names.
        assert!(out.path().join(KERNEL_FILE).exists());
        assert!(out.path().join(ROOTFS_FILE).exists());
    }

    #[test]
    fn produced_builder_pack_has_required_output_hashes() {
        let src = TempDir::new().expect("src tempdir");
        let out = TempDir::new().expect("out tempdir");
        let key = signing_key();
        let manifest =
            build_builder_pack(&params_in(&src), &key, out.path()).expect("produce pack");

        // The typed outputs a Builder pack requires carry the real sha256 of the
        // input files.
        assert_eq!(
            manifest.outputs.kernel_hash,
            Some(Sha256Hex::from_bytes(KERNEL_BYTES))
        );
        assert_eq!(
            manifest.outputs.builder_image_hash,
            Some(Sha256Hex::from_bytes(ROOTFS_BYTES))
        );

        // A full verify exercises validate_manifest -> validate_required_outputs
        // for the Builder kind, which fails closed if either hash is absent.
        let policy = host_policy(&[CHANNEL]);
        let config = trust_config(&key, &[CHANNEL]);
        verify_pack_at(&manifest, out.path(), &policy, &config, &config)
            .expect("required outputs satisfied");
    }

    const CLOSURE_BYTES: &[u8] = b"nix-store-export-closure-bytes";

    #[test]
    fn builder_pack_with_closure_carries_closure_hash_and_file() {
        let src = TempDir::new().expect("src tempdir");
        let out = TempDir::new().expect("out tempdir");
        let key = signing_key();

        let closure_src = src.path().join("closure.nar");
        fs::write(&closure_src, CLOSURE_BYTES).expect("write closure src");
        let mut params = params_in(&src);
        params.closure = Some(closure_src);

        let manifest = build_builder_pack(&params, &key, out.path()).expect("produce pack");

        assert_eq!(
            manifest.outputs.closure_hash,
            Some(Sha256Hex::from_bytes(CLOSURE_BYTES))
        );
        let files: Vec<&str> = manifest
            .outputs
            .files
            .iter()
            .map(|f| f.path.as_str())
            .collect();
        assert!(files.contains(&CLOSURE_FILE));
        assert!(out.path().join(CLOSURE_FILE).exists());

        let policy = host_policy(&[CHANNEL]);
        let config = trust_config(&key, &[CHANNEL]);
        let verified = verify_pack_at(&manifest, out.path(), &policy, &config, &config)
            .expect("pack with closure verifies");
        assert_eq!(verified.file_count, 3);
    }

    #[test]
    fn builder_pack_without_closure_has_no_closure_hash_or_file() {
        let src = TempDir::new().expect("src tempdir");
        let out = TempDir::new().expect("out tempdir");
        let key = signing_key();

        // params_in() sets closure: None by default.
        let manifest =
            build_builder_pack(&params_in(&src), &key, out.path()).expect("produce pack");

        assert_eq!(manifest.outputs.closure_hash, None);
        let files: Vec<&str> = manifest
            .outputs
            .files
            .iter()
            .map(|f| f.path.as_str())
            .collect();
        assert!(!files.contains(&CLOSURE_FILE));
        assert!(!out.path().join(CLOSURE_FILE).exists());

        // Backward compatible: still verifies with the required-outputs gate
        // for a Builder pack (closure_hash is not in that list).
        let policy = host_policy(&[CHANNEL]);
        let config = trust_config(&key, &[CHANNEL]);
        let verified = verify_pack_at(&manifest, out.path(), &policy, &config, &config)
            .expect("pack without closure still verifies");
        assert_eq!(verified.file_count, 2);
    }

    #[test]
    fn closure_nar_path_is_none_when_absent() {
        let dir = TempDir::new().expect("arch dir");
        assert_eq!(closure_nar_path(dir.path()), None);
    }

    #[test]
    fn closure_nar_path_resolves_when_present() {
        let dir = TempDir::new().expect("arch dir");
        fs::write(dir.path().join(CLOSURE_FILE), CLOSURE_BYTES).expect("write nar");
        assert_eq!(
            closure_nar_path(dir.path()),
            Some(dir.path().join(CLOSURE_FILE))
        );
    }

    #[test]
    fn produced_pack_promotes_and_resolves() {
        // Isolate the cache to a fresh dir so promote/resolve don't touch a real
        // one and the test is hermetic.
        let cache = TempDir::new().expect("cache tempdir");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_CACHE_DIR", cache.path());

        let src = TempDir::new().expect("src tempdir");
        let out = TempDir::new().expect("out tempdir");
        let key = signing_key();
        let manifest =
            build_builder_pack(&params_in(&src), &key, out.path()).expect("produce pack");

        let policy = host_policy(&[CHANNEL]);
        let config = trust_config(&key, &[CHANNEL]);
        let ctx = PackVerifyCtx::ed25519(&policy, &config, &config);

        let promoted = promote(out.path(), &manifest, &ctx).expect("promote produced pack");
        assert!(promoted.root.starts_with(cache.path()));

        let resolved = resolve_pack(PackKind::Builder, GuestArch::host(), PackBackend::Hvf, &ctx)
            .expect("resolve ok")
            .expect("produced pack is resolvable");
        assert_eq!(resolved.root, promoted.root);
        assert_eq!(resolved.verified.file_count, 2);
    }

    #[test]
    fn manifest_json_roundtrips() {
        let src = TempDir::new().expect("src tempdir");
        let out = TempDir::new().expect("out tempdir");
        let key = signing_key();
        let manifest =
            build_builder_pack(&params_in(&src), &key, out.path()).expect("produce pack");

        let bytes = fs::read(out.path().join(MANIFEST_FILE)).expect("read manifest.json");
        let recovered: PackManifest = serde_json::from_slice(&bytes).expect("decode manifest.json");
        assert_eq!(recovered, manifest);
    }

    #[test]
    fn tamper_rejects_flipped_rootfs_byte() {
        let src = TempDir::new().expect("src tempdir");
        let out = TempDir::new().expect("out tempdir");
        let key = signing_key();
        let manifest =
            build_builder_pack(&params_in(&src), &key, out.path()).expect("produce pack");

        // Flip the rootfs after production; the file hash no longer matches.
        let rootfs = out.path().join(ROOTFS_FILE);
        let mut bytes = fs::read(&rootfs).expect("read rootfs");
        bytes[0] ^= 0xff;
        fs::write(&rootfs, &bytes).expect("tamper rootfs");

        let policy = host_policy(&[CHANNEL]);
        let config = trust_config(&key, &[CHANNEL]);
        let err = verify_pack_at(&manifest, out.path(), &policy, &config, &config)
            .expect_err("tampered rootfs rejected");
        assert!(matches!(
            err,
            PackVerifyError::FileHashMismatch { .. } | PackVerifyError::FileSizeMismatch { .. }
        ));
    }

    const KEYLESS_IDENTITY: &str =
        "https://github.com/tinylabscom/mvm/.github/workflows/release.yml@refs/tags/v0.17.0";

    #[test]
    fn keyless_builder_pack_writes_no_signature() {
        let src = TempDir::new().expect("src tempdir");
        let out = TempDir::new().expect("out tempdir");
        let produced = build_keyless_builder_pack(&params_in(&src), KEYLESS_IDENTITY, out.path())
            .expect("produce keyless pack");

        assert_eq!(
            produced.manifest.provenance.signature_bundle.format,
            mvm_core::packs::SignatureFormat::Sigstore
        );
        assert!(
            produced
                .manifest
                .provenance
                .signature_bundle
                .signatures
                .is_empty()
        );
        assert_eq!(
            produced.manifest.trust.signing_key_id,
            mvm_core::plan::bundle::key_id_from_identity(KEYLESS_IDENTITY)
        );
        assert!(out.path().join(KERNEL_FILE).exists());
        assert!(out.path().join(ROOTFS_FILE).exists());
    }

    #[test]
    fn keyless_builder_pack_manifest_file_bytes_equal_canonical_bytes() {
        let src = TempDir::new().expect("src tempdir");
        let out = TempDir::new().expect("out tempdir");
        let produced = build_keyless_builder_pack(&params_in(&src), KEYLESS_IDENTITY, out.path())
            .expect("produce keyless pack");

        assert_eq!(produced.manifest_path, out.path().join(MANIFEST_FILE));
        let on_disk = fs::read(&produced.manifest_path).expect("read manifest file");
        assert_eq!(
            on_disk,
            produced
                .manifest
                .canonical_bytes()
                .expect("canonical bytes"),
            "the written file must be exactly what a release pipeline signs"
        );

        let recovered: PackManifest =
            serde_json::from_slice(&on_disk).expect("decode keyless manifest file");
        assert_eq!(recovered, produced.manifest);
    }

    #[test]
    fn keyless_builder_pack_uses_params_channel_kind_backends() {
        let src = TempDir::new().expect("src tempdir");
        let out = TempDir::new().expect("out tempdir");
        let params = params_in(&src);
        let produced = build_keyless_builder_pack(&params, KEYLESS_IDENTITY, out.path())
            .expect("produce keyless pack");

        assert_eq!(produced.manifest.kind, PackKind::Builder);
        assert_eq!(
            produced.manifest.backend_compatibility,
            vec![PackBackend::Hvf]
        );
        assert_eq!(
            produced.manifest.policy_compatibility.allowed_channels,
            vec![params.channel.clone()]
        );
    }

    #[cfg(feature = "manifest-verify")]
    #[test]
    fn keyless_builder_pack_manifest_passes_keyless_shape_gate() {
        use mvm_core::packs::{KeylessTrust, verify_pack_keyless_at};

        let src = TempDir::new().expect("src tempdir");
        let out = TempDir::new().expect("out tempdir");
        let produced = build_keyless_builder_pack(&params_in(&src), KEYLESS_IDENTITY, out.path())
            .expect("produce keyless pack");

        let policy = host_policy(&[CHANNEL]);
        let keyless = KeylessTrust {
            accepted_identities: vec![KEYLESS_IDENTITY.to_string()],
            issuer: "https://token.actions.githubusercontent.com".to_string(),
        };
        let revocations = trust_config(&signing_key(), &[CHANNEL]);
        // No real cosign bundle here — this only exercises that the manifest
        // shape reaches the signature step (garbage bundle) rather than
        // failing on `WrongSignatureAuthority` or a shape gate.
        let err = verify_pack_keyless_at(
            &produced.manifest,
            out.path(),
            &policy,
            b"not a real cosign bundle",
            &keyless,
            &revocations,
        )
        .expect_err("garbage bundle fails the signature step, not the shape gate");
        assert!(matches!(err, PackVerifyError::KeylessSignatureInvalid(_)));
    }
}
