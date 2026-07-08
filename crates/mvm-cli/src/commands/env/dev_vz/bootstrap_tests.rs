use super::stage0_cache::validate_builder_vm_stage0_artifacts;
use super::*;

#[cfg(test)]
mod attested_builder_pack_tests {
    use std::collections::{BTreeMap, BTreeSet, HashMap};

    use base64::Engine as _;
    use chrono::{DateTime, TimeZone, Utc};
    use ed25519_dalek::{SigningKey, VerifyingKey};

    use mvm_core::arch::GuestArch;
    use mvm_core::config::mvm_keys_dir;
    use mvm_core::pack_cache::{PackVerifyCtx, VerifiedPackDir, promote, resolve_pack};
    use mvm_core::pack_trust::{PackTrustConfig, TrustedPublisher};
    use mvm_core::packs::{
        HostCapability, LocalPackPolicy, PackBackend, PackBuilder, PackInputs, PackKind,
        PackManifest, PackMetadata, PackOutputHashes, PackProvenanceMeta, PackRevocationChecker,
        PackTrustMeta, PackTrustStore, PolicyCompatibility, ReproducibilityStatus,
        RevocationStatus, SbomReference, Sha256Hex, SignatureValidity, VerifiedPack,
    };
    use mvm_core::plan::bundle::KeyId;
    use mvm_core::util::test_env::TestEnv;
    use tempfile::TempDir;

    use super::bootstrap::attested_builder_pack::{
        attempt_attested_builder_pack, attested_builder_pack_selected, builder_pack_requested_for,
        materialize_builder_pack,
    };
    #[cfg(feature = "manifest-verify")]
    use super::bootstrap::attested_builder_pack::{
        keyless_release_policy, promote_staged_builder_pack,
    };
    use super::{
        MVM_BUILDER_PACK_ENV, builder_vm_source_cache_ready, validate_builder_vm_stage0_artifacts,
    };
    #[cfg(feature = "manifest-verify")]
    use mvm_build::builder_pack::{BuildBuilderPackParams, build_keyless_builder_pack};
    #[cfg(feature = "manifest-verify")]
    use mvm_core::packs::{COSIGN_BUNDLE_FILE_NAME, KeylessTrust};

    const EXT4_MAGIC_OFFSET: usize = 1024 + 56;

    /// Write a `(vmlinux, rootfs.ext4)` pair that satisfies the Stage 0 artifact
    /// floor (`≥1 MiB` kernel, `≥4 MiB` ext4-magic rootfs) the readiness check
    /// and promotion path enforce. Deterministic bytes keep a minted pack's hash
    /// stable across runs.
    fn write_valid_builder_artifacts(dir: &std::path::Path) {
        std::fs::create_dir_all(dir).expect("mkdir artifacts");
        std::fs::write(dir.join("vmlinux"), vec![0x7f; 1024 * 1024 + 1]).expect("write vmlinux");
        std::fs::write(dir.join("rootfs.ext4"), rootfs_bytes(4 * 1024 * 1024 + 1)).expect("rootfs");
    }

    fn rootfs_bytes(len: usize) -> Vec<u8> {
        let mut rootfs = vec![0u8; len];
        rootfs[EXT4_MAGIC_OFFSET] = 0x53;
        rootfs[EXT4_MAGIC_OFFSET + 1] = 0xEF;
        rootfs
    }

    /// A directly-built `VerifiedPackDir` over `root`. Bypasses promote/resolve so
    /// the materializer can be unit-tested in isolation; `full_chain_*` covers the
    /// real mint → promote → resolve → materialize path.
    fn verified_pack_dir(root: &std::path::Path) -> VerifiedPackDir {
        VerifiedPackDir {
            root: root.to_path_buf(),
            verified: VerifiedPack {
                pack_hash: Sha256Hex::from_bytes(b"builder-pack-direct-fingerprint"),
                file_count: 2,
                signer_key_id: KeyId("test-key".to_string()),
            },
        }
    }

    #[test]
    fn materialize_places_builder_files_and_marks_cache_ready() {
        let pack = TempDir::new().expect("pack tempdir");
        write_valid_builder_artifacts(pack.path());
        let out = TempDir::new().expect("out tempdir");
        let out_dir = out.path().join("builder-vm").join("aarch64");
        let verified = verified_pack_dir(pack.path());

        let fingerprint = materialize_builder_pack(&verified, &out_dir).expect("materialize");

        assert!(out_dir.join("vmlinux").exists(), "vmlinux placed");
        assert!(out_dir.join("rootfs.ext4").exists(), "rootfs placed");
        assert_eq!(fingerprint, verified.verified.pack_hash.as_str());
        assert!(
            builder_vm_source_cache_ready(&out_dir, &fingerprint),
            "materialized dir must read cache-ready for its declared fingerprint"
        );
        // The pack path only runs on installed binaries, and their readiness gate
        // is the placed-artifact check (vmlinux + rootfs.ext4), not the
        // source-checkout fingerprint marker. Assert the gate the acquisition path
        // actually consults when no builder flake is present.
        assert!(
            validate_builder_vm_stage0_artifacts(&out_dir).is_ok(),
            "materialized dir must satisfy the installed-binary readiness gate"
        );
    }

    #[test]
    fn materialize_is_atomic_partial_failure_leaves_no_ready_dir() {
        let pack = TempDir::new().expect("pack tempdir");
        std::fs::create_dir_all(pack.path()).expect("mkdir");
        // Valid kernel but an undersized rootfs: the copy succeeds, then the
        // promotion's artifact-floor check fails — after some staging work but
        // before the atomic publish.
        std::fs::write(pack.path().join("vmlinux"), vec![0x7f; 1024 * 1024 + 1]).expect("vmlinux");
        std::fs::write(pack.path().join("rootfs.ext4"), rootfs_bytes(4096)).expect("small rootfs");
        let out = TempDir::new().expect("out tempdir");
        let out_dir = out.path().join("builder-vm").join("aarch64");
        let verified = verified_pack_dir(pack.path());

        materialize_builder_pack(&verified, &out_dir).expect_err("undersized rootfs must fail");

        assert!(
            !builder_vm_source_cache_ready(&out_dir, verified.verified.pack_hash.as_str()),
            "a failed materialize must not leave a cache-ready dir"
        );
        // No staging leftover next to out_dir.
        let builder_vm_root = out.path().join("builder-vm");
        if let Ok(entries) = std::fs::read_dir(&builder_vm_root) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                assert!(
                    !name.contains("stage0-"),
                    "staging leftover after failed materialize: {name}"
                );
            }
        }
    }

    #[test]
    fn full_chain_promote_resolve_materialize_marks_cache_ready() {
        let cache = TempDir::new().expect("cache tempdir");
        let mut env = TestEnv::new();
        env.set("MVM_CACHE_DIR", cache.path());

        let staged = TempDir::new().expect("staged pack tempdir");
        write_valid_builder_artifacts(staged.path());
        let key = signing_key();
        let manifest = builder_pack_manifest(staged.path(), &key);

        let trust = trust_store(&key);
        let rev = good_revocations();
        let policy = hvf_policy();
        let ctx = PackVerifyCtx::ed25519(&policy, &trust, &rev);

        promote(staged.path(), &manifest, &ctx).expect("promote");
        let verified = resolve_pack(PackKind::Builder, GuestArch::host(), PackBackend::Hvf, &ctx)
            .expect("resolve ok")
            .expect("compatible pack found");

        let out = TempDir::new().expect("out tempdir");
        let out_dir = out
            .path()
            .join("builder-vm")
            .join(GuestArch::host().to_string());
        let fingerprint = materialize_builder_pack(&verified, &out_dir).expect("materialize");

        assert_eq!(fingerprint, manifest.outputs.pack_hash.as_str());
        assert!(out_dir.join("vmlinux").exists());
        assert!(out_dir.join("rootfs.ext4").exists());
        assert!(builder_vm_source_cache_ready(&out_dir, &fingerprint));
    }

    #[test]
    fn builder_pack_requested_truthy_falsey_none() {
        for raw in ["1", "true", "yes", "on", "TRUE", "  On  "] {
            assert!(
                builder_pack_requested_for(Some(raw)),
                "{raw:?} should be truthy"
            );
        }
        for raw in ["0", "false", "no", "off", "", "disabled"] {
            assert!(
                !builder_pack_requested_for(Some(raw)),
                "{raw:?} should be falsey"
            );
        }
        assert!(!builder_pack_requested_for(None), "missing value is falsey");
    }

    #[test]
    fn attested_builder_pack_selected_skips_on_source_checkout_and_flag_off() {
        // The test binary is compiled from a source checkout, so
        // `find_builder_vm_flake()` resolves — the pack path must be skipped even
        // with the flag on, mirroring the release-artifact download gate.
        let mut env = TestEnv::new();
        env.set(MVM_BUILDER_PACK_ENV, "1");
        assert!(
            !attested_builder_pack_selected(),
            "source checkout must skip the pack path even with the flag on"
        );
        env.remove(MVM_BUILDER_PACK_ENV);
        assert!(
            !attested_builder_pack_selected(),
            "flag off must skip the pack path"
        );
    }

    #[test]
    fn attempt_falls_through_when_no_pack_promoted() {
        let cache = TempDir::new().expect("cache tempdir");
        let mut env = TestEnv::new();
        env.set("MVM_CACHE_DIR", cache.path());
        let out = TempDir::new().expect("out tempdir");
        let out_dir = out.path().join("builder-vm").join("aarch64");

        let placed =
            attempt_attested_builder_pack("aarch64", out_dir.to_str().expect("utf-8"), false)
                .expect("attempt is fail-open, not an error");
        assert!(
            !placed,
            "no promoted pack ⇒ no materialization ⇒ fall through"
        );
        assert!(!out_dir.exists(), "fall-through must not touch out_dir");
    }

    // ---- pack-minting scaffolding (mirrors the pack_cache test fixtures) ----

    fn utc(y: i32, m: u32, d: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, 0, 0, 0)
            .single()
            .expect("valid timestamp")
    }

    fn hash(value: &str) -> Sha256Hex {
        Sha256Hex::from_bytes(value.as_bytes())
    }

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[13u8; 32])
    }

    fn builder_pack_manifest(root: &std::path::Path, key: &SigningKey) -> PackManifest {
        let kernel = std::fs::read(root.join("vmlinux")).expect("read vmlinux");
        let image = std::fs::read(root.join("rootfs.ext4")).expect("read rootfs");
        PackBuilder::new(root, builder_metadata(), key)
            .files(["vmlinux", "rootfs.ext4"])
            .output_hashes(PackOutputHashes {
                kernel_hash: Some(Sha256Hex::from_bytes(&kernel)),
                builder_image_hash: Some(Sha256Hex::from_bytes(&image)),
                ..Default::default()
            })
            .build()
            .expect("build pack")
    }

    fn builder_metadata() -> PackMetadata {
        PackMetadata {
            kind: PackKind::Builder,
            target_arch: GuestArch::host(),
            backend_compatibility: vec![PackBackend::Hvf, PackBackend::Libkrun],
            required_host_capabilities: vec![HostCapability("vsock".to_string())],
            policy_compatibility: PolicyCompatibility {
                policy_hash: hash("policy"),
                local_rebuild_required: false,
                allowed_channels: vec!["stable".to_string()],
            },
            inputs: PackInputs {
                flake_locks: Vec::new(),
                derivations: Vec::new(),
                nar_hashes: Vec::new(),
                oci_images: Vec::new(),
                setup_commands: Vec::new(),
                source_revisions: Vec::new(),
                toolchain_versions: BTreeMap::new(),
            },
            provenance: PackProvenanceMeta {
                builder_identity: "ci-builder".to_string(),
                build_environment_identity: "github-actions".to_string(),
                build_timestamp: utc(2026, 6, 23),
                reproducibility: ReproducibilityStatus::Reproduced,
                sbom: SbomReference {
                    uri: "https://example.test/sbom.spdx.json".to_string(),
                    sha256: hash("sbom"),
                },
            },
            trust: PackTrustMeta {
                expires_at: utc(2027, 12, 31),
                revocation_channel: "https://example.test/revocations.json".to_string(),
                channel_identity: "stable".to_string(),
                mirror_identity: None,
                transparency_log: None,
            },
            signature: SignatureValidity {
                signed_at: utc(2026, 6, 24),
                expires_at: utc(2027, 12, 31),
            },
        }
    }

    fn hvf_policy() -> LocalPackPolicy {
        LocalPackPolicy {
            host_arch: GuestArch::host(),
            backend: PackBackend::Hvf,
            host_capabilities: BTreeSet::from([HostCapability("vsock".to_string())]),
            policy_hash: hash("policy"),
            allowed_channels: BTreeSet::from(["stable".to_string()]),
            now: utc(2026, 6, 25),
        }
    }

    struct MapTrustStore {
        keys: HashMap<KeyId, VerifyingKey>,
    }

    impl PackTrustStore for MapTrustStore {
        fn verifying_key(&self, key_id: &KeyId) -> Option<VerifyingKey> {
            self.keys.get(key_id).copied()
        }
    }

    fn trust_store(key: &SigningKey) -> MapTrustStore {
        MapTrustStore {
            keys: HashMap::from([(
                KeyId::from_pubkey(&key.verifying_key()),
                key.verifying_key(),
            )]),
        }
    }

    struct AlwaysGood;

    impl PackRevocationChecker for AlwaysGood {
        fn status(&self, _key_id: &KeyId, _pack_hash: &Sha256Hex) -> RevocationStatus {
            RevocationStatus::Good
        }
    }

    fn good_revocations() -> AlwaysGood {
        AlwaysGood
    }

    // ---- on-disk trust config wiring (the F2 de-inert proof) ----

    /// The policy hash `host_pack_verify_inputs` derives for the running host —
    /// the value a pack's `policy_compatibility.policy_hash` must equal for the
    /// production verify context to admit it.
    fn host_policy_hash() -> Sha256Hex {
        Sha256Hex::from_bytes(GuestArch::host().nix_system().as_bytes())
    }

    /// Builder-pack metadata whose policy hash matches what the production path
    /// derives (the shared `builder_metadata` pins an unrelated `"policy"`
    /// hash), so a pack minted from it is admissible by the on-disk-config ctx.
    fn attested_builder_metadata() -> PackMetadata {
        let mut meta = builder_metadata();
        meta.policy_compatibility.policy_hash = host_policy_hash();
        meta
    }

    fn attested_builder_manifest(root: &std::path::Path, key: &SigningKey) -> PackManifest {
        let kernel = std::fs::read(root.join("vmlinux")).expect("read vmlinux");
        let image = std::fs::read(root.join("rootfs.ext4")).expect("read rootfs");
        PackBuilder::new(root, attested_builder_metadata(), key)
            .files(["vmlinux", "rootfs.ext4"])
            .output_hashes(PackOutputHashes {
                kernel_hash: Some(Sha256Hex::from_bytes(&kernel)),
                builder_image_hash: Some(Sha256Hex::from_bytes(&image)),
                ..Default::default()
            })
            .build()
            .expect("build pack")
    }

    /// A host policy matching `host_pack_verify_inputs` but with caller-chosen
    /// channels — used to promote the pack into the cache with a permissive
    /// in-test context, so the *on-disk config* is the gate under test.
    fn attested_host_policy(channels: &[&str]) -> LocalPackPolicy {
        LocalPackPolicy {
            host_arch: GuestArch::host(),
            backend: PackBackend::Hvf,
            host_capabilities: BTreeSet::from([HostCapability("vsock".to_string())]),
            policy_hash: host_policy_hash(),
            allowed_channels: channels.iter().map(|c| c.to_string()).collect(),
            now: utc(2026, 6, 25),
        }
    }

    /// Mint + promote a `"stable"`-channel builder pack signed by `key` into the
    /// (env-isolated) cache, trusting `key` for the promote step only.
    fn promote_attested_pack(key: &SigningKey, staged: &std::path::Path) -> PackManifest {
        let manifest = attested_builder_manifest(staged, key);
        let trust = trust_store(key);
        let rev = good_revocations();
        let policy = attested_host_policy(&["stable"]);
        let ctx = PackVerifyCtx::ed25519(&policy, &trust, &rev);
        promote(staged, &manifest, &ctx).expect("promote");
        manifest
    }

    fn trust_config(key: &SigningKey, channels: &[&str]) -> PackTrustConfig {
        PackTrustConfig {
            publishers: vec![TrustedPublisher {
                pubkey_base64: base64::engine::general_purpose::STANDARD
                    .encode(key.verifying_key().to_bytes()),
                channels: channels.iter().map(|c| c.to_string()).collect(),
            }],
            revocations: Vec::new(),
        }
    }

    /// Write `config` to `pack-trust.json` under the env-isolated keys dir — the
    /// exact path `host_pack_verify_inputs` reads.
    fn write_trust_config(config: &PackTrustConfig) {
        let path = mvm_keys_dir().join("pack-trust.json");
        std::fs::create_dir_all(path.parent().expect("keys dir parent")).expect("mkdir keys");
        std::fs::write(&path, serde_json::to_vec(config).expect("serialize")).expect("write trust");
    }

    fn host_arch_str() -> String {
        GuestArch::host().to_string()
    }

    fn host_out_dir(root: &std::path::Path) -> std::path::PathBuf {
        root.join("builder-vm").join(host_arch_str())
    }

    /// The de-inert proof: a pack signed by a key the on-disk `pack-trust.json`
    /// trusts on the pack's channel is resolved, materialized into `out_dir`,
    /// and the dir passes the installed-path readiness gate — end to end through
    /// the real `attempt_attested_builder_pack` entrypoint the flag hook calls.
    #[test]
    fn end_to_end_trusted_pack_materializes_and_marks_cache_ready() {
        let cache = TempDir::new().expect("cache tempdir");
        let data = TempDir::new().expect("data tempdir");
        let mut env = TestEnv::new();
        env.set("MVM_CACHE_DIR", cache.path());
        env.set("MVM_DATA_DIR", data.path());

        let staged = TempDir::new().expect("staged pack tempdir");
        write_valid_builder_artifacts(staged.path());
        let key = signing_key();
        promote_attested_pack(&key, staged.path());
        write_trust_config(&trust_config(&key, &["stable"]));

        let out = TempDir::new().expect("out tempdir");
        let out_dir = host_out_dir(out.path());
        let placed = attempt_attested_builder_pack(
            &host_arch_str(),
            out_dir.to_str().expect("utf-8"),
            false,
        )
        .expect("attempt ok");

        assert!(placed, "trusted pack must materialize");
        assert!(out_dir.join("vmlinux").exists(), "vmlinux placed");
        assert!(out_dir.join("rootfs.ext4").exists(), "rootfs placed");
        assert!(
            validate_builder_vm_stage0_artifacts(&out_dir).is_ok(),
            "materialized dir must satisfy the installed-binary readiness gate"
        );
    }

    #[test]
    fn absent_trust_config_stays_inert() {
        let cache = TempDir::new().expect("cache tempdir");
        let data = TempDir::new().expect("data tempdir");
        let mut env = TestEnv::new();
        env.set("MVM_CACHE_DIR", cache.path());
        env.set("MVM_DATA_DIR", data.path());

        let staged = TempDir::new().expect("staged pack tempdir");
        write_valid_builder_artifacts(staged.path());
        promote_attested_pack(&signing_key(), staged.path());
        // No pack-trust.json: the empty config trusts nothing.

        let out = TempDir::new().expect("out tempdir");
        let out_dir = host_out_dir(out.path());
        let placed = attempt_attested_builder_pack(
            &host_arch_str(),
            out_dir.to_str().expect("utf-8"),
            false,
        )
        .expect("attempt is fail-open");

        assert!(!placed, "absent config ⇒ nothing trusted ⇒ fall through");
        assert!(!out_dir.exists(), "fall-through must not touch out_dir");
    }

    #[test]
    fn untrusted_key_is_rejected() {
        let cache = TempDir::new().expect("cache tempdir");
        let data = TempDir::new().expect("data tempdir");
        let mut env = TestEnv::new();
        env.set("MVM_CACHE_DIR", cache.path());
        env.set("MVM_DATA_DIR", data.path());

        let staged = TempDir::new().expect("staged pack tempdir");
        write_valid_builder_artifacts(staged.path());
        promote_attested_pack(&signing_key(), staged.path());
        // Trust a different key than the one that signed the pack.
        let other = SigningKey::from_bytes(&[71u8; 32]);
        write_trust_config(&trust_config(&other, &["stable"]));

        let out = TempDir::new().expect("out tempdir");
        let out_dir = host_out_dir(out.path());
        let placed = attempt_attested_builder_pack(
            &host_arch_str(),
            out_dir.to_str().expect("utf-8"),
            false,
        )
        .expect("attempt is fail-open");

        assert!(
            !placed,
            "unknown signer ⇒ fail-closed on trust ⇒ fall through"
        );
        assert!(!out_dir.exists(), "untrusted signer must not materialize");
    }

    #[test]
    fn disallowed_channel_is_rejected() {
        let cache = TempDir::new().expect("cache tempdir");
        let data = TempDir::new().expect("data tempdir");
        let mut env = TestEnv::new();
        env.set("MVM_CACHE_DIR", cache.path());
        env.set("MVM_DATA_DIR", data.path());

        let staged = TempDir::new().expect("staged pack tempdir");
        write_valid_builder_artifacts(staged.path());
        let key = signing_key();
        promote_attested_pack(&key, staged.path());
        // Trust the signer, but only for "beta"; the pack declares "stable".
        write_trust_config(&trust_config(&key, &["beta"]));

        let out = TempDir::new().expect("out tempdir");
        let out_dir = host_out_dir(out.path());
        let placed = attempt_attested_builder_pack(
            &host_arch_str(),
            out_dir.to_str().expect("utf-8"),
            false,
        )
        .expect("attempt is fail-open");

        assert!(!placed, "disallowed channel ⇒ fall through");
        assert!(!out_dir.exists(), "channel mismatch must not materialize");
    }

    #[cfg(feature = "manifest-verify")]
    #[test]
    fn keyless_release_policy_unions_release_channels_into_allowed_set() {
        let base = LocalPackPolicy {
            host_arch: GuestArch::host(),
            backend: PackBackend::Hvf,
            host_capabilities: BTreeSet::from([HostCapability("vsock".to_string())]),
            policy_hash: hash("policy"),
            allowed_channels: BTreeSet::from(["operator-channel".to_string()]),
            now: utc(2026, 6, 25),
        };

        let policy = keyless_release_policy(&base);

        assert!(
            policy.allowed_channels.contains("stable"),
            "release channel must be allowed"
        );
        assert!(
            policy.allowed_channels.contains("operator-channel"),
            "base policy's channels must be preserved"
        );
        assert_eq!(
            policy.allowed_channels.len(),
            2,
            "union must not duplicate or drop entries"
        );
    }

    // ---- promote_staged_builder_pack (release-fetch staging → cache) ----

    #[cfg(feature = "manifest-verify")]
    const RELEASE_PACK_IDENTITY: &str =
        "https://github.com/tinylabscom/mvm/.github/workflows/release.yml@refs/tags/v0.17.0";

    /// Producer params for a real keyless builder pack, matching the shape
    /// [`mvm_build::builder_pack::build_keyless_builder_pack`]'s own tests use.
    /// Reused across the `promote_staged_builder_pack` tests so each only
    /// supplies the staging quirk (garbage bundle, missing bundle, missing or
    /// malformed manifest) it's exercising.
    #[cfg(feature = "manifest-verify")]
    fn release_pack_producer_params(src: &std::path::Path) -> BuildBuilderPackParams {
        let vmlinux = src.join("vmlinux.src");
        let rootfs = src.join("rootfs.src");
        std::fs::write(&vmlinux, b"release-pack-kernel-bytes").expect("write kernel src");
        std::fs::write(&rootfs, b"release-pack-rootfs-bytes").expect("write rootfs src");
        BuildBuilderPackParams {
            vmlinux,
            rootfs,
            target_arch: GuestArch::host(),
            channel: "stable".to_string(),
            builder_identity: "release-ci".to_string(),
            build_environment_identity: "github-actions".to_string(),
            build_timestamp: utc(2026, 6, 23),
            reproducibility: ReproducibilityStatus::Reproduced,
            sbom: SbomReference {
                uri: "https://example.test/sbom.spdx.json".to_string(),
                sha256: hash("sbom"),
            },
            expires_at: utc(2027, 12, 31),
            revocation_channel: "https://example.test/revocations.json".to_string(),
            mirror_identity: None,
            transparency_log: None,
            signature: SignatureValidity {
                signed_at: utc(2026, 6, 24),
                expires_at: utc(2027, 12, 31),
            },
        }
    }

    #[cfg(feature = "manifest-verify")]
    fn release_pack_keyless_trust() -> KeylessTrust {
        KeylessTrust {
            accepted_identities: vec![RELEASE_PACK_IDENTITY.to_string()],
            issuer: "https://token.actions.githubusercontent.com".to_string(),
        }
    }

    /// A garbage cosign bundle sidecar must fail keyless verification —
    /// `promote_staged_builder_pack` is fail-open on that (`Ok(None)`, not an
    /// error), and the pack cache must stay untouched so the caller falls
    /// through to the plain checksum download.
    #[cfg(feature = "manifest-verify")]
    #[test]
    fn promote_staged_builder_pack_rejects_garbage_bundle() {
        let cache = TempDir::new().expect("cache tempdir");
        let mut env = TestEnv::new();
        env.set("MVM_CACHE_DIR", cache.path());

        let src = TempDir::new().expect("src tempdir");
        let staging = TempDir::new().expect("staging tempdir");
        let produced = build_keyless_builder_pack(
            &release_pack_producer_params(src.path()),
            RELEASE_PACK_IDENTITY,
            staging.path(),
        )
        .expect("produce keyless pack");
        std::fs::write(
            staging.path().join("pack-manifest.json"),
            produced
                .manifest
                .canonical_bytes()
                .expect("canonical bytes"),
        )
        .expect("write staged manifest");
        std::fs::write(
            staging.path().join(COSIGN_BUNDLE_FILE_NAME),
            b"not a real cosign bundle",
        )
        .expect("write garbage bundle");

        let policy = hvf_policy();
        let keyless = release_pack_keyless_trust();
        let rev = good_revocations();
        let ctx = PackVerifyCtx::keyless(&policy, &keyless, &rev);

        let result = promote_staged_builder_pack(staging.path(), &ctx)
            .expect("verify failure is fail-open, not an error");
        assert!(result.is_none(), "garbage bundle must not verify");

        let resolved = resolve_pack(PackKind::Builder, GuestArch::host(), PackBackend::Hvf, &ctx)
            .expect("resolve ok");
        assert!(resolved.is_none(), "cache must stay unpromoted");
    }

    /// A missing cosign bundle sidecar is the same fail-open shape as a
    /// garbage one — the pack cache never sees an unattested pack.
    #[cfg(feature = "manifest-verify")]
    #[test]
    fn promote_staged_builder_pack_rejects_missing_bundle() {
        let cache = TempDir::new().expect("cache tempdir");
        let mut env = TestEnv::new();
        env.set("MVM_CACHE_DIR", cache.path());

        let src = TempDir::new().expect("src tempdir");
        let staging = TempDir::new().expect("staging tempdir");
        let produced = build_keyless_builder_pack(
            &release_pack_producer_params(src.path()),
            RELEASE_PACK_IDENTITY,
            staging.path(),
        )
        .expect("produce keyless pack");
        std::fs::write(
            staging.path().join("pack-manifest.json"),
            produced
                .manifest
                .canonical_bytes()
                .expect("canonical bytes"),
        )
        .expect("write staged manifest");
        // No manifest.cosign.bundle written.

        let policy = hvf_policy();
        let keyless = release_pack_keyless_trust();
        let rev = good_revocations();
        let ctx = PackVerifyCtx::keyless(&policy, &keyless, &rev);

        let result = promote_staged_builder_pack(staging.path(), &ctx)
            .expect("verify failure is fail-open, not an error");
        assert!(result.is_none(), "missing bundle must not verify");

        let resolved = resolve_pack(PackKind::Builder, GuestArch::host(), PackBackend::Hvf, &ctx)
            .expect("resolve ok");
        assert!(resolved.is_none(), "cache must stay unpromoted");
    }

    /// Malformed JSON in the staged manifest is a genuine error — the fetch
    /// step is expected to have already placed valid bytes, so this signals a
    /// caller bug, not an untrusted-publisher condition.
    #[cfg(feature = "manifest-verify")]
    #[test]
    fn promote_staged_builder_pack_malformed_manifest_is_an_error() {
        let cache = TempDir::new().expect("cache tempdir");
        let mut env = TestEnv::new();
        env.set("MVM_CACHE_DIR", cache.path());

        let staging = TempDir::new().expect("staging tempdir");
        std::fs::write(staging.path().join("pack-manifest.json"), b"not json")
            .expect("write garbage manifest");

        let policy = hvf_policy();
        let keyless = release_pack_keyless_trust();
        let rev = good_revocations();
        let ctx = PackVerifyCtx::keyless(&policy, &keyless, &rev);

        promote_staged_builder_pack(staging.path(), &ctx)
            .expect_err("malformed manifest must error");
    }

    /// A missing staged manifest is the same hard-error shape as a malformed
    /// one.
    #[cfg(feature = "manifest-verify")]
    #[test]
    fn promote_staged_builder_pack_missing_manifest_is_an_error() {
        let cache = TempDir::new().expect("cache tempdir");
        let mut env = TestEnv::new();
        env.set("MVM_CACHE_DIR", cache.path());

        let staging = TempDir::new().expect("staging tempdir");
        // No pack-manifest.json written at all.

        let policy = hvf_policy();
        let keyless = release_pack_keyless_trust();
        let rev = good_revocations();
        let ctx = PackVerifyCtx::keyless(&policy, &keyless, &rev);

        promote_staged_builder_pack(staging.path(), &ctx).expect_err("missing manifest must error");
    }
}
