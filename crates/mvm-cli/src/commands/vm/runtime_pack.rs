//! `--runtime-pack`: boot straight from a verified, attested
//! [`mvm_core::packs::PackKind::Runtime`] cache entry instead of building or
//! pulling an image. This is an explicit source selection — a caller who
//! passes `--runtime-pack` gets exactly that pack or a refusal, never a
//! silent fallback to a build. The kernel + rootfs paths it hands back are a
//! plain `ImageSource::Prebuilt`, so verity sidecar auto-discovery and plan
//! admission run unchanged, same as every other image source.

use anyhow::Result;

use crate::exec::ImageSource;

/// Build the keyless [`mvm_core::pack_cache::PackVerifyCtx`] this host resolves
/// runtime packs against (operator trust config unioned with the compiled-in
/// release channels), then hand it to `f` for the duration of the borrow.
/// Factored out so every runtime-pack call site — explicit `--runtime-pack`
/// resolution and the read-only diagnosis below — builds this ctx identically
/// and can't drift apart.
#[cfg(feature = "manifest-verify")]
fn with_runtime_pack_ctx<T>(
    f: impl FnOnce(&mvm_core::pack_cache::PackVerifyCtx<'_>) -> T,
) -> Result<T> {
    use std::collections::BTreeSet;

    use anyhow::Context;
    use mvm_core::arch::GuestArch;
    use mvm_core::config::mvm_keys_dir;
    use mvm_core::pack_cache::PackVerifyCtx;
    use mvm_core::pack_trust::load_pack_trust_config;
    use mvm_core::packs::{HostCapability, LocalPackPolicy, PackBackend, host_pack_policy_hash};

    let arch = GuestArch::host();
    let trust = load_pack_trust_config(&mvm_keys_dir().join("pack-trust.json"))
        .context("loading pack trust config for --runtime-pack resolution")?
        .unwrap_or_default();

    // Same trust root a runtime pack from the project's own release pipeline
    // carries: the operator's on-disk publishers unioned with the compiled-in
    // release channels, so a stock binary accepts its own release packs with
    // no operator config required. Mirrors the attested builder-pack
    // acceleration path's policy construction.
    let mut policy = LocalPackPolicy {
        host_arch: arch,
        backend: PackBackend::Hvf,
        host_capabilities: BTreeSet::from([HostCapability("vsock".to_string())]),
        policy_hash: host_pack_policy_hash(arch),
        allowed_channels: trust.allowed_channels(),
        now: chrono::Utc::now(),
    };
    policy
        .allowed_channels
        .extend(mvm_core::release_trust::release_channels());
    let keyless = mvm_core::release_trust::release_keyless_trust(env!("CARGO_PKG_VERSION"));
    let ctx = PackVerifyCtx::keyless(&policy, &keyless, &trust);
    Ok(f(&ctx))
}

/// Resolve the local, verified runtime pack for this host into the
/// `ImageSource` the launch path boots. `prod` only feeds the provenance
/// audit line — pack verification itself carries no prod/dev distinction, a
/// runtime pack either verifies or it doesn't.
///
/// Fails closed: no compatible verified pack (`resolve_pack` returning
/// `Ok(None)`), or any resolve error, is an `Err` here — never a fallback to
/// building or pulling an image. The caller asked for this specific source.
#[cfg(feature = "manifest-verify")]
pub(super) fn resolve_runtime_pack_image_source(prod: bool) -> Result<ImageSource> {
    use mvm_core::arch::GuestArch;
    use mvm_core::pack_cache::resolve_pack;
    use mvm_core::packs::{PackBackend, PackKind};

    let arch = GuestArch::host();
    let dir =
        with_runtime_pack_ctx(|ctx| resolve_pack(PackKind::Runtime, arch, PackBackend::Hvf, ctx))??
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "--runtime-pack requested but no verified attested runtime pack for this \
                     host is cached; produce/promote one first, or drop --runtime-pack to build \
                     or pull an image instead"
                )
            })?;

    mvm_core::audit_emit!(
        ImageFetch,
        "source=runtime_pack pack_hash={} prod={}",
        dir.verified.pack_hash.as_str(),
        prod
    );

    Ok(runtime_pack_image_source(&dir))
}

#[cfg(not(feature = "manifest-verify"))]
pub(super) fn resolve_runtime_pack_image_source(_prod: bool) -> Result<ImageSource> {
    anyhow::bail!(
        "--runtime-pack requires an mvmctl build with keyless pack verification (the \
         manifest-verify feature); this binary was built without it"
    )
}

/// Diagnose the local runtime-pack cache for this host without booting or
/// resolving an image source. Read-only, no side effects.
#[cfg(feature = "manifest-verify")]
pub(in crate::commands) fn runtime_pack_diagnosis() -> Result<mvm_core::pack_cache::PackDiagnosis> {
    use anyhow::Context;
    use mvm_core::pack_cache::diagnose_pack;
    use mvm_core::packs::PackKind;

    with_runtime_pack_ctx(|ctx| diagnose_pack(PackKind::Runtime, ctx))?
        .context("diagnosing the local runtime pack cache")
}

#[cfg(not(feature = "manifest-verify"))]
pub(in crate::commands) fn runtime_pack_diagnosis() -> Result<mvm_core::pack_cache::PackDiagnosis> {
    Ok(mvm_core::pack_cache::PackDiagnosis::NoCompatiblePack)
}

/// Human-facing reason a runtime pack is not instant-launchable, or `None`
/// when it is ready. Maps the verification failure to a precise cause.
pub(in crate::commands) fn not_instant_reason(
    d: &mvm_core::pack_cache::PackDiagnosis,
) -> Option<String> {
    use mvm_core::pack_cache::PackDiagnosis;
    use mvm_core::packs::PackVerifyError;

    match d {
        PackDiagnosis::Ready { .. } => None,
        PackDiagnosis::NoCompatiblePack => {
            Some("no verified runtime pack is cached for this host".to_string())
        }
        PackDiagnosis::Rejected { reason, .. } => Some(match reason {
            PackVerifyError::IncompatibleArchitecture { got, expected } => {
                format!("cached runtime pack was built for {got} but this host is {expected}")
            }
            PackVerifyError::IncompatibleBackend { backend } => {
                format!("cached runtime pack does not support this host's backend ({backend})")
            }
            PackVerifyError::MissingHostCapability(capability) => format!(
                "cached runtime pack requires host capability {capability}, which is unavailable"
            ),
            PackVerifyError::ExpiredTrustMetadata { expired_at }
            | PackVerifyError::ExpiredSignature { expired_at, .. } => {
                format!("cached runtime pack signature expired at {expired_at}")
            }
            PackVerifyError::Revoked { reason, .. } => {
                format!("cached runtime pack signer is revoked: {reason}")
            }
            PackVerifyError::UnknownSigningKey { .. } => {
                "cached runtime pack is signed by an untrusted key".to_string()
            }
            PackVerifyError::ChannelNotAllowed(channel) => {
                format!("cached runtime pack channel {channel:?} is not allowed by local policy")
            }
            PackVerifyError::PolicyHashMismatch { .. } => {
                "cached runtime pack was built for a different local policy".to_string()
            }
            PackVerifyError::MutableOciReference { .. } => {
                "cached runtime pack references a mutable OCI tag, which is not instant-eligible"
                    .to_string()
            }
            PackVerifyError::FileHashMismatch { .. }
            | PackVerifyError::PackHashMismatch { .. }
            | PackVerifyError::FileSizeMismatch { .. }
            | PackVerifyError::UnsafeFilePath(_)
            | PackVerifyError::DuplicateFile(_) => {
                "cached runtime pack failed integrity verification (tampered or corrupt)"
                    .to_string()
            }
            other => format!("cached runtime pack failed verification: {other}"),
        }),
    }
}

/// Pure mapping from a verified runtime pack dir to the `ImageSource` the
/// launch path boots: the pack's own kernel + rootfs paths, labeled by its
/// content-addressed pack hash. No I/O beyond what's already inside `dir`, so
/// it's unit-testable without a promoted pack cache.
#[cfg(feature = "manifest-verify")]
fn runtime_pack_image_source(dir: &mvm_core::pack_cache::VerifiedPackDir) -> ImageSource {
    ImageSource::Prebuilt {
        kernel_path: dir
            .root
            .join(mvm_build::builder_pack::KERNEL_FILE)
            .display()
            .to_string(),
        rootfs_path: dir
            .root
            .join(mvm_build::builder_pack::ROOTFS_FILE)
            .display()
            .to_string(),
        initrd_path: None,
        label: format!("runtime-pack:{}", dir.verified.pack_hash.as_str()),
        virtiofs_oci_root: None,
    }
}

#[cfg(all(test, feature = "manifest-verify"))]
mod tests {
    use std::path::PathBuf;

    use mvm_core::pack_cache::VerifiedPackDir;
    use mvm_core::packs::Sha256Hex;
    use mvm_core::plan::bundle::KeyId;
    use mvm_core::util::test_env::TestEnv;

    use super::*;

    fn verified_pack_dir(root: &str) -> VerifiedPackDir {
        VerifiedPackDir {
            root: PathBuf::from(root),
            verified: mvm_core::packs::VerifiedPack {
                pack_hash: Sha256Hex::from_bytes(b"runtime-pack-test"),
                file_count: 4,
                signer_key_id: KeyId::from_identity("test-identity"),
            },
        }
    }

    #[test]
    fn maps_kernel_and_rootfs_paths_under_pack_root() {
        let dir = verified_pack_dir("/cache/packs/deadbeef");
        let image = runtime_pack_image_source(&dir);
        let ImageSource::Prebuilt {
            kernel_path,
            rootfs_path,
            initrd_path,
            virtiofs_oci_root,
            ..
        } = &image
        else {
            panic!("expected ImageSource::Prebuilt");
        };
        assert_eq!(kernel_path, "/cache/packs/deadbeef/vmlinux");
        assert_eq!(rootfs_path, "/cache/packs/deadbeef/rootfs.ext4");
        assert!(rootfs_path.ends_with("rootfs.ext4"));
        assert!(initrd_path.is_none());
        assert!(virtiofs_oci_root.is_none());
    }

    #[test]
    fn label_starts_with_runtime_pack_prefix_and_carries_hash() {
        let dir = verified_pack_dir("/cache/packs/deadbeef");
        let image = runtime_pack_image_source(&dir);
        let ImageSource::Prebuilt { label, .. } = &image else {
            panic!("expected ImageSource::Prebuilt");
        };
        assert!(label.starts_with("runtime-pack:"));
        assert_eq!(
            label,
            &format!("runtime-pack:{}", dir.verified.pack_hash.as_str())
        );
    }

    /// A cache with no promoted packs must fail closed — never fall back to
    /// building or pulling an image just because the operator asked for the
    /// runtime-pack source specifically.
    #[test]
    fn resolve_fails_closed_when_no_pack_is_cached() {
        let cache = tempfile::TempDir::new().expect("cache tempdir");
        let data = tempfile::TempDir::new().expect("data tempdir");
        let mut env = TestEnv::new();
        env.set("MVM_CACHE_DIR", cache.path());
        env.set("MVM_DATA_DIR", data.path());

        let err = resolve_runtime_pack_image_source(false)
            .expect_err("no promoted runtime pack must refuse rather than fall back");
        assert!(
            err.to_string()
                .contains("no verified attested runtime pack")
        );
    }
}

/// `not_instant_reason` is a pure reason-mapper with no I/O, so its tests need
/// neither a promoted pack cache nor the `manifest-verify` feature —
/// `PackDiagnosis`/`PackVerifyError` are always available.
#[cfg(test)]
mod not_instant_reason_tests {
    use mvm_core::arch::GuestArch;
    use mvm_core::pack_cache::PackDiagnosis;
    use mvm_core::packs::{PackBackend, PackVerifyError, Sha256Hex};

    use super::not_instant_reason;

    fn hash(value: &str) -> Sha256Hex {
        Sha256Hex::from_bytes(value.as_bytes())
    }

    #[test]
    fn ready_maps_to_none() {
        let diagnosis = PackDiagnosis::Ready {
            pack_hash: hash("pack"),
            file_count: 2,
        };
        assert_eq!(not_instant_reason(&diagnosis), None);
    }

    #[test]
    fn no_compatible_pack_maps_to_absence_reason() {
        let reason = not_instant_reason(&PackDiagnosis::NoCompatiblePack)
            .expect("NoCompatiblePack must produce a reason");
        assert!(reason.contains("no verified runtime pack is cached"));
    }

    #[test]
    fn incompatible_architecture_names_both_architectures() {
        let diagnosis = PackDiagnosis::Rejected {
            pack_hash: hash("pack"),
            reason: PackVerifyError::IncompatibleArchitecture {
                got: GuestArch::X86_64,
                expected: GuestArch::Aarch64,
            },
        };
        let reason = not_instant_reason(&diagnosis).expect("Rejected must produce a reason");
        assert!(reason.contains("built for"));
        assert!(reason.contains("x86_64"));
        assert!(reason.contains("aarch64"));
    }

    #[test]
    fn incompatible_backend_names_the_backend() {
        let diagnosis = PackDiagnosis::Rejected {
            pack_hash: hash("pack"),
            reason: PackVerifyError::IncompatibleBackend {
                backend: PackBackend::Libkrun,
            },
        };
        let reason = not_instant_reason(&diagnosis).expect("Rejected must produce a reason");
        assert!(reason.contains("backend"));
        assert!(reason.contains("libkrun"));
    }

    #[test]
    fn expired_signature_reports_the_expiry_timestamp() {
        use chrono::TimeZone;
        let expired_at = chrono::Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let diagnosis = PackDiagnosis::Rejected {
            pack_hash: hash("pack"),
            reason: PackVerifyError::ExpiredSignature {
                key_id: mvm_core::plan::bundle::KeyId::from_identity("test-identity"),
                expired_at,
            },
        };
        let reason = not_instant_reason(&diagnosis).expect("Rejected must produce a reason");
        assert!(reason.contains("expired at"));
    }

    #[test]
    fn revoked_names_the_revocation_reason() {
        let diagnosis = PackDiagnosis::Rejected {
            pack_hash: hash("pack"),
            reason: PackVerifyError::Revoked {
                key_id: mvm_core::plan::bundle::KeyId::from_identity("test-identity"),
                reason: "compromised signing key".to_string(),
            },
        };
        let reason = not_instant_reason(&diagnosis).expect("Rejected must produce a reason");
        assert!(reason.contains("revoked"));
        assert!(reason.contains("compromised signing key"));
    }

    #[test]
    fn unknown_signing_key_names_untrusted() {
        let diagnosis = PackDiagnosis::Rejected {
            pack_hash: hash("pack"),
            reason: PackVerifyError::UnknownSigningKey {
                key_id: mvm_core::plan::bundle::KeyId::from_identity("test-identity"),
            },
        };
        let reason = not_instant_reason(&diagnosis).expect("Rejected must produce a reason");
        assert!(reason.contains("untrusted"));
    }

    #[test]
    fn file_hash_mismatch_names_tampered_or_corrupt() {
        let diagnosis = PackDiagnosis::Rejected {
            pack_hash: hash("pack"),
            reason: PackVerifyError::FileHashMismatch {
                path: "rootfs.ext4".to_string(),
                declared: hash("declared"),
                actual: hash("actual"),
            },
        };
        let reason = not_instant_reason(&diagnosis).expect("Rejected must produce a reason");
        assert!(reason.contains("tampered"));
    }
}
