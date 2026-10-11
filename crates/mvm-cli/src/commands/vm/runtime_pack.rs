//! `--runtime-pack`: boot straight from a verified, attested
//! [`mvm_core::packs::PackKind::Runtime`] cache entry instead of building or
//! pulling an image. This is an explicit source selection — a caller who
//! passes `--runtime-pack` gets exactly that pack or a refusal, never a
//! silent fallback to a build. The kernel + rootfs paths it hands back are a
//! plain `ImageSource::Prebuilt`, so verity sidecar auto-discovery and plan
//! admission run unchanged, same as every other image source.
//!
//! The default (no `--manifest`/`--image`/`--runtime-pack`) launch path also
//! consults the same cache as an accelerator: [`try_runtime_pack_image_source`]
//! shares this module's trust construction but never refuses — a miss or a
//! resolve error just means the accelerator isn't available, and the caller
//! falls back to its own default (building the bundled microVM). Only the
//! explicit `--runtime-pack` flag carries a fail-closed contract.

use anyhow::Result;

use crate::exec::ImageSource;

/// Build the keyless [`mvm_core::pack_cache::PackVerifyCtx`] this host resolves
/// runtime packs against (operator trust config unioned with the compiled-in
/// release channels), then hand it to `f` for the duration of the borrow.
/// Factored out so every runtime-pack call site — explicit `--runtime-pack`,
/// the fail-open auto-prefer path, and the read-only diagnosis helper — build
/// this ctx identically and can't drift apart.
#[cfg(feature = "manifest-verify")]
fn with_runtime_pack_ctx<T>(
    f: impl FnOnce(&trust::RuntimePackTrustInputs, &mvm_core::pack_cache::PackVerifyCtx<'_>) -> T,
) -> Result<T> {
    use anyhow::Context;
    use mvm_core::pack_cache::PackVerifyCtx;

    let inputs = trust::RuntimePackTrustInputs::load()
        .context("building trust inputs for --runtime-pack resolution")?;
    let ctx = PackVerifyCtx::keyless(&inputs.policy, &inputs.keyless, &inputs.trust);
    Ok(f(&inputs, &ctx))
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
pub(in crate::commands) fn resolve_runtime_pack_image_source(prod: bool) -> Result<ImageSource> {
    use anyhow::Context;
    use mvm_core::pack_cache::resolve_pack;
    use mvm_core::packs::{PackBackend, PackKind};

    let dir = with_runtime_pack_ctx(|inputs, ctx| {
        resolve_pack(
            PackKind::Runtime,
            inputs.policy.host_arch,
            PackBackend::Hvf,
            ctx,
        )
    })?
    .context("resolving verified runtime pack from the local cache")?
    .ok_or_else(|| {
        anyhow::anyhow!(
            "--runtime-pack requested but no verified attested runtime pack for this host \
                 is cached; produce/promote one first, or drop --runtime-pack to build or pull \
                 an image instead"
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
pub(in crate::commands) fn resolve_runtime_pack_image_source(_prod: bool) -> Result<ImageSource> {
    anyhow::bail!(
        "--runtime-pack requires an mvmctl build with keyless pack verification (the \
         manifest-verify feature); this binary was built without it"
    )
}

/// Fail-open sibling of [`resolve_runtime_pack_image_source`] for the *default*
/// launch path (no `--manifest`/`--image`/`--runtime-pack`): an accelerator,
/// not a source selection. A verified compatible runtime pack yields
/// `Some(ImageSource::Prebuilt)` exactly as the explicit path would; a resolve
/// miss (`Ok(None)`) or any error yields `None` — the caller falls back to
/// building the bundled default microVM. Never returns an error.
#[cfg(feature = "manifest-verify")]
pub(super) fn try_runtime_pack_image_source(prod: bool) -> Option<ImageSource> {
    use mvm_core::pack_cache::resolve_pack;
    use mvm_core::packs::{PackBackend, PackKind};

    let dir = match with_runtime_pack_ctx(|inputs, ctx| {
        resolve_pack(
            PackKind::Runtime,
            inputs.policy.host_arch,
            PackBackend::Hvf,
            ctx,
        )
    }) {
        Ok(Ok(Some(dir))) => dir,
        Ok(Ok(None)) => return None,
        Ok(Err(e)) => {
            tracing::debug!(error = %e, "runtime-pack auto-prefer: no verified pack resolved");
            return None;
        }
        Err(e) => {
            tracing::debug!(error = %e, "runtime-pack auto-prefer: trust setup unavailable");
            return None;
        }
    };

    mvm_core::audit_emit!(
        ImageFetch,
        "source=runtime_pack_autoprefer pack_hash={} prod={}",
        dir.verified.pack_hash.as_str(),
        prod
    );

    Some(runtime_pack_image_source(&dir))
}

#[cfg(not(feature = "manifest-verify"))]
pub(super) fn try_runtime_pack_image_source(_prod: bool) -> Option<ImageSource> {
    None
}

pub(in crate::commands) use mvm_client::maintenance::cache::{
    not_instant_reason, runtime_pack_diagnosis,
};

/// Trust construction shared by the fail-closed `--runtime-pack` resolver and
/// the fail-open auto-prefer accelerator, so the two never drift apart on
/// which packs a stock binary accepts.
#[cfg(feature = "manifest-verify")]
mod trust {
    pub(super) use mvm_client::maintenance::cache::RuntimePackTrustInputs;
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
        unpacked_oci_root: None,
    }
}

#[cfg(all(test, feature = "manifest-verify"))]
mod tests {
    use std::path::PathBuf;

    use mvm_core::pack_cache::VerifiedPackDir;
    use mvm_core::packs::Sha256Hex;
    use mvm_core::plan::bundle::key_id_from_identity;
    use mvm_core::util::test_env::TestEnv;

    use super::*;

    fn verified_pack_dir(root: &str) -> VerifiedPackDir {
        VerifiedPackDir {
            root: PathBuf::from(root),
            verified: mvm_core::packs::VerifiedPack {
                pack_hash: Sha256Hex::from_bytes(b"runtime-pack-test"),
                file_count: 4,
                signer_key_id: key_id_from_identity("test-identity"),
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
            unpacked_oci_root,
            ..
        } = &image
        else {
            panic!("expected ImageSource::Prebuilt");
        };
        assert_eq!(kernel_path, "/cache/packs/deadbeef/vmlinux");
        assert_eq!(rootfs_path, "/cache/packs/deadbeef/rootfs.ext4");
        assert!(rootfs_path.ends_with("rootfs.ext4"));
        assert!(initrd_path.is_none());
        assert!(unpacked_oci_root.is_none());
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
        let root = tempfile::TempDir::new().expect("mvm root tempdir");
        let mut env = TestEnv::new();
        env.set("MVM_HOME", root.path());

        let err = resolve_runtime_pack_image_source(false)
            .expect_err("no promoted runtime pack must refuse rather than fall back");
        assert!(
            err.to_string()
                .contains("no verified attested runtime pack")
        );
    }

    /// The auto-prefer accelerator is fail-open: the same cache miss that
    /// makes `--runtime-pack` refuse must instead report absence here, so the
    /// default `machine run` path falls back to building rather than
    /// propagating an error.
    #[test]
    fn try_runtime_pack_returns_none_when_no_pack_is_cached() {
        let root = tempfile::TempDir::new().expect("mvm root tempdir");
        let mut env = TestEnv::new();
        env.set("MVM_HOME", root.path());

        assert!(try_runtime_pack_image_source(false).is_none());
    }

    /// Both the fail-closed explicit resolver and the fail-open accelerator
    /// bottom out in the same `RuntimePackTrustInputs::load()` construction —
    /// verified here by exercising both against the same empty cache (so
    /// they observe the identical miss) and then checking the shared helper
    /// itself produces the host policy either call site would use.
    #[test]
    fn resolve_and_try_share_trust_inputs_construction() {
        let root = tempfile::TempDir::new().expect("mvm root tempdir");
        let mut env = TestEnv::new();
        env.set("MVM_HOME", root.path());

        let explicit_err = resolve_runtime_pack_image_source(false)
            .expect_err("no cached pack refuses the explicit path");
        assert!(
            explicit_err
                .to_string()
                .contains("no verified attested runtime pack")
        );
        assert!(try_runtime_pack_image_source(false).is_none());

        let inputs = trust::RuntimePackTrustInputs::load().expect("trust inputs load");
        assert_eq!(inputs.policy.backend, mvm_core::packs::PackBackend::Hvf);
        assert_eq!(inputs.policy.host_arch, mvm_core::arch::GuestArch::host());
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

        let expired_at = chrono::Utc
            .with_ymd_and_hms(2026, 1, 1, 0, 0, 0)
            .single()
            .expect("valid timestamp");
        let diagnosis = PackDiagnosis::Rejected {
            pack_hash: hash("pack"),
            reason: PackVerifyError::ExpiredSignature {
                key_id: mvm_core::plan::bundle::key_id_from_identity("test-identity"),
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
                key_id: mvm_core::plan::bundle::key_id_from_identity("test-identity"),
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
                key_id: mvm_core::plan::bundle::key_id_from_identity("test-identity"),
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
