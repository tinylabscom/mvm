//! `machine run <artifact.mvm>` support: verify-and-run a portable signed
//! artifact through the same admitted boot path as an OCI-image run.
//!
//! Two pure, fail-closed gates sit between a verified `.mvm` and the boot:
//!
//!   1. [`ensure_runnable_on_host`] — refuse an artifact built for a different
//!      CPU arch. `packed_artifact::verify` deliberately skips this (its doc
//!      notes "mismatched arch fails at boot"); the runner gates it up front so
//!      a wrong-arch image never reaches admission.
//!   2. [`admission_for`] — derive the admission shape from the artifact's
//!      declared `SecurityPosture`. The artifact may only *restrict* relative
//!      to what the run already requested; it never escalates. A `.mvm` is
//!      never a self-executing bypass.

use anyhow::Result;
use mvm_build::packed_artifact::{Manifest, SecurityPosture, verify as verify_artifact};
use mvm_core::arch::GuestArch;
use mvm_core::network_policy::NetworkPolicy;
use mvm_core::plan::PlanSeccompTier;
use std::path::PathBuf;

#[derive(Debug, PartialEq, Eq)]
pub(in crate::commands) enum PortableRunError {
    ArchMismatch {
        artifact: GuestArch,
        host: GuestArch,
    },
}

impl std::fmt::Display for PortableRunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ArchMismatch { artifact, host } => write!(
                f,
                "artifact targets {artifact} but this host is {host}; \
                 a {artifact} image cannot boot on a {host} host"
            ),
        }
    }
}

impl std::error::Error for PortableRunError {}

/// Refuse a portable artifact whose target arch differs from the host's.
pub(in crate::commands) fn ensure_runnable_on_host(
    manifest: &Manifest,
    host: GuestArch,
) -> Result<(), PortableRunError> {
    if manifest.target_arch != host {
        return Err(PortableRunError::ArchMismatch {
            artifact: manifest.target_arch,
            host,
        });
    }
    Ok(())
}

/// Fail-closed admission shape derived from a verified artifact's posture.
///
/// The artifact can only *narrow* what the run already requested:
/// - `seccomp_tier` is `Standard` for every profile — no artifact gets a
///   looser tier than the OCI-`run` baseline.
/// - `network` is the requested policy only when the artifact permits egress;
///   a no-egress artifact is deny-all regardless of `--net` / `--allow-host`.
/// - `allows_volumes` mirrors the artifact's declaration (deny unless declared).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::commands) struct ArtifactAdmission {
    pub seccomp_tier: PlanSeccompTier,
    pub network: NetworkPolicy,
    pub allows_volumes: bool,
}

pub(in crate::commands) fn admission_for(
    posture: &SecurityPosture,
    requested_network: NetworkPolicy,
) -> ArtifactAdmission {
    ArtifactAdmission {
        // No artifact profile earns a looser tier than the OCI-`run` baseline.
        seccomp_tier: PlanSeccompTier::Standard,
        // Intersect: honor the requested policy only when the artifact permits
        // egress; otherwise clamp to deny-all regardless of --net/--allow-host.
        network: if posture.allows_egress {
            requested_network
        } else {
            NetworkPolicy::deny_all()
        },
        allows_volumes: posture.allows_volumes,
    }
}

/// `machine check-artifact <path.mvm>` — verify a portable artifact, confirm
/// it can run on this host, and show how `machine run` would admit it. Read-
/// only: no extraction, no boot, no audit-chain emission. The companion live
/// boot (`machine run <artifact>`) reuses [`ensure_runnable_on_host`] +
/// [`admission_for`] over an `ImageSource::Prebuilt` boot path.
#[derive(clap::Args, Debug, Clone)]
pub(in crate::commands) struct CheckArtifactArgs {
    /// Path to the `.mvm` artifact to verify and preview.
    pub path: PathBuf,
    /// Verifying-key file (32-byte raw Ed25519 public key). Defaults to the
    /// host signer's public half.
    #[arg(long)]
    pub key: Option<PathBuf>,
    /// Emit the verdict as JSON.
    #[arg(long)]
    pub json: bool,
}

pub(in crate::commands) fn run_check_artifact(args: CheckArtifactArgs) -> Result<()> {
    let verifying = super::super::vm::artifact::resolve_verifying_key(args.key.as_deref())?;
    let manifest = match verify_artifact(&args.path, &verifying) {
        Ok(m) => m,
        Err(e) => {
            crate::ui::warn(&format!("{}: verify failed: {e}", args.path.display()));
            std::process::exit(65);
        }
    };

    let host = GuestArch::host();
    let runnable = ensure_runnable_on_host(&manifest, host);
    // Preview the effective admission assuming the most permissive request
    // (`--net`): this surfaces what the artifact itself caps.
    let admission = admission_for(&manifest.security, NetworkPolicy::unrestricted());

    if args.json {
        let verdict = serde_json::json!({
            "path": args.path.display().to_string(),
            "target_arch": manifest.target_arch.to_string(),
            "host_arch": host.to_string(),
            "runnable_here": runnable.is_ok(),
            "profile": format!("{:?}", manifest.security.profile),
            "seccomp_tier": admission.seccomp_tier.to_string(),
            "egress": if manifest.security.allows_egress { "allowed" } else { "deny-all" },
            "volumes": admission.allows_volumes,
        });
        println!("{}", serde_json::to_string_pretty(&verdict)?);
        return Ok(());
    }

    match runnable {
        Ok(()) => crate::ui::success(&format!(
            "{}: verified, runnable on {} (profile={:?}, seccomp={}, egress={}, volumes={})",
            args.path.display(),
            host,
            manifest.security.profile,
            admission.seccomp_tier,
            if manifest.security.allows_egress {
                "allowed"
            } else {
                "deny-all"
            },
            admission.allows_volumes,
        )),
        Err(e) => {
            crate::ui::warn(&format!(
                "{}: verified but not runnable here: {e}",
                args.path.display()
            ));
            std::process::exit(65);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_build::packed_artifact::ArtifactProfile;
    use std::collections::BTreeMap;

    fn manifest_with(arch: GuestArch, posture: SecurityPosture) -> Manifest {
        Manifest {
            format_version: mvm_build::packed_artifact::MANIFEST_FORMAT_VERSION,
            mvm_version: "test".to_string(),
            target_arch: arch,
            files: BTreeMap::new(),
            build_provenance: None,
            security: posture,
        }
    }

    fn dev_posture() -> SecurityPosture {
        SecurityPosture {
            profile: ArtifactProfile::Dev,
            verity_protected: false,
            requires_auth: false,
            allows_volumes: true,
            allows_egress: true,
        }
    }

    #[test]
    fn rejects_artifact_built_for_a_different_arch() {
        let m = manifest_with(GuestArch::X86_64, dev_posture());
        let err = ensure_runnable_on_host(&m, GuestArch::Aarch64).unwrap_err();
        assert_eq!(
            err,
            PortableRunError::ArchMismatch {
                artifact: GuestArch::X86_64,
                host: GuestArch::Aarch64,
            }
        );
    }

    #[test]
    fn accepts_artifact_matching_host_arch() {
        let m = manifest_with(GuestArch::Aarch64, dev_posture());
        assert!(ensure_runnable_on_host(&m, GuestArch::Aarch64).is_ok());
    }

    #[test]
    fn no_egress_artifact_is_deny_all_even_when_egress_requested() {
        let mut p = dev_posture();
        p.allows_egress = false;
        let adm = admission_for(&p, NetworkPolicy::unrestricted());
        assert_eq!(
            adm.network,
            NetworkPolicy::deny_all(),
            "a no-egress artifact must be deny-all regardless of --net/--allow-host"
        );
    }

    #[test]
    fn egress_artifact_keeps_the_requested_network() {
        let mut p = dev_posture();
        p.allows_egress = true;
        let adm = admission_for(&p, NetworkPolicy::unrestricted());
        assert_eq!(adm.network, NetworkPolicy::unrestricted());
    }

    #[test]
    fn volumes_follow_the_artifact_declaration() {
        let mut p = dev_posture();
        p.allows_volumes = false;
        assert!(!admission_for(&p, NetworkPolicy::deny_all()).allows_volumes);
        p.allows_volumes = true;
        assert!(admission_for(&p, NetworkPolicy::deny_all()).allows_volumes);
    }

    #[test]
    fn seccomp_is_standard_for_every_profile() {
        for profile in [
            ArtifactProfile::SealedProd,
            ArtifactProfile::Dev,
            ArtifactProfile::Builder,
        ] {
            let mut p = dev_posture();
            p.profile = profile;
            assert_eq!(
                admission_for(&p, NetworkPolicy::deny_all()).seccomp_tier,
                PlanSeccompTier::Standard,
                "no artifact profile may get a looser tier than the run baseline"
            );
        }
    }
}
