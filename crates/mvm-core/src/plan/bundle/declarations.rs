//! Checks on what a signed manifest declares, beyond the artifact hashes.
//!
//! A valid signature proves who wrote a manifest, not that it is coherent. A
//! publisher's tooling can still sign a posture that claims dm-verity over a
//! rootfs that has none, or declare a 3 GiB rootfs a host would have to read
//! into memory. These checks run on both sides: [`super::write_bundle`]
//! refuses to seal such a manifest, and [`super::read_and_verify_bundle`]
//! refuses to accept one.

use mvm_contract::plan::bundle::{
    ArtifactRole, BundleManifest, BundleMember, BundleSecurityPosture,
    ENVIRONMENT_MEMBER_MIN_SCHEMA, MAX_BUNDLE_ENTRY_BYTES, MAX_BUNDLE_TOTAL_BYTES,
    MAX_KERNEL_CMDLINE_BYTES,
};
use mvm_contract::plan::environment::{EnvironmentCapability, EnvironmentDescriptor};
use mvm_contract::plan::types::BuildProvenance;
use mvm_contract::policy::security::AgentProfile;

use super::BundleVerifyError;

/// Running total of bundle bytes, refusing any entry or total past the caps.
///
/// Fed each entry's size before its bytes are read, so an archive whose
/// headers claim more than the caps is refused without allocating for it.
/// An exporter feeds it file sizes the same way, before reading the files.
#[derive(Debug, Default)]
pub struct BundleSizeBudget {
    total: u64,
}

impl BundleSizeBudget {
    /// Count `size` bytes for `path`, refusing an entry over
    /// [`MAX_BUNDLE_ENTRY_BYTES`] or a running total over
    /// [`MAX_BUNDLE_TOTAL_BYTES`].
    pub fn admit(&mut self, path: &str, size: u64) -> Result<(), BundleVerifyError> {
        if size > MAX_BUNDLE_ENTRY_BYTES {
            return Err(BundleVerifyError::EntryTooLarge {
                path: path.to_string(),
                size,
                limit: MAX_BUNDLE_ENTRY_BYTES,
            });
        }
        let total = self.total.saturating_add(size);
        if total > MAX_BUNDLE_TOTAL_BYTES {
            return Err(BundleVerifyError::BundleTooLarge {
                total,
                limit: MAX_BUNDLE_TOTAL_BYTES,
            });
        }
        self.total = total;
        Ok(())
    }
}

/// Every check on a manifest's declarations: the size caps over its declared
/// artifacts, then each declaration member.
pub(super) fn validate_declarations(manifest: &BundleManifest) -> Result<(), BundleVerifyError> {
    let mut budget = BundleSizeBudget::default();
    for artifact in &manifest.artifacts {
        budget.admit(&artifact.path, artifact.size_bytes)?;
    }
    refuse_repeated_declarations(&manifest.members)?;
    if manifest
        .members
        .iter()
        .any(|member| matches!(member, BundleMember::EmbeddedBootAssets { .. }))
        && manifest
            .members
            .iter()
            .any(|member| matches!(member, BundleMember::EmbeddedImageSet { .. }))
    {
        return Err(BundleVerifyError::ManifestParse(
            "boot assets and full image-set declarations cannot be combined".into(),
        ));
    }
    if manifest.schema_version < 4
        && manifest
            .members
            .iter()
            .any(|member| matches!(member, BundleMember::EmbeddedBootAssets { .. }))
    {
        return Err(BundleVerifyError::ManifestParse(
            "boot assets require bundle schema 4".into(),
        ));
    }
    if let Some(cmdline) = manifest.kernel_cmdline() {
        validate_cmdline(cmdline)?;
    }
    if let Some(posture) = manifest.security_posture() {
        validate_posture(posture, manifest.verity.is_some())?;
    }
    if let Some(provenance) = manifest.build_provenance() {
        validate_provenance(provenance, manifest)?;
    }
    if let Some(environment) = manifest.environment() {
        validate_environment(environment, manifest)?;
    }
    Ok(())
}

fn declaration_class(member: &BundleMember) -> Option<&'static str> {
    match member {
        BundleMember::EmbeddedImageSet { .. } => None,
        BundleMember::EmbeddedBootAssets { .. } => Some("embedded_boot_assets"),
        BundleMember::KernelCmdline { .. } => Some("kernel_cmdline"),
        BundleMember::SecurityPosture(_) => Some("security_posture"),
        BundleMember::BuildProvenance(_) => Some("build_provenance"),
        BundleMember::Environment(_) => Some("environment"),
    }
}

/// Two postures in one bundle would leave the launcher to pick one, and
/// whichever it picked the other was signed for nothing.
fn refuse_repeated_declarations(members: &[BundleMember]) -> Result<(), BundleVerifyError> {
    let mut seen: Vec<&'static str> = Vec::new();
    for class in members.iter().filter_map(declaration_class) {
        if seen.contains(&class) {
            return Err(BundleVerifyError::DuplicateMember { class });
        }
        seen.push(class);
    }
    Ok(())
}

fn validate_cmdline(cmdline: &str) -> Result<(), BundleVerifyError> {
    let malformed = |reason: String| Err(BundleVerifyError::MalformedCmdline { reason });
    if cmdline.trim().is_empty() {
        return malformed("it is empty".to_string());
    }
    if cmdline.len() > MAX_KERNEL_CMDLINE_BYTES {
        return malformed(format!(
            "it is {} bytes, over the {MAX_KERNEL_CMDLINE_BYTES}-byte limit",
            cmdline.len()
        ));
    }
    if let Some(byte) = cmdline.bytes().find(|b| !(b' '..=b'~').contains(b)) {
        return malformed(format!(
            "it contains byte {byte:#04x}; only printable ASCII is allowed"
        ));
    }
    Ok(())
}

fn validate_posture(
    posture: &BundleSecurityPosture,
    has_verity_binding: bool,
) -> Result<(), BundleVerifyError> {
    let malformed = |reason: &str| {
        Err(BundleVerifyError::MalformedPosture {
            reason: reason.to_string(),
        })
    };
    if posture.verity_protected && !has_verity_binding {
        return malformed("it claims a dm-verity rootfs but the bundle carries no verity binding");
    }
    if !posture.verity_protected && has_verity_binding {
        return malformed("it denies a dm-verity rootfs the bundle carries a verity binding for");
    }
    if posture.profile == AgentProfile::SealedProd {
        if !posture.verity_protected {
            return malformed("a sealed-prod workload must have a dm-verity rootfs");
        }
        if !posture.requires_auth {
            return malformed("a sealed-prod workload must require authenticated vsock frames");
        }
    }
    Ok(())
}

/// The environment descriptor relates to the rest of the manifest in three
/// ways, each checked here because the descriptor alone cannot see them: it
/// needs the schema that introduced it, its target must be the manifest's
/// architecture, and every capability it requires must be one the bundle's
/// signed posture permits. A descriptor that requires any capability without a
/// posture to measure it against is refused: there is nothing to say the
/// publisher permitted it.
fn validate_environment(
    environment: &EnvironmentDescriptor,
    manifest: &BundleManifest,
) -> Result<(), BundleVerifyError> {
    if manifest.schema_version < ENVIRONMENT_MEMBER_MIN_SCHEMA {
        return Err(BundleVerifyError::EnvironmentRefused {
            reason: format!(
                "the environment member requires bundle schema {ENVIRONMENT_MEMBER_MIN_SCHEMA}, \
                 but the manifest declares schema {}",
                manifest.schema_version
            ),
        });
    }
    environment.validate()?;
    let target = environment.target.arch_label();
    if target != manifest.arch {
        return Err(BundleVerifyError::EnvironmentRefused {
            reason: format!(
                "the environment targets {target}, but the bundle is built for {}",
                manifest.arch
            ),
        });
    }
    let forbidden = forbidden_capabilities(environment, manifest.security_posture());
    if !forbidden.is_empty() {
        return Err(BundleVerifyError::EnvironmentRefused {
            reason: format!(
                "the environment requires {}, which the bundle's security posture does not \
                 permit",
                forbidden.join(", ")
            ),
        });
    }
    Ok(())
}

/// Required descriptor slots not bound by the signed plan. This checks names,
/// not secret values or endpoint substitution, which remain broker-owned.
pub fn unbound_environment_secret_slots(
    environment: &EnvironmentDescriptor,
    secrets: &[crate::plan::SecretBinding],
) -> Vec<String> {
    environment
        .required_secret_slots()
        .filter(|slot| !secrets.iter().any(|binding| binding.name == *slot))
        .map(str::to_string)
        .collect()
}

/// Every capability `environment` requires that `posture` does not permit,
/// by wire name. With no posture, every required capability is forbidden.
///
/// Shared with launch admission, which measures the same descriptor against
/// the posture the launch is held to.
pub fn forbidden_capabilities(
    environment: &EnvironmentDescriptor,
    posture: Option<&BundleSecurityPosture>,
) -> Vec<&'static str> {
    environment
        .capabilities
        .iter()
        .copied()
        .filter(|capability| !posture.is_some_and(|p| posture_permits(p, *capability)))
        .map(EnvironmentCapability::as_str)
        .collect()
}

fn posture_permits(posture: &BundleSecurityPosture, capability: EnvironmentCapability) -> bool {
    match capability {
        EnvironmentCapability::Egress => posture.allows_egress,
        EnvironmentCapability::HostVolumes => posture.allows_volumes,
        EnvironmentCapability::InteractiveTerminal => posture.profile != AgentProfile::SealedProd,
    }
}

/// The provenance's artifact digests describe what the build produced; the
/// bundle's own artifacts are what ships. A digest that names an artifact the
/// bundle carries must match it. Digests for outputs a bundle has no role for
/// (`mvm_init`, `snapshot_base`) describe the build, not the archive, and are
/// carried as recorded.
fn validate_provenance(
    provenance: &BuildProvenance,
    manifest: &BundleManifest,
) -> Result<(), BundleVerifyError> {
    if provenance.input_ref.trim().is_empty() {
        return Err(BundleVerifyError::ProvenanceMismatch {
            artifact: "input_ref".to_string(),
            reason: "the build input reference is empty".to_string(),
        });
    }
    let recorded = &provenance.artifacts;
    let bound = [
        ("kernel", ArtifactRole::Kernel, recorded.kernel.as_deref()),
        ("rootfs", ArtifactRole::Rootfs, recorded.rootfs.as_deref()),
        (
            "initramfs",
            ArtifactRole::Initrd,
            recorded.initramfs.as_deref(),
        ),
    ];
    for (label, role, digest) in bound {
        let Some(digest) = digest else { continue };
        let reason = match manifest.find_by_role(&role) {
            Some(artifact) if artifact.sha256 == digest => continue,
            Some(artifact) => format!(
                "provenance records {digest} but the bundle's {} is {}",
                artifact.name, artifact.sha256
            ),
            None => format!("provenance records {digest} but the bundle carries no {label}"),
        };
        return Err(BundleVerifyError::ProvenanceMismatch {
            artifact: label.to_string(),
            reason,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::plan::bundle::{BUNDLE_SCHEMA_VERSION, BundleArtifact, KeyId, VerityInfo};
    use mvm_contract::plan::types::{ArtifactDigests, InputKind};

    fn artifact(name: &str, role: ArtifactRole, sha256: &str, size_bytes: u64) -> BundleArtifact {
        BundleArtifact {
            name: name.to_string(),
            role,
            path: format!("artifacts/{name}"),
            sha256: sha256.to_string(),
            size_bytes,
        }
    }

    fn manifest(artifacts: Vec<BundleArtifact>, members: Vec<BundleMember>) -> BundleManifest {
        BundleManifest {
            schema_version: BUNDLE_SCHEMA_VERSION,
            publisher: "p".to_string(),
            key_id: KeyId("0".repeat(32)),
            arch: "x86_64".to_string(),
            kernel_version: None,
            profile: None,
            workload_label: None,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            labels: Default::default(),
            artifacts,
            members,
            verity: None,
            resources: None,
        }
    }

    fn sealed() -> BundleSecurityPosture {
        BundleSecurityPosture {
            profile: AgentProfile::SealedProd,
            verity_protected: true,
            requires_auth: true,
            allows_volumes: false,
            allows_egress: false,
        }
    }

    fn with_verity(mut manifest: BundleManifest) -> BundleManifest {
        manifest.verity = Some(VerityInfo {
            roothash: "a".repeat(64),
            sidecar_artifact: "rootfs.verity".to_string(),
        });
        manifest
    }

    #[test]
    fn budget_refuses_an_entry_over_two_gib_before_counting_it() {
        let mut budget = BundleSizeBudget::default();
        let err = budget
            .admit("artifacts/rootfs.ext4", MAX_BUNDLE_ENTRY_BYTES + 1)
            .unwrap_err();
        assert!(matches!(err, BundleVerifyError::EntryTooLarge { .. }));
        budget
            .admit("artifacts/rootfs.ext4", MAX_BUNDLE_ENTRY_BYTES)
            .expect("an entry at the cap is admitted");
    }

    #[test]
    fn budget_refuses_a_total_over_four_gib() {
        let mut budget = BundleSizeBudget::default();
        budget.admit("a", MAX_BUNDLE_ENTRY_BYTES).unwrap();
        budget.admit("b", MAX_BUNDLE_ENTRY_BYTES).unwrap();
        let err = budget.admit("c", 1).unwrap_err();
        assert!(
            matches!(err, BundleVerifyError::BundleTooLarge { total, .. } if total == MAX_BUNDLE_TOTAL_BYTES + 1)
        );
    }

    #[test]
    fn declared_oversized_artifact_is_refused() {
        let m = manifest(
            vec![artifact(
                "rootfs.ext4",
                ArtifactRole::Rootfs,
                "ab",
                MAX_BUNDLE_ENTRY_BYTES + 1,
            )],
            Vec::new(),
        );
        assert!(matches!(
            validate_declarations(&m),
            Err(BundleVerifyError::EntryTooLarge { .. })
        ));
    }

    #[test]
    fn boot_declaration_requires_v4_and_is_unambiguous() {
        let boot = BundleMember::EmbeddedBootAssets {
            manifest_artifact: "image-set.json".into(),
        };
        let mut m = manifest(Vec::new(), vec![boot.clone()]);
        validate_declarations(&m).unwrap();
        m.schema_version = 3;
        assert!(validate_declarations(&m).is_err());
        m.schema_version = 4;
        m.members.push(boot);
        assert!(matches!(
            validate_declarations(&m),
            Err(BundleVerifyError::DuplicateMember {
                class: "embedded_boot_assets"
            })
        ));
        m.members.pop();
        m.members.push(BundleMember::EmbeddedImageSet {
            manifest_artifact: "image-set.json".into(),
        });
        assert!(validate_declarations(&m).is_err());
    }

    #[test]
    fn a_second_posture_is_refused() {
        let m = with_verity(manifest(
            Vec::new(),
            vec![
                BundleMember::SecurityPosture(sealed()),
                BundleMember::SecurityPosture(sealed()),
            ],
        ));
        assert!(matches!(
            validate_declarations(&m),
            Err(BundleVerifyError::DuplicateMember {
                class: "security_posture"
            })
        ));
    }

    #[test]
    fn coherent_sealed_posture_is_accepted() {
        let m = with_verity(manifest(
            Vec::new(),
            vec![BundleMember::SecurityPosture(sealed())],
        ));
        validate_declarations(&m).expect("sealed posture over a verity rootfs");
    }

    #[test]
    fn posture_claiming_verity_without_a_binding_is_malformed() {
        let m = manifest(Vec::new(), vec![BundleMember::SecurityPosture(sealed())]);
        assert!(matches!(
            validate_declarations(&m),
            Err(BundleVerifyError::MalformedPosture { .. })
        ));
    }

    #[test]
    fn posture_denying_a_present_binding_is_malformed() {
        let dev = BundleSecurityPosture {
            profile: AgentProfile::Dev,
            verity_protected: false,
            ..sealed()
        };
        let m = with_verity(manifest(
            Vec::new(),
            vec![BundleMember::SecurityPosture(dev)],
        ));
        assert!(matches!(
            validate_declarations(&m),
            Err(BundleVerifyError::MalformedPosture { .. })
        ));
    }

    #[test]
    fn sealed_prod_without_auth_is_malformed() {
        let posture = BundleSecurityPosture {
            requires_auth: false,
            ..sealed()
        };
        let m = with_verity(manifest(
            Vec::new(),
            vec![BundleMember::SecurityPosture(posture)],
        ));
        assert!(matches!(
            validate_declarations(&m),
            Err(BundleVerifyError::MalformedPosture { .. })
        ));
    }

    #[test]
    fn dev_posture_without_verity_is_accepted() {
        let posture = BundleSecurityPosture {
            profile: AgentProfile::Dev,
            verity_protected: false,
            requires_auth: false,
            allows_volumes: true,
            allows_egress: true,
        };
        let m = manifest(Vec::new(), vec![BundleMember::SecurityPosture(posture)]);
        validate_declarations(&m).expect("dev posture over an unverified rootfs");
    }

    #[test]
    fn cmdline_must_be_bounded_printable_ascii() {
        let check = |cmdline: &str| {
            validate_declarations(&manifest(
                Vec::new(),
                vec![BundleMember::KernelCmdline {
                    cmdline: cmdline.to_string(),
                }],
            ))
        };
        check("console=ttyS0 quiet").expect("ordinary cmdline");
        for bad in [
            String::new(),
            "quiet\ninit=/bin/sh".to_string(),
            "a\0b".to_string(),
            "x".repeat(MAX_KERNEL_CMDLINE_BYTES + 1),
        ] {
            assert!(
                matches!(check(&bad), Err(BundleVerifyError::MalformedCmdline { .. })),
                "{bad:?} must be refused"
            );
        }
    }

    fn provenance(kernel: Option<&str>) -> BuildProvenance {
        BuildProvenance {
            input_kind: InputKind::NixFlake,
            input_ref: ".#app".to_string(),
            lock_digest: None,
            builder_id: None,
            artifacts: ArtifactDigests {
                kernel: kernel.map(str::to_string),
                mvm_init: Some("unrelated".to_string()),
                ..Default::default()
            },
        }
    }

    #[test]
    fn provenance_bound_to_the_bundle_kernel_is_accepted() {
        let m = manifest(
            vec![artifact("vmlinux", ArtifactRole::Kernel, "aa", 1)],
            vec![BundleMember::BuildProvenance(provenance(Some("aa")))],
        );
        validate_declarations(&m).expect("matching kernel digest");
    }

    #[test]
    fn provenance_naming_other_kernel_bytes_is_refused() {
        let m = manifest(
            vec![artifact("vmlinux", ArtifactRole::Kernel, "aa", 1)],
            vec![BundleMember::BuildProvenance(provenance(Some("bb")))],
        );
        assert!(matches!(
            validate_declarations(&m),
            Err(BundleVerifyError::ProvenanceMismatch { artifact, .. }) if artifact == "kernel"
        ));
    }

    #[test]
    fn provenance_naming_an_absent_artifact_is_refused() {
        let m = manifest(
            Vec::new(),
            vec![BundleMember::BuildProvenance(provenance(Some("aa")))],
        );
        assert!(matches!(
            validate_declarations(&m),
            Err(BundleVerifyError::ProvenanceMismatch { .. })
        ));
    }
    fn environment(capabilities: &[&str]) -> EnvironmentDescriptor {
        serde_json::from_value(serde_json::json!({
            "descriptor_version": 1,
            "target": "x86_64-linux",
            "entrypoint": { "argv": ["/usr/bin/app"] },
            "capabilities": capabilities,
        }))
        .expect("environment fixture")
    }

    fn open_dev_posture() -> BundleSecurityPosture {
        BundleSecurityPosture {
            profile: AgentProfile::Dev,
            verity_protected: false,
            requires_auth: true,
            allows_volumes: true,
            allows_egress: true,
        }
    }

    #[test]
    fn environment_inside_its_posture_is_accepted() {
        let m = manifest(
            Vec::new(),
            vec![
                BundleMember::SecurityPosture(open_dev_posture()),
                BundleMember::Environment(environment(&[
                    "egress",
                    "host_volumes",
                    "interactive_terminal",
                ])),
            ],
        );
        validate_declarations(&m).expect("every capability is permitted");
    }

    #[test]
    fn environment_without_capabilities_needs_no_posture() {
        let m = manifest(
            Vec::new(),
            vec![BundleMember::Environment(environment(&[]))],
        );
        validate_declarations(&m).expect("nothing required, nothing to permit");
    }

    #[test]
    fn environment_requires_schema_five() {
        let mut m = manifest(
            Vec::new(),
            vec![BundleMember::Environment(environment(&[]))],
        );
        m.schema_version = 4;
        let err = validate_declarations(&m).unwrap_err();
        assert!(
            matches!(&err, BundleVerifyError::EnvironmentRefused { reason } if reason.contains("schema 5")),
            "{err}"
        );
    }

    #[test]
    fn environment_for_another_arch_is_refused() {
        let mut m = manifest(
            Vec::new(),
            vec![BundleMember::Environment(environment(&[]))],
        );
        m.arch = "aarch64".to_string();
        assert!(matches!(
            validate_declarations(&m),
            Err(BundleVerifyError::EnvironmentRefused { reason }) if reason.contains("aarch64")
        ));
    }

    #[test]
    fn capability_beyond_the_posture_is_refused() {
        let closed = BundleSecurityPosture {
            allows_egress: false,
            ..open_dev_posture()
        };
        let m = manifest(
            Vec::new(),
            vec![
                BundleMember::SecurityPosture(closed),
                BundleMember::Environment(environment(&["egress"])),
            ],
        );
        assert!(matches!(
            validate_declarations(&m),
            Err(BundleVerifyError::EnvironmentRefused { reason }) if reason.contains("egress")
        ));
    }

    #[test]
    fn interactive_terminal_under_sealed_prod_is_refused() {
        let m = with_verity(manifest(
            Vec::new(),
            vec![
                BundleMember::SecurityPosture(sealed()),
                BundleMember::Environment(environment(&["interactive_terminal"])),
            ],
        ));
        assert!(matches!(
            validate_declarations(&m),
            Err(BundleVerifyError::EnvironmentRefused { reason })
                if reason.contains("interactive_terminal")
        ));
    }

    #[test]
    fn a_required_capability_without_any_posture_is_refused() {
        let m = manifest(
            Vec::new(),
            vec![BundleMember::Environment(environment(&["egress"]))],
        );
        assert!(matches!(
            validate_declarations(&m),
            Err(BundleVerifyError::EnvironmentRefused { .. })
        ));
    }

    #[test]
    fn a_structurally_invalid_environment_is_malformed() {
        let mut env = environment(&[]);
        env.descriptor_version = 2;
        let m = manifest(Vec::new(), vec![BundleMember::Environment(env)]);
        assert!(matches!(
            validate_declarations(&m),
            Err(BundleVerifyError::MalformedEnvironment(_))
        ));
    }

    #[test]
    fn a_second_environment_is_refused() {
        let m = manifest(
            Vec::new(),
            vec![
                BundleMember::Environment(environment(&[])),
                BundleMember::Environment(environment(&[])),
            ],
        );
        assert!(matches!(
            validate_declarations(&m),
            Err(BundleVerifyError::DuplicateMember {
                class: "environment"
            })
        ));
    }
}
