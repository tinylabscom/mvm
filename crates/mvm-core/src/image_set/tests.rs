use chrono::{TimeZone, Utc};
use mvm_contract::guest_libc::GuestLibc;
use serde::Serialize;
use serde::de::DeserializeOwned;

use super::*;
use crate::arch::GuestArch;
use crate::kernel_format::KernelFormat;
use crate::packs::{FlakeLockIdentity, Sha256Hex, SourceRevisionIdentity};
use crate::release_trust::{RELEASE_OIDC_ISSUER, accepted_boot_image_identities};

const X86: MemberTarget = MemberTarget::Arch(GuestArch::X86_64);
const ARM: MemberTarget = MemberTarget::Arch(GuestArch::Aarch64);

fn sha(seed: &str) -> Sha256Hex {
    Sha256Hex::from_bytes(seed.as_bytes())
}

fn commit(fill: char) -> GitCommit {
    GitCommit::new(fill.to_string().repeat(40)).unwrap()
}

fn version(value: &str) -> ImageSetVersion {
    ImageSetVersion::new(value).unwrap()
}

fn kernel_format(target: MemberTarget) -> ArtifactFormat {
    match target {
        MemberTarget::Arch(GuestArch::X86_64) => ArtifactFormat::Kernel(KernelFormat::Elf),
        _ => ArtifactFormat::Kernel(KernelFormat::Image),
    }
}

fn artifact(name: &str, format: ArtifactFormat) -> MemberArtifact {
    MemberArtifact {
        name: ArtifactName::new(name).unwrap(),
        format,
        sha256: sha(name),
        size: 4096,
    }
}

fn member(role: ImageSetRole, target: MemberTarget) -> ImageSetMember {
    use GuestDeviceRequirement::{DmVerity, VirtioBlk, VirtioVsock};
    let suffix = match target {
        MemberTarget::Arch(arch) => format!("-{arch}"),
        MemberTarget::ArchIndependent => String::new(),
    };
    let kernel = kernel_format(target);
    let boot = Some(BootProtocol::LinuxDirect);
    let (boot_protocol, artifacts, required_capabilities) = match role {
        ImageSetRole::BuilderVm => (
            boot,
            vec![
                artifact(&format!("builder-vm-vmlinux{suffix}"), kernel),
                artifact(
                    &format!("builder-vm-rootfs{suffix}.ext4"),
                    ArtifactFormat::Ext4,
                ),
            ],
            vec![VirtioVsock, VirtioBlk],
        ),
        ImageSetRole::WorkloadKernel => (
            boot,
            vec![artifact(
                &format!("default-microvm-vmlinux{suffix}"),
                kernel,
            )],
            vec![VirtioVsock],
        ),
        ImageSetRole::WorkloadRootfs => (
            None,
            vec![
                artifact(
                    &format!("default-microvm-rootfs{suffix}.ext4"),
                    ArtifactFormat::Ext4,
                ),
                artifact(
                    &format!("default-microvm-rootfs{suffix}.verity"),
                    ArtifactFormat::VerityHashTree,
                ),
                artifact(
                    &format!("default-microvm-rootfs{suffix}.roothash"),
                    ArtifactFormat::VerityRootHash,
                ),
            ],
            vec![VirtioBlk, DmVerity],
        ),
        ImageSetRole::RuntimeOverlay => (
            None,
            vec![artifact(
                &format!("runtime-overlay{suffix}.tar.gz"),
                ArtifactFormat::TarGz,
            )],
            vec![],
        ),
        ImageSetRole::SdkSidecar(libc) => (
            None,
            vec![artifact(
                &format!("sdk-sidecar{suffix}-{libc}.tar.gz"),
                ArtifactFormat::TarGz,
            )],
            vec![],
        ),
        ImageSetRole::Stage0BootstrapKernel => (
            boot,
            vec![artifact(&format!("stage0-vmlinux{suffix}"), kernel)],
            vec![VirtioVsock],
        ),
        ImageSetRole::QemuWasmSmokePack => (
            None,
            vec![artifact(
                "qemu-wasm-smoke-pack.tar.gz",
                ArtifactFormat::TarGz,
            )],
            vec![],
        ),
    };
    ImageSetMember {
        role,
        target,
        boot_protocol,
        artifacts,
        required_capabilities,
        pack_hash: sha(&format!("pack:{role}:{target}")),
        sbom: crate::packs::SbomReference {
            uri: format!("https://example.test/sbom/{role}/{target}.cdx.json"),
            sha256: sha(&format!("sbom:{role}:{target}")),
        },
    }
}

fn manifest_at(set_version: &str) -> ImageSetManifest {
    ImageSetManifest {
        schema_version: IMAGE_SET_SCHEMA_VERSION,
        set_version: version(set_version),
        issued_at: Utc.with_ymd_and_hms(2026, 9, 16, 0, 0, 0).unwrap(),
        producer: ImageSetProducer {
            repository: RepositorySlug::new("tinylabscom/mvm-images").unwrap(),
            workflow: WorkflowPath::new(".github/workflows/release.yml").unwrap(),
            release_tag: ReleaseTag::new(format!("v{set_version}")).unwrap(),
            source_commit: commit('a'),
        },
        mvm_source_commit: commit('b'),
        compatibility: ImageSetCompatibility {
            guest_agent_protocol: ProtocolRange::new(2, 2).unwrap(),
            builder_cache_contract: 4,
        },
        nix_inputs: NixInputs {
            flake_locks: vec![FlakeLockIdentity {
                reference: "nix/images/builder-vm".to_string(),
                lock_hash: sha("flake.lock"),
            }],
            source_revisions: vec![SourceRevisionIdentity {
                repository: "https://github.com/NixOS/nixpkgs".to_string(),
                revision: "c".repeat(40),
                tree_hash: sha("nixpkgs"),
            }],
        },
        revocation_channel: RevocationChannel::new(
            "https://github.com/tinylabscom/mvm-images/releases/download/revocations/revocations.json",
        )
        .unwrap(),
        supersedes: None,
        members: ImageSetRequirement::current_train()
            .members()
            .iter()
            .map(|required| member(required.role, required.target))
            .collect(),
    }
}

fn manifest() -> ImageSetManifest {
    manifest_at("1.0.0")
}

fn member_mut(
    manifest: &mut ImageSetManifest,
    role: ImageSetRole,
    target: MemberTarget,
) -> &mut ImageSetMember {
    manifest
        .members
        .iter_mut()
        .find(|member| member.role == role && member.target == target)
        .unwrap()
}

fn backend() -> BackendImageSupport {
    BackendImageSupport {
        guest_arches: vec![GuestArch::X86_64, GuestArch::Aarch64],
        boot_protocols: vec![BootProtocol::LinuxDirect],
        artifact_formats: vec![
            ArtifactFormat::Kernel(KernelFormat::Elf),
            ArtifactFormat::Kernel(KernelFormat::Image),
            ArtifactFormat::Ext4,
            ArtifactFormat::VerityHashTree,
            ArtifactFormat::VerityRootHash,
            ArtifactFormat::TarGz,
        ],
        device_capabilities: vec![
            GuestDeviceRequirement::VirtioVsock,
            GuestDeviceRequirement::VirtioBlk,
            GuestDeviceRequirement::DmVerity,
        ],
    }
}

fn host() -> HostProtocolSupport {
    HostProtocolSupport {
        guest_agent_protocol: ProtocolRange::new(2, 3).unwrap(),
        builder_cache_contract: 4,
    }
}

fn digest(manifest: &ImageSetManifest) -> Sha256Hex {
    Sha256Hex::from_bytes(&serde_json::to_vec(manifest).unwrap())
}

fn lock_for(manifest: &ImageSetManifest) -> ImageLock {
    let release_tag = manifest.producer.release_tag.clone();
    ImageLock {
        schema_version: IMAGE_LOCK_SCHEMA_VERSION,
        repository: manifest.producer.repository.clone(),
        manifest_asset: ArtifactName::new("image-set.json").unwrap(),
        manifest_sha256: digest(manifest),
        signing_identity: SigningIdentity {
            workflow: manifest.producer.workflow.clone(),
            tag_ref: TagRef::for_tag(&release_tag),
        },
        release_tag,
    }
}

fn round_trip<T>(value: &T)
where
    T: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug,
{
    let json = serde_json::to_string(value).unwrap();
    let back: T = serde_json::from_str(&json).unwrap();
    assert_eq!(&back, value, "round-trip changed {json}");
}

/// Insert `field` into the JSON object reached by `path` and parse `T` back.
fn parse_with_extra_field<T: DeserializeOwned>(
    value: &impl Serialize,
    path: &[&str],
) -> serde_json::Result<T> {
    let mut json = serde_json::to_value(value).unwrap();
    let mut cursor = &mut json;
    for segment in path {
        cursor = match segment.parse::<usize>() {
            Ok(index) => &mut cursor[index],
            Err(_) => &mut cursor[*segment],
        };
    }
    cursor
        .as_object_mut()
        .unwrap()
        .insert("unexpected".to_string(), serde_json::json!(true));
    serde_json::from_value(json)
}

/// Replace the string at `path` and parse `T` back.
fn parse_with_replaced<T: DeserializeOwned>(
    value: &impl Serialize,
    path: &[&str],
    replacement: serde_json::Value,
) -> serde_json::Result<T> {
    let mut json = serde_json::to_value(value).unwrap();
    let (last, parents) = path.split_last().unwrap();
    let mut cursor = &mut json;
    for segment in parents {
        cursor = match segment.parse::<usize>() {
            Ok(index) => &mut cursor[index],
            Err(_) => &mut cursor[*segment],
        };
    }
    cursor[*last] = replacement;
    serde_json::from_value(json)
}

mod identity {
    use super::*;

    #[test]
    fn image_set_version_keeps_the_published_string() {
        for value in ["0.1.0", "1.0.0-rc.1", "1.0.0+build.7"] {
            assert_eq!(ImageSetVersion::new(value).unwrap().as_str(), value);
        }
    }

    /// The grammar itself is tested with the shared parser; this pins that the
    /// image set reads it strictly and reports its own error.
    #[test]
    fn image_set_version_uses_the_strict_syntax() {
        for value in ["v1.2.3", " 1.2.3", "01.2.3", "1.2.3-01", "1.2"] {
            assert!(
                matches!(
                    ImageSetVersion::new(value),
                    Err(ImageSetIdentityError::InvalidVersion(_))
                ),
                "{value:?} must be refused"
            );
        }
    }

    #[test]
    fn image_set_version_equality_is_exact_but_precedence_ignores_build_metadata() {
        use std::cmp::Ordering::{Equal, Greater, Less};
        assert_ne!(version("1.0.0+a"), version("1.0.0+b"));
        assert_eq!(
            version("1.0.0+a").cmp_precedence(&version("1.0.0+b")),
            Equal
        );
        assert_eq!(version("1.10.0").cmp_precedence(&version("1.9.0")), Greater);
        assert_eq!(
            version("1.0.0-rc.1").cmp_precedence(&version("1.0.0")),
            Less
        );
    }

    #[test]
    fn git_commit_refuses_wrong_length_uppercase_and_non_hex() {
        assert!(GitCommit::new("a".repeat(40)).is_ok());
        for value in [
            "a".repeat(39),
            "a".repeat(41),
            "A".repeat(40),
            "g".repeat(40),
        ] {
            assert!(matches!(
                GitCommit::new(value),
                Err(ImageSetIdentityError::InvalidCommit(_))
            ));
        }
    }

    #[test]
    fn repository_slug_refuses_anything_but_owner_slash_name() {
        for value in ["tinylabscom/mvm-images", "a/b.c_d-e"] {
            assert!(RepositorySlug::new(value).is_ok(), "{value}");
        }
        for value in [
            "mvm-images",
            "a/b/c",
            "/mvm",
            "owner/",
            "-owner/mvm",
            "owner-/mvm",
            "own_er/mvm",
            "owner/..",
            "owner/.",
            "own er/mvm",
            "https://github.com/a/b",
        ] {
            assert!(
                matches!(
                    RepositorySlug::new(value),
                    Err(ImageSetIdentityError::InvalidRepositorySlug(_))
                ),
                "{value:?} must be refused"
            );
        }
    }

    #[test]
    fn workflow_path_must_name_a_workflow_file() {
        for value in [
            ".github/workflows/release.yml",
            ".github/workflows/r-1.yaml",
        ] {
            assert!(WorkflowPath::new(value).is_ok(), "{value}");
        }
        for value in [
            "release.yml",
            ".github/workflows/release.sh",
            ".github/workflows/nested/release.yml",
            ".github/workflows/.yml",
            ".github/workflows/../release.yml",
            "/.github/workflows/release.yml",
        ] {
            assert!(
                matches!(
                    WorkflowPath::new(value),
                    Err(ImageSetIdentityError::InvalidWorkflowPath(_))
                ),
                "{value:?} must be refused"
            );
        }
    }

    #[test]
    fn release_tag_carries_its_version() {
        assert_eq!(
            ReleaseTag::new("v1.2.3").unwrap().version(),
            &version("1.2.3")
        );
        assert_eq!(
            ReleaseTag::new("boot-image/v0.1.0").unwrap().version(),
            &version("0.1.0")
        );
        for value in [
            "",
            "1.2.3",
            "v1.2",
            "images/",
            "latest",
            "images//v1.0.0",
            "a b/v1.0.0",
        ] {
            assert!(
                matches!(
                    ReleaseTag::new(value),
                    Err(ImageSetIdentityError::InvalidReleaseTag(_))
                ),
                "{value:?} must be refused"
            );
        }
    }

    #[test]
    fn tag_ref_accepts_only_a_release_tag_ref() {
        let tag = ReleaseTag::new("boot-image/v0.1.0").unwrap();
        let tag_ref = TagRef::for_tag(&tag);
        assert_eq!(tag_ref.as_str(), "refs/tags/boot-image/v0.1.0");
        assert_eq!(tag_ref.tag(), &tag);
        for value in ["refs/heads/main", "refs/tags/latest", "boot-image/v0.1.0"] {
            assert!(
                matches!(
                    TagRef::new(value),
                    Err(ImageSetIdentityError::InvalidTagRef(_))
                ),
                "{value:?} must be refused"
            );
        }
    }

    #[test]
    fn artifact_name_refuses_paths_and_empty() {
        assert!(ArtifactName::new("builder-vm-rootfs-aarch64.ext4").is_ok());
        for value in ["", ".", "..", "a/b", "a\\b", "a b", "../x"] {
            assert!(
                matches!(
                    ArtifactName::new(value),
                    Err(ImageSetIdentityError::InvalidArtifactName(_))
                ),
                "{value:?} must be refused"
            );
        }
    }

    #[test]
    fn revocation_channel_must_be_an_https_url_with_a_host() {
        assert!(RevocationChannel::new("https://example.test/revocations.json").is_ok());
        for value in [
            "http://example.test/r",
            "https://",
            "https:///r",
            "file:///r",
            "",
        ] {
            assert!(
                matches!(
                    RevocationChannel::new(value),
                    Err(ImageSetIdentityError::InvalidRevocationChannel(_))
                ),
                "{value:?} must be refused"
            );
        }
    }

    #[test]
    fn protocol_range_refuses_zero_and_inverted_bounds() {
        let range = ProtocolRange::new(2, 3).unwrap();
        assert_eq!((range.min(), range.max()), (2, 3));
        for (min, max) in [(0, 1), (3, 2)] {
            assert!(matches!(
                ProtocolRange::new(min, max),
                Err(ImageSetIdentityError::InvalidProtocolRange { .. })
            ));
        }
    }
}

mod serde_shape {
    use super::*;

    #[test]
    fn manifest_round_trips() {
        let mut manifest = manifest_at("1.1.0");
        manifest.supersedes = Some(Supersedes {
            set_version: version("1.0.0"),
            manifest_sha256: sha("previous"),
        });
        round_trip(&manifest);
        round_trip(&self::manifest());
    }

    #[test]
    fn lock_round_trips() {
        round_trip(&lock_for(&manifest()));
    }

    #[test]
    fn member_and_nested_types_round_trip() {
        let manifest = manifest();
        for member in &manifest.members {
            round_trip(member);
            for artifact in &member.artifacts {
                round_trip(artifact);
            }
        }
        round_trip(&manifest.producer);
        round_trip(&manifest.compatibility);
        round_trip(&manifest.nix_inputs);
        round_trip(&Supersedes {
            set_version: version("0.9.0"),
            manifest_sha256: sha("x"),
        });
        round_trip(&lock_for(&manifest).signing_identity);
    }

    #[test]
    fn newtypes_round_trip_as_plain_strings() {
        assert_eq!(
            serde_json::to_string(&version("1.0.0")).unwrap(),
            "\"1.0.0\""
        );
        round_trip(&version("1.0.0-rc.1+b"));
        round_trip(&commit('f'));
        round_trip(&RepositorySlug::new("owner/name").unwrap());
        round_trip(&WorkflowPath::new(".github/workflows/x.yml").unwrap());
        round_trip(&ReleaseTag::new("images/v2.0.0").unwrap());
        round_trip(&TagRef::new("refs/tags/v2.0.0").unwrap());
        round_trip(&ArtifactName::new("a.json").unwrap());
        round_trip(&RevocationChannel::new("https://example.test/r").unwrap());
        round_trip(&ProtocolRange::new(1, 4).unwrap());
    }

    #[test]
    fn closed_enums_round_trip_with_stable_names() {
        let roles = [
            (ImageSetRole::BuilderVm, r#""builder_vm""#),
            (ImageSetRole::WorkloadKernel, r#""workload_kernel""#),
            (ImageSetRole::WorkloadRootfs, r#""workload_rootfs""#),
            (ImageSetRole::RuntimeOverlay, r#""runtime_overlay""#),
            (
                ImageSetRole::SdkSidecar(GuestLibc::Musl),
                r#"{"sdk_sidecar":"musl"}"#,
            ),
            (
                ImageSetRole::Stage0BootstrapKernel,
                r#""stage0_bootstrap_kernel""#,
            ),
            (ImageSetRole::QemuWasmSmokePack, r#""qemu_wasm_smoke_pack""#),
        ];
        for (role, json) in roles {
            assert_eq!(serde_json::to_string(&role).unwrap(), json);
            round_trip(&role);
        }
        assert_eq!(
            serde_json::to_string(&ARM).unwrap(),
            r#"{"arch":"aarch64"}"#
        );
        assert_eq!(
            serde_json::to_string(&MemberTarget::ArchIndependent).unwrap(),
            r#""arch_independent""#
        );
        round_trip(&X86);
        round_trip(&BootProtocol::LinuxDirect);
        assert_eq!(
            serde_json::to_string(&ArtifactFormat::Kernel(KernelFormat::Elf)).unwrap(),
            r#"{"kernel":"elf"}"#
        );
        for format in [
            ArtifactFormat::Kernel(KernelFormat::Image),
            ArtifactFormat::Ext4,
            ArtifactFormat::VerityHashTree,
            ArtifactFormat::VerityRootHash,
            ArtifactFormat::TarGz,
            ArtifactFormat::Text,
            ArtifactFormat::Json,
        ] {
            round_trip(&format);
        }
        for capability in [
            GuestDeviceRequirement::VirtioVsock,
            GuestDeviceRequirement::VirtioBlk,
            GuestDeviceRequirement::DmVerity,
        ] {
            round_trip(&capability);
        }
    }

    #[test]
    fn a_host_named_role_or_target_does_not_parse() {
        assert!(serde_json::from_str::<ImageSetRole>(r#""macos_builder_vm""#).is_err());
        assert!(serde_json::from_str::<MemberTarget>(r#"{"arch":"windows"}"#).is_err());
        assert!(serde_json::from_str::<MemberTarget>(r#""windows""#).is_err());
    }

    #[test]
    fn manifest_refuses_unknown_fields_at_every_level() {
        let manifest = manifest();
        for path in [
            &[][..],
            &["producer"],
            &["compatibility"],
            &["compatibility", "guest_agent_protocol"],
            &["nix_inputs"],
            &["members", "0"],
            &["members", "0", "artifacts", "0"],
        ] {
            let parsed = parse_with_extra_field::<ImageSetManifest>(&manifest, path);
            assert!(parsed.is_err(), "unknown field at {path:?} must be refused");
        }
        let mut superseding = manifest_at("1.1.0");
        superseding.supersedes = Some(Supersedes {
            set_version: version("1.0.0"),
            manifest_sha256: sha("previous"),
        });
        assert!(parse_with_extra_field::<ImageSetManifest>(&superseding, &["supersedes"]).is_err());
    }

    #[test]
    fn lock_refuses_unknown_fields() {
        let lock = lock_for(&manifest());
        assert!(parse_with_extra_field::<ImageLock>(&lock, &[]).is_err());
        assert!(parse_with_extra_field::<ImageLock>(&lock, &["signing_identity"]).is_err());
    }

    #[test]
    fn manifest_refuses_invalid_identities_in_json() {
        let manifest = manifest();
        let cases: [(&[&str], serde_json::Value); 6] = [
            (&["set_version"], serde_json::json!("1.0")),
            (&["mvm_source_commit"], serde_json::json!("abc")),
            (&["producer", "repository"], serde_json::json!("mvm-images")),
            (&["producer", "release_tag"], serde_json::json!("latest")),
            (
                &["compatibility", "guest_agent_protocol"],
                serde_json::json!({"min": 3, "max": 2}),
            ),
            (
                &["members", "0", "artifacts", "0", "size"],
                serde_json::json!(-1),
            ),
        ];
        for (path, replacement) in cases {
            assert!(
                parse_with_replaced::<ImageSetManifest>(&manifest, path, replacement).is_err(),
                "invalid value at {path:?} must be refused"
            );
        }
    }

    #[test]
    fn lock_refuses_a_branch_ref_as_signing_identity() {
        let lock = lock_for(&manifest());
        let parsed = parse_with_replaced::<ImageLock>(
            &lock,
            &["signing_identity", "tag_ref"],
            serde_json::json!("refs/heads/main"),
        );
        assert!(parsed.is_err());
    }
}

mod structure {
    use super::*;

    fn refused(manifest: &ImageSetManifest) -> ImageSetError {
        validate_structure(manifest).unwrap_err()
    }

    #[test]
    fn complete_two_arch_set_passes_every_check() {
        let manifest = manifest();
        validate_structure(&manifest).unwrap();
        require_complete(&manifest, &ImageSetRequirement::current_train()).unwrap();
        check_protocol_compatibility(&manifest, &host()).unwrap();
        check_against_lock(&manifest, &digest(&manifest), &lock_for(&manifest)).unwrap();
        for required in ImageSetRequirement::current_train().members() {
            let arches = match required.target {
                MemberTarget::Arch(arch) => vec![arch],
                MemberTarget::ArchIndependent => vec![GuestArch::X86_64, GuestArch::Aarch64],
            };
            for arch in arches {
                let selected = select_member(&manifest, required.role, arch, &backend()).unwrap();
                assert_eq!(
                    (selected.role, selected.target),
                    (required.role, required.target)
                );
            }
        }
    }

    #[test]
    fn refuses_unsupported_schema_version() {
        let mut manifest = manifest();
        manifest.schema_version = IMAGE_SET_SCHEMA_VERSION + 1;
        assert!(matches!(
            refused(&manifest),
            ImageSetError::UnsupportedSchemaVersion { found, supported }
                if found == IMAGE_SET_SCHEMA_VERSION + 1 && supported == IMAGE_SET_SCHEMA_VERSION
        ));
    }

    #[test]
    fn refuses_a_set_with_no_members() {
        let mut manifest = manifest();
        manifest.members.clear();
        assert!(matches!(refused(&manifest), ImageSetError::NoMembers));
    }

    #[test]
    fn refuses_two_members_for_one_role_and_target() {
        let mut manifest = manifest();
        manifest
            .members
            .push(member(ImageSetRole::WorkloadKernel, ARM));
        assert!(matches!(
            refused(&manifest),
            ImageSetError::DuplicateMember { role: ImageSetRole::WorkloadKernel, target } if target == ARM
        ));
    }

    #[test]
    fn allows_one_role_on_two_targets() {
        let manifest = manifest();
        let kernels = manifest
            .members
            .iter()
            .filter(|member| member.role == ImageSetRole::WorkloadKernel)
            .count();
        assert_eq!(kernels, 2);
        validate_structure(&manifest).unwrap();
    }

    #[test]
    fn refuses_a_repeated_artifact_name_within_a_member() {
        let mut manifest = manifest();
        let rootfs = member_mut(&mut manifest, ImageSetRole::WorkloadRootfs, X86);
        rootfs.artifacts[1].name = rootfs.artifacts[0].name.clone();
        assert!(matches!(
            refused(&manifest),
            ImageSetError::DuplicateArtifactName { role: ImageSetRole::WorkloadRootfs, name, .. }
                if name.as_str() == "default-microvm-rootfs-x86_64.ext4"
        ));
    }

    #[test]
    fn refuses_a_member_with_no_artifacts() {
        let mut manifest = manifest();
        member_mut(&mut manifest, ImageSetRole::RuntimeOverlay, ARM)
            .artifacts
            .clear();
        assert!(matches!(
            refused(&manifest),
            ImageSetError::MemberHasNoArtifacts { role: ImageSetRole::RuntimeOverlay, target }
                if target == ARM
        ));
    }

    #[test]
    fn refuses_a_zero_size_artifact() {
        let mut manifest = manifest();
        member_mut(&mut manifest, ImageSetRole::BuilderVm, X86).artifacts[1].size = 0;
        assert!(matches!(
            refused(&manifest),
            ImageSetError::ZeroSizeArtifact { role: ImageSetRole::BuilderVm, name, .. }
                if name.as_str() == "builder-vm-rootfs-x86_64.ext4"
        ));
    }

    #[test]
    fn refuses_a_bootable_role_without_a_boot_protocol() {
        for role in [
            ImageSetRole::BuilderVm,
            ImageSetRole::WorkloadKernel,
            ImageSetRole::Stage0BootstrapKernel,
        ] {
            let mut manifest = manifest();
            member_mut(&mut manifest, role, ARM).boot_protocol = None;
            assert!(
                matches!(
                    refused(&manifest),
                    ImageSetError::MissingBootProtocol { role: refused_role, .. } if refused_role == role
                ),
                "{role}"
            );
        }
    }

    #[test]
    fn refuses_a_boot_protocol_on_a_non_bootable_role() {
        let mut manifest = manifest();
        member_mut(&mut manifest, ImageSetRole::WorkloadRootfs, ARM).boot_protocol =
            Some(BootProtocol::LinuxDirect);
        assert!(matches!(
            refused(&manifest),
            ImageSetError::UnexpectedBootProtocol {
                role: ImageSetRole::WorkloadRootfs,
                ..
            }
        ));
    }

    #[test]
    fn refuses_an_arch_bound_role_published_as_arch_independent() {
        let mut manifest = manifest();
        member_mut(&mut manifest, ImageSetRole::WorkloadKernel, X86).target =
            MemberTarget::ArchIndependent;
        assert!(matches!(
            refused(&manifest),
            ImageSetError::TargetNotAllowedForRole {
                role: ImageSetRole::WorkloadKernel,
                target: MemberTarget::ArchIndependent
            }
        ));
    }

    #[test]
    fn refuses_the_arch_independent_smoke_pack_bound_to_an_arch() {
        let mut manifest = manifest();
        member_mut(
            &mut manifest,
            ImageSetRole::QemuWasmSmokePack,
            MemberTarget::ArchIndependent,
        )
        .target = X86;
        assert!(matches!(
            refused(&manifest),
            ImageSetError::TargetNotAllowedForRole { role: ImageSetRole::QemuWasmSmokePack, target }
                if target == X86
        ));
    }

    #[test]
    fn refuses_an_sdk_sidecar_for_an_unknown_libc() {
        let mut manifest = manifest();
        member_mut(
            &mut manifest,
            ImageSetRole::SdkSidecar(GuestLibc::Musl),
            X86,
        )
        .role = ImageSetRole::SdkSidecar(GuestLibc::Unknown);
        assert!(matches!(
            refused(&manifest),
            ImageSetError::UnknownSidecarLibc { target } if target == X86
        ));
    }

    #[test]
    fn refuses_a_release_tag_naming_another_version() {
        let mut manifest = manifest();
        manifest.producer.release_tag = ReleaseTag::new("v1.0.1").unwrap();
        assert!(matches!(
            refused(&manifest),
            ImageSetError::ReleaseTagVersionMismatch { set_version, release_tag }
                if set_version.as_str() == "1.0.0" && release_tag.as_str() == "v1.0.1"
        ));
    }

    #[test]
    fn accepts_superseding_an_older_set() {
        let mut manifest = manifest_at("1.1.0");
        manifest.supersedes = Some(Supersedes {
            set_version: version("1.0.0"),
            manifest_sha256: sha("previous"),
        });
        validate_structure(&manifest).unwrap();
    }

    #[test]
    fn refuses_superseding_a_set_that_is_not_older() {
        for superseded in ["1.0.0", "1.0.1", "1.0.0+rebuild"] {
            let mut manifest = manifest();
            manifest.supersedes = Some(Supersedes {
                set_version: version(superseded),
                manifest_sha256: sha("previous"),
            });
            assert!(
                matches!(refused(&manifest), ImageSetError::SupersedesNotOlder { .. }),
                "{superseded}"
            );
        }
    }

    #[test]
    fn refuses_a_set_without_a_nix_lock_digest() {
        let mut manifest = manifest();
        manifest.nix_inputs.flake_locks.clear();
        assert!(matches!(refused(&manifest), ImageSetError::MissingNixLock));
    }
}

mod completeness {
    use super::*;

    #[test]
    fn current_train_requires_every_role_on_both_arches_plus_the_smoke_pack() {
        let requirement = ImageSetRequirement::current_train();
        let members = requirement.members();
        assert_eq!(members.len(), 15);
        for arch in [X86, ARM] {
            for role in [
                ImageSetRole::BuilderVm,
                ImageSetRole::WorkloadKernel,
                ImageSetRole::WorkloadRootfs,
                ImageSetRole::RuntimeOverlay,
                ImageSetRole::SdkSidecar(GuestLibc::Glibc),
                ImageSetRole::SdkSidecar(GuestLibc::Musl),
                ImageSetRole::Stage0BootstrapKernel,
            ] {
                assert!(members.contains(&RequiredMember { role, target: arch }));
            }
        }
        assert!(members.contains(&RequiredMember {
            role: ImageSetRole::QemuWasmSmokePack,
            target: MemberTarget::ArchIndependent,
        }));
    }

    #[test]
    fn refuses_a_partial_set_and_names_every_missing_member() {
        let mut manifest = manifest();
        manifest.members.retain(|member| {
            !(member.role == ImageSetRole::BuilderVm && member.target == ARM
                || member.role == ImageSetRole::QemuWasmSmokePack)
        });
        let error = require_complete(&manifest, &ImageSetRequirement::current_train()).unwrap_err();
        let ImageSetError::Incomplete { missing } = &error else {
            panic!("expected Incomplete, got {error:?}");
        };
        assert_eq!(
            missing,
            &vec![
                RequiredMember {
                    role: ImageSetRole::BuilderVm,
                    target: ARM,
                },
                RequiredMember {
                    role: ImageSetRole::QemuWasmSmokePack,
                    target: MemberTarget::ArchIndependent,
                },
            ]
        );
        let message = error.to_string();
        assert!(message.contains("builder_vm/aarch64"), "{message}");
        assert!(
            message.contains("qemu_wasm_smoke_pack/arch_independent"),
            "{message}"
        );
    }

    #[test]
    fn a_custom_requirement_accepts_a_set_that_covers_it() {
        let manifest = manifest();
        let requirement = ImageSetRequirement::new(vec![RequiredMember {
            role: ImageSetRole::WorkloadKernel,
            target: X86,
        }]);
        require_complete(&manifest, &requirement).unwrap();
    }
}

mod protocol {
    use super::*;

    fn with_host_range(min: u32, max: u32) -> HostProtocolSupport {
        HostProtocolSupport {
            guest_agent_protocol: ProtocolRange::new(min, max).unwrap(),
            ..host()
        }
    }

    #[test]
    fn accepts_an_overlapping_guest_agent_range() {
        let manifest = manifest();
        for (min, max) in [(2, 2), (1, 2), (2, 9), (1, 9)] {
            check_protocol_compatibility(&manifest, &with_host_range(min, max)).unwrap();
        }
    }

    #[test]
    fn refuses_a_guest_agent_range_that_does_not_overlap() {
        let manifest = manifest();
        for (min, max) in [(1, 1), (3, 5)] {
            let error =
                check_protocol_compatibility(&manifest, &with_host_range(min, max)).unwrap_err();
            assert!(
                matches!(
                    error,
                    ImageSetError::GuestAgentProtocolDisjoint { set, host }
                        if (set.min(), set.max()) == (2, 2) && (host.min(), host.max()) == (min, max)
                ),
                "{min}..={max}"
            );
        }
    }

    #[test]
    fn refuses_a_builder_cache_contract_that_is_not_equal() {
        let manifest = manifest();
        for contract in [3, 5] {
            let host = HostProtocolSupport {
                builder_cache_contract: contract,
                ..host()
            };
            assert!(matches!(
                check_protocol_compatibility(&manifest, &host),
                Err(ImageSetError::BuilderCacheContractMismatch { set: 4, host }) if host == contract
            ));
        }
    }
}

mod selection {
    use super::*;

    #[test]
    fn selects_the_member_for_the_requested_arch() {
        let manifest = manifest();
        for arch in [GuestArch::X86_64, GuestArch::Aarch64] {
            let selected =
                select_member(&manifest, ImageSetRole::WorkloadKernel, arch, &backend()).unwrap();
            assert_eq!(selected.target, MemberTarget::Arch(arch));
        }
    }

    #[test]
    fn refuses_an_arch_the_backend_cannot_run() {
        let manifest = manifest();
        let backend = BackendImageSupport {
            guest_arches: vec![GuestArch::Aarch64],
            ..backend()
        };
        assert!(matches!(
            select_member(
                &manifest,
                ImageSetRole::WorkloadKernel,
                GuestArch::X86_64,
                &backend
            ),
            Err(ImageSetError::ArchitectureUnsupportedByBackend {
                arch: GuestArch::X86_64
            })
        ));
    }

    #[test]
    fn refuses_a_role_published_only_for_another_arch() {
        let mut manifest = manifest();
        manifest
            .members
            .retain(|member| !(member.role == ImageSetRole::BuilderVm && member.target == X86));
        let error = select_member(
            &manifest,
            ImageSetRole::BuilderVm,
            GuestArch::X86_64,
            &backend(),
        )
        .unwrap_err();
        assert!(matches!(
            &error,
            ImageSetError::WrongArchitecture { role: ImageSetRole::BuilderVm, requested: GuestArch::X86_64, available }
                if available == &vec![ARM]
        ));
    }

    #[test]
    fn refuses_a_role_absent_from_the_set() {
        let mut manifest = manifest();
        manifest
            .members
            .retain(|member| member.role != ImageSetRole::Stage0BootstrapKernel);
        assert!(matches!(
            select_member(
                &manifest,
                ImageSetRole::Stage0BootstrapKernel,
                GuestArch::Aarch64,
                &backend()
            ),
            Err(ImageSetError::MemberNotFound {
                role: ImageSetRole::Stage0BootstrapKernel
            })
        ));
    }

    #[test]
    fn refuses_a_boot_protocol_the_backend_does_not_speak() {
        let manifest = manifest();
        let backend = BackendImageSupport {
            boot_protocols: vec![],
            ..backend()
        };
        assert!(matches!(
            select_member(
                &manifest,
                ImageSetRole::WorkloadKernel,
                GuestArch::Aarch64,
                &backend
            ),
            Err(ImageSetError::UnsupportedBootProtocol {
                role: ImageSetRole::WorkloadKernel,
                protocol: BootProtocol::LinuxDirect
            })
        ));
        // A non-bootable role carries no protocol, so the same backend can still
        // take it.
        select_member(
            &manifest,
            ImageSetRole::RuntimeOverlay,
            GuestArch::Aarch64,
            &backend,
        )
        .unwrap();
    }

    #[test]
    fn refuses_an_artifact_format_the_backend_cannot_load() {
        let manifest = manifest();
        let backend = BackendImageSupport {
            artifact_formats: backend()
                .artifact_formats
                .into_iter()
                .filter(|format| *format != ArtifactFormat::Kernel(KernelFormat::Image))
                .collect(),
            ..backend()
        };
        assert!(matches!(
            select_member(&manifest, ImageSetRole::WorkloadKernel, GuestArch::Aarch64, &backend),
            Err(ImageSetError::UnsupportedArtifactFormat {
                role: ImageSetRole::WorkloadKernel,
                artifact,
                format: ArtifactFormat::Kernel(KernelFormat::Image),
            }) if artifact.as_str() == "default-microvm-vmlinux-aarch64"
        ));
        select_member(
            &manifest,
            ImageSetRole::WorkloadKernel,
            GuestArch::X86_64,
            &backend,
        )
        .unwrap();
    }

    #[test]
    fn refuses_a_member_needing_a_device_the_backend_lacks() {
        let manifest = manifest();
        let backend = BackendImageSupport {
            device_capabilities: vec![
                GuestDeviceRequirement::VirtioVsock,
                GuestDeviceRequirement::VirtioBlk,
            ],
            ..backend()
        };
        assert!(matches!(
            select_member(
                &manifest,
                ImageSetRole::WorkloadRootfs,
                GuestArch::X86_64,
                &backend
            ),
            Err(ImageSetError::MissingDeviceCapability {
                role: ImageSetRole::WorkloadRootfs,
                capability: GuestDeviceRequirement::DmVerity,
            })
        ));
    }
}

mod lock {
    use super::*;

    #[test]
    fn refuses_a_tampered_manifest() {
        let manifest = manifest();
        let lock = lock_for(&manifest);
        let mut tampered = manifest.clone();
        member_mut(&mut tampered, ImageSetRole::WorkloadKernel, X86).artifacts[0].sha256 =
            sha("evil kernel");
        let actual = digest(&tampered);
        assert!(matches!(
            check_against_lock(&tampered, &actual, &lock),
            Err(ImageSetError::ManifestDigestMismatch { pinned, actual: found })
                if pinned == lock.manifest_sha256 && found == actual
        ));
    }

    #[test]
    fn refuses_a_replayed_older_set_against_a_lock_pinning_the_newer_one() {
        let older = manifest_at("1.0.0");
        let mut newer = manifest_at("1.1.0");
        newer.supersedes = Some(Supersedes {
            set_version: older.set_version.clone(),
            manifest_sha256: digest(&older),
        });
        validate_structure(&older).unwrap();
        validate_structure(&newer).unwrap();
        let lock = lock_for(&newer);
        assert!(matches!(
            check_against_lock(&older, &digest(&older), &lock),
            Err(ImageSetError::ManifestDigestMismatch { .. })
        ));
    }

    #[test]
    fn refuses_a_manifest_from_another_repository() {
        let manifest = manifest();
        let mut lock = lock_for(&manifest);
        lock.repository = RepositorySlug::new("attacker/mvm-images").unwrap();
        assert!(matches!(
            check_against_lock(&manifest, &digest(&manifest), &lock),
            Err(ImageSetError::RepositoryMismatch { pinned, produced })
                if pinned.as_str() == "attacker/mvm-images" && produced.as_str() == "tinylabscom/mvm-images"
        ));
    }

    #[test]
    fn refuses_a_manifest_from_another_workflow() {
        let manifest = manifest();
        let mut lock = lock_for(&manifest);
        lock.signing_identity.workflow = WorkflowPath::new(".github/workflows/other.yml").unwrap();
        assert!(matches!(
            check_against_lock(&manifest, &digest(&manifest), &lock),
            Err(ImageSetError::WorkflowMismatch { .. })
        ));
    }

    #[test]
    fn refuses_a_manifest_from_another_release_tag() {
        let manifest = manifest();
        let mut lock = lock_for(&manifest);
        lock.release_tag = ReleaseTag::new("images/v1.0.0").unwrap();
        lock.signing_identity.tag_ref = TagRef::for_tag(&lock.release_tag);
        assert!(matches!(
            check_against_lock(&manifest, &digest(&manifest), &lock),
            Err(ImageSetError::ReleaseTagMismatch { pinned, produced })
                if pinned.as_str() == "images/v1.0.0" && produced.as_str() == "v1.0.0"
        ));
    }

    #[test]
    fn refuses_a_signing_ref_for_another_tag() {
        let manifest = manifest();
        let mut lock = lock_for(&manifest);
        lock.signing_identity.tag_ref = TagRef::new("refs/tags/v0.9.0").unwrap();
        assert!(matches!(
            check_against_lock(&manifest, &digest(&manifest), &lock),
            Err(ImageSetError::SigningRefMismatch { tag_ref, release_tag })
                if tag_ref.as_str() == "refs/tags/v0.9.0" && release_tag.as_str() == "v1.0.0"
        ));
    }

    #[test]
    fn refuses_a_set_version_that_does_not_match_the_lock_tag() {
        let mut manifest = manifest();
        manifest.set_version = version("1.0.1");
        let lock = lock_for(&manifest);
        assert!(matches!(
            check_against_lock(&manifest, &digest(&manifest), &lock),
            Err(ImageSetError::SetVersionMismatch { set_version, tag_version })
                if set_version.as_str() == "1.0.1" && tag_version.as_str() == "1.0.0"
        ));
    }

    #[test]
    fn refuses_an_unsupported_lock_schema_version() {
        let manifest = manifest();
        let mut lock = lock_for(&manifest);
        lock.schema_version = 0;
        assert!(matches!(
            check_against_lock(&manifest, &digest(&manifest), &lock),
            Err(ImageSetError::UnsupportedLockSchemaVersion { found: 0, .. })
        ));
    }

    #[test]
    fn lock_trust_root_matches_the_release_identity_shape() {
        let lock = ImageLock {
            schema_version: IMAGE_LOCK_SCHEMA_VERSION,
            repository: RepositorySlug::new("tinylabscom/mvm").unwrap(),
            release_tag: ReleaseTag::new("boot-image/v0.1.0").unwrap(),
            manifest_asset: ArtifactName::new("image-set.json").unwrap(),
            manifest_sha256: sha("m"),
            signing_identity: SigningIdentity {
                workflow: WorkflowPath::new(".github/workflows/release-boot-image.yml").unwrap(),
                tag_ref: TagRef::new("refs/tags/boot-image/v0.1.0").unwrap(),
            },
        };
        let trust = lock.keyless_trust();
        assert_eq!(trust.issuer, RELEASE_OIDC_ISSUER);
        assert_eq!(
            trust.accepted_identities,
            accepted_boot_image_identities("0.1.0")
        );
    }
}
