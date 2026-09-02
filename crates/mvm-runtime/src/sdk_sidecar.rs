//! Deciding, resolving, and shaping the optional SDK-sidecar attachment.
//!
//! The glibc host-services cdylib the language SDKs `dlopen` is not in the base
//! rootfs and not in the static-musl runtime overlay. Workloads that were
//! admitted to call an SDK-served host service get it as their own read-only
//! disk instead — and *only* those workloads, decided from the signed plan's
//! host-service bindings.
//!
//! This module owns the decision and the attachment shape so every driver
//! reaches one contract rather than each launch path inventing its own. The
//! host-side fail-closed gate that re-checks the result against the admitted
//! plan lives with the rest of admission in `mvm_hostd::plan_admission`.

use anyhow::{Context, Result};

/// One resolved SDK-sidecar attachment: the plan grant that authorizes it and
/// the launch-config volume that realizes it.
///
/// Both halves are produced together and from the same resolved artifact so the
/// signed plan and the launch config can never disagree about which bytes are
/// attached — the admission gate re-checks exactly that.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdkSidecarAttachment {
    /// The host-fs grant to bake into the signed plan.
    pub grant: mvm_core::plan::HostShareGrant,
    /// The read-only disk volume to attach to the launch config.
    pub volume: mvm_core::vm_backend::VmVolume,
    /// The resolved artifact's lowercase-hex sha256, for the audit label.
    pub image_sha256: String,
    /// The resolved artifact's version, for the audit label.
    pub version: String,
}

/// Build the plan grant + launch volume for a verified sidecar artifact.
///
/// Split out from resolution so the mapping from artifact to attachment shape is
/// unit-testable without a populated cache.
pub fn sdk_sidecar_attachment_for(
    artifact: &mvm_fs::sdk_sidecar::SdkSidecarArtifact,
) -> SdkSidecarAttachment {
    let host = artifact.image.display().to_string();
    let guest = mvm_core::plan::SDK_SIDECAR_GUEST_PATH.to_string();
    SdkSidecarAttachment {
        grant: mvm_core::plan::HostShareGrant {
            tag: SDK_SIDECAR_SHARE_TAG.to_string(),
            host_path: host.clone(),
            guest_path: guest.clone(),
            kind: mvm_core::plan::ShareKind::Disk,
            read_only: true,
            encrypted: false,
        },
        volume: mvm_core::vm_backend::VmVolume {
            materialized_image: None,
            volume_label: None,
            host,
            guest,
            size: String::new(),
            read_only: true,
            kind: mvm_core::vm_backend::VmVolumeKind::Disk,
            encrypted: false,
        },
        image_sha256: artifact.image_sha256.clone(),
        version: artifact.version.clone(),
    }
}

/// Share tag recorded on the sidecar's plan grant. Distinct from the `uvol{idx}`
/// tags user `--volume` grants carry, so an audit reader can tell a
/// host-resolved sidecar from a user-requested share at a glance.
pub const SDK_SIDECAR_SHARE_TAG: &str = "sdk-sidecar";

/// Resolve the SDK sidecar for `services`, or `None` when no bound host service
/// needs it.
///
/// Fails closed: when a binding does require the sidecar and the artifact is
/// missing, drifted, corrupt, or carries no cdylib, this returns `Err` with a
/// non-secret message naming the binding that demanded it and how to populate
/// the cache. There is no degraded attach — a workload admitted to call a host
/// service must not boot into a `dlopen` failure it cannot act on.
pub fn resolve_sdk_sidecar_attachment(
    services: &[mvm_contract::protocol::broker::ServiceId],
    resolver: &mvm_fs::sdk_sidecar::SdkSidecarResolver,
    arch: mvm_core::arch::GuestArch,
    libc: mvm_contract::guest_libc::GuestLibc,
) -> Result<Option<SdkSidecarAttachment>> {
    if !mvm_core::plan::sdk_sidecar_required_for(services) {
        return Ok(None);
    }
    let bound: Vec<&str> = mvm_core::plan::sdk_host_services_in(services)
        .iter()
        .map(|s| s.as_str())
        .collect();
    if libc == mvm_contract::guest_libc::GuestLibc::Unknown {
        anyhow::bail!(
            "this workload binds SDK host service(s) [{}], which are delivered by a shared \
             object built for one C library, but the guest's libc is unknown. The cdylib is \
             loaded with `dlopen`, and a process under one libc cannot load an object built \
             for the other, so attaching on a guess would fail inside the guest as a \
             relocation error instead of here. Use a runtime or image whose libc is known, \
             or drop the host-service binding.",
            bound.join(", "),
        );
    }
    let layout = resolver.layout(&arch.to_string(), libc);
    let artifact = resolver.resolve(&arch.to_string(), libc).with_context(|| {
        format!(
            "this workload binds SDK host service(s) [{}], which need the {libc} SDK sidecar \
             mounted read-only at {}. Populate {} from a source checkout with: \
             mvmctl build sdk-sidecar build",
            bound.join(", "),
            mvm_core::plan::SDK_SIDECAR_GUEST_PATH,
            layout.artifact_dir.display(),
        )
    })?;
    let attachment = sdk_sidecar_attachment_for(&artifact);
    tracing::info!(
        sdk_sidecar_version = %attachment.version,
        sdk_sidecar_sha256 = %attachment.image_sha256,
        sdk_host_services = %bound.join(","),
        "SDK sidecar attached read-only"
    );
    Ok(Some(attachment))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::protocol::broker::ServiceId;
    use mvm_core::arch::GuestArch;
    use mvm_fs::sdk_sidecar::{
        SDK_SIDECAR_IMAGE_FILE, SDK_SIDECAR_VERSION_FILE, SdkSidecarLayout, SdkSidecarResolver,
    };
    use sha2::{Digest, Sha256};

    fn svc(raw: &str) -> ServiceId {
        ServiceId::parse(raw).expect("fixture service id")
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    /// A valid sidecar ext4 fixture carrying the cdylib the SDKs load, built
    /// with the in-repo pure-Rust writer (no `mkfs`).
    fn sidecar_ext4_bytes() -> Vec<u8> {
        use mvm_fs::ext4::Node;
        let nodes = vec![
            Node::Dir {
                path: "/lib".into(),
                mode: 0o555,
                xattrs: Vec::new(),
            },
            Node::File {
                path: "/lib/libmvm_host_services.so".into(),
                mode: 0o555,
                data: mvm_fs::elf::test_fixture::shared_object(&[
                    "libgcc_s.so.1",
                    mvm_contract::guest_libc::GuestLibc::Musl
                        .libc_soname()
                        .expect("a fixture names a real libc"),
                ]),
                xattrs: Vec::new(),
            },
        ];
        mvm_fs::ext4::build_image(nodes).expect("build sidecar ext4 fixture")
    }

    fn seed_sidecar_cache(cache: &std::path::Path, version: &str, arch: GuestArch) {
        let layout = SdkSidecarLayout::under(
            cache,
            version,
            &arch.to_string(),
            mvm_contract::guest_libc::GuestLibc::Musl,
        );
        std::fs::create_dir_all(&layout.artifact_dir).unwrap();
        let image = sidecar_ext4_bytes();
        let version_text = format!("{version}\n");
        std::fs::write(&layout.image, &image).unwrap();
        std::fs::write(&layout.version_file, &version_text).unwrap();
        std::fs::write(
            &layout.checksum_manifest_file,
            format!(
                "{}  {SDK_SIDECAR_IMAGE_FILE}\n{}  {SDK_SIDECAR_VERSION_FILE}\n",
                sha256_hex(&image),
                sha256_hex(version_text.as_bytes()),
            ),
        )
        .unwrap();
    }

    #[test]
    fn no_sdk_binding_resolves_no_attachment() {
        let dir = tempfile::tempdir().unwrap();
        let resolver = SdkSidecarResolver::new(dir.path().to_path_buf(), "1.2.3".into());
        // A cold cache is fine here: nothing needs the sidecar, so the resolver
        // is never consulted.
        assert_eq!(
            resolve_sdk_sidecar_attachment(
                &[],
                &resolver,
                GuestArch::host(),
                mvm_contract::guest_libc::GuestLibc::Musl
            )
            .unwrap(),
            None
        );
        assert_eq!(
            resolve_sdk_sidecar_attachment(
                &[svc("broker.v1"), svc("host.other.v1")],
                &resolver,
                GuestArch::host(),
                mvm_contract::guest_libc::GuestLibc::Musl,
            )
            .unwrap(),
            None,
            "an unrelated binding must not attach the glibc sidecar"
        );
    }

    #[test]
    fn sdk_binding_attaches_the_sidecar_read_only_at_the_contract_path() {
        let dir = tempfile::tempdir().unwrap();
        let arch = GuestArch::host();
        seed_sidecar_cache(dir.path(), "1.2.3", arch);
        let resolver = SdkSidecarResolver::new(dir.path().to_path_buf(), "1.2.3".into());

        let attached = resolve_sdk_sidecar_attachment(
            &[svc("host.audit.v1")],
            &resolver,
            arch,
            mvm_contract::guest_libc::GuestLibc::Musl,
        )
        .expect("a seeded cache resolves")
        .expect("an SDK binding must attach the sidecar");

        assert!(attached.volume.read_only, "the sidecar attaches read-only");
        assert_eq!(
            attached.volume.kind,
            mvm_core::vm_backend::VmVolumeKind::Disk
        );
        assert_eq!(
            attached.volume.guest,
            mvm_core::plan::SDK_SIDECAR_GUEST_PATH
        );
        assert!(!attached.volume.encrypted);
        assert_eq!(attached.version, "1.2.3");
        assert_eq!(attached.image_sha256.len(), 64);

        // The plan grant and the launch volume describe the same attachment, so
        // the admitted-shares gate accepts it.
        assert_eq!(attached.grant.host_path, attached.volume.host);
        assert_eq!(attached.grant.guest_path, attached.volume.guest);
        assert!(attached.grant.read_only);
        assert_eq!(attached.grant.kind, mvm_core::plan::ShareKind::Disk);
        assert_eq!(attached.grant.tag, SDK_SIDECAR_SHARE_TAG);
    }

    #[test]
    fn every_sdk_host_service_attaches_the_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let arch = GuestArch::host();
        seed_sidecar_cache(dir.path(), "1.2.3", arch);
        let resolver = SdkSidecarResolver::new(dir.path().to_path_buf(), "1.2.3".into());
        for service in mvm_core::plan::SDK_HOST_SERVICES {
            assert!(
                resolve_sdk_sidecar_attachment(
                    &[svc(service)],
                    &resolver,
                    arch,
                    mvm_contract::guest_libc::GuestLibc::Musl
                )
                .unwrap()
                .is_some(),
                "{service} must attach the sidecar"
            );
        }
    }

    #[test]
    fn a_required_but_missing_sidecar_fails_closed_with_an_actionable_message() {
        let dir = tempfile::tempdir().unwrap();
        let resolver = SdkSidecarResolver::new(dir.path().to_path_buf(), "1.2.3".into());
        let err = resolve_sdk_sidecar_attachment(
            &[svc("host.secrets.v1")],
            &resolver,
            GuestArch::host(),
            mvm_contract::guest_libc::GuestLibc::Musl,
        )
        .expect_err("a cold cache must refuse a sidecar-requiring workload");
        let rendered = format!("{err:#}");
        assert!(rendered.contains("host.secrets.v1"), "{rendered}");
        assert!(
            rendered.contains("mvmctl build sdk-sidecar build"),
            "{rendered}"
        );
        // The cache path the operator has to populate is named, not implied.
        assert!(rendered.contains("sdk-sidecar/1.2.3/"), "{rendered}");
        assert!(
            rendered.contains("SDK sidecar artifact incomplete"),
            "{rendered}"
        );
    }

    #[test]
    fn a_tampered_sidecar_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let arch = GuestArch::host();
        seed_sidecar_cache(dir.path(), "1.2.3", arch);
        let layout = SdkSidecarLayout::under(
            dir.path(),
            "1.2.3",
            &arch.to_string(),
            mvm_contract::guest_libc::GuestLibc::Musl,
        );
        let mut image = std::fs::read(&layout.image).unwrap();
        let last = image.len() - 1;
        image[last] ^= 0xff;
        std::fs::write(&layout.image, &image).unwrap();

        let resolver = SdkSidecarResolver::new(dir.path().to_path_buf(), "1.2.3".into());
        let err = resolve_sdk_sidecar_attachment(
            &[svc("host.time.v1")],
            &resolver,
            arch,
            mvm_contract::guest_libc::GuestLibc::Musl,
        )
        .expect_err("a byte-flipped sidecar must refuse the launch");
        assert!(format!("{err:#}").contains("integrity mismatch"), "{err:#}");
    }

    #[test]
    fn an_incompatible_sidecar_version_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let arch = GuestArch::host();
        seed_sidecar_cache(dir.path(), "1.2.3", arch);
        // The running build wants 9.9.9; only 1.2.3 was ever cached.
        let resolver = SdkSidecarResolver::new(dir.path().to_path_buf(), "9.9.9".into());
        assert!(
            resolve_sdk_sidecar_attachment(
                &[svc("host.cost.v1")],
                &resolver,
                arch,
                mvm_contract::guest_libc::GuestLibc::Musl
            )
            .is_err(),
            "a version-mismatched sidecar must refuse the launch"
        );
    }
}
