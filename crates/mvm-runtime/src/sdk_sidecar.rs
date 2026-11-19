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
            content_sha256: None,
            include: Vec::new(),
            exclude: Vec::new(),
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
            share_include: Vec::new(),
            share_exclude: Vec::new(),
        },
        image_sha256: artifact.image_sha256.clone(),
        version: artifact.version.clone(),
    }
}

/// Share tag recorded on the sidecar's plan grant. Distinct from the `uvol{idx}`
/// tags user `--volume` grants carry, so an audit reader can tell a
/// host-resolved sidecar from a user-requested share at a glance.
pub const SDK_SIDECAR_SHARE_TAG: &str = "sdk-sidecar";

/// Immutable SDK artifact identity; mount paths and permissions are never caller-supplied.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SdkSidecarPin {
    pub version: String,
    pub arch: mvm_core::arch::GuestArch,
    pub libc: mvm_contract::guest_libc::GuestLibc,
    pub image_sha256: mvm_contract::assurance::Sha256Digest,
}

impl SdkSidecarPin {
    /// Capture the identity of an attachment resolved before signing the plan.
    pub fn from_attachment(
        attachment: &SdkSidecarAttachment,
        arch: mvm_core::arch::GuestArch,
        libc: mvm_contract::guest_libc::GuestLibc,
    ) -> Result<Self> {
        anyhow::ensure!(
            attachment.grant.content_sha256.as_ref() == Some(&attachment.image_sha256),
            "SDK sidecar attachment must pin its content before signing"
        );
        Ok(Self {
            version: attachment.version.clone(),
            arch,
            libc,
            image_sha256: mvm_contract::assurance::Sha256Digest::parse(format!(
                "sha256:{}",
                attachment.image_sha256
            ))?,
        })
    }

    /// Re-resolve exactly pinned bytes. This conveys no attachment permission.
    pub fn resolve_exact(
        &self,
        cache_root: &std::path::Path,
        source_checkout: Option<&std::path::Path>,
    ) -> Result<SdkSidecarAttachment> {
        anyhow::ensure!(
            !self.version.is_empty()
                && self.version.len() <= 128
                && self.version.as_bytes()[0].is_ascii_digit()
                && self
                    .version
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b".-+".contains(&byte)),
            "invalid pinned SDK sidecar version"
        );
        let resolver = mvm_fs::sdk_sidecar::SdkSidecarResolver::new(
            cache_root.to_path_buf(),
            self.version.clone(),
        );
        let attachment = resolve_verified_sdk_sidecar_attachment(
            &resolver,
            self.arch,
            self.libc,
            source_checkout,
        )?;
        anyhow::ensure!(
            format!("sha256:{}", attachment.image_sha256) == self.image_sha256.as_str(),
            "SDK sidecar content differs from pinned artifact"
        );
        Ok(attachment)
    }
}

impl SdkSidecarAttachment {
    /// Require the exact content-pinned system grant before attaching the verified bytes.
    pub fn require_signed_grant(&self, plan: &mvm_core::plan::ExecutionPlan) -> Result<()> {
        anyhow::ensure!(
            mvm_core::plan::sdk_sidecar_required(plan),
            "SDK sidecar is not requested"
        );
        let mut grants = plan
            .shares
            .iter()
            .filter(|grant| grant.tag == SDK_SIDECAR_SHARE_TAG);
        anyhow::ensure!(
            grants.next() == Some(&self.grant) && grants.next().is_none(),
            "SDK sidecar attachment does not match the exact signed system grant"
        );
        Ok(())
    }
}

/// Resolve the plan-required sidecar, seeding only from an already verified default cache.
///
/// Call before signing to add the returned read-only, content-pinned system grant;
/// use [`SdkSidecarPin::resolve_exact`] before attaching the volume at launch.
/// Source launches refuse stale FFI artifacts rather than rebuilding or downloading.
pub fn resolve_or_seed_sdk_sidecar_attachment(
    plan: &mvm_core::plan::ExecutionPlan,
    resolver: &mvm_fs::sdk_sidecar::SdkSidecarResolver,
    arch: mvm_core::arch::GuestArch,
    libc: mvm_contract::guest_libc::GuestLibc,
    source_checkout: Option<&std::path::Path>,
) -> Result<Option<SdkSidecarAttachment>> {
    if !mvm_core::plan::sdk_sidecar_required(plan) {
        return Ok(None);
    }
    resolve_verified_sdk_sidecar_attachment(resolver, arch, libc, source_checkout).map(Some)
}

/// Resolve verified artifact bytes without granting permission to mount them.
///
/// Trusted template preparation can use this before workflow membership exists.
/// The final signed plan must pass [`SdkSidecarAttachment::require_signed_grant`].
pub fn resolve_verified_sdk_sidecar_attachment(
    resolver: &mvm_fs::sdk_sidecar::SdkSidecarResolver,
    arch: mvm_core::arch::GuestArch,
    libc: mvm_contract::guest_libc::GuestLibc,
    source_checkout: Option<&std::path::Path>,
) -> Result<SdkSidecarAttachment> {
    anyhow::ensure!(
        libc != mvm_contract::guest_libc::GuestLibc::Unknown,
        "SDK sidecar requires a known guest libc"
    );
    let artifact = mvm_build::sdk_sidecar::resolve_or_seed_from_default_cache(resolver, arch, libc)
        .context("SDK sidecar is not prepared; run `mvmctl bootstrap` first")?;
    if let Some(source) = source_checkout {
        let provenance = mvm_build::sdk_sidecar::cached_sidecar_provenance(
            resolver.cache_root(),
            resolver.expected_version(),
            arch,
            libc,
            source,
        )
        .context("cannot verify source SDK sidecar provenance; run `mvmctl bootstrap`")?;
        anyhow::ensure!(
            provenance == mvm_build::sdk_sidecar::SidecarProvenance::MatchesSource,
            "SDK sidecar predates this source tree; run `mvmctl bootstrap` before actor launch"
        );
    }
    let mut attachment = sdk_sidecar_attachment_for(&artifact);
    attachment.grant.content_sha256 = Some(attachment.image_sha256.clone());
    Ok(attachment)
}

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
    if !mvm_core::plan::sdk_sidecar_required_for(services, true) {
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
             mounted read-only at {}. Populate {} with: mvmctl bootstrap",
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

    fn svc(raw: &str) -> ServiceId {
        ServiceId::parse(raw).expect("fixture service id")
    }

    use mvm_contract::hash::sha256_hex;

    /// A valid sidecar ext4 fixture carrying the cdylib the SDKs load, built
    /// with the in-repo pure-Rust writer (no `mkfs`).
    fn sidecar_ext4_bytes() -> Vec<u8> {
        use mvm_fs::ext4::{Node, Owner};
        let nodes = vec![
            Node::Dir {
                path: "/lib".into(),
                mode: 0o555,
                xattrs: Vec::new(),
                owner: Owner::ROOT,
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
                owner: Owner::ROOT,
            },
        ];
        mvm_fs::ext4::build_image(nodes, &Default::default()).expect("build sidecar ext4 fixture")
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
    fn actor_sidecar_pin_requires_exact_bytes_and_signed_read_only_grant() {
        let dir = tempfile::tempdir().unwrap();
        let arch = GuestArch::host();
        let libc = mvm_contract::guest_libc::GuestLibc::Musl;
        seed_sidecar_cache(dir.path(), "1.2.3", arch);
        let resolver = SdkSidecarResolver::new(dir.path().to_path_buf(), "1.2.3".into());
        let mut plan = mvm_core::plan::test_support::PlanFixture::new().build();
        plan.services = vec![svc("host.actor.v1")];
        plan.sdk_uses_sidecar = true;
        let attachment = resolve_or_seed_sdk_sidecar_attachment(&plan, &resolver, arch, libc, None)
            .unwrap()
            .unwrap();
        assert!(attachment.volume.read_only);
        assert_eq!(
            attachment.grant.content_sha256.as_ref(),
            Some(&attachment.image_sha256)
        );
        let pin = SdkSidecarPin::from_attachment(&attachment, arch, libc).unwrap();
        assert_eq!(
            serde_json::from_slice::<SdkSidecarPin>(&serde_json::to_vec(&pin).unwrap()).unwrap(),
            pin
        );
        assert!(attachment.require_signed_grant(&plan).is_err());
        plan.shares.push(attachment.grant.clone());
        let resolved = pin.resolve_exact(dir.path(), None).unwrap();
        assert_eq!(resolved, attachment);
        resolved.require_signed_grant(&plan).unwrap();
        plan.shares[0].read_only = false;
        assert!(resolved.require_signed_grant(&plan).is_err());
        plan.shares[0] = attachment.grant;
        let mut changed = pin.clone();
        changed.image_sha256 = mvm_contract::assurance::Sha256Digest::from_bytes(&[0; 32]);
        assert!(changed.resolve_exact(dir.path(), None).is_err());
        changed.version = "../elsewhere".into();
        assert!(changed.resolve_exact(dir.path(), None).is_err());
        plan.sdk_uses_sidecar = false;
        assert!(
            resolve_or_seed_sdk_sidecar_attachment(&plan, &resolver, arch, libc, None,)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn actor_sidecar_rejects_unknown_libc_and_unverified_source_provenance() {
        let dir = tempfile::tempdir().unwrap();
        let source = tempfile::tempdir().unwrap();
        let arch = GuestArch::host();
        let libc = mvm_contract::guest_libc::GuestLibc::Musl;
        seed_sidecar_cache(dir.path(), "1.2.3", arch);
        let resolver = SdkSidecarResolver::new(dir.path().to_path_buf(), "1.2.3".into());
        let mut plan = mvm_core::plan::test_support::PlanFixture::new().build();
        plan.services = vec![svc("host.actor.v1")];
        plan.sdk_uses_sidecar = true;
        assert!(
            resolve_or_seed_sdk_sidecar_attachment(
                &plan,
                &resolver,
                arch,
                mvm_contract::guest_libc::GuestLibc::Unknown,
                None,
            )
            .is_err()
        );
        assert!(
            resolve_or_seed_sdk_sidecar_attachment(
                &plan,
                &resolver,
                arch,
                libc,
                Some(source.path()),
            )
            .is_err()
        );
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
            &[svc("host.kv.v1")],
            &resolver,
            GuestArch::host(),
            mvm_contract::guest_libc::GuestLibc::Musl,
        )
        .expect_err("a cold cache must refuse a sidecar-requiring workload");
        let rendered = format!("{err:#}");
        assert!(rendered.contains("host.kv.v1"), "{rendered}");
        assert!(
            rendered.contains("Populate") && rendered.contains("with: mvmctl bootstrap"),
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
