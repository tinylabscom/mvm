//! Whether a launch boots an OCI image: the one answer every consumer reads.
//!
//! Three decisions hang on it. A run that boots an OCI image with egress
//! enabled needs a NIC-less host-vsock-proxy backend; its workload needs the
//! proxy environment handed to it, because an image's own init knows nothing
//! of the guest's egress proxy (a `mkGuest` image exports it from `/init`);
//! and a dry run reports both. Each used to ask its own question — "was
//! `--image` passed", "is this a prebuilt with an unpacked OCI tree" — so a
//! manifest whose `image` built an OCI slot answered "no" to all of them and
//! booted without a proxy environment.
//!
//! The answer is read off what the run boots, not off which flag named it: a
//! rootfs materialized from an image carries a sidecar that says so
//! ([`mvm_build::builder_vm::GuestSidecar::is_oci_materialized`]), whether it
//! came from `--image`, a manifest's `image`, or a slot a pack installed.

use std::path::Path;

use anyhow::Result;
use mvm_build::builder_vm::GuestSidecar;

use super::ImageSource;

/// How a launch names the image it boots, at whatever stage it is asked.
#[derive(Debug, Clone, Copy)]
pub(crate) enum ImageNaming<'a> {
    /// `--image <ref>`: an OCI reference, not yet pulled.
    OciReference,
    /// `--manifest <path-or-slot>`: a manifest whose built slot is booted.
    Manifest(&'a str),
    /// An image source already resolved.
    Resolved(&'a ImageSource),
    /// Nothing named: the runtime pack or the bundled default microVM, both
    /// built by `mkGuest`.
    Bundled,
}

/// What a transient launch's flags name, in the precedence the launch itself
/// resolves them: a runtime pack, then an already-resolved source, then a
/// manifest, then an image reference, then the bundled default.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct LaunchNames<'a> {
    pub runtime_pack: bool,
    pub resolved: Option<&'a ImageSource>,
    pub manifest: Option<&'a str>,
    pub image: Option<&'a str>,
}

impl<'a> From<LaunchNames<'a>> for ImageNaming<'a> {
    fn from(names: LaunchNames<'a>) -> Self {
        if names.runtime_pack {
            return Self::Bundled;
        }
        if let Some(source) = names.resolved {
            return Self::Resolved(source);
        }
        if let Some(manifest) = names.manifest {
            return Self::Manifest(manifest);
        }
        if names.image.is_some() {
            return Self::OciReference;
        }
        Self::Bundled
    }
}

/// Whether the launch named by `naming` boots an OCI image.
///
/// # Errors
///
/// A sidecar that exists but does not parse. A `--manifest` that does not
/// resolve, or names a slot not yet built, answers `false`: the launch refuses
/// it with its own message before anything boots.
pub(crate) fn boots_oci_image(naming: ImageNaming<'_>) -> Result<bool> {
    match naming {
        ImageNaming::OciReference => Ok(true),
        ImageNaming::Bundled => Ok(false),
        ImageNaming::Resolved(source) => source_boots_oci_image(source),
        // A manifest that does not resolve is not answered here: the launch
        // resolves it again to find what to boot and refuses with its own
        // message, so nothing boots on this answer. A dry run, which never
        // boots, gets a summary instead of an error.
        ImageNaming::Manifest(arg) => match crate::commands::shared::resolve_manifest_arg(arg) {
            Ok(crate::commands::shared::ManifestArgRef::Slot { slot_hash }) => {
                slot_boots_oci_image(&mvm_core::manifest::slot_current_symlink(&slot_hash))
            }
            Ok(crate::commands::shared::ManifestArgRef::WasmModule { .. }) | Err(_) => Ok(false),
        },
    }
}

fn source_boots_oci_image(source: &ImageSource) -> Result<bool> {
    match source {
        ImageSource::Prebuilt {
            unpacked_oci_root: Some(_),
            ..
        } => Ok(true),
        ImageSource::Prebuilt { rootfs_path, .. } => Path::new(rootfs_path)
            .parent()
            .map_or(Ok(false), slot_boots_oci_image_in),
        ImageSource::Template(id) if mvm_core::manifest::is_slot_hash_dirname(id) => {
            slot_boots_oci_image(&mvm_core::manifest::slot_current_symlink(id))
        }
        ImageSource::PinnedTemplate {
            slot_hash,
            revision_hash,
        } => slot_boots_oci_image(&mvm_core::manifest::slot_revision_dir(
            slot_hash,
            revision_hash,
        )),
        ImageSource::Template(_) | ImageSource::WasmModule { .. } => Ok(false),
    }
}

fn slot_boots_oci_image(dir: &str) -> Result<bool> {
    slot_boots_oci_image_in(Path::new(dir))
}

fn slot_boots_oci_image_in(dir: &Path) -> Result<bool> {
    Ok(GuestSidecar::read_from_dir(dir)?.is_some_and(|sidecar| sidecar.is_oci_materialized()))
}

/// The proxy environment a workload needs when its launch boots an OCI image
/// with egress on a backend that reaches the network only through the host
/// vsock proxy. Empty otherwise: a `mkGuest` image exports its own, and a
/// backend without the proxy has nothing to point at.
pub(crate) fn oci_proxy_env(
    boots_oci: bool,
    caps: &mvm_core::vm_backend::VmCapabilities,
    network_policy: &mvm_core::network_policy::NetworkPolicy,
) -> Vec<(String, String)> {
    if !boots_oci || !network_policy.allows_egress() {
        return Vec::new();
    }
    if !(caps.vsock && caps.no_routable_guest_nic && caps.host_vsock_proxy) {
        return Vec::new();
    }
    mvm_core::guest_netd::proxy_env_vars(mvm_core::guest_netd::DEFAULT_EGRESS_PROXY_LISTEN)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::util::test_env::TestEnv;

    fn proxy_caps() -> mvm_core::vm_backend::VmCapabilities {
        mvm_core::vm_backend::VmCapabilities {
            vsock: true,
            no_routable_guest_nic: true,
            host_vsock_proxy: true,
            ..Default::default()
        }
    }

    fn egress() -> mvm_core::network_policy::NetworkPolicy {
        mvm_core::network_policy::NetworkPolicy::allow_list(vec![
            mvm_core::network_policy::HostPort::new("example.com", 443),
        ])
    }

    /// A slot whose current revision holds `sidecar`, the shape
    /// `template_build_from_image` leaves behind.
    fn built_slot(sidecar: &GuestSidecar) -> String {
        let slot_hash = "a".repeat(64);
        let revision = mvm_core::manifest::slot_revision_dir(&slot_hash, "rev1");
        sidecar.write_to_dir(Path::new(&revision)).unwrap();
        std::fs::write(Path::new(&revision).join("rootfs.ext4"), b"ext4").unwrap();
        std::os::unix::fs::symlink(
            &revision,
            mvm_core::manifest::slot_current_symlink(&slot_hash),
        )
        .unwrap();
        slot_hash
    }

    #[test]
    fn a_manifest_image_slot_and_an_image_flag_get_the_same_proxy_env() {
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let slot = built_slot(&GuestSidecar::for_oci_run("oci:sha256-abc", false, true));

        let from_flag = boots_oci_image(ImageNaming::OciReference).unwrap();
        let from_slot =
            boots_oci_image(ImageNaming::Resolved(&ImageSource::Template(slot.clone()))).unwrap();
        assert!(from_flag && from_slot);
        let flag_env = oci_proxy_env(from_flag, &proxy_caps(), &egress());
        assert!(!flag_env.is_empty());
        assert_eq!(flag_env, oci_proxy_env(from_slot, &proxy_caps(), &egress()));

        let pinned = ImageSource::PinnedTemplate {
            slot_hash: slot,
            revision_hash: "rev1".into(),
        };
        assert!(boots_oci_image(ImageNaming::Resolved(&pinned)).unwrap());
    }

    /// Build `mvm.toml` into its slot the way `mvmctl build` does for a
    /// manifest that names an image, with `sidecar` as what materialization
    /// wrote. Returns the manifest path.
    fn build_manifest_slot(project: &Path, sidecar: &GuestSidecar) -> String {
        let manifest_path = project.join("mvm.toml");
        std::fs::write(&manifest_path, "image = \"alpine:3.20\"\n").unwrap();
        let canonical = std::fs::canonicalize(&manifest_path).unwrap();
        let manifest = mvm_core::manifest::Manifest::read_file(&canonical).unwrap();
        let persisted = mvm_core::manifest::PersistedManifest::from_manifest(
            &manifest,
            &canonical,
            "mock",
            mvm_core::manifest::Provenance::current(),
        )
        .unwrap();
        let materialized = project.join("materialized");
        sidecar.write_to_dir(&materialized).unwrap();
        std::fs::write(materialized.join("rootfs.ext4"), b"ext4").unwrap();
        std::fs::write(project.join("vmlinux"), b"kernel").unwrap();
        mvm_runtime::vm::template::lifecycle::template_build_from_image(
            &persisted,
            &mvm_runtime::vm::template::lifecycle::ImageBuildSources {
                rootfs: materialized.join("rootfs.ext4"),
                kernel: project.join("vmlinux"),
                image_ref: "alpine:3.20".into(),
            },
            mvm_build::pipeline::BuildMode::Dev,
        )
        .unwrap();
        manifest_path.display().to_string()
    }

    #[test]
    fn a_manifest_that_built_an_image_slot_boots_an_oci_image() {
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let project = tempfile::tempdir().unwrap();
        let arg = build_manifest_slot(
            project.path(),
            &GuestSidecar::for_oci_run("oci:sha256-abc", false, true),
        );
        assert!(boots_oci_image(ImageNaming::Manifest(&arg)).unwrap());
        assert_eq!(
            oci_proxy_env(true, &proxy_caps(), &egress()),
            oci_proxy_env(
                boots_oci_image(ImageNaming::Manifest(&arg)).unwrap(),
                &proxy_caps(),
                &egress()
            ),
        );
    }

    #[test]
    fn a_mkguest_slot_an_unbuilt_slot_and_the_bundled_image_do_not() {
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let mut nix = GuestSidecar::for_oci_run("default", false, true);
        nix.hypervisor = "firecracker".into();
        let slot = built_slot(&nix);
        assert!(!boots_oci_image(ImageNaming::Resolved(&ImageSource::Template(slot))).unwrap());
        let unbuilt = ImageSource::Template("b".repeat(64));
        assert!(!boots_oci_image(ImageNaming::Resolved(&unbuilt)).unwrap());
        assert!(!boots_oci_image(ImageNaming::Bundled).unwrap());
        assert!(!boots_oci_image(ImageNaming::Manifest("/no/such/project/mvm.toml")).unwrap());
    }

    #[test]
    fn a_prebuilt_rootfs_is_read_by_its_sidecar_or_its_unpacked_tree() {
        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path().join("rootfs.ext4");
        let prebuilt = |unpacked: Option<String>| ImageSource::Prebuilt {
            kernel_path: "vmlinux".into(),
            rootfs_path: rootfs.display().to_string(),
            initrd_path: None,
            label: "x".into(),
            unpacked_oci_root: unpacked,
        };
        assert!(!boots_oci_image(ImageNaming::Resolved(&prebuilt(None))).unwrap());
        assert!(boots_oci_image(ImageNaming::Resolved(&prebuilt(Some("/t".into())))).unwrap());
        GuestSidecar::for_oci_run("oci:sha256-abc", false, true)
            .write_to_dir(dir.path())
            .unwrap();
        assert!(boots_oci_image(ImageNaming::Resolved(&prebuilt(None))).unwrap());
    }

    #[test]
    fn launch_names_follow_the_launch_precedence() {
        let resolved = ImageSource::Template("x".into());
        assert!(matches!(
            ImageNaming::from(LaunchNames::default()),
            ImageNaming::Bundled
        ));
        assert!(matches!(
            ImageNaming::from(LaunchNames {
                image: Some("alpine"),
                ..LaunchNames::default()
            }),
            ImageNaming::OciReference
        ));
        assert!(matches!(
            ImageNaming::from(LaunchNames {
                manifest: Some("./mvm.toml"),
                ..LaunchNames::default()
            }),
            ImageNaming::Manifest("./mvm.toml")
        ));
        assert!(matches!(
            ImageNaming::from(LaunchNames {
                resolved: Some(&resolved),
                manifest: Some("./mvm.toml"),
                ..LaunchNames::default()
            }),
            ImageNaming::Resolved(_)
        ));
        assert!(matches!(
            ImageNaming::from(LaunchNames {
                runtime_pack: true,
                resolved: Some(&resolved),
                ..LaunchNames::default()
            }),
            ImageNaming::Bundled
        ));
    }

    #[test]
    fn the_proxy_env_needs_an_oci_image_egress_and_a_proxy_backend() {
        let deny = mvm_core::network_policy::NetworkPolicy::deny_all();
        assert!(oci_proxy_env(false, &proxy_caps(), &egress()).is_empty());
        assert!(oci_proxy_env(true, &proxy_caps(), &deny).is_empty());
        let no_proxy = mvm_core::vm_backend::VmCapabilities {
            host_vsock_proxy: false,
            ..proxy_caps()
        };
        assert!(oci_proxy_env(true, &no_proxy, &egress()).is_empty());
        let env = oci_proxy_env(true, &proxy_caps(), &egress());
        assert!(env.iter().any(|(k, _)| k == "HTTPS_PROXY"));
        assert!(env.iter().any(|(k, _)| k == "ALL_PROXY"));
    }
}
