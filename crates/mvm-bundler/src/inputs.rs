//! What an export is given.

use std::path::Path;

use mvm_core::plan::BundleResources;
use mvm_core::plan::types::BuildProvenance;
use mvm_core::policy::security::AgentProfile;

use crate::debug::DebugOutput;

/// Authenticated original image-set bytes and the two selected archive files.
/// Acquisition and publisher verification belong to the caller.
#[derive(Debug, Clone)]
pub struct BootAssetsInputs<'a> {
    pub manifest_bytes: &'a [u8],
    pub manifest_sha256: &'a mvm_core::packs::Sha256Hex,
    pub runtime_overlay: &'a Path,
    pub initramfs: &'a Path,
}

/// Everything one export reads.
///
/// The verity pair is taken as the caller found it rather than as one value:
/// a rootfs carrying only half of it is a misbuild, and the export is where
/// that is refused.
#[derive(Debug, Clone)]
pub struct BundleExportInputs<'a> {
    pub boot_assets: Option<BootAssetsInputs<'a>>,
    /// Path to the kernel image.
    pub vmlinux: &'a str,
    /// Path to the initrd, when the template boots with one.
    pub initrd: Option<&'a str>,
    /// Path to the rootfs image. The guest sidecar is read from beside it.
    pub rootfs: &'a str,
    /// The dm-verity hash sidecar's bytes, when the rootfs has one.
    pub verity_bytes: Option<&'a [u8]>,
    /// The dm-verity root hash, when the rootfs has one.
    pub roothash: Option<&'a str>,
    /// The build profile the artifacts came from, when there is one to record.
    pub profile: Option<&'a str>,
    /// The vCPUs and memory the workload was sized for. A launch on another
    /// host starts from these; without them it falls back to that host's
    /// defaults. Launch-time flags override either way.
    pub resources: Option<BundleResources>,
    /// The guest architecture the artifacts were built for.
    pub arch_label: &'a str,
    /// Human-readable workload label recorded in the manifest.
    pub label: Option<String>,
    /// The kernel command line the workload was built and tested with.
    pub cmdline: Option<&'a str>,
    /// The ceilings the publisher places on any launch of this workload.
    pub posture: Option<PostureInputs>,
    /// What the workload was built from. Its kernel, rootfs, and initramfs
    /// digests are replaced with those of the bytes actually sealed, so the
    /// record cannot describe a build other than the one shipped.
    pub provenance: Option<BuildProvenance>,
    /// Where the archive is written. Missing parent directories are created;
    /// an existing file is overwritten.
    pub out: &'a Path,
    /// Where to write a summary of the export, if anywhere.
    pub debug_out: Option<DebugOutput>,
}

impl<'a> BundleExportInputs<'a> {
    /// An export of a kernel and a rootfs, with nothing optional set.
    pub fn new(vmlinux: &'a str, rootfs: &'a str, arch_label: &'a str, out: &'a Path) -> Self {
        Self {
            boot_assets: None,
            vmlinux,
            initrd: None,
            rootfs,
            verity_bytes: None,
            roothash: None,
            profile: None,
            resources: None,
            arch_label,
            label: None,
            cmdline: None,
            posture: None,
            provenance: None,
            out,
            debug_out: None,
        }
    }

    pub fn initrd(mut self, initrd: &'a str) -> Self {
        self.initrd = Some(initrd);
        self
    }

    /// Carry the rootfs's dm-verity binding: the hash sidecar and its root hash.
    pub fn verity(mut self, sidecar: &'a [u8], roothash: &'a str) -> Self {
        self.verity_bytes = Some(sidecar);
        self.roothash = Some(roothash);
        self
    }

    pub fn profile(mut self, profile: &'a str) -> Self {
        self.profile = Some(profile);
        self
    }

    pub fn resources(mut self, vcpus: u32, mem_mib: u32) -> Self {
        self.resources = Some(BundleResources { vcpus, mem_mib });
        self
    }

    pub fn label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    pub fn cmdline(mut self, cmdline: &'a str) -> Self {
        self.cmdline = Some(cmdline);
        self
    }

    pub fn posture(mut self, posture: PostureInputs) -> Self {
        self.posture = Some(posture);
        self
    }

    pub fn provenance(mut self, provenance: BuildProvenance) -> Self {
        self.provenance = Some(provenance);
        self
    }

    pub fn debug_out(mut self, debug_out: DebugOutput) -> Self {
        self.debug_out = Some(debug_out);
        self
    }
}

/// The posture a publisher declares. Whether the rootfs is dm-verity
/// protected is not asked: the export records what it actually seals.
///
/// Every permission starts closed; [`PostureInputs::new`] grants nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PostureInputs {
    pub profile: AgentProfile,
    pub requires_auth: bool,
    pub allows_volumes: bool,
    pub allows_egress: bool,
}

impl PostureInputs {
    /// A posture for `profile` that requires authentication and allows
    /// neither volumes nor egress.
    pub fn new(profile: AgentProfile) -> Self {
        Self {
            profile,
            requires_auth: true,
            allows_volumes: false,
            allows_egress: false,
        }
    }

    pub fn requires_auth(mut self, requires_auth: bool) -> Self {
        self.requires_auth = requires_auth;
        self
    }

    pub fn allows_volumes(mut self, allows_volumes: bool) -> Self {
        self.allows_volumes = allows_volumes;
        self
    }

    pub fn allows_egress(mut self, allows_egress: bool) -> Self {
        self.allows_egress = allows_egress;
        self
    }
}
