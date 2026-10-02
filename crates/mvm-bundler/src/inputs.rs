//! What an export is given.

use std::path::Path;

use mvm_core::plan::BundleResources;

use crate::debug::DebugOutput;

/// Everything one export reads.
///
/// The verity pair is taken as the caller found it rather than as one value:
/// a rootfs carrying only half of it is a misbuild, and the export is where
/// that is refused.
#[derive(Debug, Clone)]
pub struct BundleExportInputs<'a> {
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
            vmlinux,
            initrd: None,
            rootfs,
            verity_bytes: None,
            roothash: None,
            profile: None,
            resources: None,
            arch_label,
            label: None,
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

    pub fn debug_out(mut self, debug_out: DebugOutput) -> Self {
        self.debug_out = Some(debug_out);
        self
    }
}
