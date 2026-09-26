//! Which `mvm-build` binaries `mvmctl` embeds as its Linux host payload, and
//! what each one is for.
//!
//! One list, read three ways: `mvm-cli`'s build script parses this file's text
//! to decide what to cross-compile (it cannot depend on the crate it is
//! building), `mvmctl` reads the constants to extract and assemble the payload,
//! and `xtask check-mvm-host-binaries-sync` holds `nix/lib/mvm-host-binaries.nix`
//! equal to the builder table. It lives here, beside the binaries it names, so
//! the builder code in this crate reads the same list instead of keeping a
//! copy.
//!
//! The build script finds each table by the first occurrence of its name in
//! this file's text, so a doc comment must not name a table above its
//! declaration.

#[derive(Debug, Clone, Copy)]
pub struct HostBinary {
    /// Cargo package name + name on disk after extraction + nix attrset key.
    pub name: &'static str,
    /// Absolute path inside a builder image that still installs its own copy.
    /// Images carrying a builder boot ABI of 1 or more install none: the
    /// binary reaches the guest in the boot payload instead.
    pub install_path: &'static str,
    /// Unix mode (e.g. 0o755) applied via the flake's extraFiles.
    /// Mirror note: `nix/lib/mvm-host-binaries.nix` stores this as
    /// a decimal string (`"0755"`); the `check-mvm-host-binaries-sync`
    /// xtask parses + compares numerically.
    pub mode: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct SourceBuiltBinary {
    /// Workspace package that owns the binary target.
    pub package: &'static str,
    /// Name on disk after cargo zigbuild and in the extracted cache.
    pub name: &'static str,
    /// Comma-separated Cargo features required by the binary target.
    pub features: &'static str,
}

/// The builder VM's own binaries: the boot payload `mvmctl` hands every
/// builder boot, and what a legacy builder image bakes at `install_path`.
pub const HOST_BINARIES: &[HostBinary] = &[
    HostBinary {
        name: "mvm-host-vm-init",
        install_path: "/sbin/mvm-host-vm-init",
        mode: 0o755,
    },
    // The resident builder-VM control daemon. PID 1
    // (mvm-host-vm-init) launches it at boot; the host reaches it on the
    // builder VM's forwarded AF_VSOCK control port.
    HostBinary {
        name: "mvm-builderd",
        install_path: "/sbin/mvm-builderd",
        mode: 0o755,
    },
];

/// Whether the embedded binary `name` belongs to the builder VM, and so to its
/// boot payload. Only [`HOST_BINARIES`] do; the seed and bootstrap-support
/// binaries are embedded alongside them but never reach a builder image.
pub fn is_baked_into_rootfs(name: &str) -> bool {
    HOST_BINARIES.iter().any(|bin| bin.name == name)
}

/// The names of [`HOST_BINARIES`], in table order.
pub fn host_binary_names() -> impl Iterator<Item = &'static str> {
    HOST_BINARIES.iter().map(|bin| bin.name)
}

/// Host-side-only embedded `mvm-build` binaries. Cross-compiled +
/// embedded by `mvm-cli/build.rs` exactly like [`HOST_BINARIES`], but
/// **not** installed into any VM rootfs — they carry no `install_path`
/// and are absent from `nix/lib/mvm-host-binaries.nix` (the
/// `check-mvm-host-binaries-sync` xtask only mirrors `HOST_BINARIES`).
/// The host extracts these by name and lays them down directly:
/// `stage0-init` becomes the Stage 0 nix-seed's `/init`.
pub const SEED_BINARIES: &[&str] = &["stage0-init"];

/// Stage 0 and builder bootstrap helpers also need a small set of support
/// binaries mounted under `/mvm-bins` before the runtime overlay is available.
/// These stay out of the builder/dev VM rootfs, but the source-built fallback
/// must still compile and cache them alongside the primary host binaries.
pub const BOOTSTRAP_SUPPORT_BINARIES: &[SourceBuiltBinary] = &[SourceBuiltBinary {
    package: "mvm-agentd",
    name: "mvm-egress-client",
    features: "addons",
}];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_builder_binaries_are_payload_members() {
        assert!(is_baked_into_rootfs("mvm-host-vm-init"));
        assert!(is_baked_into_rootfs("mvm-builderd"));
        for other in SEED_BINARIES
            .iter()
            .copied()
            .chain(BOOTSTRAP_SUPPORT_BINARIES.iter().map(|b| b.name))
        {
            assert!(!is_baked_into_rootfs(other), "{other}");
        }
    }

    #[test]
    fn names_follow_the_table() {
        let names: Vec<_> = host_binary_names().collect();
        assert_eq!(names, ["mvm-host-vm-init", "mvm-builderd"]);
    }
}
