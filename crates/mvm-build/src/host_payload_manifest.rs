//! Which binaries `mvmctl` embeds as its Linux host payload, and what each one
//! is for.
//!
//! One list, read three ways: `mvm-cli`'s build script parses this file's text
//! to decide what to cross-compile (it cannot depend on the crate it is
//! building), `mvmctl` reads the constants to extract and assemble the payload,
//! and `xtask check-mvm-host-binaries-sync` holds `nix/lib/mvm-host-binaries.nix`
//! equal to the entries of the builder table a legacy image installs. It lives
//! here, beside the binaries it names, so the builder code in this crate reads
//! the same list instead of keeping a copy.
//!
//! The build script finds each table by the first occurrence of its name in
//! this file's text, so a doc comment must not name a table above its
//! declaration, and the text inside a table must not carry a field label in a
//! comment.

#[derive(Debug, Clone, Copy)]
pub struct HostBinary {
    /// Workspace package that owns the binary target.
    pub package: &'static str,
    /// Binary target name, name on disk after extraction, and nix attrset key.
    pub name: &'static str,
    /// Where a legacy builder image (boot ABI 0) installs this binary from the
    /// host-binary directory its build is handed. `None` for a binary no image
    /// installs that way. Images carrying a builder boot ABI of 1 or more
    /// install nothing from that directory: the binary reaches the guest in
    /// the boot payload instead.
    pub install_path: Option<&'static str>,
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
        package: "mvm-build",
        name: "mvm-host-vm-init",
        install_path: Some("/sbin/mvm-host-vm-init"),
        mode: 0o755,
    },
    // The resident builder-VM control daemon. PID 1
    // (mvm-host-vm-init) launches it at boot; the host reaches it on the
    // builder VM's forwarded AF_VSOCK control port.
    HostBinary {
        package: "mvm-build",
        name: "mvm-builderd",
        install_path: Some("/sbin/mvm-builderd"),
        mode: 0o755,
    },
    // The privilege-drop helper PID 1 forks the guest agent under. Images
    // before boot ABI 2 bake their own copy at /sbin through the image's
    // package list rather than the host-binary directory, so no image installs
    // this one; from ABI 2 on, the payload's copy is the only one.
    HostBinary {
        package: "mvm-setpriv",
        name: "mvm-setpriv",
        install_path: None,
        mode: 0o755,
    },
];

/// The names of [`HOST_BINARIES`], in table order.
pub fn host_binary_names() -> impl Iterator<Item = &'static str> {
    HOST_BINARIES.iter().map(|bin| bin.name)
}

/// The names of the [`HOST_BINARIES`] a legacy builder image installs from its
/// host-binary directory, in table order: what a pair build of such an image
/// must build and stage.
pub fn legacy_installed_host_binary_names() -> impl Iterator<Item = &'static str> {
    HOST_BINARIES
        .iter()
        .filter(|bin| bin.install_path.is_some())
        .map(|bin| bin.name)
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
    fn names_follow_the_table() {
        let names: Vec<_> = host_binary_names().collect();
        assert_eq!(names, ["mvm-host-vm-init", "mvm-builderd", "mvm-setpriv"]);
    }

    /// A legacy image installs the builder binaries from the host-binary
    /// directory and gets `mvm-setpriv` from its own package list, so a pair
    /// build of one stages only the former.
    #[test]
    fn a_legacy_image_installs_only_the_builder_binaries() {
        let names: Vec<_> = legacy_installed_host_binary_names().collect();
        assert_eq!(names, ["mvm-host-vm-init", "mvm-builderd"]);
    }

    #[test]
    fn setpriv_is_built_from_its_own_package() {
        let setpriv = HOST_BINARIES
            .iter()
            .find(|bin| bin.name == "mvm-setpriv")
            .expect("mvm-setpriv is a payload member");
        assert_eq!(setpriv.package, crate::source_closure::SETPRIV_PACKAGE);
        assert_eq!(setpriv.install_path, None);
    }
}
