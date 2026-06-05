//! Compile-time Rust mirror of `nix/lib/mvm-host-binaries.nix`.
//! Parity with the Nix attrset is asserted by the
//! `check-mvm-host-binaries-sync` xtask (Task 3).

#[derive(Debug, Clone, Copy)]
pub struct HostBinary {
    /// Cargo package name + name on disk after extraction + nix attrset key.
    /// The kernel cmdline of the builder VM expects PID 1 at the
    /// `install_path` matching this name (e.g.
    /// `init=/sbin/mvm-host-vm-init` ↔ `install_path = "/sbin/mvm-host-vm-init"`).
    pub name: &'static str,
    /// Absolute path inside the builder/dev VM rootfs.
    pub install_path: &'static str,
    /// Unix mode (e.g. 0o755) applied via the flake's extraFiles.
    /// Mirror note: `nix/lib/mvm-host-binaries.nix` stores this as
    /// a decimal string (`"0755"`); the `check-mvm-host-binaries-sync`
    /// xtask (Task 3) parses + compares numerically.
    pub mode: u32,
}

pub const HOST_BINARIES: &[HostBinary] = &[
    HostBinary {
        name: "mvm-host-vm-init",
        install_path: "/sbin/mvm-host-vm-init",
        mode: 0o755,
    },
    HostBinary {
        name: "mvm-egress-proxy",
        install_path: "/sbin/mvm-egress-proxy",
        mode: 0o755,
    },
];

/// Host-side-only embedded `mvm-build` binaries. Cross-compiled +
/// embedded by `mvm-cli/build.rs` exactly like [`HOST_BINARIES`], but
/// **not** installed into any VM rootfs — they carry no `install_path`
/// and are absent from `nix/lib/mvm-host-binaries.nix` (the
/// `check-mvm-host-binaries-sync` xtask only mirrors `HOST_BINARIES`).
/// The host extracts these by name and lays them down directly:
/// `stage0-init` becomes the Stage 0 nix-seed's `/init` (plan 160).
pub const SEED_BINARIES: &[&str] = &["stage0-init"];
