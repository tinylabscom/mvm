//! Compile-time Rust mirror of `nix/lib/mvm-host-binaries.nix`.
//! Parity with the Nix attrset is asserted by the
//! `check-mvm-host-binaries-sync` xtask.

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
    // The resident builder-VM control daemon. PID 1
    // (mvm-host-vm-init) launches it at boot; the host reaches it on the
    // builder VM's forwarded AF_VSOCK control port.
    HostBinary {
        name: "mvm-builderd",
        install_path: "/sbin/mvm-builderd",
        mode: 0o755,
    },
];

/// Host-side-only embedded `mvm-build` binaries. Cross-compiled +
/// embedded by `mvm-cli/build.rs` exactly like [`HOST_BINARIES`], but
/// **not** installed into any VM rootfs — they carry no `install_path`
/// and are absent from `nix/lib/mvm-host-binaries.nix` (the
/// `check-mvm-host-binaries-sync` xtask only mirrors `HOST_BINARIES`).
/// The host extracts these by name and lays them down directly:
/// `stage0-init` becomes the Stage 0 nix-seed's `/init`;
/// `mvm-rootfs-patcher` becomes the self-hosting bootstrap's inject-initramfs
/// `/init` (re-bakes a builder rootfs with the current host binaries on the
/// hvf VMM — no legacy builder).
pub const SEED_BINARIES: &[&str] = &["stage0-init", "mvm-rootfs-patcher"];

/// Stage 0 and builder bootstrap helpers also need a small set of support
/// binaries mounted under `/mvm-bins` before the runtime overlay is available.
/// These stay out of the builder/dev VM rootfs, but the source-built fallback
/// must still compile and cache them alongside the primary host binaries.
pub const BOOTSTRAP_SUPPORT_BINARIES: &[SourceBuiltBinary] = &[SourceBuiltBinary {
    package: "mvm-agentd",
    name: "mvm-egress-client",
    features: "addons",
}];

/// Where a per-VM host binary can be built, expressed as data so the
/// build script, the release workflow, and the sync gate all read one
/// list instead of three hand-kept copies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PerVmScope {
    /// Every target `mvmctl` ships for.
    Always,
    /// macOS on Apple Silicon — the raw-HVF VMM supervisor.
    MacOsAarch64,
    /// Only where libkrun headers exist to link against. Deliberately not
    /// a Linux target: the released Linux `mvmctl` does not link libkrun,
    /// so the supervisor is neither buildable nor needed there.
    RequiresLibkrun,
}

/// A per-VM host process `mvmctl` spawns at runtime, one process per guest.
///
/// These are separate `[[bin]]` targets in other packages, so the root
/// `cargo build` that produces `mvmctl` does not produce them. They are
/// found at runtime by `resolve_subprocess_bin`, whose only viable lookup
/// on a downloaded install is *adjacent to the executable* — the
/// `target/{release,debug}` fallback exists solely for source checkouts.
/// A binary listed here that the release tarball omits is therefore a
/// spawn failure for anyone who installed from a release rather than
/// building from source.
#[derive(Debug, Clone, Copy)]
pub struct PerVmBinary {
    /// Workspace package that owns the `[[bin]]` target.
    pub package: &'static str,
    /// Binary name on disk, and the name `resolve_subprocess_bin` asks for.
    pub name: &'static str,
    /// Comma-separated Cargo features the binary target requires.
    pub features: &'static str,
    pub scope: PerVmScope,
}

/// The canonical per-VM host binary set. `mvm-cli/build.rs` builds these
/// beside `mvmctl` for a source checkout, `.github/workflows/release.yml`
/// builds and packages them for a downloaded install, and
/// `xtask check-per-vm-host-binaries-sync` fails the build when those two
/// consumers drift from this list.
pub const PER_VM_HOST_BINARIES: &[PerVmBinary] = &[
    // The per-tenant host-services daemon. `host_agent_daemon_enabled()`
    // defaults to ON, so this is the default services path for every
    // admitted workload on every backend.
    PerVmBinary {
        package: "mvm-hostd",
        name: "mvm-host-agent",
        features: "",
        scope: PerVmScope::Always,
    },
    // Resolved by mvm-host-agent adjacent to *itself*, so it travels
    // wherever mvm-host-agent does.
    PerVmBinary {
        package: "mvm-hostd",
        name: "mvm-signer-helper",
        features: "",
        scope: PerVmScope::Always,
    },
    // The per-VM egress gate. Every VM spawns one, on both the Firecracker
    // and HVF paths.
    PerVmBinary {
        package: "mvm-hostd",
        name: "mvm-network-endpoint",
        features: "",
        scope: PerVmScope::Always,
    },
    // The per-VM broker fork and its audit signer. Reached when
    // `MVM_HOST_AGENT_DAEMON=0` selects the pre-daemon path, which is a
    // documented escape hatch rather than dead code — so both ship.
    PerVmBinary {
        package: "mvm-hostd",
        name: "mvm-broker",
        features: "",
        scope: PerVmScope::Always,
    },
    PerVmBinary {
        package: "mvm-hostd",
        name: "mvm-audit-signer",
        features: "",
        scope: PerVmScope::Always,
    },
    PerVmBinary {
        package: "mvm-hostd",
        name: "mvm-hvf-supervisor",
        features: "",
        scope: PerVmScope::MacOsAarch64,
    },
    PerVmBinary {
        package: "mvm-hostd",
        name: "mvm-libkrun-supervisor",
        features: "libkrun-sys",
        scope: PerVmScope::RequiresLibkrun,
    },
];
