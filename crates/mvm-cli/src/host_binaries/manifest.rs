//! The binaries `mvmctl` ships beside its own code.
//!
//! The Linux host payload — what gets cross-compiled, embedded and handed to
//! builder VMs — is declared in `mvm_build::host_payload_manifest`, beside the
//! binaries it names, and re-exported here. The per-VM host processes
//! `mvmctl` spawns next to itself are declared below.

pub use mvm_build::host_payload_manifest::{
    BOOTSTRAP_SUPPORT_BINARIES, HOST_BINARIES, HostBinary, SEED_BINARIES, SourceBuiltBinary,
    host_binary_names, is_baked_into_rootfs,
};

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
    // The per-VM GPU endpoint, spawned for a guest launched with `--gpu`. It
    // needs no GPU on the host: without a driver it answers through its
    // deterministic stub backend, so it ships everywhere `mvmctl` does.
    PerVmBinary {
        package: "mvm-gpu",
        name: "mvm-gpu-endpoint",
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
