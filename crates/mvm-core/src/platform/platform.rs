use std::path::Path;
use std::sync::OnceLock;

/// Canonical libkrun shared-library search paths, ordered "most-likely first"
/// so probes short-circuit on the typical developer install.
///
/// Single source of truth shared by [`Platform::has_libkrun`] and
/// `mvm_libkrun::install_paths()`. Keeping both sides in sync is
/// structurally guaranteed: `install_paths()` is derived from this const, so
/// the two lists cannot drift.
#[cfg(target_os = "macos")]
pub const LIBKRUN_LIB_PATHS: &[&str] = &[
    "/opt/homebrew/lib/libkrun.dylib", // Apple Silicon Homebrew
    "/usr/local/lib/libkrun.dylib",    // manual / Intel Homebrew installs
];
#[cfg(target_os = "linux")]
pub const LIBKRUN_LIB_PATHS: &[&str] = &[
    "/usr/lib/x86_64-linux-gnu/libkrun.so",
    "/usr/lib/aarch64-linux-gnu/libkrun.so",
    "/usr/lib64/libkrun.so",
    "/usr/local/lib/libkrun.so",
];
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub const LIBKRUN_LIB_PATHS: &[&str] = &[];

/// The execution environment for running workloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// macOS — supported for local builder/runtime work only on Apple Silicon.
    MacOS,
    /// Native Linux with /dev/kvm available — run Firecracker directly
    LinuxNative,
    /// Linux without /dev/kvm (not WSL) — no supported local microVM path.
    LinuxNoKvm,
    /// WSL2 — future/experimental local path when nested KVM is present.
    Wsl2,
    /// Native Windows — no local microVM path; Hyper-V builder is future work.
    Windows,
}

impl Platform {
    /// Whether this platform can run Firecracker directly via /dev/kvm.
    pub fn has_kvm(self) -> bool {
        match self {
            Platform::LinuxNative => true,
            Platform::Wsl2 => Path::new("/dev/kvm").exists(),
            _ => false,
        }
    }

    /// Whether this platform supports nested KVM — required for Plan
    /// 100's symmetric builder-VM-on-Linux story (libkrun builder VM
    /// runs in a nested KVM under the host's KVM). Plan 105 W1 uses
    /// this to gate the opt-in `MVM_LINUX_BUILDER_VM=1` dispatch path.
    ///
    /// Linux-only — macOS / Windows / WSL2 / no-KVM return `false`
    /// unconditionally because the question doesn't apply. On
    /// `LinuxNative`, probes `/sys/module/kvm_intel/parameters/nested`
    /// (must read `Y`) or `/sys/module/kvm_amd/parameters/nested`
    /// (must read `1`). Either being enabled qualifies — the host
    /// runs Intel or AMD CPUs but not both, so only one of the two
    /// sysfs nodes typically exists.
    pub fn has_nested_kvm(self) -> bool {
        if !matches!(self, Platform::LinuxNative) {
            return false;
        }
        has_nested_kvm_at(
            "/sys/module/kvm_intel/parameters/nested",
            "/sys/module/kvm_amd/parameters/nested",
        )
    }

    /// Whether the microvm.nix runner can execute natively on this host.
    pub fn supports_native_runner(self) -> bool {
        matches!(self, Platform::LinuxNative)
    }

    /// Whether Apple Containers are available on this platform.
    ///
    /// Requires macOS 26+ on Apple Silicon.
    pub fn has_apple_containers(self) -> bool {
        if !matches!(self, Platform::MacOS) {
            return false;
        }
        is_macos_26_or_later()
    }

    /// Whether Apple Virtualization.framework (Vz) is available on
    /// this host.
    ///
    /// Plan 97 / ADR-056. Vz is built into macOS — no separate library
    /// to probe, no Homebrew install — so detection collapses to a
    /// combined OS-and-version check. macOS 13 (Ventura) is the floor
    /// because the full virtio surface we use
    /// (`VZMultipleDirectoryShare`, `VZDiskBlockDeviceStorageDeviceAttachment`)
    /// lands there. macOS 11–12 hosts fall back to libkrun (no
    /// regression). Both architectures are supported (Apple Silicon
    /// arm64 + Intel x86_64); Vz works on both since macOS 11.
    ///
    /// This probe does **not** assert the `mvm-vz-supervisor` binary
    /// is installed — that lives under `~/.mvm/bin/` for release
    /// layouts and at `crates/mvm-vz-supervisor/.build/.../` for
    /// source-checkout builds. `mvmctl doctor` surfaces the binary
    /// presence separately; `VzBackend::start` returns the precise
    /// "supervisor binary missing" error when needed.
    pub fn has_vz(self) -> bool {
        if !matches!(self, Platform::MacOS) {
            return false;
        }
        is_macos_13_or_later()
    }

    /// Whether libkrun is installed on this host.
    ///
    /// libkrun (plan 53 §"Plan E") is a library-style VMM that runs on
    /// Linux KVM and macOS Hypervisor.framework on Apple Silicon.
    /// macOS Intel and native Windows are intentionally unsupported.
    /// WSL2 is treated as future/experimental even if nested KVM is
    /// exposed. Detection is a filesystem probe of standard install
    /// paths (Homebrew on macOS, distro packages on Linux); it does
    /// *not* guarantee the library will load cleanly or that we have
    /// the macOS hypervisor entitlement.
    pub fn has_libkrun(self) -> bool {
        if matches!(
            self,
            Platform::Windows | Platform::Wsl2 | Platform::LinuxNoKvm
        ) {
            return false;
        }
        #[cfg(all(target_os = "macos", not(target_arch = "aarch64")))]
        if matches!(self, Platform::MacOS) {
            return false;
        }
        // Filesystem probe — delegates to the canonical path list so
        // this probe and mvm_libkrun::install_paths() can never drift.
        LIBKRUN_LIB_PATHS.iter().any(|p| Path::new(p).exists())
    }

    /// Whether Cloud Hypervisor is installed on this host.
    ///
    /// CH is a peer of Firecracker at the Tier 1 microVM layer; it
    /// adds VFIO passthrough, virtio-gpu, virtio-fs, and larger
    /// guests beyond what FC supports. Detection is a PATH probe
    /// — `cloud-hypervisor --version` succeeding is sufficient.
    /// Linux/KVM is the supported host; macOS/HVF support exists
    /// upstream (CH 35+) but isn't yet exercised here.
    pub fn has_cloud_hypervisor(self) -> bool {
        // Windows has no CH path.
        if matches!(self, Platform::Windows) {
            return false;
        }
        static CH_AVAILABLE: OnceLock<bool> = OnceLock::new();
        *CH_AVAILABLE.get_or_init(|| {
            std::process::Command::new("cloud-hypervisor")
                .arg("--version")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        })
    }

    /// Whether Docker is available on this platform.
    ///
    /// Runtime check — calls `docker version` to verify the daemon is running.
    pub fn has_docker(self) -> bool {
        static DOCKER_AVAILABLE: OnceLock<bool> = OnceLock::new();
        *DOCKER_AVAILABLE.get_or_init(|| {
            std::process::Command::new("docker")
                .args(["version", "--format", "{{.Server.Version}}"])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        })
    }

    /// Whether Nix is available on the host and can build Linux targets.
    ///
    /// Host-side Nix is no longer the normal mvm build boundary; the
    /// project builder VM owns Nix eval/build work. This probe remains
    /// for direct debug paths and legacy callers only.
    pub fn has_host_nix(self) -> bool {
        static HOST_NIX: OnceLock<bool> = OnceLock::new();
        *HOST_NIX.get_or_init(|| {
            // Try PATH first
            if std::process::Command::new("nix")
                .args(["--version"])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
            {
                return true;
            }
            // Check common Nix install locations (freshly installed Nix may
            // not be on PATH if the shell profile hasn't been sourced yet)
            for path in &[
                "/nix/var/nix/profiles/default/bin/nix",
                "/run/current-system/sw/bin/nix",
            ] {
                if Path::new(path).exists() {
                    return true;
                }
            }
            false
        })
    }

    /// Whether this platform is WSL2.
    pub fn is_wsl(self) -> bool {
        matches!(self, Platform::Wsl2)
    }

    /// Whether this platform is native Windows.
    pub fn is_windows(self) -> bool {
        matches!(self, Platform::Windows)
    }
}

/// Pure probe of two candidate sysfs paths for nested-KVM. Lifted
/// out of [`Platform::has_nested_kvm`] so unit tests can drive it
/// with tempfile-backed paths instead of the real `/sys` tree.
///
/// Either path being enabled qualifies (Intel host has only the
/// `kvm_intel` node; AMD host has only `kvm_amd`). Intel exposes the
/// flag as `Y` / `N`; AMD as `1` / `0`. We accept either truthy
/// glyph on either path so the helper isn't picky about which
/// module's encoding lives where (the kernel has changed this in
/// the past).
fn has_nested_kvm_at(intel_path: &str, amd_path: &str) -> bool {
    fn read_enabled(path: &str) -> bool {
        match std::fs::read_to_string(path) {
            Ok(s) => {
                let trimmed = s.trim();
                trimmed.eq_ignore_ascii_case("Y") || trimmed == "1"
            }
            Err(_) => false,
        }
    }
    read_enabled(intel_path) || read_enabled(amd_path)
}

/// Check whether the current macOS version is 13.0 (Ventura) or later.
/// Plan 97 §"Minimum macOS version" — Vz's full virtio surface lands
/// here. macOS 11–12 fall back to libkrun.
fn is_macos_13_or_later() -> bool {
    #[cfg(target_os = "macos")]
    {
        macos_major_version() >= 13
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

/// Check whether the current macOS version is 26.0 or later.
fn is_macos_26_or_later() -> bool {
    #[cfg(target_os = "macos")]
    {
        if cfg!(not(target_arch = "aarch64")) {
            return false;
        }
        macos_major_version() >= 26
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

/// Read the macOS major version number via sysctl.
#[cfg(target_os = "macos")]
fn macos_major_version() -> u32 {
    use std::process::Command;
    Command::new("sw_vers")
        .arg("-productVersion")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|v| v.trim().split('.').next().map(String::from))
        .and_then(|major| major.parse::<u32>().ok())
        .unwrap_or(0)
}

/// Check if running inside WSL2 by reading /proc/version.
fn is_wsl2() -> bool {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/version")
            .map(|v| {
                let lower = v.to_lowercase();
                lower.contains("microsoft") || lower.contains("wsl")
            })
            .unwrap_or(false)
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Platform::MacOS => write!(f, "macOS"),
            Platform::LinuxNative => write!(f, "Linux (native KVM)"),
            Platform::LinuxNoKvm => write!(f, "Linux (no KVM)"),
            Platform::Wsl2 => {
                if self.has_kvm() {
                    write!(f, "WSL2 (nested KVM present; experimental)")
                } else {
                    write!(f, "WSL2 (unsupported)")
                }
            }
            Platform::Windows => write!(f, "Windows"),
        }
    }
}

/// Cached platform detection result.
static DETECTED: OnceLock<Platform> = OnceLock::new();

/// Detect the current platform. Result is cached after the first call.
pub fn current() -> Platform {
    *DETECTED.get_or_init(detect)
}

fn detect() -> Platform {
    if cfg!(target_os = "macos") {
        Platform::MacOS
    } else if cfg!(target_os = "linux") {
        if is_wsl2() {
            Platform::Wsl2
        } else if Path::new("/dev/kvm").exists() {
            Platform::LinuxNative
        } else {
            Platform::LinuxNoKvm
        }
    } else if cfg!(target_os = "windows") {
        Platform::Windows
    } else {
        // Unknown OS — try Docker as universal fallback
        Platform::LinuxNoKvm
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_returns_consistent_result() {
        let a = current();
        let b = current();
        assert_eq!(a, b);
    }

    // ── Plan 105 W1 — has_nested_kvm_at ──────────────────────────

    fn write_sysfs(dir: &std::path::Path, name: &str, contents: &str) -> std::path::PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn nested_kvm_intel_y_enabled() {
        let scratch = tempfile::tempdir().unwrap();
        let intel = write_sysfs(scratch.path(), "intel-nested", "Y\n");
        let amd_missing = scratch.path().join("amd-nested-missing");
        assert!(has_nested_kvm_at(
            intel.to_str().unwrap(),
            amd_missing.to_str().unwrap(),
        ));
    }

    #[test]
    fn nested_kvm_amd_1_enabled() {
        let scratch = tempfile::tempdir().unwrap();
        let intel_missing = scratch.path().join("intel-nested-missing");
        let amd = write_sysfs(scratch.path(), "amd-nested", "1\n");
        assert!(has_nested_kvm_at(
            intel_missing.to_str().unwrap(),
            amd.to_str().unwrap(),
        ));
    }

    #[test]
    fn nested_kvm_intel_n_disabled() {
        let scratch = tempfile::tempdir().unwrap();
        let intel = write_sysfs(scratch.path(), "intel-nested", "N\n");
        let amd_missing = scratch.path().join("amd-nested-missing");
        assert!(!has_nested_kvm_at(
            intel.to_str().unwrap(),
            amd_missing.to_str().unwrap(),
        ));
    }

    #[test]
    fn nested_kvm_amd_0_disabled() {
        let scratch = tempfile::tempdir().unwrap();
        let intel_missing = scratch.path().join("intel-nested-missing");
        let amd = write_sysfs(scratch.path(), "amd-nested", "0\n");
        assert!(!has_nested_kvm_at(
            intel_missing.to_str().unwrap(),
            amd.to_str().unwrap(),
        ));
    }

    #[test]
    fn nested_kvm_both_missing() {
        let scratch = tempfile::tempdir().unwrap();
        let intel = scratch.path().join("intel-nested-missing");
        let amd = scratch.path().join("amd-nested-missing");
        assert!(!has_nested_kvm_at(
            intel.to_str().unwrap(),
            amd.to_str().unwrap(),
        ));
    }

    #[test]
    fn nested_kvm_lowercase_y_accepted() {
        // Defence in depth — `eq_ignore_ascii_case` accepts `y` too.
        let scratch = tempfile::tempdir().unwrap();
        let intel = write_sysfs(scratch.path(), "intel-nested", "y");
        let amd_missing = scratch.path().join("amd-nested-missing");
        assert!(has_nested_kvm_at(
            intel.to_str().unwrap(),
            amd_missing.to_str().unwrap(),
        ));
    }

    #[test]
    fn test_platform_display() {
        assert_eq!(Platform::LinuxNative.to_string(), "Linux (native KVM)");
        assert_eq!(Platform::LinuxNoKvm.to_string(), "Linux (no KVM)");
        assert_eq!(Platform::Windows.to_string(), "Windows");
    }

    #[test]
    fn test_has_kvm() {
        assert!(!Platform::MacOS.has_kvm());
        assert!(Platform::LinuxNative.has_kvm());
        assert!(!Platform::LinuxNoKvm.has_kvm());
        assert!(!Platform::Windows.has_kvm());
    }

    #[test]
    fn test_supports_native_runner() {
        assert!(!Platform::MacOS.supports_native_runner());
        assert!(Platform::LinuxNative.supports_native_runner());
        assert!(!Platform::LinuxNoKvm.supports_native_runner());
        assert!(!Platform::Wsl2.supports_native_runner());
        assert!(!Platform::Windows.supports_native_runner());
    }

    #[test]
    fn test_has_vz_false_on_non_macos() {
        assert!(!Platform::LinuxNative.has_vz());
        assert!(!Platform::LinuxNoKvm.has_vz());
        assert!(!Platform::Wsl2.has_vz());
        assert!(!Platform::Windows.has_vz());
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_has_vz_true_on_macos_13_or_later() {
        // Whether Vz reports available on this *contributor host*
        // depends on the actual macOS version. macOS 13+ → true;
        // 11–12 → false. The probe is the source of truth — we
        // assert it agrees with the underlying version check rather
        // than hard-coding a result that would diverge across CI
        // matrix rows.
        let plat = Platform::MacOS;
        let expected = macos_major_version() >= 13;
        assert_eq!(plat.has_vz(), expected);
    }

    #[test]
    fn test_has_apple_containers_non_macos() {
        assert!(!Platform::LinuxNative.has_apple_containers());
        assert!(!Platform::LinuxNoKvm.has_apple_containers());
        assert!(!Platform::Wsl2.has_apple_containers());
        assert!(!Platform::Windows.has_apple_containers());
    }

    #[test]
    fn test_has_libkrun_returns_false_on_windows_regardless_of_filesystem() {
        // Windows: libkrun has no Windows port. Always false irrespective
        // of what `mvm_libkrun::is_available()` would say.
        assert!(!Platform::Windows.has_libkrun());
    }

    #[test]
    fn test_has_libkrun_returns_bool_without_panic() {
        // Probe is a filesystem check — result depends on host install state.
        // Asserts it doesn't panic and returns false on unsupported platforms.
        let plat = current();
        let result = plat.has_libkrun();
        if matches!(
            plat,
            Platform::Windows | Platform::Wsl2 | Platform::LinuxNoKvm
        ) {
            assert!(!result, "has_libkrun must be false on {plat:?}");
        }
        // On macOS / LinuxNative: depends on whether libkrun is installed.
    }

    #[test]
    fn test_has_docker_returns_bool() {
        // Just verify it doesn't panic; result depends on environment
        let _ = Platform::MacOS.has_docker();
    }

    #[test]
    fn test_current_platform_valid() {
        let p = current();
        let _ = p.has_kvm();
        let _ = p.supports_native_runner();
        let _ = p.has_apple_containers();
        let _ = p.has_docker();
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_macos_major_version_is_reasonable() {
        let version = macos_major_version();
        assert!(version >= 10, "macOS version {version} seems too low");
    }
}
