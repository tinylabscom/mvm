use std::path::Path;
use std::sync::OnceLock;

/// The execution environment for running workloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// macOS — Apple Virtualization.framework on 26+, Lima fallback on older
    MacOS,
    /// Native Linux with /dev/kvm available — run Firecracker directly
    LinuxNative,
    /// Linux without /dev/kvm (not WSL) — requires Lima or Docker
    LinuxNoKvm,
    /// WSL2 — may have KVM (Hyper-V nested virt), prefers Docker as fallback
    Wsl2,
    /// Native Windows — Docker only (no Linux kernel)
    Windows,
}

impl Platform {
    /// Whether this platform needs Lima to run Firecracker.
    /// Returns false for platforms that have better alternatives (Apple VZ, Docker, native KVM).
    pub fn needs_lima(self) -> bool {
        match self {
            Platform::MacOS => !self.has_apple_containers(),
            Platform::LinuxNoKvm => true,
            Platform::LinuxNative => false,
            Platform::Wsl2 => !self.has_kvm() && !self.has_docker(),
            Platform::Windows => false, // Lima doesn't run on Windows
        }
    }

    /// Whether this platform can run Firecracker directly via /dev/kvm.
    pub fn has_kvm(self) -> bool {
        match self {
            Platform::LinuxNative => true,
            Platform::Wsl2 => Path::new("/dev/kvm").exists(),
            _ => false,
        }
    }

    /// Whether the microvm.nix runner can execute natively (without Lima).
    pub fn supports_native_runner(self) -> bool {
        matches!(self, Platform::LinuxNative) || (matches!(self, Platform::Wsl2) && self.has_kvm())
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
    /// On macOS this requires nix-daemon with a linux-builder configured.
    /// On native Linux this is always true if `nix` is on PATH.
    /// When true, `nix build` can run on the host without Lima.
    pub fn has_host_nix(self) -> bool {
        static HOST_NIX: OnceLock<bool> = OnceLock::new();
        *HOST_NIX.get_or_init(|| {
            std::process::Command::new("nix")
                .args(["--version"])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
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
                    write!(f, "WSL2 (KVM available)")
                } else {
                    write!(f, "WSL2")
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

    #[test]
    fn test_platform_display() {
        assert_eq!(Platform::LinuxNative.to_string(), "Linux (native KVM)");
        assert_eq!(Platform::LinuxNoKvm.to_string(), "Linux (no KVM)");
        assert_eq!(Platform::Windows.to_string(), "Windows");
    }

    #[test]
    fn test_needs_lima() {
        // macOS: needs Lima only if Apple Containers are NOT available
        let macos_needs = Platform::MacOS.needs_lima();
        if Platform::MacOS.has_apple_containers() {
            assert!(!macos_needs, "macOS 26+ should not need Lima");
        } else {
            assert!(macos_needs, "macOS <26 should need Lima");
        }
        assert!(!Platform::LinuxNative.needs_lima());
        assert!(Platform::LinuxNoKvm.needs_lima());
        assert!(!Platform::Windows.needs_lima());
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
        assert!(!Platform::Windows.supports_native_runner());
    }

    #[test]
    fn test_has_apple_containers_non_macos() {
        assert!(!Platform::LinuxNative.has_apple_containers());
        assert!(!Platform::LinuxNoKvm.has_apple_containers());
        assert!(!Platform::Wsl2.has_apple_containers());
        assert!(!Platform::Windows.has_apple_containers());
    }

    #[test]
    fn test_has_docker_returns_bool() {
        // Just verify it doesn't panic; result depends on environment
        let _ = Platform::MacOS.has_docker();
    }

    #[test]
    fn test_current_platform_valid() {
        let p = current();
        let _ = p.needs_lima();
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
