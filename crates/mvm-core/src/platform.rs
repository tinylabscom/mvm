use std::path::Path;
use std::sync::OnceLock;

/// The execution environment for running Firecracker workloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// macOS — requires Lima VM for nested virtualization
    MacOS,
    /// Native Linux with /dev/kvm available — run directly on host
    LinuxNative,
    /// Linux without /dev/kvm — requires Lima VM (e.g., WSL2 without KVM)
    LinuxNoKvm,
}

impl Platform {
    /// Whether this platform needs Lima to run Firecracker.
    pub fn needs_lima(self) -> bool {
        match self {
            Platform::MacOS | Platform::LinuxNoKvm => true,
            Platform::LinuxNative => false,
        }
    }

    /// Whether this platform can run Firecracker directly.
    pub fn has_kvm(self) -> bool {
        matches!(self, Platform::LinuxNative)
    }

    /// Whether the microvm.nix runner can execute natively (without Lima).
    ///
    /// On native Linux with KVM, the runner scripts execute directly.
    /// On macOS or Linux without KVM, they are routed through Lima
    /// via the [`LinuxEnv`] abstraction.
    pub fn supports_native_runner(self) -> bool {
        matches!(self, Platform::LinuxNative)
    }
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Platform::MacOS => write!(f, "macOS (via Lima)"),
            Platform::LinuxNative => write!(f, "Linux (native KVM)"),
            Platform::LinuxNoKvm => write!(f, "Linux (via Lima, no KVM)"),
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
        if Path::new("/dev/kvm").exists() {
            Platform::LinuxNative
        } else {
            Platform::LinuxNoKvm
        }
    } else {
        // Unsupported OS — fall back to Lima-based approach
        Platform::MacOS
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
        assert_eq!(Platform::MacOS.to_string(), "macOS (via Lima)");
        assert_eq!(Platform::LinuxNative.to_string(), "Linux (native KVM)");
        assert_eq!(Platform::LinuxNoKvm.to_string(), "Linux (via Lima, no KVM)");
    }

    #[test]
    fn test_needs_lima() {
        assert!(Platform::MacOS.needs_lima());
        assert!(!Platform::LinuxNative.needs_lima());
        assert!(Platform::LinuxNoKvm.needs_lima());
    }

    #[test]
    fn test_has_kvm() {
        assert!(!Platform::MacOS.has_kvm());
        assert!(Platform::LinuxNative.has_kvm());
        assert!(!Platform::LinuxNoKvm.has_kvm());
    }

    #[test]
    fn test_supports_native_runner() {
        assert!(!Platform::MacOS.supports_native_runner());
        assert!(Platform::LinuxNative.supports_native_runner());
        assert!(!Platform::LinuxNoKvm.supports_native_runner());
    }

    #[test]
    fn test_current_platform_valid() {
        let p = current();
        // On any platform, we should get a valid result
        let _ = p.needs_lima();
        let _ = p.has_kvm();
        let _ = p.supports_native_runner();
    }
}
