//! Package-manager provider abstractions.

use std::path::Path;
use std::process::Command;

/// Trait for querying native package ownership and installed versions.
pub trait PackageProvider: Send + Sync {
    /// Package-manager short name (e.g. `"dpkg"`, `"rpm"`).
    fn name(&self) -> &'static str;

    /// Return the package that owns `path`, if any.
    fn owner_of(&self, path: &Path) -> Option<PackageRecord>;

    /// Return the installed version of `package_name`, if any.
    fn version_of(&self, package_name: &str) -> Option<String>;
}

/// Package ownership record returned by a provider.
#[derive(Clone, Debug)]
pub struct PackageRecord {
    pub name: String,
    pub version: Option<String>,
}

/// All built-in providers, tried in order on Linux hosts.
pub fn all_providers() -> Vec<Box<dyn PackageProvider>> {
    vec![
        Box::new(DpkgProvider),
        Box::new(RpmProvider),
        Box::new(PacmanProvider),
        Box::new(ApkProvider),
        Box::new(NixIndexProvider),
    ]
}

/// Debian/Ubuntu provider using `dpkg` and `dpkg-query`.
pub struct DpkgProvider;

impl PackageProvider for DpkgProvider {
    fn name(&self) -> &'static str {
        "dpkg"
    }

    fn owner_of(&self, path: &Path) -> Option<PackageRecord> {
        let output = Command::new("dpkg").arg("-S").arg(path).output().ok()?;
        if !output.status.success() {
            return None;
        }
        let text = String::from_utf8_lossy(&output.stdout);
        parse_dpkg_owner(&text).map(|name| PackageRecord {
            name: name.to_owned(),
            version: None,
        })
    }

    fn version_of(&self, package_name: &str) -> Option<String> {
        let output = Command::new("dpkg-query")
            .args(["-W", "-f=${Version}", package_name])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let text = String::from_utf8_lossy(&output.stdout);
        parse_dpkg_version(&text).map(str::to_owned)
    }
}

fn parse_dpkg_owner(output: &str) -> Option<&str> {
    let first = output.lines().next()?;
    let package_part = first.split(':').next()?.trim();
    package_part.split(',').next().map(str::trim)
}

fn parse_dpkg_version(output: &str) -> Option<&str> {
    let trimmed = output.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

/// RPM-based provider (Fedora, RHEL, openSUSE).
pub struct RpmProvider;

impl PackageProvider for RpmProvider {
    fn name(&self) -> &'static str {
        "rpm"
    }

    fn owner_of(&self, _path: &Path) -> Option<PackageRecord> {
        None
    }

    fn version_of(&self, _package_name: &str) -> Option<String> {
        None
    }
}

/// Pacman-based provider (Arch, Manjaro).
pub struct PacmanProvider;

impl PackageProvider for PacmanProvider {
    fn name(&self) -> &'static str {
        "pacman"
    }

    fn owner_of(&self, _path: &Path) -> Option<PackageRecord> {
        None
    }

    fn version_of(&self, _package_name: &str) -> Option<String> {
        None
    }
}

/// APK-based provider (Alpine Linux).
pub struct ApkProvider;

impl PackageProvider for ApkProvider {
    fn name(&self) -> &'static str {
        "apk"
    }

    fn owner_of(&self, _path: &Path) -> Option<PackageRecord> {
        None
    }

    fn version_of(&self, _package_name: &str) -> Option<String> {
        None
    }
}

/// Optional `nix-index` provider that maps a store path to a nixpkgs
/// attribute. Tried only after native package managers return no match.
pub struct NixIndexProvider;

impl PackageProvider for NixIndexProvider {
    fn name(&self) -> &'static str {
        "nix-index"
    }

    fn owner_of(&self, path: &Path) -> Option<PackageRecord> {
        let output = Command::new("nix-locate")
            .args(["--minimal", "--top-level", "-w"])
            .arg(path)
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let text = String::from_utf8_lossy(&output.stdout);
        parse_nix_index_output(&text).map(|attr| PackageRecord {
            name: attr.to_owned(),
            version: None,
        })
    }

    fn version_of(&self, _package_name: &str) -> Option<String> {
        None
    }
}

fn parse_nix_index_output(output: &str) -> Option<&str> {
    output
        .lines()
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_dpkg_owner_extracts_first_package() {
        assert_eq!(
            parse_dpkg_owner("libc6: /lib/x86_64-linux-gnu/libc.so.6"),
            Some("libc6")
        );
    }

    #[test]
    fn parse_dpkg_owner_handles_comma_separated_packages() {
        assert_eq!(parse_dpkg_owner("pkg-a, pkg-b: /some/file"), Some("pkg-a"));
    }

    #[test]
    fn parse_dpkg_owner_empty_output_returns_none() {
        assert_eq!(parse_dpkg_owner(""), None);
    }

    #[test]
    fn parse_dpkg_version_trims_whitespace() {
        assert_eq!(
            parse_dpkg_version("  2.31-13+deb11u5  "),
            Some("2.31-13+deb11u5")
        );
    }

    #[test]
    fn parse_dpkg_version_empty_returns_none() {
        assert_eq!(parse_dpkg_version("   "), None);
    }

    #[test]
    fn all_providers_contains_expected_names() {
        let names: Vec<_> = all_providers().iter().map(|p| p.name()).collect();
        assert_eq!(names, vec!["dpkg", "rpm", "pacman", "apk", "nix-index"]);
    }

    #[test]
    fn parse_nix_index_output_takes_first_attribute() {
        assert_eq!(parse_nix_index_output("hello.out\n"), Some("hello.out"));
    }

    #[test]
    fn parse_nix_index_output_empty_returns_none() {
        assert_eq!(parse_nix_index_output("\n   \n"), None);
    }
}
