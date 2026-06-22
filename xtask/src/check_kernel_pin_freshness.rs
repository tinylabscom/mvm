//! `xtask check-kernel-pin-freshness [--quiet]`
//!
//! The I/O shell around [`mvm_core::kernel_advisory`]: read mvm's local kernel
//! pins, fetch the latest upstream point releases, assess, emit the
//! `KernelAdvisory` as JSON on stdout, and exit nonzero when a bump is
//! recommended. The comparison logic is pure + unit-tested in mvm-core; this
//! file does the reading/fetching and is offline-tolerant (a fetch failure
//! yields no upstream data → `Unknown`, never a false "up to date").

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

use anyhow::{Result, bail};
use mvm_core::kernel_advisory::{KernelPin, UpstreamReleases, assess};
use regex::Regex;

pub fn run(workspace: &Path, args: &[String]) -> Result<()> {
    let quiet = args.iter().any(|a| a == "--quiet");
    let pins = read_local_pins(workspace);
    if pins.is_empty() {
        bail!(
            "check-kernel-pin-freshness: found no kernel pins to assess (expected at least the libkrunfw pin in nix/packages/libkrunfw.nix)"
        );
    }
    let upstream = fetch_upstream_releases();
    let advisory = assess(&pins, &upstream);

    println!("{}", serde_json::to_string_pretty(&advisory)?);

    if !quiet {
        eprintln!(
            "check-kernel-pin-freshness: {} pin(s); worst = {:?}; action_recommended = {}",
            advisory.pins.len(),
            advisory.worst,
            advisory.action_recommended
        );
    }
    if advisory.action_recommended {
        // Nonzero so the PR/CI gate fails when a pin lands still behind.
        std::process::exit(1);
    }
    Ok(())
}

/// Read every kernel pin mvm carries. The libkrunfw pin is a deterministic
/// file read; the nixpkgs `linux_6_12` version needs a Nix eval and is
/// best-effort (skipped, not failed, when Nix is unavailable).
fn read_local_pins(workspace: &Path) -> Vec<KernelPin> {
    let mut pins = Vec::new();
    let libkrunfw = workspace.join("nix/packages/libkrunfw.nix");
    if let Ok(content) = std::fs::read_to_string(&libkrunfw)
        && let Some(version) = parse_libkrunfw_pin(&content)
    {
        pins.push(KernelPin {
            name: "libkrunfw".into(),
            version,
        });
    }
    if let Some(version) = eval_nixpkgs_linux_version(workspace) {
        pins.push(KernelPin {
            name: "nixpkgs-linux_6_12".into(),
            version,
        });
    }
    pins
}

/// Extract `6.12.91` from libkrunfw's pinned tarball URL
/// (`…/linux-6.12.91.tar.xz`).
fn parse_libkrunfw_pin(content: &str) -> Option<String> {
    let re = Regex::new(r"linux-(\d+\.\d+\.\d+)\.tar").ok()?;
    re.captures(content).map(|c| c[1].to_string())
}

/// Best-effort: the kernel package inherits `version` from `pkgs.linux_6_12`,
/// so eval it from the standalone kernel flake. Returns `None` (skip the pin)
/// on any Nix/eval failure rather than erroring.
fn eval_nixpkgs_linux_version(workspace: &Path) -> Option<String> {
    let arch = if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "x86_64"
    };
    let flake = format!("{}/nix/images/kernel", workspace.display());
    let attr = format!("packages.{arch}-linux.workload-vmlinux.version");
    let out = Command::new("nix")
        .args([
            "eval",
            "--raw",
            "--extra-experimental-features",
            "nix-command flakes",
            &format!("{flake}#{attr}"),
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let v = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!v.is_empty() && split_version(&v).is_some()).then_some(v)
}

/// Fetch kernel.org's release list. Offline-tolerant: any failure yields an
/// empty snapshot so every pin assesses as `Unknown` (never a false
/// up-to-date).
fn fetch_upstream_releases() -> UpstreamReleases {
    let out = Command::new("curl")
        .args(["-sSfL", "https://www.kernel.org/releases.json"])
        .output();
    match out {
        Ok(o) if o.status.success() => parse_releases_json(&String::from_utf8_lossy(&o.stdout)),
        _ => {
            eprintln!(
                "check-kernel-pin-freshness: could not fetch kernel.org releases (offline?); \
                 pins will assess as Unknown"
            );
            UpstreamReleases::default()
        }
    }
}

/// Reduce kernel.org `releases.json` to the latest `MAJOR.MINOR.PATCH` per
/// series. Non-point releases (`6.16-rc1`, mainline) are ignored.
fn parse_releases_json(json: &str) -> UpstreamReleases {
    let mut latest_by_series: BTreeMap<String, String> = BTreeMap::new();
    let Ok(value) = serde_json::from_str::<serde_json::Value>(json) else {
        return UpstreamReleases::default();
    };
    let Some(releases) = value.get("releases").and_then(|r| r.as_array()) else {
        return UpstreamReleases::default();
    };
    for rel in releases {
        let Some(ver) = rel.get("version").and_then(|v| v.as_str()) else {
            continue;
        };
        let Some((series, patch)) = split_version(ver) else {
            continue; // rc / mainline / malformed
        };
        match latest_by_series.get(&series) {
            Some(existing) if split_version(existing).map(|(_, p)| p) >= Some(patch) => {}
            _ => {
                latest_by_series.insert(series, ver.to_string());
            }
        }
    }
    UpstreamReleases { latest_by_series }
}

/// `MAJOR.MINOR.PATCH` → (`"MAJOR.MINOR"`, PATCH). Any non-numeric component
/// (an `-rc` suffix, a missing field) fails the parse.
fn split_version(v: &str) -> Option<(String, u32)> {
    let mut parts = v.split('.');
    let major: u32 = parts.next()?.parse().ok()?;
    let minor: u32 = parts.next()?.parse().ok()?;
    let patch: u32 = parts.next()?.parse().ok()?;
    Some((format!("{major}.{minor}"), patch))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_libkrunfw_tarball_version() {
        let s = r#"    url = "mirror://kernel/linux/kernel/v6.x/linux-6.12.91.tar.xz";"#;
        assert_eq!(parse_libkrunfw_pin(s), Some("6.12.91".to_string()));
    }

    #[test]
    fn libkrunfw_pin_none_when_absent() {
        assert_eq!(parse_libkrunfw_pin("no kernel url here"), None);
    }

    #[test]
    fn releases_json_keeps_latest_point_release_per_series() {
        let json = r#"{"releases":[
            {"moniker":"longterm","version":"6.12.95"},
            {"moniker":"longterm","version":"6.6.100"},
            {"moniker":"stable","version":"6.15.3"},
            {"moniker":"mainline","version":"6.16-rc1"}
        ]}"#;
        let up = parse_releases_json(json);
        assert_eq!(
            up.latest_by_series.get("6.12").map(String::as_str),
            Some("6.12.95")
        );
        assert_eq!(
            up.latest_by_series.get("6.6").map(String::as_str),
            Some("6.6.100")
        );
        assert_eq!(
            up.latest_by_series.get("6.15").map(String::as_str),
            Some("6.15.3")
        );
        // rc / mainline excluded
        assert!(!up.latest_by_series.contains_key("6.16"));
    }

    #[test]
    fn releases_json_picks_highest_patch_when_duplicated() {
        let json = r#"{"releases":[
            {"moniker":"longterm","version":"6.12.80"},
            {"moniker":"longterm","version":"6.12.95"}
        ]}"#;
        let up = parse_releases_json(json);
        assert_eq!(
            up.latest_by_series.get("6.12").map(String::as_str),
            Some("6.12.95")
        );
    }

    #[test]
    fn malformed_json_yields_empty_not_panic() {
        assert!(parse_releases_json("not json").latest_by_series.is_empty());
        assert!(parse_releases_json("{}").latest_by_series.is_empty());
    }
}
