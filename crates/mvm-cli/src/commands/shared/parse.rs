//! Argument parsers — clap value parsers and post-parse domain converters.

use anyhow::{Context, Result};

use mvm_runtime::vm::image;

/// Validate a VM name at Clap parse time.
pub fn clap_vm_name(s: &str) -> Result<String, String> {
    mvm_core::naming::validate_vm_name(s).map_err(|e| e.to_string())?;
    Ok(s.to_owned())
}

/// Validate a Nix flake reference at Clap parse time.
pub fn clap_flake_ref(s: &str) -> Result<String, String> {
    mvm_core::naming::validate_flake_ref(s).map_err(|e| e.to_string())?;
    Ok(s.to_owned())
}

/// Validate a port spec (`PORT` or `HOST:GUEST`) at Clap parse time.
pub fn clap_port_spec(s: &str) -> Result<String, String> {
    if s.is_empty() {
        return Err("port spec must not be empty".to_owned());
    }
    if let Some((host_part, guest_part)) = s.split_once(':') {
        host_part
            .parse::<u16>()
            .map_err(|_| format!("invalid host port {:?} in {:?}", host_part, s))?;
        guest_part
            .parse::<u16>()
            .map_err(|_| format!("invalid guest port {:?} in {:?}", guest_part, s))?;
    } else {
        s.parse::<u16>()
            .map_err(|_| format!("invalid port {:?} — expected PORT or HOST:GUEST", s))?;
    }
    Ok(s.to_owned())
}

/// Validate a volume spec (`host:/guest` or `host:/guest:size`) at Clap parse time.
pub fn clap_volume_spec(s: &str) -> Result<String, String> {
    if s.is_empty() {
        return Err("volume spec must not be empty".to_owned());
    }
    let parts: Vec<&str> = s.splitn(3, ':').collect();
    if parts.len() < 2 || parts[0].is_empty() || parts[1].is_empty() {
        return Err(format!(
            "invalid volume {:?} — expected host:/guest or host:/guest:size",
            s
        ));
    }
    Ok(s.to_owned())
}

/// Parse a port spec like `3000` or `8080:3000` into `(local, guest)`.
pub fn parse_port_spec(spec: &str) -> Result<(u16, u16)> {
    if let Some((local, guest)) = spec.split_once(':') {
        let local: u16 = local
            .parse()
            .with_context(|| format!("invalid local port '{}'", local))?;
        let guest: u16 = guest
            .parse()
            .with_context(|| format!("invalid guest port '{}'", guest))?;
        Ok((local, guest))
    } else {
        let port: u16 = spec
            .parse()
            .with_context(|| format!("invalid port '{}'", spec))?;
        Ok((port, port))
    }
}

/// Parse multiple port specs into `PortMapping` values.
pub fn parse_port_specs(specs: &[String]) -> Result<Vec<mvm_runtime::config::PortMapping>> {
    specs
        .iter()
        .map(|s| {
            let (host, guest) = parse_port_spec(s)?;
            Ok(mvm_runtime::config::PortMapping { host, guest })
        })
        .collect()
}

/// Parsed volume specification from the `--volume/-v` CLI flag.
pub enum VolumeSpec {
    /// Inject host directory contents onto a drive (2-part: `host_dir:/guest/path`).
    DirInject {
        host_dir: String,
        guest_mount: String,
    },
    /// Persistent ext4 volume with explicit size (3-part: `host:/guest/path:size`).
    Persistent(image::RuntimeVolume),
}

pub fn parse_volume_spec(spec: &str) -> Result<VolumeSpec> {
    let parts: Vec<&str> = spec.splitn(3, ':').collect();
    match parts.len() {
        2 => Ok(VolumeSpec::DirInject {
            host_dir: parts[0].to_string(),
            guest_mount: parts[1].to_string(),
        }),
        3 => Ok(VolumeSpec::Persistent(image::RuntimeVolume {
            host: parts[0].to_string(),
            guest: parts[1].to_string(),
            size: parts[2].to_string(),
            read_only: false,
        })),
        _ => anyhow::bail!(
            "Invalid volume '{}'. Expected host_dir:/guest/path or host:/guest/path:size",
            spec
        ),
    }
}
