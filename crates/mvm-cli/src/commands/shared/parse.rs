//! Clap value parsers and client-owned launch input specifications.

use anyhow::Result;

pub use mvm_client::mounts::*;

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
