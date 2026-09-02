//! `mvmctl cp` — copy one file between the host and a running VM.

use anyhow::{Context, Result, bail};
use clap::Args as ClapArgs;
use serde::Serialize;
use std::io::Write;
use std::path::{Path, PathBuf};

use mvm_agentd::vsock::{FsResult, GuestRequest};
use mvm_core::naming::validate_vm_name;
use mvm_core::user_config::MvmConfig;

use super::Cli;

const DEFAULT_MAX_BYTES: u64 = 16 * 1024 * 1024;
const DEFAULT_MODE: u32 = 0o644;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Source endpoint. Remote endpoints use `VM:/absolute/path`.
    pub source: String,
    /// Destination endpoint. Remote endpoints use `VM:/absolute/path`.
    pub destination: String,
    /// Overwrite the destination if it already exists.
    #[arg(long, short)]
    pub force: bool,
    /// Create destination parent directories.
    #[arg(long, short = 'p')]
    pub create_parents: bool,
    /// Maximum bytes to copy. Defaults to 16 MiB.
    #[arg(long, default_value_t = DEFAULT_MAX_BYTES)]
    pub max_bytes: u64,
    /// Print a machine-readable copy summary as JSON.
    ///
    /// The summary omits host paths and file contents; it includes only the
    /// guest path, direction, byte count, and copy options.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Endpoint {
    Host(PathBuf),
    Guest { vm: String, path: String },
}

#[derive(Debug, Clone, Serialize)]
struct CopySummary {
    schema_version: u32,
    direction: CopyDirection,
    vm: String,
    guest_path: String,
    bytes_copied: u64,
    force: bool,
    create_parents: bool,
    max_bytes: u64,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum CopyDirection {
    HostToGuest,
    GuestToHost,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let source = parse_endpoint(&args.source)?;
    let destination = parse_endpoint(&args.destination)?;
    let summary = match (&source, &destination) {
        (Endpoint::Host(host), Endpoint::Guest { vm, path }) => {
            copy_host_to_guest(host, vm, path, &args)
        }
        (Endpoint::Guest { vm, path }, Endpoint::Host(host)) => {
            copy_guest_to_host(vm, path, host, &args)
        }
        (Endpoint::Guest { .. }, Endpoint::Guest { .. }) => {
            bail!(
                "mvmctl machine cp supports exactly one VM endpoint; use `mvmctl machine fs mv` inside one VM"
            )
        }
        (Endpoint::Host(_), Endpoint::Host(_)) => {
            bail!("mvmctl machine cp requires one endpoint in `VM:/absolute/path` form")
        }
    }?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        match (&source, &destination) {
            (Endpoint::Host(_), Endpoint::Guest { .. }) => {
                eprintln!(
                    "copied {} bytes to {}:{}",
                    summary.bytes_copied, summary.vm, summary.guest_path
                );
            }
            (Endpoint::Guest { .. }, Endpoint::Host(host)) => {
                eprintln!(
                    "copied {} bytes to {}",
                    summary.bytes_copied,
                    host.display()
                );
            }
            _ => unreachable!("endpoint shape validated before copy"),
        }
    }
    Ok(())
}

fn copy_host_to_guest(host: &Path, vm: &str, guest_path: &str, args: &Args) -> Result<CopySummary> {
    let meta = std::fs::metadata(host)
        .with_context(|| format!("Failed to stat host source {}", host.display()))?;
    if !meta.is_file() {
        bail!("Host source {} is not a regular file", host.display());
    }
    if meta.len() > args.max_bytes {
        bail!(
            "Host source {} is {} bytes, above --max-bytes {}",
            host.display(),
            meta.len(),
            args.max_bytes
        );
    }
    let content = std::fs::read(host)
        .with_context(|| format!("Failed to read host source {}", host.display()))?;
    if !args.force && guest_exists(vm, guest_path)? {
        bail!("Guest destination {vm}:{guest_path} exists; pass --force to overwrite");
    }
    let bytes_written = super::fs::write_guest_chunks(
        vm,
        guest_path,
        &content,
        DEFAULT_MODE,
        args.create_parents,
        false,
    )?;
    mvm_core::audit_emit!(
        VmFileCopy,
        vm: vm,
        "direction=host_to_guest path={guest_path} bytes={bytes_written}"
    );
    Ok(CopySummary::new(
        CopyDirection::HostToGuest,
        vm,
        guest_path,
        bytes_written,
        args,
    ))
}

fn copy_guest_to_host(vm: &str, guest_path: &str, host: &Path, args: &Args) -> Result<CopySummary> {
    let stat = guest_stat(vm, guest_path)?;
    if !matches!(stat.kind, mvm_agentd::vsock::FsEntryKind::File) {
        bail!("Guest source {vm}:{guest_path} is not a regular file");
    }
    if stat.size > args.max_bytes {
        bail!(
            "Guest source {vm}:{guest_path} is {} bytes, above --max-bytes {}",
            stat.size,
            args.max_bytes
        );
    }
    if host.exists() && !args.force {
        bail!(
            "Host destination {} exists; pass --force to overwrite",
            host.display()
        );
    }
    if args.create_parents
        && let Some(parent) = host.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "Failed to create host destination parent {}",
                parent.display()
            )
        })?;
    }
    let content = super::fs::read_guest_chunks(vm, guest_path, 0, stat.size)?;
    let content_len = u64::try_from(content.len()).expect("content length fits u64");
    if content_len != stat.size {
        bail!(
            "Guest read returned {} bytes, expected {}",
            content.len(),
            stat.size
        );
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true);
    if args.force {
        options.truncate(true);
    } else {
        options.create_new(true);
    }
    let mut file = options
        .open(host)
        .with_context(|| format!("Failed to open host destination {}", host.display()))?;
    file.write_all(&content)
        .with_context(|| format!("Failed to write host destination {}", host.display()))?;
    mvm_core::audit_emit!(
        VmFileCopy,
        vm: vm,
        "direction=guest_to_host path={guest_path} bytes={content_len}"
    );
    Ok(CopySummary::new(
        CopyDirection::GuestToHost,
        vm,
        guest_path,
        content_len,
        args,
    ))
}

impl CopySummary {
    fn new(
        direction: CopyDirection,
        vm: &str,
        guest_path: &str,
        bytes_copied: u64,
        args: &Args,
    ) -> Self {
        Self {
            schema_version: 1,
            direction,
            vm: vm.to_string(),
            guest_path: guest_path.to_string(),
            bytes_copied,
            force: args.force,
            create_parents: args.create_parents,
            max_bytes: args.max_bytes,
        }
    }
}

fn parse_endpoint(raw: &str) -> Result<Endpoint> {
    if let Some((vm, path)) = raw.split_once(':')
        && !vm.is_empty()
        && path.starts_with('/')
    {
        validate_vm_name(vm).with_context(|| format!("Invalid VM name: {:?}", vm))?;
        return Ok(Endpoint::Guest {
            vm: vm.to_string(),
            path: path.to_string(),
        });
    }
    Ok(Endpoint::Host(PathBuf::from(raw)))
}

fn guest_exists(vm: &str, path: &str) -> Result<bool> {
    let req = GuestRequest::FsStat {
        path: path.to_string(),
        follow_symlinks: false,
    };
    // Inbound vsock RPC audit.
    super::shared::emit_vsock_rpc_audit(vm, &req);
    match super::fs::fs_request(vm, req)? {
        FsResult::Stat(_) => Ok(true),
        FsResult::Error {
            kind: mvm_agentd::vsock::FsErrorKind::NotFound,
            ..
        } => Ok(false),
        FsResult::Error { kind, message } => bail!("Guest FS error ({:?}): {}", kind, message),
        other => bail!("Unexpected FsResult variant for Stat: {:?}", other),
    }
}

fn guest_stat(vm: &str, path: &str) -> Result<mvm_agentd::vsock::FsStat> {
    let req = GuestRequest::FsStat {
        path: path.to_string(),
        follow_symlinks: true,
    };
    // Inbound vsock RPC audit.
    super::shared::emit_vsock_rpc_audit(vm, &req);
    match unwrap_fs(super::fs::fs_request(vm, req)?)? {
        FsResult::Stat(stat) => Ok(stat),
        other => bail!("Unexpected FsResult variant for Stat: {:?}", other),
    }
}

fn unwrap_fs(result: FsResult) -> Result<FsResult> {
    if let FsResult::Error { kind, message } = &result {
        bail!("Guest FS error ({:?}): {}", kind, message);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_endpoint_accepts_guest_absolute_path() {
        assert_eq!(
            parse_endpoint("vm1:/tmp/file").expect("parse"),
            Endpoint::Guest {
                vm: "vm1".to_string(),
                path: "/tmp/file".to_string(),
            }
        );
    }

    #[test]
    fn parse_endpoint_treats_relative_colon_path_as_host_path() {
        assert_eq!(
            parse_endpoint("notes:today.txt").expect("parse"),
            Endpoint::Host(PathBuf::from("notes:today.txt"))
        );
    }

    #[test]
    fn parse_endpoint_rejects_invalid_vm_name() {
        assert!(parse_endpoint("BadName:/tmp/file").is_err());
    }

    #[test]
    fn copy_summary_omits_host_paths() {
        let args = Args {
            source: "/private/source.txt".to_string(),
            destination: "vm1:/tmp/source.txt".to_string(),
            force: true,
            create_parents: true,
            max_bytes: 4096,
            json: true,
        };
        let summary = CopySummary::new(
            CopyDirection::HostToGuest,
            "vm1",
            "/tmp/source.txt",
            12,
            &args,
        );
        let json = serde_json::to_string(&summary).expect("json");

        assert!(json.contains("host_to_guest"));
        assert!(json.contains("/tmp/source.txt"));
        assert!(!json.contains("/private/source.txt"));
    }
}
