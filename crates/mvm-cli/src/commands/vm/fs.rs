//! `mvmctl fs <verb> <vm> <args>` — filesystem RPC against a
//! running microVM. W1 / A1 of the filesystem-volumes plan.
//!
//! Production-safe surface: every call routes through the agent's
//! `mvm_core::crypto::policy::PathPolicy` (deny-list +
//! canonicalization) and the agent's per-call resource caps. The
//! host side here is a thin transport — we don't validate paths
//! before sending because the agent owns the canonical answer
//! (which may differ from what the host sees, e.g. on virtio-fs
//! shares).

use anyhow::{Context, Result, bail};
use clap::{Args as ClapArgs, Subcommand};
use std::io::{Read, Write};

use mvm_backend::microvm;
use mvm_core::naming::validate_vm_name;
use mvm_core::user_config::MvmConfig;
use mvm_guest::vsock::{FsResult, GuestRequest};

use super::Cli;
use super::shared::{clap_vm_name, human_bytes};

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub command: FsCmd,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum FsCmd {
    /// Read a file from the VM and print to stdout
    Read {
        /// Name of the VM
        #[arg(value_parser = clap_vm_name)]
        name: String,
        /// Path inside the VM
        path: String,
        /// Byte offset to start reading from (default 0)
        #[arg(long, default_value = "0")]
        offset: u64,
        /// Max bytes to read in this call (default 16 MiB).
        #[arg(long, default_value_t = 16 * 1024 * 1024)]
        length: u64,
    },
    /// Write stdin (or `--content`) to a file in the VM
    Write {
        /// Name of the VM
        #[arg(value_parser = clap_vm_name)]
        name: String,
        /// Path inside the VM
        path: String,
        /// Inline content (otherwise the file is written from stdin).
        #[arg(long)]
        content: Option<String>,
        /// Mode bits for newly-created files (default 0o644).
        #[arg(long, default_value = "420")]
        mode: u32,
        /// Create parent directories if missing
        #[arg(long)]
        create_parents: bool,
        /// Follow symlinks (defaults to false — TOCTOU-safer)
        #[arg(long)]
        follow_symlinks: bool,
    },
    /// List the contents of a directory in the VM
    Ls {
        /// Name of the VM
        #[arg(value_parser = clap_vm_name)]
        name: String,
        /// Directory path inside the VM
        path: String,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Stat a path in the VM
    Stat {
        /// Name of the VM
        #[arg(value_parser = clap_vm_name)]
        name: String,
        /// Path inside the VM
        path: String,
        /// Stat the symlink itself rather than its target
        #[arg(long)]
        no_follow: bool,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Create a directory in the VM
    Mkdir {
        /// Name of the VM
        #[arg(value_parser = clap_vm_name)]
        name: String,
        /// Directory path inside the VM
        path: String,
        /// Create parent directories as needed
        #[arg(long, short)]
        parents: bool,
        /// Mode (default 0o755)
        #[arg(long, default_value = "493")]
        mode: u32,
    },
    /// Remove a file or directory in the VM
    Rm {
        /// Name of the VM
        #[arg(value_parser = clap_vm_name)]
        name: String,
        /// Path inside the VM
        path: String,
        /// Recursively remove a non-empty directory
        #[arg(long, short)]
        recursive: bool,
    },
    /// Rename / move a path in the VM (within a single filesystem)
    Mv {
        /// Name of the VM
        #[arg(value_parser = clap_vm_name)]
        name: String,
        /// Source path
        from: String,
        /// Destination path
        to: String,
    },
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    match args.command {
        FsCmd::Read {
            name,
            path,
            offset,
            length,
        } => cmd_read(&name, &path, offset, length),
        FsCmd::Write {
            name,
            path,
            content,
            mode,
            create_parents,
            follow_symlinks,
        } => cmd_write(&name, &path, content, mode, create_parents, follow_symlinks),
        FsCmd::Ls { name, path, json } => cmd_ls(&name, &path, json),
        FsCmd::Stat {
            name,
            path,
            no_follow,
            json,
        } => cmd_stat(&name, &path, !no_follow, json),
        FsCmd::Mkdir {
            name,
            path,
            parents,
            mode,
        } => cmd_mkdir(&name, &path, mode, parents),
        FsCmd::Rm {
            name,
            path,
            recursive,
        } => cmd_rm(&name, &path, recursive),
        FsCmd::Mv { name, from, to } => cmd_mv(&name, &from, &to),
    }
}

pub(super) fn instance_dir_for(name: &str) -> Result<String> {
    validate_vm_name(name).with_context(|| format!("Invalid VM name: {:?}", name))?;
    // Plan 66 W3: if a mock VM is registered at
    // `<mvm_data_dir>/mock-vms/<name>/runtime/v.sock`, route to it
    // directly. The check is filesystem-based — production code
    // never reaches the mock-vms path because `MockBackend` only
    // populates it under `--hypervisor mock`. Falls through to the
    // Lima-era resolver when no mock is in play.
    let mock_dir = mvm_backend::MockBackend::vm_dir(name);
    if mock_dir.join("runtime").join("v.sock").exists() {
        return Ok(mock_dir.to_string_lossy().into_owned());
    }
    microvm::resolve_running_vm_dir(name)
}

fn unwrap_fs(result: FsResult) -> Result<FsResult> {
    if let FsResult::Error { kind, message } = &result {
        bail!("Guest FS error ({:?}): {}", kind, message);
    }
    Ok(result)
}

fn cmd_read(name: &str, path: &str, offset: u64, length: u64) -> Result<()> {
    let dir = instance_dir_for(name)?;
    let req = GuestRequest::FsRead {
        path: path.to_string(),
        offset: if offset == 0 { None } else { Some(offset) },
        length,
        follow_symlinks: true,
    };
    // Plan 74 W2 / Plan 51 W6 — inbound vsock RPC audit.
    super::shared::emit_vsock_rpc_audit(name, &req);
    let result = unwrap_fs(mvm_guest::vsock::send_fs_request(&dir, req)?)?;
    match result {
        FsResult::Read { content, .. } => {
            std::io::stdout().write_all(&content)?;
            Ok(())
        }
        other => bail!("Unexpected FsResult variant for Read: {:?}", other),
    }
}

fn cmd_write(
    name: &str,
    path: &str,
    content: Option<String>,
    mode: u32,
    create_parents: bool,
    follow_symlinks: bool,
) -> Result<()> {
    let dir = instance_dir_for(name)?;
    let bytes = match content {
        Some(s) => s.into_bytes(),
        None => {
            let mut buf = Vec::new();
            std::io::stdin().read_to_end(&mut buf)?;
            buf
        }
    };
    let req = GuestRequest::FsWrite {
        path: path.to_string(),
        content: bytes,
        mode,
        create_parents,
        follow_symlinks,
    };
    // Plan 74 W2 / Plan 51 W6 — inbound vsock RPC audit.
    super::shared::emit_vsock_rpc_audit(name, &req);
    let result = unwrap_fs(mvm_guest::vsock::send_fs_request(&dir, req)?)?;
    match result {
        FsResult::Write { bytes_written } => {
            eprintln!("wrote {} bytes", bytes_written);
            mvm_core::audit_emit!(VmFsMutate, vm: name, "op=write path={path} bytes={bytes_written}");
            Ok(())
        }
        other => bail!("Unexpected FsResult variant for Write: {:?}", other),
    }
}

fn cmd_ls(name: &str, path: &str, json: bool) -> Result<()> {
    let dir = instance_dir_for(name)?;
    let req = GuestRequest::FsList {
        path: path.to_string(),
        follow_symlinks: true,
    };
    // Plan 74 W2 / Plan 51 W6 — inbound vsock RPC audit.
    super::shared::emit_vsock_rpc_audit(name, &req);
    let result = unwrap_fs(mvm_guest::vsock::send_fs_request(&dir, req)?)?;
    match result {
        FsResult::List { entries, truncated } => {
            if json {
                println!("{}", serde_json::to_string_pretty(&entries)?);
                if truncated {
                    eprintln!("(listing truncated; raise --max-list-entries on the agent)");
                }
                return Ok(());
            }
            if entries.is_empty() {
                println!("(empty)");
            }
            for e in &entries {
                let kind = match e.kind {
                    mvm_guest::vsock::FsEntryKind::File => "f",
                    mvm_guest::vsock::FsEntryKind::Dir => "d",
                    mvm_guest::vsock::FsEntryKind::Symlink => "l",
                    mvm_guest::vsock::FsEntryKind::Other => "?",
                };
                if e.size > 0 {
                    println!("  {} {} ({})", kind, e.name, human_bytes(e.size));
                } else {
                    println!("  {} {}", kind, e.name);
                }
            }
            if truncated {
                eprintln!("(listing truncated; agent capped entries — raise its max_list_entries)");
            }
            Ok(())
        }
        other => bail!("Unexpected FsResult variant for List: {:?}", other),
    }
}

fn cmd_stat(name: &str, path: &str, follow_symlinks: bool, json: bool) -> Result<()> {
    let dir = instance_dir_for(name)?;
    let req = GuestRequest::FsStat {
        path: path.to_string(),
        follow_symlinks,
    };
    // Plan 74 W2 / Plan 51 W6 — inbound vsock RPC audit.
    super::shared::emit_vsock_rpc_audit(name, &req);
    let result = unwrap_fs(mvm_guest::vsock::send_fs_request(&dir, req)?)?;
    match result {
        FsResult::Stat(s) => {
            if json {
                println!("{}", serde_json::to_string_pretty(&s)?);
            } else {
                println!("path:  {}", s.canonical_path);
                println!("kind:  {:?}", s.kind);
                println!("size:  {} ({})", s.size, human_bytes(s.size));
                println!("mode:  {:o}", s.mode);
                if let Some(t) = s.mtime {
                    println!("mtime: {}", t);
                }
            }
            Ok(())
        }
        other => bail!("Unexpected FsResult variant for Stat: {:?}", other),
    }
}

fn cmd_mkdir(name: &str, path: &str, mode: u32, parents: bool) -> Result<()> {
    let dir = instance_dir_for(name)?;
    let req = GuestRequest::FsMkdir {
        path: path.to_string(),
        mode,
        parents,
    };
    // Plan 74 W2 / Plan 51 W6 — inbound vsock RPC audit.
    super::shared::emit_vsock_rpc_audit(name, &req);
    let result = unwrap_fs(mvm_guest::vsock::send_fs_request(&dir, req)?)?;
    match result {
        FsResult::Mkdir => {
            mvm_core::audit_emit!(VmFsMutate, vm: name, "op=mkdir path={path} mode={mode:o} parents={parents}");
            Ok(())
        }
        other => bail!("Unexpected FsResult variant for Mkdir: {:?}", other),
    }
}

fn cmd_rm(name: &str, path: &str, recursive: bool) -> Result<()> {
    let dir = instance_dir_for(name)?;
    let req = GuestRequest::FsRemove {
        path: path.to_string(),
        recursive,
        follow_symlinks: false,
    };
    // Plan 74 W2 / Plan 51 W6 — inbound vsock RPC audit.
    super::shared::emit_vsock_rpc_audit(name, &req);
    let result = unwrap_fs(mvm_guest::vsock::send_fs_request(&dir, req)?)?;
    match result {
        FsResult::Remove { entries_removed } => {
            eprintln!("removed {} entries", entries_removed);
            mvm_core::audit_emit!(VmFsMutate, vm: name, "op=rm path={path} recursive={recursive} entries={entries_removed}");
            Ok(())
        }
        other => bail!("Unexpected FsResult variant for Remove: {:?}", other),
    }
}

fn cmd_mv(name: &str, from: &str, to: &str) -> Result<()> {
    let dir = instance_dir_for(name)?;
    let req = GuestRequest::FsMove {
        from: from.to_string(),
        to: to.to_string(),
        follow_symlinks: false,
    };
    // Plan 74 W2 / Plan 51 W6 — inbound vsock RPC audit.
    super::shared::emit_vsock_rpc_audit(name, &req);
    let result = unwrap_fs(mvm_guest::vsock::send_fs_request(&dir, req)?)?;
    match result {
        FsResult::Move => {
            mvm_core::audit_emit!(VmFsMutate, vm: name, "op=mv from={from} to={to}");
            Ok(())
        }
        other => bail!("Unexpected FsResult variant for Move: {:?}", other),
    }
}
