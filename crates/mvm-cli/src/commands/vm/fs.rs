//! `mvmctl fs <verb> <vm> <args>` — filesystem RPC against a
//! running microVM.
//!
//! Production-safe surface: every call routes through the agent's
//! `mvm_core::crypto::policy::PathPolicy` (deny-list +
//! canonicalization) and the agent's per-call resource caps. The
//! host side here is a thin transport — we don't validate paths
//! before sending because the agent owns the canonical answer
//! (which may differ from what the host sees, e.g. on virtio-fs
//! shares).

use anyhow::Result;
use clap::{Args as ClapArgs, Subcommand};
use std::io::{Read, Write};

use mvm_client::guest;
use mvm_core::user_config::MvmConfig;

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

pub(in crate::commands) use mvm_client::guest::fs_request;

fn cmd_read(name: &str, path: &str, offset: u64, length: u64) -> Result<()> {
    let content = read_guest_chunks(name, path, offset, length)?;
    std::io::stdout().write_all(&content)?;
    Ok(())
}

fn cmd_write(
    name: &str,
    path: &str,
    content: Option<String>,
    mode: u32,
    create_parents: bool,
    follow_symlinks: bool,
) -> Result<()> {
    let bytes = match content {
        Some(s) => s.into_bytes(),
        None => {
            let mut buf = Vec::new();
            std::io::stdin().read_to_end(&mut buf)?;
            buf
        }
    };
    let bytes_written = guest::write_file(
        name,
        path,
        &bytes,
        guest::WriteOptions {
            mode,
            create_parents,
            follow_symlinks,
        },
    )?;
    eprintln!("wrote {} bytes", bytes_written);
    Ok(())
}

pub(in crate::commands) fn read_guest_chunks(
    name: &str,
    path: &str,
    start_offset: u64,
    length: u64,
) -> Result<Vec<u8>> {
    guest::read_file_chunks(name, path, start_offset, length, true)
}

pub(in crate::commands) fn read_guest_chunks_with_symlink_policy(
    name: &str,
    path: &str,
    start_offset: u64,
    length: u64,
    follow_symlinks: bool,
) -> Result<Vec<u8>> {
    guest::read_file_chunks(name, path, start_offset, length, follow_symlinks)
}

pub(super) fn write_guest_chunks(
    name: &str,
    path: &str,
    content: &[u8],
    mode: u32,
    create_parents: bool,
    follow_symlinks: bool,
) -> Result<u64> {
    guest::write_file_chunks(
        name,
        path,
        content,
        guest::WriteOptions {
            mode,
            create_parents,
            follow_symlinks,
        },
    )
}

fn cmd_ls(name: &str, path: &str, json: bool) -> Result<()> {
    let guest::Listing { entries, truncated } = guest::list_dir(name, path)?;
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
            mvm_agentd::vsock::FsEntryKind::File => "f",
            mvm_agentd::vsock::FsEntryKind::Dir => "d",
            mvm_agentd::vsock::FsEntryKind::Symlink => "l",
            mvm_agentd::vsock::FsEntryKind::Other => "?",
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

fn cmd_stat(name: &str, path: &str, follow_symlinks: bool, json: bool) -> Result<()> {
    let s = guest::stat(name, path, follow_symlinks)?;
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

fn cmd_mkdir(name: &str, path: &str, mode: u32, parents: bool) -> Result<()> {
    guest::make_dir(name, path, mode, parents)
}

fn cmd_rm(name: &str, path: &str, recursive: bool) -> Result<()> {
    let entries_removed = guest::remove(name, path, recursive)?;
    eprintln!("removed {} entries", entries_removed);
    Ok(())
}

fn cmd_mv(name: &str, from: &str, to: &str) -> Result<()> {
    guest::rename(name, from, to)
}
