//! Bounded descriptor-relative inventory for prune admission, never recovery.
use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use anyhow::{Result, ensure};
use mvm_core::transcript::TranscriptManifest;
use rustix::fs::{FlockOperation, Mode, OFlags};

const LIMIT: usize = 4096;

pub(super) struct Capture {
    pub seed: Option<TranscriptManifest>,
    pub manifest: Option<TranscriptManifest>,
    pub vm_component: Option<String>,
    pub tenant_component: Option<String>,
    pub capture_component: Option<String>,
}

pub(super) struct Inventory {
    pub captures: Vec<Capture>,
    // These nonblocking leases remain alive through the prune commit.
    leases: Vec<File>,
    visited: usize,
    remaining_metadata_bytes: usize,
}

impl Inventory {
    pub fn read(root: &Path, tenant: &str) -> Result<Self> {
        super::validate_tenant(tenant)?;
        let root = File::from(rustix::fs::open(
            root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        let mut inventory = Self {
            captures: Vec::new(),
            leases: Vec::new(),
            visited: 0,
            remaining_metadata_bytes: 64 * 1024 * 1024,
        };
        if let Some(families) = directory(&root, OsStr::new("workload-output"))? {
            for vm in inventory.names(&families)? {
                let family = required_directory(&families, &vm)?;
                lease(&family)?;
                if let Some(generations) = directory(&family, OsStr::new("generations"))? {
                    for run in inventory.names(&generations)? {
                        let run = required_directory(&generations, &run)?;
                        for generation in inventory.names(&run)? {
                            let generation = required_directory(&run, &generation)?;
                            lease(&generation)?;
                            inventory.captures.push(Capture {
                                seed: manifest(
                                    &generation,
                                    crate::stream::CAPTURE_SEED_FILENAME,
                                    &mut inventory.remaining_metadata_bytes,
                                )?,
                                manifest: manifest(
                                    &generation,
                                    mvm_core::transcript::MANIFEST_FILENAME,
                                    &mut inventory.remaining_metadata_bytes,
                                )?,
                                vm_component: Some(vm.to_string_lossy().into_owned()),
                                tenant_component: None,
                                capture_component: None,
                            });
                            inventory.leases.push(generation);
                        }
                    }
                }
                inventory.leases.push(family);
            }
        }
        if let Some(transcripts) = directory(&root, OsStr::new("transcripts"))?
            && let Some(captures) = directory(&transcripts, OsStr::new(tenant))?
        {
            for name in inventory.names(&captures)? {
                let capture = required_directory(&captures, &name)?;
                lease(&capture)?;
                inventory.captures.push(Capture {
                    seed: None,
                    manifest: manifest(
                        &capture,
                        mvm_core::transcript::MANIFEST_FILENAME,
                        &mut inventory.remaining_metadata_bytes,
                    )?,
                    vm_component: None,
                    tenant_component: Some(tenant.to_owned()),
                    capture_component: Some(name.to_string_lossy().into_owned()),
                });
                inventory.leases.push(capture);
            }
        }
        Ok(inventory)
    }

    fn names(&mut self, directory: &File) -> Result<Vec<std::ffi::OsString>> {
        let mut names = Vec::new();
        for entry in rustix::fs::Dir::read_from(directory)? {
            let entry = entry?;
            let name = entry.file_name().to_bytes();
            if matches!(name, b"." | b"..") {
                continue;
            }
            self.visited += 1;
            ensure!(self.visited <= LIMIT, "protected inventory bound exceeded");
            names.push(OsStr::from_bytes(name).to_os_string());
        }
        names.sort();
        Ok(names)
    }
}

fn directory(parent: &File, name: &OsStr) -> Result<Option<File>> {
    let file = match rustix::fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(file) => File::from(file),
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let metadata = file.metadata()?;
    ensure!(
        metadata.uid() == rustix::process::geteuid().as_raw() && metadata.mode() & 0o077 == 0,
        "protected inventory directory is not private and host-owned"
    );
    Ok(Some(file))
}

fn required_directory(parent: &File, name: &OsStr) -> Result<File> {
    directory(parent, name)?.ok_or_else(|| anyhow::anyhow!("protected inventory changed"))
}

fn lease(directory: &File) -> Result<()> {
    rustix::fs::flock(directory, FlockOperation::NonBlockingLockExclusive).map_err(|_| {
        anyhow::anyhow!("protected capture inventory busy; retry after owner releases")
    })?;
    Ok(())
}

fn manifest(
    directory: &File,
    name: &str,
    remaining: &mut usize,
) -> Result<Option<TranscriptManifest>> {
    let file = match rustix::fs::openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(file) => File::from(file),
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.nlink() == 1
            && metadata.uid() == rustix::process::geteuid().as_raw()
            && metadata.mode() & 0o077 == 0,
        "protected inventory metadata is not a private single-link file"
    );
    let mut bytes = Vec::new();
    let limit = (*remaining).min(16 * 1024 * 1024);
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= limit, "protected metadata bound exceeded");
    *remaining -= bytes.len();
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| io::Error::other("invalid protected verification metadata").into())
}
