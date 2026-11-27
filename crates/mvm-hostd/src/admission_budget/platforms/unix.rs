use std::io::Read as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use mvm_core::{atomic_io, private_fs};
use mvm_vmm::host::network_endpoint_spawn::EndpointPid;

pub(super) fn prepare_directory(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            ensure!(
                meta.is_dir() && meta.mode() & 0o077 == 0,
                "host reservation directory is not private"
            );
            private_fs::require_current_owner(&meta)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            private_fs::create_owned_private_dir(path)?;
            atomic_io::sync_dir(
                path.parent()
                    .context("reservation directory parent missing")?,
            )?;
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

pub(crate) fn acquire_lock(path: &Path) -> Result<atomic_io::FileLock> {
    atomic_io::write_private_new(path, b"")?;
    let file = open_owned(path, 0o077)?.context("host reservation lock disappeared")?;
    atomic_io::FileLock::acquire_opened(file)
}

pub(crate) fn read_private(path: &Path, limit: usize) -> Result<Option<Vec<u8>>> {
    read_owned(path, limit, 0o077)
}

pub(super) fn read_legacy(path: &Path, limit: usize) -> Result<Option<Vec<u8>>> {
    read_owned(path, limit, 0o022)
}

fn read_owned(path: &Path, limit: usize, forbidden_mode: u32) -> Result<Option<Vec<u8>>> {
    let Some(file) = open_owned(path, forbidden_mode)? else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    file.take(u64::try_from(limit)? + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= limit,
        "host accounting file exceeds byte limit"
    );
    Ok(Some(bytes))
}

fn open_owned(path: &Path, forbidden_mode: u32) -> Result<Option<std::fs::File>> {
    let fd = match rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let file = std::fs::File::from(fd);
    let meta = file.metadata()?;
    ensure!(
        meta.is_file() && meta.nlink() == 1,
        "host accounting file {} is not a regular file with a single link",
        path.display()
    );
    ensure!(
        meta.mode() & forbidden_mode == 0,
        "host accounting file {path} has unsafe permissions {mode:04o}, which open it \
         to group or others; restrict it to its owner (for example `chmod 600 {path}`)",
        path = path.display(),
        mode = meta.mode() & 0o7777
    );
    private_fs::require_current_owner(&meta)?;
    Ok(Some(file))
}

pub(super) fn current_owner() -> Result<String> {
    let record = EndpointPid::of_child(std::process::id());
    ensure!(
        record.started.is_some(),
        "cannot bind host reservation owner identity"
    );
    Ok(record.render())
}

pub(super) fn validate_owner(owner: &str) -> Result<()> {
    let record = EndpointPid::parse(owner).context("invalid host reservation owner")?;
    ensure!(
        record.started.is_some() && record.render() == owner,
        "host reservation owner lacks exact identity"
    );
    Ok(())
}

pub(super) fn owner_is_confirmed_dead(owner: &str) -> bool {
    let Some(record) = EndpointPid::parse(owner) else {
        return false;
    };
    // SAFETY: signal zero only observes this positive process ID.
    if unsafe { libc::kill(record.pid, 0) } != 0 {
        return std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH);
    }
    let current = EndpointPid::of_child(record.pid as u32);
    matches!((record.started, current.started), (Some(old), Some(now)) if old != now)
}

pub(super) fn machine_is_confirmed_dead(directory: &Path) -> Result<bool> {
    let mut found = false;
    for name in mvm_vmm::host::process_liveness::PID_FILE_NAMES {
        let Some(bytes) = read_legacy(&directory.join(name), 256)? else {
            continue;
        };
        let owner = std::str::from_utf8(&bytes)?.trim();
        let record = EndpointPid::parse(owner).context("invalid machine PID evidence")?;
        ensure!(record.render() == owner, "malformed machine PID evidence");
        found = true;
        if !owner_is_confirmed_dead(&record.render()) {
            return Ok(false);
        }
    }
    Ok(found)
}

pub(super) fn machine_identity(directory: &Path) -> Result<Option<String>> {
    let mut found = None;
    for name in mvm_vmm::host::process_liveness::PID_FILE_NAMES {
        let Some(bytes) = read_legacy(&directory.join(name), 256)? else {
            continue;
        };
        let text = std::str::from_utf8(&bytes)?.trim();
        let mut record = EndpointPid::parse(text).context("invalid machine identity")?;
        ensure!(record.render() == text, "malformed machine identity");
        if *name == "fc.pid" && record.started.is_none() {
            let Some(identity) = read_legacy(&directory.join("fc.identity"), 256)? else {
                return Ok(None);
            };
            let identity = std::str::from_utf8(&identity)?.trim();
            validate_owner(identity)?;
            let original = EndpointPid::parse(identity).context("invalid Firecracker identity")?;
            ensure!(
                original.pid == record.pid,
                "Firecracker PID and original identity differ"
            );
            record = original;
        }
        if record.started.is_none() || !record.is_live_and_ours() {
            // A legacy marker cannot prove the identity of the original child.
            // Keep the dispatch charged rather than inventing that evidence.
            return Ok(None);
        }
        let identity = record.render();
        ensure!(
            found.as_ref().is_none_or(|previous| previous == &identity),
            "machine has conflicting process identities"
        );
        found = Some(identity);
    }
    Ok(found)
}
