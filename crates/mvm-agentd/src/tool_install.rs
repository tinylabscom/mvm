//! Activation-time installation of workload-origin declared-command
//! mediation.
//!
//! Runs as PID 1 after the pivot, before the privilege drop. For every
//! declared tool the signed plan bound to an exact executable path, this
//! verifies the path exists in the workload rootfs, hashes its bytes into the
//! root-only stash, finds every other runnable path to the same bytes (hard
//! links, symlinks, and content-identical copies), mounts the `mvm-tool-shim`
//! client over all of them, writes the tool map the helper loads, and starts
//! the helper under its own identity.
//!
//! The command is the unit of substitution, and the rule is fail closed: if
//! any declared path is missing, is not a regular file, or has any runnable
//! path that cannot be substituted, activation refuses the whole declared
//! command set — a workload must never boot into a half-mediated state where
//! one spelling of the tool answers to the host and another runs unmediated.

use std::collections::BTreeMap;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::tool_map::{MAX_ALIASES_PER_TOOL, STASH_DIR, ToolEntry, ToolMap};
#[cfg(target_os = "linux")]
use crate::tool_map::{TOOL_DIR, TOOL_MAP_PATH};

/// The overlay binaries the installer delivers.
pub const TOOL_SHIM_OVERLAY: &str = "/mvm/runtime/tool-shim";
pub const TOOL_HELPER_OVERLAY: &str = "/mvm/runtime/tool-helper";

/// Largest executable the installer will stash and the helper will hash.
pub const MAX_TOOL_BYTES: u64 = 512 * 1024 * 1024;
/// Total bytes the alias scan will hash across the whole install; a rootfs
/// that would exceed this refuses activation rather than booting half
/// scanned.
pub const MAX_SCAN_BYTES: u64 = 1024 * 1024 * 1024;
/// More entry paths than this indicates a shared multi-call binary. Treating
/// every applet as the declared tool would over-grant its routes and secrets;
/// leaving any applet direct would bypass mediation.
const MAX_STANDALONE_TOOL_PATHS: usize = 8;
/// Deepest symlink chain the target resolution and alias scan will follow.
const MAX_SYMLINK_HOPS: usize = 8;

/// Installation refused; activation fails closed on any variant.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum InstallError {
    /// The guest runtime overlay is too old to carry the mediation binaries.
    #[error("declared commands require the runtime overlay to carry {0}")]
    OverlayBinaryMissing(&'static str),
    /// A declared path does not exist in the workload rootfs.
    #[error("declared tool {tool} names {path}, which does not exist in the workload rootfs")]
    DeclaredPathMissing { tool: String, path: String },
    /// A declared path exists but is not a regular file (or symlink to one).
    #[error("declared tool {tool} names {path}, which is not a regular file")]
    NotAFile { tool: String, path: String },
    /// A declared executable exceeded the size bound.
    #[error("declared tool {tool} executable exceeds the {MAX_TOOL_BYTES}-byte bound")]
    TooLarge { tool: String },
    /// The alias scan hashed more than the budget allows.
    #[error("alias scan exceeded the {MAX_SCAN_BYTES}-byte hashing budget")]
    ScanBudgetExceeded,
    /// A declared tool has more runnable alias paths than the mount table can
    /// sanely carry.
    #[error("declared tool {tool} resolves through more than {MAX_ALIASES_PER_TOOL} alias paths")]
    TooManyAliases { tool: String },
    /// A path that runs the declared tool's bytes could not be substituted.
    #[error("could not substitute {path}: {reason}")]
    SubstitutionFailed { path: String, reason: String },
    /// The helper did not start, so no declared command can be mediated.
    #[error("tool helper did not start: {0}")]
    HelperSpawnFailed(String),
}

/// Build the tool map for one activation: resolve every declared path, hash
/// its bytes into a stash path, and find every alias to the same bytes.
///
/// `root` is the walk root — `/` in the guest, a tempdir in tests. Pure
/// filesystem reads, no mounts, so the scan rules are testable off-guest.
pub fn build_tool_map(
    commands: &BTreeMap<String, String>,
    root: &Path,
) -> Result<ToolMap, InstallError> {
    let mut tools = Vec::new();
    let mut budget = ScanBudget::default();
    for (tool, declared) in commands {
        let target = resolve_target(root, Path::new(declared)).ok_or_else(|| {
            if path_exists(root, Path::new(declared)) {
                InstallError::NotAFile {
                    tool: tool.clone(),
                    path: declared.clone(),
                }
            } else {
                InstallError::DeclaredPathMissing {
                    tool: tool.clone(),
                    path: declared.clone(),
                }
            }
        })?;
        let target_meta =
            std::fs::metadata(&target).map_err(|error| InstallError::SubstitutionFailed {
                path: target.to_string_lossy().into_owned(),
                reason: error.to_string(),
            })?;
        if target_meta.len() > MAX_TOOL_BYTES {
            return Err(InstallError::TooLarge { tool: tool.clone() });
        }
        let bytes = std::fs::read(&target).map_err(|_| InstallError::DeclaredPathMissing {
            tool: tool.clone(),
            path: declared.clone(),
        })?;
        if bytes.len() as u64 > MAX_TOOL_BYTES {
            return Err(InstallError::TooLarge { tool: tool.clone() });
        }
        let digest = mvm_contract::hash::sha256_hex(&bytes);
        let mut aliases = collect_aliases(
            root,
            &target,
            &target_meta,
            &digest,
            bytes.len() as u64,
            &mut budget,
        )?;
        aliases.retain(|alias| alias != declared);
        if aliases.len().saturating_add(1) > MAX_STANDALONE_TOOL_PATHS {
            return Err(InstallError::SubstitutionFailed {
                path: declared.clone(),
                reason: format!(
                    "declared executable resolves through {} paths and appears to be a shared \
                     multi-call binary; declare a standalone tool binary",
                    aliases.len() + 1
                ),
            });
        }
        if aliases.len() > MAX_ALIASES_PER_TOOL {
            return Err(InstallError::TooManyAliases { tool: tool.clone() });
        }
        tools.push(ToolEntry {
            tool: tool.clone(),
            executable: declared.clone(),
            aliases,
            stash: format!("{STASH_DIR}/{digest}"),
            digest,
        });
    }
    let map = ToolMap { tools };
    check_map(&map)?;
    Ok(map)
}

/// Structural validation for a freshly built map (the helper's
/// [`ToolMap::load`] runs the same checks on the written file). A failure
/// here must refuse activation in every build profile.
pub fn check_map(map: &ToolMap) -> Result<(), InstallError> {
    let bytes = serde_json::to_vec(map).map_err(|error| InstallError::SubstitutionFailed {
        path: crate::tool_map::TOOL_MAP_PATH.to_string(),
        reason: error.to_string(),
    })?;
    ToolMap::load(&bytes)
        .map(|_| ())
        .map_err(|error| InstallError::SubstitutionFailed {
            path: crate::tool_map::TOOL_MAP_PATH.to_string(),
            reason: error.to_string(),
        })
}

struct ScanBudget {
    hashed: u64,
    limit: u64,
}

impl Default for ScanBudget {
    fn default() -> Self {
        Self {
            hashed: 0,
            limit: MAX_SCAN_BYTES,
        }
    }
}

impl ScanBudget {
    fn hash(&mut self, len: u64) -> Result<(), InstallError> {
        self.hashed = self.hashed.saturating_add(len);
        if self.hashed > self.limit {
            return Err(InstallError::ScanBudgetExceeded);
        }
        Ok(())
    }
}

fn path_exists(root: &Path, path: &Path) -> bool {
    root.join(path.strip_prefix("/").unwrap_or(path))
        .symlink_metadata()
        .is_ok()
}

fn rooted(root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        root.join(path.strip_prefix("/").unwrap_or(path))
    } else {
        root.join(path)
    }
}

#[cfg(any(target_os = "linux", test))]
fn substitution_error(path: &Path, reason: impl ToString) -> InstallError {
    InstallError::SubstitutionFailed {
        path: path.to_string_lossy().into_owned(),
        reason: reason.to_string(),
    }
}

/// Re-read the image executable before stashing it. The map pins its digest,
/// so a changed source cannot be installed under the earlier decision.
#[cfg(any(target_os = "linux", test))]
fn source_bytes(root: &Path, entry: &ToolEntry) -> Result<Vec<u8>, InstallError> {
    let declared = Path::new(&entry.executable);
    let source = resolve_target(root, declared)
        .ok_or_else(|| substitution_error(declared, "declared executable is unavailable"))?;
    let size = std::fs::metadata(&source)
        .map_err(|error| substitution_error(&source, error))?
        .len();
    if size > MAX_TOOL_BYTES {
        return Err(InstallError::TooLarge {
            tool: entry.tool.clone(),
        });
    }
    let bytes = std::fs::read(&source).map_err(|error| substitution_error(&source, error))?;
    if bytes.len() as u64 > MAX_TOOL_BYTES {
        return Err(InstallError::TooLarge {
            tool: entry.tool.clone(),
        });
    }
    if mvm_contract::hash::sha256_hex(&bytes) != entry.digest {
        return Err(substitution_error(
            declared,
            "declared executable changed during activation",
        ));
    }
    Ok(bytes)
}

/// Resolve a declared path to the regular file it ultimately names, following
/// up to [`MAX_SYMLINK_HOPS`] symlink hops. Returns the host-side (rooted)
/// path of the target.
fn resolve_target(root: &Path, declared: &Path) -> Option<PathBuf> {
    let mut current = rooted(root, declared);
    for _ in 0..=MAX_SYMLINK_HOPS {
        match std::fs::symlink_metadata(&current) {
            Ok(meta) if meta.file_type().is_symlink() => {
                let link = std::fs::read_link(&current).ok()?;
                current = if link.is_absolute() {
                    rooted(root, &link)
                } else {
                    current.parent()?.join(link)
                };
            }
            Ok(meta) if meta.file_type().is_file() => return Some(current),
            _ => return None,
        }
    }
    None
}

/// Whether `path` (a rooted host path) resolves to the same bytes as the
/// declared tool's target: hard link, symlink to it, or content-identical
/// copy. Returns the guest-relative alias path when it does.
fn alias_of(
    root: &Path,
    path: &Path,
    target: &Path,
    target_meta: &std::fs::Metadata,
    digest: &str,
    target_len: u64,
    budget: &mut ScanBudget,
) -> Result<Option<String>, InstallError> {
    let fail = |error: std::io::Error| InstallError::SubstitutionFailed {
        path: path.to_string_lossy().into_owned(),
        reason: format!("alias scan could not prove coverage: {error}"),
    };
    let relative = path
        .strip_prefix(root)
        .map_err(|error| InstallError::SubstitutionFailed {
            path: path.to_string_lossy().into_owned(),
            reason: format!("alias scan escaped its root: {error}"),
        })?;
    let guest_path = format!("/{}", relative.to_string_lossy());
    let meta = std::fs::symlink_metadata(path).map_err(fail)?;
    let matches = if meta.file_type().is_symlink() {
        let Some(resolved) = resolve_target(root, Path::new(&guest_path)) else {
            // A dangling or looping symlink cannot execute the target bytes.
            return Ok(None);
        };
        let resolved_meta = std::fs::metadata(&resolved).map_err(fail)?;
        if !resolved_meta.file_type().is_file() || resolved_meta.len() != target_len {
            return Ok(None);
        }
        if resolved == *target {
            true
        } else {
            budget.hash(target_len)?;
            let bytes = std::fs::read(&resolved).map_err(fail)?;
            mvm_contract::hash::sha256_hex(&bytes) == digest
        }
    } else if meta.file_type().is_file() {
        let same_inode = meta.dev() == target_meta.dev() && meta.ino() == target_meta.ino();
        if !same_inode && meta.len() != target_len {
            return Ok(None);
        }
        if same_inode {
            true
        } else {
            budget.hash(target_len)?;
            let bytes = std::fs::read(path).map_err(fail)?;
            mvm_contract::hash::sha256_hex(&bytes) == digest
        }
    } else {
        false
    };
    if !matches {
        return Ok(None);
    }
    if guest_path.len() > 4096 {
        return Err(InstallError::SubstitutionFailed {
            path: guest_path,
            reason: "runnable alias exceeds the 4096-byte path bound".into(),
        });
    }
    Ok(Some(guest_path))
}

/// Walk the root filesystem (never descending into other mounts) collecting
/// every alias to the target's bytes.
fn collect_aliases(
    root: &Path,
    target: &Path,
    target_meta: &std::fs::Metadata,
    digest: &str,
    target_len: u64,
    budget: &mut ScanBudget,
) -> Result<Vec<String>, InstallError> {
    let mut aliases = Vec::new();
    let root_dev = std::fs::metadata(root)
        .map_err(|error| InstallError::SubstitutionFailed {
            path: root.to_string_lossy().into_owned(),
            reason: error.to_string(),
        })?
        .dev();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries =
            std::fs::read_dir(&dir).map_err(|error| InstallError::SubstitutionFailed {
                path: dir.to_string_lossy().into_owned(),
                reason: format!("alias scan could not read directory: {error}"),
            })?;
        for entry in entries {
            let entry = entry.map_err(|error| InstallError::SubstitutionFailed {
                path: dir.to_string_lossy().into_owned(),
                reason: format!("alias scan could not read directory entry: {error}"),
            })?;
            let path = entry.path();
            let meta = std::fs::symlink_metadata(&path).map_err(|error| {
                InstallError::SubstitutionFailed {
                    path: path.to_string_lossy().into_owned(),
                    reason: format!("alias scan could not inspect entry: {error}"),
                }
            })?;
            if meta.file_type().is_dir() {
                // Stay on the rootfs: other mounts hold no image bytes, and
                // tmpfs trees can change under the walk.
                if meta.dev() == root_dev {
                    stack.push(path);
                }
                continue;
            }
            if let Some(alias) =
                alias_of(root, &path, target, target_meta, digest, target_len, budget)?
            {
                aliases.push(alias);
            }
        }
    }
    Ok(aliases)
}

/// Deliver the mediation binaries, write the map, and start the helper.
///
/// Linux-only: the mounts, ownership and identity spawn need root. `root` is
/// `/` in the guest.
#[cfg(target_os = "linux")]
pub fn install(commands: &BTreeMap<String, String>, root: &Path) -> Result<(), InstallError> {
    if commands.is_empty() {
        return Ok(());
    }
    if !crate::guest_bootstrap::is_executable(Path::new(TOOL_SHIM_OVERLAY)) {
        return Err(InstallError::OverlayBinaryMissing(TOOL_SHIM_OVERLAY));
    }
    if !crate::guest_bootstrap::is_executable(Path::new(TOOL_HELPER_OVERLAY)) {
        return Err(InstallError::OverlayBinaryMissing(TOOL_HELPER_OVERLAY));
    }
    let map = build_tool_map(commands, root)?;

    prepare_dirs()?;
    for entry in &map.tools {
        let bytes = source_bytes(root, entry)?;
        write_stash(&entry.stash, &bytes)?;
    }
    write_map(&map)?;

    // Every substitution lands only after the whole map is known good, so a
    // failure cannot leave some paths mediated and others not: the error
    // refuses activation and the mounts from this boot die with the VM.
    for entry in &map.tools {
        for path in entry.paths() {
            substitute(path)?;
        }
    }
    spawn_helper()
}

/// No mediation off-Linux: the installer exists only where the guest runs.
#[cfg(not(target_os = "linux"))]
pub fn install(_commands: &BTreeMap<String, String>, _root: &Path) -> Result<(), InstallError> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn prepare_dirs() -> Result<(), InstallError> {
    use std::os::unix::fs::PermissionsExt;

    let helper = crate::guest_mount::TOOL_HELPER_IDENTITY;
    for (path, mode, gid) in [
        (TOOL_DIR, 0o775, helper.gid()),
        (STASH_DIR, 0o750, helper.gid()),
        (crate::tool_map::TOOL_ATTRIBUTION_DIR, 0o775, helper.gid()),
    ] {
        std::fs::create_dir_all(path).map_err(|error| InstallError::SubstitutionFailed {
            path: path.to_string(),
            reason: error.to_string(),
        })?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(|error| {
            InstallError::SubstitutionFailed {
                path: path.to_string(),
                reason: error.to_string(),
            }
        })?;
        chown(path, 0, gid)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn chown(path: &str, uid: u32, gid: u32) -> Result<(), InstallError> {
    let c_path = crate::guest_bootstrap::cstring_str(path).ok_or_else(|| {
        InstallError::SubstitutionFailed {
            path: path.to_string(),
            reason: "path contains NUL".into(),
        }
    })?;
    // SAFETY: `c_path` is NUL-terminated and outlives the call.
    let rc = unsafe { libc::chown(c_path.as_ptr(), uid, gid) };
    if rc != 0 {
        return Err(InstallError::SubstitutionFailed {
            path: path.to_string(),
            reason: std::io::Error::last_os_error().to_string(),
        });
    }
    Ok(())
}

/// Mode for a staged stash file. The tool child executes the stash through
/// `execveat(AT_EMPTY_PATH)` after `setgroups(0)` + `setresgid(TOOL_GID)` +
/// `setresuid(TOOL_UID)`, so its credentials are uid 902 / gid 907 with no
/// supplementary groups — while the stash is group 906 (the helper's). The
/// exec therefore succeeds or fails on the OTHER bits: a read-only mode
/// (0640) fails with EACCES, which the helper reports as the spawn-exit 127 —
/// the exact failure a live `tool_live` run produced. World `r-x` is safe
/// because the stash directory (0750 root:906) refuses traversal to the
/// workload uid, so the fd-inherited execveat is the only way in.
#[cfg(any(target_os = "linux", test))]
const STASH_MODE: u32 = 0o755;

#[cfg(target_os = "linux")]
fn write_stash(stash: &str, bytes: &[u8]) -> Result<(), InstallError> {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    let helper = crate::guest_mount::TOOL_HELPER_IDENTITY;
    let mut file =
        std::fs::File::create(stash).map_err(|error| InstallError::SubstitutionFailed {
            path: stash.to_string(),
            reason: error.to_string(),
        })?;
    file.write_all(bytes)
        .map_err(|error| InstallError::SubstitutionFailed {
            path: stash.to_string(),
            reason: error.to_string(),
        })?;
    file.set_permissions(std::fs::Permissions::from_mode(STASH_MODE))
        .map_err(|error| InstallError::SubstitutionFailed {
            path: stash.to_string(),
            reason: error.to_string(),
        })?;
    chown(stash, 0, helper.gid())
}

#[cfg(target_os = "linux")]
fn write_map(map: &ToolMap) -> Result<(), InstallError> {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    let bytes = serde_json::to_vec(map).map_err(|error| InstallError::SubstitutionFailed {
        path: TOOL_MAP_PATH.to_string(),
        reason: error.to_string(),
    })?;
    let mut file =
        std::fs::File::create(TOOL_MAP_PATH).map_err(|error| InstallError::SubstitutionFailed {
            path: TOOL_MAP_PATH.to_string(),
            reason: error.to_string(),
        })?;
    file.write_all(&bytes)
        .map_err(|error| InstallError::SubstitutionFailed {
            path: TOOL_MAP_PATH.to_string(),
            reason: error.to_string(),
        })?;
    file.set_permissions(std::fs::Permissions::from_mode(0o640))
        .map_err(|error| InstallError::SubstitutionFailed {
            path: TOOL_MAP_PATH.to_string(),
            reason: error.to_string(),
        })?;
    chown(
        TOOL_MAP_PATH,
        0,
        crate::guest_mount::TOOL_HELPER_IDENTITY.gid(),
    )
}

/// Mount the shim client over one runnable path. Fails closed: unlike the
/// ping stand-in, a declared command that cannot be substituted refuses the
/// activation rather than degrading to the image's original binary.
#[cfg(target_os = "linux")]
fn substitute(path: &str) -> Result<(), InstallError> {
    use crate::guest_bootstrap::{overlay_parent_for_write, substitute_in_place};

    substitute_with_fallback(
        path,
        || substitute_in_place(TOOL_SHIM_OVERLAY, path),
        || overlay_parent_for_write(Path::new(path)),
    )
}

#[cfg(any(target_os = "linux", test))]
fn substitute_with_fallback(
    path: &str,
    mut substitute: impl FnMut() -> Result<(), String>,
    make_writable: impl FnOnce() -> Result<(), String>,
) -> Result<(), InstallError> {
    let fail = |reason: String| InstallError::SubstitutionFailed {
        path: path.to_string(),
        reason,
    };
    if let Err(first) = substitute() {
        make_writable().map_err(|overlay| {
            fail(format!(
                "{first}; preparing writable parent also failed: {overlay}"
            ))
        })?;
        substitute().map_err(fail)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn spawn_helper() -> Result<(), InstallError> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    let mut pipe = [-1; 2];
    // SAFETY: pipe is a writable pair of integers.
    if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(InstallError::HelperSpawnFailed(format!(
            "create readiness pipe: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: successful pipe2 returned two new owned descriptors.
    let read_ready = unsafe { std::os::fd::OwnedFd::from_raw_fd(pipe[0]) };
    let write_ready = unsafe { std::os::fd::OwnedFd::from_raw_fd(pipe[1]) };
    let ready_fd = write_ready.as_raw_fd();
    let mut command = Command::new(TOOL_HELPER_OVERLAY);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .env("MVM_TOOL_READY_FD", ready_fd.to_string());
    crate::fd_hygiene::configure_close_fds(&mut command, 3, Some(ready_fd as u32));
    let identity = crate::guest_mount::TOOL_HELPER_IDENTITY;
    // SAFETY: both calls are async-signal-safe and run in the forked child;
    // only the readiness writer survives exec, then the helper owns it.
    unsafe {
        command.pre_exec(move || {
            if libc::fcntl(ready_fd, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            identity.assume()
        });
    }
    let mut child = command.spawn().map_err(|error| {
        InstallError::HelperSpawnFailed(format!("spawn {TOOL_HELPER_OVERLAY}: {error}"))
    })?;
    drop(write_ready);
    let mut poll = libc::pollfd {
        fd: read_ready.as_raw_fd(),
        events: libc::POLLIN | libc::POLLHUP,
        revents: 0,
    };
    // SAFETY: poll points at one writable entry; read_ready stays open.
    let signaled = unsafe { libc::poll(&mut poll, 1, 5_000) };
    let mut byte = 0u8;
    // SAFETY: byte is writable and the pipe reader remains open.
    let ready = signaled > 0
        && unsafe { libc::read(read_ready.as_raw_fd(), (&mut byte as *mut u8).cast(), 1) } == 1
        && byte == 1;
    if !ready {
        let _ = child.kill();
        let _ = child.wait();
        return Err(InstallError::HelperSpawnFailed(
            "helper did not bind its socket within five seconds".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rootfs() -> (tempfile::TempDir, PathBuf) {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().to_path_buf();
        // Layout: /bin/sh -> /bin/busybox (hard link to /usr/bin/busybox-real),
        // a same-byte copy at /usr/local/bin/sh-copy, plus unrelated files.
        std::fs::create_dir_all(root.join("bin")).expect("bin");
        std::fs::create_dir_all(root.join("usr/bin")).expect("usr/bin");
        std::fs::create_dir_all(root.join("usr/local/bin")).expect("local bin");
        std::fs::create_dir_all(root.join("etc")).expect("etc");
        std::fs::write(root.join("usr/bin/busybox-real"), b"busybox bytes").expect("write busybox");
        std::fs::hard_link(root.join("usr/bin/busybox-real"), root.join("bin/busybox"))
            .expect("hard link busybox");
        std::os::unix::fs::symlink("busybox", root.join("bin/sh")).expect("sh symlink");
        std::fs::write(root.join("usr/local/bin/sh-copy"), b"busybox bytes").expect("write copy");
        std::fs::write(root.join("etc/other"), b"other bytes").expect("write other");
        (temp, root)
    }

    #[test]
    fn build_finds_hard_links_symlinks_and_copies_as_aliases() {
        let (_temp, root) = rootfs();
        let commands = BTreeMap::from([("shell".to_string(), "/bin/sh".to_string())]);
        let map = build_tool_map(&commands, &root).expect("map builds");
        assert_eq!(map.tools.len(), 1);
        let entry = &map.tools[0];
        assert_eq!(entry.tool, "shell");
        assert_eq!(entry.executable, "/bin/sh");
        assert_eq!(
            entry.digest,
            mvm_contract::hash::sha256_hex(b"busybox bytes")
        );
        assert!(entry.stash.starts_with(STASH_DIR));
        // The declared symlink target, the hard link, and the same-byte copy
        // are all runnable paths to the tool's bytes.
        assert!(entry.substitutes("/bin/busybox"));
        assert!(entry.substitutes("/usr/bin/busybox-real"));
        assert!(entry.substitutes("/usr/local/bin/sh-copy"));
        assert!(!entry.substitutes("/etc/other"));
        // The map validates as written.
        ToolMap::load(&serde_json::to_vec(&map).unwrap()).expect("map validates");
    }

    #[test]
    fn the_stash_mode_execs_for_the_tool_uid_and_stays_unreachable_by_path() {
        // The tool child (uid 902, gid 907, no supplementary groups) matches
        // neither the owner (root) nor the group (helper 906): the execveat
        // succeeds only via the OTHER bits.
        assert_eq!(
            STASH_MODE & 0o005,
            0o005,
            "other needs r-x: that is the tool child's only match"
        );
        // The defense against the workload exec'ing the stash by path is the
        // stash directory, not the file mode.
        assert_eq!(STASH_MODE & 0o070, 0o050, "the helper group keeps r-x");
    }

    #[test]
    fn fresh_rootfs_source_bytes_are_staged_and_digest_checked() {
        let (_temp, root) = rootfs();
        let commands = BTreeMap::from([("shell".to_string(), "/bin/sh".to_string())]);
        let map = build_tool_map(&commands, &root).expect("map builds");

        assert_eq!(
            source_bytes(&root, &map.tools[0]).expect("source bytes"),
            b"busybox bytes"
        );

        std::fs::write(root.join("usr/bin/busybox-real"), b"changed").expect("change source");
        assert!(matches!(
            source_bytes(&root, &map.tools[0]),
            Err(InstallError::SubstitutionFailed { reason, .. })
                if reason.contains("changed during activation")
        ));
    }

    #[test]
    fn missing_and_nonfile_declared_paths_refuse() {
        let (_temp, root) = rootfs();
        let missing = BTreeMap::from([("shell".to_string(), "/bin/nope".to_string())]);
        assert!(matches!(
            build_tool_map(&missing, &root),
            Err(InstallError::DeclaredPathMissing { .. })
        ));
        let dir = BTreeMap::from([("shell".to_string(), "/bin".to_string())]);
        assert!(matches!(
            build_tool_map(&dir, &root),
            Err(InstallError::NotAFile { .. })
        ));
    }

    #[test]
    fn shared_multi_call_binaries_refuse_instead_of_overgranting_applets() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path();
        std::fs::create_dir_all(root.join("bin")).expect("bin");
        std::fs::write(root.join("bin/busybox"), b"busybox").expect("busybox");
        for applet in [
            "sh", "ls", "cat", "echo", "ash", "sed", "awk", "mkdir", "mount",
        ] {
            std::os::unix::fs::symlink("busybox", root.join("bin").join(applet))
                .expect("applet link");
        }
        let commands = BTreeMap::from([("shell".to_string(), "/bin/sh".to_string())]);

        assert!(matches!(
            build_tool_map(&commands, root),
            Err(InstallError::SubstitutionFailed { reason, .. })
                if reason.contains("multi-call")
        ));
    }

    #[test]
    fn scan_budget_refuses_a_rootfs_of_copies() {
        let (_temp, root) = rootfs();
        let target = resolve_target(&root, Path::new("/bin/sh")).expect("target");
        let target_meta = std::fs::metadata(&target).expect("metadata");
        let digest = mvm_contract::hash::sha256_hex(b"busybox bytes");
        let mut budget = ScanBudget {
            hashed: 0,
            limit: 1,
        };

        assert_eq!(
            collect_aliases(
                &root,
                &target,
                &target_meta,
                &digest,
                b"busybox bytes".len() as u64,
                &mut budget,
            ),
            Err(InstallError::ScanBudgetExceeded)
        );
    }

    #[test]
    fn unreadable_directory_refuses_instead_of_leaving_coverage_unknown() {
        use std::os::unix::fs::PermissionsExt;

        let (_temp, root) = rootfs();
        let locked = root.join("locked");
        std::fs::create_dir(&locked).expect("locked dir");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000))
            .expect("lock dir");
        let commands = BTreeMap::from([("shell".to_string(), "/bin/sh".to_string())]);
        let result = build_tool_map(&commands, &root);
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700))
            .expect("unlock for cleanup");

        if unsafe { libc::geteuid() } != 0 {
            assert!(matches!(
                result,
                Err(InstallError::SubstitutionFailed { reason, .. })
                    if reason.contains("could not read directory")
            ));
        }
    }

    #[test]
    fn substitution_retries_once_after_making_the_parent_writable() {
        let calls = std::cell::Cell::new(0);
        let writable = std::cell::Cell::new(false);
        let result = substitute_with_fallback(
            "/bin/tool",
            || {
                calls.set(calls.get() + 1);
                if writable.get() {
                    Ok(())
                } else {
                    Err("read-only".into())
                }
            },
            || {
                writable.set(true);
                Ok(())
            },
        );
        assert!(result.is_ok());
        assert_eq!(calls.get(), 2);
    }

    #[test]
    fn empty_command_set_builds_an_empty_map() {
        let (_temp, root) = rootfs();
        let map = build_tool_map(&BTreeMap::new(), &root).expect("empty map");
        assert!(map.tools.is_empty());
    }
}
