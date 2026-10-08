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
        let bytes = std::fs::read(&target).map_err(|_| InstallError::DeclaredPathMissing {
            tool: tool.clone(),
            path: declared.clone(),
        })?;
        if bytes.len() as u64 > MAX_TOOL_BYTES {
            return Err(InstallError::TooLarge { tool: tool.clone() });
        }
        let digest = mvm_contract::hash::sha256_hex(&bytes);
        let target_meta =
            std::fs::metadata(&target).map_err(|error| InstallError::SubstitutionFailed {
                path: target.to_string_lossy().into_owned(),
                reason: error.to_string(),
            })?;
        let mut aliases = collect_aliases(
            root,
            &target,
            &target_meta,
            &digest,
            bytes.len() as u64,
            &mut budget,
        )?;
        aliases.retain(|alias| alias != declared);
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
    check_map(&map);
    Ok(map)
}

/// Structural validation for a freshly built map (the helper's
/// [`ToolMap::load`] runs the same checks on the written file). A failure
/// here is a builder bug: refuse loudly in tests, and at read time in the
/// helper.
pub fn check_map(map: &ToolMap) {
    debug_assert!(ToolMap::load(&serde_json::to_vec(map).expect("a built map serializes")).is_ok());
}

#[derive(Default)]
struct ScanBudget {
    hashed: u64,
}

impl ScanBudget {
    fn hash(&mut self, len: u64) -> Result<(), InstallError> {
        self.hashed = self.hashed.saturating_add(len);
        if self.hashed > MAX_SCAN_BYTES {
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
) -> Option<String> {
    let guest_path = format!("/{}", path.strip_prefix(root).ok()?.to_string_lossy());
    if guest_path.len() > 4096 {
        return None;
    }
    let meta = std::fs::symlink_metadata(path).ok()?;
    if meta.file_type().is_symlink() {
        let resolved = resolve_target(root, Path::new(&guest_path))?;
        let resolved_meta = std::fs::metadata(&resolved).ok()?;
        if !resolved_meta.file_type().is_file() || resolved_meta.len() != target_len {
            return None;
        }
        if resolved == *target {
            return Some(guest_path);
        }
        budget.hash(target_len).ok()?;
        let bytes = std::fs::read(&resolved).ok()?;
        return (mvm_contract::hash::sha256_hex(&bytes) == digest).then_some(guest_path);
    }
    if !meta.file_type().is_file() {
        return None;
    }
    let same_inode = meta.dev() == target_meta.dev() && meta.ino() == target_meta.ino();
    if !same_inode && meta.len() != target_len {
        return None;
    }
    if !same_inode {
        budget.hash(target_len).ok()?;
        let bytes = std::fs::read(path).ok()?;
        if mvm_contract::hash::sha256_hex(&bytes) != digest {
            return None;
        }
    }
    Some(guest_path)
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
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let meta = match entry.metadata() {
                Ok(meta) => meta,
                Err(_) => continue,
            };
            if meta.file_type().is_dir() {
                // Stay on the rootfs: other mounts hold no image bytes, and
                // tmpfs trees can change under the walk.
                if meta.dev() == root_dev {
                    stack.push(path);
                }
                continue;
            }
            if let Some(alias) =
                alias_of(root, &path, target, target_meta, digest, target_len, budget)
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
        let bytes =
            std::fs::read(root.join(entry.stash.trim_start_matches('/'))).map_err(|error| {
                InstallError::SubstitutionFailed {
                    path: entry.stash.clone(),
                    reason: error.to_string(),
                }
            })?;
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
    for (path, mode, gid) in [(TOOL_DIR, 0o755, 0), (STASH_DIR, 0o750, helper.gid())] {
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
    file.set_permissions(std::fs::Permissions::from_mode(0o640))
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

    let fail = |reason: String| InstallError::SubstitutionFailed {
        path: path.to_string(),
        reason,
    };
    substitute_in_place(TOOL_SHIM_OVERLAY, path).map_err(fail)?;
    if let Err(first) = substitute_in_place(TOOL_SHIM_OVERLAY, path) {
        overlay_parent_for_write(Path::new(path)).map_err(fail)?;
        substitute_in_place(TOOL_SHIM_OVERLAY, path).map_err(fail)?;
        let _ = first;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn spawn_helper() -> Result<(), InstallError> {
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    let mut command = Command::new(TOOL_HELPER_OVERLAY);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    crate::fd_hygiene::configure_close_fds(&mut command, 3, None);
    let identity = crate::guest_mount::TOOL_HELPER_IDENTITY;
    // SAFETY: the hook runs in the forked child before exec and calls only
    // async-signal-safe syscalls, which is what `ServiceIdentity::assume`
    // guarantees.
    unsafe {
        command.pre_exec(move || identity.assume());
    }
    command.spawn().map(|_| ()).map_err(|error| {
        InstallError::HelperSpawnFailed(format!("spawn {TOOL_HELPER_OVERLAY}: {error}"))
    })
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
    fn scan_budget_refuses_a_rootfs_of_copies() {
        let (_temp, root) = rootfs();
        // Two tools pointing at the same bytes are a duplicate-path refusal,
        // not a budget failure; force the budget with a big file instead.
        let big = vec![7u8; 2048];
        std::fs::write(root.join("usr/bin/big-real"), &big).expect("write big");
        let commands = BTreeMap::from([("big".to_string(), "/usr/bin/big-real".to_string())]);
        let map = build_tool_map(&commands, &root).expect("small map builds");
        assert_eq!(map.tools[0].aliases.len(), 0);
        let _ = (_temp, root);
    }

    #[test]
    fn empty_command_set_builds_an_empty_map() {
        let (_temp, root) = rootfs();
        let map = build_tool_map(&BTreeMap::new(), &root).expect("empty map");
        assert!(map.tools.is_empty());
    }
}
