//! Idle Firecracker processes a cold launch claims instead of starting one.
//!
//! Starting a Firecracker on the launch path costs a `bash` launch script, a
//! `systemd-run --user --scope` round trip to the user manager, and a wait for
//! the API socket: tens of milliseconds, and the D-Bus leg alone varies from 6
//! to 30 on a loaded host. None of it depends on the guest. So after a launch
//! boots, a replacement process is started in the background — same launch
//! line, same `sudo`/`setsid` posture, already inside a scope carrying the
//! ceilings a launch of that shape would get — and the next launch of that
//! shape claims it.
//!
//! An idle process is a Firecracker with nothing configured: no kernel, no
//! drive, no vsock, no guest memory, no plan. Everything a launch gives its
//! VMM is still sent over the API after the claim, exactly as on a cold start.
//! A claimed process is never returned: the VM's stop kills it like any other.
//!
//! **What must match.** The scope is created with its limits, so only a launch
//! whose limits are the ones the idle process was scoped with may claim it: the
//! same guest memory (so `MemoryMax` is guest RAM plus the fixed overhead) and
//! no CPU grant (so there is no `CPUQuota` to differ). `TasksMax` is the same
//! for every spawn. Any other launch starts its own process, as before. The
//! scope's unit name moves into the VM's state dir with the process, so the
//! limits read back into `plan.grants_enforced` from the cgroup exactly as they
//! do for a process the launch started itself.
//!
//! **Claiming.** Each idle process lives in its own directory under
//! [`mvm_core::config::fc_idle_pool_dir`]. A claim is an atomic `rename` of
//! that directory, so two launches cannot claim one process. The claimant then
//! renames the API socket, the console and log files, the scope record and the
//! pid marker into the VM's state dir. Both directories are under the mvm
//! home, so these are renames on one filesystem; a VM whose sockets fall back
//! to the short `/tmp` namespace does not use the pool. Firecracker's command
//! line still names the socket it was started with, so the claim records that
//! path ([`CLAIM_ORIGIN_FILE`]) for the stop path's identity check.
//!
//! **Release.** Every idle process has a reaper beside it, a detached shell
//! that stops it once it has sat unclaimed for the residency idle timeout, or
//! as soon as the pool directory is gone (a deleted home). Claiming stops the
//! reaper. The pool holds at most one process per shape and
//! [`MAX_IDLE_PROCESSES`] in all, is off under `MVM_RESIDENCY=cold`, and is
//! off when [`IDLE_POOL_ENV`] is `0`.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use mvm_vmm::host::network_endpoint_spawn::EndpointPid;

/// Set to `0` (or `false`) to start every Firecracker on the launch path.
pub const IDLE_POOL_ENV: &str = "MVM_FC_IDLE_POOL";

/// The most idle processes the pool keeps across all shapes.
pub const MAX_IDLE_PROCESSES: usize = 2;

/// Recorded in a VM's state dir when its Firecracker came from the pool: the
/// API socket path that process's command line names.
pub const CLAIM_ORIGIN_FILE: &str = "fc.api-sock-origin";

/// Prefix of a directory holding an unclaimed process.
const IDLE_PREFIX: &str = "idle-";
/// Prefix a claim renames that directory to.
const CLAIMED_PREFIX: &str = "claimed-";
/// The shape an idle process was scoped for.
const SHAPE_FILE: &str = "shape";
/// The reaper's pid and start time, so a claim can stop it.
const REAPER_PID_FILE: &str = "reaper.pid";
/// The idle Firecracker's pid and start time, recorded once its command line
/// was confirmed to name this entry's socket. Nothing in the pool signals a
/// pid that this record does not confirm.
pub(crate) const FC_IDENTITY_FILE: &str = "fc.identity";
/// Files a claim moves into the VM's state dir. The pid marker is moved last
/// and separately: its presence is what says the dir has a live VMM.
const MOVED_FILES: &[&str] = &["console.log", "firecracker.log", SPAWN_SCOPE_FILE];
/// The scope record `mvm_core::spawn_scope` writes beside the process.
const SPAWN_SCOPE_FILE: &str = "spawn-scope";
const API_SOCKET: &str = "fc.socket";
const PID_FILE: &str = "fc.pid";

/// Journal written into the claimed entry before adoption begins. Contains the
/// target `state_dir` as a single line, so crash recovery knows where the claim
/// was heading and can either finish or roll back.
const CLAIM_JOURNAL: &str = "claim.journal";

/// What an idle process was prepared for. Two launches of the same shape get
/// the same scope limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdleShape {
    guest_memory_mib: u32,
}

impl IdleShape {
    /// The shape of a launch, or `None` when it cannot use the pool: it carries
    /// a CPU grant (whose quota the idle scope does not have), its guest size is
    /// unknown, or it is a builder rather than a workload.
    #[must_use]
    pub fn for_launch(spec: &mvm_vmm::driver::spec::VmmSpec) -> Option<Self> {
        if spec.trusted_builder || !spec.serves_guest_agent() {
            return None;
        }
        Self::for_bounds(spec.memory_mib, spec.cpu_grant.as_ref())
    }

    fn for_bounds(
        guest_memory_mib: u32,
        cpu_grant: Option<&mvm_contract::grants::CpuGrant>,
    ) -> Option<Self> {
        if cpu_grant.is_some() || guest_memory_mib == 0 {
            return None;
        }
        Some(Self { guest_memory_mib })
    }

    fn bounds(self) -> mvm_core::spawn_scope::SpawnBounds {
        mvm_core::spawn_scope::SpawnBounds::for_guest_memory(self.guest_memory_mib)
    }

    fn render(self) -> String {
        format!("memory_mib={}\n", self.guest_memory_mib)
    }

    fn parse(text: &str) -> Option<Self> {
        let mib = text.trim().strip_prefix("memory_mib=")?.parse().ok()?;
        Self::for_bounds(mib, None)
    }
}

/// Whether this host keeps idle Firecracker processes at all.
#[must_use]
pub fn enabled() -> bool {
    cfg!(target_os = "linux")
        && env_allows(std::env::var(IDLE_POOL_ENV).ok().as_deref())
        && residency_allows(mvm_core::residency::resolve_residency().0.kind())
}

fn env_allows(value: Option<&str>) -> bool {
    !matches!(value.map(str::trim), Some("0" | "false" | "FALSE" | "no"))
}

fn residency_allows(kind: mvm_core::residency::ResidencyKind) -> bool {
    kind != mvm_core::residency::ResidencyKind::Cold
}

/// How long an idle process may wait for a claim: the residency idle timeout a
/// warm standby gets.
fn idle_lifetime() -> Duration {
    mvm_core::residency::ResidencyPolicy::always_warm()
        .idle_timeout()
        .unwrap_or(Duration::from_secs(20 * 60))
}

/// Remove the record that this state dir's VMM came from the pool. Called
/// whenever a Firecracker is started for the dir directly.
pub fn forget_claim_origin(state_dir: &Path) {
    let _ = std::fs::remove_file(state_dir.join(CLAIM_ORIGIN_FILE));
}

/// The socket path the claimed process serving `api_socket` was started with,
/// when the VMM in that socket's directory came from the pool.
///
/// Read back only when it has the shape a pool socket has, so a hand-edited
/// record cannot widen which processes the stop path will signal to anything
/// outside the pool.
#[must_use]
pub fn claim_origin_for(api_socket: &Path) -> Option<PathBuf> {
    let recorded = read_private(&api_socket.parent()?.join(CLAIM_ORIGIN_FILE))?;
    let origin = PathBuf::from(recorded.trim());
    is_pool_socket_path(&origin).then_some(origin)
}

fn is_pool_socket_path(path: &Path) -> bool {
    let dir = path.parent();
    path.is_absolute()
        && path.file_name().is_some_and(|name| name == API_SOCKET)
        && dir
            .and_then(Path::file_name)
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with(IDLE_PREFIX))
        && dir
            .and_then(Path::parent)
            .and_then(Path::file_name)
            .is_some_and(|name| {
                Some(name) == mvm_core::config::fc_idle_pool_dir_at("/").file_name()
            })
}

/// Claim an idle process of `shape` as the VMM for the VM whose state dir is
/// `state_dir` and whose API socket is to be `api_socket`.
///
/// Returns `true` when the VM now has a running, unconfigured Firecracker
/// exactly as a cold start would have left it. `false` means the caller starts
/// one itself; nothing it needs was touched.
///
/// Crash recovery: the claim writes a journal inside the claimed entry before
/// it begins moving files, recording the target `state_dir`. If the process
/// dies mid-adopt, [`recover_incomplete_claims`] reads the journal back and
/// cleans up — destroying the process if it is still running. The journal
/// uses the same identity-stable signalling as the pool itself (`EndpointPid`
/// records), never bare numeric PIDs.
pub fn claim(shape: IdleShape, state_dir: &Path, api_socket: &Path) -> bool {
    let root = mvm_core::config::fc_idle_pool_dir();
    // Only a VM whose sockets live in its state dir can take a process whose
    // files are renamed there.
    if api_socket.parent() != Some(state_dir) {
        return false;
    }
    // Clean up any claimed entries left by a crashed predecessor before
    // scanning for ready entries, so a stale claim does not block the pool.
    recover_incomplete_claims_in(&root);
    for entry in ready_entries(&root, shape) {
        // Use a random hex token, not a PID, so the claimed name is
        // identity-stable across PID-reuse scenarios.
        let token = claim_token();
        let claimed = root.join(format!(
            "{CLAIMED_PREFIX}{}-{token}",
            entry
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
        ));
        // The atomic step. A concurrent launch or the reaper that renamed it
        // first wins; try the next one.
        if std::fs::rename(&entry, &claimed).is_err() {
            continue;
        }
        // Persist the claim journal before any file moves, so crash recovery
        // knows what this claim was targeting.
        if let Err(error) = write_claim_journal(&claimed, state_dir) {
            tracing::warn!(
                error = %format!("{error:#}"),
                "could not persist the claim journal; rolling back"
            );
            let _ = std::fs::rename(&claimed, &entry);
            continue;
        }
        stop_reaper(&claimed, &entry);
        match adopt(&claimed, &entry, state_dir, api_socket) {
            Ok(()) => {
                let _ = std::fs::remove_dir_all(&claimed);
                return true;
            }
            Err(error) => {
                tracing::warn!(
                    error = %format!("{error:#}"),
                    "claimed idle Firecracker could not be handed to the launch; starting one"
                );
                destroy(&claimed, &entry, state_dir);
            }
        }
    }
    false
}

/// A random hex token for a claimed directory name, independent of the
/// claimant's PID. Used only as a collision-avoidance suffix, never for
/// signalling — identity-stable signalling uses `EndpointPid` records.
fn claim_token() -> String {
    // Read 8 bytes from /dev/urandom (always available on Linux, where the
    // pool runs). Falls back to timestamp + pid, which is still not a bare
    // PID used for signalling.
    let mut buf = [0u8; 8];
    match std::fs::File::open("/dev/urandom").and_then(|mut f| {
        use std::io::Read as _;
        f.read_exact(&mut buf)
    }) {
        Ok(()) => {
            let mut hex = String::with_capacity(16);
            for b in &buf {
                use std::fmt::Write as _;
                let _ = write!(hex, "{b:02x}");
            }
            hex
        }
        Err(_) => {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos());
            format!("{:x}{:x}", nanos & 0xffff_ffff, std::process::id())
        }
    }
}

/// Record which `state_dir` this claim targets, so crash recovery can clean up.
fn write_claim_journal(claimed: &Path, state_dir: &Path) -> Result<()> {
    write_private(
        &claimed.join(CLAIM_JOURNAL),
        state_dir.to_string_lossy().as_bytes(),
    )
    .context("writing claim journal")
}

/// Read the state-dir target from a claimed entry's journal.
fn read_claim_journal(claimed: &Path) -> Option<PathBuf> {
    read_private(&claimed.join(CLAIM_JOURNAL)).map(|s| PathBuf::from(s.trim()))
}

/// Clean up claimed entries left by a process that died mid-adopt.
///
/// For each `claimed-*` directory with a journal, the idle Firecracker inside
/// it is stopped (through its identity record, never a bare PID) and the entry
/// is removed. Files that were already moved into the target state dir are
/// cleaned up there too.
///
/// Called on the next launch, or by a host-agent restart. Safe to call
/// concurrently — each entry is handled at most once because destroying
/// removes the directory.
pub fn recover_incomplete_claims() {
    recover_incomplete_claims_in(&mvm_core::config::fc_idle_pool_dir());
}

fn recover_incomplete_claims_in(root: &Path) {
    let Ok(read) = std::fs::read_dir(root) else {
        return;
    };
    for entry in read.flatten() {
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        if !name_str.starts_with(CLAIMED_PREFIX) {
            continue;
        }
        let claimed = entry.path();
        let Some(state_dir) = read_claim_journal(&claimed) else {
            // No journal means either a pre-crash incomplete without a
            // journal (shouldn't happen with new code) or the cleanup
            // already ran. Either way, destroy if stale.
            if older_than(&claimed, ABANDONED_AFTER) {
                let origin = infer_origin_dir(root, name_str);
                destroy(&claimed, &origin, &claimed);
            }
            continue;
        };
        let origin = infer_origin_dir(root, name_str);
        tracing::info!(
            claimed = %claimed.display(),
            state_dir = %state_dir.display(),
            "recovering incomplete idle-pool claim"
        );
        destroy(&claimed, &origin, &state_dir);
    }
}

/// Reconstruct the original `idle-*` directory path from a `claimed-*` name.
fn infer_origin_dir(root: &Path, claimed_name: &str) -> PathBuf {
    // claimed_name = "claimed-idle-XXXX-TOKEN". Strip the "claimed-" prefix,
    // then strip the last "-TOKEN" suffix to recover "idle-XXXX".
    let after_prefix = claimed_name
        .strip_prefix(CLAIMED_PREFIX)
        .unwrap_or(claimed_name);
    let origin_name = match after_prefix.rfind('-') {
        Some(pos) if pos > 0 => &after_prefix[..pos],
        _ => after_prefix,
    };
    root.join(origin_name)
}

/// Idle entries of `shape` whose process is running and whose private socket
/// has been handed to the caller, oldest first.
fn ready_entries(root: &Path, shape: IdleShape) -> Vec<PathBuf> {
    let mut entries: Vec<(std::time::SystemTime, PathBuf)> = idle_entries(root)
        .into_iter()
        .filter(|dir| entry_shape(dir) == Some(shape))
        .filter(|dir| is_ready(dir))
        .map(|dir| {
            let created = std::fs::metadata(&dir)
                .and_then(|m| m.modified())
                .unwrap_or(std::time::UNIX_EPOCH);
            (created, dir)
        })
        .collect();
    entries.sort();
    entries.into_iter().map(|(_, dir)| dir).collect()
}

fn idle_entries(root: &Path) -> Vec<PathBuf> {
    let Ok(read) = std::fs::read_dir(root) else {
        return Vec::new();
    };
    read.flatten()
        .filter(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|name| name.starts_with(IDLE_PREFIX))
        })
        .map(|e| e.path())
        .collect()
}

fn entry_shape(dir: &Path) -> Option<IdleShape> {
    IdleShape::parse(&read_private(&dir.join(SHAPE_FILE))?)
}

fn is_ready(dir: &Path) -> bool {
    socket_is_private_to(&dir.join(API_SOCKET), effective_uid())
        && confirmed_firecracker(dir, &dir.join(API_SOCKET)).is_some()
}

fn socket_is_private_to(socket: &Path, uid: u32) -> bool {
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};

    // Refill binds as root before handing off ownership; a claim must not move
    // the socket out from under that handoff while it is still inaccessible.
    std::fs::symlink_metadata(socket).is_ok_and(|m| {
        m.file_type().is_socket() && m.uid() == uid && m.permissions().mode() & 0o777 == 0o600
    })
}

fn read_pid(path: &Path) -> Option<u32> {
    read_private(path)?.trim().parse().ok()
}

/// The pid a record names, while the live process at that pid is the one the
/// record was written for: same pid, same start time. A bare pid, a pid whose
/// process has since been replaced, and an unreadable record all answer `None`.
fn confirmed_pid(record: &Path) -> Option<u32> {
    let record = EndpointPid::parse(&read_private(record)?)?;
    record
        .is_live_and_ours()
        .then(|| u32::try_from(record.pid).ok())
        .flatten()
}

/// The Firecracker an entry's files describe, when its identity record
/// confirms the live process (pid and start time), its pid marker agrees, and
/// that process is the Firecracker serving `entry_socket` — the socket the
/// entry was created with, which its command line still names after a claim
/// renames the entry.
fn confirmed_firecracker(dir: &Path, entry_socket: &Path) -> Option<u32> {
    let pid = confirmed_pid(&dir.join(FC_IDENTITY_FILE))?;
    (read_pid(&dir.join(PID_FILE)) == Some(pid)
        && super::is_firecracker_for_socket(pid, entry_socket).unwrap_or(false))
    .then_some(pid)
}

/// Write a pool-owned file: created fresh, mode 0600, and never through a
/// symlink someone left at the path.
fn write_private(path: &Path, contents: &[u8]) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    file.write_all(contents)
        .with_context(|| format!("writing {}", path.display()))
}

/// Read a pool-owned file without following a symlink at its path.
fn read_private(path: &Path) -> Option<String> {
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .ok()?;
    let mut text = String::new();
    file.read_to_string(&mut text).ok()?;
    Some(text)
}

/// Create a pool directory readable by its owner alone.
fn create_private_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .with_context(|| format!("creating {}", path.display()))
}

/// Move a claimed process's files into the VM's state dir, pid marker last.
fn adopt(claimed: &Path, origin_dir: &Path, state_dir: &Path, api_socket: &Path) -> Result<()> {
    if confirmed_firecracker(claimed, &origin_dir.join(API_SOCKET)).is_none() {
        bail!("the claimed idle Firecracker is no longer the process its entry recorded");
    }
    move_files(claimed, origin_dir, state_dir, api_socket)
}

/// The renames of [`adopt`], split from its liveness check so they can be
/// exercised without a Firecracker.
fn move_files(
    claimed: &Path,
    origin_dir: &Path,
    state_dir: &Path,
    api_socket: &Path,
) -> Result<()> {
    // What a cold start's launch script clears before it starts a process:
    // a stale API socket and the vsock sockets a previous boot left behind.
    let abs_dir = state_dir.to_string_lossy();
    for stale in [
        api_socket.to_path_buf(),
        PathBuf::from(super::firecracker_vsock_uds_path(&abs_dir)),
        state_dir.join("v.sock"),
        state_dir.join(SPAWN_SCOPE_FILE),
    ] {
        remove_if_present(&stale)?;
    }
    std::fs::rename(claimed.join(API_SOCKET), api_socket)
        .with_context(|| format!("moving the API socket to {}", api_socket.display()))?;
    for name in MOVED_FILES {
        let from = claimed.join(name);
        if from.exists() {
            std::fs::rename(&from, state_dir.join(name))
                .with_context(|| format!("moving {name} into {}", state_dir.display()))?;
        }
    }
    let origin_record = state_dir.join(CLAIM_ORIGIN_FILE);
    remove_if_present(&origin_record)?;
    write_private(
        &origin_record,
        origin_dir.join(API_SOCKET).to_string_lossy().as_bytes(),
    )
    .context("recording the claimed process's original socket")?;
    std::fs::rename(claimed.join(PID_FILE), state_dir.join(PID_FILE))
        .context("moving the pid marker")?;
    Ok(())
}

fn remove_if_present(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("removing stale {}", path.display())),
    }
}

/// Stop a claimed process that could not be handed over, and forget it.
///
/// Only a process its entry's identity record confirms is signalled; a pid
/// marker on its own is never enough.
fn destroy(claimed: &Path, entry: &Path, state_dir: &Path) {
    let pid_file = [claimed.join(PID_FILE), state_dir.join(PID_FILE)]
        .into_iter()
        .find(|path| path.exists());
    if let Some(pid_file) = pid_file
        && let Some(pid) = confirmed_pid(&claimed.join(FC_IDENTITY_FILE))
        && read_pid(&pid_file) == Some(pid)
        && super::is_firecracker_for_socket(pid, &entry.join(API_SOCKET)).unwrap_or(false)
        && let Err(error) =
            crate::driver::fc::terminate_firecracker_pid("idle Firecracker", pid, &pid_file)
    {
        tracing::warn!(error = %format!("{error:#}"), "could not stop a claimed idle Firecracker");
    }
    let _ = std::fs::remove_dir_all(claimed);
    forget_claim_origin(state_dir);
}

/// Stop the reaper watching an entry that has just been claimed. Signalled
/// only while its record confirms the live process (pid and start time) and
/// its command line still names the entry, so a recycled pid is left alone.
fn stop_reaper(claimed: &Path, entry: &Path) {
    let Some(pid) = confirmed_pid(&claimed.join(REAPER_PID_FILE)) else {
        return;
    };
    let names_entry = std::fs::read(format!("/proc/{pid}/cmdline")).is_ok_and(|cmdline| {
        let entry = entry.to_string_lossy();
        cmdline
            .split(|b| *b == 0)
            .any(|arg| arg == entry.as_bytes())
    });
    if names_entry {
        // The reaper leads its own session; signal the group so its `sleep`
        // goes with it.
        // SAFETY: `kill` takes plain integers and dereferences nothing.
        unsafe {
            libc::kill(-(pid as libc::pid_t), libc::SIGKILL);
        }
    }
}

/// Start a replacement process of `shape` in the background, unless the pool
/// already holds one or is full.
pub fn refill_in_background(shape: IdleShape) {
    let root = mvm_core::config::fc_idle_pool_dir();
    let spawned = std::thread::Builder::new()
        .name("fc-idle-refill".into())
        .spawn(move || {
            if let Err(error) = refill(&root, shape) {
                tracing::debug!(error = %format!("{error:#}"), "idle Firecracker not refilled");
            }
        });
    if let Err(error) = spawned {
        tracing::debug!(%error, "idle Firecracker refill thread not started");
    }
}

fn refill(root: &Path, shape: IdleShape) -> Result<()> {
    discard_abandoned(root);
    let entries = idle_entries(root);
    if !needs_refill(&entries, shape) {
        return Ok(());
    }
    match std::fs::symlink_metadata(root) {
        Ok(meta) if meta.file_type().is_dir() => {}
        Ok(_) => bail!("{} is not a directory", root.display()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => create_private_dir(root)?,
        Err(e) => return Err(e).with_context(|| format!("reading {}", root.display())),
    }
    let id = entry_id();
    let dir = root.join(format!("{IDLE_PREFIX}{id}"));
    let socket = dir.join(API_SOCKET);
    if !mvm_core::config::fits_unix_socket_path(&socket) {
        bail!("{} is too long for a Unix socket", socket.display());
    }
    create_private_dir(&dir)?;
    write_private(&dir.join(SHAPE_FILE), shape.render().as_bytes())?;
    // The reaper first: if this process dies anywhere below, the entry is still
    // released on time.
    if let Err(error) = start_reaper(&dir) {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(error);
    }
    let abs_dir = dir.to_string_lossy().into_owned();
    let scope = super::spawn_scope_prefix(&format!("fc-idle-{id}"), &dir, &shape.bounds());
    super::start_idle_firecracker(&abs_dir, &socket.to_string_lossy(), &scope)
        .context("starting an idle Firecracker")?;
    if confirmed_firecracker(&dir, &socket).is_none() {
        bail!("the idle Firecracker did not record an identity that confirms it");
    }
    // Owned by the invoking user from here, as a launch's socket is after
    // adoption; doing it now keeps it off the claim's path.
    super::adopt_api_socket(&socket.to_string_lossy())?;
    Ok(())
}

/// How long an entry may go without a running process before it is taken to
/// be a refill that died partway (its `mvmctl` exited first, say).
const ABANDONED_AFTER: Duration = Duration::from_secs(10);

/// Remove entries whose process never came up, so they do not hold a shape's
/// place in the pool until their reaper's timer runs out.
fn discard_abandoned(root: &Path) {
    for dir in idle_entries(root) {
        if is_ready(&dir) || !older_than(&dir, ABANDONED_AFTER) {
            continue;
        }
        let parked = dir.with_file_name(format!(
            "{CLAIMED_PREFIX}abandoned-{}",
            dir.file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default()
        ));
        if std::fs::rename(&dir, &parked).is_ok() {
            stop_reaper(&parked, &dir);
            destroy(&parked, &dir, &parked);
        }
    }
}

fn older_than(dir: &Path, age: Duration) -> bool {
    std::fs::metadata(dir)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|modified| modified.elapsed().ok())
        .is_some_and(|elapsed| elapsed > age)
}

/// Whether the pool should gain a process of `shape`, given its entries.
fn needs_refill(entries: &[PathBuf], shape: IdleShape) -> bool {
    entries.len() < MAX_IDLE_PROCESSES && !entries.iter().any(|dir| entry_shape(dir) == Some(shape))
}

fn entry_id() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!("{:x}{:x}", nanos & 0xffff_ffff_ffff, std::process::id())
}

/// The reaper: a detached shell that waits for the process's pid marker, waits
/// out the idle lifetime, then stops the process if it was never claimed — or,
/// if the pool directory itself is gone, stops it regardless, because nothing
/// is left that could claim or find it.
fn reaper_script() -> &'static str {
    r#"E=$1; T=$2; S=$3
st() { sed 's/^.*) //' "/proc/$1/stat" 2>/dev/null | cut -d' ' -f20; }
i=0
while [ ! -s "$E/fc.pid" ] && [ "$i" -lt 30 ]; do sleep 1; i=$((i+1)); done
P=$(cat "$E/fc.pid" 2>/dev/null)
P0=""
[ -n "$P" ] && P0=$(st "$P")
sleep "$T"
owned=0
if mv "$E" "$E.expired" 2>/dev/null; then owned=1
elif [ ! -d "$(dirname "$E")" ]; then owned=1
fi
if [ "$owned" = 1 ] && [ -n "$P" ] && [ -n "$P0" ] \
   && [ "$(st "$P")" = "$P0" ] \
   && [ "$(cat /proc/$P/comm 2>/dev/null)" = firecracker ] \
   && tr '\0' '\n' < /proc/$P/cmdline | grep -qxF "$E/fc.socket"; then
  $S kill "$P"
fi
rm -rf "$E.expired""#
}

fn start_reaper(dir: &Path) -> Result<()> {
    let sudo = super::sudo_prefix_for_euid(effective_uid()).trim();
    let sudo = if sudo.is_empty() {
        String::new()
    } else {
        format!("{sudo} -n")
    };
    let child = mvm_core::env_hygiene::helper_command("setsid")
        .args(["sh", "-c", reaper_script(), "mvm-fc-idle-reaper"])
        .arg(dir)
        .arg(idle_lifetime().as_secs().to_string())
        .arg(sudo)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("starting the idle Firecracker reaper")?;
    write_private(
        &dir.join(REAPER_PID_FILE),
        EndpointPid::of_child(child.id()).render().as_bytes(),
    )?;
    Ok(())
}

fn effective_uid() -> u32 {
    // SAFETY: `geteuid` takes no arguments and cannot fail.
    unsafe { libc::geteuid() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shape(mib: u32) -> IdleShape {
        IdleShape::for_bounds(mib, None).expect("a plain shape")
    }

    #[test]
    fn a_launch_with_a_cpu_grant_or_no_memory_size_has_no_shape() {
        let grant = mvm_contract::grants::CpuGrant::Share { millicores: 500 };
        assert_eq!(IdleShape::for_bounds(512, Some(&grant)), None);
        assert_eq!(IdleShape::for_bounds(0, None), None);
        assert_eq!(IdleShape::for_bounds(512, None), Some(shape(512)));
    }

    #[test]
    fn a_shape_round_trips_through_its_file() {
        assert_eq!(IdleShape::parse(&shape(768).render()), Some(shape(768)));
        assert_eq!(IdleShape::parse("memory_mib=0\n"), None);
        assert_eq!(IdleShape::parse("garbage"), None);
    }

    /// The shape fixes the scope's limits, so two launches that would get
    /// different ceilings can never share one.
    #[test]
    fn a_shape_scopes_exactly_what_a_cold_start_of_it_would() {
        assert_eq!(
            shape(512).bounds(),
            mvm_core::spawn_scope::SpawnBounds::for_guest_memory(512).with_cpu_grant(None)
        );
        assert_ne!(shape(512).bounds(), shape(1024).bounds());
    }

    #[test]
    fn the_pool_is_off_when_asked_and_under_cold_residency() {
        assert!(env_allows(None));
        assert!(env_allows(Some("1")));
        assert!(!env_allows(Some("0")));
        assert!(!env_allows(Some("false")));
        assert!(!residency_allows(mvm_core::residency::ResidencyKind::Cold));
        assert!(residency_allows(mvm_core::residency::ResidencyKind::Parked));
        assert!(residency_allows(mvm_core::residency::ResidencyKind::Warm));
    }

    fn entry(root: &Path, name: &str, mib: Option<u32>) -> PathBuf {
        let dir = root.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        if let Some(mib) = mib {
            std::fs::write(dir.join(SHAPE_FILE), shape(mib).render()).unwrap();
        }
        dir
    }

    #[test]
    fn the_pool_keeps_one_process_per_shape_and_a_bounded_total() {
        let root = tempfile::tempdir().unwrap();
        assert!(needs_refill(&idle_entries(root.path()), shape(512)));
        entry(root.path(), "idle-a", Some(512));
        assert!(!needs_refill(&idle_entries(root.path()), shape(512)));
        assert!(needs_refill(&idle_entries(root.path()), shape(1024)));
        entry(root.path(), "idle-b", Some(1024));
        assert!(
            !needs_refill(&idle_entries(root.path()), shape(2048)),
            "full at {MAX_IDLE_PROCESSES}"
        );
        // A claimed entry is not idle and does not count.
        entry(root.path(), "claimed-idle-c-1", Some(2048));
        assert_eq!(idle_entries(root.path()).len(), 2);
    }

    /// An entry whose process never came up, or whose socket is missing, is
    /// not offered to a launch.
    #[test]
    fn only_a_running_process_with_its_socket_is_claimable() {
        let root = tempfile::tempdir().unwrap();
        let dir = entry(root.path(), "idle-a", Some(512));
        assert!(ready_entries(root.path(), shape(512)).is_empty(), "no pid");
        std::fs::write(dir.join(PID_FILE), "999999999").unwrap();
        assert!(
            ready_entries(root.path(), shape(512)).is_empty(),
            "dead pid"
        );
    }

    #[test]
    fn an_idle_socket_is_unclaimable_until_private_to_the_caller() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join(API_SOCKET);
        let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let uid = std::fs::symlink_metadata(&socket).unwrap().uid();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();

        assert!(
            !socket_is_private_to(&socket, uid.checked_add(1).unwrap()),
            "a bound socket owned by the launcher is not ready for another user"
        );
        for mode in [0o000, 0o400, 0o640, 0o660, 0o666] {
            std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(
                !socket_is_private_to(&socket, uid),
                "ownership alone does not complete the private handoff: {mode:o}"
            );
        }
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(socket_is_private_to(&socket, uid));
    }

    #[test]
    fn idle_socket_readiness_refuses_missing_files_and_symlinks() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join(API_SOCKET);
        assert!(!socket_is_private_to(&socket, effective_uid()));
        std::fs::write(&socket, b"not a socket").unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(!socket_is_private_to(&socket, effective_uid()));
        std::fs::remove_file(&socket).unwrap();
        let target = dir.path().join("target.socket");
        let _listener = std::os::unix::net::UnixListener::bind(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(&target, &socket).unwrap();
        assert!(!socket_is_private_to(&socket, effective_uid()));
    }

    #[test]
    fn a_claim_origin_is_honoured_only_when_it_names_a_pool_socket() {
        let state = tempfile::tempdir().unwrap();
        let api = state.path().join(API_SOCKET);
        assert_eq!(claim_origin_for(&api), None);

        let pool_socket = mvm_core::config::fc_idle_pool_dir_at("/srv/state")
            .join("idle-1f")
            .join(API_SOCKET);
        std::fs::write(
            state.path().join(CLAIM_ORIGIN_FILE),
            pool_socket.to_string_lossy().as_bytes(),
        )
        .unwrap();
        assert_eq!(claim_origin_for(&api), Some(pool_socket));

        for other in [
            "/srv/state/vms/other/fc.socket",
            "/srv/state/fc-idle/idle-1f/other.sock",
            "relative/fc-idle/idle-1f/fc.socket",
            "/srv/state/fc-idle/claimed-1f/fc.socket",
        ] {
            std::fs::write(state.path().join(CLAIM_ORIGIN_FILE), other).unwrap();
            assert_eq!(claim_origin_for(&api), None, "{other}");
        }
        forget_claim_origin(state.path());
        assert!(!state.path().join(CLAIM_ORIGIN_FILE).exists());
    }

    /// The hand-over moves every file a cold start would have put in the state
    /// dir, the pid marker last, and records where the socket came from.
    #[test]
    fn adopting_moves_the_process_files_into_the_state_dir() {
        let root = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let claimed = entry(root.path(), "claimed-idle-a-1", Some(512));
        let origin = root.path().join("idle-a");
        // A real socket, so the move is the move a launch makes.
        let listener = std::os::unix::net::UnixListener::bind(claimed.join(API_SOCKET)).unwrap();
        for name in MOVED_FILES {
            std::fs::write(claimed.join(name), name).unwrap();
        }
        // This test process stands in for Firecracker only through the pid
        // probe, so the hand-over is driven past it directly.
        std::fs::write(claimed.join(PID_FILE), "1").unwrap();
        std::fs::write(state.path().join(SPAWN_SCOPE_FILE), "stale.scope").unwrap();
        let api = state.path().join(API_SOCKET);

        move_files(&claimed, &origin, state.path(), &api).expect("moved");

        assert!(
            std::os::unix::net::UnixStream::connect(&api).is_ok(),
            "same listener"
        );
        drop(listener);
        for name in MOVED_FILES {
            assert_eq!(
                std::fs::read_to_string(state.path().join(name)).unwrap(),
                *name
            );
        }
        assert_eq!(
            std::fs::read_to_string(state.path().join(PID_FILE)).unwrap(),
            "1"
        );
        assert_eq!(
            std::fs::read_to_string(state.path().join(CLAIM_ORIGIN_FILE)).unwrap(),
            origin.join(API_SOCKET).to_string_lossy()
        );
    }

    /// An idle process scoped without a mechanism leaves no scope record, and
    /// a stale one from an earlier boot of the VM must not be read back as
    /// this process's.
    #[test]
    fn adopting_without_a_scope_record_clears_a_stale_one() {
        let root = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let claimed = entry(root.path(), "claimed-idle-a-1", Some(512));
        let _listener = std::os::unix::net::UnixListener::bind(claimed.join(API_SOCKET)).unwrap();
        std::fs::write(claimed.join(PID_FILE), "1").unwrap();
        std::fs::write(state.path().join(SPAWN_SCOPE_FILE), "stale.scope").unwrap();
        move_files(
            &claimed,
            &root.path().join("idle-a"),
            state.path(),
            &state.path().join(API_SOCKET),
        )
        .expect("moved");
        assert!(!state.path().join(SPAWN_SCOPE_FILE).exists());
    }

    /// A VM whose sockets fell back to the short `/tmp` namespace cannot take
    /// a process whose socket is renamed into its state dir.
    #[test]
    fn a_vm_whose_socket_is_outside_its_state_dir_starts_its_own_process() {
        let state = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        assert!(!claim(
            shape(512),
            state.path(),
            &elsewhere.path().join(API_SOCKET)
        ));
    }

    #[cfg(target_os = "linux")]
    /// A child standing in for a pool process: `sh -c 'sleep 30'` in its own
    /// session, its argv naming `entry` the way a reaper's does.
    fn session_child(entry: &Path) -> std::process::Child {
        std::process::Command::new("setsid")
            .args(["sh", "-c", "sleep 30", "mvm-fc-idle-reaper"])
            .arg(entry)
            .spawn()
            .expect("spawn a stand-in process")
    }

    #[cfg(target_os = "linux")]
    fn alive(child: &mut std::process::Child) -> bool {
        child.try_wait().expect("try_wait").is_none()
    }

    #[cfg(target_os = "linux")]
    fn wait_gone(child: &mut std::process::Child) -> bool {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            if !alive(child) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        false
    }

    #[cfg(target_os = "linux")]
    fn record(child: &std::process::Child) -> EndpointPid {
        EndpointPid::of_child(child.id())
    }

    /// A bare pid, and a live process whose start time is not the recorded
    /// one, are never confirmed; only the exact record is.
    #[cfg(target_os = "linux")]
    #[test]
    fn only_a_pid_with_its_recorded_start_time_is_confirmed() {
        let dir = tempfile::tempdir().unwrap();
        let mut child = session_child(dir.path());
        let real = record(&child);
        let file = dir.path().join(REAPER_PID_FILE);

        std::fs::write(&file, child.id().to_string()).unwrap();
        assert_eq!(confirmed_pid(&file), None, "a bare pid proves nothing");

        let recycled = EndpointPid {
            started: real.started.map(|started| started + 1),
            ..real
        };
        std::fs::write(&file, recycled.render()).unwrap();
        assert_eq!(confirmed_pid(&file), None, "another process at that pid");

        std::fs::write(&file, real.render()).unwrap();
        assert_eq!(confirmed_pid(&file), Some(child.id()));
        let _ = child.kill();
        let _ = child.wait();
    }

    /// A reaper is signalled only through a record that confirms it. A bare
    /// pid or a wrong start time leaves the live process alone.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_reaper_is_never_signalled_through_a_bare_or_stale_record() {
        let root = tempfile::tempdir().unwrap();
        let entry = root.path().join("idle-a");
        let claimed = entry_dir_for_claim(root.path());
        let mut child = session_child(&entry);
        let real = record(&child);
        let file = claimed.join(REAPER_PID_FILE);

        std::fs::write(&file, child.id().to_string()).unwrap();
        stop_reaper(&claimed, &entry);
        std::thread::sleep(Duration::from_millis(100));
        assert!(alive(&mut child), "signalled through a bare pid");

        let stale = EndpointPid {
            started: real.started.map(|started| started + 1),
            ..real
        };
        std::fs::write(&file, stale.render()).unwrap();
        stop_reaper(&claimed, &entry);
        std::thread::sleep(Duration::from_millis(100));
        assert!(alive(&mut child), "signalled through a wrong start time");

        std::fs::write(&file, real.render()).unwrap();
        stop_reaper(&claimed, &entry);
        assert!(wait_gone(&mut child), "the confirmed reaper is stopped");
    }

    /// Destroying a claim never signals a process its identity record does not
    /// confirm, whatever the pid marker says.
    #[cfg(target_os = "linux")]
    #[test]
    fn destroy_never_signals_a_bare_or_stale_pid() {
        let root = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let mut child = session_child(root.path());
        let real = record(&child);
        for identity in [
            child.id().to_string(),
            EndpointPid {
                started: real.started.map(|started| started + 1),
                ..real
            }
            .render(),
        ] {
            let claimed = entry_dir_for_claim(root.path());
            std::fs::write(claimed.join(PID_FILE), child.id().to_string()).unwrap();
            std::fs::write(claimed.join(FC_IDENTITY_FILE), identity).unwrap();
            destroy(&claimed, root.path(), state.path());
            std::thread::sleep(Duration::from_millis(100));
            assert!(alive(&mut child), "signalled through an unconfirmed record");
        }
        let _ = child.kill();
        let _ = child.wait();
    }

    #[cfg(target_os = "linux")]
    fn entry_dir_for_claim(root: &Path) -> PathBuf {
        let dir = root.join(format!("claimed-idle-a-{}", claim_token()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The claim token never contains the caller's PID as a plain decimal
    /// number, so it cannot be confused with a signalling target.
    #[test]
    fn a_claim_token_is_not_a_bare_pid() {
        let token = claim_token();
        assert!(
            token.parse::<u32>().is_err() || token.len() > 10,
            "the token must not look like a bare PID: {token}"
        );
        // Tokens are non-empty hex strings.
        assert!(!token.is_empty());
        assert!(
            token.chars().all(|c| c.is_ascii_hexdigit()),
            "token must be hex: {token}"
        );
    }

    /// A claim journal round-trips the target state dir.
    #[test]
    fn a_claim_journal_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let state = Path::new("/srv/state/vms/test-vm");
        write_claim_journal(dir.path(), state).unwrap();
        assert_eq!(read_claim_journal(dir.path()), Some(state.to_path_buf()));
    }

    /// The origin dir name is recovered from a claimed entry's name.
    #[test]
    fn infer_origin_dir_reconstructs_the_idle_entry() {
        let root = Path::new("/pool");
        assert_eq!(
            infer_origin_dir(root, "claimed-idle-abc-deadbeef01234567"),
            root.join("idle-abc")
        );
    }

    /// Recovery cleans up a claimed entry with a journal.
    #[test]
    fn recovery_destroys_incomplete_claims_with_journals() {
        let root = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        // Simulate a crash: create a claimed entry with a journal but no
        // completed adoption.
        let claimed = entry(root.path(), "claimed-idle-x-aabbccdd", Some(512));
        std::fs::write(
            claimed.join(CLAIM_JOURNAL),
            state.path().to_string_lossy().as_bytes(),
        )
        .unwrap();
        assert!(claimed.exists());

        recover_incomplete_claims_in(root.path());

        assert!(!claimed.exists(), "the incomplete claim must be removed");
    }

    /// Pool files are created fresh, owner-only, and never through a symlink.
    #[test]
    fn pool_files_are_private_and_never_written_through_a_symlink() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(SHAPE_FILE);
        write_private(&file, b"memory_mib=512\n").unwrap();
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(write_private(&file, b"again").is_err(), "never overwritten");

        let target = dir.path().join("target");
        std::fs::write(&target, "untouched").unwrap();
        let link = dir.path().join(REAPER_PID_FILE);
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(write_private(&link, b"1").is_err());
        assert_eq!(read_private(&link), None, "not read through a symlink");
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "untouched");

        let sub = dir.path().join("pool");
        create_private_dir(&sub).unwrap();
        assert_eq!(
            std::fs::metadata(&sub).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[test]
    fn the_reaper_only_stops_a_firecracker_serving_its_own_entry() {
        let script = reaper_script();
        assert!(
            script.contains(r#"mv "$E" "$E.expired""#),
            "claim race decided by rename"
        );
        assert!(script.contains("= firecracker"));
        assert!(
            script.contains(r#"[ "$(st "$P")" = "$P0" ]"#),
            "the start time read when the pid appeared must still hold"
        );
        assert!(script.contains(r#"grep -qxF "$E/fc.socket""#));
    }
}
