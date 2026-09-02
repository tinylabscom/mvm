//! Cross-process locking and sparse allocation for the builder VM's
//! persistent block images.
//!
//! Two images live here: the Nix store
//! (`<builder_cache_dir>/nix-store-<arch>.img`, shared by every builder
//! backend) and any user-attached persistent volume. Both are attached
//! to a guest as writable virtio-blk devices, and two guests mounting
//! one ext4 read-write corrupts it — so each writable image is guarded
//! by an exclusive `flock` on a `<image>.lock` sidecar, held for the
//! VM's lifetime.
//!
//! Contention is expected rather than exceptional: a second
//! `mvmctl build` in another terminal is a normal thing to do. The
//! acquire path therefore queues (see [`LockWait`]) and reports who it
//! is waiting for, instead of failing and asking the operator to retry.

use std::path::{Path, PathBuf};
use std::time::Duration;

use super::LIBKRUN_BLOCK_DEVICE_TAIL_RESERVE_BYTES;
use crate::builder_vm::BuilderVmError;

/// Host-side exclusive lock guarding the persistent `/nix-store` sparse
/// image.
///
/// The builder VM attaches the image as a writable virtio-blk device;
/// the guest's `mvm-host-vm-init` mounts it as ext4 at `/nix-store`.
/// Two independent guests mounting the same ext4 image read-write can
/// corrupt the filesystem, so the host holds an exclusive `flock` for
/// the full VM lifetime.
///
/// The lock lives on a **sidecar** `<image>.lock` file, NOT on the
/// image fd itself. The macOS hypervisor takes its own exclusive lock on
/// the disk image when the VM starts; if the host also held an `flock` on
/// the image it would collide ("The storage device attachment is
/// invalid"). libkrun doesn't lock the image, so it was unaffected — the
/// sidecar split keeps the cross-process serialisation while letting the
/// hypervisor open the image exclusively. The host holds no fd on the
/// image.
///
/// `_file: std::fs::File` is **load-bearing** — it's the sidecar lock
/// handle; dropping the guard releases the lock. Callers must keep the
/// guard alive until the supervisor exits and all artifact reads are
/// done. Called out explicitly because an underscore-prefixed field
/// reads as inert; it isn't.
///
/// Hypervisor-agnostic: both libkrun and HVF attach the same image
/// path as a virtio-blk device. Migrated from `libkrun_builder.rs`.
#[derive(Debug)]
pub struct NixStoreImageLock {
    path: PathBuf,
    _file: std::fs::File,
}

impl NixStoreImageLock {
    /// Path to the image file. Callers pass this into the hypervisor as
    /// the `virtio-blk` device backing. (The lock is on `<path>.lock`.)
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Sidecar lock path for an image: `<image>.lock` (appended, not an
/// extension swap, so `foo.img` → `foo.img.lock`). Ends in `.lock` so
/// it never matches `cache info`'s `nix-store-*.img` glob.
pub(crate) fn sidecar_lock_path(image: &Path) -> PathBuf {
    let mut s = image.as_os_str().to_os_string();
    s.push(".lock");
    PathBuf::from(s)
}

/// Sparse-allocate `path` to `size_bytes` minus the libkrun tail reserve if
/// it's missing or empty, then close the fd. Existing non-empty images are
/// left at their current size.
///
/// The filesystem records the size without
/// allocating blocks until something writes them (APFS + ext4), so a
/// multi-GiB cap costs ~nothing until used. An existing non-empty file
/// is left untouched so a warm store / volume survives across runs.
///
/// The fd is dropped before returning — deliberately. The host must
/// hold no open handle on the image so the hypervisor (HVF) can
/// open it exclusively; serialisation lives on the sidecar lock.
pub(crate) fn sparse_create_image(path: &Path, size_bytes: u64) -> Result<(), BuilderVmError> {
    sparse_ensure_image(path, size_bytes, ExistingImageSize::Preserve)
}

/// Create an empty sparse image or restore an undersized existing image to its
/// configured capacity. Growing a sparse file preserves every existing block.
///
/// Writable raw block backends may turn a trailing discard into a shorter host
/// file. The filesystem still records the device capacity it was formatted
/// against, so the persistent builder store must regain that capacity before
/// its next attachment. Oversized images are never truncated.
fn sparse_create_or_grow_image(path: &Path, size_bytes: u64) -> Result<(), BuilderVmError> {
    sparse_ensure_image(path, size_bytes, ExistingImageSize::GrowUndersized)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExistingImageSize {
    Preserve,
    GrowUndersized,
}

fn sparse_ensure_image(
    path: &Path,
    size_bytes: u64,
    existing_size: ExistingImageSize,
) -> Result<(), BuilderVmError> {
    let existed_before_open = path.exists();

    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(|e| BuilderVmError::ExtractionFailed(format!("open {}: {e}", path.display())))?;

    let image_bytes = size_bytes
        .checked_sub(LIBKRUN_BLOCK_DEVICE_TAIL_RESERVE_BYTES)
        .ok_or_else(|| {
            BuilderVmError::ExtractionFailed(format!(
                "image size {size_bytes} is too small for the libkrun block-device reserve"
            ))
        })?;
    let len = file
        .metadata()
        .map_err(|e| BuilderVmError::ExtractionFailed(format!("metadata {}: {e}", path.display())))?
        .len();
    let should_resize =
        len == 0 || (existing_size == ExistingImageSize::GrowUndersized && len < image_bytes);
    if should_resize {
        file.set_len(image_bytes).map_err(|e| {
            if !existed_before_open {
                let _ = std::fs::remove_file(path);
            }
            BuilderVmError::ExtractionFailed(format!(
                "set_len({image_bytes}) on {}: {e}",
                path.display()
            ))
        })?;
    }

    let len = file
        .metadata()
        .map_err(|e| BuilderVmError::ExtractionFailed(format!("metadata {}: {e}", path.display())))?
        .len();
    if len == 0 {
        if !existed_before_open {
            let _ = std::fs::remove_file(path);
        }
        return Err(BuilderVmError::ExtractionFailed(format!(
            "image {} stayed empty after sparse allocation",
            path.display()
        )));
    }

    Ok(())
}

/// How long a contended sidecar lock is waited on before giving up.
/// Generous because the holder is normally a cold `nix build`, and the
/// waiter's own build timeout ([`DEFAULT_BUILDER_VM_TIMEOUT`]) doesn't
/// start until the lock is held.
pub const DEFAULT_LOCK_WAIT: Duration = Duration::from_secs(60 * 60);

/// Override for [`DEFAULT_LOCK_WAIT`], in seconds. `0` restores
/// fail-fast: CI and the unit suite should surface contention as an
/// error rather than queue behind a builder that will never finish.
pub const LOCK_WAIT_ENV: &str = "MVM_BUILDER_LOCK_WAIT_SECS";

/// Gap between `try_lock` retries while waiting. Short enough that a
/// freed lock is picked up promptly, long enough that an hour-long
/// wait costs nothing.
const LOCK_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// Gap between "still waiting" progress lines.
const LOCK_PROGRESS_INTERVAL: Duration = Duration::from_secs(15);

/// How long a caller is willing to queue for a contended sidecar lock.
/// A named type rather than a bare `Duration` so the fail-fast case
/// reads as [`LockWait::none`] at the call site instead of an
/// unexplained zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockWait(Duration);

impl LockWait {
    /// Refuse to queue: the first `try_lock` failure is the error.
    /// What the unit suite and CI want — nothing there should ever
    /// wait on a builder that isn't coming back.
    pub const fn none() -> Self {
        Self(Duration::ZERO)
    }

    /// Wait up to `budget`.
    pub const fn of(budget: Duration) -> Self {
        Self(budget)
    }

    /// [`LOCK_WAIT_ENV`] if set and parseable, else
    /// [`DEFAULT_LOCK_WAIT`]. An unparseable value warns and takes the
    /// default rather than failing a build over a typo.
    ///
    /// Under `cfg(test)` the default flips to [`Self::none`]. Several
    /// unit tests drive production entry points (`run_build` and
    /// friends) that lock the *host-wide* store image rather than a
    /// tempdir, so a waiting default lets one crate's test suite queue
    /// behind another process's builder for the full hour. A test that
    /// wants to exercise waiting passes [`Self::of`] explicitly.
    ///
    /// That flip covers **this crate's own test build and nothing else**.
    /// `cfg!` is evaluated where it is compiled, so when this crate is built
    /// as an ordinary dependency of another crate's test binary it is not
    /// under `cfg(test)`, and that binary's tests inherit
    /// [`DEFAULT_LOCK_WAIT`] — an hour, spent queueing rather than failing.
    /// A test outside this crate therefore has to state its own budget; it
    /// cannot borrow this one. `mvm-libkrun-supervisor` learned that the
    /// expensive way and now takes its wait as an argument.
    pub fn from_env() -> Self {
        if cfg!(test) {
            return Self::none();
        }
        let Some(raw) = std::env::var_os(LOCK_WAIT_ENV) else {
            return Self(DEFAULT_LOCK_WAIT);
        };
        let raw = raw.to_string_lossy();
        Self::parse(&raw).unwrap_or_else(|| {
            tracing::warn!(
                value = %raw,
                "ignoring unparseable {LOCK_WAIT_ENV}; using the default wait"
            );
            Self(DEFAULT_LOCK_WAIT)
        })
    }

    /// Parse one [`LOCK_WAIT_ENV`] value: whitespace-trimmed seconds.
    /// `None` for anything else, so [`Self::from_env`] owns the
    /// fallback and this stays testable without env mutation.
    fn parse(raw: &str) -> Option<Self> {
        raw.trim()
            .parse::<u64>()
            .ok()
            .map(Duration::from_secs)
            .map(Self)
    }

    fn budget(&self) -> Duration {
        self.0
    }

    fn is_none(&self) -> bool {
        self.0.is_zero()
    }
}

/// Owner record the lock holder writes into the sidecar file so a
/// waiter can name the real process instead of guessing a verb. Read
/// on a best-effort basis: a partial read, a stale record, or a dead
/// pid all degrade to an anonymous description.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct LockOwner {
    pid: u32,
    /// The holder's argv, joined — e.g. `mvmctl build image --flake .`.
    command: String,
    acquired_unix_secs: u64,
}

impl LockOwner {
    /// The current process, as it should be recorded on acquisition.
    fn current(now_unix_secs: u64) -> Self {
        Self {
            pid: std::process::id(),
            command: current_command_line(),
            acquired_unix_secs: now_unix_secs,
        }
    }

    /// Human description for a contention message: the command, its
    /// pid, and how long it has held the lock.
    fn describe(&self, now_unix_secs: u64) -> String {
        let held = Duration::from_secs(now_unix_secs.saturating_sub(self.acquired_unix_secs));
        format!(
            "`{}` (pid {}, running {})",
            self.command,
            self.pid,
            format_duration(held)
        )
    }
}

/// `argv` joined with spaces, with the program reduced to its file
/// name. Truncated so a pathological command line can't bloat the lock
/// file or a terminal line.
fn current_command_line() -> String {
    const MAX_LEN: usize = 200;

    let mut args = std::env::args();
    let program = args
        .next()
        .map(|p| {
            Path::new(&p)
                .file_name()
                .map(|f| f.to_string_lossy().into_owned())
                .unwrap_or(p)
        })
        .unwrap_or_else(|| "mvmctl".to_string());

    let mut line = program;
    for arg in args {
        line.push(' ');
        line.push_str(&arg);
        if line.len() > MAX_LEN {
            line.truncate(MAX_LEN);
            line.push('…');
            break;
        }
    }
    line
}

/// `1h02m`, `4m12s`, `9s` — compact enough for a progress line.
fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    match (secs / 3600, (secs % 3600) / 60, secs % 60) {
        (0, 0, s) => format!("{s}s"),
        (0, m, s) => format!("{m}m{s:02}s"),
        (h, m, _) => format!("{h}h{m:02}m"),
    }
}

/// `kill(pid, 0)` — does the process exist? Used to discard a stale
/// owner record (holder died between writing it and releasing the
/// lock, or the record predates the current holder).
///
/// Anything that isn't a single positive pid is reported dead without
/// a syscall. `kill` reads 0 as "my process group" and negative values
/// as "a whole group", so a `u32` that doesn't fit `pid_t` — from a
/// corrupt record, say — must never reach it.
pub(crate) fn pid_alive(pid: u32) -> bool {
    let Ok(pid) = i32::try_from(pid) else {
        return false;
    };
    if pid <= 0 {
        return false;
    }
    #[cfg(unix)]
    {
        // SAFETY: signal 0 performs the permission/existence check
        // without delivering anything.
        unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// Describe whoever currently holds `lock_path`, falling back to
/// `"another mvm builder process"` when the record is missing,
/// unreadable, or names a dead pid.
fn describe_lock_holder(lock_path: &Path, now_unix_secs: u64) -> String {
    std::fs::read_to_string(lock_path)
        .ok()
        .and_then(|raw| serde_json::from_str::<LockOwner>(&raw).ok())
        .filter(|owner| pid_alive(owner.pid))
        .map(|owner| owner.describe(now_unix_secs))
        .unwrap_or_else(|| "another mvm builder process".to_string())
}

/// Stamp the current process into the freshly acquired lock file.
/// Best-effort: the lock is already held, so a write failure costs a
/// waiter its diagnostic, not correctness.
fn record_lock_owner(file: &std::fs::File, lock_path: &Path) {
    use std::io::{Seek, SeekFrom, Write};

    let owner = LockOwner::current(current_unix_secs());
    let Ok(json) = serde_json::to_vec(&owner) else {
        return;
    };

    let mut file = file;
    let stamped = file
        .set_len(0)
        .and_then(|()| file.seek(SeekFrom::Start(0)))
        .and_then(|_| file.write_all(&json))
        .and_then(|()| file.flush());
    if let Err(e) = stamped {
        tracing::debug!(lock = %lock_path.display(), error = %e, "stamping lock owner failed");
    }
}

/// Seconds since the Unix epoch. Local to this module so the lock
/// helpers don't reach into `persistent_builder`.
fn current_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

/// Open (creating if needed) the sidecar lock file at `lock_path` and
/// take an exclusive `flock`. The lock — never the image — is what
/// serialises concurrent writers, so the image carries no host-side
/// lock and the hypervisor can open it exclusively (required for
/// HVF; harmless for libkrun). Returns the locked handle; dropping it
/// releases the lock.
///
/// A contended lock **waits** rather than failing: a second
/// `mvmctl build` queues behind the first (naming it on stderr) for up
/// to [`LockWait::from_env`]. Failing fast here was a poor trade — the
/// image is a genuinely exclusive resource, so the only thing a hard
/// error bought the operator was the job of retrying by hand.
///
/// `wait` is explicit rather than read from the environment here so
/// the unit suite can exercise both the fail-fast ([`LockWait::none`])
/// and the wait-then-succeed paths without process-wide env mutation.
/// Production callers pass [`LockWait::from_env`].
pub(crate) fn acquire_sidecar_lock_within(
    lock_path: &Path,
    wait: LockWait,
) -> Result<std::fs::File, BuilderVmError> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)
        .map_err(|e| {
            BuilderVmError::ExtractionFailed(format!("open lock {}: {e}", lock_path.display()))
        })?;

    let started = std::time::Instant::now();
    let mut announced = false;
    let mut last_progress = started;

    loop {
        match file.try_lock() {
            Ok(()) => {
                if announced {
                    eprintln!(
                        "[mvm] builder image lock acquired after {}",
                        format_duration(started.elapsed())
                    );
                }
                record_lock_owner(&file, lock_path);
                return Ok(file);
            }
            // Anything that isn't contention (a permission problem, a
            // filesystem without locking) is the caller's to see now.
            Err(std::fs::TryLockError::Error(e)) => {
                return Err(BuilderVmError::ExtractionFailed(format!(
                    "locking {}: {e}",
                    lock_path.display()
                )));
            }
            Err(std::fs::TryLockError::WouldBlock) => (),
        };

        let waited = started.elapsed();
        if waited >= wait.budget() {
            return Err(contended_lock_error(lock_path, waited, wait));
        }

        if !announced {
            eprintln!(
                "[mvm] builder image {} is held by {}; waiting (Ctrl-C to abort, \
                 or run builds concurrently with `mvmctl persistent-builder start`)",
                lock_path.display(),
                describe_lock_holder(lock_path, current_unix_secs())
            );
            announced = true;
            last_progress = std::time::Instant::now();
        } else if last_progress.elapsed() >= LOCK_PROGRESS_INTERVAL {
            eprintln!(
                "[mvm] still waiting for the builder image lock ({} elapsed)",
                format_duration(waited)
            );
            last_progress = std::time::Instant::now();
        }

        std::thread::sleep(LOCK_POLL_INTERVAL.min(wait.budget().saturating_sub(waited)));
    }
}

/// The error raised once the wait budget is spent (or immediately,
/// when the budget is zero). Names the holder and both escape
/// hatches: a longer wait, or the persistent builder that lets
/// concurrent builds share one VM instead of queueing.
fn contended_lock_error(lock_path: &Path, waited: Duration, wait: LockWait) -> BuilderVmError {
    let holder = describe_lock_holder(lock_path, current_unix_secs());
    let waited_for = if wait.is_none() {
        String::new()
    } else {
        format!(" after waiting {}", format_duration(waited))
    };
    BuilderVmError::ExtractionFailed(format!(
        "image {} is still held by {}{waited_for}. Wait for it to finish, raise \
         {LOCK_WAIT_ENV} (seconds), or start a persistent builder \
         (`mvmctl persistent-builder start`) so concurrent builds share one \
         builder VM instead of queueing for its store image",
        lock_path.display(),
        holder
    ))
}

/// Is another process holding the store image right now?
///
/// A probe, not a claim: it tries the lock without waiting and releases it
/// immediately. `true` means a builder VM currently owns the image, which is
/// the signal that this build should look for a session to share rather than
/// queue behind it.
///
/// Any non-contention error reads as not-contended, so a broken or
/// unlockable sidecar sends the caller down the ordinary path, where the real
/// acquire reports the real error instead of this probe guessing at it.
pub fn nix_store_image_is_contended(builder_cache_dir: &Path, arch: &str) -> bool {
    let image = builder_cache_dir.join(format!("nix-store-{arch}.img"));
    let lock_path = sidecar_lock_path(&image);
    if !lock_path.exists() {
        // No sidecar means no builder has ever locked this image, and probing
        // would create the file as a side effect. Report free.
        return false;
    }
    match acquire_sidecar_lock_within(&lock_path, LockWait::none()) {
        // Took it, so nobody else held it. Released as this returns.
        Ok(_) => false,
        Err(BuilderVmError::ExtractionFailed(msg)) => msg.contains("is still held by"),
        Err(_) => false,
    }
}

/// Find or create the persistent `<builder_cache_dir>/nix-store-<arch>.img`
/// sparse image and hold an exclusive host-side lock on it.
///
/// `builder_cache_dir` is the host-side root the builder VM uses for
/// shared state — callers compute this themselves (typically
/// `~/.mvm/cache/builder-vm/`) so the helper stays free of
/// `mvm_core::config` lookups. The directory is created if missing.
///
/// `arch` only appears in the filename (`nix-store-<arch>.img`) so
/// multi-arch hosts can keep one image per arch in the same cache.
///
/// `size_mib` is the sparse cap — the file consumes only the bytes
/// the in-VM ext4 actually writes. Caller-controlled because dev
/// hosts may want a smaller cap than CI runners.
///
/// Returns a [`NixStoreImageLock`] guard. Dropping it releases the
/// lock — see the type docs.
pub fn acquire_nix_store_image_lock(
    builder_cache_dir: &Path,
    arch: &str,
    size_mib: u64,
) -> Result<NixStoreImageLock, BuilderVmError> {
    acquire_nix_store_image_lock_named(
        builder_cache_dir,
        &format!("nix-store-{arch}.img"),
        size_mib,
    )
}

/// Like [`acquire_nix_store_image_lock`] but the image filename is
/// supplied verbatim instead of derived as `nix-store-<arch>.img`.
///
/// Stage 0 (the builder-VM *image* build) uses this to key a dedicated
/// `nix-store-stage0-<arch>.img` separate from the steady-state
/// builder's `nix-store-<arch>.img`. Two reasons for the split: the
/// flock would otherwise serialize the builder VM bootstrap against any
/// concurrent `mvmctl build` in another session, and the bootstrap's
/// kernel/Rust-toolchain closure has no reason to share a store with
/// user-workload builds. Both images live in the same cache dir and
/// match `cache info`'s `nix-store-*.img` sparse-footprint report.
pub fn acquire_nix_store_image_lock_named(
    builder_cache_dir: &Path,
    file_name: &str,
    size_mib: u64,
) -> Result<NixStoreImageLock, BuilderVmError> {
    acquire_nix_store_image_lock_named_within(
        builder_cache_dir,
        file_name,
        size_mib,
        LockWait::from_env(),
    )
}

/// [`acquire_nix_store_image_lock_named`] with an explicit wait
/// budget. Test-facing seam: the unit suite asserts the contention
/// error, which only exists under [`LockWait::none`].
pub(crate) fn acquire_nix_store_image_lock_named_within(
    builder_cache_dir: &Path,
    file_name: &str,
    size_mib: u64,
    wait: LockWait,
) -> Result<NixStoreImageLock, BuilderVmError> {
    std::fs::create_dir_all(builder_cache_dir).map_err(|e| {
        BuilderVmError::ExtractionFailed(format!(
            "creating builder cache dir {}: {e}",
            builder_cache_dir.display()
        ))
    })?;
    let path = builder_cache_dir.join(file_name);

    let size_bytes = size_mib.checked_mul(1024 * 1024).ok_or_else(|| {
        BuilderVmError::ExtractionFailed(format!(
            "nix-store size_mib overflowed multiplying to bytes: {size_mib}"
        ))
    })?;

    // Take the sidecar lock first so a losing concurrent writer fails
    // before touching the image. The lock is on `<image>.lock`, never
    // the image fd — HVF needs to open the image exclusively at
    // start (see [`NixStoreImageLock`] docs).
    let lock = acquire_sidecar_lock_within(&sidecar_lock_path(&path), wait)?;
    sparse_create_or_grow_image(&path, size_bytes)?;

    Ok(NixStoreImageLock { path, _file: lock })
}

/// Materialize the Nix store image **without** taking its lock, and return the
/// image path alongside the sidecar the owner must lock.
///
/// For the persistent builder, where the process that starts the VM is not the
/// process that should hold the lock: the starter creates the image and names
/// the sidecar, and the supervisor — which lives exactly as long as the VM —
/// acquires it via [`hold_image_lock`]. A starter that locked first would have
/// to hand the lock over, and the gap between its release and the supervisor's
/// acquire is precisely the window another builder could win.
///
/// One-shot builders must keep using [`acquire_nix_store_image_lock`]: there
/// the caller outlives the VM, so caller-held is already correct.
pub fn ensure_nix_store_image_unlocked(
    builder_cache_dir: &Path,
    arch: &str,
    size_mib: u64,
) -> Result<UnlockedStoreImage, BuilderVmError> {
    std::fs::create_dir_all(builder_cache_dir).map_err(|e| {
        BuilderVmError::ExtractionFailed(format!(
            "creating builder cache dir {}: {e}",
            builder_cache_dir.display()
        ))
    })?;
    let path = builder_cache_dir.join(format!("nix-store-{arch}.img"));
    let size_bytes = size_mib.checked_mul(1024 * 1024).ok_or_else(|| {
        BuilderVmError::ExtractionFailed(format!(
            "nix-store size_mib overflowed multiplying to bytes: {size_mib}"
        ))
    })?;
    sparse_create_or_grow_image(&path, size_bytes)?;
    let lock_path = sidecar_lock_path(&path);
    Ok(UnlockedStoreImage { path, lock_path })
}

/// A store image that exists on disk and is **not** locked by this process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnlockedStoreImage {
    path: PathBuf,
    lock_path: PathBuf,
}

impl UnlockedStoreImage {
    /// The image to attach as a virtio-blk device.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The sidecar whose exclusive lock confers the right to write the image.
    /// Handed to the supervisor, which holds it for the VM's lifetime.
    pub fn lock_path(&self) -> &Path {
        &self.lock_path
    }
}

/// Take the exclusive sidecar lock at `lock_path` and return the open file
/// whose lifetime *is* the lock's.
///
/// Called by a supervisor at startup for the image its VM will write. The
/// returned handle must stay alive for the process's lifetime — binding it to
/// `_` rather than a named `_guard` drops it immediately and silently unlocks
/// the image.
pub fn hold_image_lock(lock_path: &Path, wait: LockWait) -> Result<std::fs::File, BuilderVmError> {
    acquire_sidecar_lock_within(lock_path, wait)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::volume_image::{VolumeImageLock, ensure_persistent_volume_image};

    // -----------------------------------------------------------------
    // Tests migrated from libkrun_builder.rs alongside NixStoreImageLock
    // and acquire_nix_store_image_lock. The new signature takes the
    // cache dir as a &Path arg,
    // so the cache-env override hack from the old tests is gone — each
    // test passes a fresh TempDir path directly and runs without
    // process-wide env mutation.
    // -----------------------------------------------------------------

    #[test]
    fn sparse_store_regrows_after_a_trailing_discard_without_losing_data() {
        use std::io::{Read as _, Seek as _, Write as _};

        let scratch = tempfile::TempDir::new().unwrap();
        let image = scratch.path().join("nix-store.img");
        let nominal_size = 4 * 1024 * 1024;
        let target_size = nominal_size - LIBKRUN_BLOCK_DEVICE_TAIL_RESERVE_BYTES;
        let shortened_size = target_size - LIBKRUN_BLOCK_DEVICE_TAIL_RESERVE_BYTES;
        let payload_offset = 4096;
        let payload = b"persistent-cache-data";

        let mut file = std::fs::File::create(&image).unwrap();
        file.set_len(shortened_size).unwrap();
        file.seek(std::io::SeekFrom::Start(payload_offset)).unwrap();
        file.write_all(payload).unwrap();
        drop(file);

        sparse_create_or_grow_image(&image, nominal_size).unwrap();

        assert_eq!(std::fs::metadata(&image).unwrap().len(), target_size);
        let mut file = std::fs::File::open(&image).unwrap();
        file.seek(std::io::SeekFrom::Start(payload_offset)).unwrap();
        let mut actual = vec![0; payload.len()];
        file.read_exact(&mut actual).unwrap();
        assert_eq!(actual, payload);
    }

    #[test]
    fn sparse_store_never_truncates_an_oversized_existing_image() {
        let scratch = tempfile::TempDir::new().unwrap();
        let image = scratch.path().join("nix-store.img");
        let existing_size = 8 * 1024 * 1024;

        std::fs::File::create(&image)
            .unwrap()
            .set_len(existing_size)
            .unwrap();
        sparse_create_or_grow_image(&image, 4 * 1024 * 1024).unwrap();

        assert_eq!(std::fs::metadata(&image).unwrap().len(), existing_size);
    }

    #[test]
    fn acquire_nix_store_image_lock_creates_sparse_file_once() {
        // Sparse file allocates the logical size but consumes ~no disk
        // blocks. `set_len` is what asks the FS to record the size. A
        // later acquisition finds the existing file and returns its
        // path without retouching.
        let scratch = tempfile::TempDir::new().unwrap();
        let cache_dir = scratch.path().join("builder-vm");
        let guard = acquire_nix_store_image_lock(&cache_dir, "x86_64", 256).unwrap();
        let path = guard.path().to_path_buf();
        assert!(path.is_file());
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            256 * 1024 * 1024 - LIBKRUN_BLOCK_DEVICE_TAIL_RESERVE_BYTES
        );
        drop(guard);
        // Second acquisition is idempotent.
        let guard2 = acquire_nix_store_image_lock(&cache_dir, "x86_64", 256).unwrap();
        let path2 = guard2.path().to_path_buf();
        assert_eq!(path, path2);
        drop(guard2);
    }

    #[test]
    fn acquire_nix_store_image_lock_refuses_concurrent_writer() {
        let scratch = tempfile::TempDir::new().unwrap();
        let cache_dir = scratch.path().join("builder-vm");

        let first = acquire_nix_store_image_lock(&cache_dir, "x86_64", 256).unwrap();
        let err = acquire_nix_store_image_lock_named_within(
            &cache_dir,
            "nix-store-x86_64.img",
            256,
            LockWait::none(),
        )
        .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("is still held by"), "unexpected error: {msg}");
        drop(first);

        acquire_nix_store_image_lock(&cache_dir, "x86_64", 256)
            .expect("lock should be available after first guard drops");
    }

    #[test]
    fn acquire_nix_store_image_lock_filename_carries_arch() {
        // Multi-arch hosts can keep one image per arch in the same
        // cache. Pin the filename convention so a future refactor that
        // collapses the arch out of the path doesn't silently break it.
        let scratch = tempfile::TempDir::new().unwrap();
        let cache_dir = scratch.path().join("builder-vm");
        let guard = acquire_nix_store_image_lock(&cache_dir, "aarch64", 64).unwrap();
        assert_eq!(
            guard.path().file_name().and_then(|s| s.to_str()),
            Some("nix-store-aarch64.img")
        );
    }

    /// `try_lock` can report `WouldBlock` on a fresh, uncontended path under
    /// heavy parallel test load. A bounded wait absorbs that for a test
    /// that expects the lock to be FREE, without hanging the suite on a
    /// lock that is genuinely held.
    fn acquire_named_or_retry(
        cache_dir: &Path,
        file_name: &str,
        size_mib: u64,
    ) -> NixStoreImageLock {
        acquire_nix_store_image_lock_named_within(
            cache_dir,
            file_name,
            size_mib,
            LockWait::of(Duration::from_secs(5)),
        )
        .unwrap_or_else(|e| panic!("acquire {file_name}: {e}"))
    }

    #[test]
    fn contended_lock_waits_for_the_holder_instead_of_failing() {
        // The DX fix: a second builder queues behind the first rather
        // than dying. The holder releases mid-wait and the waiter picks
        // the lock up.
        let scratch = tempfile::TempDir::new().unwrap();
        let lock_path = scratch.path().join("nix-store.img.lock");

        let held = acquire_sidecar_lock_within(&lock_path, LockWait::none()).expect("first lock");
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            drop(held);
        });

        let started = std::time::Instant::now();
        let second = acquire_sidecar_lock_within(&lock_path, LockWait::of(Duration::from_secs(30)))
            .expect("second lock should be granted once the holder releases");
        assert!(
            started.elapsed() >= Duration::from_millis(250),
            "waiter returned before the holder released"
        );
        releaser.join().unwrap();
        drop(second);
    }

    #[test]
    fn contention_error_names_the_holding_process() {
        // A refusal has to be actionable: it names the live holder (this
        // process) and both escape hatches.
        let scratch = tempfile::TempDir::new().unwrap();
        let lock_path = scratch.path().join("nix-store.img.lock");

        let held = acquire_sidecar_lock_within(&lock_path, LockWait::none()).expect("first lock");
        let err = acquire_sidecar_lock_within(&lock_path, LockWait::none()).unwrap_err();
        let msg = format!("{err}");

        assert!(
            msg.contains(&format!("pid {}", std::process::id())),
            "holder pid missing: {msg}"
        );
        assert!(msg.contains(LOCK_WAIT_ENV), "wait override missing: {msg}");
        assert!(
            msg.contains("mvmctl persistent-builder start"),
            "concurrent-build hint missing: {msg}"
        );
        drop(held);
    }

    #[test]
    fn lock_owner_record_survives_a_round_trip_through_the_lock_file() {
        let scratch = tempfile::TempDir::new().unwrap();
        let lock_path = scratch.path().join("nix-store.img.lock");

        let held = acquire_sidecar_lock_within(&lock_path, LockWait::none()).expect("lock");
        let raw = std::fs::read_to_string(&lock_path).expect("read lock file");
        let owner: LockOwner = serde_json::from_str(&raw).expect("parse owner record");

        assert_eq!(owner.pid, std::process::id());
        assert!(!owner.command.is_empty());
        drop(held);
    }

    #[test]
    fn a_dead_or_missing_owner_record_degrades_to_an_anonymous_holder() {
        let scratch = tempfile::TempDir::new().unwrap();
        let lock_path = scratch.path().join("nix-store.img.lock");

        // No record at all.
        std::fs::write(&lock_path, b"").unwrap();
        assert_eq!(
            describe_lock_holder(&lock_path, 0),
            "another mvm builder process"
        );

        // A record naming a pid that cannot be alive.
        let stale = LockOwner {
            pid: u32::MAX,
            command: "mvmctl build image".to_string(),
            acquired_unix_secs: 0,
        };
        std::fs::write(&lock_path, serde_json::to_vec(&stale).unwrap()).unwrap();
        assert_eq!(
            describe_lock_holder(&lock_path, 0),
            "another mvm builder process"
        );
    }

    #[test]
    fn ensure_nix_store_image_unlocked_creates_the_image_and_leaves_it_free() {
        // The whole point of this entry point: the starter materializes the
        // image but takes no lock, so the supervisor can take it without a
        // handoff — and without a window where neither process holds it.
        let scratch = tempfile::TempDir::new().unwrap();
        let cache = scratch.path().join("builder-vm");

        let image = ensure_nix_store_image_unlocked(&cache, "aarch64", 64).expect("ensure image");
        assert!(image.path().is_file(), "image must exist on disk");
        assert_eq!(
            image.lock_path(),
            sidecar_lock_path(image.path()),
            "the named sidecar must be the one the lock helpers use"
        );

        // Free: a fresh acquire succeeds immediately.
        let held = acquire_sidecar_lock_within(image.lock_path(), LockWait::none())
            .expect("the sidecar must be unlocked after an unlocked ensure");
        drop(held);
    }

    #[test]
    fn hold_image_lock_excludes_a_second_holder_until_it_drops() {
        let scratch = tempfile::TempDir::new().unwrap();
        let cache = scratch.path().join("builder-vm");
        let image = ensure_nix_store_image_unlocked(&cache, "aarch64", 64).expect("ensure image");

        let guard = hold_image_lock(image.lock_path(), LockWait::none()).expect("first holder");
        let err = hold_image_lock(image.lock_path(), LockWait::none())
            .expect_err("a second holder must be refused while the first holds it");
        assert!(
            format!("{err}").contains("is still held by"),
            "unexpected error: {err}"
        );

        drop(guard);
        hold_image_lock(image.lock_path(), LockWait::none())
            .expect("the lock must be free once its holder drops");
    }

    #[test]
    fn a_free_store_image_does_not_read_as_contended() {
        let scratch = tempfile::TempDir::new().unwrap();
        let cache = scratch.path().join("builder-vm");

        // Never locked: no sidecar exists yet, and probing must not create one
        // as a side effect.
        assert!(!nix_store_image_is_contended(&cache, "aarch64"));
        assert!(
            !cache.join("nix-store-aarch64.img.lock").exists(),
            "the probe must not leave a sidecar behind"
        );

        // Locked once, then released.
        let guard = acquire_nix_store_image_lock(&cache, "aarch64", 64).unwrap();
        drop(guard);
        assert!(
            !nix_store_image_is_contended(&cache, "aarch64"),
            "a released lock is not contention"
        );
    }

    #[test]
    fn a_held_store_image_reads_as_contended_and_the_probe_does_not_steal_it() {
        let scratch = tempfile::TempDir::new().unwrap();
        let cache = scratch.path().join("builder-vm");
        let guard = acquire_nix_store_image_lock(&cache, "aarch64", 64).unwrap();

        assert!(nix_store_image_is_contended(&cache, "aarch64"));
        // Probing is not acquiring: the holder still holds it afterwards, so a
        // second probe sees the same answer.
        assert!(nix_store_image_is_contended(&cache, "aarch64"));

        drop(guard);
        assert!(!nix_store_image_is_contended(&cache, "aarch64"));
    }

    #[test]
    fn lock_wait_parses_seconds_and_rejects_junk() {
        assert_eq!(LockWait::parse("0"), Some(LockWait::none()));
        assert_eq!(
            LockWait::parse("  90 "),
            Some(LockWait::of(Duration::from_secs(90)))
        );
        assert_eq!(LockWait::parse("forever"), None);
        assert_eq!(LockWait::parse("-1"), None);
        assert_eq!(LockWait::parse(""), None);
    }

    #[test]
    fn this_crates_own_test_build_never_queues_for_a_lock() {
        // Unit tests reach production entry points that lock the
        // host-wide store image. Waiting there makes one suite queue
        // behind another process's builder — a 35-minute "passing"
        // test. The default stays fail-fast under cfg(test) no matter
        // what the environment says.
        //
        // Read what this does and does not prove. `cfg!(test)` is true
        // here because *this crate* is being compiled as a test, so this
        // asserts a property of this crate's test build alone. It says
        // nothing about a test in a crate that merely depends on this
        // one: there this crate is an ordinary library, the flip does not
        // happen, and the caller gets the production hour. Reading this
        // test as a workspace-wide guarantee is what let
        // `mvm-libkrun-supervisor` ship a test that queued for an hour.
        assert_eq!(LockWait::from_env(), LockWait::none());
    }

    /// The other half of the same fact, asserted directly rather than left
    /// to be inferred: the production default really is the long wait, so a
    /// caller that does not state a budget and is not inside this crate's
    /// test build gets an hour.
    #[test]
    fn the_production_default_is_the_long_wait() {
        assert_eq!(
            LockWait::of(DEFAULT_LOCK_WAIT),
            LockWait::of(Duration::from_secs(60 * 60))
        );
        assert_ne!(LockWait::of(DEFAULT_LOCK_WAIT), LockWait::none());
    }

    #[test]
    fn durations_format_compactly() {
        assert_eq!(format_duration(Duration::from_secs(9)), "9s");
        assert_eq!(format_duration(Duration::from_secs(252)), "4m12s");
        assert_eq!(format_duration(Duration::from_secs(3720)), "1h02m");
    }

    #[test]
    fn acquire_nix_store_image_lock_named_uses_supplied_filename() {
        // The named variant backs Stage 0's dedicated store image. It
        // must use the filename verbatim, not re-derive `nix-store-<arch>`.
        let scratch = tempfile::TempDir::new().unwrap();
        let cache_dir = scratch.path().join("builder-vm");
        let guard = acquire_named_or_retry(&cache_dir, "nix-store-stage0-aarch64.img", 64);
        assert_eq!(
            guard.path().file_name().and_then(|s| s.to_str()),
            Some("nix-store-stage0-aarch64.img")
        );
        // Matches `cache info`'s `nix-store-*.img` sparse report glob.
        let n = guard.path().file_name().unwrap().to_string_lossy();
        assert!(n.starts_with("nix-store-") && n.ends_with(".img"));
    }

    #[test]
    fn stage0_and_builder_store_locks_do_not_collide() {
        // The whole point of the split: a Stage 0 bootstrap and a
        // steady-state builder build can hold their store locks at the
        // same time because they key different image files. If they
        // shared a filename, the second acquire would fail the flock.
        let scratch = tempfile::TempDir::new().unwrap();
        let cache_dir = scratch.path().join("builder-vm");
        let builder = acquire_named_or_retry(&cache_dir, "nix-store-aarch64.img", 64);
        let stage0 = acquire_named_or_retry(&cache_dir, "nix-store-stage0-aarch64.img", 64);
        assert_ne!(builder.path(), stage0.path());
    }

    #[test]
    fn acquire_nix_store_image_lock_creates_missing_cache_dir() {
        // `create_dir_all` is part of the contract — callers pass the
        // computed `~/.mvm/cache/builder-vm/` path and expect it to be
        // created on demand.
        let scratch = tempfile::TempDir::new().unwrap();
        let cache_dir = scratch.path().join("not").join("yet").join("created");
        let guard = acquire_nix_store_image_lock(&cache_dir, "x86_64", 16).unwrap();
        assert!(guard.path().is_file());
        assert!(cache_dir.is_dir());
    }

    /// The load-bearing property of the sidecar-lock fix: while the
    /// guard is held, the host holds NO lock on the image file itself,
    /// so a hypervisor (HVF) can open it exclusively at start. We
    /// prove it by opening the image from a second fd in-process and
    /// taking our own exclusive `flock` — which would fail if the guard
    /// still locked the image. The lock lives on `<image>.lock` instead.
    #[test]
    fn nix_store_lock_does_not_lock_the_image_itself() {
        let scratch = tempfile::TempDir::new().unwrap();
        let cache_dir = scratch.path().join("builder-vm");
        let guard = acquire_named_or_retry(&cache_dir, "nix-store-aarch64.img", 64);

        // Sidecar lock file exists next to the image.
        let sidecar = sidecar_lock_path(guard.path());
        assert!(
            sidecar.is_file(),
            "sidecar lock {} should exist",
            sidecar.display()
        );
        assert!(sidecar.to_string_lossy().ends_with(".img.lock"));

        // A second handle on the IMAGE can take an exclusive flock —
        // proving the guard didn't lock the image. Retry to absorb a
        // spurious `WouldBlock` on a fresh path under parallel test load.
        let img = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(guard.path())
            .expect("open image");
        let mut locked = false;
        for _ in 0..40 {
            if img.try_lock().is_ok() {
                locked = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        assert!(locked, "image file must NOT be locked by the guard");
        drop(guard);
    }

    /// RW volume image the test expects to be FREE. The short wait
    /// absorbs a spurious `WouldBlock` without letting a genuinely
    /// stuck lock hang the suite.
    fn ensure_vol_rw_or_retry(path: &Path, size_bytes: u64) -> VolumeImageLock {
        crate::volume_image::ensure_persistent_volume_image_within(
            path,
            size_bytes,
            false,
            LockWait::of(Duration::from_secs(5)),
        )
        .expect("ensure volume")
    }

    #[test]
    fn ensure_persistent_volume_image_sparse_creates_and_is_idempotent() {
        let scratch = tempfile::TempDir::new().unwrap();
        let img = scratch.path().join("vols").join("data.img");
        let guard = ensure_vol_rw_or_retry(&img, 32 * 1024 * 1024);
        assert!(img.is_file(), "parent dir + sparse image created");
        assert_eq!(
            std::fs::metadata(&img).unwrap().len(),
            32 * 1024 * 1024 - LIBKRUN_BLOCK_DEVICE_TAIL_RESERVE_BYTES
        );
        let mut file = std::fs::File::open(&img).unwrap();
        use std::io::{Read as _, Seek as _};
        file.seek(std::io::SeekFrom::Start(1024 + 56)).unwrap();
        let mut magic = [0u8; 2];
        file.read_exact(&mut magic).unwrap();
        assert_eq!(u16::from_le_bytes(magic), 0xef53, "new volume is ext4");
        drop(guard);
        // Second call leaves the existing (non-empty) image untouched —
        // a warm volume's data must survive. Pass a different size to
        // prove we don't resize an existing image.
        let guard2 = ensure_vol_rw_or_retry(&img, 8 * 1024 * 1024);
        assert_eq!(
            std::fs::metadata(&img).unwrap().len(),
            32 * 1024 * 1024 - LIBKRUN_BLOCK_DEVICE_TAIL_RESERVE_BYTES,
            "existing volume must not be resized"
        );
        drop(guard2);
    }

    #[test]
    fn ensure_persistent_volume_image_rw_refuses_concurrent() {
        let scratch = tempfile::TempDir::new().unwrap();
        let img = scratch.path().join("data.img");
        let first = ensure_vol_rw_or_retry(&img, 16 * 1024 * 1024);
        let err = crate::volume_image::ensure_persistent_volume_image_within(
            &img,
            16 * 1024 * 1024,
            false,
            LockWait::none(),
        )
        .unwrap_err();
        assert!(
            format!("{err}").contains("is still held by"),
            "unexpected error: {err}"
        );
        drop(first);
        ensure_vol_rw_or_retry(&img, 16 * 1024 * 1024);
    }

    #[test]
    fn ensure_persistent_volume_image_refuses_existing_non_ext4_data() {
        let scratch = tempfile::TempDir::new().unwrap();
        let img = scratch.path().join("not-ext4.img");
        std::fs::write(&img, vec![0xa5; 4096]).unwrap();

        let err = ensure_persistent_volume_image(&img, 16 * 1024 * 1024, true).unwrap_err();
        assert!(err.to_string().contains("not a valid ext4 filesystem"));
    }

    #[test]
    fn ensure_persistent_volume_image_ro_allows_concurrent_and_takes_no_lock() {
        let scratch = tempfile::TempDir::new().unwrap();
        let img = scratch.path().join("ro.img");
        // Seed the image directly (no RW guard, so no sidecar is created)
        // — isolates the "RO takes no lock" assertion below.
        let mut f = std::fs::File::create(&img).unwrap();
        let image_bytes = 16 * 1024 * 1024 - LIBKRUN_BLOCK_DEVICE_TAIL_RESERVE_BYTES;
        f.set_len(image_bytes).unwrap();
        mvm_fs::ext4::mkfs::format_empty_ext4(&mut f, image_bytes).unwrap();
        drop(f);
        // Two concurrent RO guards coexist (read-only = no exclusive lock).
        let a = ensure_persistent_volume_image(&img, 16 * 1024 * 1024, true).unwrap();
        let b = ensure_persistent_volume_image(&img, 16 * 1024 * 1024, true).unwrap();
        assert_eq!(a.path(), b.path());
        // No sidecar lock file is created for a read-only volume.
        assert!(!sidecar_lock_path(&img).exists());
        drop((a, b));
    }
}
