//! Per-VM host bounds on a VMM process, via a transient systemd scope on the
//! user's own manager.
//!
//! Every VMM spawn on a host with the mechanism is born inside a scope carrying
//! a memory ceiling (guest RAM plus [`VMM_MEMORY_OVERHEAD_MIB`], with swap
//! excluded), a task ceiling ([`VMM_TASKS_MAX`]), and — only when a share was
//! granted — a CPU quota. Memory and tasks are not grants: nobody asks for
//! them, and every VMM gets them, because a leak in device emulation or a
//! runaway helper thread exhausts the host whatever the plan said about CPU.
//!
//! The obvious mechanism — `mkdir` a cgroup v2 leaf under the delegated
//! `user@<uid>.service` subtree and write the VMM's pid into `cgroup.procs` —
//! creates the leaf and accepts the limit writes, and then refuses the one
//! step that matters. Migrating a process needs write access to the *common
//! ancestor* of its current and destination cgroups, and a login session's
//! `session-N.scope` is not delegated, so a process launched from any ordinary
//! shell cannot move itself in. The limit is set, correctly, on a cgroup the
//! workload never enters.
//!
//! Asking the user's own `systemd --user` manager to create the scope sidesteps
//! that: the placement is performed from inside the delegated tree, by the
//! process that owns it. It also settles the born-bounded requirement for free.
//! `systemd-run --scope` registers the scope *before* it execs the payload, so
//! there is no interval in which the workload runs unbounded — which is exactly
//! the interval a workload built to burn CPU or memory would use.
//!
//! Shelling out to `systemd-run` rather than speaking `StartTransientUnit` over
//! D-Bus directly keeps the dependency budget where this project wants it; the
//! placement, and the delegation it depends on, are identical either way.
//!
//! # Scope creation is bounded
//!
//! A stopped or wedged user manager does not make `systemd-run` fail; it makes
//! it wait, and it was measured waiting 90 s before giving up. A launch that
//! inherits that wait looks hung. So every spawn through this module watches
//! the launcher until it has exec'd the payload — which it does only once the
//! scope exists — and kills it and fails the launch after
//! [`SCOPE_CREATION_TIMEOUT`]. The read-back queries are bounded the same way.
//!
//! # The rejected alternative: adopting an already-running process
//!
//! A scope can also be created *around* a process that is already running —
//! `StartTransientUnit` with a `PIDs` property. This was measured working, not
//! guessed at: a pid living in a login session's own scope was moved into the
//! delegated tree and the quota applied. It is tempting because it needs no
//! bound threaded onto the launch config — a caller can bound a VM it has
//! already started.
//!
//! It is deliberately not what this module does, and the reason is not that it
//! fails. It trades the born-bounded property away for one saved field.
//! Adoption leaves a window between exec and the adopting call in which the
//! process is unbounded, and the only argument that the window is harmless is
//! that the guest is still in kernel boot — which is a timing argument, and
//! timing arguments rot. Wrapping the spawn gives born-bounded for free, so
//! there is nothing to buy. Recorded here so the next reader does not
//! rediscover adoption and assume it was overlooked.
//!
//! Nothing here is `cfg`-gated to Linux. Every call first asks whether the
//! mechanism is present, and a host without `systemd-run` or without a user
//! session bus answers [`EnforcedTier::Declared`] — the same honest answer a
//! compile-time gate would produce, arrived at by one code path instead of two
//! that could disagree.

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};
use mvm_contract::grants::CpuGrant;
use mvm_contract::protocol::resource_controls::{EnforcedCeiling, EnforcedGrants, EnforcedTier};

/// systemd expresses a CPU quota as a percentage of one core, so one percent is
/// ten millicores.
const MILLICORES_PER_PERCENT: u32 = 10;

/// Host memory a VMM process may use beyond its guest's RAM.
///
/// Measured rather than guessed, on an x86_64 Linux 6.8 KVM host with a
/// 512 MiB, 2-vCPU guest, as the scope's `memory.current` minus the resident
/// size of the guest RAM mapping: Firecracker charged about 2 MiB beyond the
/// guest, and QEMU with its guest RAM fully preallocated 34 MiB (38 MiB at
/// peak). The libkrun supervisor has no measurement. The margin is several
/// times the largest measured figure on purpose: the ceiling exists to stop a
/// VMM that is leaking without bound, and a VMM killed for ordinary device
/// emulation churn would be a liveness bug wearing a security label. Page cache
/// from disk I/O is charged here too, but the kernel reclaims it before it
/// kills anything.
pub const VMM_MEMORY_OVERHEAD_MIB: u64 = 256;

/// Tasks (processes plus threads) a VMM's scope may hold.
///
/// A VMM's thread count is its vCPUs plus a handful of device and I/O workers:
/// the Firecracker and QEMU guests measured above sat at 5 tasks with two
/// vCPUs, and the largest vCPU ceiling any backend declares is 255. A thousand
/// leaves that worst case several hundred threads of headroom while still
/// stopping a fork loop long before it reaches the host's own limit.
pub const VMM_TASKS_MAX: u32 = 1024;

/// How long the service manager has to create a scope before the launch fails.
///
/// Creation normally takes milliseconds. The bound is not a latency target; it
/// is the point at which an unresponsive manager is reported as one instead of
/// being indistinguishable from a hung launch.
pub const SCOPE_CREATION_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a read-back query may wait on the service manager. Past this the
/// answer is "declared" — nothing could be confirmed — rather than a stall on
/// a path that runs after the VM is already up.
const SCOPE_QUERY_TIMEOUT: Duration = Duration::from_secs(5);

/// A systemd unit name is capped at 255 bytes including its type suffix. The
/// margin is not tuning: it leaves room for the suffix and keeps a rejected id
/// a validation error here rather than an opaque refusal from systemd.
const MAX_SCOPE_ID_LEN: usize = 200;

/// The unified cgroup hierarchy's mount point. A kernel/systemd ABI location on
/// every unified host, not a configurable path.
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// Where the kernel publishes each process's command name.
const PROC_ROOT: &str = "/proc";

const SYSTEMD_RUN: &str = "systemd-run";
const SYSTEMCTL: &str = "systemctl";

/// The `Result=` a scope reports when the kernel's OOM killer ended it.
const OOM_KILL_RESULT: &str = "oom-kill";

const BYTES_PER_MIB: u64 = 1024 * 1024;

/// Why this host cannot bound a VMM through a transient scope.
///
/// A reason rather than a bool: the two cases have different operator fixes,
/// and a caller that logs "unavailable" without saying which one sends someone
/// looking for a missing package that is already installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MechanismGap {
    /// `systemd-run` is not on `PATH`.
    SystemdRunMissing,
    /// No user session bus. Delegation hangs off the session, so a
    /// non-interactive `ssh host mvmctl …`, a CI runner, or a `nohup`'d process
    /// often has none.
    NoUserSessionBus,
}

impl MechanismGap {
    /// Operator-facing explanation, including the fix.
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::SystemdRunMissing => {
                "systemd-run is not on PATH, so no CPU quota, memory ceiling or task \
                 ceiling can be attached to this VM"
            }
            Self::NoUserSessionBus => {
                "no user session bus (XDG_RUNTIME_DIR / DBUS_SESSION_BUS_ADDRESS); \
                 cgroup delegation hangs off a systemd user session, so no CPU quota, \
                 memory ceiling or task ceiling can be attached — run under a login \
                 session, or enable lingering for this user"
            }
        }
    }
}

/// Whether a transient scope can bound anything on this host.
///
/// `None` means it can. Probed rather than assumed: the enforcement claim a
/// receipt carries has to describe this host, and both halves of the mechanism
/// are things a deployment can legitimately be missing.
#[must_use]
pub fn mechanism_gap() -> Option<MechanismGap> {
    if !binary_on_path(SYSTEMD_RUN) {
        return Some(MechanismGap::SystemdRunMissing);
    }
    if !session_bus_present() {
        return Some(MechanismGap::NoUserSessionBus);
    }
    None
}

/// The operator-facing sentence for a boot that asked for a CPU bound and did
/// not get one, or `None` when there is nothing to say.
///
/// Degrading is deliberate: a dev run on a host with no user session bus still
/// boots. Degrading *silently* is not — a user who asked for 1.5 cores, got the
/// whole machine, and was told nothing has no way to learn the difference, and
/// the shape of host that degrades (a non-interactive `ssh host mvmctl …`, a CI
/// runner, a `nohup`'d process) is the common one.
///
/// Pure, with the host probe left to the caller, so both gap messages are
/// exercisable from a host that has neither gap.
///
/// A [`CpuGrant::Fuel`] request is not a degradation here: an instruction
/// budget is wasmtime's unit, and a cgroup scope has no conversion for it.
#[must_use]
pub fn cpu_degradation_reason(
    requested: Option<&CpuGrant>,
    enforced: EnforcedTier,
    gap: Option<MechanismGap>,
) -> Option<String> {
    if enforced.is_enforced() {
        return None;
    }
    let CpuGrant::Share { millicores } = requested? else {
        return None;
    };
    let why = match gap {
        Some(gap) => gap.describe(),
        None => "this backend has no CPU quota mechanism",
    };
    Some(format!(
        "CPU grant of {millicores} millicores was NOT enforced: {why}. \
         This workload is running unbounded."
    ))
}

/// A scope id may contain only characters that cannot change the meaning of a
/// unit name or a cgroup path. The machine id is validated upstream; this is
/// the second gate, and the only source a scope name is ever built from.
pub fn validate_scope_id(id: &str) -> Result<()> {
    if id.is_empty() {
        bail!("a spawn scope id must not be empty");
    }
    if id.len() > MAX_SCOPE_ID_LEN {
        bail!(
            "spawn scope id is {len} bytes; systemd unit names are capped, so ids over \
             {MAX_SCOPE_ID_LEN} are refused",
            len = id.len()
        );
    }
    if id.starts_with('-') {
        // A leading dash reaches `systemd-run` as something that reads like an
        // option rather than a unit name.
        bail!("spawn scope id {id:?} must not start with '-'");
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        bail!("spawn scope id {id:?} contains characters that are not path-safe");
    }
    Ok(())
}

/// The transient unit name for a scope id.
///
/// Call [`validate_scope_id`] first; this is a rendering, not a gate.
#[must_use]
pub fn scope_name(scope_id: &str) -> String {
    format!("{scope_id}.scope")
}

/// The file under a VM's state dir naming the scope its process was born into.
///
/// The unit name is unique per boot, so it cannot be recomputed from the
/// machine id later. Recording it is what keeps the read-back possible: without
/// it, uniqueness would have been bought by giving up the ability to say what is
/// in effect, which is the one thing this module exists to do.
const SCOPE_UNIT_FILE: &str = "spawn-scope";

/// A scope id for one boot: the machine id plus a per-boot suffix.
///
/// Unique rather than fixed because `systemd-run --unit` refuses a name that is
/// already taken, and a scope outlives the process that created it for as long
/// as anything remains in its cgroup. With a fixed name, one leftover VMM from
/// an unclean stop would make every subsequent boot of that machine fail.
///
/// Resetting the stale unit instead was considered and rejected: a leftover
/// scope is only *active* because a process is still in it, so clearing it means
/// killing whatever that is. The drivers deliberately refuse to displace a live
/// VM, and a limits helper is the wrong place to overrule them.
#[must_use]
fn boot_scope_id(machine_id: &str) -> String {
    // Wall-clock nanoseconds and the pid: unique across boots on one host, and
    // unique across concurrent processes on it. This is a name, not a secret —
    // it needs to not collide, not to be unguessable.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!("{machine_id}-{:x}-{:x}", nanos, std::process::id())
}

/// The `CPUQuota=` percentage for a share, in thousandths of a core.
///
/// Rounds *down*. A rounded-up quota would hand the workload more host CPU than
/// it was granted, and a bound that exceeds its own grant is not a bound;
/// flooring can only make the limit tighter than asked. A share that floors to
/// nothing is refused rather than emitted as `0%`, which systemd reads as a
/// quota of zero — something other than either "unbounded" or "as granted".
pub fn cpu_quota_percent(millicores: u32) -> Result<u32> {
    let percent = millicores / MILLICORES_PER_PERCENT;
    if percent == 0 {
        bail!(
            "a CPU share of {millicores} millicores is below the {MILLICORES_PER_PERCENT} \
             millicores systemd can express; declare no CPU grant for unbounded"
        );
    }
    Ok(percent)
}

/// The `memory.max` a guest of `guest_memory_mib` is scoped to, in bytes.
#[must_use]
pub const fn memory_max_bytes_for_guest(guest_memory_mib: u32) -> u64 {
    (guest_memory_mib as u64 + VMM_MEMORY_OVERHEAD_MIB) * BYTES_PER_MIB
}

/// What one VMM spawn is to be bounded by.
///
/// Guest memory is known at every spawn site and always bounded; the CPU grant
/// is present only when the launch was admitted under one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpawnBounds {
    guest_memory_mib: u32,
    cpu_grant: Option<CpuGrant>,
}

impl SpawnBounds {
    /// Bounds for a VMM whose guest has `guest_memory_mib` of RAM.
    #[must_use]
    pub const fn for_guest_memory(guest_memory_mib: u32) -> Self {
        Self {
            guest_memory_mib,
            cpu_grant: None,
        }
    }

    /// Carry the CPU grant this launch was admitted under, if any.
    #[must_use]
    pub const fn with_cpu_grant(mut self, cpu_grant: Option<CpuGrant>) -> Self {
        self.cpu_grant = cpu_grant;
        self
    }
}

/// The limits a scope is created with, resolved from [`SpawnBounds`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ScopeLimits {
    cpu_quota_percent: Option<u32>,
    memory_max_mib: Option<u64>,
    tasks_max: u32,
}

impl ScopeLimits {
    /// Resolve the limits for one spawn, logging whatever cannot be applied.
    fn resolve(machine_id: &str, bounds: &SpawnBounds) -> Self {
        Self {
            cpu_quota_percent: bindable_quota_percent(machine_id, bounds.cpu_grant.as_ref()),
            memory_max_mib: memory_max_mib(machine_id, bounds.guest_memory_mib),
            tasks_max: VMM_TASKS_MAX,
        }
    }

    /// The `-p` properties, in a fixed order so an argv can be asserted whole.
    fn properties(&self) -> Vec<String> {
        let mut props = Vec::new();
        if let Some(percent) = self.cpu_quota_percent {
            props.push(format!("CPUQuota={percent}%"));
        }
        if let Some(mib) = self.memory_max_mib {
            props.push(format!("MemoryMax={mib}M"));
            // Without this the ceiling bounds resident memory and nothing
            // else: a leaking VMM on a host with swap is pushed out to swap
            // instead of being stopped, until swap is gone too.
            props.push("MemorySwapMax=0".to_string());
        }
        props.push(format!("TasksMax={}", self.tasks_max));
        // Stated rather than inherited from the manager's default, so a kill
        // ends the whole scope and the unit reports `oom-kill`, which is what
        // the exit report reads.
        props.push("OOMPolicy=stop".to_string());
        props
            .into_iter()
            .flat_map(|prop| ["-p".to_string(), prop])
            .collect()
    }
}

/// The memory ceiling for a guest, or `None` when the guest size is unknown.
///
/// Zero means "the backend's default", which this module cannot see; a ceiling
/// computed from it would be the overhead alone and kill the VM at boot.
fn memory_max_mib(machine_id: &str, guest_memory_mib: u32) -> Option<u64> {
    if guest_memory_mib == 0 {
        tracing::warn!(
            "no guest memory size for '{machine_id}', so its VMM gets no memory ceiling"
        );
        return None;
    }
    Some(u64::from(guest_memory_mib) + VMM_MEMORY_OVERHEAD_MIB)
}

/// The quota percent to bind, or `None` with the reason logged.
fn bindable_quota_percent(machine_id: &str, grant: Option<&CpuGrant>) -> Option<u32> {
    let Some(CpuGrant::Share { millicores }) = grant else {
        // No grant, or a fuel budget — which is wasmtime's unit, not this
        // mechanism's, so it passes through rather than being converted into a
        // share nobody granted.
        return None;
    };
    match cpu_quota_percent(*millicores) {
        Ok(percent) => Some(percent),
        Err(e) => {
            tracing::warn!("CPU share for '{machine_id}' not applied: {e}");
            None
        }
    }
}

/// The `systemd-run` tokens that precede a payload's own argv, ending in the
/// `--` separator.
///
/// The single place these flags are spelled. Two kinds of spawn site consume
/// them — one building a [`Command`], one building a shell string for a spawn
/// that daemonizes — and a second copy of this list is how the two would
/// silently drift into bounding different things.
fn scope_prefix(scope_id: &str, limits: &ScopeLimits) -> Vec<String> {
    let mut prefix = vec![
        SYSTEMD_RUN.to_string(),
        "--user".to_string(),
        "--scope".to_string(),
        "--quiet".to_string(),
        "--unit".to_string(),
        scope_name(scope_id),
    ];
    prefix.extend(limits.properties());
    prefix.push("--".to_string());
    prefix
}

/// A scope decided on for one boot: its minted id and the limits it carries.
struct PreparedScope {
    scope_id: String,
    limits: ScopeLimits,
}

/// Decide whether to scope this spawn, mint this boot's unit name, and record
/// it.
///
/// One ladder, so the `Command` and shell-string paths cannot disagree about
/// which spawns get scoped or about what the scope is called.
fn prepare_scope(
    machine_id: &str,
    state_dir: &Path,
    bounds: &SpawnBounds,
) -> Option<PreparedScope> {
    if let Some(gap) = mechanism_gap() {
        // A requested share going unenforced is worth an operator's attention.
        // The memory and task ceilings every spawn gets were not requested, so
        // their absence on a host without the mechanism is the expected case.
        if let Some(CpuGrant::Share { millicores }) = bounds.cpu_grant {
            tracing::info!(
                "CPU share of {millicores} millicores for '{machine_id}' will not be enforced: {}",
                gap.describe()
            );
        } else {
            tracing::debug!("no spawn scope for '{machine_id}': {}", gap.describe());
        }
        return None;
    }
    if let Err(e) = validate_scope_id(machine_id) {
        tracing::warn!("no spawn scope for '{machine_id}': {e}");
        return None;
    }
    let limits = ScopeLimits::resolve(machine_id, bounds);
    let scope_id = boot_scope_id(machine_id);
    // A recorded name is what makes the limits readable afterwards. If it
    // cannot be written the bound still applies — the workload is bounded
    // either way — and only the report suffers, which then *understates* what
    // is in effect. Understating is the safe direction; dropping a working
    // bound to keep the bookkeeping tidy is not.
    if let Err(e) = std::fs::write(state_dir.join(SCOPE_UNIT_FILE), scope_name(&scope_id)) {
        tracing::warn!(
            "spawn scope for '{machine_id}' is in effect but its name could not be recorded in \
             {}: {e} — the achieved limits will read back as declared",
            state_dir.display()
        );
    }
    Some(PreparedScope { scope_id, limits })
}

/// The scope prefix for this boot, or `None` when nothing is to be bound.
///
/// For spawn sites that build a command line as *text* rather than a
/// [`Command`]: the caller quotes each token into its own shell, records the
/// launcher's pid, and hands it to [`await_detached_launcher`]. Same ladder,
/// same per-boot unit, same recorded name as [`bind_spawn`]; only the rendering
/// differs.
#[must_use]
pub fn scope_prefix_for_spawn(
    machine_id: &str,
    state_dir: &Path,
    bounds: &SpawnBounds,
) -> Option<Vec<String>> {
    let prepared = prepare_scope(machine_id, state_dir, bounds)?;
    Some(scope_prefix(&prepared.scope_id, &prepared.limits))
}

/// A VMM launch, wrapped in its scope when this host can serve one.
///
/// Not a bare [`Command`], because starting a scoped launch is not only
/// starting a process: the launch must also fail if the service manager never
/// creates the scope. Keeping the command private is what makes that watch
/// impossible to skip.
pub struct BoundCommand {
    command: Command,
    unit: Option<String>,
    machine_id: String,
    creation_timeout: Duration,
}

impl BoundCommand {
    /// Configure the payload's stdin.
    pub fn stdin(&mut self, cfg: impl Into<Stdio>) -> &mut Self {
        self.command.stdin(cfg);
        self
    }

    /// Configure the payload's stdout.
    pub fn stdout(&mut self, cfg: impl Into<Stdio>) -> &mut Self {
        self.command.stdout(cfg);
        self
    }

    /// Configure the payload's stderr.
    pub fn stderr(&mut self, cfg: impl Into<Stdio>) -> &mut Self {
        self.command.stderr(cfg);
        self
    }

    /// The scope unit this launch is born into, or `None` when unscoped.
    #[must_use]
    pub fn unit(&self) -> Option<&str> {
        self.unit.as_deref()
    }

    /// The command as it will run, for assertions.
    #[must_use]
    pub fn as_command(&self) -> &Command {
        &self.command
    }

    /// Shorten the creation deadline, so the timeout path is testable without
    /// a ten-second wait.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn with_creation_timeout(mut self, timeout: Duration) -> Self {
        self.creation_timeout = timeout;
        self
    }

    /// Start the launch and, for a scoped one, wait until the payload is
    /// running inside its scope.
    ///
    /// On timeout the launcher is killed and reaped before the error returns,
    /// so an unresponsive manager leaves no half-started launch behind.
    pub fn spawn(&mut self) -> Result<Child> {
        let program = self.command.get_program().to_string_lossy().into_owned();
        let mut child = self
            .command
            .spawn()
            .with_context(|| format!("spawning {program}"))?;
        let Some(unit) = self.unit.as_deref() else {
            return Ok(child);
        };
        let pid = child.id();
        let outcome = watch_launcher(self.creation_timeout, || {
            if child.try_wait()?.is_some() {
                return Ok(LauncherProbe::Exited);
            }
            probe_launcher_comm(Path::new(PROC_ROOT), pid)
        })
        .with_context(|| format!("watching the scope launcher for '{}'", self.machine_id))?;
        if outcome == LaunchWatch::TimedOut {
            let _ = child.kill();
            let _ = child.wait();
            return Err(scope_creation_timeout(
                &self.machine_id,
                unit,
                self.creation_timeout,
            ));
        }
        Ok(child)
    }

    /// Run the launch to completion and return its status.
    pub fn status(&mut self) -> Result<ExitStatus> {
        let mut child = self.spawn()?;
        child.wait().context("waiting for the launch to exit")
    }
}

/// The one seam every per-VM `Command` spawn goes through: bound the process
/// this command is about to become, if this host can serve a scope.
///
/// Infallible by design. A scope that cannot be attached — no mechanism on this
/// host, an unusable machine id — returns the original command unwrapped and
/// says why, and [`enforced_grants_for_vm`] then reads the live controls back
/// and reports [`EnforcedTier::Declared`], so a degraded boot cannot be mistaken
/// for a bounded one. What *is* fatal is a mechanism that is present and does
/// not answer; that surfaces from [`BoundCommand::spawn`].
///
/// The admission gate refuses an unenforceable CPU share under `--prod` before
/// anything is spawned, and since it consults this host's own
/// [`mechanism_gap`], a sealed run does not reach here with a share it cannot
/// serve. Dev runs do, and degrade.
///
/// [`CpuGrant::Fuel`] is not this mechanism's unit — an instruction budget is
/// wasmtime's to enforce — so it adds no quota rather than being converted into
/// a share it is not.
#[must_use]
pub fn bind_spawn(
    cmd: Command,
    machine_id: &str,
    state_dir: &Path,
    bounds: &SpawnBounds,
) -> BoundCommand {
    let (command, unit) = match prepare_scope(machine_id, state_dir, bounds) {
        Some(prepared) => (
            wrap_checked(cmd, &prepared.scope_id, &prepared.limits),
            Some(scope_name(&prepared.scope_id)),
        ),
        None => (cmd, None),
    };
    BoundCommand {
        command,
        unit,
        machine_id: machine_id.to_string(),
        creation_timeout: SCOPE_CREATION_TIMEOUT,
    }
}

/// The rendering half of the wrap, after the decision has been made.
///
/// Split out because `Command` is not `Clone`: a fallible wrap consumes its
/// input, so a caller that wants the original back on refusal has to do the
/// checking before handing it over. [`bind_spawn`] is that caller.
fn wrap_checked(cmd: Command, scope_id: &str, limits: &ScopeLimits) -> Command {
    let prefix = scope_prefix(scope_id, limits);
    let mut wrapped = Command::new(&prefix[0]);
    wrapped.args(&prefix[1..]);
    wrapped.arg(cmd.get_program());
    wrapped.args(cmd.get_args());

    // `systemd-run --scope` execs the payload from its own process, so the
    // inherited environment carries over on its own; only the overrides the
    // caller set on the original command need replaying.
    for (key, value) in cmd.get_envs() {
        match value {
            Some(value) => wrapped.env(key, value),
            None => wrapped.env_remove(key),
        };
    }
    if let Some(dir) = cmd.get_current_dir() {
        wrapped.current_dir(dir);
    }
    wrapped
}

/// Wait for a launcher that was started detached — by a shell that has already
/// exited — to exec its payload inside the scope.
///
/// `pid_file` holds the launcher's pid, written by the shell that started it.
/// A launcher still waiting on the manager at the deadline is killed and the
/// launch fails.
pub fn await_detached_launcher(pid_file: &Path, machine_id: &str) -> Result<()> {
    await_detached_launcher_within(pid_file, machine_id, SCOPE_CREATION_TIMEOUT)
}

fn await_detached_launcher_within(
    pid_file: &Path,
    machine_id: &str,
    timeout: Duration,
) -> Result<()> {
    let raw = std::fs::read_to_string(pid_file).with_context(|| {
        format!(
            "reading the scope launcher pid for '{machine_id}' from {}",
            pid_file.display()
        )
    })?;
    let pid: u32 = raw.trim().parse().with_context(|| {
        format!(
            "the scope launcher pid in {} is not a pid: {raw:?}",
            pid_file.display()
        )
    })?;
    let proc_root = Path::new(PROC_ROOT);
    let outcome = watch_launcher(timeout, || probe_launcher_comm(proc_root, pid))
        .with_context(|| format!("watching the scope launcher for '{machine_id}'"))?;
    if outcome == LaunchWatch::TimedOut {
        // Re-checked immediately before the kill: once the launcher has exec'd,
        // this pid is the VMM, and it is not this function's to kill.
        if probe_launcher_comm(proc_root, pid).ok() == Some(LauncherProbe::Launching) {
            let _ = Command::new("kill")
                .args(["-KILL", &pid.to_string()])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        return Err(scope_creation_timeout(
            machine_id,
            "for this launch",
            timeout,
        ));
    }
    Ok(())
}

fn scope_creation_timeout(machine_id: &str, unit: &str, timeout: Duration) -> anyhow::Error {
    anyhow::anyhow!(
        "the systemd user manager did not create scope {unit} for '{machine_id}' within \
         {timeout:?}; the launch was aborted rather than left waiting on an unresponsive \
         service manager (check `systemctl --user status`)"
    )
}

/// One observation of a scope launcher.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LauncherProbe {
    /// Still `systemd-run`: the scope does not exist yet.
    Launching,
    /// The pid now runs the payload, which `systemd-run` execs only after the
    /// scope exists.
    Execed,
    /// The launcher is gone. Whatever it reported is the caller's to surface;
    /// a failed launch already has its own error path.
    Exited,
    /// This host has no process table to read, so nothing can be watched.
    Unobservable,
}

/// How a launcher watch ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LaunchWatch {
    Execed,
    Exited,
    Unobservable,
    TimedOut,
}

/// Poll `probe` until the launcher stops launching or `timeout` passes.
///
/// The probe is a parameter so the deadline logic is testable without a
/// service manager to wedge.
fn watch_launcher(
    timeout: Duration,
    mut probe: impl FnMut() -> std::io::Result<LauncherProbe>,
) -> std::io::Result<LaunchWatch> {
    let deadline = Instant::now() + timeout;
    let mut attempt = 0u32;
    loop {
        match probe()? {
            LauncherProbe::Execed => return Ok(LaunchWatch::Execed),
            LauncherProbe::Exited => return Ok(LaunchWatch::Exited),
            LauncherProbe::Unobservable => return Ok(LaunchWatch::Unobservable),
            LauncherProbe::Launching => {}
        }
        if Instant::now() >= deadline {
            return Ok(LaunchWatch::TimedOut);
        }
        std::thread::sleep(crate::poll_backoff::poll_delay(attempt));
        attempt = attempt.saturating_add(1);
    }
}

/// Classify a launcher pid by its command name under `proc_root`.
///
/// The name is the signal because it is the one thing that changes at exec and
/// that any user may read: a launcher that execs `sudo` becomes a root process
/// whose executable link this user cannot follow.
fn probe_launcher_comm(proc_root: &Path, pid: u32) -> std::io::Result<LauncherProbe> {
    if !proc_root.join("self").exists() {
        return Ok(LauncherProbe::Unobservable);
    }
    match std::fs::read_to_string(proc_root.join(pid.to_string()).join("comm")) {
        Ok(comm) if comm.trim() == SYSTEMD_RUN => Ok(LauncherProbe::Launching),
        Ok(_) => Ok(LauncherProbe::Execed),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(LauncherProbe::Exited),
        Err(e) => Err(e),
    }
}

/// What actually bounded this VM, read off the live controls.
///
/// The one function a backend's `apply_grants` calls. Resolves the scope this
/// VM's process was born into, asks systemd where it put it, and reads that
/// cgroup's `cpu.max`, `memory.max` and `pids.max`. A tier derived from "the
/// spawn returned 0" would assert an enforcement that a silently-dropped limit
/// makes false, which is the overstatement this whole seam exists to prevent.
///
/// For the in-house HVF VMM the CPU probe is superseded: the supervisor writes
/// a measured quota record instead, and that record is read back here when it
/// is present.
///
/// Wall clock is [`EnforcedTier::Declared`] because nothing here bounds it. It
/// is reported rather than omitted so a receipt says which dimensions were
/// measured and found unenforced, instead of leaving a reader to guess.
#[must_use]
pub fn enforced_grants_for_vm(state_dir: &Path) -> EnforcedGrants {
    let scope = ScopeProbe::default().readback_for_vm(state_dir);
    let vcpu_quota_tier = crate::vcpu_quota::tier_for_vm(state_dir);
    let cpu = if vcpu_quota_tier == EnforcedTier::HvfVcpuQuota {
        EnforcedTier::HvfVcpuQuota
    } else {
        scope.cpu
    };
    EnforcedGrants {
        cpu,
        wall_clock: EnforcedTier::Declared,
        memory: scope.memory,
        tasks: scope.tasks,
    }
}

/// The limits a scope was read back as enforcing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScopeReadback {
    pub cpu: EnforcedTier,
    pub memory: EnforcedCeiling,
    pub tasks: EnforcedCeiling,
}

impl ScopeReadback {
    /// Nothing confirmed on any dimension.
    #[must_use]
    pub const fn declared() -> Self {
        Self {
            cpu: EnforcedTier::Declared,
            memory: EnforcedCeiling::declared(),
            tasks: EnforcedCeiling::declared(),
        }
    }
}

/// A scope the kernel's OOM killer ended, as its unit reports afterwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryLimitExceeded {
    /// The ceiling the unit carried, when it reports a finite one.
    pub memory_max_bytes: Option<u64>,
}

/// Reads a live scope's limits off the system.
///
/// A struct rather than free functions so the two things it touches — the
/// unified hierarchy's mount point and the `systemctl` binary — are values a
/// test can point somewhere else. Without that seam the read-back could only be
/// exercised on a Linux host with a real session, which is exactly the
/// coverage gap that let an unreported tier ship.
pub struct ScopeProbe {
    cgroup_root: PathBuf,
    systemctl: PathBuf,
}

impl Default for ScopeProbe {
    fn default() -> Self {
        Self {
            cgroup_root: PathBuf::from(CGROUP_ROOT),
            systemctl: PathBuf::from(SYSTEMCTL),
        }
    }
}

impl ScopeProbe {
    /// A probe pointed at a scratch hierarchy and a stand-in `systemctl`.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn with_root_and_systemctl(cgroup_root: PathBuf, systemctl: PathBuf) -> Self {
        Self {
            cgroup_root,
            systemctl,
        }
    }

    /// The limits in effect for the VM whose state lives in `state_dir`.
    ///
    /// A VM with no recorded scope was never bound, so it is a declaration.
    #[must_use]
    pub fn readback_for_vm(&self, state_dir: &Path) -> ScopeReadback {
        match read_scope_unit(state_dir) {
            Some(unit) => self.readback_for_unit(&unit),
            None => ScopeReadback::declared(),
        }
    }

    /// The limits a named scope unit is enforcing.
    ///
    /// An absent mechanism, an absent unit, an unreadable cgroup and a control
    /// reading `max` all answer declared for that dimension. There is no error
    /// case: the boot already happened, and the only question left is what is
    /// true about it.
    #[must_use]
    pub fn readback_for_unit(&self, unit: &str) -> ScopeReadback {
        let Some(control_group) = self.control_group(unit) else {
            return ScopeReadback::declared();
        };
        let read = |file: &str| std::fs::read_to_string(self.cgroup_file(&control_group, file));
        ScopeReadback {
            cpu: read("cpu.max").map_or(EnforcedTier::Declared, |line| tier_from_cpu_max(&line)),
            memory: read("memory.max").map_or(EnforcedCeiling::declared(), |value| {
                ceiling_from_limit_file(&value, EnforcedTier::Cgroup2MemoryMax)
            }),
            tasks: read("pids.max").map_or(EnforcedCeiling::declared(), |value| {
                ceiling_from_limit_file(&value, EnforcedTier::Cgroup2PidsMax)
            }),
        }
    }

    /// Whether the OOM killer ended the scope this VM was born into.
    ///
    /// Read from the unit rather than the cgroup: a scope whose processes are
    /// all dead has no cgroup left to read, but a failed unit keeps its result
    /// until it is reset.
    #[must_use]
    pub fn memory_limit_exceeded(&self, state_dir: &Path) -> Option<MemoryLimitExceeded> {
        let unit = read_scope_unit(state_dir)?;
        let output = self.systemctl_show(&unit, &["Result", "MemoryMax"])?;
        parse_memory_limit_exceeded(&output)
    }

    /// The cgroup path systemd placed a scope in, or `None` when the unit does
    /// not exist or no user manager answered in time.
    fn control_group(&self, unit: &str) -> Option<String> {
        let output = self.systemctl_show(unit, &["ControlGroup"])?;
        // A unit that does not exist is not an error to `systemctl show`; it
        // reports the property's default, which for `ControlGroup` is empty.
        let value = show_property(&output, "ControlGroup")?;
        if value.is_empty() {
            return None;
        }
        Some(value.to_string())
    }

    /// `systemctl --user show <unit> -p <property>…`, as its `Key=value` lines,
    /// bounded by [`SCOPE_QUERY_TIMEOUT`].
    fn systemctl_show(&self, unit: &str, properties: &[&str]) -> Option<String> {
        let mut cmd = Command::new(&self.systemctl);
        cmd.args(["--user", "show", unit]);
        for property in properties {
            cmd.args(["-p", property]);
        }
        run_bounded(cmd, SCOPE_QUERY_TIMEOUT)
    }

    /// A control file inside a cgroup, resolved against the hierarchy root.
    fn cgroup_file(&self, control_group: &str, file: &str) -> PathBuf {
        self.cgroup_root
            .join(control_group.trim_start_matches('/'))
            .join(file)
    }
}

/// Run a query and return its stdout, or `None` when it fails or outlives
/// `timeout`. A query that hangs is killed rather than waited on.
fn run_bounded(mut cmd: Command, timeout: Duration) -> Option<String> {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let deadline = Instant::now() + timeout;
    let mut attempt = 0u32;
    let status = loop {
        if let Some(status) = child.try_wait().ok()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            tracing::warn!("{:?} did not answer within {timeout:?}", cmd.get_program());
            return None;
        }
        std::thread::sleep(crate::poll_backoff::poll_delay(attempt));
        attempt = attempt.saturating_add(1);
    };
    if !status.success() {
        return None;
    }
    let mut stdout = String::new();
    child.stdout.take()?.read_to_string(&mut stdout).ok()?;
    Some(stdout)
}

/// One property's value from `systemctl show` output.
fn show_property<'a>(output: &'a str, key: &str) -> Option<&'a str> {
    output
        .lines()
        .find_map(|line| line.strip_prefix(key)?.strip_prefix('='))
        .map(str::trim)
}

/// The scope unit this VM's process was born into, as recorded at spawn.
#[must_use]
pub fn read_scope_unit(state_dir: &Path) -> Option<String> {
    let recorded = std::fs::read_to_string(state_dir.join(SCOPE_UNIT_FILE)).ok()?;
    let unit = recorded.trim();
    if unit.is_empty() {
        return None;
    }
    // Re-validated on the way out. The file sits in a directory the invoking
    // user owns, and a unit name is about to reach a subprocess argv, so its
    // shape is checked here rather than trusted because we wrote it.
    let id = unit.strip_suffix(".scope")?;
    validate_scope_id(id).ok()?;
    Some(unit.to_string())
}

/// The tier a `cpu.max` line witnesses.
///
/// `max <period>` is cgroup v2's spelling of "no quota", so a scope that exists
/// but was never given one is a declaration, not an enforcement.
fn tier_from_cpu_max(line: &str) -> EnforcedTier {
    match parse_cpu_max_quota(line) {
        Some(_) => EnforcedTier::Cgroup2CpuMax,
        None => EnforcedTier::Declared,
    }
}

/// The quota field of a `cpu.max` line, or `None` when it reads `max`.
fn parse_cpu_max_quota(line: &str) -> Option<u64> {
    line.split_whitespace().next()?.parse::<u64>().ok()
}

/// The ceiling a single-value limit file (`memory.max`, `pids.max`) witnesses.
///
/// `max` is no limit, and so is anything that does not parse: a reading that
/// cannot be understood must not become a claimed enforcement.
fn ceiling_from_limit_file(contents: &str, tier: EnforcedTier) -> EnforcedCeiling {
    match parse_limit_value(contents) {
        Some(limit) => EnforcedCeiling::enforced(tier, limit),
        None => EnforcedCeiling::declared(),
    }
}

/// A single-value limit, or `None` for `max`, `infinity`, or anything
/// unparseable.
fn parse_limit_value(contents: &str) -> Option<u64> {
    contents.trim().parse::<u64>().ok()
}

/// Whether `systemctl show -p Result -p MemoryMax` output describes an OOM kill.
fn parse_memory_limit_exceeded(show: &str) -> Option<MemoryLimitExceeded> {
    if show_property(show, "Result")? != OOM_KILL_RESULT {
        return None;
    }
    Some(MemoryLimitExceeded {
        memory_max_bytes: show_property(show, "MemoryMax").and_then(parse_limit_value),
    })
}

/// Whether a binary is reachable through `PATH`.
///
/// Resolved by inspection rather than by spawning: probing availability must
/// not itself start a process on a host where the answer is "absent".
fn binary_on_path(binary: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| dir.join(binary).is_file())
}

/// Whether this process can reach a systemd *user* manager.
///
/// Delegation hangs off the session, so this is the half that is missing on a
/// headless daemon far more often than the binary is.
fn session_bus_present() -> bool {
    if non_empty_env("DBUS_SESSION_BUS_ADDRESS").is_some() {
        return true;
    }
    non_empty_env("XDG_RUNTIME_DIR").is_some_and(|dir| Path::new(&dir).join("bus").exists())
}

fn non_empty_env(key: &str) -> Option<std::ffi::OsString> {
    std::env::var_os(key).filter(|value| !value.is_empty())
}

/// Make [`mechanism_gap`] answer "present" for the duration of a test.
///
/// Creates a `systemd-run` on a scratch `PATH` and a session-bus path, then
/// points the process at both. It fakes only what the *probe* reads — a spawn
/// through this still runs whatever is on that `PATH` — so a test can assert the
/// argv a bound spawn produces on any host, including a Mac, instead of
/// asserting one thing on Linux and something weaker everywhere else.
///
/// `scratch` must outlive the guard; a caller's `tempfile::TempDir` is the
/// intended source. Env mutation goes through [`crate::util::test_env::TestEnv`]
/// so it is serialized and restored on drop.
#[cfg(any(test, feature = "test-support"))]
pub fn pretend_mechanism_present(
    env: &mut crate::util::test_env::TestEnv,
    scratch: &Path,
) -> std::io::Result<()> {
    pretend_mechanism_with_launcher(env, scratch, "#!/bin/sh\nexit 0\n")
}

/// [`pretend_mechanism_present`] with a chosen `systemd-run` body, so a test
/// can stand in a launcher that execs its payload or one that never does.
#[cfg(any(test, feature = "test-support"))]
pub fn pretend_mechanism_with_launcher(
    env: &mut crate::util::test_env::TestEnv,
    scratch: &Path,
    launcher_script: &str,
) -> std::io::Result<()> {
    let bin_dir = scratch.join("bin");
    let run_dir = scratch.join("run");
    std::fs::create_dir_all(&bin_dir)?;
    std::fs::create_dir_all(&run_dir)?;
    let fake = bin_dir.join(SYSTEMD_RUN);
    std::fs::write(&fake, launcher_script)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755))?;
    }
    std::fs::write(run_dir.join("bus"), b"")?;
    let mut path = std::ffi::OsString::from(&bin_dir);
    // The stand-in launcher is a shell script, so the ordinary tool
    // directories stay reachable behind it.
    path.push(":/usr/bin:/bin");
    env.set("PATH", path);
    env.set("XDG_RUNTIME_DIR", &run_dir);
    env.remove("DBUS_SESSION_BUS_ADDRESS");
    Ok(())
}

/// Render a command as `program arg arg …` for assertions and logs.
#[cfg(any(test, feature = "test-support"))]
#[must_use]
pub fn rendered_argv(cmd: &Command) -> Vec<String> {
    std::iter::once(cmd.get_program())
        .chain(cmd.get_args())
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Never claim HVF vCPU-quota enforcement without a bounded quota record.
    ///
    /// `enforced_grants_for_vm` branches on `vcpu_quota_tier ==
    /// EnforcedTier::HvfVcpuQuota`. Inverting that comparison makes the
    /// *absence* of a record report `HvfVcpuQuota` — a receipt asserting an
    /// enforcement mechanism that never ran, which is precisely the
    /// overstatement this seam exists to prevent.
    ///
    /// A state dir with no record is the common case on every non-HVF backend,
    /// so this is not a corner.
    #[test]
    fn a_vm_with_no_quota_record_never_reports_hvf_quota_enforcement() {
        let dir = tempfile::tempdir().expect("tempdir");
        let grants = enforced_grants_for_vm(dir.path());
        assert_ne!(
            grants.cpu,
            EnforcedTier::HvfVcpuQuota,
            "no quota record was written, so no HVF quota can have been enforced"
        );
    }

    /// Wall clock is reported as declared rather than omitted, so a receipt
    /// says which dimensions were measured and found unenforced instead of
    /// leaving a reader to infer it from silence.
    #[test]
    fn wall_clock_is_reported_declared_rather_than_omitted() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(
            enforced_grants_for_vm(dir.path()).wall_clock,
            EnforcedTier::Declared
        );
    }

    /// Point `PATH` at an empty directory and drop the session bus, so the
    /// mechanism is absent however the host running the test is set up.
    fn pretend_mechanism_absent(env: &mut crate::util::test_env::TestEnv, scratch: &Path) {
        let empty = scratch.join("empty-path");
        std::fs::create_dir_all(&empty).expect("empty PATH dir");
        env.set("PATH", &empty);
        env.remove("XDG_RUNTIME_DIR");
        env.remove("DBUS_SESSION_BUS_ADDRESS");
    }

    fn limits(cpu: Option<u32>, memory: Option<u64>) -> ScopeLimits {
        ScopeLimits {
            cpu_quota_percent: cpu,
            memory_max_mib: memory,
            tasks_max: VMM_TASKS_MAX,
        }
    }

    #[test]
    fn a_scope_name_derives_only_from_the_validated_id() {
        // A user-supplied string in a unit name is a traversal into a sibling
        // subtree by another spelling; the machine id, validated, is the only
        // acceptable source.
        assert_eq!(scope_name("mvm-abc123"), "mvm-abc123.scope");
    }

    #[test]
    fn a_traversing_id_is_refused() {
        for bad in [
            "../escape",
            "a/b",
            "..",
            "with space",
            "",
            "-leading-dash",
            "semi;colon",
            "dollar$sign",
            "new\nline",
        ] {
            assert!(
                validate_scope_id(bad).is_err(),
                "{bad:?} must not reach a unit name"
            );
        }
    }

    #[test]
    fn an_overlong_id_is_refused_here_rather_than_by_systemd() {
        let long = "a".repeat(MAX_SCOPE_ID_LEN + 1);
        assert!(validate_scope_id(&long).is_err());
        assert!(validate_scope_id(&"a".repeat(MAX_SCOPE_ID_LEN)).is_ok());
    }

    #[test]
    fn a_valid_id_is_accepted() {
        assert!(validate_scope_id("mvm-abc123").is_ok());
        assert!(validate_scope_id("mvm_abc_123").is_ok());
    }

    #[test]
    fn millicores_convert_to_a_systemd_percentage() {
        assert_eq!(cpu_quota_percent(1500).expect("1.5 cores"), 150);
        assert_eq!(cpu_quota_percent(1000).expect("1 core"), 100);
        assert_eq!(cpu_quota_percent(500).expect("half a core"), 50);
        assert_eq!(cpu_quota_percent(10).expect("the smallest share"), 1);
    }

    #[test]
    fn a_share_between_percentages_rounds_down_never_up() {
        // Tighter than asked is still a bound; looser than asked is not.
        assert_eq!(cpu_quota_percent(1509).expect("floors"), 150);
        assert_eq!(cpu_quota_percent(1999).expect("floors"), 199);
    }

    #[test]
    fn a_zero_share_is_refused_rather_than_written_as_a_zero_quota() {
        // `CPUQuota=0%` is neither "unbounded" nor the share that was asked
        // for, so no share may round into it.
        assert!(cpu_quota_percent(0).is_err());
        for below_one_percent in [1, 5, 9] {
            assert!(
                cpu_quota_percent(below_one_percent).is_err(),
                "{below_one_percent} millicores floors to 0% and must be refused"
            );
        }
    }

    #[test]
    fn the_memory_ceiling_is_guest_ram_plus_the_named_overhead() {
        assert_eq!(
            memory_max_mib("mvm-abc123", 512),
            Some(512 + VMM_MEMORY_OVERHEAD_MIB)
        );
        assert_eq!(
            memory_max_bytes_for_guest(512),
            (512 + VMM_MEMORY_OVERHEAD_MIB) * 1024 * 1024
        );
    }

    #[test]
    fn an_unknown_guest_size_gets_no_memory_ceiling_rather_than_the_overhead_alone() {
        // A ceiling of the overhead alone would OOM-kill the VM at boot.
        assert_eq!(memory_max_mib("mvm-abc123", 0), None);
        let props = limits(None, None).properties();
        assert!(!props.iter().any(|p| p.starts_with("MemoryMax=")));
        assert!(props.contains(&format!("TasksMax={VMM_TASKS_MAX}")));
    }

    #[test]
    fn limits_resolve_from_the_admitted_bounds() {
        let bounds = SpawnBounds::for_guest_memory(2048)
            .with_cpu_grant(Some(CpuGrant::Share { millicores: 750 }));
        assert_eq!(
            ScopeLimits::resolve("mvm-abc123", &bounds),
            limits(Some(75), Some(2048 + VMM_MEMORY_OVERHEAD_MIB))
        );
        // A share systemd cannot express drops the quota and keeps the rest.
        let bounds = SpawnBounds::for_guest_memory(256)
            .with_cpu_grant(Some(CpuGrant::Share { millicores: 5 }));
        assert_eq!(
            ScopeLimits::resolve("mvm-abc123", &bounds),
            limits(None, Some(256 + VMM_MEMORY_OVERHEAD_MIB))
        );
    }

    #[test]
    fn wrapping_a_spawn_puts_every_limit_ahead_of_the_payload() {
        let mut inner = Command::new("/usr/bin/mvm-libkrun-supervisor");
        inner.arg("--config").arg("-");
        // The scope id is supplied rather than derived: `boot_scope_id` mixes in
        // the clock and the pid, so an exact-argv assertion can only be written
        // against a fixed id. What is under test here is the *shape* — every
        // limit reaching systemd ahead of the payload — not how the id is minted.
        let wrapped = wrap_checked(inner, "mvm-abc123-1f2e3d-2a", &limits(Some(150), Some(768)));
        assert_eq!(
            rendered_argv(&wrapped),
            vec![
                "systemd-run",
                "--user",
                "--scope",
                "--quiet",
                "--unit",
                "mvm-abc123-1f2e3d-2a.scope",
                "-p",
                "CPUQuota=150%",
                "-p",
                "MemoryMax=768M",
                "-p",
                "MemorySwapMax=0",
                "-p",
                "TasksMax=1024",
                "-p",
                "OOMPolicy=stop",
                "--",
                "/usr/bin/mvm-libkrun-supervisor",
                "--config",
                "-",
            ]
        );
    }

    #[test]
    fn wrapping_carries_the_environment_and_working_directory_across() {
        let mut inner = Command::new("/bin/true");
        inner.env("MVM_HOME", "/tmp/mvm-home");
        inner.env_remove("RUST_LOG");
        inner.current_dir("/tmp");
        let wrapped = wrap_checked(inner, "mvm-abc123-1f2e3d-2a", &limits(Some(100), None));

        let envs: Vec<(String, Option<String>)> = wrapped
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect();
        assert!(envs.contains(&("MVM_HOME".to_string(), Some("/tmp/mvm-home".to_string()))));
        assert!(envs.contains(&("RUST_LOG".to_string(), None)));
        assert_eq!(wrapped.get_current_dir(), Some(Path::new("/tmp")));
    }

    #[test]
    fn an_unusable_share_yields_no_quota_to_bind() {
        assert!(
            bindable_quota_percent("mvm-abc123", Some(&CpuGrant::Share { millicores: 0 }))
                .is_none()
        );
        assert_eq!(
            bindable_quota_percent("mvm-abc123", Some(&CpuGrant::Share { millicores: 1500 })),
            Some(150)
        );
    }

    #[test]
    fn a_host_without_the_mechanism_leaves_the_spawn_exactly_as_it_was() {
        let scratch = tempfile::tempdir().expect("scratch");
        let mut env = crate::util::test_env::TestEnv::new();
        pretend_mechanism_absent(&mut env, scratch.path());
        let bounds = SpawnBounds::for_guest_memory(512)
            .with_cpu_grant(Some(CpuGrant::Share { millicores: 1500 }));
        let bound = bind_spawn(
            Command::new("/bin/true"),
            "mvm-abc123",
            scratch.path(),
            &bounds,
        );
        assert_eq!(rendered_argv(bound.as_command()), vec!["/bin/true"]);
        assert_eq!(bound.unit(), None);
        assert!(read_scope_unit(scratch.path()).is_none());
    }

    #[test]
    fn a_spawn_with_no_grant_still_gets_memory_and_task_ceilings() {
        // The ceilings are not grants: a VMM admitted with no CPU share is the
        // one most likely to be left unbounded if they were.
        let scratch = tempfile::tempdir().expect("scratch");
        let mut env = crate::util::test_env::TestEnv::new();
        pretend_mechanism_present(&mut env, scratch.path()).expect("fake mechanism");
        let bound = bind_spawn(
            Command::new("/bin/payload"),
            "mvm-abc123",
            scratch.path(),
            &SpawnBounds::for_guest_memory(512),
        );
        let argv = rendered_argv(bound.as_command());
        assert!(argv.contains(&"MemoryMax=768M".to_string()), "{argv:?}");
        assert!(argv.contains(&"TasksMax=1024".to_string()), "{argv:?}");
        assert!(!argv.iter().any(|a| a.starts_with("CPUQuota=")), "{argv:?}");
        assert_eq!(argv.last().map(String::as_str), Some("/bin/payload"));
    }

    #[test]
    fn binding_a_fuel_grant_adds_no_cpu_quota() {
        // An instruction budget is wasmtime's unit. Converting it into a share
        // would invent a number nobody granted.
        let scratch = tempfile::tempdir().expect("scratch");
        let mut env = crate::util::test_env::TestEnv::new();
        pretend_mechanism_present(&mut env, scratch.path()).expect("fake mechanism");
        let bound = bind_spawn(
            Command::new("/bin/true"),
            "mvm-abc123",
            scratch.path(),
            &SpawnBounds::for_guest_memory(128).with_cpu_grant(Some(CpuGrant::Fuel {
                instructions: 1_000_000,
            })),
        );
        let argv = rendered_argv(bound.as_command());
        assert!(!argv.iter().any(|a| a.starts_with("CPUQuota=")), "{argv:?}");
    }

    #[test]
    fn binding_an_unusable_id_degrades_instead_of_failing_the_spawn() {
        // The boot was already admitted; a bound that cannot be attached must
        // not turn into a refusal here. The read-back is what keeps it honest.
        let scratch = tempfile::tempdir().expect("scratch");
        let mut env = crate::util::test_env::TestEnv::new();
        pretend_mechanism_present(&mut env, scratch.path()).expect("fake mechanism");
        let bound = bind_spawn(
            Command::new("/bin/true"),
            "../escape",
            scratch.path(),
            &SpawnBounds::for_guest_memory(512)
                .with_cpu_grant(Some(CpuGrant::Share { millicores: 1500 })),
        );
        assert_eq!(rendered_argv(bound.as_command()), vec!["/bin/true"]);
    }

    #[test]
    fn a_share_grant_binds_the_spawn_when_the_mechanism_is_present() {
        // The probe is faked, not the enforcement, so this asserts the real
        // argv on every host instead of exercising the degrade branch on macOS
        // and never checking the branch that does the work.
        let scratch = tempfile::tempdir().expect("scratch");
        let mut env = crate::util::test_env::TestEnv::new();
        pretend_mechanism_present(&mut env, scratch.path()).expect("fake mechanism");
        assert_eq!(mechanism_gap(), None, "the probe must see the fake");

        let bound = bind_spawn(
            Command::new("/usr/bin/mvm-libkrun-supervisor"),
            "mvm-abc123",
            scratch.path(),
            &SpawnBounds::for_guest_memory(512)
                .with_cpu_grant(Some(CpuGrant::Share { millicores: 1500 })),
        );
        let argv = rendered_argv(bound.as_command());

        // The unit name carries a per-boot suffix, so it is matched by shape
        // rather than by value; everything around it is still pinned exactly.
        let unit = &argv[5];
        assert!(
            unit.starts_with("mvm-abc123-") && unit.ends_with(".scope"),
            "unit name should be the machine id plus a per-boot suffix, got {unit}"
        );
        assert_eq!(bound.unit(), Some(unit.as_str()));
        let mut skeleton = argv.clone();
        skeleton[5] = "<unit>".to_string();
        assert_eq!(
            skeleton,
            vec![
                "systemd-run",
                "--user",
                "--scope",
                "--quiet",
                "--unit",
                "<unit>",
                "-p",
                "CPUQuota=150%",
                "-p",
                "MemoryMax=768M",
                "-p",
                "MemorySwapMax=0",
                "-p",
                "TasksMax=1024",
                "-p",
                "OOMPolicy=stop",
                "--",
                "/usr/bin/mvm-libkrun-supervisor",
            ]
        );

        // The name is only useful if it was recorded — that file is what makes
        // the limits readable afterwards.
        let recorded = std::fs::read_to_string(scratch.path().join(SCOPE_UNIT_FILE))
            .expect("the scope name is recorded for the read-back");
        assert_eq!(&recorded, unit);
    }

    #[test]
    fn the_shell_prefix_and_the_command_wrap_spell_the_same_flags() {
        // Two spawn shapes, one flag list. If these ever disagree, one of the
        // two backends is bounding something other than what the other is.
        let scratch = tempfile::tempdir().expect("scratch");
        let mut env = crate::util::test_env::TestEnv::new();
        pretend_mechanism_present(&mut env, scratch.path()).expect("fake mechanism");

        let bounds = SpawnBounds::for_guest_memory(1024)
            .with_cpu_grant(Some(CpuGrant::Share { millicores: 1500 }));
        let prefix = scope_prefix_for_spawn("mvm-abc123", scratch.path(), &bounds)
            .expect("a bindable spawn");
        let bound = bind_spawn(
            Command::new("/bin/payload"),
            "mvm-abc123",
            scratch.path(),
            &bounds,
        );

        // Each call mints its own per-boot unit, so the names differ by design.
        // Blank that one token out; every other flag must match.
        let blank_unit = |mut argv: Vec<String>| {
            if let Some(i) = argv.iter().position(|a| a == "--unit") {
                argv[i + 1] = "<unit>".to_string();
            }
            argv
        };
        let mut expected = blank_unit(prefix);
        expected.push("/bin/payload".to_string());
        assert_eq!(blank_unit(rendered_argv(bound.as_command())), expected);
    }

    #[test]
    fn the_shell_prefix_is_absent_when_the_host_has_no_mechanism() {
        let scratch = tempfile::tempdir().expect("scratch");
        let mut env = crate::util::test_env::TestEnv::new();
        pretend_mechanism_absent(&mut env, scratch.path());
        assert_eq!(
            scope_prefix_for_spawn(
                "mvm-abc123",
                scratch.path(),
                &SpawnBounds::for_guest_memory(512)
            ),
            None
        );
    }

    #[test]
    fn a_cpu_max_line_without_a_quota_is_not_an_enforcement() {
        assert_eq!(tier_from_cpu_max("max 100000"), EnforcedTier::Declared);
        assert_eq!(tier_from_cpu_max(""), EnforcedTier::Declared);
        assert_eq!(
            tier_from_cpu_max("150000 100000\n"),
            EnforcedTier::Cgroup2CpuMax
        );
    }

    #[test]
    fn a_cpu_max_quota_parses_off_the_first_field() {
        assert_eq!(parse_cpu_max_quota("150000 100000\n"), Some(150_000));
        assert_eq!(parse_cpu_max_quota("max 100000"), None);
    }

    #[test]
    fn a_limit_file_reading_max_is_not_an_enforcement() {
        assert_eq!(
            ceiling_from_limit_file("max\n", EnforcedTier::Cgroup2MemoryMax),
            EnforcedCeiling::declared()
        );
        assert_eq!(
            ceiling_from_limit_file("", EnforcedTier::Cgroup2PidsMax),
            EnforcedCeiling::declared()
        );
        assert_eq!(
            ceiling_from_limit_file("not-a-number", EnforcedTier::Cgroup2PidsMax),
            EnforcedCeiling::declared()
        );
    }

    #[test]
    fn a_numeric_limit_file_reads_back_its_value() {
        let memory = ceiling_from_limit_file("805306368\n", EnforcedTier::Cgroup2MemoryMax);
        assert_eq!(memory.tier(), EnforcedTier::Cgroup2MemoryMax);
        assert_eq!(memory.limit(), Some(805_306_368));
        let tasks = ceiling_from_limit_file("1024\n", EnforcedTier::Cgroup2PidsMax);
        assert_eq!(tasks.tier(), EnforcedTier::Cgroup2PidsMax);
        assert_eq!(tasks.limit(), Some(1024));
    }

    #[test]
    fn a_cgroup_file_resolves_under_the_probe_s_hierarchy() {
        let probe = ScopeProbe::with_root_and_systemctl(
            PathBuf::from("/sys/fs/cgroup"),
            PathBuf::from("/bin/systemctl"),
        );
        assert_eq!(
            probe.cgroup_file("/user.slice/user-30033.slice/mvm-abc.scope", "cpu.max"),
            Path::new("/sys/fs/cgroup/user.slice/user-30033.slice/mvm-abc.scope/cpu.max")
        );
    }

    #[test]
    fn a_vm_with_no_recorded_scope_reads_back_as_declared_not_as_an_error() {
        // True on every host: nothing was ever bound for this VM, and a boot
        // must not fail because a bound is absent — the admission gate already
        // decided whether that was allowed. Note the return type carries no
        // error at all, which is the design saying the same thing.
        let state = tempfile::tempdir().expect("state dir");
        assert_eq!(
            ScopeProbe::default().readback_for_vm(state.path()),
            ScopeReadback::declared()
        );
    }

    #[test]
    fn a_scope_whose_cgroup_cannot_be_read_reads_back_as_declared() {
        // The understating direction. A recorded unit that resolves to nothing
        // readable must report "not enforced" rather than claim a bound it
        // cannot see.
        let state = tempfile::tempdir().expect("state dir");
        std::fs::write(state.path().join(SCOPE_UNIT_FILE), "mvm-absent-unit.scope")
            .expect("record a unit that does not exist");
        let probe = ScopeProbe::with_root_and_systemctl(
            state.path().join("no-such-cgroup-root"),
            PathBuf::from("/bin/false"),
        );
        assert_eq!(
            probe.readback_for_vm(state.path()),
            ScopeReadback::declared()
        );
    }

    fn fake_systemctl(dir: &Path, body: &str) -> PathBuf {
        let systemctl = dir.join("systemctl");
        std::fs::write(&systemctl, format!("#!/bin/sh\n{body}\n")).expect("write fake systemctl");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&systemctl, std::fs::Permissions::from_mode(0o755))
                .expect("chmod fake systemctl");
        }
        systemctl
    }

    #[test]
    fn a_scope_with_a_resolvable_cgroup_reads_back_its_enforcement() {
        // The overstating direction. A recorded unit whose ControlGroup
        // resolves and whose limit files exist must report the enforced tiers
        // and the values in effect, not silently down-grade to "declared".
        let state = tempfile::tempdir().expect("state dir");
        std::fs::write(state.path().join(SCOPE_UNIT_FILE), "mvm-resolved.scope")
            .expect("record a unit");

        let cgroup_root = state.path().join("cgroup");
        let control_group = "/user.slice/user-1000.slice/mvm-resolved.scope";
        let cgroup_dir = cgroup_root.join(control_group.trim_start_matches('/'));
        std::fs::create_dir_all(&cgroup_dir).expect("create cgroup dir");
        std::fs::write(cgroup_dir.join("cpu.max"), "150000 100000\n").expect("cpu.max");
        std::fs::write(cgroup_dir.join("memory.max"), "805306368\n").expect("memory.max");
        std::fs::write(cgroup_dir.join("pids.max"), "1024\n").expect("pids.max");

        let systemctl = fake_systemctl(
            state.path(),
            &format!("echo 'ControlGroup={control_group}'"),
        );
        let probe = ScopeProbe::with_root_and_systemctl(cgroup_root, systemctl);
        assert_eq!(
            probe.readback_for_vm(state.path()),
            ScopeReadback {
                cpu: EnforcedTier::Cgroup2CpuMax,
                memory: EnforcedCeiling::enforced(EnforcedTier::Cgroup2MemoryMax, 805_306_368),
                tasks: EnforcedCeiling::enforced(EnforcedTier::Cgroup2PidsMax, 1024),
            }
        );
    }

    #[test]
    fn a_scope_missing_one_control_file_declares_only_that_dimension() {
        // A scope created with no CPU quota has no `cpu.max` at all; that must
        // not drag the memory and task read-backs down with it.
        let state = tempfile::tempdir().expect("state dir");
        std::fs::write(state.path().join(SCOPE_UNIT_FILE), "mvm-partial.scope")
            .expect("record a unit");
        let cgroup_root = state.path().join("cgroup");
        let control_group = "/app.slice/mvm-partial.scope";
        let cgroup_dir = cgroup_root.join(control_group.trim_start_matches('/'));
        std::fs::create_dir_all(&cgroup_dir).expect("create cgroup dir");
        std::fs::write(cgroup_dir.join("memory.max"), "max\n").expect("memory.max");
        std::fs::write(cgroup_dir.join("pids.max"), "1024\n").expect("pids.max");
        let systemctl = fake_systemctl(
            state.path(),
            &format!("echo 'ControlGroup={control_group}'"),
        );
        let readback = ScopeProbe::with_root_and_systemctl(cgroup_root, systemctl)
            .readback_for_vm(state.path());
        assert_eq!(readback.cpu, EnforcedTier::Declared);
        assert_eq!(readback.memory, EnforcedCeiling::declared());
        assert_eq!(
            readback.tasks,
            EnforcedCeiling::enforced(EnforcedTier::Cgroup2PidsMax, 1024)
        );
    }

    #[test]
    fn a_hung_systemctl_reads_back_as_declared_instead_of_stalling() {
        let state = tempfile::tempdir().expect("state dir");
        let started = Instant::now();
        let out = run_bounded(
            {
                let mut cmd = Command::new(fake_systemctl(state.path(), "sleep 30"));
                cmd.arg("--user");
                cmd
            },
            Duration::from_millis(200),
        );
        assert_eq!(out, None);
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the query must be killed at its deadline, took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn an_oom_killed_scope_is_recognised_with_its_ceiling() {
        assert_eq!(
            parse_memory_limit_exceeded("Result=oom-kill\nMemoryMax=805306368\n"),
            Some(MemoryLimitExceeded {
                memory_max_bytes: Some(805_306_368)
            })
        );
        assert_eq!(
            parse_memory_limit_exceeded("MemoryMax=infinity\nResult=oom-kill\n"),
            Some(MemoryLimitExceeded {
                memory_max_bytes: None
            })
        );
    }

    #[test]
    fn a_scope_that_ended_any_other_way_is_not_a_memory_kill() {
        for show in [
            "Result=success\nMemoryMax=805306368\n",
            "Result=signal\nMemoryMax=805306368\n",
            "MemoryMax=805306368\n",
            "",
        ] {
            assert_eq!(parse_memory_limit_exceeded(show), None, "{show:?}");
        }
    }

    #[test]
    fn the_memory_kill_query_reads_the_recorded_unit() {
        let state = tempfile::tempdir().expect("state dir");
        std::fs::write(state.path().join(SCOPE_UNIT_FILE), "mvm-killed.scope")
            .expect("record a unit");
        let systemctl = fake_systemctl(
            state.path(),
            "[ \"$3\" = mvm-killed.scope ] || exit 1\nprintf 'Result=oom-kill\\nMemoryMax=4096\\n'",
        );
        let probe = ScopeProbe::with_root_and_systemctl(state.path().join("cgroup"), systemctl);
        assert_eq!(
            probe.memory_limit_exceeded(state.path()),
            Some(MemoryLimitExceeded {
                memory_max_bytes: Some(4096)
            })
        );
        let unrecorded = tempfile::tempdir().expect("no unit");
        assert_eq!(probe.memory_limit_exceeded(unrecorded.path()), None);
    }

    #[test]
    fn a_launcher_that_never_execs_times_out() {
        let outcome =
            watch_launcher(Duration::from_millis(30), || Ok(LauncherProbe::Launching)).unwrap();
        assert_eq!(outcome, LaunchWatch::TimedOut);
    }

    #[test]
    fn a_launcher_watch_ends_on_the_first_settled_probe() {
        let mut probes = vec![
            LauncherProbe::Execed,
            LauncherProbe::Launching,
            LauncherProbe::Launching,
        ];
        let outcome = watch_launcher(Duration::from_secs(5), || {
            Ok(probes.pop().expect("probed past the settled answer"))
        })
        .unwrap();
        assert_eq!(outcome, LaunchWatch::Execed);
        for (probe, expected) in [
            (LauncherProbe::Exited, LaunchWatch::Exited),
            (LauncherProbe::Unobservable, LaunchWatch::Unobservable),
        ] {
            assert_eq!(
                watch_launcher(Duration::from_secs(5), || Ok(probe)).unwrap(),
                expected
            );
        }
        assert!(
            watch_launcher(Duration::from_secs(5), || Err(std::io::Error::other(
                "boom"
            )))
            .is_err()
        );
    }

    #[test]
    fn a_launcher_is_classified_by_its_command_name() {
        let proc_root = tempfile::tempdir().expect("proc root");
        let no_proc = probe_launcher_comm(proc_root.path(), 42).unwrap();
        assert_eq!(no_proc, LauncherProbe::Unobservable);

        std::fs::create_dir_all(proc_root.path().join("self")).unwrap();
        std::fs::create_dir_all(proc_root.path().join("42")).unwrap();
        std::fs::write(proc_root.path().join("42/comm"), "systemd-run\n").unwrap();
        assert_eq!(
            probe_launcher_comm(proc_root.path(), 42).unwrap(),
            LauncherProbe::Launching
        );
        std::fs::write(proc_root.path().join("42/comm"), "sudo\n").unwrap();
        assert_eq!(
            probe_launcher_comm(proc_root.path(), 42).unwrap(),
            LauncherProbe::Execed
        );
        assert_eq!(
            probe_launcher_comm(proc_root.path(), 43).unwrap(),
            LauncherProbe::Exited
        );
    }

    #[test]
    fn a_launcher_that_execs_its_payload_spawns_normally() {
        let scratch = tempfile::tempdir().expect("scratch");
        let mut env = crate::util::test_env::TestEnv::new();
        pretend_mechanism_with_launcher(
            &mut env,
            scratch.path(),
            "#!/bin/sh\nwhile [ \"$1\" != -- ]; do shift; done\nshift\nexec \"$@\"\n",
        )
        .expect("fake launcher");
        let mut bound = bind_spawn(
            {
                let mut cmd = Command::new("/bin/sh");
                cmd.args(["-c", "exit 7"]);
                cmd
            },
            "mvm-abc123",
            scratch.path(),
            &SpawnBounds::for_guest_memory(64),
        );
        assert!(bound.unit().is_some());
        let status = bound
            .status()
            .expect("a launcher that execs is not refused");
        assert_eq!(status.code(), Some(7), "the payload ran as the launch");
    }

    /// The hung-manager case, with the manager replaced by a launcher that
    /// never gets past the point `systemd-run` blocks at. Linux-only because it
    /// needs a process table to watch; elsewhere there is no mechanism to hang.
    #[cfg(target_os = "linux")]
    #[test]
    fn an_unresponsive_manager_fails_the_launch_instead_of_hanging_it() {
        let scratch = tempfile::tempdir().expect("scratch");
        let mut env = crate::util::test_env::TestEnv::new();
        pretend_mechanism_with_launcher(
            &mut env,
            scratch.path(),
            "#!/bin/sh\nwhile true; do sleep 0.05; done\n",
        )
        .expect("fake launcher");
        let mut bound = bind_spawn(
            Command::new("/bin/true"),
            "mvm-abc123",
            scratch.path(),
            &SpawnBounds::for_guest_memory(64),
        )
        .with_creation_timeout(Duration::from_millis(300));
        let started = Instant::now();
        let err = bound
            .spawn()
            .expect_err("a scope that is never created must fail the launch");
        let message = format!("{err:#}");
        assert!(message.contains("did not create scope"), "{message}");
        assert!(message.contains("mvm-abc123"), "{message}");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the launch must fail at its deadline, took {:?}",
            started.elapsed()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_detached_launcher_past_its_deadline_is_killed_and_the_launch_fails() {
        let scratch = tempfile::tempdir().expect("scratch");
        let launcher = scratch.path().join(SYSTEMD_RUN);
        std::fs::write(&launcher, "#!/bin/sh\nwhile true; do sleep 0.05; done\n").unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&launcher, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let mut child = Command::new(&launcher).spawn().expect("spawn launcher");
        // Give exec a moment to set the command name before the first probe.
        std::thread::sleep(Duration::from_millis(50));
        let pid_file = scratch.path().join("launcher.pid");
        std::fs::write(&pid_file, child.id().to_string()).unwrap();

        let err =
            await_detached_launcher_within(&pid_file, "mvm-abc123", Duration::from_millis(200))
                .expect_err("a launcher that never execs fails the launch");
        assert!(format!("{err:#}").contains("did not create scope"));
        let status = child.wait().expect("reap the launcher");
        assert!(!status.success(), "the stuck launcher was killed");
    }

    #[test]
    fn a_missing_launcher_pid_is_an_error_not_a_silent_pass() {
        let scratch = tempfile::tempdir().expect("scratch");
        assert!(await_detached_launcher(&scratch.path().join("absent.pid"), "mvm-abc123").is_err());
    }

    /// The silence case, and the whole reason the reason-builder exists: a
    /// share was asked for, nothing bounded it, and the operator is told which
    /// half of the mechanism was missing.
    #[test]
    fn a_degraded_share_names_the_missing_mechanism() {
        let reason = cpu_degradation_reason(
            Some(&CpuGrant::Share { millicores: 1500 }),
            EnforcedTier::Declared,
            Some(MechanismGap::NoUserSessionBus),
        )
        .expect("an unenforced share must say so");
        assert!(reason.contains("1500"), "{reason}");
        assert!(reason.contains("NOT enforced"), "{reason}");
        assert!(
            reason.contains(MechanismGap::NoUserSessionBus.describe()),
            "the operator must be told which mechanism was missing: {reason}"
        );
    }

    #[test]
    fn a_degraded_share_without_systemd_run_names_that_gap_instead() {
        let reason = cpu_degradation_reason(
            Some(&CpuGrant::Share { millicores: 500 }),
            EnforcedTier::Declared,
            Some(MechanismGap::SystemdRunMissing),
        )
        .expect("an unenforced share must say so");
        assert!(reason.contains("systemd-run"), "{reason}");
    }

    /// A host with no gap at all still owes an explanation when the tier came
    /// back unenforced — the backend simply has no quota mechanism.
    #[test]
    fn an_unenforced_share_on_a_host_with_no_gap_still_warns() {
        let reason = cpu_degradation_reason(
            Some(&CpuGrant::Share { millicores: 250 }),
            EnforcedTier::Declared,
            None,
        )
        .expect("an unenforced share must say so");
        assert!(reason.contains("no CPU quota mechanism"), "{reason}");
    }

    #[test]
    fn an_enforced_share_says_nothing() {
        assert_eq!(
            cpu_degradation_reason(
                Some(&CpuGrant::Share { millicores: 1500 }),
                EnforcedTier::Cgroup2CpuMax,
                None,
            ),
            None
        );
    }

    #[test]
    fn a_run_that_asked_for_no_bound_says_nothing() {
        assert_eq!(
            cpu_degradation_reason(
                None,
                EnforcedTier::Declared,
                Some(MechanismGap::SystemdRunMissing)
            ),
            None
        );
    }

    /// Fuel is wasmtime's unit. A scope that cannot serve it is not degrading;
    /// warning here would train an operator to ignore the message.
    #[test]
    fn a_fuel_budget_is_not_a_scope_degradation() {
        assert_eq!(
            cpu_degradation_reason(
                Some(&CpuGrant::Fuel {
                    instructions: 1_000
                }),
                EnforcedTier::Declared,
                None,
            ),
            None
        );
    }

    #[test]
    fn a_missing_binary_is_not_on_path() {
        assert!(!binary_on_path("mvm-definitely-not-a-real-binary"));
    }
}
