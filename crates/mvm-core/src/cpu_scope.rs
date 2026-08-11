//! Per-VM CPU bounds, via a transient systemd scope on the user's own manager.
//!
//! The obvious mechanism — `mkdir` a cgroup v2 leaf under the delegated
//! `user@<uid>.service` subtree and write the VMM's pid into `cgroup.procs` —
//! creates the leaf and accepts the `cpu.max` write, and then refuses the one
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
//! there is no interval in which the workload runs uncapped — which is exactly
//! the interval a workload built to burn CPU would use.
//!
//! Shelling out to `systemd-run` rather than speaking `StartTransientUnit` over
//! D-Bus directly keeps the dependency budget where this project wants it; the
//! placement, and the delegation it depends on, are identical either way.
//!
//! # The rejected alternative: adopting an already-running process
//!
//! A scope can also be created *around* a process that is already running —
//! `StartTransientUnit` with a `PIDs` property. This was measured working, not
//! guessed at: a pid living in a login session's own scope was moved into the
//! delegated tree and the quota applied. It is tempting because it needs no
//! grant threaded onto the launch config — a caller can bound a VM it has
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

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Result, bail};
use mvm_contract::grants::CpuGrant;
use mvm_contract::protocol::resource_controls::{EnforcedGrants, EnforcedTier};

/// systemd expresses a CPU quota as a percentage of one core, so one percent is
/// ten millicores.
const MILLICORES_PER_PERCENT: u32 = 10;

/// A systemd unit name is capped at 255 bytes including its type suffix. The
/// margin is not tuning: it leaves room for the suffix and keeps a rejected id
/// a validation error here rather than an opaque refusal from systemd.
const MAX_SCOPE_ID_LEN: usize = 200;

/// The unified cgroup hierarchy's mount point. A kernel/systemd ABI location on
/// every unified host, not a configurable path.
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

const SYSTEMD_RUN: &str = "systemd-run";
const SYSTEMCTL: &str = "systemctl";

/// Why this host cannot bound CPU through a transient scope.
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
                "systemd-run is not on PATH, so no CPU quota can be attached to this VM"
            }
            Self::NoUserSessionBus => {
                "no user session bus (XDG_RUNTIME_DIR / DBUS_SESSION_BUS_ADDRESS); \
                 cgroup delegation hangs off a systemd user session, so a CPU quota \
                 cannot be attached — run under a login session, or enable lingering \
                 for this user"
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

/// A scope id may contain only characters that cannot change the meaning of a
/// unit name or a cgroup path. The machine id is validated upstream; this is
/// the second gate, and the only source a scope name is ever built from.
pub fn validate_scope_id(id: &str) -> Result<()> {
    if id.is_empty() {
        bail!("a CPU scope id must not be empty");
    }
    if id.len() > MAX_SCOPE_ID_LEN {
        bail!(
            "CPU scope id is {len} bytes; systemd unit names are capped, so ids over \
             {MAX_SCOPE_ID_LEN} are refused",
            len = id.len()
        );
    }
    if id.starts_with('-') {
        // A leading dash reaches `systemd-run` as something that reads like an
        // option rather than a unit name.
        bail!("CPU scope id {id:?} must not start with '-'");
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        bail!("CPU scope id {id:?} contains characters that are not path-safe");
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
const SCOPE_UNIT_FILE: &str = "cpu-scope";

/// A scope id for one boot: the machine id plus a per-boot suffix.
///
/// Unique rather than fixed because `systemd-run --unit` refuses a name that is
/// already taken, and a scope outlives the process that created it for as long
/// as anything remains in its cgroup. With a fixed name, one leftover VMM from
/// an unclean stop would make every subsequent boot of that machine fail —
/// turning a CPU bound into a liveness bug, on a path that is supposed to
/// degrade rather than refuse.
///
/// Resetting the stale unit instead was considered and rejected: a leftover
/// scope is only *active* because a process is still in it, so clearing it means
/// killing whatever that is. The drivers deliberately refuse to displace a live
/// VM, and a CPU-quota helper is the wrong place to overrule them.
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

/// The `systemd-run` tokens that precede a payload's own argv, ending in the
/// `--` separator.
///
/// The single place these flags are spelled. Two kinds of spawn site consume
/// them — one building a [`Command`], one building a shell string for a spawn
/// that daemonizes — and a second copy of this list is how the two would
/// silently drift into bounding different things.
fn scope_prefix(scope_id: &str, percent: u32) -> Vec<String> {
    vec![
        SYSTEMD_RUN.to_string(),
        "--user".to_string(),
        "--scope".to_string(),
        "--quiet".to_string(),
        "--unit".to_string(),
        scope_name(scope_id),
        "-p".to_string(),
        format!("CPUQuota={percent}%"),
        "--".to_string(),
    ]
}

/// The scope prefix for this boot, or `None` when nothing is to be bound.
///
/// For spawn sites that build a command line as *text* rather than a
/// [`Command`] — the caller quotes each token into its own shell. Same ladder,
/// same per-boot unit, same recorded name as [`bind_cpu_grant`]; only the
/// rendering differs.
#[must_use]
pub fn scope_prefix_for_grant(
    machine_id: &str,
    state_dir: &Path,
    grant: Option<&CpuGrant>,
) -> Option<Vec<String>> {
    let (scope_id, percent) = prepare_scope(machine_id, state_dir, grant)?;
    Some(scope_prefix(&scope_id, percent))
}

/// Decide whether to bind, mint this boot's unit name, and record it.
///
/// One ladder, so the `Command` and shell-string paths cannot disagree about
/// which grants get bound or about what the scope is called.
fn prepare_scope(
    machine_id: &str,
    state_dir: &Path,
    grant: Option<&CpuGrant>,
) -> Option<(String, u32)> {
    let percent = bindable_quota_percent(machine_id, grant)?;
    let scope_id = boot_scope_id(machine_id);
    // A recorded name is what makes the tier readable afterwards. If it cannot
    // be written the bound still applies — the workload is bounded either way —
    // and only the report suffers, which then *understates* what is in effect.
    // Understating is the safe direction; dropping a working bound to keep the
    // bookkeeping tidy is not.
    if let Err(e) = std::fs::write(state_dir.join(SCOPE_UNIT_FILE), scope_name(&scope_id)) {
        tracing::warn!(
            "CPU scope for '{machine_id}' is in effect but its name could not be recorded in \
             {}: {e} — the achieved tier will read back as declared",
            state_dir.display()
        );
    }
    Some((scope_id, percent))
}

/// The quota percent to bind, or `None` with the reason logged.
fn bindable_quota_percent(machine_id: &str, grant: Option<&CpuGrant>) -> Option<u32> {
    let Some(CpuGrant::Share { millicores }) = grant else {
        // No grant, or a fuel budget — which is wasmtime's unit, not this
        // mechanism's, so it passes through rather than being converted into a
        // share nobody granted.
        return None;
    };
    if let Some(gap) = mechanism_gap() {
        tracing::info!(
            "CPU share of {millicores} millicores for '{machine_id}' will not be enforced: {}",
            gap.describe()
        );
        return None;
    }
    if let Err(e) = validate_scope_id(machine_id) {
        tracing::warn!("CPU share for '{machine_id}' not applied: {e}");
        return None;
    }
    match cpu_quota_percent(*millicores) {
        Ok(percent) => Some(percent),
        Err(e) => {
            tracing::warn!("CPU share for '{machine_id}' not applied: {e}");
            None
        }
    }
}

/// The rendering half of the wrap, after the decision has been made.
///
/// Split out because `Command` is not `Clone`: a fallible wrap consumes its
/// input, so a caller that wants the original back on refusal has to do the
/// checking before handing it over. [`bind_cpu_grant`] is that caller.
fn wrap_checked(cmd: Command, scope_id: &str, percent: u32) -> Command {
    let prefix = scope_prefix(scope_id, percent);
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

/// The one seam every per-VM spawn goes through: bound the process this command
/// is about to become, if a share was granted and this host can serve it.
///
/// Infallible by design. A CPU bound that cannot be attached must not take down
/// a boot the admission gate already allowed. Every refusal path returns the
/// original command unwrapped and says why, and [`enforced_grants_for_vm`] then
/// reads the live control back and reports [`EnforcedTier::Declared`], so a
/// degraded boot cannot be mistaken for a bounded one.
///
/// The admission gate refuses an unenforceable grant under `--prod` before
/// anything is spawned, and since it consults this host's own
/// [`mechanism_gap`], a sealed run does not reach here with a share it cannot
/// serve. Dev runs do, and degrade.
///
/// [`CpuGrant::Fuel`] is not this mechanism's unit — an instruction budget is
/// wasmtime's to enforce — so it passes through untouched rather than being
/// converted into a share it is not.
#[must_use]
pub fn bind_cpu_grant(
    cmd: Command,
    machine_id: &str,
    state_dir: &Path,
    grant: Option<&CpuGrant>,
) -> Command {
    match prepare_scope(machine_id, state_dir, grant) {
        Some((scope_id, percent)) => wrap_checked(cmd, &scope_id, percent),
        None => cmd,
    }
}

/// What actually bounded this VM, read off the live control.
///
/// The one function a backend's `apply_grants` calls. Resolves the scope this
/// VM's process was born into, asks systemd where it put it, and reads that
/// cgroup's `cpu.max`. A tier derived from "the spawn returned 0" would assert
/// an enforcement that a silently-dropped quota makes false, which is the
/// overstatement this whole seam exists to prevent.
///
/// Wall clock is [`EnforcedTier::Declared`] because nothing here bounds it. It
/// is reported rather than omitted so a receipt says which dimensions were
/// measured and found unenforced, instead of leaving a reader to guess.
#[must_use]
pub fn enforced_grants_for_vm(state_dir: &Path) -> EnforcedGrants {
    EnforcedGrants {
        cpu: ScopeProbe::default().tier_for_vm(state_dir),
        wall_clock: EnforcedTier::Declared,
    }
}

/// Reads a live scope's CPU tier off the system.
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

    /// The tier in effect for the VM whose state lives in `state_dir`.
    ///
    /// A VM with no recorded scope was never bound, so it is a declaration.
    #[must_use]
    pub fn tier_for_vm(&self, state_dir: &Path) -> EnforcedTier {
        match read_scope_unit(state_dir) {
            Some(unit) => self.tier_for_unit(&unit),
            None => EnforcedTier::Declared,
        }
    }

    /// The tier a named scope unit is enforcing.
    ///
    /// An absent mechanism, an absent unit, an unreadable cgroup and a scope
    /// carrying no quota all answer [`EnforcedTier::Declared`]. There is no
    /// error case: the boot already happened, and the only question left is
    /// what is true about it.
    #[must_use]
    pub fn tier_for_unit(&self, unit: &str) -> EnforcedTier {
        let Some(control_group) = self.control_group(unit) else {
            return EnforcedTier::Declared;
        };
        let Ok(cpu_max) = std::fs::read_to_string(self.cgroup_file(&control_group, "cpu.max"))
        else {
            return EnforcedTier::Declared;
        };
        tier_from_cpu_max(&cpu_max)
    }

    /// The cgroup path systemd placed a scope in, or `None` when the unit does
    /// not exist or no user manager answered.
    fn control_group(&self, unit: &str) -> Option<String> {
        let output = Command::new(&self.systemctl)
            .args(["--user", "show", unit, "-p", "ControlGroup", "--value"])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
        // A unit that does not exist is not an error to `systemctl show`; it
        // reports the property's default, which for `ControlGroup` is empty.
        if value.is_empty() {
            return None;
        }
        Some(value)
    }

    /// A control file inside a cgroup, resolved against the hierarchy root.
    fn cgroup_file(&self, control_group: &str, file: &str) -> PathBuf {
        self.cgroup_root
            .join(control_group.trim_start_matches('/'))
            .join(file)
    }
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
    let bin_dir = scratch.join("bin");
    let run_dir = scratch.join("run");
    std::fs::create_dir_all(&bin_dir)?;
    std::fs::create_dir_all(&run_dir)?;
    let fake = bin_dir.join(SYSTEMD_RUN);
    std::fs::write(&fake, "#!/bin/sh\nexit 0\n")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755))?;
    }
    std::fs::write(run_dir.join("bus"), b"")?;
    env.set("PATH", &bin_dir);
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
    fn wrapping_a_spawn_puts_the_quota_ahead_of_the_payload() {
        let mut inner = Command::new("/usr/bin/mvm-libkrun-supervisor");
        inner.arg("--config").arg("-");
        // The scope id is supplied rather than derived: `boot_scope_id` mixes in
        // the clock and the pid, so an exact-argv assertion can only be written
        // against a fixed id. What is under test here is the *shape* — the quota
        // reaching systemd ahead of the payload — not how the id is minted.
        let wrapped = wrap_checked(inner, "mvm-abc123-1f2e3d-2a", 150);
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
        let wrapped = wrap_checked(inner, "mvm-abc123-1f2e3d-2a", 100);

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
    fn an_unusable_id_or_share_yields_no_quota_to_bind() {
        // Validation moved off the wrapper and into the decision of whether to
        // wrap at all: `bindable_quota_percent` returning `None` is what makes
        // `bind_cpu_grant` infallible without ever emitting a bad argv.
        assert!(
            bindable_quota_percent("../escape", Some(&CpuGrant::Share { millicores: 1500 }))
                .is_none()
        );
        assert!(
            bindable_quota_percent("mvm-abc123", Some(&CpuGrant::Share { millicores: 0 }))
                .is_none()
        );
    }

    #[test]
    fn binding_no_grant_leaves_the_spawn_exactly_as_it_was() {
        let dir = tempfile::tempdir().expect("tempdir");
        let wrapped = bind_cpu_grant(Command::new("/bin/true"), "mvm-abc123", dir.path(), None);
        assert_eq!(rendered_argv(&wrapped), vec!["/bin/true"]);
    }

    #[test]
    fn binding_a_fuel_grant_leaves_the_spawn_alone() {
        // An instruction budget is wasmtime's unit. Converting it into a share
        // would invent a number nobody granted.
        let dir = tempfile::tempdir().expect("tempdir");
        let wrapped = bind_cpu_grant(
            Command::new("/bin/true"),
            "mvm-abc123",
            dir.path(),
            Some(&CpuGrant::Fuel {
                instructions: 1_000_000,
            }),
        );
        assert_eq!(rendered_argv(&wrapped), vec!["/bin/true"]);
    }

    #[test]
    fn binding_an_unusable_share_degrades_instead_of_failing_the_spawn() {
        // The boot was already admitted; a bound that cannot be attached must
        // not turn into a refusal here. The read-back is what keeps it honest.
        let dir = tempfile::tempdir().expect("tempdir");
        let wrapped = bind_cpu_grant(
            Command::new("/bin/true"),
            "../escape",
            dir.path(),
            Some(&CpuGrant::Share { millicores: 1500 }),
        );
        assert_eq!(rendered_argv(&wrapped), vec!["/bin/true"]);

        let wrapped = bind_cpu_grant(
            Command::new("/bin/true"),
            "mvm-abc123",
            dir.path(),
            Some(&CpuGrant::Share { millicores: 0 }),
        );
        assert_eq!(rendered_argv(&wrapped), vec!["/bin/true"]);
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

        let wrapped = bind_cpu_grant(
            Command::new("/usr/bin/mvm-libkrun-supervisor"),
            "mvm-abc123",
            scratch.path(),
            Some(&CpuGrant::Share { millicores: 1500 }),
        );
        let argv = rendered_argv(&wrapped);

        // The unit name carries a per-boot suffix, so it is matched by shape
        // rather than by value; everything around it is still pinned exactly.
        let unit = &argv[5];
        assert!(
            unit.starts_with("mvm-abc123-") && unit.ends_with(".scope"),
            "unit name should be the machine id plus a per-boot suffix, got {unit}"
        );
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
                "--",
                "/usr/bin/mvm-libkrun-supervisor",
            ]
        );

        // The name is only useful if it was recorded — that file is what makes
        // the tier readable afterwards.
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

        let grant = CpuGrant::Share { millicores: 1500 };
        let prefix = scope_prefix_for_grant("mvm-abc123", scratch.path(), Some(&grant))
            .expect("a bindable grant");
        let wrapped = bind_cpu_grant(
            Command::new("/bin/payload"),
            "mvm-abc123",
            scratch.path(),
            Some(&grant),
        );

        // Each call mints its own per-boot unit, so the names differ by design.
        // Blank that one token out; every other flag must match, because a
        // disagreement there means one backend is bounding something the other
        // is not.
        let blank_unit = |mut argv: Vec<String>| {
            if let Some(i) = argv.iter().position(|a| a == "--unit") {
                argv[i + 1] = "<unit>".to_string();
            }
            argv
        };
        let mut expected = blank_unit(prefix);
        expected.push("/bin/payload".to_string());
        assert_eq!(blank_unit(rendered_argv(&wrapped)), expected);
    }

    #[test]
    fn the_shell_prefix_is_absent_when_there_is_nothing_to_bind() {
        let scratch = tempfile::tempdir().expect("scratch");
        assert_eq!(
            scope_prefix_for_grant("mvm-abc123", scratch.path(), None),
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
            ScopeProbe::default().tier_for_vm(state.path()),
            EnforcedTier::Declared
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
        assert_eq!(probe.tier_for_vm(state.path()), EnforcedTier::Declared);
    }

    #[test]
    fn a_missing_binary_is_not_on_path() {
        assert!(!binary_on_path("mvm-definitely-not-a-real-binary"));
    }
}
