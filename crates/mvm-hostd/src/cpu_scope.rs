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
//! Nothing here is `cfg`-gated to Linux. Every call first asks whether the
//! mechanism is present, and a host without `systemd-run` or without a user
//! session bus answers [`EnforcedTier::Declared`] — the same honest answer a
//! compile-time gate would produce, arrived at by one code path instead of two
//! that could disagree.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Result, bail};
use mvm_contract::protocol::resource_controls::EnforcedTier;

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

/// The transient unit name for a machine.
///
/// Call [`validate_scope_id`] first; this is a rendering, not a gate.
#[must_use]
pub fn scope_name(machine_id: &str) -> String {
    format!("{machine_id}.scope")
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

/// Wrap `cmd` so the process is *born* inside a CPU-bounded transient scope.
///
/// Returns a `systemd-run` invocation carrying the original program, arguments,
/// environment overrides, and working directory. Moving an already-running
/// process would leave an interval in which it is unbounded; this has none.
///
/// Call this before configuring stdio: `Command` exposes its program, argv,
/// env overrides and cwd for reading, but not its stdio handles, so redirection
/// set on the input is not carried across. Set stdio on the returned command.
///
/// Check [`mechanism_gap`] first. This renders the wrapper unconditionally; on
/// a host with no `systemd-run` or no session bus the wrapped spawn fails, and
/// a failed spawn is a failed boot — where degrading to an unwrapped spawn and
/// an honest [`EnforcedTier::Declared`] is what a dev run wants.
pub fn wrap_spawn(cmd: Command, machine_id: &str, millicores: u32) -> Result<Command> {
    validate_scope_id(machine_id)?;
    let percent = cpu_quota_percent(millicores)?;

    let mut wrapped = Command::new(SYSTEMD_RUN);
    wrapped.arg("--user");
    wrapped.arg("--scope");
    wrapped.arg("--quiet");
    wrapped.arg("--unit");
    wrapped.arg(scope_name(machine_id));
    wrapped.arg("-p");
    wrapped.arg(format!("CPUQuota={percent}%"));
    wrapped.arg("--");
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
    Ok(wrapped)
}

/// What actually bounds this machine's CPU right now, read off the live
/// control.
///
/// Resolves the scope's cgroup through `systemctl --user show <scope> -p
/// ControlGroup` and reads that cgroup's `cpu.max`. A tier derived from "the
/// spawn returned 0" would assert an enforcement that a silently-dropped quota
/// makes false, which is the overstatement this whole seam exists to prevent.
///
/// An absent mechanism, an absent scope, and a scope with no quota all answer
/// [`EnforcedTier::Declared`]. Only a malformed id is an error: degrading is
/// the honest report, not a reason to refuse a boot the admission gate already
/// decided to allow.
pub fn read_back_tier(machine_id: &str) -> Result<EnforcedTier> {
    validate_scope_id(machine_id)?;
    if let Some(gap) = mechanism_gap() {
        tracing::debug!("{}", gap.describe());
        return Ok(EnforcedTier::Declared);
    }
    let Some(control_group) = scope_control_group(&scope_name(machine_id)) else {
        return Ok(EnforcedTier::Declared);
    };
    let Ok(cpu_max) = std::fs::read_to_string(cgroup_file(&control_group, "cpu.max")) else {
        return Ok(EnforcedTier::Declared);
    };
    Ok(tier_from_cpu_max(&cpu_max))
}

/// The cgroup path systemd placed a scope in, or `None` when the unit does not
/// exist or no user manager answered.
fn scope_control_group(unit: &str) -> Option<String> {
    let output = Command::new(SYSTEMCTL)
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

/// A control file inside a cgroup, resolved against the unified hierarchy.
fn cgroup_file(control_group: &str, file: &str) -> PathBuf {
    Path::new(CGROUP_ROOT)
        .join(control_group.trim_start_matches('/'))
        .join(file)
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

/// Render a command as `program arg arg …` for assertions and logs.
#[cfg(test)]
fn rendered_argv(cmd: &Command) -> Vec<String> {
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
        let wrapped = wrap_spawn(inner, "mvm-abc123", 1500).expect("wraps");
        assert_eq!(
            rendered_argv(&wrapped),
            vec![
                "systemd-run",
                "--user",
                "--scope",
                "--quiet",
                "--unit",
                "mvm-abc123.scope",
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
        let wrapped = wrap_spawn(inner, "mvm-abc123", 1000).expect("wraps");

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
    fn wrapping_refuses_an_unusable_id_or_share_before_building_an_argv() {
        assert!(wrap_spawn(Command::new("/bin/true"), "../escape", 1500).is_err());
        assert!(wrap_spawn(Command::new("/bin/true"), "mvm-abc123", 0).is_err());
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
    fn a_cgroup_file_resolves_under_the_unified_hierarchy() {
        assert_eq!(
            cgroup_file("/user.slice/user-30033.slice/mvm-abc.scope", "cpu.max"),
            Path::new("/sys/fs/cgroup/user.slice/user-30033.slice/mvm-abc.scope/cpu.max")
        );
    }

    #[test]
    fn a_machine_with_no_scope_reads_back_as_declared_not_as_an_error() {
        // True on every host: with no mechanism the probe short-circuits, and
        // with one, no scope by this name was ever created. Either way a boot
        // must not fail because a bound is absent — the admission gate already
        // decided whether that was allowed.
        let tier = read_back_tier("mvm-cpu-scope-absent-fixture").expect("reads back");
        assert_eq!(tier, EnforcedTier::Declared);
    }

    #[test]
    fn reading_back_a_malformed_id_is_the_one_error() {
        assert!(read_back_tier("../escape").is_err());
    }

    #[test]
    fn a_missing_binary_is_not_on_path() {
        assert!(!binary_on_path("mvm-definitely-not-a-real-binary"));
    }
}
