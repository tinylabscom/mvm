//! Process-wide policy for cold source builds on the launch path.
//!
//! A launch whose caches are cold has to build part of what it boots from
//! local sources — the guest runtime, host helpers, the initramfs and, with an
//! images checkout selected, the pair images — and on a cold cache that can
//! take tens of minutes. `machine run` therefore runs under
//! [`ColdBuildPolicy::Announce`]: it builds what it needs, and the first cold
//! build in the process is preceded by one notice saying so. Scripts, CI and
//! perf gates that would rather fail than build opt into
//! [`ColdBuildPolicy::Refuse`] with `machine run --no-build` or
//! `MVM_COLD_BUILD=refuse`. Every other caller — other verbs, library
//! embedders, tests — keeps the [`ColdBuildPolicy::Allow`] default. Downloads
//! of published artifacts are never gated; the policy covers source and pair
//! builds only.

use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

/// Environment override consulted when a launch process settles its policy.
pub const COLD_BUILD_ENV: &str = "MVM_COLD_BUILD";

/// Whether, and how, cold source and pair builds may start in this process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColdBuildPolicy {
    /// Builds start when needed, with only their own status lines.
    Allow,
    /// Builds start when needed; the first one prints a first-run notice.
    Announce,
    /// A launch that would have to build fails with an actionable error.
    Refuse(RefusalSource),
}

/// How a run opted into refusing cold builds, so the refusal can say how to
/// undo it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalSource {
    /// `machine run --no-build`.
    NoBuildFlag,
    /// `MVM_COLD_BUILD=refuse`.
    Env,
}

/// The cold-build flag a launch was given on its command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BuildFlag {
    /// Neither flag: the environment, then the announced default, decide.
    #[default]
    Unset,
    /// `--build`: build without the notice, whatever the environment says.
    Build,
    /// `--no-build`: refuse, whatever the environment says.
    NoBuild,
}

/// What a choke point does with one cold artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ColdBuildAdmission {
    /// Build it.
    Build,
    /// Build it, after showing this notice to the user.
    Announce(String),
    /// Do not build it; fail with this message.
    Refuse(String),
}

/// The policy and the once-per-process notice state behind it. One static
/// instance serves the process; tests build their own.
#[derive(Debug)]
pub struct ColdBuildGate {
    policy: AtomicU8,
    announced: AtomicBool,
}

const ALLOW_TAG: u8 = 0;
const ANNOUNCE_TAG: u8 = 1;
const REFUSE_FLAG_TAG: u8 = 2;
const REFUSE_ENV_TAG: u8 = 3;

impl ColdBuildGate {
    /// A gate under the [`ColdBuildPolicy::Allow`] default.
    pub const fn new() -> Self {
        Self {
            policy: AtomicU8::new(ALLOW_TAG),
            announced: AtomicBool::new(false),
        }
    }

    pub fn set_policy(&self, policy: ColdBuildPolicy) {
        self.policy.store(tag(policy), Ordering::Relaxed);
    }

    pub fn policy(&self) -> ColdBuildPolicy {
        match self.policy.load(Ordering::Relaxed) {
            ANNOUNCE_TAG => ColdBuildPolicy::Announce,
            REFUSE_FLAG_TAG => ColdBuildPolicy::Refuse(RefusalSource::NoBuildFlag),
            REFUSE_ENV_TAG => ColdBuildPolicy::Refuse(RefusalSource::Env),
            _ => ColdBuildPolicy::Allow,
        }
    }

    /// Decide whether a cold build of `artifact` may start. Under
    /// [`ColdBuildPolicy::Announce`] only the first call carries the notice;
    /// later cold builds in the same process rely on their own status lines.
    pub fn admit(&self, artifact: &str) -> ColdBuildAdmission {
        match self.policy() {
            ColdBuildPolicy::Allow => ColdBuildAdmission::Build,
            ColdBuildPolicy::Announce if self.announced.swap(true, Ordering::Relaxed) => {
                ColdBuildAdmission::Build
            }
            ColdBuildPolicy::Announce => ColdBuildAdmission::Announce(first_run_notice(artifact)),
            ColdBuildPolicy::Refuse(source) => {
                ColdBuildAdmission::Refuse(refusal_message(artifact, source))
            }
        }
    }
}

impl Default for ColdBuildGate {
    fn default() -> Self {
        Self::new()
    }
}

static GATE: ColdBuildGate = ColdBuildGate::new();

/// Set the process-wide policy. Short-lived CLI processes set it once at
/// dispatch; library callers should leave the `Allow` default alone.
pub fn set_policy(policy: ColdBuildPolicy) {
    GATE.set_policy(policy);
}

/// The current process policy.
pub fn policy() -> ColdBuildPolicy {
    GATE.policy()
}

/// [`ColdBuildGate::admit`] on the process gate. Launch-path choke points
/// call this before starting a source or pair build.
pub fn admit(artifact: &str) -> ColdBuildAdmission {
    GATE.admit(artifact)
}

/// The policy a `machine run` process should run under, from its command-line
/// flag and `MVM_COLD_BUILD`.
pub fn launch_policy(flag: BuildFlag) -> ColdBuildPolicy {
    let env_value = std::env::var(COLD_BUILD_ENV).ok();
    if let Some(value) = env_value.as_deref()
        && EnvSetting::parse(value).is_none()
    {
        tracing::warn!(
            "{COLD_BUILD_ENV}={value:?} is not recognised (expected `auto` or `refuse`); \
             using the default"
        );
    }
    decide(flag, env_value.as_deref())
}

/// The values `MVM_COLD_BUILD` accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EnvSetting {
    Auto,
    Refuse,
}

impl EnvSetting {
    fn parse(value: &str) -> Option<Self> {
        let value = value.trim();
        if value.eq_ignore_ascii_case("auto") {
            Some(Self::Auto)
        } else if value.eq_ignore_ascii_case("refuse") {
            Some(Self::Refuse)
        } else {
            None
        }
    }
}

fn decide(flag: BuildFlag, env_value: Option<&str>) -> ColdBuildPolicy {
    match flag {
        BuildFlag::Build => ColdBuildPolicy::Allow,
        BuildFlag::NoBuild => ColdBuildPolicy::Refuse(RefusalSource::NoBuildFlag),
        BuildFlag::Unset => match env_value.and_then(EnvSetting::parse) {
            Some(EnvSetting::Auto) => ColdBuildPolicy::Allow,
            Some(EnvSetting::Refuse) => ColdBuildPolicy::Refuse(RefusalSource::Env),
            None => ColdBuildPolicy::Announce,
        },
    }
}

fn first_run_notice(artifact: &str) -> String {
    format!(
        "First run from this checkout (or its sources changed): building {artifact} locally. \
         On a cold cache this can take tens of minutes; later runs reuse what it builds. \
         Optional: `mvmctl bootstrap` prewarms this ahead of time."
    )
}

fn refusal_message(artifact: &str, source: RefusalSource) -> String {
    let (opted_in, to_build) = match source {
        RefusalSource::NoBuildFlag => ("`--no-build`", "rerun without `--no-build`".to_string()),
        RefusalSource::Env => (
            "`MVM_COLD_BUILD=refuse`",
            format!("unset `{COLD_BUILD_ENV}` (or set it to `auto`)"),
        ),
    };
    format!(
        "cold caches: {artifact} would have to be built from this checkout, and {opted_in} \
         refuses cold builds.\nTo build it now, {to_build}; or run `mvmctl bootstrap` to \
         prewarm the environment."
    )
}

fn tag(policy: ColdBuildPolicy) -> u8 {
    match policy {
        ColdBuildPolicy::Allow => ALLOW_TAG,
        ColdBuildPolicy::Announce => ANNOUNCE_TAG,
        ColdBuildPolicy::Refuse(RefusalSource::NoBuildFlag) => REFUSE_FLAG_TAG,
        ColdBuildPolicy::Refuse(RefusalSource::Env) => REFUSE_ENV_TAG,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gate(policy: ColdBuildPolicy) -> ColdBuildGate {
        let gate = ColdBuildGate::new();
        gate.set_policy(policy);
        gate
    }

    #[test]
    fn a_fresh_gate_allows_builds_without_a_notice() {
        let gate = ColdBuildGate::new();
        assert_eq!(gate.policy(), ColdBuildPolicy::Allow);
        assert_eq!(gate.admit("anything"), ColdBuildAdmission::Build);
        assert_eq!(gate.admit("anything else"), ColdBuildAdmission::Build);
    }

    #[test]
    fn announce_builds_and_notices_exactly_once_across_cold_artifacts() {
        let gate = gate(ColdBuildPolicy::Announce);
        let ColdBuildAdmission::Announce(notice) = gate.admit("the OCI guest runtime") else {
            panic!("the first cold build under Announce must carry the notice");
        };
        assert!(notice.contains("First run from this checkout"));
        assert!(notice.contains("the OCI guest runtime"));
        assert!(notice.contains("tens of minutes"));
        assert!(notice.contains("later runs reuse"));
        assert!(notice.contains("Optional: `mvmctl bootstrap`"));
        assert_eq!(
            gate.admit("the universal initramfs"),
            ColdBuildAdmission::Build
        );
        assert_eq!(
            gate.admit("the runtime-overlay.default image"),
            ColdBuildAdmission::Build
        );
    }

    #[test]
    fn the_notice_does_not_ask_for_a_second_command() {
        let notice = first_run_notice("the OCI guest runtime");
        assert!(!notice.contains("--build"));
        assert!(!notice.contains("Run `mvmctl bootstrap`"));
    }

    #[test]
    fn refusal_under_the_flag_names_the_flag_and_how_to_build() {
        let gate = gate(ColdBuildPolicy::Refuse(RefusalSource::NoBuildFlag));
        let ColdBuildAdmission::Refuse(message) = gate.admit("the universal initramfs") else {
            panic!("Refuse must refuse");
        };
        assert!(message.contains("the universal initramfs"));
        assert!(message.contains("`--no-build` refuses cold builds"));
        assert!(message.contains("rerun without `--no-build`"));
        assert!(message.contains("mvmctl bootstrap"));
    }

    #[test]
    fn refusal_under_the_env_names_the_variable_and_how_to_build() {
        let gate = gate(ColdBuildPolicy::Refuse(RefusalSource::Env));
        let ColdBuildAdmission::Refuse(message) = gate.admit("the OCI guest runtime") else {
            panic!("Refuse must refuse");
        };
        assert!(message.contains("the OCI guest runtime"));
        assert!(message.contains("`MVM_COLD_BUILD=refuse` refuses cold builds"));
        assert!(message.contains("unset `MVM_COLD_BUILD` (or set it to `auto`)"));
        assert!(message.contains("mvmctl bootstrap"));
    }

    #[test]
    fn refusal_repeats_for_every_artifact_and_never_notices() {
        let gate = gate(ColdBuildPolicy::Refuse(RefusalSource::Env));
        for artifact in ["a", "b"] {
            assert!(matches!(
                gate.admit(artifact),
                ColdBuildAdmission::Refuse(_)
            ));
        }
    }

    #[test]
    fn set_policy_roundtrips_every_variant() {
        let gate = ColdBuildGate::new();
        for policy in [
            ColdBuildPolicy::Announce,
            ColdBuildPolicy::Refuse(RefusalSource::NoBuildFlag),
            ColdBuildPolicy::Refuse(RefusalSource::Env),
            ColdBuildPolicy::Allow,
        ] {
            gate.set_policy(policy);
            assert_eq!(gate.policy(), policy);
        }
    }

    #[test]
    fn the_launch_default_announces() {
        assert_eq!(decide(BuildFlag::Unset, None), ColdBuildPolicy::Announce);
        assert_eq!(
            decide(BuildFlag::Unset, Some("something-else")),
            ColdBuildPolicy::Announce
        );
        assert_eq!(
            decide(BuildFlag::Unset, Some("")),
            ColdBuildPolicy::Announce
        );
    }

    #[test]
    fn the_env_opts_into_refusal_or_unannounced_builds() {
        assert_eq!(
            decide(BuildFlag::Unset, Some("refuse")),
            ColdBuildPolicy::Refuse(RefusalSource::Env)
        );
        assert_eq!(
            decide(BuildFlag::Unset, Some(" Refuse ")),
            ColdBuildPolicy::Refuse(RefusalSource::Env)
        );
        assert_eq!(
            decide(BuildFlag::Unset, Some("auto")),
            ColdBuildPolicy::Allow
        );
        assert_eq!(
            decide(BuildFlag::Unset, Some(" AUTO ")),
            ColdBuildPolicy::Allow
        );
    }

    #[test]
    fn the_flags_win_over_the_env() {
        assert_eq!(decide(BuildFlag::Build, None), ColdBuildPolicy::Allow);
        assert_eq!(
            decide(BuildFlag::Build, Some("refuse")),
            ColdBuildPolicy::Allow
        );
        assert_eq!(
            decide(BuildFlag::NoBuild, None),
            ColdBuildPolicy::Refuse(RefusalSource::NoBuildFlag)
        );
        assert_eq!(
            decide(BuildFlag::NoBuild, Some("auto")),
            ColdBuildPolicy::Refuse(RefusalSource::NoBuildFlag)
        );
    }

    #[test]
    fn the_process_gate_keeps_the_allow_default() {
        // Nothing in this crate's tests sets the process policy, so the
        // static gate shows what an embedder that never calls `set_policy`
        // gets.
        assert_eq!(policy(), ColdBuildPolicy::Allow);
        assert_eq!(admit("anything"), ColdBuildAdmission::Build);
    }
}
