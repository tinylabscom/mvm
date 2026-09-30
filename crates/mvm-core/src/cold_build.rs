//! Process-wide policy for cold source builds on the launch path.
//!
//! A launch whose caches are cold can otherwise escalate, silently and one
//! phase at a time, into minute-scale source builds. `machine run` refuses
//! that escalation by default: it sets [`ColdBuildPolicy::Refuse`] before
//! launching, so the first cold artifact fails fast with a pointer to
//! `mvmctl bootstrap` instead of building for tens of minutes. Every other
//! caller — other verbs, library embedders, tests — keeps the
//! [`ColdBuildPolicy::Allow`] default. `MVM_COLD_BUILD=auto` restores
//! `Allow` inside a refusing process, and `machine run --build` opts the
//! run in explicitly. Downloads of published artifacts are never refused;
//! the policy gates source and pair builds only.

use std::sync::atomic::{AtomicU8, Ordering};

/// Environment override consulted when a launch process settles its policy.
pub const COLD_BUILD_ENV: &str = "MVM_COLD_BUILD";

/// Whether cold source and pair builds may start in this process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColdBuildPolicy {
    /// Builds start when needed, announced, as they always have.
    Allow,
    /// A launch that would have to build fails with an actionable error.
    Refuse,
}

const ALLOW_TAG: u8 = 0;
const REFUSE_TAG: u8 = 1;

static POLICY: AtomicU8 = AtomicU8::new(ALLOW_TAG);

/// Set the process-wide policy. Short-lived CLI processes set it once at
/// dispatch; library callers should leave the `Allow` default alone.
pub fn set_policy(policy: ColdBuildPolicy) {
    POLICY.store(tag(policy), Ordering::Relaxed);
}

/// The current process policy.
pub fn policy() -> ColdBuildPolicy {
    match POLICY.load(Ordering::Relaxed) {
        REFUSE_TAG => ColdBuildPolicy::Refuse,
        _ => ColdBuildPolicy::Allow,
    }
}

/// The policy a fresh launch process should run under: refuse unless the
/// caller opted in with `--build` or `MVM_COLD_BUILD=auto`.
pub fn launch_policy(explicit_build: bool) -> ColdBuildPolicy {
    decide(
        explicit_build,
        std::env::var(COLD_BUILD_ENV).ok().as_deref(),
    )
}

fn decide(explicit_build: bool, env_value: Option<&str>) -> ColdBuildPolicy {
    if explicit_build || env_value.is_some_and(|value| value.trim() == "auto") {
        ColdBuildPolicy::Allow
    } else {
        ColdBuildPolicy::Refuse
    }
}

/// `Some(message)` when the current policy refuses a cold build of
/// `artifact`; the message names the artifact and both ways forward. Launch
/// path choke points consult this before starting a source or pair build.
pub fn refusal(artifact: &str) -> Option<String> {
    match policy() {
        ColdBuildPolicy::Allow => None,
        ColdBuildPolicy::Refuse => Some(format!(
            "cold caches: {artifact} would have to be built from this checkout, and this run \
             refuses cold builds.\nRun `mvmctl bootstrap` to prewarm the environment, or rerun \
             with `--build` (or set `{COLD_BUILD_ENV}=auto`) to build it now."
        )),
    }
}

fn tag(policy: ColdBuildPolicy) -> u8 {
    match policy {
        ColdBuildPolicy::Allow => ALLOW_TAG,
        ColdBuildPolicy::Refuse => REFUSE_TAG,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The policy is process-global, so the tests that mutate it serialize on
    // one lock and always restore the Allow default they found.
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn default_policy_allows_builds() {
        let _guard = LOCK.lock().unwrap();
        set_policy(ColdBuildPolicy::Allow);
        assert_eq!(policy(), ColdBuildPolicy::Allow);
        assert!(refusal("anything").is_none());
    }

    #[test]
    fn refusal_names_the_artifact_and_both_ways_forward() {
        let _guard = LOCK.lock().unwrap();
        set_policy(ColdBuildPolicy::Refuse);
        let message = refusal("the universal initramfs").expect("refusal under Refuse");
        assert!(message.contains("the universal initramfs"));
        assert!(message.contains("mvmctl bootstrap"));
        assert!(message.contains("--build"));
        assert!(message.contains(COLD_BUILD_ENV));
        set_policy(ColdBuildPolicy::Allow);
    }

    #[test]
    fn set_policy_roundtrips() {
        let _guard = LOCK.lock().unwrap();
        set_policy(ColdBuildPolicy::Refuse);
        assert_eq!(policy(), ColdBuildPolicy::Refuse);
        set_policy(ColdBuildPolicy::Allow);
        assert_eq!(policy(), ColdBuildPolicy::Allow);
    }

    #[test]
    fn launch_policy_decision() {
        assert_eq!(decide(true, None), ColdBuildPolicy::Allow);
        assert_eq!(decide(true, Some("refuse")), ColdBuildPolicy::Allow);
        assert_eq!(decide(false, Some("auto")), ColdBuildPolicy::Allow);
        assert_eq!(decide(false, Some(" auto ")), ColdBuildPolicy::Allow);
        assert_eq!(decide(false, Some("1")), ColdBuildPolicy::Refuse);
        assert_eq!(decide(false, None), ColdBuildPolicy::Refuse);
    }
}
