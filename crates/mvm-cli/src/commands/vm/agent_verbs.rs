use anyhow::{Context, Result, bail};
use mvm_core::plan::VerbId;
use mvm_guest::vsock::GuestRequest;

/// Whether a run should receive an attenuated agent-verb grant. Only a
/// baked-entrypoint run on a non-dev profile qualifies: those issue only
/// ProdSafe verbs. An interactive PTY (ConsoleOpen) or an ad-hoc command
/// (Exec) needs DevOnly verbs and must NOT be grant-restricted; dev profile
/// stays permissive by contract.
pub(crate) fn grant_eligible(pty: bool, has_ad_hoc_argv: bool, is_dev_profile: bool) -> bool {
    !pty && !has_ad_hoc_argv && !is_dev_profile
}

/// Compute the default agent-verb set for a workload.
/// - `restrict_agent_verbs = false` → `None` (class-gate-only; unchanged behavior).
/// - `restrict_agent_verbs = true` → all ProdSafe verbs, minus the volume verbs when the
///   workload declares no shares (the only safe per-workload attenuation;
///   host-lifecycle verbs stay so pause/resume/snapshot/pooling never break).
pub(crate) fn default_agent_verbs(
    restrict_agent_verbs: bool,
    has_shares: bool,
) -> Option<Vec<VerbId>> {
    if !restrict_agent_verbs {
        return None;
    }
    let set = GuestRequest::prod_safe_verb_names()
        .iter()
        .filter(|n| has_shares || (**n != "mount-volume" && **n != "unmount-volume"))
        .map(|n| VerbId::new(n).expect("prod_safe_verb_names entries are valid kebab verbs"))
        .collect();
    Some(set)
}

/// Validate CLI `--agent-verb` values into an override set. Empty ⇒ `None`
/// (use the computed default). Any value that is not a known ProdSafe verb
/// (unknown, DevOnly, or malformed) is a hard error.
pub(crate) fn parse_agent_verb_override(raw: &[String]) -> Result<Option<Vec<VerbId>>> {
    if raw.is_empty() {
        return Ok(None);
    }
    let allowed: std::collections::BTreeSet<&str> = GuestRequest::prod_safe_verb_names()
        .iter()
        .copied()
        .collect();
    let mut out = Vec::with_capacity(raw.len());
    for r in raw {
        let v = VerbId::new(r).with_context(|| format!("invalid --agent-verb '{r}'"))?;
        if !allowed.contains(v.as_str()) {
            bail!(
                "unknown or non-production --agent-verb '{r}'; valid verbs: {}",
                GuestRequest::prod_safe_verb_names().join(", ")
            );
        }
        out.push(v);
    }
    Ok(Some(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dev_gets_no_restriction() {
        assert_eq!(default_agent_verbs(false, false), None);
        assert_eq!(default_agent_verbs(false, true), None);
    }

    #[test]
    fn prod_without_shares_drops_volume_verbs_keeps_lifecycle_and_entrypoint() {
        let set = default_agent_verbs(true, false).unwrap();
        let s: Vec<&str> = set.iter().map(|v| v.as_str()).collect();
        assert!(s.contains(&"run-entrypoint"));
        assert!(s.contains(&"readiness-status"));
        assert!(s.contains(&"wake")); // host-lifecycle stays
        assert!(!s.contains(&"mount-volume")); // attenuated: no shares
        assert!(!s.contains(&"unmount-volume"));
    }

    #[test]
    fn prod_with_shares_includes_mount() {
        let set = default_agent_verbs(true, true).unwrap();
        assert!(set.iter().any(|v| v.as_str() == "mount-volume"));
    }

    #[test]
    fn default_never_contains_a_devonly_verb() {
        // "exec"/"fs-read"/"proc-start" are DevOnly kind_names — none may appear.
        let set = default_agent_verbs(true, true).unwrap();
        for banned in ["exec", "fs-read", "proc-start", "console-open"] {
            assert!(
                !set.iter().any(|v| v.as_str() == banned),
                "{banned} leaked into default"
            );
        }
    }

    #[test]
    fn grant_eligible_only_for_nonpty_noargv_nondev() {
        // Baked-entrypoint run on a prod profile → eligible.
        assert!(grant_eligible(false, false, false));
        // Interactive (pty) → NOT eligible (needs ConsoleOpen, DevOnly).
        assert!(!grant_eligible(true, false, false));
        // Ad-hoc command (argv present) → NOT eligible (needs Exec, DevOnly).
        assert!(!grant_eligible(false, true, false));
        // Dev profile → NOT eligible (dev stays permissive).
        assert!(!grant_eligible(false, false, true));
        // Any combination with a disqualifier → NOT eligible.
        assert!(!grant_eligible(true, true, true));
    }

    #[test]
    fn persistent_with_trailing_argv_is_not_eligible() {
        // `machine run -d --image X -- cmd` boots the machine AND then runs an
        // ad-hoc command via GuestRequest::Exec (a DevOnly verb). The admitted
        // plan must NOT carry an attenuated ProdSafe grant.
        assert!(
            !grant_eligible(false, true, false),
            "persistent + ad-hoc argv must not receive a ProdSafe-only grant"
        );
        // Without trailing argv, a non-dev persistent boot IS eligible.
        assert!(
            grant_eligible(false, false, false),
            "persistent baked-entrypoint on non-dev profile must be eligible"
        );
    }

    #[test]
    fn override_parses_valid_and_rejects_unknown_and_empty() {
        assert_eq!(parse_agent_verb_override(&[]).unwrap(), None);
        let ok = parse_agent_verb_override(&["run-entrypoint".into(), "ping".into()])
            .unwrap()
            .unwrap();
        assert_eq!(
            ok.iter().map(|v| v.as_str()).collect::<Vec<_>>(),
            ["run-entrypoint", "ping"]
        );
        assert!(parse_agent_verb_override(&["exec".into()]).is_err()); // DevOnly rejected
        assert!(parse_agent_verb_override(&["not-a-verb".into()]).is_err()); // unknown rejected
        assert!(parse_agent_verb_override(&["BAD".into()]).is_err()); // not kebab
    }
}
