use anyhow::{Context, Result, bail};
use mvm_core::plan::VerbId;
use mvm_guest::vsock::GuestRequest;

/// Compute the default agent-verb set for a workload.
/// - Non-sealed-prod (dev) → `None` (class-gate-only; unchanged behavior).
/// - Sealed-prod → all ProdSafe verbs, minus the volume verbs when the
///   workload declares no shares (the only safe per-workload attenuation;
///   host-lifecycle verbs stay so pause/resume/snapshot/pooling never break).
#[allow(dead_code)]
pub(crate) fn default_agent_verbs(is_sealed_prod: bool, has_shares: bool) -> Option<Vec<VerbId>> {
    if !is_sealed_prod {
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
#[allow(dead_code)]
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

    #[allow(dead_code)]
    fn names(v: &Option<Vec<VerbId>>) -> Vec<String> {
        v.as_ref()
            .map(|s| s.iter().map(|x| x.as_str().to_string()).collect())
            .unwrap_or_default()
    }

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
