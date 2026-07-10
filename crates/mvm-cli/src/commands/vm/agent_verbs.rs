use anyhow::{Context, Result, bail};
use mvm_core::plan::VerbId;
use mvm_guest::vsock::GuestRequest;

/// Whether the image at `rootfs_path` is a sealed prod image, read from the
/// `mvm-meta.json` sidecar the build/materialize pipeline writes next to the
/// rootfs. Absent or unreadable sidecar => `false` (treat as not sealed => no
/// default grant), matching the `accessible: true` fallback convention for
/// pre-sidecar artifacts.
pub(crate) fn image_is_sealed(rootfs_path: &std::path::Path) -> bool {
    rootfs_path
        .parent()
        .and_then(|dir| {
            mvm_build::builder_vm::GuestSidecar::read_from_dir(dir)
                .ok()
                .flatten()
        })
        .map(|s| s.sealed)
        .unwrap_or(false)
}

/// Whether a run should receive an attenuated default agent-verb grant. Only a
/// baked-entrypoint run, on a non-dev profile, of a **sealed** image qualifies:
/// those issue only ProdSafe verbs and the image's agent has no console/exec
/// baked in. An interactive PTY (ConsoleOpen) or ad-hoc command (Exec) needs
/// DevOnly verbs; a dev profile stays permissive by contract; and a dev-shell /
/// OCI image (not sealed) must stay reachable via `machine exec` / `console`.
pub(crate) fn grant_eligible(
    pty: bool,
    has_ad_hoc_argv: bool,
    is_dev_profile: bool,
    image_sealed: bool,
) -> bool {
    !pty && !has_ad_hoc_argv && !is_dev_profile && image_sealed
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
    fn grant_eligible_only_for_nonpty_noargv_nondev_sealed() {
        // Baked-entrypoint, prod profile, SEALED image → eligible.
        assert!(grant_eligible(false, false, false, true));
        // Same run but the image is NOT sealed (dev-shell / OCI) → NOT eligible.
        assert!(!grant_eligible(false, false, false, false));
        // Interactive (pty) → NOT eligible even when sealed.
        assert!(!grant_eligible(true, false, false, true));
        // Ad-hoc command (argv) → NOT eligible even when sealed.
        assert!(!grant_eligible(false, true, false, true));
        // Dev profile → NOT eligible even when sealed.
        assert!(!grant_eligible(false, false, true, true));
        // Every disqualifier at once → NOT eligible.
        assert!(!grant_eligible(true, true, true, false));
    }

    #[test]
    fn persistent_with_trailing_argv_is_not_eligible() {
        // `machine run -d --image X -- cmd` runs an ad-hoc Exec (DevOnly): no grant,
        // regardless of sealed state.
        assert!(!grant_eligible(false, true, false, true));
        // Sealed baked-entrypoint on non-dev profile IS eligible.
        assert!(grant_eligible(false, false, false, true));
    }

    #[test]
    fn image_is_sealed_reads_sidecar_sealed_field() {
        use mvm_build::builder_vm::GuestSidecar;
        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"x").unwrap();

        // A sealed prod sidecar => sealed.
        let mut sc = GuestSidecar::for_oci_run("t", false); // accessible:true, sealed:false baseline
        sc.accessible = false;
        sc.sealed = true;
        sc.write_to_dir(dir.path()).unwrap();
        assert!(image_is_sealed(&rootfs));
    }

    #[test]
    fn image_is_sealed_false_for_accessible_and_oci_and_absent() {
        use mvm_build::builder_vm::GuestSidecar;
        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"x").unwrap();

        // Absent sidecar => not sealed.
        assert!(!image_is_sealed(&rootfs));

        // OCI sidecar (accessible:true, sealed:false) => not sealed.
        GuestSidecar::for_oci_run("t", false)
            .write_to_dir(dir.path())
            .unwrap();
        assert!(!image_is_sealed(&rootfs));
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
