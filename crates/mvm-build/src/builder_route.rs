//! Host-side builder dispatch routing — the compatibility-adapter seam.
//!
//! The builder VM's stable API is the typed `mvm-builderd` request set
//! (`builderd_protocol`), driven from the host by `builderd_client::BuilderdClient`.
//! The legacy controlled-shell-job channel (`builder_protocol::HostVmRequest::Run`,
//! dispatched by `persistent_builder`) is being migrated onto that typed client
//! one operation at a time.
//!
//! This module is the decision seam for that migration. A host build path asks
//! [`resolve_route`] whether a given dispatch should use the typed `mvm-builderd`
//! route or fall back to the legacy shell-job channel, and emits
//! [`legacy_shell_diagnostic`] whenever the legacy channel is taken — so the
//! remaining shell surface stays visible and shrinkable (the
//! `xtask check-builder-shell-job-sites` allowlist is the static counterpart).
//!
//! The phasing is "opt-in, then default": today the typed route is taken only
//! when the daemon is reachable *and* the caller opted in via
//! [`BUILDERD_TYPED_OPT_IN_ENV`]; once a typed operation is proven over the wire,
//! flipping its default is a one-line change here rather than a scatter of
//! call-site edits.

/// Opt-in env flag letting a host build path prefer the typed `mvm-builderd`
/// route when the daemon is reachable. Off by default during the migration.
pub const BUILDERD_TYPED_OPT_IN_ENV: &str = "MVM_BUILDERD_TYPED";

/// Which channel a host-side builder dispatch takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuilderRoute {
    /// Typed request over vsock to the resident `mvm-builderd`.
    Typed,
    /// Legacy controlled-shell-job channel (the compatibility adapter).
    LegacyShell,
}

/// Resolve the dispatch route: typed only when the daemon is reachable **and**
/// the caller opted in; otherwise the legacy shell channel. Pure so the
/// opt-in-then-default phasing is a one-line change once a typed op is proven.
pub fn resolve_route(daemon_reachable: bool, typed_opt_in: bool) -> BuilderRoute {
    if daemon_reachable && typed_opt_in {
        BuilderRoute::Typed
    } else {
        BuilderRoute::LegacyShell
    }
}

/// Read the typed opt-in flag from an env getter (`1`/`true`/`yes`,
/// case-insensitive, whitespace-trimmed). Injected rather than reading the
/// process env directly so it is unit-testable.
pub fn typed_opt_in(getter: impl Fn(&str) -> Option<String>) -> bool {
    matches!(
        getter(BUILDERD_TYPED_OPT_IN_ENV)
            .as_deref()
            .map(|v| v.trim().to_ascii_lowercase())
            .as_deref(),
        Some("1") | Some("true") | Some("yes")
    )
}

/// The structured diagnostic emitted whenever a dispatch takes the legacy
/// shell-job channel, naming the job so the remaining shell surface is visible.
pub fn legacy_shell_diagnostic(job_label: &str) -> String {
    format!(
        "builder dispatch via legacy shell-job channel (job {job_label}); \
         not yet migrated to the typed mvm-builderd route"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_route_needs_both_reachable_and_opt_in() {
        assert_eq!(resolve_route(true, true), BuilderRoute::Typed);
        assert_eq!(resolve_route(true, false), BuilderRoute::LegacyShell);
        assert_eq!(resolve_route(false, true), BuilderRoute::LegacyShell);
        assert_eq!(resolve_route(false, false), BuilderRoute::LegacyShell);
    }

    #[test]
    fn opt_in_parses_truthy_values_case_insensitively() {
        let on = |v: &str| {
            let v = v.to_string();
            typed_opt_in(move |_| Some(v.clone()))
        };
        assert!(on("1"));
        assert!(on("true"));
        assert!(on("TRUE"));
        assert!(on("  yes  "));
        assert!(!on("0"));
        assert!(!on("false"));
        assert!(!on("off"));
        assert!(!on(""));
        // Absent var → not opted in.
        assert!(!typed_opt_in(|_| None));
    }

    #[test]
    fn legacy_diagnostic_names_the_job() {
        let msg = legacy_shell_diagnostic("job-7f3a");
        assert!(msg.contains("job-7f3a"));
        assert!(msg.contains("legacy shell-job channel"));
        assert!(msg.contains("mvm-builderd"));
    }
}
