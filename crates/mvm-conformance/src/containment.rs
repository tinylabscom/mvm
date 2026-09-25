//! Pure host-evidence primitives for the `DestructiveLabOnly` containment
//! scenario.
//!
//! The scenario boots a sealed guest on a kernel known vulnerable to
//! CVE-2026-80521 (an AF_UNIX `SCM_RIGHTS` garbage-collection use-after-free),
//! delivers and runs the public proof-of-concept inside that guest through
//! admission, and then asserts from *host* evidence that the guest-kernel
//! compromise did not cross the microVM boundary: the host filesystem,
//! processes and listeners are unchanged, a bystander sibling guest's rootfs
//! digest is unchanged, no egress connection was admitted, and the audit chain
//! is intact.
//!
//! The decision logic lives here — separated from the cucumber steps that
//! gather the raw observations — so it is a pure function the workspace test
//! run exercises without a live VM. The steps do the privileged, unrepeatable
//! work (boot a guest, run an exploit, read `/proc`); this module decides what
//! the numbers mean, and that is the part a regression would silently break.

use std::collections::{BTreeMap, BTreeSet};

/// A snapshot of the host surface a guest-kernel compromise would perturb if it
/// crossed the boundary.
///
/// Deliberately coarse and cheap: the exact bytes of a watched set of host
/// files, the set of process command lines, and the set of listening sockets.
/// The claim is not "nothing on the host changed" — a busy host mutates
/// constantly — but "nothing the guest could reach changed", so the watched
/// file set is the narrow set of host paths the boundary is supposed to keep a
/// guest away from, chosen by the caller.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostObservation {
    /// Watched host path → content digest (hex). A path that is absent in one
    /// snapshot and present in the other is itself a difference.
    pub files: BTreeMap<String, String>,
    /// Process identities (a stable rendering of each process, e.g.
    /// `pid:comm`), as a set so ordering and transient churn outside the set do
    /// not register.
    pub procs: BTreeSet<String>,
    /// Listening sockets, rendered as `proto:addr:port`, as a set.
    pub listeners: BTreeSet<String>,
}

impl HostObservation {
    /// Every way `after` differs from `self`, as human-readable lines. Empty
    /// means the host surface is unchanged, which is the passing outcome.
    ///
    /// New and removed elements are both reported: an exploit that *deletes* a
    /// host file or kills a host process has crossed the boundary exactly as
    /// much as one that adds a listener.
    #[must_use]
    pub fn drift(&self, after: &HostObservation) -> Vec<String> {
        let mut out = Vec::new();

        for (path, before_digest) in &self.files {
            match after.files.get(path) {
                None => out.push(format!("host file disappeared: {path}")),
                Some(after_digest) if after_digest != before_digest => {
                    out.push(format!("host file changed: {path}"));
                }
                Some(_) => {}
            }
        }
        for path in after.files.keys() {
            if !self.files.contains_key(path) {
                out.push(format!("host file appeared: {path}"));
            }
        }

        for gone in self.procs.difference(&after.procs) {
            out.push(format!("host process gone: {gone}"));
        }
        for added in after.procs.difference(&self.procs) {
            out.push(format!("new host process: {added}"));
        }

        for gone in self.listeners.difference(&after.listeners) {
            out.push(format!("host listener gone: {gone}"));
        }
        for added in after.listeners.difference(&self.listeners) {
            out.push(format!("new host listener: {added}"));
        }

        out
    }
}

/// What the audit chain says about the victim guest's outbound attempts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressVerdict {
    /// Count of recorded egress refusals — the positive evidence that the
    /// guest tried to reach the network and default-deny stopped it.
    pub refusals: usize,
    /// Any recorded egress *admissions*. Non-empty is a containment failure:
    /// an admitted outbound connection from a workload that declared no policy.
    pub admitted: Vec<String>,
}

impl EgressVerdict {
    /// Containment holds when nothing outbound was admitted. Refusals are
    /// welcome but not required — a PoC that never reaches the egress stage
    /// still must not have crossed it.
    #[must_use]
    pub fn contained(&self) -> bool {
        self.admitted.is_empty()
    }
}

/// Scan chain-signed audit lines for egress decisions.
///
/// Matches on the decision event token rather than parsing every field, so a
/// schema addition does not silently turn a refusal into an invisible line: an
/// `egress.admitted`/`egress.allowed` token anywhere is counted as an
/// admission, and `egress.refused`/`egress.denied` as a refusal. The caller
/// supplies already-verified chain lines; this only classifies them.
#[must_use]
pub fn classify_egress(audit_lines: &[String]) -> EgressVerdict {
    let mut refusals = 0usize;
    let mut admitted = Vec::new();
    for line in audit_lines {
        if line.contains("egress.admitted") || line.contains("egress.allowed") {
            admitted.push(line.clone());
        }
        if line.contains("egress.refused") || line.contains("egress.denied") {
            refusals += 1;
        }
    }
    EgressVerdict { refusals, admitted }
}

/// Whether an observed content digest matches a pinned one, case-insensitively.
///
/// The pins in `features/suites/s37_cve_containment/pins.toml` are lowercase
/// hex; a fetched artifact's digest may arrive from a tool that upper-cases.
/// Trims surrounding whitespace so a digest read from a `*.sha256` sidecar
/// (which carries a trailing newline) compares equal.
#[must_use]
pub fn digest_matches_pin(pinned_hex: &str, observed_hex: &str) -> bool {
    pinned_hex.trim().eq_ignore_ascii_case(observed_hex.trim())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(files: &[(&str, &str)], procs: &[&str], listeners: &[&str]) -> HostObservation {
        HostObservation {
            files: files
                .iter()
                .map(|(p, d)| ((*p).to_string(), (*d).to_string()))
                .collect(),
            procs: procs.iter().map(|s| (*s).to_string()).collect(),
            listeners: listeners.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    #[test]
    fn identical_snapshots_have_no_drift() {
        let a = obs(&[("/etc/passwd", "aa")], &["1:init"], &["tcp:0.0.0.0:22"]);
        assert!(a.drift(&a).is_empty());
    }

    #[test]
    fn a_changed_host_file_is_drift() {
        let before = obs(&[("/etc/passwd", "aa")], &[], &[]);
        let after = obs(&[("/etc/passwd", "bb")], &[], &[]);
        assert_eq!(before.drift(&after), vec!["host file changed: /etc/passwd"]);
    }

    #[test]
    fn an_appeared_or_disappeared_host_file_is_drift() {
        let before = obs(&[("/etc/passwd", "aa")], &[], &[]);
        let after = obs(&[("/tmp/pwned", "cc")], &[], &[]);
        let drift = before.drift(&after);
        assert!(drift.contains(&"host file disappeared: /etc/passwd".to_string()));
        assert!(drift.contains(&"host file appeared: /tmp/pwned".to_string()));
    }

    #[test]
    fn a_new_host_process_and_a_killed_one_are_both_drift() {
        let before = obs(&[], &["1:init", "2:agent"], &[]);
        let after = obs(&[], &["1:init", "9:reverse-shell"], &[]);
        let drift = before.drift(&after);
        assert!(drift.contains(&"host process gone: 2:agent".to_string()));
        assert!(drift.contains(&"new host process: 9:reverse-shell".to_string()));
    }

    #[test]
    fn a_new_host_listener_is_drift() {
        let before = obs(&[], &[], &["tcp:0.0.0.0:22"]);
        let after = obs(&[], &[], &["tcp:0.0.0.0:22", "tcp:0.0.0.0:4444"]);
        assert_eq!(
            before.drift(&after),
            vec!["new host listener: tcp:0.0.0.0:4444".to_string()]
        );
    }

    #[test]
    fn no_admitted_egress_is_contained_even_with_refusals() {
        let lines = vec![
            r#"{"event":"egress.refused","dest":"depthfirst.com:443"}"#.to_string(),
            r#"{"event":"plan.launched"}"#.to_string(),
        ];
        let verdict = classify_egress(&lines);
        assert_eq!(verdict.refusals, 1);
        assert!(verdict.contained());
    }

    #[test]
    fn an_admitted_egress_breaks_containment() {
        let lines = vec![r#"{"event":"egress.admitted","dest":"1.2.3.4:4444"}"#.to_string()];
        let verdict = classify_egress(&lines);
        assert!(!verdict.contained());
        assert_eq!(verdict.admitted.len(), 1);
    }

    #[test]
    fn a_run_with_no_egress_records_is_still_contained() {
        let verdict = classify_egress(&[]);
        assert_eq!(verdict.refusals, 0);
        assert!(verdict.contained());
    }

    #[test]
    fn pin_comparison_ignores_case_and_surrounding_whitespace() {
        assert!(digest_matches_pin(
            "291ece1b9632016c1fd4a4f29eba1764acfa2012fa3c417b29f38fb3d73d4965",
            "  291ECE1B9632016C1FD4A4F29EBA1764ACFA2012FA3C417B29F38FB3D73D4965\n"
        ));
        assert!(!digest_matches_pin("aa", "bb"));
    }
}
