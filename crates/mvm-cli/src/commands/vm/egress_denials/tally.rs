//! Collapse a run's refusals into one line per distinct destination and
//! reason, counted, with the exact re-run flags for the ones that can be
//! allowed.
//!
//! A workload that retries a refused destination does so tens of times a
//! second; a notice per attempt would bury its own output. The live view shows
//! each distinct refusal once, and the summary carries the count.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::denial::{EgressDenial, Subject};
use super::reason::{DenialKind, Remedy};

/// One distinct refusal: what, why, how often, and what to do about it. The
/// record `--json` output and `mvmctl explain --json` carry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(in crate::commands) struct DeniedDestination {
    /// What was refused, as the notice names it (`api.example.com:443`,
    /// `DNS lookup of pypi.org`, `POST api.github.com:443`).
    pub destination: String,
    /// The audit event that recorded the refusal.
    pub event: String,
    /// The reason label exactly as the chain recorded it.
    pub reason: String,
    /// The reason in words.
    pub description: String,
    /// How many times the workload was refused.
    pub count: u64,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub remedy: Remedy,
    /// The remedy as the notice words it.
    pub hint: String,
}

/// The dedup key: the same destination refused for the same reason is one
/// line however often it recurs.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Key {
    subject: Subject,
    reason: String,
}

#[derive(Debug, Clone)]
struct Seen {
    denial: EgressDenial,
    count: u64,
    last_seen: DateTime<Utc>,
    /// Order of first sighting, so the summary lists refusals in the order
    /// the workload hit them.
    order: usize,
}

/// Every refusal seen for one machine, counted by destination and reason.
#[derive(Debug, Clone, Default)]
pub(in crate::commands) struct DenialTally {
    seen: BTreeMap<Key, Seen>,
}

impl DenialTally {
    /// Count `denial`. `true` the first time this destination is refused for
    /// this reason — the one time a live notice is worth printing.
    pub(in crate::commands) fn observe(&mut self, denial: EgressDenial) -> bool {
        let key = Key {
            subject: denial.subject.clone(),
            reason: denial.reason.clone(),
        };
        if let Some(seen) = self.seen.get_mut(&key) {
            seen.count += 1;
            seen.last_seen = seen.last_seen.max(denial.at);
            return false;
        }
        let order = self.seen.len();
        self.seen.insert(
            key,
            Seen {
                last_seen: denial.at,
                denial,
                count: 1,
                order,
            },
        );
        true
    }

    pub(in crate::commands) fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    fn in_order(&self) -> Vec<&Seen> {
        let mut rows: Vec<&Seen> = self.seen.values().collect();
        rows.sort_by_key(|seen| seen.order);
        rows
    }

    /// The distinct refusals in the order they were first seen.
    pub(in crate::commands) fn destinations(&self) -> Vec<DeniedDestination> {
        self.in_order()
            .into_iter()
            .map(|seen| DeniedDestination {
                destination: seen.denial.subject.to_string(),
                event: seen.denial.event.clone(),
                reason: seen.denial.reason.clone(),
                description: seen.denial.kind.describe(),
                count: seen.count,
                first_seen: seen.denial.at,
                last_seen: seen.last_seen,
                remedy: seen.denial.remedy(),
                hint: seen.denial.remedy().render(seen.denial.subject.has_port()),
            })
            .collect()
    }

    /// The exit summary: one block listing every refused destination with its
    /// count, then the exact flags — and the manifest snippet — that admit
    /// the ones a grant can admit. Empty when nothing was refused.
    pub(in crate::commands) fn summary_lines(&self) -> Vec<String> {
        if self.is_empty() {
            return Vec::new();
        }
        let rows = self.in_order();
        let attempts: u64 = rows.iter().map(|seen| seen.count).sum();
        let mut lines = vec![format!(
            "egress denied: {} {}, {} {}",
            rows.len(),
            plural(rows.len() as u64, "destination", "destinations"),
            attempts,
            plural(attempts, "attempt", "attempts"),
        )];
        let width = rows
            .iter()
            .map(|seen| seen.denial.subject.to_string().len())
            .max()
            .unwrap_or(0);
        for seen in &rows {
            let remedy = seen.denial.remedy();
            let tail = match &remedy {
                Remedy::AllowHost { .. } => String::new(),
                other => format!(" — {}", other.render(seen.denial.subject.has_port())),
            };
            lines.push(format!(
                "  {:<width$}  {:>4}×  {}{tail}",
                seen.denial.subject.to_string(),
                seen.count,
                seen.denial.kind.describe(),
            ));
        }
        let allowable = allow_targets(&rows, DenialKind::is_plain_allow);
        if !allowable.is_empty() {
            lines.push("to allow what the allow-list refused, re-run with:".to_string());
            lines.push(format!("  {}", allow_flags(&allowable)));
            lines.push(
                "or, for a machine created with `machine create --manifest`, in its mvm.toml:"
                    .to_string(),
            );
            lines.push("  [network]".to_string());
            lines.push(format!(
                "  allow_hosts = [{}]",
                allowable
                    .iter()
                    .map(|target| format!("{target:?}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        let named_only = allow_targets(&rows, DenialKind::is_named_only);
        if !named_only.is_empty() {
            lines.push(
                "denied by default, and admitted only by naming each exactly — do so only if \
                 the workload should reach it:"
                    .to_string(),
            );
            lines.push(format!("  {}", allow_flags(&named_only)));
        }
        lines
    }
}

/// The distinct `--allow-host` targets of the rows `admits` accepts, a bare
/// name dropped where the same name on port 443 is already listed.
fn allow_targets(rows: &[&Seen], admits: impl Fn(&DenialKind) -> bool) -> Vec<String> {
    let mut targets: Vec<String> = Vec::new();
    for seen in rows {
        if !admits(&seen.denial.kind) {
            continue;
        }
        if let Some(target) = seen.denial.subject.allow_target()
            && !targets.iter().any(|t| t == target)
        {
            targets.push(target.to_string());
        }
    }
    let explicit: Vec<String> = targets.clone();
    targets.retain(|target| {
        target.contains(':') || !explicit.iter().any(|t| *t == format!("{target}:443"))
    });
    targets
}

fn allow_flags(targets: &[String]) -> String {
    targets
        .iter()
        .map(|target| format!("--allow-host {target}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn plural(n: u64, one: &'static str, many: &'static str) -> &'static str {
    if n == 1 { one } else { many }
}

#[cfg(test)]
mod tests {
    use super::super::denial::tests::entry;
    use super::*;

    fn denial(event: &str, labels: &[(&str, &str)]) -> EgressDenial {
        let mut labels = labels.to_vec();
        labels.push(("vm_name", "vm-a"));
        EgressDenial::from_entry(&entry(event, &labels), "vm-a").unwrap()
    }

    fn flow(target: &str, reason: &str) -> EgressDenial {
        denial(
            "host.flow.denied",
            &[("class", "tcp"), ("target", target), ("reason", reason)],
        )
    }

    #[test]
    fn a_repeated_refusal_is_new_once_and_counted_every_time() {
        let mut tally = DenialTally::default();
        assert!(tally.observe(flow("a.example:443", "policy_denied")));
        assert!(!tally.observe(flow("a.example:443", "policy_denied")));
        assert!(!tally.observe(flow("a.example:443", "policy_denied")));
        assert!(tally.observe(flow("b.example:443", "policy_denied")));
        let rows = tally.destinations();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].destination, "a.example:443");
        assert_eq!(rows[0].count, 3);
        assert_eq!(rows[1].count, 1);
    }

    #[test]
    fn the_same_destination_for_a_different_reason_is_a_separate_line() {
        let mut tally = DenialTally::default();
        assert!(tally.observe(flow("a.example:443", "policy_denied")));
        assert!(tally.observe(flow("a.example:443", "rate_limited")));
        assert_eq!(tally.destinations().len(), 2);
    }

    #[test]
    fn nothing_refused_prints_no_summary() {
        assert!(DenialTally::default().summary_lines().is_empty());
    }

    #[test]
    fn the_summary_counts_and_gives_the_exact_flags_and_manifest_snippet() {
        let mut tally = DenialTally::default();
        for _ in 0..3 {
            tally.observe(flow("api.example.com:443", "policy_denied"));
        }
        tally.observe(denial(
            "dns.refused",
            &[("qname", "pypi.org"), ("reason", "policy_denied")],
        ));
        tally.observe(flow("169.254.169.254:80", "cloud_metadata"));
        tally.observe(flow("10.0.0.5:5432", "private_range"));

        let lines = tally.summary_lines();
        let text = lines.join("\n");
        assert_eq!(
            lines[0], "egress denied: 4 destinations, 6 attempts",
            "{text}"
        );
        assert!(
            lines
                .iter()
                .any(|line| line.starts_with("  api.example.com:443 ")
                    && line.ends_with(" 3×  not in the allow-list")),
            "{text}"
        );
        assert!(
            text.contains("  --allow-host api.example.com:443 --allow-host pypi.org\n"),
            "{text}"
        );
        assert!(
            text.contains("  allow_hosts = [\"api.example.com:443\", \"pypi.org\"]"),
            "{text}"
        );
        // Metadata is listed, with no way to allow it anywhere in the block.
        assert!(text.contains("169.254.169.254:80"), "{text}");
        assert!(!text.contains("--allow-host 169.254.169.254"), "{text}");
        assert!(!text.contains("\"169.254.169.254:80\""), "{text}");
        // A private address is kept out of the allow command and the manifest
        // snippet, and named separately as needing an exact grant.
        assert!(!text.contains("\"10.0.0.5:5432\""), "{text}");
        assert!(text.contains("naming each exactly"), "{text}");
        assert!(text.contains("  --allow-host 10.0.0.5:5432"), "{text}");
    }

    #[test]
    fn a_bare_lookup_is_folded_into_the_same_name_on_port_443() {
        let mut tally = DenialTally::default();
        tally.observe(denial(
            "dns.refused",
            &[("qname", "pypi.org"), ("reason", "policy_denied")],
        ));
        tally.observe(flow("pypi.org:443", "policy_denied"));
        let text = tally.summary_lines().join("\n");
        assert!(text.contains("  --allow-host pypi.org:443\n"), "{text}");
        assert!(!text.contains("--allow-host pypi.org "), "{text}");
    }

    #[test]
    fn a_summary_of_only_unallowable_refusals_offers_nothing_to_allow() {
        let mut tally = DenialTally::default();
        tally.observe(flow("169.254.169.254:80", "cloud_metadata"));
        tally.observe(flow("127.0.0.1:8080", "loopback"));
        let text = tally.summary_lines().join("\n");
        assert!(!text.contains("--allow-host"), "{text}");
        assert!(!text.contains("allow_hosts"), "{text}");
        assert!(!text.contains("re-run"), "{text}");
    }

    #[test]
    fn the_json_record_has_a_stable_shape() {
        let mut tally = DenialTally::default();
        tally.observe(flow("api.example.com:443", "policy_denied"));
        tally.observe(flow("api.example.com:443", "policy_denied"));
        let json = serde_json::to_value(tally.destinations()).unwrap();
        assert_eq!(
            json,
            serde_json::json!([{
                "destination": "api.example.com:443",
                "event": "host.flow.denied",
                "reason": "policy_denied",
                "description": "not in the allow-list",
                "count": 2,
                "first_seen": "2026-09-26T10:00:00Z",
                "last_seen": "2026-09-26T10:00:00Z",
                "remedy": {"kind": "allow_host", "flag": "--allow-host api.example.com:443"},
                "hint": "allow with --allow-host api.example.com:443"
            }])
        );
    }
}
