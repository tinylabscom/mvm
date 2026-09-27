//! The ratchet: comparing observed survivors against the accepted set,
//! and parsing cargo-mutants report lines into stable identities.

use super::*;
use std::collections::BTreeSet;

pub fn ratchet(accepted: &[AcceptedMiss], observed: &[Miss]) -> Verdict {
    let accepted_keys: BTreeSet<(&str, &str)> = accepted
        .iter()
        .map(|a| (a.file.as_str(), a.mutant.as_str()))
        .collect();
    let observed_keys: BTreeSet<(&str, &str)> = observed
        .iter()
        .map(|m| (m.file.as_str(), m.mutant.as_str()))
        .collect();

    Verdict {
        new_misses: observed
            .iter()
            .filter(|m| !accepted_keys.contains(&(m.file.as_str(), m.mutant.as_str())))
            .cloned()
            .collect(),
        now_caught: accepted
            .iter()
            .filter(|a| !observed_keys.contains(&(a.file.as_str(), a.mutant.as_str())))
            .cloned()
            .collect(),
    }
}

/// Judge a shard from the evidence for every file it owns.
///
/// The accepted set narrows to the shard's files, or every other package's
/// entries would read as "now caught" by a shard that never looked at them.
/// It narrows again for "now caught": an accepted miss in a file with no
/// finished result was not re-observed, so its absence proves nothing. The
/// survivors an unfinished file did report still count as observed, so a
/// new hole found before a timeout is not lost with the rest of the file.
pub fn judge_shard(accepted: &[AcceptedMiss], evidence: &[(String, FileEvidence)]) -> ShardVerdict {
    let shard_files: BTreeSet<&str> = evidence.iter().map(|(file, _)| file.as_str()).collect();
    let measured: BTreeSet<&str> = evidence
        .iter()
        .filter(|(_, e)| matches!(e, FileEvidence::Measured(_)))
        .map(|(file, _)| file.as_str())
        .collect();
    let accepted: Vec<AcceptedMiss> = accepted
        .iter()
        .filter(|a| shard_files.contains(a.file.as_str()))
        .cloned()
        .collect();
    let verdict = ratchet(&accepted, &observed_misses(evidence));
    ShardVerdict {
        new_misses: verdict.new_misses,
        now_caught: verdict
            .now_caught
            .into_iter()
            .filter(|a| measured.contains(a.file.as_str()))
            .collect(),
        unmeasured: evidence
            .iter()
            .filter_map(|(file, e)| match e {
                FileEvidence::Measured(_) => None,
                FileEvidence::Unmeasured { reason, .. } => Some(UnmeasuredFile {
                    file: file.clone(),
                    reason: reason.clone(),
                }),
            })
            .collect(),
    }
}

/// Every survivor the evidence reports, finished files or not.
pub(crate) fn observed_misses(evidence: &[(String, FileEvidence)]) -> Vec<Miss> {
    let mut all: Vec<Miss> = evidence
        .iter()
        .flat_map(|(_, e)| match e {
            FileEvidence::Measured(misses) | FileEvidence::Unmeasured { misses, .. } => {
                misses.iter().cloned()
            }
        })
        .collect();
    all.sort();
    all.dedup();
    all
}

pub(crate) fn seed_accepted(misses: &[Miss]) -> Vec<AcceptedMiss> {
    misses
        .iter()
        .map(|m| AcceptedMiss {
            file: m.file.clone(),
            mutant: m.mutant.clone(),
            reason: "untriaged: seeded from the first observed run".to_string(),
        })
        .collect()
}

/// Split a cargo-mutants report line into (file, description), dropping
/// `line:col`. Identity without position survives edits elsewhere in the
/// same file, so an unrelated change above a mutant does not invalidate
/// the baseline.
///
/// `crates/a/src/b.rs:23:5: replace f -> bool with true`
///   -> ("crates/a/src/b.rs", "replace f -> bool with true")
pub fn mutant_identity(line: &str) -> Option<Miss> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    // Walk from the left: path, then two numeric fields, then the rest.
    // A description can itself contain colons (`Foo::bar`), so splitting
    // naively on ':' and taking a fixed field count is wrong.
    let mut rest = line;
    let mut fields = Vec::new();
    for _ in 0..3 {
        let (head, tail) = rest.split_once(':')?;
        fields.push(head);
        rest = tail;
    }
    let (line_no, col_no) = (fields[1], fields[2]);
    if line_no.parse::<u32>().is_err() || col_no.parse::<u32>().is_err() {
        return None;
    }
    let description = rest.trim();
    if description.is_empty() {
        return None;
    }
    Some(Miss {
        file: fields[0].to_string(),
        mutant: description.to_string(),
    })
}

pub fn parse_missed(report: &str) -> Vec<Miss> {
    let mut out: Vec<Miss> = report.lines().filter_map(mutant_identity).collect();
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn miss(file: &str, mutant: &str) -> Miss {
        Miss {
            file: file.into(),
            mutant: mutant.into(),
        }
    }

    fn accepted(file: &str, mutant: &str) -> AcceptedMiss {
        AcceptedMiss {
            file: file.into(),
            mutant: mutant.into(),
            reason: "known".into(),
        }
    }

    #[test]
    fn identity_strips_line_and_column() {
        let m = mutant_identity("crates/a/src/b.rs:23:5: replace f -> bool with true").unwrap();
        assert_eq!(m.file, "crates/a/src/b.rs");
        assert_eq!(m.mutant, "replace f -> bool with true");
    }

    #[test]
    fn identity_keeps_colons_inside_the_description() {
        let m = mutant_identity("crates/a/src/b.rs:9:1: replace == with != in Foo::bar").unwrap();
        assert_eq!(m.mutant, "replace == with != in Foo::bar");
    }

    #[test]
    fn identity_rejects_non_report_lines() {
        assert!(mutant_identity("").is_none());
        assert!(mutant_identity("just prose").is_none());
        assert!(mutant_identity("path:notanumber:5: replace x").is_none());
        assert!(mutant_identity("crates/a.rs:1:2: ").is_none());
    }

    #[test]
    fn identity_collapses_two_positions_of_the_same_change() {
        // Same description at different positions is one identity: that
        // is what keeps the baseline stable under code motion.
        let a = mutant_identity("f.rs:1:1: replace == with !=").unwrap();
        let b = mutant_identity("f.rs:90:7: replace == with !=").unwrap();
        assert_eq!(a, b);
    }

    /// Verbatim `mutants.out/missed.txt` from a real cargo-mutants 27.1
    /// run over the claim-10 anchor. A hand-written fixture would only
    /// prove the parser matches my assumption about the format; this
    /// proves it matches the tool.
    const REAL_MISSED_REPORT: &str = "\
crates/mvm-contract/src/policy/network_policy.rs:92:5: replace is_banned_ssh_port -> bool with false
crates/mvm-contract/src/policy/network_policy.rs:140:9: replace NetworkPreset::is_deny_all -> bool with false
crates/mvm-contract/src/policy/network_policy.rs:140:9: replace NetworkPreset::is_deny_all -> bool with true
crates/mvm-contract/src/policy/network_policy.rs:271:9: replace NetworkPolicy::trusted_build_egress -> Self with Default::default()
";

    #[test]
    fn real_tool_output_parses_into_four_distinct_identities() {
        let misses = parse_missed(REAL_MISSED_REPORT);
        assert_eq!(
            misses.len(),
            4,
            "two is_deny_all mutants differ by replacement"
        );
        assert!(
            misses
                .iter()
                .all(|m| m.file == "crates/mvm-contract/src/policy/network_policy.rs")
        );
        // The `-> Self with Default::default()` form carries both `::`
        // and `()`; a naive field split would truncate it.
        assert!(misses.iter().any(|m| m.mutant
            == "replace NetworkPolicy::trusted_build_egress -> Self with Default::default()"));
    }

    #[test]
    fn real_tool_output_ratchets_clean_against_matching_accepted_entries() {
        let observed = parse_missed(REAL_MISSED_REPORT);
        let accepted: Vec<AcceptedMiss> = observed
            .iter()
            .map(|m| AcceptedMiss {
                file: m.file.clone(),
                mutant: m.mutant.clone(),
                reason: "triaged".into(),
            })
            .collect();
        let v = ratchet(&accepted, &observed);
        assert!(v.new_misses.is_empty(), "identities must round-trip");
        assert!(v.now_caught.is_empty());
    }

    #[test]
    fn parse_missed_sorts_and_dedupes() {
        let report = "\
z.rs:2:1: replace b with c
a.rs:1:1: replace x with y
a.rs:5:1: replace x with y
";
        let misses = parse_missed(report);
        assert_eq!(misses.len(), 2);
        assert_eq!(misses[0].file, "a.rs");
        assert_eq!(misses[1].file, "z.rs");
    }

    #[test]
    fn ratchet_flags_a_new_miss() {
        let v = ratchet(&[], &[miss("a.rs", "replace x")]);
        assert_eq!(v.new_misses, vec![miss("a.rs", "replace x")]);
        assert!(v.now_caught.is_empty());
    }

    #[test]
    fn ratchet_accepts_a_baselined_miss() {
        let v = ratchet(
            &[accepted("a.rs", "replace x")],
            &[miss("a.rs", "replace x")],
        );
        assert!(v.new_misses.is_empty());
        assert!(v.now_caught.is_empty());
    }

    #[test]
    fn ratchet_reports_a_baselined_miss_that_is_now_caught() {
        let v = ratchet(&[accepted("a.rs", "replace x")], &[]);
        assert!(v.new_misses.is_empty());
        assert_eq!(v.now_caught.len(), 1);
    }

    #[test]
    fn ratchet_distinguishes_same_mutant_in_different_files() {
        let v = ratchet(
            &[accepted("a.rs", "replace x")],
            &[miss("b.rs", "replace x")],
        );
        assert_eq!(v.new_misses, vec![miss("b.rs", "replace x")]);
    }

    #[test]
    fn seeded_misses_carry_a_reason_so_the_gate_accepts_them() {
        let seeded = seed_accepted(&[miss("a.rs", "replace x")]);
        assert!(check_accepted_reasons(&seeded).is_empty());
    }
}
