//! Surface resolution: mapping claim witnesses to the enforcement files
//! they guard, and diffing the resolved surface against the committed pin.

use super::*;
use crate::claims_ledger::{self, Witness};
use anyhow::Result;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Map every `fn:` witness in the ledger to the file that declares it.
pub fn resolve_surface(workspace: &Path) -> Result<Surface> {
    let rows = claims_ledger::load(workspace)?;

    // fn name -> claim numbers naming it.
    let mut wanted: BTreeMap<String, BTreeSet<u32>> = BTreeMap::new();
    // Claims with no `fn:` witness at all have nothing to resolve.
    let mut claims_with_fn_witness: BTreeSet<u32> = BTreeSet::new();
    for row in &rows {
        for w in &row.witnesses {
            if let Witness::Fn(name) = w {
                wanted.entry(name.clone()).or_default().insert(row.number);
                claims_with_fn_witness.insert(row.number);
            }
        }
    }

    // path -> claim numbers whose witnesses live there. Integration-test
    // paths are collected too, so a claim witnessed *only* by an
    // integration test can be reported as uncovered rather than
    // silently vanishing.
    let mut hits: BTreeMap<String, BTreeSet<u32>> = BTreeMap::new();
    // Files that resolved but hold nothing cargo-mutants would mutate, kept
    // apart from the ones that do so the uncovered-claim accounting can tell
    // "no witness resolved here" from "a witness resolved into test code".
    let mut unmutatable: BTreeSet<String> = BTreeSet::new();
    let crates = workspace.join("crates");
    claims_ledger::for_each_file(&crates, Some("rs"), &mut |path, content| {
        for (name, claims) in &wanted {
            if content.contains(&format!("fn {name}(")) {
                let Some(rel) = workspace_relative(workspace, path) else {
                    continue;
                };
                if is_test_only_module(content) {
                    unmutatable.insert(rel.clone());
                }
                hits.entry(rel).or_default().extend(claims.iter().copied());
            }
        }
    })?;

    let mut files: Vec<SurfaceFile> = hits
        .iter()
        .filter(|(path, _)| !is_integration_test(path) && !unmutatable.contains(*path))
        .filter_map(|(path, claims)| {
            Some(SurfaceFile {
                path: path.clone(),
                package: package_for(path)?,
                claims: claims.iter().copied().collect(),
                // Resolution never narrows. A scope can only be added by
                // hand to the committed baseline, which is what makes it
                // a reviewable act rather than a silent one.
                scope: None,
                features: Vec::new(),
            })
        })
        .collect();
    files.sort();

    let covered: BTreeSet<u32> = files
        .iter()
        .flat_map(|f| f.claims.iter().copied())
        .collect();
    let uncovered = rows
        .iter()
        .map(|r| r.number)
        .filter(|n| !covered.contains(n))
        .map(|number| UncoveredClaim {
            why: if claims_with_fn_witness.contains(&number) {
                WHY_ONLY_INTEGRATION_TESTS.to_string()
            } else {
                WHY_NO_FN_WITNESS.to_string()
            },
            number,
        })
        .collect();

    Ok(Surface { files, uncovered })
}

/// `crates/mvm-contract/src/policy/network_policy.rs` -> `mvm-contract`.
pub fn package_for(rel_path: &str) -> Option<String> {
    let mut parts = rel_path.split('/');
    if parts.next()? != "crates" {
        return None;
    }
    let first = parts.next()?;
    // `crates/deps/libkrun-sys/...` nests one level deeper.
    if first == "deps" {
        return parts.next().map(str::to_string);
    }
    Some(first.to_string())
}

/// True for `crates/<pkg>/tests/...`, which cargo-mutants never mutates.
pub fn is_integration_test(rel_path: &str) -> bool {
    rel_path.split('/').nth(2) == Some("tests")
}

/// True for a module file that is compiled only under `cfg(test)`.
///
/// Resolution maps a `fn:` witness to the file declaring it and assumes that
/// file is the enforcement code the witness guards — which holds because this
/// repo keeps `#[cfg(test)] mod tests` inline, beside the implementation. It
/// does not hold when the tests are a *separate* module file: there the
/// resolved file is the tests themselves, and the code they guard is
/// elsewhere.
///
/// The cost of not noticing is not a weak measurement, it is a dead shard.
/// cargo-mutants does not mutate test code, so such a file yields zero mutants
/// and cargo-mutants writes no `outcomes.json` at all — the gate then died
/// reading a missing path under a temp directory, taking the whole package's
/// run with it and reporting nothing about the files that did have mutants.
/// `crates/mvm-cli/src/commands/tests.rs` is the case in point: 165 KB behind
/// `#![cfg(test)]`, reached because `commands/mod.rs` declares `mod tests;`.
///
/// Matched on the inner attribute rather than the filename, because it is the
/// attribute and not the name that decides whether anything compiles outside
/// test.
fn is_test_only_module(content: &str) -> bool {
    content
        .lines()
        .map(str::trim)
        .any(|line| line == "#![cfg(test)]")
}

fn workspace_relative(workspace: &Path, path: &Path) -> Option<String> {
    let rel = path.strip_prefix(workspace).ok()?;
    Some(rel.to_string_lossy().replace('\\', "/"))
}

/// Human-readable differences between the pinned and resolved surfaces.
pub fn diff_surface(committed: &[SurfaceFile], resolved: &[SurfaceFile]) -> Vec<String> {
    let mut errors = Vec::new();
    let by_path = |v: &[SurfaceFile]| -> BTreeMap<String, SurfaceFile> {
        v.iter().map(|s| (s.path.clone(), s.clone())).collect()
    };
    let old = by_path(committed);
    let new = by_path(resolved);

    for path in new.keys() {
        if !old.contains_key(path) {
            errors.push(format!("surface gained {path} (not in the committed pin)"));
        }
    }
    for (path, was) in &old {
        match new.get(path) {
            None => errors.push(format!(
                "surface lost {path} — claim(s) {:?} no longer resolve there, so they have \
                 dropped out of mutation coverage",
                was.claims
            )),
            Some(now) if now.claims != was.claims => errors.push(format!(
                "surface {path} changed claims {:?} -> {:?}",
                was.claims, now.claims
            )),
            Some(now) if now.package != was.package => errors.push(format!(
                "surface {path} changed package {} -> {}",
                was.package, now.package
            )),
            Some(_) => {}
        }
    }
    errors
}

/// Differences between the pinned and resolved uncovered-claim sets.
///
/// A claim gaining coverage is progress and only worth re-pinning; a
/// claim *losing* it means the nightly lane silently stopped asking
/// anything about that claim.
pub fn diff_uncovered(committed: &[UncoveredClaim], resolved: &[UncoveredClaim]) -> Vec<String> {
    let old: BTreeSet<u32> = committed.iter().map(|u| u.number).collect();
    let mut errors = Vec::new();
    for u in resolved {
        if !old.contains(&u.number) {
            errors.push(format!(
                "claim {} lost its mutation surface ({}) — the nightly lane no longer asks \
                 anything about it",
                u.number, u.why
            ));
        }
    }
    let now: BTreeSet<u32> = resolved.iter().map(|u| u.number).collect();
    for n in old.difference(&now) {
        errors.push(format!(
            "claim {n} gained a mutation surface — re-pin so the baseline records it"
        ));
    }
    errors
}

/// Copy each committed file's `scope` onto the freshly resolved surface.
///
/// Resolution cannot derive a scope, so without this every re-pin would
/// drop the narrowings and silently re-admit the code they exclude.
pub fn carry_scopes_forward(
    mut resolved: Vec<SurfaceFile>,
    previous: Option<&Baseline>,
) -> Vec<SurfaceFile> {
    let Some(previous) = previous else {
        return resolved;
    };
    let scopes: BTreeMap<&str, &SurfaceScope> = previous
        .surface
        .iter()
        .filter_map(|s| s.scope.as_ref().map(|sc| (s.path.as_str(), sc)))
        .collect();
    let features: BTreeMap<&str, &Vec<String>> = previous
        .surface
        .iter()
        .filter(|s| !s.features.is_empty())
        .map(|s| (s.path.as_str(), &s.features))
        .collect();
    for file in &mut resolved {
        if let Some(scope) = scopes.get(file.path.as_str()) {
            file.scope = Some((*scope).clone());
        }
        if let Some(f) = features.get(file.path.as_str()) {
            file.features = (*f).clone();
        }
    }
    resolved
}

/// Every narrowed surface must say why, and where the excluded code's
/// coverage is tracked. A scope without either is a claim quietly
/// shrinking to fit its evidence.
pub fn check_scope_reasons(surface: &[SurfaceFile]) -> Vec<String> {
    let mut errors = Vec::new();
    for file in surface {
        let Some(scope) = &file.scope else { continue };
        if scope.examine_re.trim().is_empty() {
            errors.push(format!(
                "surface {} has an empty scope regex — remove the scope rather than                  narrowing to nothing",
                file.path
            ));
        }
        if scope.why.trim().is_empty() {
            errors.push(format!(
                "surface {} is scoped with no stated reason — say why the rest of the                  file is not claim {:?}'s surface",
                file.path, file.claims
            ));
        }
        if scope.excluded_tracked_by.trim().is_empty() {
            errors.push(format!(
                "surface {} is scoped without naming where the excluded code's coverage                  is tracked — narrowing must record the debt, not discharge it",
                file.path
            ));
        }
    }
    errors
}

/// Every accepted miss must say why. An unexplained entry is how a
/// ratchet baseline degrades into a suppression list.
pub fn check_accepted_reasons(accepted: &[AcceptedMiss]) -> Vec<String> {
    accepted
        .iter()
        .filter(|a| a.reason.trim().is_empty())
        .map(|a| {
            format!(
                "accepted miss {} :: {} has no reason — state why the hole is tolerable",
                a.file, a.mutant
            )
        })
        .collect()
}

/// Every accepted miss must belong to a file on the pinned mutation surface.
///
/// Without this check, moving enforcement code to another crate leaves the old
/// entries inert: package shards filter accepted misses by their current files,
/// so the moved mutants are reported as new while the stale debt remains hidden.
pub fn check_accepted_files_on_surface(
    surface: &[SurfaceFile],
    accepted: &[AcceptedMiss],
) -> Vec<String> {
    let surface_paths: BTreeSet<&str> = surface.iter().map(|file| file.path.as_str()).collect();
    accepted
        .iter()
        .map(|miss| miss.file.as_str())
        .filter(|file| !surface_paths.contains(file))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|file| {
            format!(
                "accepted misses for {file} are outside the pinned mutation surface — remove them or migrate them to the current enforcement file"
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn accepted(file: &str, mutant: &str) -> AcceptedMiss {
        AcceptedMiss {
            file: file.into(),
            mutant: mutant.into(),
            reason: "known".into(),
        }
    }

    fn surface(path: &str, claims: Vec<u32>) -> SurfaceFile {
        SurfaceFile {
            path: path.into(),
            package: package_for(path).unwrap_or_else(|| "unknown".into()),
            claims,
            scope: None,
            features: Vec::new(),
        }
    }

    fn scoped(path: &str, examine_re: &str, why: &str, tracked: &str) -> SurfaceFile {
        SurfaceFile {
            path: path.into(),
            package: package_for(path).unwrap_or_else(|| "unknown".into()),
            claims: vec![2],
            features: Vec::new(),
            scope: Some(SurfaceScope {
                examine_re: examine_re.into(),
                why: why.into(),
                excluded_tracked_by: tracked.into(),
            }),
        }
    }

    fn uncovered(number: u32) -> UncoveredClaim {
        UncoveredClaim {
            number,
            why: WHY_NO_FN_WITNESS.to_string(),
        }
    }

    /// A temp workspace carrying just a claims ledger with `rows`.
    fn ledger_tree(rows: &str) -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        let adr = tmp.path().join("specs").join("adrs");
        std::fs::create_dir_all(&adr).unwrap();
        std::fs::write(
            adr.join("001-microvm-security-posture.md"),
            format!(
                "<!-- claims-catalog:begin -->\n\
                 | # | Claim | Witnesses | Authority | Status |\n\
                 |---|-------|-----------|-----------|--------|\n\
                 {rows}<!-- claims-catalog:end -->\n"
            ),
        )
        .unwrap();
        tmp
    }

    #[test]
    fn package_derivation_handles_flat_and_nested_crates() {
        assert_eq!(
            package_for("crates/mvm-contract/src/policy/network_policy.rs").as_deref(),
            Some("mvm-contract")
        );
        assert_eq!(
            package_for("crates/deps/libkrun-sys/src/sys.rs").as_deref(),
            Some("libkrun-sys")
        );
        assert_eq!(package_for("src/lib.rs"), None);
        assert_eq!(package_for("xtask/src/main.rs"), None);
    }

    #[test]
    fn integration_tests_are_not_part_of_the_surface() {
        assert!(is_integration_test("crates/mvm-cli/tests/cli.rs"));
        assert!(!is_integration_test("crates/mvm-cli/src/lib.rs"));
    }

    #[test]
    fn accepted_misses_must_belong_to_the_pinned_surface() {
        let pinned = vec![surface("crates/a/src/live.rs", vec![1])];
        let accepted = vec![
            accepted("crates/a/src/live.rs", "replace live"),
            accepted("crates/a/src/moved.rs", "replace moved one"),
            accepted("crates/a/src/moved.rs", "replace moved two"),
        ];

        let errors = check_accepted_files_on_surface(&pinned, &accepted);

        assert_eq!(
            errors.len(),
            1,
            "one error per stale file keeps output concise"
        );
        assert!(errors[0].contains("crates/a/src/moved.rs"));
        assert!(errors[0].contains("outside the pinned mutation surface"));
    }

    #[test]
    fn accepted_misses_on_the_pinned_surface_are_valid() {
        let pinned = vec![surface("crates/a/src/live.rs", vec![1])];
        let accepted = vec![accepted("crates/a/src/live.rs", "replace live")];

        assert!(check_accepted_files_on_surface(&pinned, &accepted).is_empty());
    }

    #[test]
    fn surface_diff_is_empty_when_pinned() {
        let s = vec![surface("crates/a/src/l.rs", vec![1])];
        assert!(diff_surface(&s, &s).is_empty());
    }

    #[test]
    fn surface_diff_reports_a_lost_file_as_lost_coverage() {
        let old = vec![surface("crates/a/src/l.rs", vec![10])];
        let errs = diff_surface(&old, &[]);
        assert_eq!(errs.len(), 1);
        assert!(errs[0].contains("surface lost"));
        assert!(errs[0].contains("dropped out of mutation coverage"));
    }

    #[test]
    fn surface_diff_reports_a_gained_file() {
        let new = vec![surface("crates/a/src/l.rs", vec![1])];
        let errs = diff_surface(&[], &new);
        assert_eq!(errs.len(), 1);
        assert!(errs[0].contains("surface gained"));
    }

    #[test]
    fn surface_diff_reports_a_claim_set_change() {
        let old = vec![surface("crates/a/src/l.rs", vec![1])];
        let new = vec![surface("crates/a/src/l.rs", vec![1, 2])];
        let errs = diff_surface(&old, &new);
        assert_eq!(errs.len(), 1);
        assert!(errs[0].contains("changed claims"));
    }

    #[test]
    fn an_unscoped_surface_file_needs_no_justification() {
        assert!(check_scope_reasons(&[surface("crates/a/src/l.rs", vec![1])]).is_empty());
    }

    #[test]
    fn a_scope_must_state_why_and_where_the_rest_is_tracked() {
        let ok = scoped(
            "crates/a/src/l.rs",
            "virtiofs",
            "one witness, big file",
            "#123",
        );
        assert!(check_scope_reasons(&[ok]).is_empty());

        let no_why = scoped("crates/a/src/l.rs", "virtiofs", "   ", "#123");
        let errs = check_scope_reasons(&[no_why]);
        assert_eq!(errs.len(), 1);
        assert!(errs[0].contains("no stated reason"), "{}", errs[0]);

        let no_tracking = scoped("crates/a/src/l.rs", "virtiofs", "because", "");
        let errs = check_scope_reasons(&[no_tracking]);
        assert_eq!(errs.len(), 1);
        assert!(errs[0].contains("record the debt"), "{}", errs[0]);

        let empty_re = scoped("crates/a/src/l.rs", "", "because", "#123");
        let errs = check_scope_reasons(&[empty_re]);
        assert_eq!(errs.len(), 1);
        assert!(errs[0].contains("narrowing to nothing"), "{}", errs[0]);
    }

    /// A re-pin resolves the surface afresh, and resolution never yields a
    /// scope. Without carrying them forward, routine maintenance would
    /// silently widen every narrowed file back out.
    #[test]
    fn repinning_carries_a_scope_forward() {
        let previous = Baseline {
            surface: vec![scoped("crates/a/src/l.rs", "virtiofs", "why", "#123")],
            uncovered_claims: vec![],
            accepted_misses: vec![],
        };
        let resolved = vec![surface("crates/a/src/l.rs", vec![2])];
        assert!(resolved[0].scope.is_none());

        let carried = carry_scopes_forward(resolved, Some(&previous));
        assert_eq!(
            carried[0].scope.as_ref().map(|s| s.examine_re.as_str()),
            Some("virtiofs")
        );
    }

    #[test]
    fn carrying_forward_leaves_unscoped_files_alone() {
        let previous = Baseline {
            surface: vec![scoped("crates/a/src/l.rs", "virtiofs", "why", "#123")],
            uncovered_claims: vec![],
            accepted_misses: vec![],
        };
        let carried = carry_scopes_forward(
            vec![surface("crates/b/src/other.rs", vec![9])],
            Some(&previous),
        );
        assert!(carried[0].scope.is_none());
    }

    #[test]
    fn accepted_misses_must_state_a_reason() {
        let bad = vec![AcceptedMiss {
            file: "a.rs".into(),
            mutant: "replace x".into(),
            reason: "  ".into(),
        }];
        let errs = check_accepted_reasons(&bad);
        assert_eq!(errs.len(), 1);
        assert!(errs[0].contains("no reason"));
        assert!(check_accepted_reasons(&[accepted("a.rs", "replace x")]).is_empty());
    }

    #[test]
    fn surface_resolves_witnesses_to_their_declaring_file() {
        let tmp = ledger_tree(
            "\
| 1 | one | fn:enforces_it, ci:some-lane | auth | Shipped |
| 2 | two | fn:elsewhere | auth | Shipped |
",
        );
        let src = tmp.path().join("crates").join("demo").join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("lib.rs"), "fn enforces_it() {}\n").unwrap();
        std::fs::write(src.join("other.rs"), "fn elsewhere() {}\n").unwrap();
        // An integration test naming the same witness must not widen
        // the surface: cargo-mutants never mutates a test target.
        let itest = tmp.path().join("crates").join("demo").join("tests");
        std::fs::create_dir_all(&itest).unwrap();
        std::fs::write(itest.join("it.rs"), "fn enforces_it() {}\n").unwrap();

        let surface = resolve_surface(tmp.path()).unwrap();
        let paths: Vec<&str> = surface.files.iter().map(|s| s.path.as_str()).collect();
        assert_eq!(
            paths,
            ["crates/demo/src/lib.rs", "crates/demo/src/other.rs"]
        );
        assert_eq!(surface.files[0].claims, vec![1]);
        assert_eq!(surface.files[0].package, "demo");
        assert_eq!(surface.files[1].claims, vec![2]);
        assert!(surface.uncovered.is_empty());
    }

    /// A claim witnessed only by a CI lane has nothing to mutate. That is
    /// legitimate, but it must be reported rather than silently absent.
    #[test]
    fn a_ci_only_claim_is_reported_as_uncovered() {
        let tmp = ledger_tree(
            "\
| 1 | one | fn:enforces_it | auth | Shipped |
| 2 | two | ci:some-lane | auth | Shipped |
",
        );
        let src = tmp.path().join("crates").join("demo").join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("lib.rs"), "fn enforces_it() {}\n").unwrap();

        let surface = resolve_surface(tmp.path()).unwrap();
        assert_eq!(surface.files.len(), 1);
        assert_eq!(surface.uncovered.len(), 1);
        assert_eq!(surface.uncovered[0].number, 2);
        assert_eq!(surface.uncovered[0].why, WHY_NO_FN_WITNESS);
    }

    /// A claim whose only `fn:` witnesses are integration tests gets no
    /// mutation surface, because cargo-mutants does not mutate test
    /// targets. Distinguished from the CI-only case so the report says
    /// which fix applies.
    #[test]
    fn an_integration_test_only_claim_is_reported_as_uncovered() {
        let tmp = ledger_tree(
            "\
| 1 | one | fn:enforces_it | auth | Shipped |
| 2 | two | fn:only_in_a_test | auth | Shipped |
",
        );
        let demo = tmp.path().join("crates").join("demo");
        std::fs::create_dir_all(demo.join("src")).unwrap();
        std::fs::create_dir_all(demo.join("tests")).unwrap();
        std::fs::write(demo.join("src").join("lib.rs"), "fn enforces_it() {}\n").unwrap();
        std::fs::write(demo.join("tests").join("it.rs"), "fn only_in_a_test() {}\n").unwrap();

        let surface = resolve_surface(tmp.path()).unwrap();
        assert_eq!(surface.uncovered.len(), 1);
        assert_eq!(surface.uncovered[0].number, 2);
        assert_eq!(surface.uncovered[0].why, WHY_ONLY_INTEGRATION_TESTS);
    }

    /// A `#![cfg(test)]` module file stays off the surface, and a claim that
    /// has other witnesses keeps its coverage.
    ///
    /// Resolution assumes the file declaring a witness is the enforcement code
    /// the witness guards. A separate tests module breaks that assumption, and
    /// the failure is not a weak measurement but a dead shard: cargo-mutants
    /// mutates no test code, so it writes no `outcomes.json`, and the gate used
    /// to die reading that missing path — losing every other file in the same
    /// package's run along with it.
    #[test]
    fn a_test_only_module_file_is_not_mutation_surface() {
        let tmp = ledger_tree(
            "\
| 1 | one | fn:enforces_it, fn:also_checked_in_the_tests_module | auth | Shipped |
",
        );
        let demo = tmp.path().join("crates").join("demo").join("src");
        std::fs::create_dir_all(&demo).unwrap();
        std::fs::write(demo.join("lib.rs"), "fn enforces_it() {}\n").unwrap();
        std::fs::write(
            demo.join("tests.rs"),
            "#![cfg(test)]\nfn also_checked_in_the_tests_module() {}\n",
        )
        .unwrap();

        let surface = resolve_surface(tmp.path()).unwrap();
        let paths: Vec<&str> = surface.files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(
            paths,
            vec!["crates/demo/src/lib.rs"],
            "the tests module has nothing cargo-mutants would mutate"
        );
        assert!(
            surface.uncovered.is_empty(),
            "claim 1 still resolves to enforcement code, so it is not uncovered"
        );
    }

    /// A claim witnessed *only* from a tests module has no surface at all, and
    /// says which kind of test-only code it landed in.
    #[test]
    fn a_claim_witnessed_only_from_a_tests_module_is_reported_as_uncovered() {
        let tmp = ledger_tree(
            "\
| 1 | one | fn:enforces_it | auth | Shipped |
| 2 | two | fn:only_in_the_tests_module | auth | Shipped |
",
        );
        let demo = tmp.path().join("crates").join("demo").join("src");
        std::fs::create_dir_all(&demo).unwrap();
        std::fs::write(demo.join("lib.rs"), "fn enforces_it() {}\n").unwrap();
        std::fs::write(
            demo.join("tests.rs"),
            "#![cfg(test)]\nfn only_in_the_tests_module() {}\n",
        )
        .unwrap();

        let surface = resolve_surface(tmp.path()).unwrap();
        assert_eq!(surface.uncovered.len(), 1);
        assert_eq!(surface.uncovered[0].number, 2);
        assert_eq!(surface.uncovered[0].why, WHY_ONLY_INTEGRATION_TESTS);
    }

    /// Only the inner attribute counts. A file with ordinary `#[cfg(test)] mod
    /// tests` beside its implementation is exactly the shape resolution is
    /// built around, and dropping it would silently delete real surface.
    #[test]
    fn an_inline_test_module_does_not_make_the_file_test_only() {
        assert!(is_test_only_module("#![cfg(test)]\nfn a() {}\n"));
        assert!(is_test_only_module("//! docs\n\n  #![cfg(test)]\n"));
        assert!(!is_test_only_module(
            "fn enforce() {}\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn t() {}\n}\n"
        ));
        assert!(!is_test_only_module("fn enforce() {}\n"));
    }

    #[test]
    fn uncovered_diff_fails_when_a_claim_loses_its_surface() {
        let errs = diff_uncovered(&[], &[uncovered(10)]);
        assert_eq!(errs.len(), 1);
        assert!(errs[0].contains("claim 10 lost its mutation surface"));
    }

    #[test]
    fn uncovered_diff_asks_for_a_repin_when_a_claim_gains_a_surface() {
        let errs = diff_uncovered(&[uncovered(10)], &[]);
        assert_eq!(errs.len(), 1);
        assert!(errs[0].contains("gained a mutation surface"));
    }

    #[test]
    fn uncovered_diff_is_empty_when_pinned() {
        let pinned = [uncovered(4), uncovered(5)];
        assert!(diff_uncovered(&pinned, &pinned).is_empty());
    }

    #[test]
    fn one_file_serving_two_claims_records_both() {
        let tmp = ledger_tree(
            "\
| 1 | one | fn:alpha | auth | Shipped |
| 2 | two | fn:beta | auth | Shipped |
",
        );
        let src = tmp.path().join("crates").join("demo").join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("lib.rs"), "fn alpha() {}\nfn beta() {}\n").unwrap();

        let surface = resolve_surface(tmp.path()).unwrap();
        assert_eq!(surface.files.len(), 1);
        assert_eq!(surface.files[0].claims, vec![1, 2]);
    }
}
