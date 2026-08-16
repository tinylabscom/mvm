//! `xtask check-single-host-predicate`
//!
//! Whether a destination is bound by a secret's `allowed_hosts` set is decided
//! in exactly one place: `host_is_bound` (over the set) and `host_matches`
//! (over one pattern), both in `crates/mvm-contract/src/ir/workload.rs`. Every
//! enforcement point calls them.
//!
//! A second copy of that quantifier is a second decision, and the two can
//! disagree — at which point which credentials a destination can reach depends
//! on the code path the request took. That is not hypothetical here: a second
//! copy did exist (`decide_substitution`, an exact `==` where the live
//! predicate is a case-insensitive wildcard match), it had no callers, and the
//! security prose described *it* rather than the live path. This gate exists so
//! that cannot recur silently.
//!
//! The rule: outside the owner file, no production source may iterate or search
//! an `allowed_hosts` set itself. Reading the field, cloning it, building it, or
//! handing it to `host_is_bound` are all fine — writing the quantifier is not.
//!
//! Test code is exempt, decided textually the same way
//! `check-single-exec-secs-writer` decides it: a file under a `tests/`
//! directory, a file named `test_support.rs`, and everything from a file's
//! first `#[cfg(test)]` attribute onward. A gate that fired on fixtures would
//! be turned off rather than obeyed.
//!
//! Two files carry a same-named field that is a different concept, and are
//! exempted by name rather than silently skipped — see [`EXEMPT`]. Each is
//! checked to still exist, so an exemption cannot go stale unnoticed.
//!
//! Known and accepted limit: a re-implementation that first rebinds the set to
//! another name (`let hs = &meta.allowed_hosts; hs.iter().any(…)`) is a
//! different shape and is not detectable by a text gate. It has to be caught in
//! review — as does any comparison written against a host that never names the
//! set at all.

use anyhow::{Result, bail};
use std::path::Path;

/// The sole file permitted to quantify over an `allowed_hosts` set.
const OWNER_FILE: &str = "crates/mvm-contract/src/ir/workload.rs";

/// The predicates the owner must define. Named here so the gate fails closed if
/// the owner stops owning them and the quantifier moves somewhere unpinned.
const PREDICATES: [&str; 2] = ["fn host_is_bound", "fn host_matches"];

/// The set whose traversal is reserved.
const FIELD: &str = "allowed_hosts";

/// Traversals that constitute writing the quantifier yourself.
const TRAVERSALS: [&str; 4] = [".iter()", ".contains(", ".any(", ".find("];

/// Roots to scan. Root `src/` is the facade and `tests/` holds workspace-level
/// integration tests; either could host a second predicate as easily as
/// `crates/`.
const ROOTS: [&str; 3] = ["crates", "src", "tests"];

/// Files holding an `allowed_hosts` that is **not** a secret's destination
/// binding. Exempt by name, with the reason, because a text gate matches a
/// field name and cannot see a type.
///
/// Both are checked to still exist: an exemption for a deleted file is an
/// exemption nobody reconsidered.
const EXEMPT: [(&str, &str); 2] = [
    (
        "crates/mvm-client/src/secret.rs",
        "validates an allow-list's shape at `secret set` time (rejects an empty \
         entry); decides nothing about a destination",
    ),
    (
        "crates/mvm-hostd/src/supervisor/tools/web_fetch.rs",
        "`WebFetchTool`'s own per-tenant fetch allow-list — a different policy \
         surface over exact hosts, not a secret's destination binding",
    ),
];

pub fn run(workspace: &Path) -> Result<()> {
    let owner = workspace.join(OWNER_FILE);
    let body = std::fs::read_to_string(&owner)
        .map_err(|e| anyhow::anyhow!("the host predicate is missing at {OWNER_FILE}: {e}"))?;
    for predicate in PREDICATES {
        if !body.contains(predicate) {
            bail!(
                "{OWNER_FILE} no longer defines `{predicate}`; the host-binding \
                 predicate must stay in one place, so move it back or update \
                 this gate deliberately"
            );
        }
    }

    for (path, reason) in EXEMPT {
        if !workspace.join(path).is_file() {
            bail!(
                "the exemption for {path} ({reason}) names a file that no longer \
                 exists; drop the exemption or point it at the file that replaced it"
            );
        }
    }

    let mut offenders = Vec::new();
    for root in ROOTS {
        let dir = workspace.join(root);
        if !dir.is_dir() {
            continue;
        }
        crate::fs_walk::for_each_file(&dir, Some("rs"), &mut |path, body| {
            let rel = path
                .strip_prefix(workspace)
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/");
            if rel == OWNER_FILE || is_test_path(&rel) || EXEMPT.iter().any(|(p, _)| *p == rel) {
                return;
            }
            for (line_no, line) in production_lines(body) {
                if traverses_the_set(line) {
                    offenders.push(format!("{rel}:{line_no}: {}", line.trim()));
                }
            }
        })?;
    }

    if !offenders.is_empty() {
        bail!(
            "a second host-binding predicate exists in:\n  {}\n\
             Whether a destination is bound is decided by `host_is_bound` in \
             {OWNER_FILE} and nowhere else. Call it instead of re-deciding: two \
             copies disagree eventually, and the disagreement surfaces as a \
             credential reaching a destination it should not.",
            offenders.join("\n  ")
        );
    }
    Ok(())
}

/// Whether a path is test-only by location or by name.
fn is_test_path(rel: &str) -> bool {
    rel.split('/').any(|seg| seg == "tests")
        || rel.ends_with("/test_support.rs")
        || rel.ends_with("/fuzz_targets")
}

/// The `(1-indexed line number, line)` pairs that precede a file's first test
/// module. Everything from that attribute onward is test code.
fn production_lines(body: &str) -> Vec<(usize, &str)> {
    body.lines()
        .enumerate()
        .take_while(|(_, line)| {
            let t = line.trim_start();
            !(t.starts_with("#[cfg(test)]") || t.starts_with("#[cfg(any(test"))
        })
        .map(|(i, line)| (i + 1, line))
        .collect()
}

/// Whether one line traverses an `allowed_hosts` set rather than delegating.
///
/// Only a traversal applied *directly* to the set counts. `allowed_hosts:
/// meta.allowed_hosts` (a move), `&secret_ref.allowed_hosts` (a borrow handed
/// onward), and `host_is_bound(&r.allowed_hosts, dest)` (the delegation this
/// gate exists to encourage) all name the field without deciding anything.
/// Comments are excluded so prose about the set is not a match.
fn traverses_the_set(line: &str) -> bool {
    let code = match line.find("//") {
        Some(i) => &line[..i],
        None => line,
    };
    let mut from = 0;
    while let Some(idx) = code[from..].find(FIELD) {
        let at = from + idx;
        let rest = &code[at + FIELD.len()..];
        if TRAVERSALS.iter().any(|t| rest.starts_with(t)) {
            return true;
        }
        from = at + FIELD.len();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passes_on_this_workspace() {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        run(&workspace).expect("the real tree carries exactly one host predicate");
    }

    #[test]
    fn a_stale_exemption_fails_closed() {
        let tmp = fixture("stale-exemption", OWNER_BODY, "");
        std::fs::remove_file(tmp.join(EXEMPT[0].0)).unwrap();
        let err = run(&tmp).unwrap_err();
        assert!(err.to_string().contains(EXEMPT[0].0), "{err}");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn an_exempt_file_may_traverse_its_own_set() {
        let tmp = fixture("exempt", OWNER_BODY, "");
        std::fs::write(
            tmp.join(EXEMPT[1].0),
            "pub fn f(&self, h: &str) -> bool { self.allowed_hosts.contains(h) }\n",
        )
        .unwrap();
        run(&tmp).expect("an exempt file carries a different concept");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn missing_owner_file_fails_closed() {
        let tmp = scratch("missing");
        std::fs::create_dir_all(&tmp).unwrap();
        let err = run(&tmp).unwrap_err();
        assert!(err.to_string().contains(OWNER_FILE));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn an_owner_that_stopped_owning_the_predicate_is_caught() {
        let tmp = fixture("moved-away", "pub fn host_matches() {}", "");
        let err = run(&tmp).unwrap_err();
        assert!(err.to_string().contains("host_is_bound"), "{err}");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn a_second_any_quantifier_is_caught() {
        let tmp = fixture(
            "second-any",
            OWNER_BODY,
            "pub fn sneaky(r: &SecretRef, d: &str) -> bool {\n    \
             r.allowed_hosts.iter().any(|h| h == d)\n}\n",
        );
        let err = run(&tmp).unwrap_err();
        assert!(
            err.to_string().contains("crates/mvm-core/src/lib.rs"),
            "{err}"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn a_second_contains_check_is_caught() {
        // The shape the deleted `decide_substitution` had: a direct membership
        // test standing in for the wildcard predicate.
        let tmp = fixture(
            "second-contains",
            OWNER_BODY,
            "pub fn sneaky(m: &Meta, d: &str) -> bool { m.allowed_hosts.contains(&d.to_string()) }\n",
        );
        let err = run(&tmp).unwrap_err();
        assert!(err.to_string().contains("sneaky"), "{err}");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn delegating_to_the_predicate_is_allowed() {
        let tmp = fixture(
            "delegates",
            OWNER_BODY,
            "pub fn ok(r: &SecretRef, d: &str) -> bool { host_is_bound(&r.allowed_hosts, d) }\n",
        );
        run(&tmp).expect("calling the predicate is the point of the gate");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn moving_or_declaring_the_field_is_not_a_predicate() {
        let tmp = fixture(
            "moves",
            OWNER_BODY,
            "pub struct Meta {\n    pub allowed_hosts: Vec<String>,\n}\n\
             pub fn build(m: Meta) -> SecretRef {\n    \
             SecretRef { allowed_hosts: m.allowed_hosts }\n}\n",
        );
        run(&tmp).expect("declaring and moving the set decides nothing");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn a_test_module_fixture_is_not_a_predicate() {
        let tmp = fixture(
            "test-module",
            OWNER_BODY,
            "#[cfg(test)]\nmod tests {\n    fn f(r: &SecretRef) -> bool { \
             r.allowed_hosts.iter().any(|h| h == \"x\") }\n}\n",
        );
        run(&tmp).expect("a fixture asserts on the predicate, it does not compete");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn a_comment_about_the_set_is_not_a_predicate() {
        let tmp = fixture(
            "comment",
            OWNER_BODY,
            "// allowed_hosts.iter().any(..) is how this used to be decided\npub fn f() {}\n",
        );
        run(&tmp).expect("prose is not a decision");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// An owner body carrying both required predicates.
    const OWNER_BODY: &str = "pub fn host_matches(p: &str, h: &str) -> bool { p == h }\n\
         pub fn host_is_bound(hs: &[String], d: &str) -> bool { \
         hs.iter().any(|p| host_matches(p, d)) }\n";

    fn scratch(label: &str) -> std::path::PathBuf {
        let tmp = std::env::temp_dir().join(format!(
            "xtask-single-host-predicate-{label}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        tmp
    }

    /// A fake workspace: the owner file holding `owner_body`, plus one other
    /// production file holding `other`.
    fn fixture(label: &str, owner_body: &str, other: &str) -> std::path::PathBuf {
        let tmp = scratch(label);
        let owner_dir = tmp.join("crates/mvm-contract/src/ir");
        std::fs::create_dir_all(&owner_dir).unwrap();
        std::fs::write(owner_dir.join("workload.rs"), owner_body).unwrap();

        let other_dir = tmp.join("crates/mvm-core/src");
        std::fs::create_dir_all(&other_dir).unwrap();
        std::fs::write(other_dir.join("lib.rs"), other).unwrap();

        for (path, _) in EXEMPT {
            let f = tmp.join(path);
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(&f, "").unwrap();
        }
        tmp
    }
}
