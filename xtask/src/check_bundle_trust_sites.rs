//! `xtask check-bundle-trust-sites`
//!
//! The official bundle-author keys pinned in the client apply only to an
//! installed application, and only where a call site composes them
//! (`trust_for_installed_bundle`, `BuiltinAuthorTrust::for_policy`). A site that
//! verifies a bundle against the raw `FsTrustStore` silently refuses an
//! official application at launch, and no runtime test notices. This gate
//! freezes the set of production files that build the raw store:
//!
//! - `MUST_COMPOSE`: files that handle an application bundle and must contain a
//!   composing call, so reverting one to the raw store fails here.
//! - `MUST_DELEGATE`: the canonical verifier receives already-classified trust
//!   from its callers rather than constructing publisher policy itself.
//! - `RAW_ALLOWED`: files that legitimately use the raw store, each with the
//!   reason it is not an application-bundle path.
//!
//! Any other non-test file under `crates/*/src` that calls
//! `FsTrustStore::default_path` fails.

use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};

const RAW_CALL: &str = "FsTrustStore::default_path";
const COMPOSING_CALLS: &[&str] = &[
    "trust_for_installed_archive(",
    "trust_for_installed_bundle(",
    "BuiltinAuthorTrust::for_policy(",
];

/// Files that verify an application bundle and must compose the pinned keys.
const MUST_COMPOSE: &[&str] = &[
    "crates/mvm-hostd/src/supervisor/caller_registration.rs",
    "crates/mvm-client/src/admission/pinned_bundle.rs",
    "crates/mvm-client/src/launch/bundle_runtime.rs",
    "crates/mvm-client/src/launch/canonical_linux.rs",
    "crates/mvm-runtime/src/vm/template/lifecycle/snapshot.rs",
    "crates/mvm-cli/src/pack_registry.rs",
    "crates/mvm-cli/src/commands/pack/inspect.rs",
    "crates/mvm-cli/src/commands/vm/exec/composition.rs",
];

const MUST_DELEGATE: &str = "crates/mvm-core/src/canonical_linux.rs";

/// Files that use the raw store, with why that is not an application path.
const RAW_ALLOWED: &[(&str, &str)] = &[
    (
        "crates/mvm-core/src/plan/bundle/lookup.rs",
        "defines FsTrustStore",
    ),
    (
        "crates/mvm-core/src/plan/bundle.rs",
        "documentation of the store",
    ),
    (
        "crates/mvm-client/src/instruction_trust/gate.rs",
        "instruction policy trust, not a bundle",
    ),
    (
        "crates/mvm-client/src/entrypoint/foreground_diagnostic.rs",
        "diagnostic pack key check, not an application",
    ),
    (
        "crates/mvm-hostd/src/plan_admission/registry_pack.rs",
        "calls resolve_installed_application_bundle, which composes internally",
    ),
    (
        "crates/mvm-runtime/src/legacy_bundle_runtime.rs",
        "legacy runtime bundle, never an application",
    ),
    (
        "crates/mvm-runtime/src/legacy_portable_runtime.rs",
        "legacy portable runtime bundle, never an application",
    ),
    (
        "crates/mvm-cli/src/commands/bundle/push.rs",
        "publishes a bundle the operator signed",
    ),
    (
        "crates/mvm-cli/src/commands/bundle/export.rs",
        "exports a bundle under operator trust",
    ),
    (
        "crates/mvm-cli/src/commands/bundle/fetch.rs",
        "application path composes inside load_application_bundle",
    ),
    (
        "crates/mvm-cli/src/commands/bundle/install.rs",
        "operator-supplied bundle install under operator trust",
    ),
    (
        "crates/mvm-cli/src/commands/vm/exec/application_source.rs",
        "calls resolve_installed_application, which composes internally",
    ),
    (
        "crates/mvm-cli/src/commands/machine/portable.rs",
        "operator-supplied portable bundle, never an application",
    ),
    (
        "crates/mvm-cli/src/commands/trust/mod.rs",
        "the enrollment commands themselves",
    ),
];

pub(crate) fn run(workspace: &Path) -> Result<()> {
    let mut paths = Vec::new();
    collect(&workspace.join("crates"), &mut paths)?;
    let mut files = Vec::new();
    for path in paths {
        let rel = path
            .strip_prefix(workspace)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        if !is_production_source(&rel) {
            continue;
        }
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        files.push((rel, text));
    }
    let problems = problems(&files);
    if !problems.is_empty() {
        bail!(
            "check-bundle-trust-sites: {} problem(s):\n  {}\n\
             Compose the pinned author keys with `trust_for_installed_bundle` (unknown bundle \
             kind) or `BuiltinAuthorTrust::for_policy` (known application), or add the file to \
             RAW_ALLOWED in xtask/src/check_bundle_trust_sites.rs with the reason it is not an \
             application path.",
            problems.len(),
            problems.join("\n  ")
        );
    }
    eprintln!(
        "check-bundle-trust-sites: clean ({} composing site(s), {} raw-store file(s) allowlisted)",
        MUST_COMPOSE.len(),
        RAW_ALLOWED.len()
    );
    Ok(())
}

fn is_production_source(rel: &str) -> bool {
    rel.contains("/src/")
        && !rel.contains("/tests/")
        && !rel.ends_with("tests.rs")
        && !rel.ends_with("_tests.rs")
        && !rel.contains("/bin/")
}

/// Text before the test module, which by convention closes the file: the first
/// `#[cfg(test)]` whose item is a `mod` with "test" in its name.
fn production_part(text: &str) -> &str {
    let re = regex::Regex::new(
        r"#\[cfg\(test\)\]\s*(?:#\[[^\]]*\]\s*)*(?:pub(?:\([a-z]+\))?\s+)?mod\s+\w*test",
    )
    .expect("static regex");
    re.find(text).map_or(text, |m| &text[..m.start()])
}

fn problems(files: &[(String, String)]) -> Vec<String> {
    let mut out = Vec::new();
    for (rel, text) in files {
        let body = production_part(text);
        let raw = body.contains(RAW_CALL);
        let composes = COMPOSING_CALLS.iter().any(|call| body.contains(call));
        let must = MUST_COMPOSE.contains(&rel.as_str());
        let allowed = RAW_ALLOWED.iter().any(|(file, _)| file == rel);
        if rel == MUST_DELEGATE
            && (!body.contains("trust: &dyn TrustStore")
                || !body.contains("capture_canonical_linux_inputs(archive, pin, trust)"))
        {
            out.push(format!(
                "{rel}: canonical capture no longer uses caller-classified trust"
            ));
        } else if must && !composes {
            out.push(format!(
                "{rel}: handles an application bundle but composes no pinned-key trust"
            ));
        } else if raw && !must && !allowed {
            out.push(format!(
                "{rel}: builds the raw FsTrustStore outside the allowlist"
            ));
        }
    }
    for entry in std::iter::once(MUST_DELEGATE)
        .chain(MUST_COMPOSE.iter().copied())
        .chain(RAW_ALLOWED.iter().map(|(file, _)| *file))
    {
        if !files.iter().any(|(rel, _)| rel == entry) {
            out.push(format!("{entry}: listed in the gate but no longer exists"));
        }
    }
    out
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let path = entry?.path();
        if path.is_dir() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name == "target" || name == ".git" {
                continue;
            }
            collect(&path, out)?;
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn corpus(overrides: &[(&str, &str)]) -> Vec<(String, String)> {
        let mut files: Vec<(String, String)> = MUST_COMPOSE
            .iter()
            .map(|f| (f.to_string(), "trust_for_installed_bundle(raw)".to_string()))
            .chain(std::iter::once((
                MUST_DELEGATE.to_string(),
                "trust: &dyn TrustStore; capture_canonical_linux_inputs(archive, pin, trust)"
                    .to_string(),
            )))
            .chain(
                RAW_ALLOWED
                    .iter()
                    .map(|(f, _)| (f.to_string(), String::new())),
            )
            .collect();
        for (name, text) in overrides {
            files.retain(|(f, _)| f != name);
            files.push((name.to_string(), text.to_string()));
        }
        files
    }

    #[test]
    fn the_declared_set_is_clean() {
        assert!(problems(&corpus(&[])).is_empty());
    }

    #[test]
    fn a_new_raw_call_outside_the_allowlist_fails() {
        let files = corpus(&[(
            "crates/mvm-client/src/new.rs",
            "FsTrustStore::default_path()?",
        )]);
        assert_eq!(problems(&files).len(), 1);
    }

    #[test]
    fn a_composing_site_reverted_to_the_raw_store_fails() {
        let files = corpus(&[(MUST_COMPOSE[0], "let t = FsTrustStore::default_path()?;")]);
        assert_eq!(problems(&files).len(), 1);
    }

    #[test]
    fn a_canonical_capture_that_ignores_caller_trust_fails() {
        let files = corpus(&[(
            MUST_DELEGATE,
            "capture_canonical_linux_inputs(archive, pin, &raw)",
        )]);
        assert_eq!(problems(&files).len(), 1);
    }

    #[test]
    fn a_raw_call_only_in_the_test_module_is_ignored() {
        let text =
            "fn f() {}\n#[cfg(test)]\nmod tests { fn x() { FsTrustStore::default_path(); } }";
        let files = corpus(&[("crates/mvm-client/src/new.rs", text)]);
        assert!(problems(&files).is_empty());
    }

    #[test]
    fn a_stale_entry_fails() {
        let mut files = corpus(&[]);
        files.retain(|(f, _)| f != RAW_ALLOWED[0].0);
        assert_eq!(problems(&files).len(), 1);
    }

    #[test]
    fn test_files_are_not_production_source() {
        assert!(!is_production_source("crates/a/src/x_tests.rs"));
        assert!(!is_production_source("crates/a/tests/x.rs"));
        assert!(is_production_source("crates/a/src/x.rs"));
    }
}
