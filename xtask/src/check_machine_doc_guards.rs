//! `xtask check-machine-doc-guards`
//!
//! Beginner machine docs hygiene lint. The docs must include explicit use-case
//! and limitation pages, and they must not imply that host Nix, GPU, ICMP, or
//! unsupported architectures are available by default.

use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};

const USE_CASES: &str = "public/src/content/docs/guides/machine-use-cases.md";
const LIMITATIONS: &str = "public/src/content/docs/guides/machine-limitations.md";
const QUICKSTART: &str = "public/src/content/docs/getting-started/quickstart.md";
const HAPPY_PATHS: &str = "public/src/content/docs/getting-started/happy-paths.md";

// `local image archive` was here until 2026-08-27, requiring the use-cases page
// to document a `--image-archive` input. No such flag has ever existed: no
// commit in this repository has touched `image-archive` under `crates/`, and
// `RunArgs` takes `--manifest`, `--image`, `--flake`, `--deployment`,
// `--runtime-pack`, and `--runtime` only. The guard was mandating a false
// claim, and the page complied for two months. A required term has to name
// something the CLI does; add the flag first if this capability is wanted.
const REQUIRED_USE_CASE_TERMS: &[&str] = &[
    "sandbox untrusted code",
    "mvmctl machine run --image",
    "mvmctl machine create",
    "mvm.toml",
    "machine check-artifact",
    "/guides/machine-limitations/",
];

const REQUIRED_LIMITATION_TERMS: &[&str] = &[
    "Host Nix",
    "Network Protocol Scope",
    "ICMP",
    "Volume Shapes",
    "No SSH, On Any Tier",
    "macOS Signing And Entitlements",
    "GPU Status",
    "Host And Guest Architecture Support",
    "machine check-artifact",
];

const BEGINNER_DOCS: &[&str] = &[USE_CASES, LIMITATIONS, QUICKSTART, HAPPY_PATHS];

#[derive(Debug)]
struct Finding {
    path: PathBuf,
    line: usize,
    message: String,
}

pub fn run(workspace: &Path) -> Result<()> {
    let use_cases = read_required(workspace, USE_CASES)?;
    let limitations = read_required(workspace, LIMITATIONS)?;

    let mut findings = Vec::new();
    require_terms(
        workspace.join(USE_CASES),
        &use_cases,
        REQUIRED_USE_CASE_TERMS,
        &mut findings,
    );
    require_terms(
        workspace.join(LIMITATIONS),
        &limitations,
        REQUIRED_LIMITATION_TERMS,
        &mut findings,
    );

    for rel in BEGINNER_DOCS {
        let source = read_required(workspace, rel)?;
        lint_beginner_doc(&workspace.join(rel), &source, &mut findings);
    }

    if findings.is_empty() {
        eprintln!("check-machine-doc-guards: clean");
        return Ok(());
    }

    eprintln!(
        "check-machine-doc-guards: {} finding(s) — keep beginner machine docs honest about host Nix, GPU, ICMP, and architecture limits",
        findings.len()
    );
    for finding in &findings {
        eprintln!(
            "  {}:{} — {}",
            finding.path.display(),
            finding.line,
            finding.message
        );
    }
    std::process::exit(1);
}

fn read_required(workspace: &Path, rel: &str) -> Result<String> {
    let path = workspace.join(rel);
    if !path.is_file() {
        bail!("required machine doc missing: {}", path.display());
    }
    std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))
}

fn require_terms(path: PathBuf, source: &str, terms: &[&str], findings: &mut Vec<Finding>) {
    let lower = source.to_ascii_lowercase();
    for term in terms {
        if !lower.contains(&term.to_ascii_lowercase()) {
            findings.push(Finding {
                path: path.clone(),
                line: 1,
                message: format!("missing required machine-doc term `{term}`"),
            });
        }
    }
}

fn lint_beginner_doc(path: &Path, source: &str, findings: &mut Vec<Finding>) {
    for (idx, line) in source.lines().enumerate() {
        let lower = line.to_ascii_lowercase();

        if lower.contains("host nix") && !line_allows_no_host_nix_claim(&lower) {
            findings.push(Finding {
                path: path.to_path_buf(),
                line: idx + 1,
                message: "host Nix mention must say it is not required for normal machine runs or is optional/builder-scoped".into(),
            });
        }

        if lower.contains("gpu") && !line_marks_unsupported_or_future(&lower) {
            findings.push(Finding {
                path: path.to_path_buf(),
                line: idx + 1,
                message: "GPU mention must be explicitly unsupported, future, or non-default"
                    .into(),
            });
        }

        if lower.contains("icmp") && !line_marks_unsupported_or_future(&lower) {
            findings.push(Finding {
                path: path.to_path_buf(),
                line: idx + 1,
                message: "ICMP mention must be explicitly unsupported, future, or non-default"
                    .into(),
            });
        }

        if lower.contains("all architectures")
            || lower.contains("any architecture")
            || lower.contains("arbitrary architecture")
        {
            findings.push(Finding {
                path: path.to_path_buf(),
                line: idx + 1,
                message: "architecture support must point to the supported host/guest matrix, not all/any architectures".into(),
            });
        }
    }
}

fn line_allows_no_host_nix_claim(lower: &str) -> bool {
    let allowed = [
        "do not need host nix",
        "do not require host nix",
        "does not need host nix",
        "does not require host nix",
        "doesn't need host nix",
        "## host nix",
        "without installing host nix",
        "not require host nix",
        "installing host nix",
        "host nix not required",
        "no host nix",
        "not need host nix",
        "not required",
        "never required",
        "optional",
        "builder boundary",
        "builder vm",
    ];
    allowed.iter().any(|needle| lower.contains(needle))
}

fn line_marks_unsupported_or_future(lower: &str) -> bool {
    let allowed = [
        "## gpu",
        "gpu,",
        "gpu status",
        "gpu availability",
        "not part of the default",
        "not assume",
        "not supported",
        "unsupported",
        "future",
        "do not depend",
        "do not treat",
        "not available",
        "limits",
    ];
    allowed.iter().any(|needle| lower.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_nix_must_be_framed_as_not_required_or_builder_scoped() {
        assert!(line_allows_no_host_nix_claim(
            "image-backed runs do not need host nix"
        ));
        assert!(line_allows_no_host_nix_claim(
            "host nix is optional for source builds"
        ));
        assert!(!line_allows_no_host_nix_claim(
            "install host nix before running a machine"
        ));
    }

    #[test]
    fn gpu_and_icmp_need_explicit_limit_words() {
        assert!(line_marks_unsupported_or_future(
            "gpu passthrough is not part of the default machine surface"
        ));
        assert!(line_marks_unsupported_or_future(
            "icmp is future backend-specific work"
        ));
        assert!(!line_marks_unsupported_or_future(
            "gpu acceleration is available"
        ));
    }
}
