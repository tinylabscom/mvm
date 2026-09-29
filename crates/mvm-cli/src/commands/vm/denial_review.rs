//! Explicitly turn grantable egress refusals into a reviewed `mvm.toml` edit.
//!
//! A denial is never itself authority. The operator chooses Grant or Skip for
//! each safe candidate, sees the exact additions, and separately confirms the
//! write. Until that final confirmation the draft exists only in memory.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use mvm_client::approval_broker::display_safe;
use toml_edit::{Array, DocumentMut, Item, Table, Value};

use super::egress_denials::{DenialTally, DeniedDestination};
use crate::approval::tty::{ARMING_WINDOW, ControllingTty, Terminal};

const ANSWER_LIMIT: usize = 32;
const DISPLAY_LIMIT: usize = 200;
const REVIEW_TIMEOUT: Duration = Duration::from_secs(600);

/// One denial the selector is permitted to turn into policy.
#[derive(Debug, Clone, PartialEq, Eq)]
struct GrantCandidate {
    pub target: String,
    pub description: String,
    pub requires_explicit_name: bool,
}

/// Only grant-producing remedies become candidates. The target is deduplicated
/// even when several reason labels refused it.
#[cfg(test)]
fn candidates(tally: &DenialTally) -> Vec<GrantCandidate> {
    candidates_from_destinations(&tally.destinations())
}

fn candidates_from_destinations(denials: &[DeniedDestination]) -> Vec<GrantCandidate> {
    let mut seen = BTreeSet::new();
    denials
        .iter()
        .filter_map(candidate)
        .filter(|candidate| seen.insert(candidate_key(&candidate.target)))
        .collect()
}

fn candidate_key(target: &str) -> String {
    if target.rsplit_once(':').is_some() {
        target.to_ascii_lowercase()
    } else {
        format!("{}:443", target.to_ascii_lowercase())
    }
}

fn candidate(denial: &DeniedDestination) -> Option<GrantCandidate> {
    Some(GrantCandidate {
        target: denial.grant_target()?.to_string(),
        description: denial.description.clone(),
        requires_explicit_name: denial.requires_explicit_name(),
    })
}

/// Open the controlling terminal and run the two-stage review. `Ok(false)`
/// means no terminal, no candidates, or the operator declined the write.
pub(in crate::commands) fn review(tally: &DenialTally, manifest: &Path) -> Result<bool> {
    let denials = tally.destinations();
    if candidates_from_destinations(&denials).is_empty() {
        return Ok(false);
    }
    super::egress_denials::verify_local_chain()?;
    review_destinations(&denials, manifest)
}

/// Review denials recovered after the run from the verified audit chain.
pub(in crate::commands) fn review_destinations(
    denials: &[DeniedDestination],
    manifest: &Path,
) -> Result<bool> {
    let offered = candidates_from_destinations(denials);
    if offered.is_empty() {
        return Ok(false);
    }
    let Ok(mut terminal) = ControllingTty::open() else {
        return Ok(false);
    };
    review_with_terminal(&mut terminal, &offered, manifest)
}

/// The one project file a review edits. Discover an existing manifest from
/// `project`; when none exists, stage a new `mvm.toml` at that directory.
pub(in crate::commands) fn manifest_path(project: &Path) -> Result<PathBuf> {
    Ok(mvm_core::manifest::discover_manifest_from_dir(project)?
        .unwrap_or_else(|| project.join("mvm.toml")))
}

fn review_with_terminal(
    terminal: &mut dyn Terminal,
    offered: &[GrantCandidate],
    manifest: &Path,
) -> Result<bool> {
    let mut selected = Vec::new();
    for candidate in offered {
        let caution = if candidate.requires_explicit_name {
            " (restricted address; grant only if this exact destination is intended)"
        } else {
            ""
        };
        let prompt = format!(
            "\r\n── mvm: review denied egress ──\r\n  destination  {}\r\n  reason       {}{}\r\nAdd to the policy draft? [g] Grant / [S] Skip: ",
            display_safe(&candidate.target, DISPLAY_LIMIT),
            display_safe(&candidate.description, DISPLAY_LIMIT),
            caution,
        );
        if ask(terminal, &prompt)?.as_deref() == Some("g") {
            selected.push(candidate.target.clone());
        }
    }
    if selected.is_empty() {
        terminal.write("\r\n(no policy changes selected)\r\n")?;
        return Ok(false);
    }

    let edit = ManifestEdit::prepare(manifest, &selected)?;
    if edit.added.is_empty() {
        terminal.write("\r\n(all selected destinations are already in mvm.toml)\r\n")?;
        return Ok(false);
    }
    let diff = edit
        .added
        .iter()
        .map(|target| format!("  + {target:?}"))
        .collect::<Vec<_>>()
        .join("\r\n");
    let prompt = format!(
        "\r\nDraft for {}:\r\n[network].allow_hosts\r\n{}\r\nWrite this change? [y/N]: ",
        manifest.display(),
        diff,
    );
    if ask(terminal, &prompt)?.as_deref() != Some("y") {
        terminal.write("\r\n(policy unchanged)\r\n")?;
        return Ok(false);
    }
    edit.commit()?;
    terminal.write(&format!(
        "\r\n(wrote {} grant(s) to {})\r\n",
        edit.added.len(),
        manifest.display()
    ))?;
    Ok(true)
}

/// Read one armed answer. Only the first ASCII word is relevant; everything
/// typed before the prompt or during its arming window is discarded.
fn ask(terminal: &mut dyn Terminal, prompt: &str) -> Result<Option<String>> {
    terminal.discard_input()?;
    terminal.write(prompt)?;
    terminal.pause(ARMING_WINDOW);
    terminal.discard_input()?;
    Ok(terminal
        .read_line(Instant::now() + REVIEW_TIMEOUT, ANSWER_LIMIT)?
        .map(|line| line.trim().to_ascii_lowercase()))
}

struct ManifestEdit {
    path: PathBuf,
    original: Option<Vec<u8>>,
    updated: String,
    added: Vec<String>,
}

impl ManifestEdit {
    fn prepare(path: &Path, targets: &[String]) -> Result<Self> {
        let original = match std::fs::read(path) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error).with_context(|| format!("reading {}", path.display())),
        };
        if std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
            bail!("refusing to replace symlinked manifest {}", path.display());
        }
        let text = original
            .as_deref()
            .map(String::from_utf8_lossy)
            .unwrap_or_default();
        let mut document = if text.trim().is_empty() {
            DocumentMut::new()
        } else {
            text.parse::<DocumentMut>()
                .with_context(|| format!("parsing {} for a policy edit", path.display()))?
        };
        let network = document
            .entry("network")
            .or_insert_with(|| Item::Table(Table::new()))
            .as_table_mut()
            .with_context(|| format!("{}: `network` is not a table", path.display()))?;
        let allow_hosts = network
            .entry("allow_hosts")
            .or_insert_with(|| Item::Value(Value::Array(Array::new())))
            .as_array_mut()
            .with_context(|| {
                format!("{}: `network.allow_hosts` is not an array", path.display())
            })?;
        let mut existing: BTreeSet<String> = allow_hosts
            .iter()
            .filter_map(Value::as_str)
            .map(ToString::to_string)
            .collect();
        let mut added = Vec::new();
        for target in targets {
            if existing.insert(target.clone()) {
                allow_hosts.push(target.as_str());
                added.push(target.clone());
            }
        }
        let updated = document.to_string();
        mvm_core::manifest::Manifest::from_toml_str(&updated)
            .with_context(|| format!("validating the edited {}", path.display()))?;
        Ok(Self {
            path: path.to_path_buf(),
            original,
            updated,
            added,
        })
    }

    fn commit(&self) -> Result<()> {
        let current = match std::fs::read(&self.path) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => {
                return Err(error).with_context(|| format!("re-reading {}", self.path.display()));
            }
        };
        if current != self.original {
            bail!(
                "{} changed while its policy draft was being reviewed; review again",
                self.path.display()
            );
        }
        mvm_core::util::atomic_io::atomic_write_durable(&self.path, self.updated.as_bytes())
            .with_context(|| format!("writing policy grants to {}", self.path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::vm::egress_denials::denial::EgressDenial;
    use crate::commands::vm::egress_denials::denial::tests::entry;
    use std::collections::VecDeque;

    #[derive(Default)]
    struct FakeTerminal {
        answers: VecDeque<String>,
        drawn: String,
    }

    impl Terminal for FakeTerminal {
        fn write(&mut self, text: &str) -> std::io::Result<()> {
            self.drawn.push_str(text);
            Ok(())
        }
        fn discard_input(&mut self) -> std::io::Result<()> {
            Ok(())
        }
        fn read_line(
            &mut self,
            _deadline: Instant,
            _max_bytes: usize,
        ) -> std::io::Result<Option<String>> {
            Ok(self.answers.pop_front())
        }
        fn pause(&mut self, _duration: Duration) {}
    }

    fn tally(target: &str, reason: &str) -> DenialTally {
        let audit = entry(
            "host.flow.denied",
            &[
                ("vm_name", "vm-a"),
                ("class", "tcp"),
                ("target", target),
                ("reason", reason),
            ],
        );
        let mut tally = DenialTally::default();
        tally.observe(EgressDenial::from_entry(&audit, "vm-a").unwrap());
        tally
    }

    #[test]
    fn only_safely_grantable_denials_become_candidates() {
        assert_eq!(
            candidates(&tally("api.example.com:443", "policy_denied")).len(),
            1
        );
        for (target, reason) in [
            ("169.254.169.254:80", "cloud_metadata"),
            ("127.0.0.1:443", "loopback"),
            ("example.com:22", "policy_denied"),
            ("api.example.com:443", "rate_limited"),
        ] {
            assert!(
                candidates(&tally(target, reason)).is_empty(),
                "{target} {reason}"
            );
        }
    }

    #[test]
    fn candidates_deduplicate_dns_and_tcp_default_port() {
        let denials = [
            tally("pypi.org", "policy_denied").destinations(),
            tally("pypi.org:443", "policy_denied").destinations(),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();

        assert_eq!(candidates_from_destinations(&denials).len(), 1);
    }

    #[test]
    fn review_needs_grant_and_a_separate_write_confirmation() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("mvm.toml");
        std::fs::write(
            &manifest,
            "# keep this project note\nimage = \"alpine:3.20\"\n",
        )
        .unwrap();
        let offered = candidates(&tally("api.example.com:443", "policy_denied"));

        let mut skipped = FakeTerminal {
            answers: ["s".into()].into(),
            ..FakeTerminal::default()
        };
        assert!(!review_with_terminal(&mut skipped, &offered, &manifest).unwrap());
        assert!(
            !std::fs::read_to_string(&manifest)
                .unwrap()
                .contains("allow_hosts")
        );

        let mut declined = FakeTerminal {
            answers: ["g".into(), "n".into()].into(),
            ..FakeTerminal::default()
        };
        assert!(!review_with_terminal(&mut declined, &offered, &manifest).unwrap());
        assert!(
            !std::fs::read_to_string(&manifest)
                .unwrap()
                .contains("allow_hosts")
        );

        let mut accepted = FakeTerminal {
            answers: ["g".into(), "y".into()].into(),
            ..FakeTerminal::default()
        };
        assert!(review_with_terminal(&mut accepted, &offered, &manifest).unwrap());
        let written = std::fs::read_to_string(&manifest).unwrap();
        assert!(written.contains("api.example.com:443"));
        assert!(written.contains("image = \"alpine:3.20\""));
        assert!(written.contains("# keep this project note"));
    }

    #[test]
    fn a_project_without_a_manifest_gets_one_valid_policy_file() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("mvm.toml");
        let edit = ManifestEdit::prepare(&manifest, &["api.example.com:443".into()]).unwrap();

        edit.commit().unwrap();

        let written = std::fs::read_to_string(&manifest).unwrap();
        let parsed = mvm_core::manifest::Manifest::from_toml_str(&written).unwrap();
        assert_eq!(parsed.network.allow_hosts, ["api.example.com:443"]);
    }

    #[test]
    fn manifest_edit_deduplicates_and_refuses_a_concurrent_change() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("mvm.toml");
        std::fs::write(
            &manifest,
            "[network]\nallow_hosts = [\"api.example.com:443\"]\n",
        )
        .unwrap();
        let edit = ManifestEdit::prepare(
            &manifest,
            &["api.example.com:443".into(), "pypi.org:443".into()],
        )
        .unwrap();
        assert_eq!(edit.added, ["pypi.org:443"]);
        std::fs::write(&manifest, "# another writer\n").unwrap();
        assert!(
            edit.commit()
                .unwrap_err()
                .to_string()
                .contains("changed while")
        );
    }
}
