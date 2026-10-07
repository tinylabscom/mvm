//! Explicitly turn grantable egress refusals into a reviewed `mvm.toml` edit.
//!
//! A denial is never itself authority. The operator chooses Grant or Skip for
//! each safe candidate, sees the exact additions, and separately confirms the
//! write. Until that final confirmation the draft exists only in memory.
//!
//! A run that cannot be reviewed where it ended — no terminal, or no project
//! manifest this process admitted it under — names the `mvmctl explain`
//! command that opens the same review later instead.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use mvm_client::approval_broker::display_safe;
use toml_edit::{Array, DocumentMut, Item, Table, Value};

use super::egress_denials::{DenialTally, DeniedDestination};
use super::exec::RunArgs;
use super::host_notices::{NoticeSink, Stderr};
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

/// Open the controlling terminal and run the two-stage review, after verifying
/// the local audit chain. `Ok(false)` means no terminal, no candidates, or the
/// operator declined the write.
pub(in crate::commands) fn review(tally: &DenialTally, manifest: &Path) -> Result<bool> {
    review_with(
        &tally.destinations(),
        manifest,
        &mut LocalHost::verifying_chain(),
    )
    .map(ReviewOutcome::wrote)
}

/// Review denials recovered after the run from the verified audit chain.
pub(in crate::commands) fn review_destinations(
    denials: &[DeniedDestination],
    manifest: &Path,
) -> Result<bool> {
    review_with(denials, manifest, &mut LocalHost::chain_already_verified())
        .map(ReviewOutcome::wrote)
}

/// The one project file a review edits: `project` itself when it names a
/// manifest file, otherwise the manifest discovered from that directory, or a
/// new `mvm.toml` staged there when none exists.
pub(in crate::commands) fn manifest_path(project: &Path) -> Result<PathBuf> {
    if project.is_file() {
        return Ok(project.to_path_buf());
    }
    Ok(mvm_core::manifest::discover_manifest_from_dir(project)?
        .unwrap_or_else(|| project.join("mvm.toml")))
}

/// Where the policy of a run came from, which decides whether its refusals
/// can become grants in place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::commands) enum ReviewSource {
    /// This process admitted the run, and this project manifest contributed
    /// its `[network].allow_hosts`.
    Manifest(PathBuf),
    /// There is no project manifest here that a grant could be added to.
    Unavailable(NoManifest),
}

/// Why a run has no project manifest a review could edit in place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::commands) enum NoManifest {
    /// This process admitted the run, and no project manifest contributed to
    /// its policy.
    NotNamed,
    /// The run's policy came from a verified pack, which a review never edits.
    SignedPack,
    /// The run's policy came from a resolved-manifest file (`--plan`).
    ResolvedPlan,
    /// Another `mvmctl` invocation admitted the run, so this one cannot know
    /// which manifest its policy came from.
    AdmittedElsewhere,
}

impl ReviewSource {
    /// The source of a launch's policy, read from its arguments the way
    /// `apply_run_policy` reads them. Call it before a flake is built into a
    /// slot: after that, the arguments no longer name the project directory.
    pub(in crate::commands) fn for_launch(args: &RunArgs) -> Result<Self> {
        if args.registry_pack_image.is_some() {
            return Ok(Self::Unavailable(NoManifest::SignedPack));
        }
        if args.plan.is_some() {
            return Ok(Self::Unavailable(NoManifest::ResolvedPlan));
        }
        Ok(super::run_routes::project_manifest(args)?
            .map_or(Self::Unavailable(NoManifest::NotNamed), |(path, _)| {
                Self::Manifest(path)
            }))
    }

    pub(in crate::commands) fn admitted_elsewhere() -> Self {
        Self::Unavailable(NoManifest::AdmittedElsewhere)
    }
}

impl NoManifest {
    fn reason(self, vm_name: &str) -> String {
        match self {
            Self::NotNamed => {
                "this run was admitted without a project mvm.toml to add grants to".into()
            }
            Self::SignedPack => {
                "this run's policy came from a verified pack, which a review never edits".into()
            }
            Self::ResolvedPlan => {
                "this run's policy came from --plan, not from a project mvm.toml".into()
            }
            Self::AdmittedElsewhere => format!(
                "machine {} was admitted by a separate run, so its project manifest is not \
                 known here",
                display_safe(vm_name, DISPLAY_LIMIT)
            ),
        }
    }
}

/// What a lane knows about the run whose refusals it has just summarized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::commands) struct ReviewOffer {
    vm_name: String,
    source: ReviewSource,
}

impl ReviewOffer {
    pub(in crate::commands) fn new(vm_name: impl Into<String>, source: ReviewSource) -> Self {
        Self {
            vm_name: vm_name.into(),
            source,
        }
    }
}

/// Print a finished run's exit summary, then offer its grantable refusals for
/// review: in place when the run's project manifest is known and there is a
/// terminal to ask on; otherwise as the `mvmctl explain` command that opens
/// the same review later. Never fails the run — a review that cannot proceed
/// says why.
pub(in crate::commands) fn summarize_and_offer(tally: &DenialTally, offer: &ReviewOffer) {
    summarize_and_offer_with(tally, offer, &mut LocalHost::verifying_chain());
}

fn summarize_and_offer_with(tally: &DenialTally, offer: &ReviewOffer, host: &mut dyn ReviewHost) {
    super::egress_denials::print_summary(tally, host.sink());
    offer_with(tally, offer, host);
}

/// How a review ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReviewOutcome {
    /// Nothing refused could become a grant.
    NothingGrantable,
    /// No controlling terminal to ask on.
    NoTerminal,
    /// The operator answered; `true` when the manifest was written.
    Answered(bool),
}

impl ReviewOutcome {
    fn wrote(self) -> bool {
        self == Self::Answered(true)
    }
}

/// What a review needs from the host it runs on.
trait ReviewHost {
    /// Where notices about the review go.
    fn sink(&self) -> &dyn NoticeSink;
    /// The controlling terminal, or `None` when the process has none.
    fn open_terminal(&mut self) -> Option<Box<dyn Terminal>>;
    /// Refuse unless the chain the refusals were read from verifies.
    fn verify_chain(&mut self) -> Result<()>;
    /// The plan id `mvmctl explain` should be pointed at for `vm_name`.
    fn run_id(&self, vm_name: &str) -> Option<String>;
}

/// `/dev/tty`, the local tenant's chain, and stderr.
struct LocalHost {
    chain_verified: bool,
}

impl LocalHost {
    fn verifying_chain() -> Self {
        Self {
            chain_verified: false,
        }
    }

    fn chain_already_verified() -> Self {
        Self {
            chain_verified: true,
        }
    }
}

impl ReviewHost for LocalHost {
    fn sink(&self) -> &dyn NoticeSink {
        &Stderr
    }

    fn open_terminal(&mut self) -> Option<Box<dyn Terminal>> {
        ControllingTty::open()
            .ok()
            .map(|terminal| Box::new(terminal) as Box<dyn Terminal>)
    }

    fn verify_chain(&mut self) -> Result<()> {
        if !self.chain_verified {
            super::egress_denials::verify_local_chain()?;
            self.chain_verified = true;
        }
        Ok(())
    }

    fn run_id(&self, vm_name: &str) -> Option<String> {
        super::egress_denials::latest_admission(vm_name)
    }
}

/// The review itself. The chain is verified once a terminal is known to exist
/// and before anything is asked on it.
fn review_with(
    denials: &[DeniedDestination],
    manifest: &Path,
    host: &mut dyn ReviewHost,
) -> Result<ReviewOutcome> {
    let offered = candidates_from_destinations(denials);
    if offered.is_empty() {
        return Ok(ReviewOutcome::NothingGrantable);
    }
    let Some(mut terminal) = host.open_terminal() else {
        return Ok(ReviewOutcome::NoTerminal);
    };
    host.verify_chain()?;
    review_with_terminal(terminal.as_mut(), &offered, manifest).map(ReviewOutcome::Answered)
}

fn offer_with(tally: &DenialTally, offer: &ReviewOffer, host: &mut dyn ReviewHost) {
    let denials = tally.destinations();
    if candidates_from_destinations(&denials).is_empty() {
        return;
    }
    let (reason, manifest) = match &offer.source {
        ReviewSource::Manifest(manifest) => match review_with(&denials, manifest, host) {
            Ok(ReviewOutcome::NoTerminal) => (
                "no terminal to review these refusals on".to_string(),
                Some(manifest.as_path()),
            ),
            Ok(ReviewOutcome::NothingGrantable | ReviewOutcome::Answered(_)) => return,
            Err(error) => (
                format!("could not review denied egress: {error:#}"),
                Some(manifest.as_path()),
            ),
        },
        ReviewSource::Unavailable(why) => (why.reason(&offer.vm_name), None),
    };
    let run = host
        .run_id(&offer.vm_name)
        .unwrap_or_else(|| offer.vm_name.clone());
    let lines = review_pointer(&reason, &run, manifest);
    host.sink().block(&lines);
}

/// The lines naming the command that reviews a run's refusals later.
fn review_pointer(reason: &str, run: &str, manifest: Option<&Path>) -> Vec<String> {
    match manifest {
        Some(manifest) => vec![
            format!("{reason}; to grant any of them later, run:"),
            format!(
                "  mvmctl explain {} --review --project {}",
                shell_word(run),
                shell_word(&manifest.display().to_string())
            ),
        ],
        None => vec![
            format!("{reason}; to grant any of them later, run from the project directory:"),
            format!("  mvmctl explain {} --review", shell_word(run)),
        ],
    }
}

/// `word` as one shell word, quoted only when it has to be.
fn shell_word(word: &str) -> String {
    let plain = !word.is_empty()
        && word
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./:@+=,".contains(c));
    if plain {
        word.to_string()
    } else {
        crate::exec::shell_quote(word)
    }
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
    use mvm_client::egress_denials::denial::EgressDenial;
    use mvm_hostd::supervisor::PlanAuditEntry;
    use std::collections::VecDeque;

    /// An endpoint audit entry carrying `labels`, as the chain records one.
    fn entry(event: &str, labels: &[(&str, &str)]) -> PlanAuditEntry {
        PlanAuditEntry {
            timestamp: "2026-09-26T10:00:00Z".parse().unwrap(),
            tenant: mvm_core::plan::TenantId("local".into()),
            plan_id: mvm_core::plan::PlanId("00000000-0000-0000-0000-000000000000".into()),
            plan_version: 0,
            bundle_id: None,
            bundle_version: None,
            image_name: "<unbound>".into(),
            image_sha256: "0".repeat(64),
            event: event.into(),
            caller_commitment: None,
            labels: labels
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

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

    /// A terminal the host hands out by value while the test keeps a handle
    /// on what was drawn on it and what is left to answer.
    #[derive(Clone, Default)]
    struct SharedTerminal(std::rc::Rc<std::cell::RefCell<FakeTerminal>>);

    impl SharedTerminal {
        fn answering(answers: &[&str]) -> Self {
            Self(std::rc::Rc::new(std::cell::RefCell::new(FakeTerminal {
                answers: answers.iter().map(ToString::to_string).collect(),
                ..FakeTerminal::default()
            })))
        }

        fn drawn(&self) -> String {
            self.0.borrow().drawn.clone()
        }
    }

    impl Terminal for SharedTerminal {
        fn write(&mut self, text: &str) -> std::io::Result<()> {
            self.0.borrow_mut().write(text)
        }
        fn discard_input(&mut self) -> std::io::Result<()> {
            self.0.borrow_mut().discard_input()
        }
        fn read_line(
            &mut self,
            deadline: Instant,
            max_bytes: usize,
        ) -> std::io::Result<Option<String>> {
            self.0.borrow_mut().read_line(deadline, max_bytes)
        }
        fn pause(&mut self, _duration: Duration) {}
    }

    struct FakeHost {
        sink: crate::commands::vm::host_notices::Captured,
        terminal: Option<SharedTerminal>,
        chain: std::result::Result<(), &'static str>,
        verified: bool,
        run_id: Option<String>,
    }

    impl FakeHost {
        /// No terminal; a chain that verifies; run `plan-1`.
        fn headless() -> Self {
            Self {
                sink: crate::commands::vm::host_notices::Captured::default(),
                terminal: None,
                chain: Ok(()),
                verified: false,
                run_id: Some("plan-1".into()),
            }
        }

        fn with_terminal(terminal: &SharedTerminal) -> Self {
            Self {
                terminal: Some(terminal.clone()),
                ..Self::headless()
            }
        }

        fn said(&self) -> String {
            self.sink.lines().join("\n")
        }
    }

    impl ReviewHost for FakeHost {
        fn sink(&self) -> &dyn NoticeSink {
            &self.sink
        }
        fn open_terminal(&mut self) -> Option<Box<dyn Terminal>> {
            self.terminal
                .clone()
                .map(|terminal| Box::new(terminal) as Box<dyn Terminal>)
        }
        fn verify_chain(&mut self) -> Result<()> {
            self.chain.map_err(|error| anyhow::anyhow!(error))?;
            self.verified = true;
            Ok(())
        }
        fn run_id(&self, _vm_name: &str) -> Option<String> {
            self.run_id.clone()
        }
    }

    fn grantable() -> DenialTally {
        tally("api.example.com:443", "policy_denied")
    }

    fn project() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("mvm.toml");
        std::fs::write(&manifest, "image = \"alpine:3.20\"\n").unwrap();
        (dir, manifest)
    }

    #[test]
    fn a_run_without_a_terminal_names_the_review_command_for_its_manifest() {
        let (_dir, manifest) = project();
        let before = std::fs::read(&manifest).unwrap();
        let mut host = FakeHost::headless();

        summarize_and_offer_with(
            &grantable(),
            &ReviewOffer::new("vm-a", ReviewSource::Manifest(manifest.clone())),
            &mut host,
        );

        let lines = host.sink.lines();
        let summary = lines
            .iter()
            .position(|line| line.starts_with("egress denied: 1 destination"))
            .expect("the exit summary");
        let pointer = lines
            .iter()
            .position(|line| line.contains("no terminal to review these refusals on"))
            .expect("why no review was opened");
        assert!(summary < pointer, "{lines:#?}");
        assert_eq!(
            lines[pointer + 1],
            format!(
                "  mvmctl explain plan-1 --review --project {}",
                manifest.display()
            )
        );
        assert!(!host.verified, "no review was opened, so nothing to verify");
        assert_eq!(std::fs::read(&manifest).unwrap(), before);
    }

    #[test]
    fn a_run_with_a_terminal_reviews_in_place_after_verifying_the_chain() {
        let (_dir, manifest) = project();
        let terminal = SharedTerminal::answering(&["g", "y"]);
        let mut host = FakeHost::with_terminal(&terminal);

        summarize_and_offer_with(
            &grantable(),
            &ReviewOffer::new("vm-a", ReviewSource::Manifest(manifest.clone())),
            &mut host,
        );

        assert!(host.verified);
        assert!(terminal.drawn().contains("Grant / [S] Skip"));
        assert!(terminal.drawn().contains("Write this change? [y/N]"));
        let written = mvm_core::manifest::Manifest::read_file(&manifest).unwrap();
        assert_eq!(written.network.allow_hosts, ["api.example.com:443"]);
        assert!(!host.said().contains("mvmctl explain"), "{}", host.said());
    }

    #[test]
    fn a_review_declined_at_the_write_leaves_the_manifest_and_prints_no_pointer() {
        let (_dir, manifest) = project();
        let before = std::fs::read(&manifest).unwrap();
        let terminal = SharedTerminal::answering(&["g", "n"]);
        let mut host = FakeHost::with_terminal(&terminal);

        summarize_and_offer_with(
            &grantable(),
            &ReviewOffer::new("vm-a", ReviewSource::Manifest(manifest.clone())),
            &mut host,
        );

        assert_eq!(std::fs::read(&manifest).unwrap(), before);
        assert!(!host.said().contains("mvmctl explain"));
    }

    #[test]
    fn a_chain_that_does_not_verify_is_never_reviewed() {
        let (_dir, manifest) = project();
        let before = std::fs::read(&manifest).unwrap();
        let terminal = SharedTerminal::answering(&["g", "y"]);
        let mut host = FakeHost {
            chain: Err("chain broken at entry 3"),
            ..FakeHost::with_terminal(&terminal)
        };

        summarize_and_offer_with(
            &grantable(),
            &ReviewOffer::new("vm-a", ReviewSource::Manifest(manifest.clone())),
            &mut host,
        );

        assert!(terminal.drawn().is_empty(), "nothing may be asked");
        assert_eq!(std::fs::read(&manifest).unwrap(), before);
        let said = host.said();
        assert!(said.contains("chain broken at entry 3"), "{said}");
        assert!(
            said.contains("mvmctl explain plan-1 --review --project"),
            "{said}"
        );
    }

    #[test]
    fn a_symlinked_manifest_is_refused_and_pointed_at_explain() {
        let (dir, target) = project();
        let manifest = dir.path().join("linked.toml");
        std::os::unix::fs::symlink(&target, &manifest).unwrap();
        let before = std::fs::read(&target).unwrap();
        let terminal = SharedTerminal::answering(&["g", "y"]);
        let mut host = FakeHost::with_terminal(&terminal);

        summarize_and_offer_with(
            &grantable(),
            &ReviewOffer::new("vm-a", ReviewSource::Manifest(manifest)),
            &mut host,
        );

        assert_eq!(std::fs::read(&target).unwrap(), before);
        let said = host.said();
        assert!(said.contains("symlinked manifest"), "{said}");
        assert!(said.contains("mvmctl explain plan-1 --review"), "{said}");
    }

    #[test]
    fn a_run_without_a_project_manifest_says_so_and_never_prompts() {
        for (why, expected) in [
            (NoManifest::NotNamed, "without a project mvm.toml"),
            (NoManifest::SignedPack, "verified pack"),
            (NoManifest::ResolvedPlan, "--plan"),
            (NoManifest::AdmittedElsewhere, "admitted by a separate run"),
        ] {
            let terminal = SharedTerminal::answering(&["g", "y"]);
            let mut host = FakeHost::with_terminal(&terminal);

            summarize_and_offer_with(
                &grantable(),
                &ReviewOffer::new("vm-a", ReviewSource::Unavailable(why)),
                &mut host,
            );

            assert!(terminal.drawn().is_empty(), "{why:?} must not prompt");
            let lines = host.sink.lines();
            let reason = lines
                .iter()
                .position(|line| line.contains(expected))
                .unwrap_or_else(|| panic!("{why:?}: {lines:#?}"));
            assert!(lines[reason].ends_with("run from the project directory:"));
            assert_eq!(lines[reason + 1], "  mvmctl explain plan-1 --review");
        }
    }

    #[test]
    fn refusals_that_cannot_become_grants_get_neither_a_review_nor_a_pointer() {
        let terminal = SharedTerminal::answering(&["g", "y"]);
        let mut host = FakeHost::with_terminal(&terminal);

        summarize_and_offer_with(
            &tally("169.254.169.254:80", "cloud_metadata"),
            &ReviewOffer::new("vm-a", ReviewSource::admitted_elsewhere()),
            &mut host,
        );

        assert!(terminal.drawn().is_empty());
        assert!(
            host.said().contains("egress denied"),
            "the summary still prints"
        );
        assert!(!host.said().contains("mvmctl explain"));
    }

    #[test]
    fn the_pointer_names_the_machine_when_no_admission_is_found() {
        let mut host = FakeHost {
            run_id: None,
            ..FakeHost::headless()
        };

        summarize_and_offer_with(
            &grantable(),
            &ReviewOffer::new("vm-a", ReviewSource::admitted_elsewhere()),
            &mut host,
        );

        assert!(host.said().contains("  mvmctl explain vm-a --review"));
    }

    #[test]
    fn the_pointer_quotes_only_what_the_shell_would_split() {
        assert_eq!(shell_word("plan-1"), "plan-1");
        assert_eq!(
            shell_word("/p/my project/mvm.toml"),
            "'/p/my project/mvm.toml'"
        );
        assert_eq!(shell_word("it's"), r"'it'\''s'");
    }

    #[test]
    fn a_manifest_file_is_its_own_review_target() {
        let (dir, _) = project();
        let custom = dir.path().join("custom.toml");
        std::fs::write(&custom, "").unwrap();
        assert_eq!(manifest_path(&custom).unwrap(), custom);
    }

    #[test]
    fn a_launch_review_source_is_the_manifest_its_policy_was_read_from() {
        let (dir, manifest) = project();
        let flake = RunArgs {
            flake: Some(dir.path().display().to_string()),
            ..RunArgs::default()
        };
        assert_eq!(
            ReviewSource::for_launch(&flake).unwrap(),
            ReviewSource::Manifest(manifest.clone())
        );
        let named = RunArgs {
            manifest: Some(manifest.display().to_string()),
            ..RunArgs::default()
        };
        assert_eq!(
            ReviewSource::for_launch(&named).unwrap(),
            ReviewSource::Manifest(manifest)
        );

        let empty = tempfile::tempdir().unwrap();
        let bare = RunArgs {
            flake: Some(empty.path().display().to_string()),
            ..RunArgs::default()
        };
        assert_eq!(
            ReviewSource::for_launch(&bare).unwrap(),
            ReviewSource::Unavailable(NoManifest::NotNamed)
        );
        let planned = RunArgs {
            flake: Some(dir.path().display().to_string()),
            plan: Some(dir.path().join("resolved.json")),
            ..RunArgs::default()
        };
        assert_eq!(
            ReviewSource::for_launch(&planned).unwrap(),
            ReviewSource::Unavailable(NoManifest::ResolvedPlan)
        );
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
