//! cargo-mutants invocation, isolation, and reading back what a run's
//! output directory proves for each surface file.

use super::*;
use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};

/// Run cargo-mutants once per surface file, returning the directory the
/// per-file output landed in.
///
/// Scoped per file with `-p <package> --file <path>`: the package scope
/// keeps each invocation from re-testing the whole workspace, and it is
/// the stricter question — the owning crate's own tests must catch the
/// tampering.
///
/// Each file's previous output is removed before anything runs, so the
/// directory only ever holds this run's evidence. Left in place, output
/// from an earlier run would stand in for a file this one never reached.
pub(crate) fn run_mutants_over(
    workspace: &Path,
    surface: &[SurfaceFile],
    pinned: &str,
) -> Result<PathBuf> {
    ensure_cargo_mutants(pinned)?;
    let out_root = std::env::temp_dir().join("mvm-mutation-witnesses");
    std::fs::create_dir_all(&out_root)
        .with_context(|| format!("creating {}", out_root.display()))?;
    for file in surface {
        let stale = file_output_dir(&out_root, &file.path);
        if stale.exists() {
            std::fs::remove_dir_all(&stale)
                .with_context(|| format!("clearing earlier output at {}", stale.display()))?;
        }
    }
    let isolation = MutationIsolation::establish(&out_root)?;

    for (i, file) in surface.iter().enumerate() {
        eprintln!(
            "[{}/{}] mutating {} (package {}, claims {:?})",
            i + 1,
            surface.len(),
            file.path,
            file.package,
            file.claims
        );
        let out_dir = file_output_dir(&out_root, &file.path);
        run_mutants_for_file(workspace, file, &out_dir, &isolation, pinned)?;
    }
    Ok(out_root)
}

/// Where one surface file's cargo-mutants output lives under a run's root.
/// The run and every later reading of its output go through this, so the
/// two cannot disagree about where a file's evidence is.
fn file_output_dir(out_root: &Path, path: &str) -> PathBuf {
    out_root.join(path.replace('/', "_"))
}

/// The evidence for every file in `surface`, in surface order.
pub fn collect_evidence(
    out_root: &Path,
    surface: &[SurfaceFile],
    pinned: &str,
) -> Vec<(String, FileEvidence)> {
    surface
        .iter()
        .map(|file| {
            let dir = file_output_dir(out_root, &file.path);
            (
                file.path.clone(),
                read_file_evidence(&dir, &file.path, pinned),
            )
        })
        .collect()
}

/// Read what one file's cargo-mutants output directory proves.
///
/// Anything short of a finished run under the pinned mutator is
/// unmeasured, and says which way it fell short: a shard stopped by its
/// timeout leaves no directory at all for the files it never reached, a
/// partial `outcomes.json` for the file it was in, and neither may be read
/// as clean.
pub fn read_file_evidence(out_dir: &Path, path: &str, pinned: &str) -> FileEvidence {
    let report = out_dir.join("mutants.out");
    let unmeasured =
        |reason: String, misses: Vec<Miss>| FileEvidence::Unmeasured { reason, misses };
    if !report.is_dir() {
        return unmeasured(
            format!(
                "no cargo-mutants output at {} — the run never reached this file",
                report.display()
            ),
            Vec::new(),
        );
    }
    let missed = report.join("missed.txt");
    let misses = match std::fs::read_to_string(&missed) {
        Ok(text) => parse_missed(&text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => {
            return unmeasured(format!("reading {}: {e}", missed.display()), Vec::new());
        }
    };
    let outcomes_path = report.join("outcomes.json");
    let outcomes = match std::fs::read_to_string(&outcomes_path) {
        Ok(text) => text,
        // cargo-mutants writes `outcomes.json` after its first scenario, so
        // a directory without one stopped before the baseline finished, or
        // found nothing to mutate. Either way it is the harness that failed
        // rather than a witness: check the file has anything mutable in it
        // before looking for missing tests.
        Err(e) => {
            return unmeasured(
                format!(
                    "cargo-mutants left no readable {} ({e}), so the run for this file did \
                     not complete — a harness failure, not a witness gap",
                    outcomes_path.display()
                ),
                misses,
            );
        }
    };
    if let Err(reason) = ensure_recorded_by(&outcomes, pinned) {
        return unmeasured(reason, misses);
    }
    match ensure_mutants_actually_ran(&outcomes, path) {
        Ok(_) => FileEvidence::Measured(misses),
        // The error leads with the path for callers that print it alone;
        // the verdict already names the file.
        Err(e) => {
            let text = format!("{e:#}");
            let reason = text.strip_prefix(&format!("{path}: ")).unwrap_or(&text);
            unmeasured(reason.to_string(), misses)
        }
    }
}

/// Refuse evidence recorded by a mutator other than the pinned one.
///
/// Accepted misses are matched on the description text cargo-mutants
/// renders, and a release that attributes a mutant to a different
/// enclosing function renames it. A survivor recorded under another version
/// can therefore look new when it is accepted, or accepted when it is new.
fn ensure_recorded_by(outcomes_json: &str, pinned: &str) -> std::result::Result<(), String> {
    let v: serde_json::Value = serde_json::from_str(outcomes_json).map_err(|e| {
        format!("outcomes.json does not parse ({e}), so the run did not finish writing it")
    })?;
    match v.get("cargo_mutants_version").and_then(|s| s.as_str()) {
        Some(version) if version == pinned => Ok(()),
        Some(version) => Err(format!(
            "recorded by cargo-mutants {version}, but the pin is {pinned}; mutant descriptions \
             are only comparable to the baseline under the pinned version"
        )),
        None => Err(format!(
            "outcomes.json names no cargo_mutants_version, so it cannot be shown to come from \
             the pinned cargo-mutants {pinned}"
        )),
    }
}

/// The state roots a mutation run is confined to.
///
/// `--run` executes security code with its check removed: plan verification
/// that no longer verifies, the host signer, seccomp construction. It must
/// not reach a real mvm state root — the mutation may be *in* the path or
/// mode logic, so it can mint a key at the wrong path or leave firewall
/// rules behind.
///
/// Applied here, at the one place cargo-mutants is spawned, rather than in
/// each caller's shell. A caller that forgets is the whole failure mode,
/// and there is no reason for the nightly lane, the Justfile recipe and a
/// bare `cargo run -p xtask` to each carry their own copy of it.
struct MutationIsolation {
    home: std::path::PathBuf,
    cargo_home: std::path::PathBuf,
    rustup_home: std::path::PathBuf,
}

impl MutationIsolation {
    fn establish(under: &Path) -> Result<Self> {
        // Resolve the toolchain roots from the *real* home before
        // redirecting: `~` follows `HOME`, so a subprocess whose `HOME`
        // moved would look for cargo and rustup inside the empty temp
        // root and find no toolchain at all.
        let real_home = std::env::var_os("HOME").map(std::path::PathBuf::from);
        let cargo_home = std::env::var_os("CARGO_HOME")
            .map(std::path::PathBuf::from)
            .or_else(|| real_home.as_ref().map(|h| h.join(".cargo")))
            .context("resolving CARGO_HOME: neither CARGO_HOME nor HOME is set")?;
        let rustup_home = std::env::var_os("RUSTUP_HOME")
            .map(std::path::PathBuf::from)
            .or_else(|| real_home.as_ref().map(|h| h.join(".rustup")))
            .context("resolving RUSTUP_HOME: neither RUSTUP_HOME nor HOME is set")?;

        let home = under.join("state-root");
        std::fs::create_dir_all(&home)
            .with_context(|| format!("creating the isolated state root {}", home.display()))?;

        // A reachable keystore under the redirected root means the
        // redirect did not take. Refuse rather than mutate against keys.
        let keys = home.join(".mvm").join("keys");
        if keys.exists() {
            bail!(
                "refusing to mutate against a reachable keystore at {} — the isolated \
                 state root is supposed to be empty",
                keys.display()
            );
        }
        eprintln!(
            "check-mutation-witnesses: mutating under an isolated HOME/MVM_HOME at {}",
            home.display()
        );
        Ok(Self {
            home,
            cargo_home,
            rustup_home,
        })
    }

    fn apply(&self, cmd: &mut std::process::Command) {
        // Both roots move together. `MVM_HOME` alone is not enough:
        // `default_mvm_cache_dir` deliberately reads the home directory to
        // seed from the shared cache, which is the one door `MVM_HOME`
        // does not close.
        cmd.env("MVM_HOME", &self.home)
            .env("HOME", &self.home)
            .env("CARGO_HOME", &self.cargo_home)
            .env("RUSTUP_HOME", &self.rustup_home);
    }
}

fn run_mutants_for_file(
    workspace: &Path,
    file: &SurfaceFile,
    out_dir: &Path,
    isolation: &MutationIsolation,
    pinned: &str,
) -> Result<()> {
    let mut cmd = std::process::Command::new("cargo");
    cmd.current_dir(workspace)
        .arg("mutants")
        .args(["-p", &file.package])
        .args(["--file", &file.path])
        .args(["--test-tool", "nextest"])
        .args([
            "--timeout-multiplier",
            &MUTANT_TIMEOUT_MULTIPLIER.to_string(),
        ])
        .args([
            "--minimum-test-timeout",
            &MUTANT_MINIMUM_TIMEOUT_SECS.to_string(),
        ])
        .arg("--output")
        .arg(out_dir);
    if !file.features.is_empty() {
        let joined = file.features.join(",");
        eprintln!("      features {joined}");
        cmd.args(["--features", &joined]);
    }
    if let Some(scope) = &file.scope {
        eprintln!(
            "      scoped to /{}/ — {}",
            scope.examine_re, scope.excluded_tracked_by
        );
        cmd.args(["--re", &scope.examine_re]);
    }
    isolation.apply(&mut cmd);
    let status = cmd.status().context("spawning `cargo mutants`")?;

    // Exit status is deliberately not the signal: cargo-mutants exits
    // nonzero merely because mutants survived, which is the case this
    // gate exists to report. The output directory is the signal, read the
    // same way here as by `--verify-outcomes`. A file the run could not
    // measure stops the shard: the next one would most likely fail the same
    // way, and hours spent confirming that are hours not spent on the fix.
    match read_file_evidence(out_dir, &file.path, pinned) {
        FileEvidence::Measured(_) => Ok(()),
        FileEvidence::Unmeasured { reason, .. } => bail!(
            "cargo mutants did not measure {} (exit {:?}): {reason}",
            file.path,
            status.code()
        ),
    }
}

/// Reject a run that never tested a mutant.
///
/// When the unmutated tree does not build or its tests fail,
/// cargo-mutants stops before mutating anything and reports
/// `cargo test failed in an unmutated tree, so no mutants were tested`.
/// It still writes `missed.txt` and `caught.txt` — both **empty** — so the
/// obvious "did it produce a report" guard passes and `parse_missed` on an
/// empty file yields zero misses. A surface file that contributed no
/// coverage then reads exactly like one that is fully covered.
///
/// That is the failure this whole gate exists to prevent, one level up: a
/// green result standing in for evidence that was never collected. So the
/// counts in `outcomes.json` are the signal, not the presence of a file.
///
/// There are two ways to arrive here having tested nothing, and both have
/// been observed on this repo's own claim surface:
///
/// - The baseline fails to build or fails its tests, giving a `Baseline`
///   outcome summarised `Failure`.
/// - The baseline **times out**, giving one summarised `Timeout`. That is
///   what a package whose own suite runs longer than the per-test budget
///   produces, and it is indistinguishable from the above in every way
///   that matters here.
///
/// So the check is that the summary *is* `Success`, rather than that it is
/// one of a list of known failures. A summary this code has not seen
/// before is not evidence that anything ran. `total_mutants` is checked
/// for being **nonzero** for the same reason: cargo-mutants writes the key
/// as `0` on an aborted run, so its mere presence proves nothing.
fn ensure_mutants_actually_ran(outcomes_json: &str, path: &str) -> Result<u64> {
    let v: serde_json::Value = serde_json::from_str(outcomes_json)
        .with_context(|| format!("parsing cargo-mutants outcomes.json for {path}"))?;

    let baseline_verdict = v
        .get("outcomes")
        .and_then(|o| o.as_array())
        .and_then(|entries| {
            entries
                .iter()
                .find(|e| e.get("scenario").and_then(|s| s.as_str()) == Some("Baseline"))
        })
        .and_then(|e| e.get("summary").and_then(|s| s.as_str()));
    if let Some(verdict) = baseline_verdict
        && verdict != "Success"
    {
        bail!(
            "{path}: the unmutated tree did not pass its own tests (baseline \
             {verdict}), so cargo-mutants tested no mutants. This file contributed \
             no coverage — it is not clean, it is unmeasured. Fix its package's \
             suite, or raise the per-test timeout if the suite is merely slow, then \
             re-run."
        );
    }

    let Some(total) = v.get("total_mutants").and_then(|t| t.as_u64()) else {
        bail!(
            "{path}: cargo-mutants wrote no `total_mutants` count, so the run did not \
             complete. Treating this as clean would report coverage that was never \
             measured."
        );
    };
    if total == 0 {
        bail!(
            "{path}: cargo-mutants tested zero mutants. A claim-surface file with \
             nothing to mutate is not covered, it is unmeasured — either the run \
             aborted before mutating anything, or `--file` matched no code."
        );
    }
    // `total_mutants` counts mutants tested *so far*: cargo-mutants rewrites
    // the file after every scenario and stamps `end_time` only when the lab
    // finishes. A run stopped part-way through this file has a real total and
    // no end.
    if v.get("end_time").is_none_or(serde_json::Value::is_null) {
        bail!(
            "{path}: cargo-mutants stopped after testing {total} mutants and never \
             recorded finishing (no `end_time`), so it was interrupted part-way through \
             this file. Its survivors so far are real, but the file is unmeasured, not clean."
        );
    }
    Ok(total)
}

/// Refuse to mutate with anything but the pinned cargo-mutants.
fn ensure_cargo_mutants(pinned: &str) -> Result<()> {
    let install = format!("`cargo install --locked cargo-mutants@{pinned}`");
    let output = std::process::Command::new("cargo")
        .args(["mutants", "--version"])
        .stderr(std::process::Stdio::null())
        .output();
    let stdout = match output {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).into_owned(),
        _ => bail!("cargo-mutants is not installed — {install}"),
    };
    match installed_mutator_version(&stdout) {
        Some(found) if found == pinned => Ok(()),
        Some(found) => bail!(
            "cargo-mutants {found} is installed, but [workspace.metadata.mvm.toolchain] pins \
             {pinned}; the baseline's accepted misses are matched on the descriptions the \
             pinned version renders — {install}"
        ),
        None => bail!(
            "could not read a version from `cargo mutants --version` ({:?}) — {install}",
            stdout.trim()
        ),
    }
}

#[cfg(test)]
mod baseline_guard_tests {
    use super::*;

    /// Verbatim shape cargo-mutants 27.1 writes when the unmutated tree
    /// fails its own tests: an `outcomes` array carrying only the failed
    /// Baseline scenario, and no counts at all.
    const BASELINE_FAILED: &str = r#"{
  "outcomes": [
    {
      "scenario": "Baseline",
      "summary": "Failure",
      "log_path": "log/baseline.log"
    }
  ]
}"#;

    /// The same file from a completed run, trimmed to its counts.
    const COMPLETED: &str = r#"{
  "outcomes": [],
  "total_mutants": 17,
  "missed": 0,
  "caught": 17,
  "timeout": 0,
  "unviable": 0,
  "end_time": "2026-09-24T05:29:14.1841255Z"
}"#;

    /// Verbatim shape observed running this gate's own surface over
    /// `crates/mvm-build/src/app_deps_gate.rs`: three of that package's
    /// tests outran the per-test budget, so the *baseline* timed out.
    /// cargo-mutants found 33 mutants, tested none of them, and still
    /// wrote every count as zero.
    const BASELINE_TIMED_OUT: &str = r#"{
  "outcomes": [
    {
      "scenario": "Baseline",
      "summary": "Timeout",
      "log_path": "log/baseline.log"
    }
  ],
  "total_mutants": 0,
  "missed": 0,
  "caught": 0,
  "timeout": 0,
  "unviable": 0
}"#;

    #[test]
    fn a_failed_baseline_is_an_error_not_a_clean_file() {
        let err = ensure_mutants_actually_ran(BASELINE_FAILED, "crates/x/src/y.rs")
            .expect_err("a run that tested no mutants must not read as clean");
        let msg = err.to_string();
        assert!(msg.contains("crates/x/src/y.rs"), "{msg}");
        assert!(msg.contains("unmeasured"), "{msg}");
    }

    #[test]
    fn a_completed_run_reports_its_mutant_count() {
        assert_eq!(
            ensure_mutants_actually_ran(COMPLETED, "crates/x/src/y.rs").unwrap(),
            17
        );
    }

    /// A run that stopped before writing counts, without a Baseline entry
    /// to explain why, is still unmeasured.
    #[test]
    fn missing_counts_are_an_error() {
        let err = ensure_mutants_actually_ran(r#"{"outcomes": []}"#, "crates/x/src/y.rs")
            .expect_err("no total_mutants means the run did not complete");
        assert!(err.to_string().contains("total_mutants"), "{err}");
    }

    #[test]
    fn unparseable_outcomes_are_an_error() {
        assert!(ensure_mutants_actually_ran("not json", "crates/x/src/y.rs").is_err());
    }

    /// Zero surviving mutants out of a real total is the genuinely clean
    /// case and must stay distinguishable from the two above.
    #[test]
    fn a_clean_file_is_still_accepted() {
        assert_eq!(ensure_mutants_actually_ran(COMPLETED, "p").unwrap(), 17);
        assert!(parse_missed("").is_empty());
    }

    /// A timed-out baseline tested nothing, exactly like a failed one. It
    /// was not caught while the check enumerated known failure summaries,
    /// which is why the check now asks for `Success` instead.
    #[test]
    fn a_timed_out_baseline_is_an_error_not_a_clean_file() {
        let err = ensure_mutants_actually_ran(BASELINE_TIMED_OUT, "crates/x/src/y.rs")
            .expect_err("a baseline that timed out tested no mutants");
        let msg = err.to_string();
        assert!(msg.contains("Timeout"), "{msg}");
        assert!(msg.contains("unmeasured"), "{msg}");
    }

    /// Any baseline verdict other than success is unmeasured, including
    /// one this code has never seen. Enumerating known failures would let
    /// a new cargo-mutants summary read as coverage.
    #[test]
    fn an_unrecognised_baseline_verdict_is_an_error() {
        let json = r#"{
  "outcomes": [{"scenario": "Baseline", "summary": "SomeFutureVerdict"}],
  "total_mutants": 0
}"#;
        let err = ensure_mutants_actually_ran(json, "crates/x/src/y.rs")
            .expect_err("an unknown baseline verdict is not evidence anything ran");
        assert!(err.to_string().contains("SomeFutureVerdict"), "{err}");
    }

    /// A run that completed its baseline but mutated nothing is also
    /// unmeasured: a claim-surface file with no mutants tells you nothing
    /// about its witness.
    #[test]
    fn zero_mutants_tested_is_an_error_even_with_a_passing_baseline() {
        let json = r#"{
  "outcomes": [{"scenario": "Baseline", "summary": "Success"}],
  "total_mutants": 0,
  "missed": 0,
  "caught": 0
}"#;
        let err = ensure_mutants_actually_ran(json, "crates/x/src/y.rs")
            .expect_err("zero mutants is not coverage");
        assert!(err.to_string().contains("zero mutants"), "{err}");
    }

    /// A successful baseline alongside a real total is still accepted —
    /// the new checks must not reject the shape a healthy run writes.
    #[test]
    fn a_successful_baseline_with_mutants_is_accepted() {
        let json = r#"{
  "outcomes": [{"scenario": "Baseline", "summary": "Success"}],
  "total_mutants": 33,
  "missed": 2,
  "caught": 31,
  "end_time": "2026-09-24T05:29:14.1841255Z"
}"#;
        assert_eq!(
            ensure_mutants_actually_ran(json, "crates/x/src/y.rs").unwrap(),
            33
        );
    }

    /// cargo-mutants rewrites `outcomes.json` after every mutant, so a run
    /// stopped part-way through a file leaves a healthy baseline and a real
    /// running total. Only the missing `end_time` says it never finished.
    #[test]
    fn a_run_interrupted_part_way_through_a_file_is_unmeasured() {
        let json = r#"{
  "outcomes": [{"scenario": "Baseline", "summary": "Success"}],
  "total_mutants": 12,
  "missed": 0,
  "caught": 12,
  "end_time": null
}"#;
        let err = ensure_mutants_actually_ran(json, "crates/x/src/y.rs")
            .expect_err("a run that never finished is not a clean file");
        let msg = err.to_string();
        assert!(msg.contains("end_time"), "{msg}");
        assert!(msg.contains("unmeasured"), "{msg}");
    }
}

#[cfg(test)]
mod evidence_tests {
    use super::*;

    const PIN: &str = "27.1.0";

    fn surface_file(path: &str) -> SurfaceFile {
        SurfaceFile {
            path: path.to_string(),
            package: "mvm-cli".to_string(),
            claims: vec![20],
            scope: None,
            features: Vec::new(),
        }
    }

    /// The shape cargo-mutants writes, trimmed to the fields the gate reads.
    fn outcomes(version: &str, finished: bool, tested: u64) -> String {
        let end = if finished {
            r#""2026-09-24T05:29:14.1841255Z""#
        } else {
            "null"
        };
        format!(
            r#"{{
  "outcomes": [{{"scenario": "Baseline", "summary": "Success"}}],
  "total_mutants": {tested},
  "missed": 0,
  "caught": {tested},
  "start_time": "2026-09-24T04:44:12.7668693Z",
  "end_time": {end},
  "cargo_mutants_version": "{version}"
}}"#
        )
    }

    /// Lay out one file's output exactly where a run puts it.
    fn write_output(root: &Path, path: &str, outcomes_json: &str, missed: &str) {
        let report = file_output_dir(root, path).join("mutants.out");
        std::fs::create_dir_all(&report).unwrap();
        std::fs::write(report.join("outcomes.json"), outcomes_json).unwrap();
        std::fs::write(report.join("missed.txt"), missed).unwrap();
        std::fs::write(report.join("caught.txt"), "").unwrap();
    }

    const SHARD: [&str; 3] = [
        "crates/mvm-cli/src/commands/env/artifact_verify.rs",
        "crates/mvm-cli/src/commands/vm/audit_chain.rs",
        "crates/mvm-cli/src/update.rs",
    ];

    fn shard() -> Vec<SurfaceFile> {
        SHARD.iter().map(|p| surface_file(p)).collect()
    }

    fn judge(root: &Path, accepted: &[AcceptedMiss]) -> ShardVerdict {
        judge_shard(accepted, &collect_evidence(root, &shard(), PIN))
    }

    /// A shard its timeout stopped leaves no directory at all for the files
    /// it never reached. Those must fail by name, as unmeasured rather than
    /// as survivors, while the files it did reach are judged normally.
    #[test]
    fn a_truncated_shard_fails_its_unreached_tail_as_unmeasured() {
        let root = tempfile::tempdir().unwrap();
        write_output(root.path(), SHARD[0], &outcomes(PIN, true, 17), "");
        write_output(root.path(), SHARD[1], &outcomes(PIN, true, 9), "");

        let verdict = judge(root.path(), &[]);
        assert_eq!(
            verdict
                .unmeasured
                .iter()
                .map(|u| u.file.as_str())
                .collect::<Vec<_>>(),
            vec![SHARD[2]]
        );
        assert!(
            verdict.unmeasured[0].reason.contains("never reached"),
            "{}",
            verdict.unmeasured[0].reason
        );
        assert!(verdict.new_misses.is_empty(), "{:?}", verdict.new_misses);
    }

    /// The healthy case must stay green: every file finished under the pin,
    /// and the only survivor is an accepted one.
    #[test]
    fn a_complete_shard_passes() {
        let root = tempfile::tempdir().unwrap();
        write_output(root.path(), SHARD[0], &outcomes(PIN, true, 5), "");
        write_output(root.path(), SHARD[1], &outcomes(PIN, true, 5), "");
        write_output(
            root.path(),
            SHARD[2],
            &outcomes(PIN, true, 5),
            "crates/mvm-cli/src/update.rs:88:9: replace < with <= in install_announcement\n",
        );
        let accepted = [AcceptedMiss {
            file: SHARD[2].to_string(),
            mutant: "replace < with <= in install_announcement".to_string(),
            reason: "equivalent".to_string(),
        }];
        assert_eq!(judge(root.path(), &accepted), ShardVerdict::default());
    }

    /// The file a shard was in when it stopped has a partial report: its
    /// survivors so far are real and must still count, but the file is
    /// unmeasured.
    #[test]
    fn the_file_a_shard_stopped_in_is_unmeasured_but_its_survivors_count() {
        let root = tempfile::tempdir().unwrap();
        write_output(root.path(), SHARD[0], &outcomes(PIN, true, 17), "");
        write_output(root.path(), SHARD[1], &outcomes(PIN, true, 9), "");
        write_output(
            root.path(),
            SHARD[2],
            &outcomes(PIN, false, 4),
            "crates/mvm-cli/src/update.rs:12:5: replace verify -> bool with true\n",
        );

        let verdict = judge(root.path(), &[]);
        assert_eq!(verdict.unmeasured.len(), 1);
        assert_eq!(verdict.unmeasured[0].file, SHARD[2]);
        assert!(
            verdict.unmeasured[0].reason.contains("end_time"),
            "{}",
            verdict.unmeasured[0].reason
        );
        assert_eq!(
            verdict.new_misses,
            vec![Miss {
                file: SHARD[2].to_string(),
                mutant: "replace verify -> bool with true".to_string(),
            }]
        );
    }

    /// An accepted miss in a file the shard never measured was not
    /// re-observed, so its absence is not evidence that it is now caught.
    #[test]
    fn an_accepted_miss_in_an_unmeasured_file_is_not_reported_as_caught() {
        let root = tempfile::tempdir().unwrap();
        write_output(root.path(), SHARD[0], &outcomes(PIN, true, 17), "");
        write_output(root.path(), SHARD[1], &outcomes(PIN, true, 9), "");
        let accepted = [AcceptedMiss {
            file: SHARD[2].to_string(),
            mutant: "replace < with <= in install_announcement".to_string(),
            reason: "equivalent".to_string(),
        }];
        let verdict = judge(root.path(), &accepted);
        assert!(verdict.now_caught.is_empty(), "{:?}", verdict.now_caught);
        assert_eq!(verdict.unmeasured.len(), 1);
    }

    /// Output recorded by another cargo-mutants release renders descriptions
    /// the baseline cannot be compared against.
    #[test]
    fn output_from_another_mutator_version_is_unmeasured() {
        let root = tempfile::tempdir().unwrap();
        for path in SHARD {
            write_output(root.path(), path, &outcomes(PIN, true, 5), "");
        }
        write_output(root.path(), SHARD[1], &outcomes("27.2.0", true, 5), "");
        let verdict = judge(root.path(), &[]);
        assert_eq!(verdict.unmeasured.len(), 1);
        let reason = &verdict.unmeasured[0].reason;
        assert!(
            reason.contains("27.2.0") && reason.contains(PIN),
            "{reason}"
        );
    }

    /// Verbatim from the 2026-09-22 nightly: the mvm-cli shard's first file,
    /// where the baseline failed and the run stopped before mutating.
    #[test]
    fn a_failed_baseline_on_disk_is_unmeasured() {
        let root = tempfile::tempdir().unwrap();
        let json = r#"{
  "outcomes": [{"scenario": "Baseline", "summary": "Failure", "log_path": "log/baseline.log"}],
  "total_mutants": 0, "missed": 0, "caught": 0, "timeout": 0, "unviable": 0, "success": 0,
  "start_time": "2026-09-22T05:27:34.397291115Z",
  "end_time": "2026-09-22T05:31:08.35826663Z",
  "cargo_mutants_version": "27.1.0"
}"#;
        write_output(root.path(), SHARD[0], json, "");
        let evidence = read_file_evidence(&file_output_dir(root.path(), SHARD[0]), SHARD[0], PIN);
        let FileEvidence::Unmeasured { reason, .. } = evidence else {
            panic!("a failed baseline measured nothing: {evidence:?}");
        };
        assert!(reason.contains("Failure"), "{reason}");
    }

    #[test]
    fn a_directory_with_no_outcomes_is_unmeasured() {
        let root = tempfile::tempdir().unwrap();
        let dir = file_output_dir(root.path(), SHARD[0]);
        std::fs::create_dir_all(dir.join("mutants.out")).unwrap();
        assert!(matches!(
            read_file_evidence(&dir, SHARD[0], PIN),
            FileEvidence::Unmeasured { .. }
        ));
    }
}
