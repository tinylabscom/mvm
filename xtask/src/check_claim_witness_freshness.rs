//! `xtask check-claim-witness-freshness`
//!
//! A claim whose witness is a CI lane has two ways to stop backing it. The
//! lane can go **red**, and the lane can stop **running**.
//!
//! `Security lane watch` reports a red lane, but it triggers on
//! `workflow_run: [Security] completed` — so it fires only when Security
//! finishes. When the schedule itself stops firing, nothing completes,
//! nothing reports, and the silence is indistinguishable from health. That
//! is not hypothetical: this repo's Security workflow ran nightly to
//! 2026-06-16, then did not run again until 2026-07-21. Five weeks with
//! every claim's ledger entry green and no evidence behind any of them.
//!
//! This gate is the independent backstop for both failure modes. For every
//! scheduled workflow that anchors a `ci:` witness, it reads the most recent
//! scheduled run and fails when that run is older than the schedule can
//! explain or did not complete successfully. Re-checking the conclusion is
//! intentional: GitHub can omit a `workflow_run` delivery, so the event-driven
//! watcher cannot be the only observer of a failed nightly.

use anyhow::{Context, Result, bail};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::claims_ledger::{self, Witness};

/// How many missed firings to tolerate before calling a lane stale.
///
/// One missed nightly is a runner hiccup; three in a row is the schedule
/// not running. Tolerating a couple of misses keeps the tracking issue
/// meaningful instead of flapping on transient GitHub capacity.
const MISSED_FIRINGS_ALLOWED: u32 = 3;

/// A workflow that anchors at least one `ci:` witness.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct WitnessWorkflow {
    /// File name as the Actions API addresses it, e.g. `security.yml`.
    pub file: String,
    /// Claim numbers whose witnesses anchor here, sorted.
    pub claims: Vec<u32>,
    /// Witness tokens that resolved to this file, sorted.
    pub witnesses: Vec<String>,
    /// Shortest scheduled interval in hours, or None when the workflow
    /// carries no cron this gate can reason about.
    pub schedule_hours: Option<u32>,
}

impl WitnessWorkflow {
    /// Oldest a successful run may be before the lane counts as stale.
    fn max_age_hours(&self) -> Option<u32> {
        self.schedule_hours
            .map(|h| h.saturating_mul(MISSED_FIRINGS_ALLOWED))
    }
}

/// What a single lane's most recent run says about its freshness.
#[derive(Debug, PartialEq, Eq)]
pub enum Freshness {
    /// Ran recently enough for its schedule.
    Fresh,
    /// The schedule should have fired by now and did not.
    Stale { age_hours: u32, allowed_hours: u32 },
    /// The workflow has never run at all.
    NeverRan,
    /// No cron this gate can reason about, so absence carries no signal —
    /// a pull-request-triggered lane is legitimately idle on a quiet day.
    NotScheduled,
}

/// The fields needed from the latest scheduled Actions run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LatestRun {
    pub created_at: String,
    pub status: String,
    pub conclusion: Option<String>,
}

/// Whether the latest scheduled run established healthy evidence.
#[derive(Debug, PartialEq, Eq)]
pub enum RunOutcome {
    Healthy,
    Unhealthy {
        status: String,
        conclusion: Option<String>,
    },
}

pub fn run(workspace: &Path, check_reporting: bool) -> Result<()> {
    let workflows = resolve_witness_workflows(workspace)?;
    if workflows.is_empty() {
        bail!(
            "check-claim-witness-freshness: no ci: witness resolved to a workflow file — \
             either the ledger has no ci: witnesses or resolution is broken (run check-claim-catalog)"
        );
    }

    let mut problems = Vec::new();
    let mut checked = 0usize;
    let mut skipped = Vec::new();

    for wf in &workflows {
        let allowed = wf.max_age_hours();
        if !should_read_run_history(allowed, check_reporting) {
            match allowed {
                Some(_) => checked += 1,
                None => skipped.push(wf.file.clone()),
            }
            continue;
        }
        // Only pay for an API call once the schedule says absence means
        // something.
        let latest = match allowed {
            Some(_) => latest_scheduled_run(&wf.file)?,
            None => None,
        };
        let age = latest
            .as_ref()
            .map(|run| {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .context("reading the system clock")?
                    .as_secs() as i64;
                age_hours_since(&run.created_at, now).with_context(|| {
                    format!(
                        "interpreting run timestamp {:?} for {}",
                        run.created_at, wf.file
                    )
                })
            })
            .transpose()?;
        match classify(age, allowed) {
            Freshness::NotScheduled => skipped.push(wf.file.clone()),
            Freshness::Fresh => {
                let run = latest
                    .as_ref()
                    .expect("a fresh verdict requires a latest scheduled run");
                match classify_outcome(run) {
                    RunOutcome::Healthy => checked += 1,
                    RunOutcome::Unhealthy { status, conclusion } => problems.push(format!(
                        "{} latest scheduled run has status {status:?} and conclusion {:?} — \
                         claim(s) {:?} are witnessed by {:?}",
                        wf.file, conclusion, wf.claims, wf.witnesses
                    )),
                }
            }
            Freshness::NeverRan => problems.push(format!(
                "{} has never run, yet it backs claim(s) {:?} via {:?}",
                wf.file, wf.claims, wf.witnesses
            )),
            Freshness::Stale {
                age_hours,
                allowed_hours,
            } => problems.push(format!(
                "{} last ran {age_hours}h ago (schedule allows {allowed_hours}h) — \
                 claim(s) {:?} are witnessed by {:?}, which has stopped firing",
                wf.file, wf.claims, wf.witnesses
            )),
        }
    }

    for f in &skipped {
        eprintln!(
            "[note] {f} carries no schedule this gate can reason about — absence is not a signal there"
        );
    }

    if !problems.is_empty() {
        bail!(
            "check-claim-witness-freshness: {} claim-bearing lane(s) are stale or unhealthy:\n  {}\n\n\
             The scheduled backstop independently verifies both cadence and conclusion because a \
             missing workflow_run delivery can otherwise hide a failed lane.",
            problems.len(),
            problems.join("\n  ")
        );
    }

    if check_reporting {
        eprintln!(
            "check-claim-witness-freshness: clean ({checked} scheduled lane(s) fresh and successful, {} unscheduled)",
            skipped.len()
        );
    } else {
        eprintln!(
            "check-claim-witness-freshness: clean ({} witness workflow(s) resolved; external run history reserved for scheduled reporting)",
            workflows.len()
        );
    }
    Ok(())
}

fn should_read_run_history(allowed_hours: Option<u32>, check_reporting: bool) -> bool {
    check_reporting && allowed_hours.is_some()
}

/// Decide freshness from an age and the schedule's allowance.
///
/// `allowed_hours: None` means the workflow carries no cron this gate can
/// reason about, so absence proves nothing and the lane is not judged.
pub fn classify(age_hours: Option<u32>, allowed_hours: Option<u32>) -> Freshness {
    let Some(allowed_hours) = allowed_hours else {
        return Freshness::NotScheduled;
    };
    match age_hours {
        None => Freshness::NeverRan,
        Some(age) if age > allowed_hours => Freshness::Stale {
            age_hours: age,
            allowed_hours,
        },
        Some(_) => Freshness::Fresh,
    }
}

pub fn classify_outcome(run: &LatestRun) -> RunOutcome {
    if run.status == "completed" && run.conclusion.as_deref() == Some("success") {
        RunOutcome::Healthy
    } else {
        RunOutcome::Unhealthy {
            status: run.status.clone(),
            conclusion: run.conclusion.clone(),
        }
    }
}

/// Map every `ci:` witness in the ledger onto the workflow file that
/// anchors it, carrying the claims and the schedule along.
pub fn resolve_witness_workflows(workspace: &Path) -> Result<Vec<WitnessWorkflow>> {
    let rows = claims_ledger::load(workspace)?;
    let mut wanted: BTreeMap<String, BTreeSet<u32>> = BTreeMap::new();
    for row in &rows {
        for w in &row.witnesses {
            if let Witness::Ci(name) = w {
                wanted.entry(name.clone()).or_default().insert(row.number);
            }
        }
    }
    if wanted.is_empty() {
        return Ok(Vec::new());
    }

    /// What one workflow file has accumulated as the walk proceeds.
    #[derive(Default)]
    struct Acc {
        claims: BTreeSet<u32>,
        witnesses: BTreeSet<String>,
        schedule_hours: Option<u32>,
    }

    let dir = workspace.join(".github").join("workflows");
    let mut by_file: BTreeMap<String, Acc> = BTreeMap::new();

    claims_ledger::for_each_file(&dir, None, &mut |path, content| {
        let Some(file) = path.file_name().and_then(|n| n.to_str()) else {
            return;
        };
        let anchors = claims_ledger::ci_anchors(content);
        let sched = shortest_schedule_hours(content);
        for (token, claims) in &wanted {
            if anchors.iter().any(|a| a == token) {
                let e = by_file.entry(file.to_string()).or_insert_with(|| Acc {
                    schedule_hours: sched,
                    ..Acc::default()
                });
                e.claims.extend(claims.iter().copied());
                e.witnesses.insert(token.clone());
            }
        }
    })?;

    Ok(by_file
        .into_iter()
        .map(|(file, acc)| WitnessWorkflow {
            file,
            claims: acc.claims.into_iter().collect(),
            witnesses: acc.witnesses.into_iter().collect(),
            schedule_hours: acc.schedule_hours,
        })
        .collect())
}

/// Shortest interval among a workflow's `cron:` entries, in hours.
///
/// Only crons that fire at least daily are reasoned about: for anything
/// restricted by day-of-month or day-of-week, the gap between firings is not
/// derivable from the expression alone, and guessing would flag a healthy
/// weekly lane as stale.
pub fn shortest_schedule_hours(content: &str) -> Option<u32> {
    let mut best: Option<u32> = None;
    for line in content.lines() {
        let t = line.trim_start();
        if t.starts_with('#') {
            continue;
        }
        let Some(rest) = t.strip_prefix("- cron:") else {
            continue;
        };
        let expr = rest.trim().trim_matches(['"', '\'']);
        if let Some(h) = cron_interval_hours(expr) {
            best = Some(best.map_or(h, |b: u32| b.min(h)));
        }
    }
    best
}

/// Interval in hours for a 5-field cron, when it fires at least daily.
pub fn cron_interval_hours(expr: &str) -> Option<u32> {
    let f: Vec<&str> = expr.split_whitespace().collect();
    if f.len() != 5 {
        return None;
    }
    let (hour, dom, month, dow) = (f[1], f[2], f[3], f[4]);
    // A restricted day means the gap between firings depends on the
    // calendar, not just the expression.
    if dom != "*" || month != "*" || dow != "*" {
        return None;
    }
    if hour == "*" {
        return Some(1);
    }
    if let Some(step) = hour.strip_prefix("*/") {
        return step.parse::<u32>().ok().filter(|s| *s > 0);
    }
    // A fixed hour, or an explicit list of them, fires that many times a day.
    let count = hour.split(',').filter(|p| !p.is_empty()).count() as u32;
    (count > 0).then(|| 24 / count.max(1))
}

/// Most recent scheduled run of `file`, or None when it has never run.
fn latest_scheduled_run(file: &str) -> Result<Option<LatestRun>> {
    let out = std::process::Command::new("gh")
        .args([
            "run",
            "list",
            "--workflow",
            file,
            "--event",
            "schedule",
            "--limit",
            "1",
            "--json",
            "createdAt,status,conclusion",
        ])
        .output()
        .with_context(|| format!("running `gh run list --workflow {file}`"))?;
    if !out.status.success() {
        bail!(
            "gh run list --workflow {file} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(first_run(&String::from_utf8_lossy(&out.stdout)))
}

/// First entry in `gh run list --json createdAt,status,conclusion` output.
pub fn first_run(json: &str) -> Option<LatestRun> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let run = v.as_array()?.first()?;
    Some(LatestRun {
        created_at: run.get("createdAt")?.as_str()?.to_string(),
        status: run.get("status")?.as_str()?.to_string(),
        conclusion: run
            .get("conclusion")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
    })
}

/// Hours between `rfc3339` and `now_unix`. Pure, so the verdict this gate
/// turns on is unit-testable rather than a function of the wall clock.
pub fn age_hours_since(rfc3339: &str, now_unix: i64) -> Result<u32> {
    let then =
        parse_utc_rfc3339(rfc3339).with_context(|| format!("parsing run timestamp {rfc3339:?}"))?;
    Ok((((now_unix - then).max(0)) / 3600) as u32)
}

/// Unix seconds for a `YYYY-MM-DDTHH:MM:SSZ` timestamp — the shape the
/// Actions API emits. Deliberately strict: anything else is an error rather
/// than a silently wrong age that would read as "fresh".
fn parse_utc_rfc3339(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let num = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, sec) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    Some(days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + sec)
}

/// Days since 1970-01-01 for a proleptic-Gregorian date (Hinnant's
/// `days_from_civil`), so no date library is needed for one subtraction.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_daily_cron_is_twenty_four_hours() {
        assert_eq!(cron_interval_hours("17 4 * * *"), Some(24));
    }

    #[test]
    fn an_hourly_cron_is_one_hour() {
        assert_eq!(cron_interval_hours("0 * * * *"), Some(1));
        assert_eq!(cron_interval_hours("0 */6 * * *"), Some(6));
    }

    #[test]
    fn twice_daily_halves_the_interval() {
        assert_eq!(cron_interval_hours("0 4,16 * * *"), Some(12));
    }

    #[test]
    fn a_weekly_cron_is_not_reasoned_about() {
        // Restricted by day-of-week: the gap is a calendar question, and
        // guessing would flag a healthy weekly lane as stale.
        assert_eq!(cron_interval_hours("0 4 * * 1"), None);
        assert_eq!(cron_interval_hours("0 4 1 * *"), None);
    }

    #[test]
    fn malformed_cron_yields_nothing() {
        assert_eq!(cron_interval_hours("not a cron"), None);
        assert_eq!(cron_interval_hours("0 4 * *"), None);
    }

    #[test]
    fn shortest_schedule_wins_and_comments_are_ignored() {
        let wf = "on:\n  schedule:\n    # - cron: \"0 * * * *\"\n    - cron: \"17 4 * * *\"\n    - cron: \"0 */6 * * *\"\n";
        assert_eq!(shortest_schedule_hours(wf), Some(6));
    }

    #[test]
    fn a_workflow_with_no_cron_has_no_schedule() {
        assert_eq!(shortest_schedule_hours("on:\n  pull_request:\n"), None);
    }

    #[test]
    fn pull_request_validation_never_reads_external_run_state() {
        assert!(!should_read_run_history(Some(72), false));
        assert!(!should_read_run_history(None, true));
        assert!(should_read_run_history(Some(72), true));
    }

    #[test]
    fn staleness_is_measured_against_missed_firings() {
        // A daily lane tolerates a couple of missed nightlies, then trips.
        let allowed = 24 * MISSED_FIRINGS_ALLOWED;
        assert_eq!(classify(Some(25), Some(allowed)), Freshness::Fresh);
        assert_eq!(
            classify(Some(allowed + 1), Some(allowed)),
            Freshness::Stale {
                age_hours: allowed + 1,
                allowed_hours: allowed
            }
        );
    }

    #[test]
    fn an_unscheduled_lane_is_never_judged_on_absence() {
        // A pull-request-triggered lane is legitimately idle on a quiet
        // day; calling that stale would be a false alarm forever.
        assert_eq!(classify(None, None), Freshness::NotScheduled);
        assert_eq!(classify(Some(10_000), None), Freshness::NotScheduled);
    }

    #[test]
    fn a_lane_that_never_ran_is_its_own_verdict() {
        assert_eq!(classify(None, Some(72)), Freshness::NeverRan);
    }

    #[test]
    fn the_five_week_gap_this_gate_exists_for_is_caught() {
        // Security ran nightly to 2026-06-16, then not again until
        // 2026-07-21 — 35 days. A red-lane watcher saw nothing, because
        // nothing completed.
        let allowed = 24 * MISSED_FIRINGS_ALLOWED;
        let gap_hours = 35 * 24;
        assert!(matches!(
            classify(Some(gap_hours), Some(allowed)),
            Freshness::Stale { .. }
        ));
    }

    #[test]
    fn latest_scheduled_run_must_complete_successfully() {
        let successful = LatestRun {
            created_at: "2026-08-21T04:17:00Z".to_string(),
            status: "completed".to_string(),
            conclusion: Some("success".to_string()),
        };
        assert_eq!(classify_outcome(&successful), RunOutcome::Healthy);

        for conclusion in ["failure", "cancelled", "timed_out"] {
            let run = LatestRun {
                conclusion: Some(conclusion.to_string()),
                ..successful.clone()
            };
            assert_eq!(
                classify_outcome(&run),
                RunOutcome::Unhealthy {
                    status: "completed".to_string(),
                    conclusion: Some(conclusion.to_string()),
                }
            );
        }

        let running = LatestRun {
            status: "in_progress".to_string(),
            conclusion: None,
            ..successful
        };
        assert_eq!(
            classify_outcome(&running),
            RunOutcome::Unhealthy {
                status: "in_progress".to_string(),
                conclusion: None,
            }
        );
    }

    #[test]
    fn first_run_reads_status_and_conclusion() {
        let json = r#"[{"createdAt":"2026-08-21T04:17:00Z","status":"completed","conclusion":"cancelled"}]"#;
        assert_eq!(
            first_run(json),
            Some(LatestRun {
                created_at: "2026-08-21T04:17:00Z".to_string(),
                status: "completed".to_string(),
                conclusion: Some("cancelled".to_string()),
            })
        );
        assert_eq!(first_run("[]"), None);
        assert_eq!(first_run("not json"), None);
    }

    #[test]
    fn epoch_and_a_known_instant_round_trip() {
        assert_eq!(super::parse_utc_rfc3339("1970-01-01T00:00:00Z"), Some(0));
        // 2026-07-31T05:26:57Z — this morning's nightly.
        let t = super::parse_utc_rfc3339("2026-07-31T05:26:57Z").unwrap();
        assert_eq!(t, 1785475617);
    }

    #[test]
    fn age_is_measured_in_whole_hours() {
        let then = "2026-07-31T00:00:00Z";
        let base = super::parse_utc_rfc3339(then).unwrap();
        assert_eq!(age_hours_since(then, base).unwrap(), 0);
        assert_eq!(age_hours_since(then, base + 3599).unwrap(), 0);
        assert_eq!(age_hours_since(then, base + 3600).unwrap(), 1);
        assert_eq!(age_hours_since(then, base + 35 * 86400).unwrap(), 840);
    }

    #[test]
    fn a_clock_behind_the_run_reads_as_zero_not_negative() {
        let then = "2026-07-31T00:00:00Z";
        let base = super::parse_utc_rfc3339(then).unwrap();
        assert_eq!(age_hours_since(then, base - 7200).unwrap(), 0);
    }

    #[test]
    fn a_malformed_timestamp_is_an_error_not_a_fresh_verdict() {
        // Silently treating an unparseable stamp as recent would make the
        // gate report health it never established.
        for bad in ["", "2026-07-31", "yesterday", "2026-13-01T00:00:00Z"] {
            assert!(age_hours_since(bad, 0).is_err(), "{bad:?} must not parse");
        }
    }
}
