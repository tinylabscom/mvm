//! `trust audit sessions`, `trust audit show <session>`, and
//! `trust audit verify <session>`: the per-session view of the chain-signed
//! log. The logic lives in `mvm_hostd::audit::session`; this is rendering.

use anyhow::{Context, Result};
use chrono::{DateTime, NaiveDate, Utc};
use serde::Serialize;

use mvm_hostd::audit::session::{
    EventFilter, LedgerCheck, SessionSummary, SessionVerification, TimeRange, Verdict,
    list_sessions, resolve_session, session_events, verify_session_in_lines,
};

use super::{default_audit_dir, host_signer, print_chain_line, ui};

/// `trust audit verify [SESSION]`.
#[derive(clap::Args, Debug, Clone)]
pub(in crate::commands) struct VerifyArgs {
    /// Session to verify: its plan id, or at least 8 leading hex characters
    /// of it (see `trust audit sessions`).
    pub session: Option<String>,
    /// Tenant whose chain to verify. Defaults to `"local"`.
    #[arg(long, default_value = "local")]
    pub tenant: String,
    /// Print the session verdict as JSON. Requires SESSION.
    #[arg(long, requires = "session")]
    pub json: bool,
}

/// `trust audit sessions`.
#[derive(clap::Args, Debug, Clone)]
pub(in crate::commands) struct SessionsArgs {
    /// Tenant whose sessions to list. Defaults to `"local"`.
    #[arg(long, default_value = "local")]
    pub tenant: String,
    /// Only sessions active at or after this time: RFC 3339, YYYY-MM-DD, or a
    /// duration back from now (30m, 12h, 7d).
    #[arg(long, value_parser = parse_time_bound)]
    pub since: Option<DateTime<Utc>>,
    /// Only sessions active at or before this time (same forms as --since).
    #[arg(long, value_parser = parse_time_bound)]
    pub until: Option<DateTime<Utc>>,
    /// Emit the sessions and the ledger check as JSON.
    #[arg(long)]
    pub json: bool,
}

/// `trust audit show <SESSION>`.
#[derive(clap::Args, Debug, Clone)]
pub(in crate::commands) struct ShowArgs {
    /// The session: its plan id (`sha256:<hex>`), or at least 8 leading hex
    /// characters of it.
    pub session: String,
    /// Tenant whose chain to search. Defaults to `"local"`.
    #[arg(long, default_value = "local")]
    pub tenant: String,
    /// Only entries whose event name matches this glob (`plan.*`, `*.sealed`).
    #[arg(long)]
    pub kind: Option<String>,
    /// Only entries at or after this time: RFC 3339, YYYY-MM-DD, or a
    /// duration back from now (30m, 12h, 7d).
    #[arg(long, value_parser = parse_time_bound)]
    pub since: Option<DateTime<Utc>>,
    /// Only entries at or before this time (same forms as --since).
    #[arg(long, value_parser = parse_time_bound)]
    pub until: Option<DateTime<Utc>>,
    /// Emit matching entries as a JSON array to stdout.
    #[arg(long)]
    pub json: bool,
}

/// Parse a `--since` / `--until` bound: an RFC 3339 timestamp, a calendar
/// date (midnight UTC), or a duration back from now (`30m`, `12h`, `7d`).
pub(in crate::commands) fn parse_time_bound(raw: &str) -> Result<DateTime<Utc>, String> {
    parse_time_bound_at(raw, Utc::now())
}

fn parse_time_bound_at(raw: &str, now: DateTime<Utc>) -> Result<DateTime<Utc>, String> {
    let raw = raw.trim();
    if let Some(at) = mvm_core::util::time::parse_iso8601(raw) {
        return Ok(at);
    }
    if let Ok(date) = NaiveDate::parse_from_str(raw, "%Y-%m-%d") {
        return Ok(date
            .and_hms_opt(0, 0, 0)
            .expect("midnight exists on every date")
            .and_utc());
    }
    let ago = mvm_core::crypto::policy::parse_ttl(raw).map_err(|_| {
        format!(
            "{raw:?} is not a time: use an RFC 3339 timestamp, a YYYY-MM-DD date, or a \
             duration back from now such as 30m, 12h or 7d"
        )
    })?;
    let ago = chrono::Duration::from_std(ago).map_err(|e| e.to_string())?;
    Ok(now - ago)
}

fn range(since: Option<DateTime<Utc>>, until: Option<DateTime<Utc>>) -> TimeRange {
    TimeRange { since, until }
}

/// Whether `tenant` has any chain at all, checked without touching the host
/// signer so a read on a pristine host never mints a keypair.
fn has_chain(dir: &std::path::Path, tenant: &str) -> Result<bool> {
    Ok(!mvm_client::audit::discover_source_ids(dir, Some(tenant))
        .context("enumerating audit sources")?
        .is_empty())
}

/// The tenant's chain lines, verified. Refuses a chain that does not verify:
/// a listing is presented as fact, so it may only be drawn from a chain that
/// is.
fn verified_lines(tenant: &str) -> Result<Option<Vec<String>>> {
    let dir = default_audit_dir()?;
    if !has_chain(&dir, tenant)? {
        return Ok(None);
    }
    let signer =
        host_signer::load_or_init().context("loading host signer to read the audit chain")?;
    mvm_hostd::audit::merkle::read_leaves(&dir, tenant, &signer.verifying)
        .map(Some)
        .with_context(|| {
            format!(
                "the audit chain for tenant '{tenant}' does not verify; run \
                 `mvmctl trust audit verify --tenant {tenant}` for the reason"
            )
        })
}

/// The `--json` shape of `trust audit sessions`.
#[derive(Serialize)]
struct SessionList<'a> {
    tenant: &'a str,
    ledger: LedgerCheck,
    sessions: Vec<SessionSummary>,
}

pub(in crate::commands) fn audit_sessions(query: &SessionsArgs) -> Result<()> {
    let tenant = query.tenant.as_str();
    let Some(lines) = verified_lines(tenant)? else {
        if query.json {
            return crate::json_out::emit_json(&SessionList {
                tenant,
                ledger: LedgerCheck {
                    seals: 0,
                    intact: true,
                    detail: None,
                },
                sessions: Vec::new(),
            });
        }
        ui::info(&format!("No audit chain for tenant '{tenant}'."));
        return Ok(());
    };
    let (sessions, ledger) = list_sessions(&lines, range(query.since, query.until))?;
    if query.json {
        return crate::json_out::emit_json(&SessionList {
            tenant,
            ledger,
            sessions,
        });
    }
    if sessions.is_empty() {
        ui::info(&format!("No sessions for tenant '{tenant}' in that range."));
    } else {
        println!(
            "{:<14} {:<27} {:>6}  {:<22} IMAGE",
            "SESSION", "STARTED", "EVENTS", "STATE"
        );
        for session in &sessions {
            println!(
                "{:<14} {:<27} {:>6}  {:<22} {}",
                short_id(&session.plan_id),
                session.started_at,
                session.event_count,
                session_state(session),
                session.image_name
            );
        }
    }
    if ledger.intact {
        ui::info(&format!(
            "Session ledger: {} seal(s), linked.",
            ledger.seals
        ));
    } else {
        ui::warn(&format!(
            "Session ledger is BROKEN: {}",
            ledger.detail.as_deref().unwrap_or("a seal does not link")
        ));
    }
    Ok(())
}

/// The session id as operators type it: the first 12 hex characters of the
/// plan id.
pub(in crate::commands) fn short_id(plan_id: &str) -> &str {
    let bare = plan_id.strip_prefix("sha256:").unwrap_or(plan_id);
    &bare[..bare.len().min(12)]
}

fn session_state(session: &SessionSummary) -> String {
    let Some(seal) = &session.seal else {
        return if session.sealed {
            "sealed (unreadable)".to_string()
        } else {
            "unsealed".to_string()
        };
    };
    match (&seal.exit_code, &seal.error_class) {
        (Some(code), _) => format!("sealed (exit {code})"),
        (None, Some(class)) => format!("sealed (failed: {class})"),
        (None, None) => format!("sealed ({})", reason_label(seal.reason)),
    }
}

fn reason_label(reason: mvm_hostd::audit::session::SealReason) -> &'static str {
    match reason {
        mvm_hostd::audit::session::SealReason::Exited => "exited",
        mvm_hostd::audit::session::SealReason::Failed => "failed",
        mvm_hostd::audit::session::SealReason::Stopped => "stopped",
    }
}

pub(in crate::commands) fn audit_show(query: &ShowArgs) -> Result<()> {
    let tenant = query.tenant.as_str();
    let Some(lines) = verified_lines(tenant)? else {
        if query.json {
            return crate::json_out::emit_json(&Vec::<()>::new());
        }
        ui::info(&format!("No audit chain for tenant '{tenant}'."));
        return Ok(());
    };
    let plan_id = resolve_or_exact(&lines, &query.session)?;
    let filter = EventFilter {
        kind: query.kind.clone(),
        range: range(query.since, query.until),
    };
    let events = session_events(&lines, &plan_id, &filter)?;
    if query.json {
        return crate::json_out::emit_json(&events);
    }
    if events.is_empty() {
        ui::info(&format!(
            "No entries for session {plan_id} in tenant '{tenant}' match those filters."
        ));
    }
    for event in &events {
        print_chain_line(&lines[event.seq as usize]);
    }
    Ok(())
}

/// A session selector, or — for host-level entries that belong to no admitted
/// session — an exact plan id that appears in the chain.
fn resolve_or_exact(lines: &[String], selector: &str) -> Result<String> {
    match resolve_session(lines, selector) {
        Ok(plan_id) => Ok(plan_id),
        Err(error) => {
            let quoted = format!("\"plan_id\":\"{selector}\"");
            if lines.iter().any(|line| line.contains(&quoted)) {
                Ok(selector.to_string())
            } else {
                Err(error)
            }
        }
    }
}

/// The `--json` shape of `trust audit verify <session>`.
#[derive(Serialize)]
struct VerifyReport<'a> {
    tenant: &'a str,
    #[serde(flatten)]
    report: &'a SessionVerification,
}

/// Verify one session and exit with its verdict's status: 0 verified,
/// 1 mismatch, 2 unsealed, 3 not found.
pub(in crate::commands) fn audit_verify_session(
    tenant: &str,
    session: &str,
    json: bool,
) -> Result<()> {
    let dir = default_audit_dir()?;
    let report = if has_chain(&dir, tenant)? {
        let signer =
            host_signer::load_or_init().context("loading host signer to verify the session")?;
        // One walk from genesis serves both the selector and the verdict.
        match mvm_hostd::audit::session::read_lines_from_genesis(&dir, tenant, &signer.verifying) {
            Ok(lines) => {
                let plan_id =
                    resolve_or_exact(&lines, session).unwrap_or_else(|_| session.to_string());
                verify_session_in_lines(&lines, &plan_id)
            }
            // The chain's reason is the session's: a seal inside a broken
            // chain vouches for nothing.
            Err((reason, detail)) => SessionVerification::chain_failure(session, reason, detail),
        }
    } else {
        let mut report = verify_session_absent(session);
        report.detail = Some(format!("no audit chain for tenant '{tenant}'"));
        report
    };
    if json {
        crate::json_out::emit_json(&VerifyReport {
            tenant,
            report: &report,
        })?;
    } else {
        print_verdict(&report);
    }
    match report.verdict.exit_code() {
        0 => Ok(()),
        code => mvm_observability::exit(code),
    }
}

fn verify_session_absent(session: &str) -> SessionVerification {
    verify_session_in_lines(&[], session)
}

fn print_verdict(report: &SessionVerification) {
    let id = &report.plan_id;
    match report.verdict {
        Verdict::Verified => {
            let seal = report.seals.last().map(|check| &check.seal);
            let root = seal.map_or("", |s| &s.session_root[..12]);
            println!(
                "VERIFIED  session {id}: {} entries, {} seal(s), session root {root}…",
                report.event_count,
                report.seals.len()
            );
            if report.late_entries > 0 {
                ui::warn(&format!(
                    "{} entr(ies) were appended after the last seal and are not covered by it",
                    report.late_entries
                ));
            }
        }
        Verdict::Mismatch => println!(
            "MISMATCH  session {id}: {} — {}",
            report.reason.map(reason_name).unwrap_or("unknown"),
            report.detail.as_deref().unwrap_or("")
        ),
        Verdict::Unsealed => println!(
            "UNSEALED  session {id}: {} entries verify, but {}",
            report.event_count,
            report.detail.as_deref().unwrap_or("there is no seal")
        ),
        Verdict::NotFound => println!(
            "NOT_FOUND session {id}: {}",
            report.detail.as_deref().unwrap_or("no such session")
        ),
    }
}

fn reason_name(reason: mvm_hostd::audit::session::MismatchReason) -> &'static str {
    use mvm_hostd::audit::session::MismatchReason as R;
    match reason {
        R::ChainBreak => "chain break",
        R::Signature => "signature",
        R::Malformed => "malformed entry",
        R::TruncatedTail => "truncated tail",
        R::CountMismatch => "count mismatch",
        R::SequenceMismatch => "sequence mismatch",
        R::RootMismatch => "root mismatch",
        R::HeadMismatch => "chain head mismatch",
        R::LedgerBreak => "ledger break",
        R::MalformedSeal => "malformed seal",
        R::Io => "unreadable chain",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> DateTime<Utc> {
        s.parse().unwrap()
    }

    #[test]
    fn time_bounds_accept_timestamps_dates_and_durations_back_from_now() {
        let now = at("2026-09-26T12:00:00Z");
        assert_eq!(
            parse_time_bound_at("2026-09-01T08:30:00Z", now).unwrap(),
            at("2026-09-01T08:30:00Z")
        );
        assert_eq!(
            parse_time_bound_at("2026-09-01", now).unwrap(),
            at("2026-09-01T00:00:00Z")
        );
        assert_eq!(
            parse_time_bound_at("2h", now).unwrap(),
            at("2026-09-26T10:00:00Z")
        );
        assert_eq!(
            parse_time_bound_at("7d", now).unwrap(),
            at("2026-09-19T12:00:00Z")
        );
        let err = parse_time_bound_at("yesterday", now).unwrap_err();
        assert!(err.contains("RFC 3339"), "{err}");
    }

    #[test]
    fn a_session_id_is_twelve_hex_characters_of_the_plan_id() {
        assert_eq!(short_id("sha256:0123456789abcdef"), "0123456789ab");
        assert_eq!(short_id("short"), "short");
    }

    #[test]
    fn an_absent_chain_reports_the_session_as_not_found() {
        let report = verify_session_absent("sha256:ab");
        assert_eq!(report.verdict, Verdict::NotFound);
        assert_eq!(report.verdict.exit_code(), 3);
    }
}
