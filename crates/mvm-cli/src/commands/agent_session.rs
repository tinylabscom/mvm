//! `mvmctl agent-session` — the operator surface for durable agent sessions.
//!
//! A durable agent session outlives the sandbox that runs it: it parks
//! (releasing its sandbox) and resumes later as a fresh admission. The records
//! behind that live in `mvm_runtime::agent_session`; until this verb existed
//! nothing outside the library could see or move one.
//!
//! Deliberately **not** called `session`: `mvmctl machine session` already
//! means machine-session residency — a warm VM kept alive across calls, with
//! idle timeouts and attach — which is a different concept over a different
//! store. The types settled the collision first by taking the `AgentSession`
//! prefix; the verb follows them.

use anyhow::{Context, Result};
use clap::{Args as ClapArgs, Subcommand};

use mvm_contract::protocol::agent_session::AgentSessionId;
use mvm_core::user_config::MvmConfig;
use mvm_runtime::agent_session::{
    AgentSessionRecord, AgentSessionStore, ParkReason, SandboxResidency, StorageTier,
};

use super::Cli;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub action: AgentSessionAction,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum AgentSessionAction {
    /// List every durable agent session recorded on this host
    #[command(alias = "list")]
    Ls(LsArgs),
    /// Print one session's recorded state in full
    Show(ShowArgs),
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct LsArgs {
    /// Emit the records as JSON instead of one summary line each
    #[arg(long)]
    pub json: bool,
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct ShowArgs {
    /// Session id, as `agent-session ls` prints it
    pub session_id: String,
    /// Emit the record as JSON instead of a field-per-line summary
    #[arg(long)]
    pub json: bool,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    match args.action {
        AgentSessionAction::Ls(a) => ls(&AgentSessionStore::open(), a.json),
        AgentSessionAction::Show(a) => show(&AgentSessionStore::open(), &a.session_id, a.json),
    }
}

/// Parse an operator-supplied session id at the boundary, so a malformed one
/// is refused before it is ever joined into a store path.
fn parse_session_id(raw: &str) -> Result<AgentSessionId> {
    AgentSessionId::parse(raw).map_err(|e| anyhow::anyhow!("invalid session id '{raw}': {e}"))
}

fn ls(store: &AgentSessionStore, json: bool) -> Result<()> {
    let records = store.list()?;
    if json {
        return crate::json_out::emit_json(&records);
    }
    if records.is_empty() {
        println!("(no agent sessions)");
        return Ok(());
    }
    println!("{:<32} {:<5} RESIDENCY", "SESSION", "GEN");
    for record in &records {
        println!("{}", summary_line(record));
    }
    Ok(())
}

fn show(store: &AgentSessionStore, raw_id: &str, json: bool) -> Result<()> {
    let id = parse_session_id(raw_id)?;
    // An absent session is an error naming the id rather than an empty
    // success: "no such session" and "a session with nothing in it" are
    // different answers and an operator acts differently on each.
    let record = store
        .load(&id)
        .with_context(|| format!("no agent session '{raw_id}' on this host"))?;
    if json {
        return crate::json_out::emit_json(&record);
    }
    for line in detail_lines(&record) {
        println!("{line}");
    }
    Ok(())
}

/// The `ls` row for one session.
///
/// A parked session's reason and tier ride on the same line because they are
/// what an operator triages on: the reason says why it is waiting, and the
/// tier says what the wait costs.
fn summary_line(record: &AgentSessionRecord) -> String {
    let mut line = format!(
        "{:<32} {:<5} {}",
        record.session_id.as_str(),
        record.generation,
        residency_name(record.state)
    );
    if let Some(reason) = record.park_reason {
        line.push_str("  reason=");
        line.push_str(park_reason_name(reason));
    }
    if let Some(tier) = record.storage_tier {
        line.push_str("  tier=");
        line.push_str(storage_tier_name(tier));
    }
    line
}

/// Every recorded field of one session, one per line.
fn detail_lines(record: &AgentSessionRecord) -> Vec<String> {
    let mut lines = vec![
        format!("session:        {}", record.session_id.as_str()),
        format!("residency:      {}", residency_name(record.state)),
        format!("generation:     {}", record.generation),
        format!(
            "park reason:    {}",
            record
                .park_reason
                .map_or("-", |reason| park_reason_name(reason))
        ),
        format!(
            "storage tier:   {}",
            record.storage_tier.map_or("-", storage_tier_name)
        ),
        format!("journal cursor: {}", record.journal_cursor),
        format!(
            "resume point:   {}",
            record
                .parent_checkpoint
                .as_ref()
                .map_or_else(|| "-".to_string(), ToString::to_string)
        ),
    ];
    // The head is a digest, not a secret, so it is printed as recorded. Its
    // *absence* is the reportable fact: the store's resume fence has nothing
    // to compare against for a session parked without one, so that session
    // resumes unfenced and an operator should be able to see it.
    lines.push(match record.approval_head.as_ref() {
        Some(head) => format!("approval head:  {head}"),
        None => "approval head:  (none recorded — this session resumes unfenced)".to_string(),
    });
    lines.push(format!(
        "members:        {}",
        if record.members.is_empty() {
            "-".to_string()
        } else {
            record.members.join(", ")
        }
    ));
    lines.push(format!("created (unix): {}", record.created_unix));
    lines.push(format!("updated (unix): {}", record.updated_unix));
    lines
}

fn residency_name(state: SandboxResidency) -> &'static str {
    match state {
        SandboxResidency::Active => "active",
        SandboxResidency::Hibernated => "hibernated",
        SandboxResidency::Closed => "closed",
    }
}

/// The operator-facing spelling of a park reason. Shared by the renderer and
/// by `--reason` parsing, so what an operator reads back is exactly what they
/// may type.
fn park_reason_name(reason: ParkReason) -> &'static str {
    match reason {
        ParkReason::ApprovalWait => "approval-wait",
        ParkReason::Idle => "idle",
        ParkReason::HostShutdown => "host-shutdown",
        ParkReason::Operator => "operator",
        ParkReason::RetentionDemotion => "retention-demotion",
    }
}

fn storage_tier_name(tier: StorageTier) -> &'static str {
    match tier {
        StorageTier::Resident => "resident",
        StorageTier::Parked => "parked",
        StorageTier::Cold => "cold",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::checkpoint::{ApprovalHead, CheckpointDigest};
    use mvm_runtime::agent_session::ParkInput;

    fn active(id: &str) -> AgentSessionRecord {
        AgentSessionRecord {
            session_id: AgentSessionId::parse(id).unwrap(),
            generation: 1,
            state: SandboxResidency::Active,
            members: vec!["vm-alpha".to_string()],
            parent_checkpoint: Some(
                CheckpointDigest::parse(format!("sha256:{}", "1a".repeat(32))).unwrap(),
            ),
            created_unix: 1_755_000_000,
            updated_unix: 1_755_000_000,
            journal_cursor: 7,
            approval_head: None,
            storage_tier: None,
            park_reason: None,
        }
    }

    /// Park through the real transition rather than writing `Hibernated` into
    /// a literal, so the fixture cannot describe a state the state machine
    /// would never produce.
    fn parked(id: &str, reason: ParkReason) -> AgentSessionRecord {
        active(id)
            .park(
                &ParkInput {
                    reason,
                    journal_cursor: 7,
                    approval_head: Some(
                        ApprovalHead::parse(format!("sha256:{}", "ab".repeat(32))).unwrap(),
                    ),
                },
                1_755_000_100,
            )
            .unwrap()
    }

    #[test]
    fn an_active_session_renders_its_residency_and_nothing_about_a_park() {
        let line = summary_line(&active("sess-alpha"));
        assert!(line.contains("sess-alpha"), "{line}");
        assert!(line.contains("active"), "{line}");
        assert!(!line.contains("reason="), "{line}");
        assert!(!line.contains("tier="), "{line}");
    }

    #[test]
    fn a_parked_session_renders_its_reason_and_tier() {
        // The tier is not decoration: approval-wait selects `parked`, so the
        // rendered row is also how an operator sees what the wait costs.
        let line = summary_line(&parked("sess-beta", ParkReason::ApprovalWait));
        assert!(line.contains("hibernated"), "{line}");
        assert!(line.contains("reason=approval-wait"), "{line}");
        assert!(line.contains("tier=parked"), "{line}");
    }

    #[test]
    fn an_idle_park_renders_the_resident_tier_it_actually_selects() {
        let line = summary_line(&parked("sess-gamma", ParkReason::Idle));
        assert!(line.contains("reason=idle"), "{line}");
        assert!(line.contains("tier=resident"), "{line}");
    }

    #[test]
    fn a_closed_session_renders_as_closed() {
        let mut record = active("sess-delta");
        record.state = SandboxResidency::Closed;
        assert!(summary_line(&record).contains("closed"));
    }

    #[test]
    fn detail_says_when_no_approval_head_was_recorded() {
        let lines = detail_lines(&active("sess-alpha")).join("\n");
        assert!(
            lines.contains("approval head:  (none recorded"),
            "an unfenced session must say so: {lines}"
        );
    }

    #[test]
    fn detail_prints_a_recorded_approval_head_as_the_digest_it_is() {
        let record = parked("sess-alpha", ParkReason::Operator);
        let lines = detail_lines(&record).join("\n");
        assert!(
            lines.contains(&format!("sha256:{}", "ab".repeat(32))),
            "the head is a digest, not a secret: {lines}"
        );
    }

    #[test]
    fn detail_carries_every_recorded_field() {
        let record = parked("sess-alpha", ParkReason::ApprovalWait);
        let lines = detail_lines(&record).join("\n");
        for expected in [
            "session:        sess-alpha",
            "residency:      hibernated",
            "generation:     1",
            "park reason:    approval-wait",
            "storage tier:   parked",
            "journal cursor: 7",
            "members:        vm-alpha",
        ] {
            assert!(lines.contains(expected), "missing `{expected}`:\n{lines}");
        }
        assert!(
            lines.contains(&format!("resume point:   sha256:{}", "1a".repeat(32))),
            "{lines}"
        );
    }

    #[test]
    fn an_absent_session_is_an_error_naming_the_id() {
        let tmp = tempfile::tempdir().unwrap();
        let store = AgentSessionStore::at(tmp.path());
        let err = show(&store, "sess-nope", false).expect_err("an absent session must refuse");
        assert!(
            format!("{err}").contains("sess-nope"),
            "the refusal must name the id: {err}"
        );
    }

    #[test]
    fn a_malformed_session_id_is_refused_before_it_reaches_the_store() {
        let tmp = tempfile::tempdir().unwrap();
        let store = AgentSessionStore::at(tmp.path());
        let err = show(&store, "../escape", false).expect_err("a path-escaping id must refuse");
        assert!(format!("{err}").contains("invalid session id"), "{err}");
    }

    #[test]
    fn ls_on_an_empty_store_is_a_success() {
        let tmp = tempfile::tempdir().unwrap();
        let store = AgentSessionStore::at(tmp.path().join("not-created-yet"));
        ls(&store, false).expect("an empty host has no sessions, which is not an error");
    }
}
