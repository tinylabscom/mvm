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
use mvm_core::checkpoint::ApprovalHead;
use mvm_core::user_config::MvmConfig;
use mvm_runtime::agent_session::{
    AgentSessionRecord, AgentSessionStore, ParkInput, ParkReason, SandboxResidency, StorageTier,
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
    /// Release an active session's sandbox, recording why
    Park(ParkArgs),
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

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct ParkArgs {
    /// Session id, as `agent-session ls` prints it
    pub session_id: String,
    /// Why the session is parking. One of approval-wait, idle,
    /// host-shutdown, operator, retention-demotion. The reason selects the
    /// storage tier, so it is not decoration.
    #[arg(long)]
    pub reason: String,
    /// Session-journal position the park is consistent with. A later resume
    /// that replayed from an earlier cursor would re-run committed work.
    #[arg(long, default_value_t = 0)]
    pub journal_cursor: u64,
    /// Approval-ledger head the session was last admitted under, as
    /// `sha256:<64-hex>`. A session parked without one resumes unfenced.
    #[arg(long)]
    pub approval_head: Option<String>,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    match args.action {
        AgentSessionAction::Ls(a) => ls(&AgentSessionStore::open(), a.json),
        AgentSessionAction::Show(a) => show(&AgentSessionStore::open(), &a.session_id, a.json),
        AgentSessionAction::Park(a) => park(&AgentSessionStore::open(), &a),
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

/// Park a session, then bind the park into the chain-signed audit log.
fn park(store: &AgentSessionStore, args: &ParkArgs) -> Result<()> {
    let record = park_record(store, args)?;
    println!("{}", summary_line(&record));
    // The record is already durable at this point. A chain entry that cannot
    // be written is reported rather than raised: failing here would tell an
    // operator the park did not happen when it did, and a park with no entry
    // is the lesser of those two wrongs.
    if let Err(error) = record_park_in_chain(&record) {
        crate::ui::warn(&format!(
            "session {} parked, but the park was not recorded in the audit chain: {error:#}",
            record.session_id.as_str()
        ));
    }
    Ok(())
}

/// Apply the park to the store and return the record it wrote.
///
/// Split from the audit half so the transition is testable without a signer
/// or an audit directory.
fn park_record(store: &AgentSessionStore, args: &ParkArgs) -> Result<AgentSessionRecord> {
    let id = parse_session_id(&args.session_id)?;
    let reason = parse_park_reason(&args.reason)?;
    let approval_head = args
        .approval_head
        .as_deref()
        .map(ApprovalHead::parse)
        .transpose()
        .map_err(|e| anyhow::anyhow!("invalid --approval-head: {e}"))?;
    let current = store
        .load(&id)
        .with_context(|| format!("no agent session '{}' on this host", args.session_id))?;
    // The store's fence refuses a caller working from a record some other
    // transition has superseded. This command loaded the record a moment ago
    // and is the caller, so it passes what it just read; the fence is doing
    // nothing for it. What the fence cannot do either way is serialize two
    // concurrent parks of one session — that needs file locking the store
    // does not have.
    store.park(
        &id,
        current.generation,
        ParkInput {
            reason,
            journal_cursor: args.journal_cursor,
            approval_head,
        },
        mvm_core::util::time::now_unix_secs(),
    )
}

/// Map the `--reason` spelling onto the typed reason.
///
/// An explicit match rather than a permissive lookup: an unrecognised reason
/// is refused naming the accepted set, because falling through to a default
/// would pick a storage tier the operator never asked for.
fn parse_park_reason(raw: &str) -> Result<ParkReason> {
    match raw {
        "approval-wait" => Ok(ParkReason::ApprovalWait),
        "idle" => Ok(ParkReason::Idle),
        "host-shutdown" => Ok(ParkReason::HostShutdown),
        "operator" => Ok(ParkReason::Operator),
        "retention-demotion" => Ok(ParkReason::RetentionDemotion),
        other => anyhow::bail!(
            "unknown park reason '{other}'; accepted: approval-wait, idle, \
             host-shutdown, operator, retention-demotion"
        ),
    }
}

/// The extra labels a `session.parked` entry carries.
///
/// The keys are deliberately not `session_id` / `session_generation`. An
/// entry's extras are merged *over* the signed plan's audit labels, and a
/// resume plan carries both of those names as signed labels; an extra reusing
/// one would replace what was admitted with what this command believed, so the
/// entry would attribute the park to the emitter's belief rather than to the
/// admission. The `parked_`/`park_` prefixes keep both readable side by side.
fn park_audit_extras(record: &AgentSessionRecord) -> Vec<(String, String)> {
    let mut extras = vec![
        (
            "parked_session".to_string(),
            record.session_id.as_str().to_string(),
        ),
        (
            "parked_at_generation".to_string(),
            record.generation.to_string(),
        ),
    ];
    // Both are written by the park transition, so both are present on a record
    // this function is called with. They are still emitted conditionally
    // rather than defaulted: a blank tier would read in the chain as a tier
    // that was checked and found empty.
    if let Some(reason) = record.park_reason {
        extras.push((
            "park_reason".to_string(),
            park_reason_name(reason).to_string(),
        ));
    }
    if let Some(tier) = record.storage_tier {
        extras.push((
            "park_storage_tier".to_string(),
            storage_tier_name(tier).to_string(),
        ));
    }
    extras
}

/// Bind a completed park into the chain-signed audit log.
///
/// The entry rides on the plan the parked residency was admitted under: the
/// session record holds no plan of its own, and the member sandbox's persisted
/// plan is the authority the residency actually ran with. A session with no
/// member, or a member with no persisted plan, has nothing to bind to and is
/// reported rather than recorded under a plan it never ran.
fn record_park_in_chain(record: &AgentSessionRecord) -> Result<()> {
    let member = record.members.first().ok_or_else(|| {
        anyhow::anyhow!(
            "session {} records no member sandbox, so there is no admitted plan to bind to",
            record.session_id.as_str()
        )
    })?;
    let plan = mvm_hostd::audit::plan_persist::read_plan(member)
        .with_context(|| format!("reading the admitted plan of member sandbox '{member}'"))?;
    let signer = super::vm::host_signer::load_or_init()
        .context("loading the host signer to sign the park entry")?;
    let emitter = super::vm::audit_chain::AuditEmitter::new(signer.signing)
        .context("opening the audit chain to record the park")?;
    emitter.emit_session_parked(&plan, park_audit_extras(record))
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
    fn the_park_entry_keys_do_not_collide_with_the_plan_labels() {
        // `for_plan` extends the plan's labels with the per-event extras, so
        // an extra sharing a key silently replaces the signed plan's value.
        // The resume plan carries `session_id` and `session_generation` as
        // signed labels; a park entry must not shadow either.
        let extras = park_audit_extras(&parked("sess-alpha", ParkReason::ApprovalWait));
        let keys: Vec<&str> = extras.iter().map(|(k, _)| k.as_str()).collect();
        assert!(!keys.contains(&"session_id"), "{keys:?}");
        assert!(!keys.contains(&"session_generation"), "{keys:?}");
        assert!(!keys.is_empty(), "the entry must carry something");
    }

    #[test]
    fn park_extras_carry_what_the_store_actually_wrote() {
        let record = parked("sess-alpha", ParkReason::ApprovalWait);
        let extras = park_audit_extras(&record);
        let got = |key: &str| {
            extras
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(got("parked_session"), Some("sess-alpha"));
        // The generation is unchanged by a park — it identifies one period of
        // residency, which a park suspends rather than ends.
        assert_eq!(got("parked_at_generation"), Some("1"));
        assert_eq!(got("park_reason"), Some("approval-wait"));
        assert_eq!(got("park_storage_tier"), Some("parked"));
    }

    #[test]
    fn an_unknown_park_reason_is_refused_and_names_the_accepted_set() {
        let err = parse_park_reason("whenever").expect_err("an unknown reason must refuse");
        let text = format!("{err}");
        assert!(text.contains("whenever"), "{text}");
        for accepted in ["approval-wait", "idle", "host-shutdown", "operator"] {
            assert!(
                text.contains(accepted),
                "the error must list `{accepted}`: {text}"
            );
        }
    }

    #[test]
    fn every_park_reason_round_trips_through_its_operator_spelling() {
        // What `ls` prints back is exactly what `--reason` accepts. A reason
        // added later that renders one way and parses another would leave an
        // operator retyping a value the tool just showed them.
        for reason in [
            ParkReason::ApprovalWait,
            ParkReason::Idle,
            ParkReason::HostShutdown,
            ParkReason::Operator,
            ParkReason::RetentionDemotion,
        ] {
            assert_eq!(parse_park_reason(park_reason_name(reason)).unwrap(), reason);
        }
    }

    #[test]
    fn parking_an_already_parked_session_refuses_and_leaves_the_record_alone() {
        let tmp = tempfile::tempdir().unwrap();
        let store = AgentSessionStore::at(tmp.path());
        let record = parked("sess-alpha", ParkReason::Idle);
        store.write(&record).unwrap();
        park_record(
            &store,
            &ParkArgs {
                session_id: "sess-alpha".to_string(),
                reason: "operator".to_string(),
                journal_cursor: 0,
                approval_head: None,
            },
        )
        .expect_err("a hibernated session is not active, so it cannot be parked");
        assert_eq!(store.load(&record.session_id).unwrap(), record);
    }

    #[test]
    fn a_park_writes_the_reason_and_the_tier_it_selects() {
        let tmp = tempfile::tempdir().unwrap();
        let store = AgentSessionStore::at(tmp.path());
        store.write(&active("sess-alpha")).unwrap();
        let parked = park_record(
            &store,
            &ParkArgs {
                session_id: "sess-alpha".to_string(),
                reason: "approval-wait".to_string(),
                journal_cursor: 11,
                approval_head: None,
            },
        )
        .expect("an active session parks");
        assert_eq!(parked.state, SandboxResidency::Hibernated);
        assert_eq!(parked.park_reason, Some(ParkReason::ApprovalWait));
        assert_eq!(parked.storage_tier, Some(StorageTier::Parked));
        assert_eq!(parked.journal_cursor, 11);
        assert_eq!(store.load(&parked.session_id).unwrap(), parked);
    }

    #[test]
    fn a_malformed_approval_head_is_refused_before_the_record_moves() {
        let tmp = tempfile::tempdir().unwrap();
        let store = AgentSessionStore::at(tmp.path());
        let record = active("sess-alpha");
        store.write(&record).unwrap();
        park_record(
            &store,
            &ParkArgs {
                session_id: "sess-alpha".to_string(),
                reason: "operator".to_string(),
                journal_cursor: 0,
                approval_head: Some("not-a-digest".to_string()),
            },
        )
        .expect_err("a malformed head must be refused at the boundary");
        assert_eq!(
            store.load(&record.session_id).unwrap(),
            record,
            "a refused park must not touch the record"
        );
    }

    #[test]
    fn ls_on_an_empty_store_is_a_success() {
        let tmp = tempfile::tempdir().unwrap();
        let store = AgentSessionStore::at(tmp.path().join("not-created-yet"));
        ls(&store, false).expect("an empty host has no sessions, which is not an error");
    }
}
