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

use mvm_client::{ResumeBootLocalRequest, resume_and_boot_local};
use mvm_contract::protocol::agent_session::AgentSessionId;
use mvm_core::checkpoint::{ApprovalHead, CheckpointDigest};
use mvm_core::plan::PlanId;
use mvm_core::user_config::MvmConfig;
use mvm_hostd::plan_admission::AdmittedPlan;
use mvm_hostd::plan_admission::{InMemoryNonceLedger, SystemClock};
use mvm_hostd::session_resume::{
    BootedSession, ResumeOutcome, ResumePlanMaterial, ResumeRequest, resume_session,
};
use mvm_runtime::agent_session::{
    AgentSessionRecord, AgentSessionStore, GenerationFence, ParkInput, ParkReason, RenewRequest,
    RetentionStatus, SandboxResidency, StorageTier, TransitionResult,
};
use mvm_runtime::checkpoint::CheckpointStore;
use serde::Serialize;

use super::Cli;
use super::shared::human_age_secs;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub action: AgentSessionAction,
}

impl Args {
    /// Whether this invocation prints a JSON payload on stdout, so host chrome
    /// has to go to stderr instead.
    pub(in crate::commands) fn emits_machine_readable_stdout(&self) -> bool {
        match &self.action {
            AgentSessionAction::Open(_) => false,
            AgentSessionAction::Ls(a) => a.json,
            AgentSessionAction::Show(a) => a.json,
            AgentSessionAction::Park(a) => a.retry.json,
            AgentSessionAction::Resume(a) => a.retry.json,
            AgentSessionAction::Renew(a) => a.retry.json,
        }
    }
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum AgentSessionAction {
    /// Record a new durable agent session, resident from the start
    Open(OpenArgs),
    /// List every durable agent session recorded on this host
    #[command(alias = "list")]
    Ls(LsArgs),
    /// Print one session's recorded state in full
    Show(ShowArgs),
    /// Release an active session's sandbox, recording why
    Park(ParkArgs),
    /// Re-admit a parked session under a freshly signed plan
    Resume(ResumeArgs),
    /// Extend a parked session's retention deadline; never shortens it
    Renew(RenewArgs),
}

/// What it takes to bring a session into existence.
///
/// Every other subcommand needs a record that already exists, so without this
/// one the verb had no reachable production input at all: `ls` printed nothing
/// forever and `park` and `resume` could only ever refuse.
#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct OpenArgs {
    /// Session id to create. Refused if a record already exists under it.
    pub session_id: String,
    /// Checkpoint the session may later resume from, as `sha256:<64-hex>`.
    /// Optional: a session with no resume point is legal, and `resume` will
    /// refuse it later saying so.
    #[arg(long)]
    pub resume_point: Option<String>,
    /// Sandbox lineage belonging to the session. Repeatable. The first one
    /// supplies the admitted plan a `park` entry is chained under, so a
    /// session opened with none cannot record its park in the audit chain.
    #[arg(long = "member")]
    pub members: Vec<String>,
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
    /// How long the host promises to keep the parked session resumable:
    /// `30m`, `48h`, `7d` (at most 30d). Defaults by reason — approval-wait
    /// 24h (the longest an approval can live), idle 30m (the standby TTL),
    /// host-shutdown and operator 48h, retention-demotion 30d.
    #[arg(long, value_name = "DURATION")]
    pub retain_for: Option<String>,
    #[command(flatten)]
    pub retry: RetryArgs,
}

/// Extending a parked session's retention deadline.
#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct RenewArgs {
    /// Session id, as `agent-session ls` prints it
    pub session_id: String,
    /// New retention, measured from now: `30m`, `48h`, `7d` (at most 30d).
    /// Refused if it would end before the current deadline, if the deadline
    /// has already passed, or if the session is not parked.
    #[arg(long = "for", value_name = "DURATION")]
    pub extend_for: String,
    /// The deadline you read, in unix seconds, as `show` prints it. Successive
    /// renewals share a generation, so an exact replay needs this as well as
    /// --expected-generation; without both, a retry is applied as a new
    /// renewal.
    #[arg(long, value_name = "UNIX_SECS")]
    pub expected_deadline: Option<u64>,
    #[command(flatten)]
    pub retry: RetryArgs,
}

/// The generation fence every transition takes, and what makes a retry exact.
#[derive(ClapArgs, Debug, Clone, Default)]
pub(in crate::commands) struct RetryArgs {
    /// Generation you read the session at, as `show` prints it. The transition
    /// refuses if the session has since moved on, and a retry of one that
    /// already applied is answered with its original result, marked as a
    /// replay, writing nothing and adding no audit entry. Without it the
    /// generation is read at call time: nothing is fenced, and a retry after a
    /// lost response cannot be told apart from a new request — it is refused
    /// or applied again, never recognised as a replay.
    #[arg(long, value_name = "N")]
    pub expected_generation: Option<u64>,
    /// Emit the result as JSON, including whether it was a replay
    #[arg(long)]
    pub json: bool,
}

impl RetryArgs {
    fn fence(&self) -> GenerationFence {
        self.expected_generation
            .map_or(GenerationFence::ReadCurrent, GenerationFence::Observed)
    }
}

/// The workload half of a resume, taken as flags.
///
/// The session record deliberately holds none of this: an image, a kernel and
/// a size change on their own schedule, and recording them in the record would
/// make it a second copy of the plan that has to be kept in step with one.
/// Somebody therefore has to supply them, and for now that is the operator.
/// Deriving them from the resume point's supervisor config is a later step;
/// taking them as flags keeps the seam visible instead of guessing.
#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct ResumeArgs {
    /// Session id, as `agent-session ls` prints it
    pub session_id: String,
    /// Runtime profile the resumed sandbox is admitted for (hvf, libkrun, …).
    /// Not in the session record — supply it here.
    #[arg(long)]
    pub backend: String,
    /// Image reference to record in the signed plan. Not in the session
    /// record — supply it here.
    #[arg(long)]
    pub image: String,
    /// Lowercase-hex SHA-256 of the rootfs the resume boots. Not in the
    /// session record — supply it here.
    #[arg(long)]
    pub image_sha256: String,
    /// Lowercase-hex SHA-256 of the kernel. Omit for a backend that carries
    /// its own.
    #[arg(long)]
    pub kernel_sha256: Option<String>,
    /// vCPUs the resumed sandbox is admitted for
    #[arg(long)]
    pub cpus: u32,
    /// Memory the resumed sandbox is admitted for, in MiB
    #[arg(long)]
    pub mem_mib: u64,
    /// The approval ledger's head right now, as `sha256:<64-hex>`. The store
    /// refuses when it differs from the head recorded at park time, so a
    /// resume cannot silently run under grants the session was never admitted
    /// for. Omit only for a session parked without one.
    #[arg(long)]
    pub approval_head: Option<String>,
    /// Boot the resumed sandbox instead of stopping at an admitted plan. Only
    /// a cold-tier session boots; a parked or resident one refuses, because
    /// cold-booting either would throw away state it is holding.
    #[arg(long)]
    pub boot: bool,
    /// Kernel image the booted sandbox loads. Needed with --boot whenever
    /// --kernel-sha256 is given, because the admitted plan pins that digest and
    /// the boot hashes this file against it.
    #[arg(long)]
    pub kernel: Option<std::path::PathBuf>,
    /// A retried `--boot` resume that already applied is refused rather than
    /// replayed: it never boots a second sandbox, and the record cannot say
    /// whether the first boot succeeded.
    #[command(flatten)]
    pub retry: RetryArgs,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    match args.action {
        AgentSessionAction::Open(a) => open(&AgentSessionStore::open(), &a),
        AgentSessionAction::Ls(a) => ls(&AgentSessionStore::open(), a.json),
        AgentSessionAction::Show(a) => show(&AgentSessionStore::open(), &a.session_id, a.json),
        AgentSessionAction::Park(a) => park(&AgentSessionStore::open(), &a),
        AgentSessionAction::Resume(a) => {
            resume(&AgentSessionStore::open(), &CheckpointStore::open(), &a)
        }
        AgentSessionAction::Renew(a) => renew(&AgentSessionStore::open(), &a),
    }
}

/// Parse an operator-supplied session id at the boundary, so a malformed one
/// is refused before it is ever joined into a store path.
fn parse_session_id(raw: &str) -> Result<AgentSessionId> {
    AgentSessionId::parse(raw).map_err(|e| anyhow::anyhow!("invalid session id '{raw}': {e}"))
}

/// Create a session record and report the state it starts in.
fn open(store: &AgentSessionStore, args: &OpenArgs) -> Result<()> {
    let record = open_record(store, args)?;
    println!("{}", summary_line(&record, now_unix()));
    if record.members.is_empty() {
        // Said at open time rather than discovered at park time: the park is
        // what fails to chain, and by then the operator has already moved on.
        crate::ui::warn(
            "this session records no member sandbox, so a later park has no admitted \
             plan to bind to and will not reach the audit chain",
        );
    }
    Ok(())
}

/// Write the initial record, refusing to displace an existing one.
///
/// Split from the printing half for the same reason `park_record` is: the
/// transition is then testable without a terminal.
fn open_record(store: &AgentSessionStore, args: &OpenArgs) -> Result<AgentSessionRecord> {
    let id = parse_session_id(&args.session_id)?;
    let parent_checkpoint = args
        .resume_point
        .as_deref()
        .map(CheckpointDigest::parse)
        .transpose()
        .map_err(|e| anyhow::anyhow!("invalid --resume-point: {e}"))?;
    // Refuse rather than replace. An overwrite would reset a live session to
    // generation 1 and drop its resume point, which is the one piece of state
    // a parked session cannot be recovered without. `exists` rather than a
    // successful `load` so a record that is present but corrupt also refuses.
    anyhow::ensure!(
        !store.exists(&id),
        "agent session '{}' already exists on this host",
        args.session_id
    );
    let now = mvm_core::util::time::now_unix_secs();
    let record = AgentSessionRecord {
        session_id: id,
        // Generation 1, not 0: a generation counts periods of sandbox
        // residency and this record opens the first one.
        generation: 1,
        state: SandboxResidency::Active,
        members: args.members.clone(),
        parent_checkpoint,
        created_unix: now,
        updated_unix: now,
        journal_cursor: 0,
        // Both are the park transition's to write. An active session has not
        // parked, so it has no tier, no reason, and no head it was parked
        // under.
        approval_head: None,
        storage_tier: None,
        park_reason: None,
        retain_until_unix: None,
        last_transition: None,
    };
    store.write(&record)?;
    Ok(record)
}

fn ls(store: &AgentSessionStore, json: bool) -> Result<()> {
    let records = store.list()?;
    let now = now_unix();
    if json {
        let views: Vec<SessionView<'_>> = records.iter().map(|r| SessionView::at(r, now)).collect();
        return crate::json_out::emit_json(&views);
    }
    if records.is_empty() {
        println!("(no agent sessions)");
        return Ok(());
    }
    println!("{:<32} {:<5} RESIDENCY", "SESSION", "GEN");
    for record in &records {
        println!("{}", summary_line(record, now));
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
    let now = now_unix();
    if json {
        return crate::json_out::emit_json(&SessionView::at(&record, now));
    }
    for line in detail_lines(&record, now) {
        println!("{line}");
    }
    Ok(())
}

/// Park a session, then bind the park into the chain-signed audit log.
fn park(store: &AgentSessionStore, args: &ParkArgs) -> Result<()> {
    let result = park_and_chain(store, args, |record| {
        record_park_in_chain(record, &host_audit_emitter()?)
    })?;
    report_transition(
        &TransitionReport::of(TransitionVerb::Park, &result, now_unix()),
        args.retry.json,
    )
}

/// The host clock, read once per command so everything one command prints
/// agrees on whether a deadline has passed.
fn now_unix() -> u64 {
    mvm_core::util::time::now_unix_secs()
}

/// Parse a retention duration with the host's shared bounded duration parser.
fn parse_retention(flag: &str, raw: &str) -> Result<u64> {
    mvm_core::crypto::policy::parse_ttl(raw)
        .map(|d| d.as_secs())
        .map_err(|e| anyhow::anyhow!("invalid {flag}: {e}"))
}

/// Extend a parked session's deadline, then bind the renewal into the chain.
fn renew(store: &AgentSessionStore, args: &RenewArgs) -> Result<()> {
    let result = renew_and_chain(store, args, now_unix(), |record| {
        record_renew_in_chain(record, &host_audit_emitter()?)
    })?;
    report_transition(
        &TransitionReport::of(TransitionVerb::Renew, &result, now_unix()),
        args.retry.json,
    )
}

/// Apply the renewal and, unless it was a replay, chain it — the same shape and
/// the same best-effort chain posture as a park.
fn renew_and_chain(
    store: &AgentSessionStore,
    args: &RenewArgs,
    now: u64,
    chain: impl FnOnce(&AgentSessionRecord) -> Result<()>,
) -> Result<TransitionResult> {
    let result = renew_record(store, args, now)?;
    if result.is_replay() {
        return Ok(result);
    }
    if let Err(error) = chain(result.record()) {
        crate::ui::warn(&format!(
            "session {} renewed, but the renewal was not recorded in the audit chain: {error:#}",
            result.record().session_id.as_str()
        ));
    }
    Ok(result)
}

/// Apply the renewal to the store.
fn renew_record(store: &AgentSessionStore, args: &RenewArgs, now: u64) -> Result<TransitionResult> {
    let id = parse_session_id(&args.session_id)?;
    let extend_for_secs = parse_retention("--for", &args.extend_for)?;
    anyhow::ensure!(
        store.exists(&id),
        "no agent session '{}' on this host",
        args.session_id
    );
    store.renew(
        &id,
        RenewRequest {
            generation: args.retry.fence(),
            expected_deadline_unix: args.expected_deadline,
            extend_for_secs,
        },
        now,
    )
}

/// The extra labels a `session.renewed` entry carries. Prefixed like the park
/// entry's, so none can overwrite a signed plan label.
fn renew_audit_extras(record: &AgentSessionRecord) -> Vec<(String, String)> {
    let mut extras = vec![
        (
            "renewed_session".to_string(),
            record.session_id.as_str().to_string(),
        ),
        (
            "renewed_at_generation".to_string(),
            record.generation.to_string(),
        ),
    ];
    if let Some(until) = record.retain_until_unix {
        extras.push(("renewed_until_unix".to_string(), until.to_string()));
    }
    // The deadline this renewal extended, read off the identity it recorded,
    // so the entry shows the move and not only where it landed.
    if let Some(from) = record.last_transition.as_ref().and_then(|t| {
        t.identity
            .observed
            .get("retain_until_unix")
            .cloned()
            .flatten()
    }) {
        extras.push(("renewed_from_unix".to_string(), from));
    }
    extras
}

/// Bind a completed renewal into the chain, under the member sandbox's plan
/// exactly as a park is.
fn record_renew_in_chain(
    record: &AgentSessionRecord,
    emitter: &super::vm::audit_chain::AuditEmitter,
) -> Result<()> {
    let plan = member_plan(record)?;
    emitter.emit_session_renewed(&plan, renew_audit_extras(record))
}

/// Apply the park and, unless it was a replay, chain it.
///
/// The chain half is a parameter so a test can hand it a real emitter over a
/// scratch directory. A replay chains nothing: the entry the original park
/// wrote is the record of that transition, and a second one would claim the
/// session parked twice.
fn park_and_chain(
    store: &AgentSessionStore,
    args: &ParkArgs,
    chain: impl FnOnce(&AgentSessionRecord) -> Result<()>,
) -> Result<TransitionResult> {
    let result = park_record(store, args)?;
    if result.is_replay() {
        return Ok(result);
    }
    // The record is already durable at this point. A chain entry that cannot
    // be written is reported rather than raised: failing here would tell an
    // operator the park did not happen when it did, and a park with no entry
    // is the lesser of those two wrongs.
    if let Err(error) = chain(result.record()) {
        crate::ui::warn(&format!(
            "session {} parked, but the park was not recorded in the audit chain: {error:#}",
            result.record().session_id.as_str()
        ));
    }
    Ok(result)
}

/// Apply the park to the store and return the record it wrote.
///
/// Split from the audit half so the transition is testable without a signer
/// or an audit directory.
fn park_record(store: &AgentSessionStore, args: &ParkArgs) -> Result<TransitionResult> {
    let id = parse_session_id(&args.session_id)?;
    let reason = parse_park_reason(&args.reason)?;
    let approval_head = args
        .approval_head
        .as_deref()
        .map(ApprovalHead::parse)
        .transpose()
        .map_err(|e| anyhow::anyhow!("invalid --approval-head: {e}"))?;
    let retain_for_secs = args
        .retain_for
        .as_deref()
        .map(|raw| parse_retention("--retain-for", raw))
        .transpose()?;
    anyhow::ensure!(
        store.exists(&id),
        "no agent session '{}' on this host",
        args.session_id
    );
    // With --expected-generation the fence is the caller's, and an exact retry
    // replays; without it the store reads the generation itself, which fences
    // nothing. Neither serializes two concurrent parks of one session — that
    // needs file locking the store does not have.
    store.park(
        &id,
        args.retry.fence(),
        ParkInput {
            reason,
            journal_cursor: args.journal_cursor,
            approval_head,
            retain_for_secs,
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
    if let Some(until) = record.retain_until_unix {
        extras.push(("park_retain_until_unix".to_string(), until.to_string()));
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
fn record_park_in_chain(
    record: &AgentSessionRecord,
    emitter: &super::vm::audit_chain::AuditEmitter,
) -> Result<()> {
    let plan = member_plan(record)?;
    emitter.emit_session_parked(&plan, park_audit_extras(record))
}

/// The admitted plan of the session's first member sandbox.
fn member_plan(record: &AgentSessionRecord) -> Result<mvm_core::plan::ExecutionPlan> {
    let member = record.members.first().ok_or_else(|| {
        anyhow::anyhow!(
            "session {} records no member sandbox, so there is no admitted plan to bind to",
            record.session_id.as_str()
        )
    })?;
    mvm_hostd::audit::plan_persist::read_plan(member)
        .with_context(|| format!("reading the admitted plan of member sandbox '{member}'"))
}

/// The host's chain-signed audit emitter, under the host signer.
fn host_audit_emitter() -> Result<super::vm::audit_chain::AuditEmitter> {
    let signer = super::vm::host_signer::load_or_init()
        .context("loading the host signer to sign the session entry")?;
    super::vm::audit_chain::AuditEmitter::new(signer.signing)
        .context("opening the audit chain to record the session transition")
}

/// Re-admit a parked session, then bind the resume into the audit chain.
fn resume(
    sessions: &AgentSessionStore,
    checkpoints: &CheckpointStore,
    args: &ResumeArgs,
) -> Result<()> {
    if args.boot {
        return resume_booting(sessions, checkpoints, args);
    }
    let report = match resume_record(sessions, checkpoints, args)? {
        ResumeOutcome::Resumed(resumed) => {
            if let Err(error) = record_resume_in_chain(&resumed.record, &resumed.admitted) {
                crate::ui::warn(&format!(
                    "session {} resumed, but the resume was not recorded in the audit chain: \
                     {error:#}",
                    resumed.record.session_id.as_str()
                ));
            }
            OwnedResumeReport {
                replayed: false,
                record: resumed.record,
                admitted_plan_id: resumed.admitted.plan_id().0.clone(),
            }
        }
        // Nothing was admitted and nothing is chained: the entry the original
        // resume wrote is the record of it.
        ResumeOutcome::Replayed(replayed) => OwnedResumeReport {
            replayed: true,
            record: replayed.record,
            admitted_plan_id: replayed.admitted_plan_id,
        },
    };
    report_transition(&report.borrowed(now_unix()), args.retry.json)
}

/// A resume's reportable result, owned across the two outcomes it comes from.
struct OwnedResumeReport {
    replayed: bool,
    record: AgentSessionRecord,
    admitted_plan_id: String,
}

impl OwnedResumeReport {
    fn borrowed(&self, now: u64) -> TransitionReport<'_> {
        TransitionReport {
            verb: TransitionVerb::Resume,
            replayed: self.replayed,
            session: SessionView::at(&self.record, now),
            admitted_plan_id: Some(&self.admitted_plan_id),
            booted_sandbox: None,
        }
    }
}

/// The owned values a [`ResumeRequest`] borrows from.
///
/// A `ResumeRequest` holds references to its id, approval head and material, so
/// a helper that built one directly would hand back references into its own
/// frame. This owns them and lends the request instead, which is what lets the
/// boot and no-boot paths share one parse of the flags.
struct ResumeInputs {
    id: AgentSessionId,
    approval_head: Option<ApprovalHead>,
    material: ResumePlanMaterial,
    /// The operator's `--expected-generation`, or a read at call time.
    generation: GenerationFence,
}

impl ResumeInputs {
    fn parse(sessions: &AgentSessionStore, args: &ResumeArgs) -> Result<Self> {
        let id = parse_session_id(&args.session_id)?;
        let approval_head = args
            .approval_head
            .as_deref()
            .map(ApprovalHead::parse)
            .transpose()
            .map_err(|e| anyhow::anyhow!("invalid --approval-head: {e}"))?;
        anyhow::ensure!(
            sessions.exists(&id),
            "no agent session '{}' on this host",
            args.session_id
        );
        Ok(Self {
            id,
            approval_head,
            material: ResumePlanMaterial {
                backend_name: args.backend.clone(),
                image_name: args.image.clone(),
                image_sha256: args.image_sha256.clone(),
                kernel_sha256: args.kernel_sha256.clone(),
                cpus: args.cpus,
                mem_mib: args.mem_mib,
            },
            generation: args.retry.fence(),
        })
    }

    fn request(&self) -> ResumeRequest<'_> {
        ResumeRequest {
            session_id: &self.id,
            generation: self.generation,
            // The operator's assertion of where the ledger is now, not the head
            // the record was parked under. Passing the record's own head back
            // would compare it against itself and check nothing.
            current_approval_head: self.approval_head.as_ref(),
            material: &self.material,
            host_signer_keys_dir: None,
            now_unix: mvm_core::util::time::now_unix_secs(),
        }
    }
}

/// Drive the resume through the host's admission path.
///
/// This is the first production caller of `resume_session`. It stops at an
/// admitted plan, exactly as that function does.
fn resume_record(
    sessions: &AgentSessionStore,
    checkpoints: &CheckpointStore,
    args: &ResumeArgs,
) -> Result<ResumeOutcome> {
    let inputs = ResumeInputs::parse(sessions, args)?;
    // The nonce ledger is per-invocation, so it refuses a replay within one
    // command and not across two. That is the same posture every other CLI
    // admission path runs under.
    resume_session(
        sessions,
        checkpoints,
        &inputs.request(),
        &SystemClock,
        &InMemoryNonceLedger::new(),
    )
}

/// `resume --boot`: re-admit the session and start a sandbox for it.
///
/// Resolves the backend from the same `--backend` name the plan is admitted
/// under, so the runtime profile in the signed plan is the one that boots.
fn resume_booting(
    sessions: &AgentSessionStore,
    checkpoints: &CheckpointStore,
    args: &ResumeArgs,
) -> Result<()> {
    let booted = resume_boot_record(sessions, checkpoints, args)?;
    report_transition(
        &TransitionReport {
            verb: TransitionVerb::Resume,
            replayed: false,
            session: SessionView::at(&booted.record, now_unix()),
            admitted_plan_id: Some(&booted.started.admitted.plan_id().0),
            booted_sandbox: Some(&booted.started.vm_id.0),
        },
        args.retry.json,
    )
}

/// Drive a booting resume through the client-owned backend boundary.
fn resume_boot_record(
    sessions: &AgentSessionStore,
    checkpoints: &CheckpointStore,
    args: &ResumeArgs,
) -> Result<BootedSession> {
    // Refused here rather than by the admitted-environment gate, which only
    // runs once the record has already transitioned. A plan that pins a kernel
    // digest needs a kernel to hash against it, and an operator who forgot the
    // flag should not pay a generation to find that out.
    if args.kernel_sha256.is_some() && args.kernel.is_none() {
        anyhow::bail!(
            "--boot with --kernel-sha256 also needs --kernel <path>: the admitted plan pins              that digest, and the boot hashes the file it is given against it"
        );
    }
    let inputs = ResumeInputs::parse(sessions, args)?;
    // The session's own state dir, named for the session, so the staged resume
    // point sits where every other per-VM artifact for that name does.
    let state_dir = mvm_core::config::vm_state_dir(inputs.id.as_str());
    let signer = super::vm::host_signer::load_or_init()
        .context("loading the host signer to sign the resume entry")?;
    let emitter = super::vm::audit_chain::AuditEmitter::new(signer.signing)
        .context("opening the audit chain to record the resume")?;
    let resume = inputs.request();
    let request = ResumeBootLocalRequest::builder()
        .sessions(sessions)
        .checkpoints(checkpoints)
        .resume(&resume)
        .backend_name(&args.backend)
        .state_dir(&state_dir)
        .kernel_path(args.kernel.as_deref())
        .emitter(Some(&emitter))
        .build()?;
    resume_and_boot_local(&request, &SystemClock, &InMemoryNonceLedger::new())
}

/// The extra labels a `session.resumed` entry carries.
///
/// Non-colliding for the same reason the park entry's are, and here the hazard
/// is live rather than theoretical: this entry rides on the resume plan
/// itself, which carries `session_id` and `session_generation` as signed
/// labels. An extra reusing either name would overwrite a value that was
/// signed with one this command merely believed.
fn resume_audit_extras(record: &AgentSessionRecord, plan_id: &PlanId) -> Vec<(String, String)> {
    vec![
        (
            "resumed_session".to_string(),
            record.session_id.as_str().to_string(),
        ),
        // The generation the transition wrote — the residency this resume
        // opened, not the parked one it came from.
        (
            "resumed_at_generation".to_string(),
            record.generation.to_string(),
        ),
        // Restates the entry's own plan_id field, so a reader looking only at
        // labels can still say which admission authorized this residency.
        ("resumed_plan_id".to_string(), plan_id.0.clone()),
    ]
}

/// Bind a completed resume into the chain-signed audit log.
///
/// Unlike the park entry, this one needs no plan lookup: the resume produced
/// the plan it is recorded under.
fn record_resume_in_chain(record: &AgentSessionRecord, admitted: &AdmittedPlan) -> Result<()> {
    host_audit_emitter()?.emit_session_resumed(
        admitted.plan(),
        resume_audit_extras(record, admitted.plan_id()),
    )
}

/// Which transition a report describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum TransitionVerb {
    Park,
    Resume,
    Renew,
}

impl TransitionVerb {
    fn as_str(self) -> &'static str {
        match self {
            Self::Park => "park",
            Self::Resume => "resume",
            Self::Renew => "renew",
        }
    }
}

/// What a transition command reports, in text or JSON.
///
/// `replayed` is the one field a retrying caller needs: it separates "this
/// call applied the transition" from "an earlier call had already applied it
/// and this is what that call produced".
#[derive(Debug, Serialize)]
struct TransitionReport<'a> {
    #[serde(rename = "transition")]
    verb: TransitionVerb,
    replayed: bool,
    session: SessionView<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    admitted_plan_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    booted_sandbox: Option<&'a str>,
}

impl<'a> TransitionReport<'a> {
    fn of(verb: TransitionVerb, result: &'a TransitionResult, now: u64) -> Self {
        Self {
            verb,
            replayed: result.is_replay(),
            session: SessionView::at(result.record(), now),
            admitted_plan_id: None,
            booted_sandbox: None,
        }
    }
}

fn report_transition(report: &TransitionReport<'_>, json: bool) -> Result<()> {
    if json {
        return crate::json_out::emit_json(report);
    }
    for line in transition_lines(report) {
        println!("{line}");
    }
    Ok(())
}

/// The text form of a transition report.
fn transition_lines(report: &TransitionReport<'_>) -> Vec<String> {
    let mut lines = vec![summary_line(report.session.record, report.session.now)];
    if let Some(plan) = report.admitted_plan_id {
        lines.push(format!("admitted plan:  {plan}"));
    }
    match report.booted_sandbox {
        Some(sandbox) => lines.push(format!("booted sandbox: {sandbox}")),
        // Said plainly rather than implied by silence: a resume re-admits the
        // session under a fresh signed plan and stops there. Restoring the
        // memory image and starting a sandbox from it is not wired.
        None if report.verb == TransitionVerb::Resume => lines.push(
            "(no sandbox was booted — a resume re-admits the session, nothing more)".to_string(),
        ),
        None => {}
    }
    if report.replayed {
        lines.push(format!(
            "replay: this {} had already applied; nothing was written and no audit entry was \
             added",
            report.verb.as_str()
        ));
    }
    lines
}

/// A session record as `--json` reports it: the record, plus whether its
/// retention deadline is alive at the moment the command ran.
///
/// Derived rather than stored, because expiry is a fact about the clock and
/// not about the record; storing it would make it stale the second it was
/// written.
#[derive(Debug, Serialize)]
struct SessionView<'a> {
    #[serde(flatten)]
    record: &'a AgentSessionRecord,
    #[serde(skip_serializing_if = "Option::is_none")]
    retention: Option<RetentionStatus>,
    #[serde(skip)]
    now: u64,
}

impl<'a> SessionView<'a> {
    fn at(record: &'a AgentSessionRecord, now: u64) -> Self {
        Self {
            record,
            retention: record.retention_status(now),
            now,
        }
    }
}

/// The retention column: `alive(2h left)` or `expired(3h ago)`.
fn retention_phrase(status: RetentionStatus) -> String {
    match status {
        RetentionStatus::Alive { remaining_secs, .. } => {
            format!("alive({} left)", human_age_secs(remaining_secs))
        }
        RetentionStatus::Expired {
            expired_for_secs, ..
        } => format!("expired({} ago)", human_age_secs(expired_for_secs)),
    }
}

/// The `ls` row for one session.
///
/// A parked session's reason, tier and retention ride on the same line because
/// they are what an operator triages on: the reason says why it is waiting, the
/// tier says what the wait costs, and the retention says how long the host has
/// promised to keep paying it.
fn summary_line(record: &AgentSessionRecord, now: u64) -> String {
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
    if let Some(status) = record.retention_status(now) {
        line.push_str("  retention=");
        line.push_str(&retention_phrase(status));
    }
    line
}

/// Every recorded field of one session, one per line.
fn detail_lines(record: &AgentSessionRecord, now: u64) -> Vec<String> {
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
            "retain until:   {}",
            match (record.retain_until_unix, record.retention_status(now)) {
                (Some(until), Some(status @ RetentionStatus::Alive { .. })) => {
                    format!("{until} (unix) — {}", retention_phrase(status))
                }
                (Some(until), Some(status)) => format!(
                    "{until} (unix) — {}; past its promise, so renew refuses",
                    retention_phrase(status)
                ),
                _ => "-".to_string(),
            }
        ),
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

    /// A clock shortly after the fixtures park, so their deadlines are alive.
    const TEST_NOW: u64 = 1_755_000_200;

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
            retain_until_unix: None,
            last_transition: None,
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
                    retain_for_secs: None,
                },
                1_755_000_100,
            )
            .unwrap()
    }

    #[test]
    fn an_active_session_renders_its_residency_and_nothing_about_a_park() {
        let line = summary_line(&active("sess-alpha"), TEST_NOW);
        assert!(line.contains("sess-alpha"), "{line}");
        assert!(line.contains("active"), "{line}");
        assert!(!line.contains("reason="), "{line}");
        assert!(!line.contains("tier="), "{line}");
    }

    #[test]
    fn a_parked_session_renders_its_reason_and_tier() {
        // The tier is not decoration: approval-wait selects `parked`, so the
        // rendered row is also how an operator sees what the wait costs.
        let line = summary_line(&parked("sess-beta", ParkReason::ApprovalWait), TEST_NOW);
        assert!(line.contains("hibernated"), "{line}");
        assert!(line.contains("reason=approval-wait"), "{line}");
        assert!(line.contains("tier=parked"), "{line}");
    }

    #[test]
    fn an_idle_park_renders_the_resident_tier_it_actually_selects() {
        let line = summary_line(&parked("sess-gamma", ParkReason::Idle), TEST_NOW);
        assert!(line.contains("reason=idle"), "{line}");
        assert!(line.contains("tier=resident"), "{line}");
    }

    #[test]
    fn a_closed_session_renders_as_closed() {
        let mut record = active("sess-delta");
        record.state = SandboxResidency::Closed;
        assert!(summary_line(&record, TEST_NOW).contains("closed"));
    }

    #[test]
    fn detail_says_when_no_approval_head_was_recorded() {
        let lines = detail_lines(&active("sess-alpha"), TEST_NOW).join("\n");
        assert!(
            lines.contains("approval head:  (none recorded"),
            "an unfenced session must say so: {lines}"
        );
    }

    #[test]
    fn detail_prints_a_recorded_approval_head_as_the_digest_it_is() {
        let record = parked("sess-alpha", ParkReason::Operator);
        let lines = detail_lines(&record, TEST_NOW).join("\n");
        assert!(
            lines.contains(&format!("sha256:{}", "ab".repeat(32))),
            "the head is a digest, not a secret: {lines}"
        );
    }

    #[test]
    fn detail_carries_every_recorded_field() {
        let record = parked("sess-alpha", ParkReason::ApprovalWait);
        let lines = detail_lines(&record, TEST_NOW).join("\n");
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

    /// The signed labels a resume plan actually carries, read out of the
    /// synthesis the resume path runs.
    ///
    /// Derived rather than listed. A hardcoded denylist of `session_id` and
    /// `session_generation` would miss `session_parent_checkpoint` and
    /// `session_approval_head`, which that synthesis also emits, and would go
    /// on missing whatever is added next.
    fn resume_plan_label_keys(record: &AgentSessionRecord) -> Vec<String> {
        let material = ResumePlanMaterial {
            backend_name: "hvf".to_string(),
            image_name: "demo".to_string(),
            image_sha256: "ab".repeat(32),
            kernel_sha256: None,
            cpus: 1,
            mem_mib: 256,
        };
        let synthesis = mvm_hostd::session_resume::synthesis_for_resume(record, &material);
        synthesis.audit_labels.keys().cloned().collect()
    }

    /// Assert an emitter's extras cannot shadow any signed plan label.
    fn assert_extras_are_disjoint_from_the_plan_labels(
        record: &AgentSessionRecord,
        extras: &[(String, String)],
    ) {
        let labels = resume_plan_label_keys(record);
        // Guard the guard: an empty label set would make the disjointness
        // below hold for a reason that has nothing to do with the code.
        assert!(
            labels.contains(&"session_id".to_string()),
            "the label set is not the one the resume plan carries: {labels:?}"
        );
        let keys: Vec<&str> = extras.iter().map(|(k, _)| k.as_str()).collect();
        assert!(!keys.is_empty(), "the entry must carry something");
        for label in &labels {
            assert!(
                !keys.contains(&label.as_str()),
                "extra `{label}` would overwrite the signed plan label of the same name \
                 (extras: {keys:?}, plan labels: {labels:?})"
            );
        }
    }

    #[test]
    fn the_park_entry_keys_do_not_collide_with_the_plan_labels() {
        // `for_plan` extends the plan's labels with the per-event extras, so
        // an extra sharing a key silently replaces the signed plan's value.
        let record = parked("sess-alpha", ParkReason::ApprovalWait);
        assert_extras_are_disjoint_from_the_plan_labels(&record, &park_audit_extras(&record));
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
                retain_for: None,
                retry: RetryArgs::default(),
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
                retain_for: None,
                retry: RetryArgs::default(),
            },
        )
        .expect("an active session parks")
        .into_record();
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
                retain_for: None,
                retry: RetryArgs::default(),
            },
        )
        .expect_err("a malformed head must be refused at the boundary");
        assert_eq!(
            store.load(&record.session_id).unwrap(),
            record,
            "a refused park must not touch the record"
        );
    }

    fn resume_args(session_id: &str) -> ResumeArgs {
        ResumeArgs {
            session_id: session_id.to_string(),
            backend: "hvf".to_string(),
            image: "demo".to_string(),
            image_sha256: "ab".repeat(32),
            kernel_sha256: Some("cd".repeat(32)),
            cpus: 2,
            mem_mib: 512,
            approval_head: None,
            boot: false,
            kernel: None,
            retry: RetryArgs::default(),
        }
    }

    /// The same flags with `--boot` and a kernel path set. Gated with its
    /// callers.
    ///
    /// The kernel is supplied because the fixture pins `--kernel-sha256`, and a
    /// pin with no path is refused before any tier is looked at — a tier test
    /// built on it would pass on the wrong refusal.
    #[cfg(feature = "test-support")]
    fn boot_args(session_id: &str, kernel: &std::path::Path) -> ResumeArgs {
        ResumeArgs {
            boot: true,
            backend: "mock".to_string(),
            kernel: Some(kernel.to_path_buf()),
            ..resume_args(session_id)
        }
    }

    /// A file standing in for a kernel. The tier refusals never hash it.
    #[cfg(feature = "test-support")]
    fn stub_kernel(dir: &std::path::Path) -> std::path::PathBuf {
        let p = dir.join("vmlinux");
        std::fs::write(&p, b"stub-kernel").unwrap();
        p
    }

    #[cfg(feature = "test-support")]
    fn install_runtime_overlay(home: &std::path::Path) {
        use mvm_build::runtime_overlay::{InstallOptions, install_overlay_into_cache};
        use mvm_fs::ext4::Node;
        use mvm_fs::overlay::{REQUIRED_OVERLAY_GUEST_PATHS, read_overlay_artifact_from_dir};

        let source = home.join("runtime-overlay-source");
        std::fs::create_dir_all(&source).unwrap();
        let nodes = REQUIRED_OVERLAY_GUEST_PATHS
            .iter()
            .map(|path| Node::File {
                path: path.to_string(),
                mode: 0o755,
                data: b"session-resume-runtime-stub".to_vec(),
                xattrs: Vec::new(),
            })
            .collect();
        let ext4 = mvm_fs::ext4::build_image(nodes).unwrap();
        std::fs::write(source.join("overlay.ext4"), ext4).unwrap();
        std::fs::write(source.join("overlay.verity"), b"verity-sidecar").unwrap();
        std::fs::write(
            source.join("overlay.roothash"),
            format!("{}\n", "ab".repeat(32)),
        )
        .unwrap();
        std::fs::write(
            source.join("VERSION"),
            format!("{}\n", env!("CARGO_PKG_VERSION")),
        )
        .unwrap();

        let artifact = read_overlay_artifact_from_dir(&source, std::env::consts::ARCH).unwrap();
        install_overlay_into_cache(
            &artifact,
            &home.join("cache"),
            &InstallOptions { overwrite: true },
        )
        .unwrap();
    }

    #[cfg(feature = "test-support")]
    fn seed_resume_checkpoint(
        store: &CheckpointStore,
        dir: &std::path::Path,
    ) -> mvm_core::checkpoint::CheckpointMeta {
        use mvm_core::checkpoint::CheckpointId;
        use mvm_runtime::checkpoint::{CaptureFsQuickParams, capture_fs_quick};

        let rootfs = dir.join("rootfs.ext4");
        std::fs::write(&rootfs, b"fake-ext4-bytes").unwrap();
        capture_fs_quick(
            store,
            CaptureFsQuickParams {
                id: CheckpointId::new("cp-parent"),
                vm_name: "vm-alpha".to_string(),
                rootfs,
                supervisor_config_digest: "digest".to_string(),
                runtime_overlay_version: None,
                tag: None,
                created_unix: 1,
                quiesced: true,
                grants: None,
            },
        )
        .unwrap()
    }

    #[cfg(feature = "test-support")]
    #[test]
    fn booting_resume_reaches_the_cli_backend_boundary_and_starts_the_session() {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        install_runtime_overlay(home.path());

        let sessions = AgentSessionStore::at(home.path().join("sessions"));
        let checkpoints = CheckpointStore::at(home.path().join("checkpoints"));
        let parent = seed_resume_checkpoint(&checkpoints, home.path());
        let mut record = parked("sess-boot", ParkReason::RetentionDemotion);
        assert_eq!(record.storage_tier, Some(StorageTier::Cold));
        record.parent_checkpoint = Some(parent.meta_digest);
        sessions.write(&record).unwrap();

        let kernel = stub_kernel(home.path());
        let mut args = boot_args("sess-boot", &kernel);
        args.kernel_sha256 = Some(mvm_core::crypto::image_verify::sha256_file(&kernel).unwrap());
        args.approval_head = record.approval_head.as_ref().map(ToString::to_string);

        let booted = resume_boot_record(&sessions, &checkpoints, &args)
            .expect("the CLI boot path must start a cold-tier session");

        assert_eq!(booted.record.state, SandboxResidency::Active);
        assert_eq!(booted.record.generation, record.generation + 1);
        assert_eq!(booted.started.vm_id.0, "sess-boot");
        assert_eq!(booted.started.admitted.plan().workload.0, "sess-boot");
        assert_eq!(
            sessions.load(&record.session_id).unwrap(),
            booted.record,
            "the successful boot must persist the new residency"
        );
    }

    #[cfg(feature = "test-support")]
    #[test]
    fn boot_refuses_a_parked_tier_session_naming_the_tier() {
        // The flag reaches the tier gate: a session parked with a memory image
        // must not be cold-booted out from under the operator.
        let tmp = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(tmp.path());
        let sessions = AgentSessionStore::at(tmp.path().join("sessions"));
        let checkpoints = CheckpointStore::at(tmp.path().join("checkpoints"));
        let record = parked("sess-alpha", ParkReason::ApprovalWait);
        assert_eq!(record.storage_tier, Some(StorageTier::Parked));
        sessions.write(&record).unwrap();

        let kernel = stub_kernel(tmp.path());
        let args = boot_args("sess-alpha", &kernel);
        let err = resume_boot_record(&sessions, &checkpoints, &args)
            .expect_err("a parked-tier session must not boot");
        let text = format!("{err:#}");
        assert!(text.contains("parked"), "{text}");
        assert!(text.contains("not built"), "{text}");
        assert_eq!(
            sessions.load(&record.session_id).unwrap(),
            record,
            "a refused boot must not touch the record"
        );
    }

    #[cfg(feature = "test-support")]
    #[test]
    fn boot_refuses_a_resident_tier_session_naming_the_tier() {
        let tmp = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(tmp.path());
        let sessions = AgentSessionStore::at(tmp.path().join("sessions"));
        let checkpoints = CheckpointStore::at(tmp.path().join("checkpoints"));
        let record = parked("sess-alpha", ParkReason::Idle);
        assert_eq!(record.storage_tier, Some(StorageTier::Resident));
        sessions.write(&record).unwrap();

        let kernel = stub_kernel(tmp.path());
        let args = boot_args("sess-alpha", &kernel);
        let err = resume_boot_record(&sessions, &checkpoints, &args)
            .expect_err("a resident-tier session must not boot");
        let text = format!("{err:#}");
        assert!(text.contains("resident"), "{text}");
        assert!(text.contains("not built"), "{text}");
        assert_eq!(sessions.load(&record.session_id).unwrap(), record);
    }

    #[cfg(feature = "test-support")]
    #[test]
    fn boot_refuses_an_active_session_before_reaching_the_tier_gate() {
        // The residency check still comes first: an active session has no
        // parked state to resume, whatever tier it might name.
        let tmp = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(tmp.path());
        let sessions = AgentSessionStore::at(tmp.path().join("sessions"));
        let checkpoints = CheckpointStore::at(tmp.path().join("checkpoints"));
        let record = active("sess-alpha");
        sessions.write(&record).unwrap();

        let kernel = stub_kernel(tmp.path());
        let args = boot_args("sess-alpha", &kernel);
        let err = resume_boot_record(&sessions, &checkpoints, &args)
            .expect_err("an active session must not boot");
        // On its residency, not on the tier it does not have: the tier gate
        // steps aside for a record nothing ever parked.
        assert!(format!("{err:#}").contains("not parked"), "{err:#}");
        assert_eq!(sessions.load(&record.session_id).unwrap(), record);
    }

    #[cfg(feature = "test-support")]
    #[test]
    fn boot_without_a_kernel_path_refuses_before_the_record_moves() {
        // The pin needs a file to hash. Catching it here rather than at the
        // admitted-environment gate is what keeps the record parked.
        let tmp = tempfile::tempdir().unwrap();
        let sessions = AgentSessionStore::at(tmp.path().join("sessions"));
        let checkpoints = CheckpointStore::at(tmp.path().join("checkpoints"));
        let record = parked("sess-alpha", ParkReason::RetentionDemotion);
        assert_eq!(record.storage_tier, Some(StorageTier::Cold));
        sessions.write(&record).unwrap();

        let args = ResumeArgs {
            boot: true,
            ..resume_args("sess-alpha")
        };
        assert!(args.kernel_sha256.is_some() && args.kernel.is_none());
        let err = resume_boot_record(&sessions, &checkpoints, &args)
            .expect_err("a pinned kernel with no path must refuse");
        assert!(format!("{err:#}").contains("--kernel"), "{err:#}");
        assert_eq!(
            sessions.load(&record.session_id).unwrap(),
            record,
            "the refusal must come before the transition"
        );
    }

    #[test]
    fn boot_defaults_off_so_the_plain_resume_is_unchanged() {
        // The flag is opt-in: nothing about an existing invocation changes.
        assert!(!resume_args("sess-alpha").boot);
        assert!(resume_args("sess-alpha").kernel.is_none());
    }

    #[test]
    fn resume_refuses_a_session_that_is_not_parked() {
        // An active session must be refused on its residency alone, before any
        // checkpoint is resolved or any plan is signed: a resume of something
        // already resident would open a second residency for one session.
        let tmp = tempfile::tempdir().unwrap();
        let sessions = AgentSessionStore::at(tmp.path().join("sessions"));
        let checkpoints = CheckpointStore::at(tmp.path().join("checkpoints"));
        let record = active("sess-alpha");
        sessions.write(&record).unwrap();

        let err = resume_record(&sessions, &checkpoints, &resume_args("sess-alpha"))
            .expect_err("an active session must not resume");
        let text = format!("{err:#}");
        assert!(text.contains("not parked"), "{text}");
        assert_eq!(
            sessions.load(&record.session_id).unwrap(),
            record,
            "a refused resume must not touch the record"
        );
    }

    #[test]
    fn resume_refuses_an_unknown_session_naming_it() {
        let tmp = tempfile::tempdir().unwrap();
        let sessions = AgentSessionStore::at(tmp.path().join("sessions"));
        let checkpoints = CheckpointStore::at(tmp.path().join("checkpoints"));
        let err = resume_record(&sessions, &checkpoints, &resume_args("sess-nope"))
            .expect_err("an absent session must refuse");
        assert!(format!("{err:#}").contains("sess-nope"), "{err:#}");
    }

    #[test]
    fn the_resume_entry_keys_do_not_collide_with_the_plan_labels() {
        // Same hazard as the park entry, and here it is live rather than
        // theoretical: this entry rides on the resume plan itself.
        let record = parked("sess-alpha", ParkReason::ApprovalWait);
        let extras = resume_audit_extras(&record, &PlanId("plan-abc".to_string()));
        assert_extras_are_disjoint_from_the_plan_labels(&record, &extras);
    }

    #[test]
    fn the_derived_label_set_covers_more_than_the_two_obvious_names() {
        // The reason the guard is derived: a record carrying a resume point
        // and an approval head makes the synthesis emit four labels, and a
        // hardcoded pair would have watched only half of them.
        let labels = resume_plan_label_keys(&parked("sess-alpha", ParkReason::ApprovalWait));
        for expected in [
            "session_id",
            "session_generation",
            "session_parent_checkpoint",
            "session_approval_head",
        ] {
            assert!(
                labels.contains(&expected.to_string()),
                "missing `{expected}`: {labels:?}"
            );
        }
    }

    #[test]
    fn resume_extras_name_the_residency_the_resume_opened() {
        let mut record = active("sess-alpha");
        record.generation = 2;
        let extras = resume_audit_extras(&record, &PlanId("plan-abc".to_string()));
        let got = |key: &str| {
            extras
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(got("resumed_session"), Some("sess-alpha"));
        // The generation the transition wrote, not the parked one it came
        // from: an entry naming the parent would put the whole chain one
        // residency behind.
        assert_eq!(got("resumed_at_generation"), Some("2"));
        assert_eq!(got("resumed_plan_id"), Some("plan-abc"));
    }

    fn open_args(session_id: &str) -> OpenArgs {
        OpenArgs {
            session_id: session_id.to_string(),
            resume_point: None,
            members: vec!["vm-alpha".to_string()],
        }
    }

    #[test]
    fn open_creates_a_resident_record_at_generation_one() {
        let tmp = tempfile::tempdir().unwrap();
        let store = AgentSessionStore::at(tmp.path());
        let record = open_record(&store, &open_args("sess-alpha")).expect("a new session opens");

        assert_eq!(record.generation, 1);
        assert_eq!(record.state, SandboxResidency::Active);
        assert_eq!(record.members, vec!["vm-alpha".to_string()]);
        // A session that has not parked carries none of the park transition's
        // fields; a tier written here would name a cost nothing is paying.
        assert_eq!(record.park_reason, None);
        assert_eq!(record.storage_tier, None);
        assert_eq!(record.approval_head, None);
        assert_eq!(
            store.load(&record.session_id).unwrap(),
            record,
            "the record must be readable back through the store"
        );
    }

    #[test]
    fn open_records_a_resume_point_when_one_is_supplied() {
        let tmp = tempfile::tempdir().unwrap();
        let store = AgentSessionStore::at(tmp.path());
        let digest = format!("sha256:{}", "1a".repeat(32));
        let record = open_record(
            &store,
            &OpenArgs {
                resume_point: Some(digest.clone()),
                ..open_args("sess-alpha")
            },
        )
        .expect("a resume point is legal at open");
        assert_eq!(
            record.parent_checkpoint.as_ref().map(ToString::to_string),
            Some(digest)
        );
    }

    #[test]
    fn opening_an_existing_session_is_refused_and_leaves_it_byte_identical() {
        // The failure this prevents: an overwrite resets a live session to
        // generation 1 and drops the resume point it would be brought back
        // from, so the session becomes unrecoverable rather than merely stale.
        let tmp = tempfile::tempdir().unwrap();
        let store = AgentSessionStore::at(tmp.path());
        let record = parked("sess-alpha", ParkReason::ApprovalWait);
        store.write(&record).unwrap();
        let on_disk = tmp.path().join("sess-alpha").join("session.json");
        let before = std::fs::read(&on_disk).unwrap();

        let err = open_record(&store, &open_args("sess-alpha"))
            .expect_err("an existing session must not be displaced");
        assert!(format!("{err:#}").contains("already exists"), "{err:#}");
        assert_eq!(
            std::fs::read(&on_disk).unwrap(),
            before,
            "a refused open must not rewrite a byte"
        );
    }

    #[test]
    fn open_refuses_a_malformed_session_id_before_it_reaches_the_store() {
        let tmp = tempfile::tempdir().unwrap();
        let store = AgentSessionStore::at(tmp.path());
        let err = open_record(&store, &open_args("../escape"))
            .expect_err("a path-escaping id must refuse");
        assert!(format!("{err:#}").contains("invalid session id"), "{err:#}");
    }

    #[test]
    fn open_refuses_a_malformed_resume_point_and_writes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let store = AgentSessionStore::at(tmp.path());
        let err = open_record(
            &store,
            &OpenArgs {
                resume_point: Some("not-a-digest".to_string()),
                ..open_args("sess-alpha")
            },
        )
        .expect_err("a malformed digest must be refused at the boundary");
        assert!(
            format!("{err:#}").contains("invalid --resume-point"),
            "{err:#}"
        );
        assert!(
            store.list().unwrap().is_empty(),
            "a refused open must leave no record behind"
        );
    }

    #[test]
    fn open_then_park_then_show_walks_one_session_end_to_end() {
        // The four subcommands are only useful as a sequence, and until
        // `open` existed no sequence was reachable: `park` needed a record
        // nothing produced. This walks the real code paths in order.
        let tmp = tempfile::tempdir().unwrap();
        let store = AgentSessionStore::at(tmp.path());

        let opened = open_record(&store, &open_args("sess-alpha")).expect("open");
        assert_eq!(opened.state, SandboxResidency::Active);
        assert_eq!(
            store.list().unwrap().len(),
            1,
            "`ls` must now see the session `open` created"
        );

        let parked = park_record(
            &store,
            &ParkArgs {
                session_id: "sess-alpha".to_string(),
                reason: "approval-wait".to_string(),
                journal_cursor: 9,
                approval_head: None,
                retain_for: None,
                retry: RetryArgs::default(),
            },
        )
        .expect("the session opened active, so it parks")
        .into_record();

        // What `show` renders, read off the same record `show` would load.
        let rendered = detail_lines(&store.load(&parked.session_id).unwrap(), TEST_NOW).join("\n");
        assert!(
            rendered.contains("residency:      hibernated"),
            "{rendered}"
        );
        assert!(
            rendered.contains("park reason:    approval-wait"),
            "{rendered}"
        );
        assert!(rendered.contains("storage tier:   parked"), "{rendered}");
        assert!(rendered.contains("journal cursor: 9"), "{rendered}");
        assert!(
            rendered.contains("approval head:  (none recorded"),
            "the park carried no head, and `show` must say so: {rendered}"
        );
    }

    #[test]
    fn ls_on_an_empty_store_is_a_success() {
        let tmp = tempfile::tempdir().unwrap();
        let store = AgentSessionStore::at(tmp.path().join("not-created-yet"));
        ls(&store, false).expect("an empty host has no sessions, which is not an error");
    }

    // ── exact retry at the CLI boundary ─────────────────────────────────

    fn park_args(reason: &str, expected_generation: Option<u64>) -> ParkArgs {
        ParkArgs {
            session_id: "sess-alpha".to_string(),
            reason: reason.to_string(),
            journal_cursor: 3,
            approval_head: None,
            retain_for: None,
            retry: RetryArgs {
                expected_generation,
                json: false,
            },
        }
    }

    /// A host whose member sandbox has a persisted plan, and an emitter over a
    /// scratch chain, so a park reaches the real chain-writing path.
    struct ChainedHost {
        _env: mvm_core::util::test_env::TestEnv,
        home: tempfile::TempDir,
        emitter: super::super::vm::audit_chain::AuditEmitter,
    }

    impl ChainedHost {
        fn new() -> Self {
            let home = tempfile::tempdir().unwrap();
            let mut env = mvm_core::util::test_env::TestEnv::new();
            env.isolate_mvm_home(home.path());
            mvm_hostd::audit::plan_persist::write_plan(
                "vm-alpha",
                &mvm_core::plan::signing::test_support::sample_plan(),
            )
            .unwrap();
            let emitter = super::super::vm::audit_chain::AuditEmitter::with_dir(
                ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]),
                &home.path().join("audit"),
            )
            .unwrap();
            Self {
                _env: env,
                home,
                emitter,
            }
        }

        fn park(&self, store: &AgentSessionStore, args: &ParkArgs) -> Result<TransitionResult> {
            park_and_chain(store, args, |record| {
                record_park_in_chain(record, &self.emitter)
            })
        }

        fn entries(&self, event: &str) -> usize {
            std::fs::read_to_string(self.home.path().join("audit").join("tenant-a.jsonl"))
                .unwrap_or_default()
                .matches(&format!("\"{event}\""))
                .count()
        }
    }

    #[test]
    fn an_exact_park_retry_is_reported_as_a_replay_and_adds_no_chain_entry() {
        let host = ChainedHost::new();
        let store = AgentSessionStore::at(host.home.path().join("sessions"));
        store.write(&active("sess-alpha")).unwrap();
        let args = park_args("approval-wait", Some(1));

        let first = host.park(&store, &args).expect("the first park applies");
        assert!(!first.is_replay());
        assert_eq!(host.entries("session.parked"), 1, "the park is chained");

        let retry = host
            .park(&store, &args)
            .expect("an exact retry is answered");
        assert!(retry.is_replay());
        assert_eq!(retry.record(), first.record());
        assert_eq!(
            host.entries("session.parked"),
            1,
            "a replay must not chain a second park"
        );

        let json: serde_json::Value = serde_json::from_str(
            &crate::json_out::to_json_string(&TransitionReport::of(
                TransitionVerb::Park,
                &retry,
                TEST_NOW,
            ))
            .unwrap(),
        )
        .unwrap();
        assert_eq!(json["replayed"], true);
        assert_eq!(json["transition"], "park");
        assert_eq!(json["session"]["state"], "hibernated");
        let text = transition_lines(&TransitionReport::of(
            TransitionVerb::Park,
            &retry,
            TEST_NOW,
        ))
        .join("\n");
        assert!(
            text.contains("replay: this park had already applied"),
            "{text}"
        );
    }

    #[test]
    fn a_park_retry_with_another_reason_is_a_conflict_naming_it() {
        let host = ChainedHost::new();
        let store = AgentSessionStore::at(host.home.path().join("sessions"));
        store.write(&active("sess-alpha")).unwrap();
        host.park(&store, &park_args("approval-wait", Some(1)))
            .unwrap();
        let before = store
            .load(&AgentSessionId::parse("sess-alpha").unwrap())
            .unwrap();

        let err = host
            .park(&store, &park_args("operator", Some(1)))
            .expect_err("a changed park must not apply");
        assert!(
            format!("{err:#}").contains("reason: recorded approval_wait, retried operator"),
            "{err:#}"
        );
        assert_eq!(
            store.load(&before.session_id).unwrap(),
            before,
            "a conflict must not touch the record"
        );
        assert_eq!(host.entries("session.parked"), 1);
    }

    #[test]
    fn a_park_with_a_stale_expected_generation_is_refused_naming_it() {
        let tmp = tempfile::tempdir().unwrap();
        let store = AgentSessionStore::at(tmp.path());
        let record = active("sess-alpha");
        store.write(&record).unwrap();
        let err = park_record(&store, &park_args("operator", Some(4)))
            .expect_err("a caller holding another generation must be refused");
        assert!(
            format!("{err:#}").contains("at generation 1, not the expected 4"),
            "{err:#}"
        );
        assert_eq!(store.load(&record.session_id).unwrap(), record);
    }

    #[test]
    fn a_fresh_park_report_is_not_marked_as_a_replay() {
        let tmp = tempfile::tempdir().unwrap();
        let store = AgentSessionStore::at(tmp.path());
        store.write(&active("sess-alpha")).unwrap();
        let result = park_record(&store, &park_args("idle", None)).unwrap();
        let report = TransitionReport::of(TransitionVerb::Park, &result, TEST_NOW);
        assert!(!report.replayed);
        assert!(
            !transition_lines(&report).join("\n").contains("replay"),
            "an applied park must not read as a replay"
        );
    }

    #[test]
    fn a_resume_report_says_nothing_booted_and_carries_the_plan() {
        let record = parked("sess-alpha", ParkReason::Operator);
        let report = OwnedResumeReport {
            replayed: true,
            record,
            admitted_plan_id: "plan-abc".to_string(),
        };
        let text = transition_lines(&report.borrowed(TEST_NOW)).join("\n");
        assert!(text.contains("admitted plan:  plan-abc"), "{text}");
        assert!(text.contains("no sandbox was booted"), "{text}");
        assert!(
            text.contains("replay: this resume had already applied"),
            "{text}"
        );
        let json: serde_json::Value = serde_json::from_str(
            &crate::json_out::to_json_string(&report.borrowed(TEST_NOW)).unwrap(),
        )
        .unwrap();
        assert_eq!(json["replayed"], true);
        assert_eq!(json["admitted_plan_id"], "plan-abc");
    }

    #[cfg(feature = "test-support")]
    #[test]
    fn an_exact_resume_retry_replays_the_admitted_plan_at_the_cli() {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let sessions = AgentSessionStore::at(home.path().join("sessions"));
        let checkpoints = CheckpointStore::at(home.path().join("checkpoints"));
        let parent = seed_resume_checkpoint(&checkpoints, home.path());
        let mut record = parked("sess-alpha", ParkReason::Operator);
        record.parent_checkpoint = Some(parent.meta_digest);
        sessions.write(&record).unwrap();
        let mut args = resume_args("sess-alpha");
        args.approval_head = record.approval_head.as_ref().map(ToString::to_string);
        args.retry.expected_generation = Some(record.generation);

        let plan_id = match resume_record(&sessions, &checkpoints, &args).unwrap() {
            ResumeOutcome::Resumed(resumed) => resumed.admitted.plan_id().0.clone(),
            ResumeOutcome::Replayed(_) => panic!("the first resume must apply"),
        };
        match resume_record(&sessions, &checkpoints, &args).unwrap() {
            ResumeOutcome::Replayed(replayed) => {
                assert_eq!(replayed.admitted_plan_id, plan_id);
                assert_eq!(replayed.record.generation, record.generation + 1);
            }
            ResumeOutcome::Resumed(_) => panic!("an exact retry must not resume again"),
        }
    }

    #[cfg(feature = "test-support")]
    #[test]
    fn a_retried_boot_resume_is_refused_at_the_cli_and_boots_nothing_more() {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        install_runtime_overlay(home.path());
        let sessions = AgentSessionStore::at(home.path().join("sessions"));
        let checkpoints = CheckpointStore::at(home.path().join("checkpoints"));
        let parent = seed_resume_checkpoint(&checkpoints, home.path());
        let mut record = parked("sess-boot", ParkReason::RetentionDemotion);
        record.parent_checkpoint = Some(parent.meta_digest);
        sessions.write(&record).unwrap();
        let kernel = stub_kernel(home.path());
        let mut args = boot_args("sess-boot", &kernel);
        args.kernel_sha256 = Some(mvm_core::crypto::image_verify::sha256_file(&kernel).unwrap());
        args.approval_head = record.approval_head.as_ref().map(ToString::to_string);
        args.retry.expected_generation = Some(record.generation);

        let booted = resume_boot_record(&sessions, &checkpoints, &args).unwrap();
        let after_boot = sessions.load(&record.session_id).unwrap();
        let err = resume_boot_record(&sessions, &checkpoints, &args)
            .expect_err("a retried boot resume must refuse rather than boot again");
        let text = format!("{err:#}");
        assert!(text.contains("already applied"), "{text}");
        assert!(
            text.contains(&booted.started.admitted.plan_id().0),
            "{text}"
        );
        assert_eq!(sessions.load(&record.session_id).unwrap(), after_boot);
    }

    // ── retention deadline ──────────────────────────────────────────────

    const HOUR: u64 = 60 * 60;

    fn renew_args(extend_for: &str, deadline: Option<u64>, generation: Option<u64>) -> RenewArgs {
        RenewArgs {
            session_id: "sess-alpha".to_string(),
            extend_for: extend_for.to_string(),
            expected_deadline: deadline,
            retry: RetryArgs {
                expected_generation: generation,
                json: false,
            },
        }
    }

    /// Park `sess-alpha` for an hour through the CLI path and return its deadline.
    fn parked_for_an_hour(store: &AgentSessionStore) -> u64 {
        store.write(&active("sess-alpha")).unwrap();
        let args = ParkArgs {
            retain_for: Some("1h".to_string()),
            ..park_args("operator", Some(1))
        };
        park_record(store, &args)
            .unwrap()
            .record()
            .retain_until_unix
            .expect("a park sets a deadline")
    }

    #[test]
    fn park_retain_for_sets_the_deadline_from_the_flag() {
        let tmp = tempfile::tempdir().unwrap();
        let store = AgentSessionStore::at(tmp.path());
        let before = now_unix();
        let deadline = parked_for_an_hour(&store);
        assert!(
            (before + HOUR..=now_unix() + HOUR).contains(&deadline),
            "{deadline}"
        );
    }

    #[test]
    fn park_without_retain_for_takes_the_reasons_default() {
        let tmp = tempfile::tempdir().unwrap();
        let store = AgentSessionStore::at(tmp.path());
        store.write(&active("sess-alpha")).unwrap();
        let before = now_unix();
        let record = park_record(&store, &park_args("approval-wait", None))
            .unwrap()
            .into_record();
        let default = mvm_runtime::agent_session::APPROVAL_WAIT_RETENTION.as_secs();
        assert!(record.retain_until_unix.unwrap() >= before + default);
    }

    #[test]
    fn a_malformed_retain_for_is_refused_before_the_record_moves() {
        let tmp = tempfile::tempdir().unwrap();
        let store = AgentSessionStore::at(tmp.path());
        let record = active("sess-alpha");
        store.write(&record).unwrap();
        let err = park_record(
            &store,
            &ParkArgs {
                retain_for: Some("forever".to_string()),
                ..park_args("operator", None)
            },
        )
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("invalid --retain-for"),
            "{err:#}"
        );
        assert_eq!(store.load(&record.session_id).unwrap(), record);
    }

    #[test]
    fn a_park_retry_with_another_retention_is_a_conflict_naming_it() {
        let tmp = tempfile::tempdir().unwrap();
        let store = AgentSessionStore::at(tmp.path());
        parked_for_an_hour(&store);
        let err = park_record(
            &store,
            &ParkArgs {
                retain_for: Some("2h".to_string()),
                ..park_args("operator", Some(1))
            },
        )
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("retain_for_secs: recorded 3600, retried 7200"),
            "{err:#}"
        );
    }

    #[test]
    fn renew_extends_and_an_exact_retry_replays_without_a_chain_entry() {
        let host = ChainedHost::new();
        let store = AgentSessionStore::at(host.home.path().join("sessions"));
        let deadline = parked_for_an_hour(&store);
        let args = renew_args("5h", Some(deadline), Some(1));
        let now = deadline - 10;
        let chain = |record: &AgentSessionRecord| record_renew_in_chain(record, &host.emitter);

        let first = renew_and_chain(&store, &args, now, chain).unwrap();
        assert!(!first.is_replay());
        assert_eq!(first.record().retain_until_unix, Some(now + 5 * HOUR));
        assert_eq!(host.entries("session.renewed"), 1);

        let retry = renew_and_chain(&store, &args, now + 60, chain).unwrap();
        assert!(retry.is_replay());
        assert_eq!(retry.record(), first.record());
        assert_eq!(
            host.entries("session.renewed"),
            1,
            "a replayed renewal must not chain a second entry"
        );
        let report = TransitionReport::of(TransitionVerb::Renew, &retry, now + 60);
        assert!(
            transition_lines(&report)
                .join("\n")
                .contains("replay: this renew had already applied")
        );
    }

    #[test]
    fn renew_refuses_to_shorten_and_leaves_the_record_alone() {
        let tmp = tempfile::tempdir().unwrap();
        let store = AgentSessionStore::at(tmp.path());
        let deadline = parked_for_an_hour(&store);
        let before = store.list().unwrap();
        let err =
            renew_record(&store, &renew_args("1m", None, None), deadline - HOUR / 2).unwrap_err();
        assert!(format!("{err:#}").contains("can only extend"), "{err:#}");
        assert_eq!(store.list().unwrap(), before);
    }

    #[test]
    fn renew_refuses_an_expired_session_saying_it_is_past_its_promise() {
        let tmp = tempfile::tempdir().unwrap();
        let store = AgentSessionStore::at(tmp.path());
        let deadline = parked_for_an_hour(&store);
        let err = renew_record(&store, &renew_args("7d", None, None), deadline + 1).unwrap_err();
        assert!(format!("{err:#}").contains("past its promise"), "{err:#}");
    }

    #[test]
    fn renew_refuses_a_closed_or_active_session() {
        let tmp = tempfile::tempdir().unwrap();
        let store = AgentSessionStore::at(tmp.path());
        store.write(&active("sess-alpha")).unwrap();
        let err = renew_record(&store, &renew_args("1h", None, None), TEST_NOW).unwrap_err();
        assert!(format!("{err:#}").contains("not hibernated"), "{err:#}");

        let mut closed = parked("sess-alpha", ParkReason::Operator);
        closed.state = SandboxResidency::Closed;
        store.write(&closed).unwrap();
        let err = renew_record(&store, &renew_args("1h", None, None), TEST_NOW).unwrap_err();
        assert!(format!("{err:#}").contains("closed"), "{err:#}");
    }

    #[test]
    fn renew_refuses_a_malformed_duration() {
        let tmp = tempfile::tempdir().unwrap();
        let store = AgentSessionStore::at(tmp.path());
        parked_for_an_hour(&store);
        let err = renew_record(&store, &renew_args("soon", None, None), TEST_NOW).unwrap_err();
        assert!(format!("{err:#}").contains("invalid --for"), "{err:#}");
    }

    #[test]
    fn the_renew_entry_keys_do_not_collide_with_the_plan_labels() {
        // Past the operator default, so the renewal extends rather than refuses.
        let parked = parked("sess-alpha", ParkReason::Operator);
        let renewed = parked.renew(72 * HOUR, 1_755_000_150).unwrap();
        assert_extras_are_disjoint_from_the_plan_labels(&renewed, &renew_audit_extras(&renewed));
    }

    #[test]
    fn listings_report_an_alive_deadline_and_an_expired_one() {
        let record = parked("sess-alpha", ParkReason::Operator);
        let until = record.retain_until_unix.unwrap();

        let alive = summary_line(&record, until - 2 * HOUR);
        assert!(alive.contains("retention=alive(2h left)"), "{alive}");
        let detail = detail_lines(&record, until - 2 * HOUR).join("\n");
        assert!(
            detail.contains(&format!("retain until:   {until} (unix) — alive")),
            "{detail}"
        );

        let expired = summary_line(&record, until + 3 * HOUR);
        assert!(expired.contains("retention=expired(3h ago)"), "{expired}");
        let detail = detail_lines(&record, until + 3 * HOUR).join("\n");
        assert!(
            detail.contains("past its promise, so renew refuses"),
            "{detail}"
        );

        let json: serde_json::Value = serde_json::from_str(
            &crate::json_out::to_json_string(&SessionView::at(&record, until + 3 * HOUR)).unwrap(),
        )
        .unwrap();
        assert_eq!(json["retention"]["state"], "expired");
        assert_eq!(json["retention"]["expired_for_secs"], 3 * HOUR);
        assert_eq!(json["retain_until_unix"], until);
        assert_eq!(
            json["session_id"], "sess-alpha",
            "the record is flattened in"
        );

        let json: serde_json::Value = serde_json::from_str(
            &crate::json_out::to_json_string(&SessionView::at(&record, until - 1)).unwrap(),
        )
        .unwrap();
        assert_eq!(json["retention"]["state"], "alive");
    }

    #[test]
    fn an_active_session_reports_no_retention() {
        let record = active("sess-alpha");
        assert!(!summary_line(&record, TEST_NOW).contains("retention="));
        let json: serde_json::Value = serde_json::from_str(
            &crate::json_out::to_json_string(&SessionView::at(&record, TEST_NOW)).unwrap(),
        )
        .unwrap();
        assert!(json.get("retention").is_none(), "{json}");
    }

    #[test]
    fn park_extras_carry_the_deadline() {
        let record = parked("sess-alpha", ParkReason::Operator);
        let extras = park_audit_extras(&record);
        assert!(extras.contains(&(
            "park_retain_until_unix".to_string(),
            record.retain_until_unix.unwrap().to_string()
        )));
    }
}
