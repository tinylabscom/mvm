//! Operator surface for durable sessions, distinct from machine residency.
//! The client owns storage, admission, retries, retention and chained audit.

use anyhow::Result;
use clap::{Args as ClapArgs, Subcommand};
use mvm_client::agent_sessions::{
    AgentSessions, OpenRequest, ParkReason, ParkRequest, RenewRequest, Residency, ResumeRequest,
    RetentionStatus, SessionReport, StorageTier, Transition, TransitionReport,
};
use mvm_core::user_config::MvmConfig;

use super::Cli;
use super::shared::human_age_secs;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub action: AgentSessionAction,
}

impl Args {
    pub(in crate::commands) fn emits_machine_readable_stdout(&self) -> bool {
        match &self.action {
            AgentSessionAction::Open(_) => false,
            AgentSessionAction::Ls(a) => a.json,
            AgentSessionAction::Show(a) => a.json,
            AgentSessionAction::Park(a) => a.retry.json,
            AgentSessionAction::Resume(a) => a.retry.json,
            AgentSessionAction::Renew(a) => a.retry.json,
            AgentSessionAction::Replay(_) => false,
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
    /// Fork one of the session's checkpoints and re-deliver its recorded prompts
    Replay(super::vm::prompt_replay::ReplayArgs),
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct OpenArgs {
    /// Session id to create. Refused if a record already exists under it.
    pub session_id: String,
    /// Checkpoint the session may later resume from, as `sha256:<64-hex>`.
    /// Optional: without one, a later resume refuses.
    #[arg(long)]
    pub resume_point: Option<String>,
    /// Sandbox lineage belonging to the session. Repeatable. The first member
    /// supplies the admitted plan under which a park is chained.
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
    /// Why the session is parking: approval-wait, idle, host-shutdown, operator,
    /// retention-demotion. The reason selects the storage tier.
    #[arg(long)]
    pub reason: String,
    /// Session-journal position the park is consistent with
    #[arg(long, default_value_t = 0)]
    pub journal_cursor: u64,
    /// Approval-ledger head as `sha256:<64-hex>`. Without one, resume is unfenced.
    #[arg(long)]
    pub approval_head: Option<String>,
    /// Retention: `30m`, `48h`, `7d` (at most 30d). Defaults: approval-wait 24h,
    /// idle 30m, host-shutdown/operator 48h, retention-demotion 30d.
    #[arg(long, value_name = "DURATION")]
    pub retain_for: Option<String>,
    #[command(flatten)]
    pub retry: RetryArgs,
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct RenewArgs {
    /// Session id, as `agent-session ls` prints it
    pub session_id: String,
    /// Retention measured from now: `30m`, `48h`, `7d` (at most 30d).
    /// Refused if shorter than the current deadline, expired, or not parked.
    #[arg(long = "for", value_name = "DURATION")]
    pub extend_for: String,
    /// Deadline read in unix seconds. Exact renewal retry needs this and
    /// --expected-generation; otherwise it is a new renewal.
    #[arg(long, value_name = "UNIX_SECS")]
    pub expected_deadline: Option<u64>,
    #[command(flatten)]
    pub retry: RetryArgs,
}

#[derive(ClapArgs, Debug, Clone, Default)]
pub(in crate::commands) struct RetryArgs {
    /// Generation read from show. Stale transitions refuse; exact retries return
    /// the original result without writes or audit entries. Without this flag
    /// the generation is read at call time and retries are not recognised.
    #[arg(long, value_name = "N")]
    pub expected_generation: Option<u64>,
    /// Emit the result as JSON, including whether it was a replay
    #[arg(long)]
    pub json: bool,
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct ResumeArgs {
    /// Session id, as `agent-session ls` prints it
    pub session_id: String,
    /// Runtime profile the resumed sandbox is admitted for (hvf, libkrun, …)
    #[arg(long)]
    pub backend: String,
    /// Image reference to record in the signed plan
    #[arg(long)]
    pub image: String,
    /// Lowercase-hex SHA-256 of the rootfs the resume boots
    #[arg(long)]
    pub image_sha256: String,
    /// Lowercase-hex SHA-256 of the kernel. Omit for a backend carrying its own.
    #[arg(long)]
    pub kernel_sha256: Option<String>,
    /// vCPUs the resumed sandbox is admitted for
    #[arg(long)]
    pub cpus: u32,
    /// Memory the resumed sandbox is admitted for, in MiB
    #[arg(long)]
    pub mem_mib: u64,
    /// Current approval-ledger head, as `sha256:<64-hex>`. Must match the parked
    /// head. Omit only for a session parked without one.
    #[arg(long)]
    pub approval_head: Option<String>,
    /// Boot instead of stopping at admission. Only cold-tier sessions boot;
    /// parked and resident tiers refuse rather than discard held state.
    #[arg(long)]
    pub boot: bool,
    /// Kernel image. Required with --boot when --kernel-sha256 is given.
    #[arg(long)]
    pub kernel: Option<std::path::PathBuf>,
    /// An already-applied --boot retry refuses: it never boots another sandbox.
    #[command(flatten)]
    pub retry: RetryArgs,
}

impl From<OpenArgs> for OpenRequest {
    fn from(a: OpenArgs) -> Self {
        Self {
            session_id: a.session_id,
            resume_point: a.resume_point,
            members: a.members,
        }
    }
}

impl From<ParkArgs> for ParkRequest {
    fn from(a: ParkArgs) -> Self {
        Self {
            session_id: a.session_id,
            reason: a.reason,
            journal_cursor: a.journal_cursor,
            approval_head: a.approval_head,
            retain_for: a.retain_for,
            expected_generation: a.retry.expected_generation,
        }
    }
}

impl From<RenewArgs> for RenewRequest {
    fn from(a: RenewArgs) -> Self {
        Self {
            session_id: a.session_id,
            extend_for: a.extend_for,
            expected_deadline: a.expected_deadline,
            expected_generation: a.retry.expected_generation,
        }
    }
}

impl From<ResumeArgs> for ResumeRequest {
    fn from(a: ResumeArgs) -> Self {
        Self {
            session_id: a.session_id,
            backend: a.backend,
            image: a.image,
            image_sha256: a.image_sha256,
            kernel_sha256: a.kernel_sha256,
            cpus: a.cpus,
            mem_mib: a.mem_mib,
            approval_head: a.approval_head,
            boot: a.boot,
            kernel: a.kernel,
            expected_generation: a.retry.expected_generation,
        }
    }
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let service = AgentSessions::local();
    match args.action {
        AgentSessionAction::Open(a) => {
            let record = service.open(&a.into())?;
            println!("{}", summary_line(&record));
            if record.members.is_empty() {
                crate::ui::warn(
                    "this session records no member sandbox, so a later park has no admitted \
                     plan to bind to and will not reach the audit chain",
                );
            }
            Ok(())
        }
        AgentSessionAction::Ls(a) => {
            let records = service.list()?;
            if a.json {
                return crate::json_out::emit_json(&records);
            }
            if records.is_empty() {
                println!("(no agent sessions)");
            } else {
                println!("{:<32} {:<5} RESIDENCY", "SESSION", "GEN");
                for record in &records {
                    println!("{}", summary_line(record));
                }
            }
            Ok(())
        }
        AgentSessionAction::Show(a) => {
            let record = service.show(&a.session_id)?;
            if a.json {
                return crate::json_out::emit_json(&record);
            }
            for line in detail_lines(&record) {
                println!("{line}");
            }
            Ok(())
        }
        AgentSessionAction::Park(a) => {
            let json = a.retry.json;
            report_transition(&service.park(&a.into())?, json)
        }
        AgentSessionAction::Renew(a) => {
            let json = a.retry.json;
            report_transition(&service.renew(&a.into())?, json)
        }
        AgentSessionAction::Resume(a) => {
            let json = a.retry.json;
            report_transition(&service.resume(&a.into())?, json)
        }
        AgentSessionAction::Replay(a) => super::vm::prompt_replay::run(&a),
    }
}

fn report_transition(report: &TransitionReport, json: bool) -> Result<()> {
    for warning in &report.warnings {
        crate::ui::warn(warning);
    }
    if json {
        return crate::json_out::emit_json(report);
    }
    for line in transition_lines(report) {
        println!("{line}");
    }
    Ok(())
}

fn transition_lines(report: &TransitionReport) -> Vec<String> {
    let mut lines = vec![summary_line(&report.session)];
    if let Some(plan) = &report.admitted_plan_id {
        lines.push(format!("admitted plan:  {plan}"));
    }
    match &report.booted_sandbox {
        Some(sandbox) => lines.push(format!("booted sandbox: {sandbox}")),
        None if report.transition == Transition::Resume => lines.push(
            "(no sandbox was booted — a resume re-admits the session, nothing more)".to_string(),
        ),
        None => {}
    }
    if report.replayed {
        let verb = match report.transition {
            Transition::Park => "park",
            Transition::Resume => "resume",
            Transition::Renew => "renew",
        };
        lines.push(format!(
            "replay: this {verb} had already applied; nothing was written and no audit entry was \
             added"
        ));
    }
    lines
}

fn retention_phrase(status: RetentionStatus) -> String {
    match status {
        RetentionStatus::Alive { remaining_secs, .. } => {
            format!("alive({} left)", human_age_secs(remaining_secs))
        }
        RetentionStatus::Expired {
            expired_for_secs, ..
        } => {
            format!("expired({} ago)", human_age_secs(expired_for_secs))
        }
    }
}

fn summary_line(record: &SessionReport) -> String {
    let mut line = format!(
        "{:<32} {:<5} {}",
        record.session_id,
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
    if let Some(status) = record.retention {
        line.push_str("  retention=");
        line.push_str(&retention_phrase(status));
    }
    line
}

fn detail_lines(record: &SessionReport) -> Vec<String> {
    let mut lines = vec![
        format!("session:        {}", record.session_id),
        format!("residency:      {}", residency_name(record.state)),
        format!("generation:     {}", record.generation),
        format!(
            "park reason:    {}",
            record.park_reason.map_or("-", park_reason_name)
        ),
        format!(
            "storage tier:   {}",
            record.storage_tier.map_or("-", storage_tier_name)
        ),
        format!("journal cursor: {}", record.journal_cursor),
        format!(
            "retain until:   {}",
            match (record.retain_until_unix, record.retention) {
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
            record.parent_checkpoint.as_deref().unwrap_or("-")
        ),
    ];
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

fn residency_name(state: Residency) -> &'static str {
    match state {
        Residency::Active => "active",
        Residency::Hibernated => "hibernated",
        Residency::Closed => "closed",
    }
}

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
    use clap::Parser;

    // Renderer fixtures are owned reports, not a second session state machine.
    fn active() -> SessionReport {
        serde_json::from_value(serde_json::json!({
            "session_id": "sess-alpha", "generation": 1, "state": "active",
            "members": ["vm-alpha"], "parent_checkpoint": format!("sha256:{}", "1a".repeat(32)),
            "created_unix": 1755000000_u64, "updated_unix": 1755000100_u64,
            "journal_cursor": 7
        }))
        .unwrap()
    }

    fn parked() -> SessionReport {
        SessionReport {
            state: Residency::Hibernated,
            park_reason: Some(ParkReason::ApprovalWait),
            storage_tier: Some(StorageTier::Parked),
            approval_head: Some(format!("sha256:{}", "ab".repeat(32))),
            retain_until_unix: Some(1755086500),
            retention: Some(RetentionStatus::Alive {
                until_unix: 1755086500,
                remaining_secs: 7200,
            }),
            ..active()
        }
    }

    fn transition(transition: Transition, replayed: bool) -> TransitionReport {
        TransitionReport {
            transition,
            replayed,
            session: parked(),
            admitted_plan_id: None,
            booted_sandbox: None,
            warnings: Vec::new(),
        }
    }

    #[test]
    fn an_active_session_renders_its_residency_and_nothing_about_a_park() {
        let line = summary_line(&active());
        assert!(
            line.contains("sess-alpha") && line.contains("active"),
            "{line}"
        );
        assert!(
            !line.contains("reason=") && !line.contains("tier="),
            "{line}"
        );
    }

    #[test]
    fn a_parked_session_renders_its_reason_and_tier() {
        let line = summary_line(&parked());
        for expected in ["hibernated", "reason=approval-wait", "tier=parked"] {
            assert!(line.contains(expected), "{line}");
        }
    }

    #[test]
    fn an_idle_park_renders_the_resident_tier_it_actually_selects() {
        let record = SessionReport {
            park_reason: Some(ParkReason::Idle),
            storage_tier: Some(StorageTier::Resident),
            ..parked()
        };
        let line = summary_line(&record);
        assert!(
            line.contains("reason=idle") && line.contains("tier=resident"),
            "{line}"
        );
    }

    #[test]
    fn a_closed_session_renders_as_closed() {
        assert!(
            summary_line(&SessionReport {
                state: Residency::Closed,
                ..active()
            })
            .contains("closed")
        );
    }

    #[test]
    fn every_park_reason_renders_its_operator_spelling() {
        for (reason, spelling) in [
            (ParkReason::ApprovalWait, "approval-wait"),
            (ParkReason::Idle, "idle"),
            (ParkReason::HostShutdown, "host-shutdown"),
            (ParkReason::Operator, "operator"),
            (ParkReason::RetentionDemotion, "retention-demotion"),
        ] {
            assert_eq!(park_reason_name(reason), spelling);
        }
    }

    #[test]
    fn detail_says_when_no_approval_head_was_recorded() {
        assert!(
            detail_lines(&active())
                .join("\n")
                .contains("approval head:  (none recorded")
        );
    }

    #[test]
    fn detail_prints_a_recorded_approval_head_as_the_digest_it_is() {
        assert!(
            detail_lines(&parked())
                .join("\n")
                .contains(&format!("sha256:{}", "ab".repeat(32)))
        );
    }

    #[test]
    fn detail_carries_every_recorded_field() {
        let lines = detail_lines(&parked()).join("\n");
        for expected in [
            "session:        sess-alpha",
            "residency:      hibernated",
            "generation:     1",
            "park reason:    approval-wait",
            "storage tier:   parked",
            "journal cursor: 7",
            "members:        vm-alpha",
            "created (unix): 1755000000",
            "updated (unix): 1755000100",
        ] {
            assert!(lines.contains(expected), "{lines}");
        }
        assert!(lines.contains(&format!("resume point:   sha256:{}", "1a".repeat(32))));
    }

    #[test]
    fn a_fresh_park_report_is_not_marked_as_a_replay() {
        assert!(
            !transition_lines(&transition(Transition::Park, false))
                .join("\n")
                .contains("replay")
        );
    }

    #[test]
    fn replay_reports_name_each_transition_in_text_and_json() {
        for (verb, name) in [
            (Transition::Park, "park"),
            (Transition::Renew, "renew"),
            (Transition::Resume, "resume"),
        ] {
            let report = transition(verb, true);
            assert!(
                transition_lines(&report)
                    .join("\n")
                    .contains(&format!("replay: this {name} had already applied"))
            );
            let json = serde_json::to_value(&report).unwrap();
            assert_eq!(json["transition"], name);
            assert_eq!(json["replayed"], true);
            assert_eq!(json["session"]["state"], "hibernated");
        }
    }

    #[test]
    fn a_resume_report_says_nothing_booted_and_carries_the_plan() {
        let mut report = transition(Transition::Resume, true);
        report.admitted_plan_id = Some("plan-abc".into());
        let text = transition_lines(&report).join("\n");
        assert!(
            text.contains("admitted plan:  plan-abc") && text.contains("no sandbox was booted")
        );
        assert_eq!(
            serde_json::to_value(&report).unwrap()["admitted_plan_id"],
            "plan-abc"
        );
        report.booted_sandbox = Some("sandbox-abc".into());
        let text = transition_lines(&report).join("\n");
        assert!(text.contains("booted sandbox: sandbox-abc"));
        assert!(!text.contains("no sandbox was booted"));
    }

    #[test]
    fn listings_report_an_alive_deadline_and_an_expired_one() {
        let mut record = parked();
        assert!(summary_line(&record).contains("retention=alive(2h left)"));
        assert!(
            detail_lines(&record)
                .join("\n")
                .contains("1755086500 (unix) — alive")
        );
        assert_eq!(
            serde_json::to_value(&record).unwrap()["retention"]["state"],
            "alive"
        );
        record.retention = Some(RetentionStatus::Expired {
            until_unix: 1755086500,
            expired_for_secs: 10800,
        });
        assert!(summary_line(&record).contains("retention=expired(3h ago)"));
        assert!(
            detail_lines(&record)
                .join("\n")
                .contains("past its promise, so renew refuses")
        );
        let json = serde_json::to_value(&record).unwrap();
        assert_eq!(json["retention"]["state"], "expired");
        assert_eq!(json["retention"]["expired_for_secs"], 10800);
        assert_eq!(json["retain_until_unix"], 1755086500);
        assert_eq!(json["session_id"], "sess-alpha");
    }

    #[test]
    fn an_active_session_reports_no_retention() {
        assert!(!summary_line(&active()).contains("retention="));
        assert!(
            serde_json::to_value(active())
                .unwrap()
                .get("retention")
                .is_none()
        );
    }

    #[derive(Parser)]
    struct Command {
        #[command(flatten)]
        args: Args,
    }

    fn parse(flags: &[&str]) -> Args {
        Command::try_parse_from(std::iter::once("agent-session").chain(flags.iter().copied()))
            .unwrap()
            .args
    }

    #[test]
    fn boot_defaults_off_so_the_plain_resume_is_unchanged() {
        let args = parse(&[
            "resume",
            "sess-alpha",
            "--backend",
            "hvf",
            "--image",
            "demo",
            "--image-sha256",
            "abcd",
            "--cpus",
            "2",
            "--mem-mib",
            "512",
        ]);
        assert!(!args.emits_machine_readable_stdout());
        let AgentSessionAction::Resume(a) = args.action else {
            panic!("resume")
        };
        let request: ResumeRequest = a.into();
        assert!(!request.boot);
        assert!(request.kernel.is_none());
    }

    #[test]
    fn clap_flags_map_losslessly_to_owned_requests() {
        let args = parse(&[
            "open",
            "sess-alpha",
            "--resume-point",
            "cp",
            "--member",
            "one",
            "--member",
            "two",
        ]);
        let AgentSessionAction::Open(a) = args.action else {
            panic!("open")
        };
        let request: OpenRequest = a.into();
        assert_eq!(request.session_id, "sess-alpha");
        assert_eq!(request.resume_point.as_deref(), Some("cp"));
        assert_eq!(request.members, ["one", "two"]);

        let args = parse(&[
            "park",
            "sess-alpha",
            "--reason",
            "idle",
            "--journal-cursor",
            "19",
            "--approval-head",
            "head",
            "--retain-for",
            "7d",
            "--expected-generation",
            "4",
            "--json",
        ]);
        assert!(args.emits_machine_readable_stdout());
        let AgentSessionAction::Park(a) = args.action else {
            panic!("park")
        };
        let request: ParkRequest = a.into();
        assert_eq!(
            serde_json::to_value(request).unwrap(),
            serde_json::json!({
                "session_id": "sess-alpha", "reason": "idle", "journal_cursor": 19,
                "approval_head": "head", "retain_for": "7d", "expected_generation": 4
            })
        );
        let args = parse(&[
            "renew",
            "sess-alpha",
            "--for",
            "5h",
            "--expected-deadline",
            "900",
            "--expected-generation",
            "4",
            "--json",
        ]);
        assert!(args.emits_machine_readable_stdout());
        let AgentSessionAction::Renew(a) = args.action else {
            panic!("renew")
        };
        let request: RenewRequest = a.into();
        assert_eq!(
            serde_json::to_value(request).unwrap(),
            serde_json::json!({
                "session_id": "sess-alpha", "extend_for": "5h", "expected_deadline": 900, "expected_generation": 4
            })
        );
        let args = parse(&[
            "resume",
            "sess-alpha",
            "--backend",
            "hvf",
            "--image",
            "demo",
            "--image-sha256",
            "root",
            "--kernel-sha256",
            "kernel",
            "--cpus",
            "2",
            "--mem-mib",
            "512",
            "--approval-head",
            "head",
            "--boot",
            "--kernel",
            "/kernel",
            "--expected-generation",
            "4",
            "--json",
        ]);
        assert!(args.emits_machine_readable_stdout());
        let AgentSessionAction::Resume(a) = args.action else {
            panic!("resume")
        };
        let request: ResumeRequest = a.into();
        assert_eq!(
            serde_json::to_value(request).unwrap(),
            serde_json::json!({
                "session_id": "sess-alpha", "backend": "hvf", "image": "demo", "image_sha256": "root",
                "kernel_sha256": "kernel", "cpus": 2, "mem_mib": 512, "approval_head": "head",
                "boot": true, "kernel": "/kernel", "expected_generation": 4
            })
        );
        assert!(parse(&["list", "--json"]).emits_machine_readable_stdout());
        assert!(parse(&["show", "sess-alpha", "--json"]).emits_machine_readable_stdout());
    }
}
