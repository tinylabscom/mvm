//! `mvmctl machine apply|undo|redo`, and the apply a foreground `machine run`
//! offers when it ends — the operator's side of the reviewed workspace apply.
//!
//! A workspace is a private copy of a host directory; nothing the guest
//! writes reaches the host tree by itself. The engine that plans, gates,
//! snapshots, journals, writes and signs lives in
//! [`mvm_client::workspace_apply`]; this module picks the workspace, shows
//! the operator what would change, and asks on the controlling terminal.
//! Every path that writes the host tree here goes through that one engine.

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::Args;
use mvm_client::approval_broker::display_safe;
use mvm_client::workspace_apply::{
    Applied, ApplyPlan, ExitApply, ExitApplyRequest, ExitOutcome, ExitSettlement, FileOp, OpAction,
    Recovered, Review, ReviewRequest, SignedWorkspaceAudit, WorkspaceApplier, WorkspaceTarget,
    apply_command, apply_store_root, is_affirmative, review,
};
use mvm_core::naming::validate_vm_name;
use mvm_core::user_config::MvmConfig;

use super::workspace::Workspace;
use super::{diff, workspace};
use crate::approval::tty::{ControllingTty, Terminal, ask_armed};

/// The question every reviewed apply asks.
const APPLY_QUESTION: &str = "Apply to working tree? [y/N] ";
/// How long the question waits; no answer is a no.
const ANSWER_WAIT: Duration = Duration::from_secs(600);
/// Longest answer line read.
const ANSWER_LIMIT: usize = 32;
/// Longest diff line shown on the terminal; the rest is cut.
const SHOWN_LINE_CHARS: usize = 400;

#[derive(Args, Debug, Clone)]
pub(in crate::commands) struct ApplyArgs {
    /// Persistent machine name.
    #[arg(value_name = "NAME")]
    pub name: String,
    /// Apply only this workspace volume (required when the machine has more
    /// than one).
    #[arg(long, value_name = "VOLUME")]
    pub volume: Option<String>,
    /// A path the apply must never write or delete (repeatable; the
    /// protected CI/build/test classes are always in force).
    #[arg(long, value_name = "GLOB")]
    pub exclude: Vec<String>,
    /// Extend the protected-path set with an operator pattern (repeatable).
    #[arg(long, value_name = "GLOB")]
    pub protected_path: Vec<String>,
    /// Apply without prompting (required without a terminal).
    #[arg(long)]
    pub yes: bool,
    /// Plan and report without staging or writing anything.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Args, Debug, Clone)]
pub(in crate::commands) struct UndoArgs {
    /// Persistent machine name.
    #[arg(value_name = "NAME")]
    pub name: String,
    /// Undo the latest apply to this workspace volume.
    #[arg(long, value_name = "VOLUME")]
    pub volume: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub(in crate::commands) struct RedoArgs {
    /// Persistent machine name.
    #[arg(value_name = "NAME")]
    pub name: String,
    /// Redo the latest undone apply on this workspace volume.
    #[arg(long, value_name = "VOLUME")]
    pub volume: Option<String>,
}

pub(in crate::commands) fn run_apply(
    _cli: &super::Cli,
    args: ApplyArgs,
    _cfg: &MvmConfig,
) -> Result<()> {
    validate_vm_name(&args.name).with_context(|| format!("Invalid VM name: {:?}", args.name))?;
    let selected = select_workspace(&args.name, args.volume.as_deref())?;
    let audit = SignedWorkspaceAudit::new();
    let applier = open_applier(&args.name, &selected, &audit)?;
    flush_running_guest(&args.name)?;
    let pending =
        match review_workspace(&args.name, &selected, &args.exclude, &args.protected_path)? {
            Review::Refused(plan) => {
                report_refusals(&plan);
                bail!("refusing the apply");
            }
            Review::Unchanged => {
                crate::ui::notice("no changes to apply");
                return Ok(());
            }
            Review::Ready(pending) => pending,
        };
    crate::ui::info(&plan_summary(&selected, pending.plan()));

    if args.dry_run {
        for op in &pending.plan().ops {
            println!("  {}", op_summary(op));
        }
        crate::ui::notice("dry run: nothing staged, nothing written");
        return Ok(());
    }

    ensure_apply_authorized(args.yes, crate::approval::operator_at_terminal())?;
    if !args.yes && !confirm_on_terminal(None)? {
        crate::ui::notice("not applied");
        return Ok(());
    }
    report_applied(&applier.apply(pending)?);
    Ok(())
}

pub(in crate::commands) fn run_undo(
    _cli: &super::Cli,
    args: UndoArgs,
    _cfg: &MvmConfig,
) -> Result<()> {
    validate_vm_name(&args.name).with_context(|| format!("Invalid VM name: {:?}", args.name))?;
    let selected = select_workspace(&args.name, args.volume.as_deref())?;
    let audit = SignedWorkspaceAudit::new();
    let applier = open_applier(&args.name, &selected, &audit)?;
    match applier.undo()? {
        Some(applied) => crate::ui::success(&format!("undid apply {}", applied.target_id)),
        None => crate::ui::notice("nothing to undo"),
    }
    Ok(())
}

pub(in crate::commands) fn run_redo(
    _cli: &super::Cli,
    args: RedoArgs,
    _cfg: &MvmConfig,
) -> Result<()> {
    validate_vm_name(&args.name).with_context(|| format!("Invalid VM name: {:?}", args.name))?;
    let selected = select_workspace(&args.name, args.volume.as_deref())?;
    let audit = SignedWorkspaceAudit::new();
    let applier = open_applier(&args.name, &selected, &audit)?;
    match applier.redo()? {
        Some(applied) => crate::ui::success(&format!("redid apply {}", applied.target_id)),
        None => crate::ui::notice("nothing to redo"),
    }
    Ok(())
}

/// When a foreground run of `vm` ends, offer each of its workspaces back to
/// the host through the same engine `machine apply` uses. `request` decides
/// whether that means asking, applying, or only naming the command.
pub(in crate::commands) fn offer_at_exit(vm: &str, request: ExitApplyRequest) -> Result<()> {
    let workspaces = workspace::workspaces_of(vm)?;
    if workspaces.is_empty() {
        if request.apply {
            crate::ui::notice(&format!(
                "machine {vm:?} has no workspace volume; nothing to apply"
            ));
        }
        return Ok(());
    }
    flush_running_guest(vm)?;
    let decision = request.decide();
    let several = workspaces.len() > 1;
    for selected in &workspaces {
        let pointer = apply_command(vm, several.then_some(selected.volume.as_str()));
        offer_workspace(vm, selected, decision, &pointer)?;
    }
    Ok(())
}

fn offer_workspace(
    vm: &str,
    selected: &Workspace,
    decision: ExitApply,
    pointer: &str,
) -> Result<()> {
    let baseline = workspace::baseline_image(selected)?;
    let audit = SignedWorkspaceAudit::new();
    let settlement = ExitSettlement {
        target: target(vm, selected),
        request: ReviewRequest {
            baseline_image: &baseline,
            live_image: &selected.image,
            exclude: &[],
            protected_paths: &[],
        },
        store_root: apply_store_root(vm, &selected.volume),
        audit: &audit,
    };
    let settled = settlement.settle(decision, |plan| {
        let changes = diff::workspace_changes_text(selected)?.unwrap_or_default();
        let summary = plan_summary(selected, plan);
        confirm_on_terminal(Some(&format!("{changes}{summary}\n")))
    })?;
    report_recovered(settled.recovered);
    match settled.outcome {
        ExitOutcome::Unchanged => {}
        ExitOutcome::Refused(plan) => {
            report_refusals(&plan);
            if decision == ExitApply::Apply {
                bail!(
                    "refusing the apply of workspace volume {:?}",
                    selected.volume
                );
            }
            crate::ui::notice(&format!(
                "nothing was applied to {}",
                selected.source_dir.display()
            ));
        }
        ExitOutcome::NotApplied(plan) => crate::ui::notice(&format!(
            "{}; nothing was applied. Review and apply with: {pointer}",
            plan_summary(selected, &plan)
        )),
        ExitOutcome::Declined(_) => {
            crate::ui::notice(&format!("not applied; apply later with: {pointer}"));
        }
        ExitOutcome::Applied(applied) => report_applied(&applied),
    }
    Ok(())
}

/// Plan `selected` against its baseline and the guest's current image.
fn review_workspace(
    vm: &str,
    selected: &Workspace,
    exclude: &[String],
    protected_paths: &[String],
) -> Result<Review> {
    let baseline = workspace::baseline_image(selected)?;
    review(
        target(vm, selected),
        &ReviewRequest {
            baseline_image: &baseline,
            live_image: &selected.image,
            exclude,
            protected_paths,
        },
    )
}

/// The guest's writes reach the disk before anything is planned from it.
fn flush_running_guest(vm: &str) -> Result<()> {
    if mvm_runtime::checkpoint::vm_is_running(vm) {
        diff::flush_guest(vm)?;
    }
    Ok(())
}

fn target<'a>(vm: &'a str, selected: &'a Workspace) -> WorkspaceTarget<'a> {
    WorkspaceTarget {
        vm,
        volume: &selected.volume,
        source_dir: &selected.source_dir,
    }
}

/// The store for one workspace, with interrupted work settled and reported.
fn open_applier<'a>(
    vm: &'a str,
    selected: &'a Workspace,
    audit: &'a SignedWorkspaceAudit,
) -> Result<WorkspaceApplier<'a>> {
    let (applier, recovered) = WorkspaceApplier::open(target(vm, selected), audit)?;
    report_recovered(recovered);
    Ok(applier)
}

fn report_recovered(recovered: Vec<Recovered>) {
    for item in recovered {
        crate::ui::warn(&match item {
            Recovered::Interrupted(id) => {
                format!("rolled back an interrupted apply ({id}) before continuing")
            }
            Recovered::Unaudited(id) => {
                format!("restored unaudited workspace apply {id} after an interrupted command")
            }
        });
    }
}

/// The prompt gate: `--yes` always authorizes; without it a terminal is
/// required so the reviewed apply is never a silent non-interactive write.
fn ensure_apply_authorized(yes: bool, operator_at_terminal: bool) -> Result<()> {
    if yes || operator_at_terminal {
        return Ok(());
    }
    bail!("not applying without a terminal; pass --yes to apply non-interactively")
}

/// Ask on the controlling terminal — never on standard input, which may
/// belong to the workload that just ran.
fn confirm_on_terminal(shown: Option<&str>) -> Result<bool> {
    let mut terminal = ControllingTty::open().context("opening the controlling terminal")?;
    confirm_apply(&mut terminal, shown)
}

/// Show `shown` with every terminal control sequence removed — it carries
/// file content the guest wrote — then ask the armed question.
fn confirm_apply(terminal: &mut dyn Terminal, shown: Option<&str>) -> Result<bool> {
    if let Some(text) = shown {
        terminal.write(&terminal_safe(text))?;
    }
    let answer = ask_armed(terminal, APPLY_QUESTION, ANSWER_WAIT, ANSWER_LIMIT)?;
    let applied = is_affirmative(answer.as_deref());
    terminal.write(if applied {
        "\r\n"
    } else {
        "\r\n(not applied)\r\n"
    })?;
    Ok(applied)
}

fn terminal_safe(text: &str) -> String {
    text.lines()
        .map(|line| display_safe(line, SHOWN_LINE_CHARS) + "\r\n")
        .collect()
}

/// The workspace to act on: the machine's only one, or the `--volume` pick.
fn select_workspace(vm: &str, volume: Option<&str>) -> Result<Workspace> {
    let all = workspace::workspaces_of(vm)?;
    if all.is_empty() {
        bail!(
            "machine {vm:?} has no workspace volume; attach a host directory read-write with \
             `mvmctl machine volume mount {vm} --volume NAME --host DIR --guest PATH --rw`"
        );
    }
    match volume {
        Some(name) => all
            .into_iter()
            .find(|w| w.volume == name)
            .with_context(|| format!("machine {vm:?} has no workspace volume {name:?}")),
        None => {
            if all.len() > 1 {
                let names: Vec<&str> = all.iter().map(|w| w.volume.as_str()).collect();
                bail!(
                    "machine {vm:?} has several workspace volumes ({}); pass --volume",
                    names.join(", ")
                )
            }
            Ok(all.into_iter().next().expect("one workspace"))
        }
    }
}

fn plan_summary(selected: &Workspace, plan: &ApplyPlan) -> String {
    summary_line(&selected.source_dir, plan)
}

fn summary_line(source_dir: &Path, plan: &ApplyPlan) -> String {
    let removals = plan
        .ops
        .iter()
        .filter(|op| matches!(op.action, OpAction::Remove))
        .count();
    format!(
        "{} change(s) to {}: {} write(s), {} removal(s){}",
        plan.ops.len(),
        source_dir.display(),
        plan.ops.len() - removals,
        removals,
        if plan.skipped_excluded.is_empty() {
            String::new()
        } else {
            format!(", {} excluded", plan.skipped_excluded.len())
        }
    )
}

/// Always shown: this line is the record that the host tree was written.
fn report_applied(applied: &Applied) {
    crate::ui::notice(&format!(
        "applied {} change(s); snapshot merkle root {}; apply manifest root {}",
        applied.changes, applied.snapshot_root, applied.merkle_root
    ));
}

fn report_refusals(plan: &ApplyPlan) {
    crate::ui::warn("the apply is refused:");
    for (path, class) in plan
        .refused_protected
        .iter()
        .chain(plan.refused_unappliable.iter())
    {
        println!("  {path} ({class})");
    }
}

fn op_summary(op: &FileOp) -> String {
    match &op.action {
        OpAction::WriteFile => format!("write {}", op.path),
        OpAction::WriteSymlink { target } => format!("link {} -> {target}", op.path),
        OpAction::Remove => format!("remove {}", op.path),
    }
}

#[cfg(test)]
mod tests {
    use super::{confirm_apply, ensure_apply_authorized, terminal_safe};
    use crate::approval::tty::Terminal;
    use std::collections::VecDeque;
    use std::time::{Duration, Instant};

    /// A terminal that answers from a script. `typed_ahead` is input waiting
    /// before the question is drawn; the arming discards drop it.
    #[derive(Default)]
    struct ScriptedTerminal {
        typed_ahead: VecDeque<String>,
        answers: VecDeque<String>,
        drawn: String,
        discards: usize,
    }

    impl Terminal for ScriptedTerminal {
        fn write(&mut self, text: &str) -> std::io::Result<()> {
            self.drawn.push_str(text);
            Ok(())
        }
        fn discard_input(&mut self) -> std::io::Result<()> {
            self.typed_ahead.clear();
            self.discards += 1;
            Ok(())
        }
        fn read_line(
            &mut self,
            _deadline: Instant,
            _max_bytes: usize,
        ) -> std::io::Result<Option<String>> {
            Ok(self
                .typed_ahead
                .pop_front()
                .or_else(|| self.answers.pop_front()))
        }
        fn pause(&mut self, _duration: Duration) {}
    }

    fn answering(answer: Option<&str>) -> ScriptedTerminal {
        ScriptedTerminal {
            answers: answer.map(String::from).into_iter().collect(),
            ..ScriptedTerminal::default()
        }
    }

    #[test]
    fn yes_authorizes_without_a_terminal() {
        assert!(ensure_apply_authorized(true, false).is_ok());
    }

    #[test]
    fn a_terminal_authorizes_the_prompt() {
        assert!(ensure_apply_authorized(false, true).is_ok());
    }

    #[test]
    fn no_terminal_and_no_yes_refuses() {
        let err = ensure_apply_authorized(false, false).expect_err("must refuse");
        assert!(err.to_string().contains("--yes"), "{err}");
    }

    #[test]
    fn the_prompt_shows_the_changes_then_asks() {
        let mut terminal = answering(Some("y"));
        let applied =
            confirm_apply(&mut terminal, Some("+added line\n1 change(s)\n")).expect("prompt");
        assert!(applied);
        let changes = terminal.drawn.find("+added line").expect("diff shown");
        let question = terminal
            .drawn
            .find("Apply to working tree? [y/N]")
            .expect("question asked");
        assert!(changes < question, "{}", terminal.drawn);
    }

    #[test]
    fn an_empty_or_other_answer_or_none_does_not_apply() {
        for answer in [Some(""), Some("n"), Some("sure"), None] {
            let mut terminal = answering(answer);
            assert!(
                !confirm_apply(&mut terminal, None).expect("prompt"),
                "{answer:?}"
            );
            assert!(terminal.drawn.contains("(not applied)"));
        }
    }

    #[test]
    fn type_ahead_cannot_answer_the_question() {
        let mut terminal = ScriptedTerminal {
            typed_ahead: ["y".to_string()].into(),
            ..answering(None)
        };
        assert!(!confirm_apply(&mut terminal, None).expect("prompt"));
        assert_eq!(terminal.discards, 2, "before drawing and after arming");
    }

    #[test]
    fn guest_written_control_sequences_never_reach_the_terminal() {
        let shown = terminal_safe("+\u{1b}]0;owned\u{7}title\n+\u{1b}[2J\u{1b}[Hcleared\n");
        assert!(!shown.contains('\u{1b}'), "{shown:?}");
        assert!(!shown.contains('\u{7}'), "{shown:?}");
        assert!(shown.contains("+title\r\n"), "{shown:?}");
        assert!(shown.contains("+cleared\r\n"), "{shown:?}");
    }
}
