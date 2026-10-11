//! `cmd.*` audit envelope around the CLI dispatch.
//!
//! Wraps `commands::run()`'s top-level match so every `mvmctl <verb>`
//! invocation produces two chain-signed entries:
//!
//! - `cmd.<verb>.invoked` — fired before the command runs.
//! - `cmd.<verb>.completed` / `cmd.<verb>.failed` — fired after.
//!
//! These complement (don't replace) the per-command `LocalAuditKind`
//! emissions and the `plan.*` chain. Read-only commands
//! (`ls`, `logs`, `audit tail`) didn't previously emit anything; with
//! this wrap, every invocation has at least one audit footprint.
//!
//! ## Best-effort posture
//!
//! Recorder construction is best-effort. On any failure (`$HOME`
//! unset, host signer not initialized, loose perms on the secret
//! half), the wrap logs a `tracing::warn` and the command runs
//! without cmd-level audit. Audit emits themselves are also
//! best-effort — a chain-signer failure does NOT fail the command,
//! same posture as `mvm_cli::commands::vm::audit_chain::AuditEmitter`
//! and the secret command's audit wiring.
//!
//! The client owns recorder construction, signer scope, and event emission.
//! This adapter owns only the CLI's command classification and stable names.

pub(super) use mvm_client::audit::command::{
    CommandAudit, build_cmd_recorder, emit_cmd_invoked, emit_cmd_outcome,
};

use super::Commands;
use super::machine;

impl Commands {
    /// Whether this command emits a structured payload on stdout and must
    /// reserve that channel before reconcile-on-entry or other startup chrome.
    pub(super) fn emits_machine_readable_stdout(&self) -> bool {
        match self {
            Commands::Run(a) => a.run.json,
            Commands::Why(a) => a.json,
            Commands::SdkNoVm(_) => true,
            Commands::Machine(a) => match &a.action {
                // Folded advanced ops delegate to their own check.
                machine::MachineAction::Vm(cmd) => cmd.emits_machine_readable_stdout(),
                // `machine run --json` streams a structured MachineRunSummary;
                // `machine run --up-json` emits the SDK boot envelope;
                // reserve stdout so reconcile chrome can't interleave.
                //
                // A trailing argv reserves it too. That run relays the guest's
                // own stdout to the caller, so anything the host prints there
                // lands in the middle of the workload's output — a caller
                // reading `machine run -- echo hi` got the greeting with an
                // `[mvm]` warning glued to the front of it.
                machine::MachineAction::Run(r) => r.run.json || r.up_json || !r.run.argv.is_empty(),
                // `machine timeline --json` prints a structured lineage.
                machine::MachineAction::Timeline(t) => t.json,
                // A `--json` restore reuses the fork path's structured output.
                machine::MachineAction::Revert(a) | machine::MachineAction::Rewind(a) => a.json,
                machine::MachineAction::Advance(a) => a.json,
                machine::MachineAction::Ls(a) => a.json,
                machine::MachineAction::Fork(a) => a.json,
                machine::MachineAction::Restore(a) => a.json,
                _ => false,
            },
            // A transition's `--json` report is what a retrying caller parses
            // to learn whether it was a replay; a chain warning printed into it
            // would make that report unreadable exactly when it matters.
            Commands::AgentSession(a) => a.emits_machine_readable_stdout(),
            _ => false,
        }
    }

    /// Whether this command reads or mutates VM lifecycle state and so
    /// warrants the cheap reconcile-on-entry convergence pass.
    /// Read-only, VM-agnostic commands (`doctor`, `ls`
    /// of caches, build/compile, config, …) skip it. `reconcile` itself
    /// is excluded — it *is* the convergence pass, run with its own opts.
    pub(super) fn touches_vm_state(&self) -> bool {
        // `machine <sub>` — named/persistent lifecycle commands touch
        // running-VM state. Unnamed foreground `machine run` is throwaway
        // cattle: running global convergence before it can auto-resume
        // unrelated machines and turn a plain OCI launch into a hidden
        // builder/dev-VM boot.
        // For the advanced VmCmd variants folded under `machine`, delegate to
        // VmCmd's own touches_vm_state (pause/resume/snapshot/save/restore
        // converge; registry-record and guest-RPC ops opt out).
        if let Commands::Machine(a) = self {
            if let machine::MachineAction::Vm(ref cmd) = a.action {
                return cmd.touches_vm_state();
            }
            if let machine::MachineAction::Run(ref run) = a.action {
                return machine_run_touches_vm_state(run);
            }
            // `machine ls --all` is the listing that must render registry-only
            // stopped rows before any convergence pass can sweep them.
            if let machine::MachineAction::Ls(ref list) = a.action {
                return !list.all;
            }
            return true;
        }
        matches!(
            self,
            // Lifecycle mutate/read on the local single-host path.
            Commands::Run(_)
        )
    }

    /// Canonical clap-subcommand name for this variant. Used as the
    /// `<verb>` slot in `cmd.<verb>.*` audit events. The values
    /// MUST match the names emitted by `clap::Command::get_name()`
    /// (the `audit_total_coverage.rs` test pins this via the
    /// AUDIT_POSTURE table; bumping a name here without a matching
    /// table update will trip that test).
    pub(super) fn verb_name(&self) -> &'static str {
        match self {
            // `env <sub>` delegates (bootstrap/cleanup/uninstall/update/sign).
            Commands::Env(a) => a.action.verb_name(),
            Commands::Bootstrap(_) => "bootstrap",
            Commands::BuilderVmBootstrap(_) => "__builder-vm-bootstrap",
            Commands::BuilderEgressSupervisor(_) => "__builder-egress-supervisor",
            Commands::BuilderShellJob(_) => "__builder-shell-job",
            Commands::Explain(_) => "explain",
            Commands::Why(_) => "why",
            Commands::Bench(_) => "bench",
            Commands::Plugin(_) => "plugin",
            Commands::Completions(_) => "completions",
            Commands::Run(_) => "run",
            Commands::SdkNoVm(_) => "__sdk-no-vm",
            Commands::Doctor(_) => "doctor",
            Commands::Dashboard(_) => "dashboard",
            Commands::Prepare(_) => "prepare",
            Commands::Kernel(_) => "kernel",
            Commands::Generate(_) => "generate",
            Commands::Template(_) => "template",
            Commands::Watch(_) => "watch",
            Commands::Manifest(_) => "manifest",
            Commands::Image(_) => "image",
            Commands::Pack(_) => "pack",
            // `machine <sub>`: folded advanced ops (pause/snapshot/set-ttl/…)
            // keep their per-op verb; native lifecycle verbs report `machine`.
            Commands::Machine(a) => a.action.verb_name(),
            Commands::Storage(_) => "storage",
            // `build <sub>` delegates to the per-op verb (image/compile/validate/kernel).
            Commands::Build(a) => a.action.verb_name(),
            Commands::Deploy(_) => "deploy",
            Commands::Deployments(_) => "deployments",
            Commands::ShellInit(_) => "shell-init",
            // `ops <sub>` delegates to the per-op verb (metrics/config/MCP).
            Commands::Ops(a) => a.action.verb_name(),
            Commands::Network(_) => "network",
            Commands::Catalog(_) => "catalog",
            Commands::Cache(_) => "cache",
            Commands::Pool(_) => "pool",
            Commands::Reconcile(_) => "reconcile",
            Commands::Init(_) => "init",
            Commands::Secret(_) => "secret",
            Commands::Bundle(_) => "bundle",
            // `trust <sub>` delegates: attest/receipt/audit keep their own
            // verbs, publisher add/list/remove keep `trust`.
            Commands::Trust(a) => a.action.verb_name(),
            Commands::Policy(_) => "policy",
            Commands::Pull(_) => "pull",
            Commands::Search(_) => "search",
            Commands::AgentSession(_) => "agent-session",
            Commands::Deps(_) => "deps",
            Commands::Capture(a) => a.action.verb_name(),
            Commands::Artifact(_) => "artifact",
            Commands::SeccompAudit(_) => "seccomp-audit",
            Commands::PersistentBuilder(_) => "persistent-builder",
            Commands::QemuVsockBridge(_) => "__qemu-vsock-bridge",
        }
    }
}

fn machine_run_touches_vm_state(run: &machine::MachineRunArgs) -> bool {
    run.name.is_some() || run.detach || run.up_json || run.ttl.is_some() || run.attach
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn emit_helpers_are_noop_when_recorder_is_none() {
        emit_cmd_invoked(None, "up");
        let r: Result<(), anyhow::Error> = Ok(());
        emit_cmd_outcome(None, "up", &r);
    }

    fn parse(args: &[&str]) -> Commands {
        super::super::Cli::try_parse_from(args).unwrap().command
    }

    #[test]
    fn explicit_reconcile_uses_its_own_intent_without_startup_repairs() {
        let command = parse(&["mvmctl", "reconcile", "--dry-run"]);
        assert_eq!(command.verb_name(), "reconcile");
        assert!(!command.touches_vm_state());
    }

    #[test]
    fn read_only_command_metadata_stays_in_the_cli() {
        let command = parse(&["mvmctl", "doctor"]);
        assert_eq!(command.verb_name(), "doctor");
        assert!(!command.touches_vm_state());
        let command = parse(&["mvmctl", "machine", "ls", "--all", "--json"]);
        assert!(command.emits_machine_readable_stdout());
        assert!(!command.touches_vm_state());
    }
}
