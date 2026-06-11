//! `mvmctl wait` + `mvmctl boot-report` — host-side readiness UX
//! built on `GuestRequest::ReadinessStatus`.
//!
//! Both commands share a `fetch_readiness` helper that drives the
//! protocol-hello prelude with
//! `GuestCapability::Readiness` and dispatches a single
//! `ReadinessStatus` request through `mvm::vsock_transport` (so
//! Firecracker, libkrun, Apple Container, and Docker backends all
//! work without per-backend code in the CLI).
//!
//! `wait` polls until the requested component reaches `Ready`,
//! `Disabled`, or `Failed`. `boot-report` is a single snapshot.

use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use clap::{Args as ClapArgs, ValueEnum};

use mvm::vsock_transport::{self, VsockTransport};
use mvm_core::naming::validate_vm_name;
use mvm_core::user_config::MvmConfig;
use mvm_guest::vsock::{
    ComponentState, GUEST_AGENT_PORT, GuestCapability, GuestRequest, GuestResponse,
    ReadinessReport, negotiate_protocol, send_request,
};

use super::Cli;
use super::shared::clap_vm_name;
use crate::ui;

// ============================================================================
// `mvmctl wait`
// ============================================================================

/// Which `ReadinessReport` component to wait on. Maps 1:1 to the
/// fields of `ReadinessReport`; `All` requires every non-Disabled
/// component to reach `Ready`.
#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
#[clap(rename_all = "kebab-case")]
pub(in crate::commands) enum WaitTarget {
    /// Vsock listener bound. Almost always already `Ready` by the
    /// time `wait` connects — included for shape symmetry.
    ControlPlane,
    /// `/etc/mvm/entrypoint` validated. Gates `mvmctl invoke`.
    Entrypoint,
    /// Warm-process pool started + `after_start.sh` probe passed.
    WarmPool,
    /// Integration drop-in scan complete (zero or more integrations
    /// loaded, health loop running if any).
    Integrations,
    /// Probe drop-in scan complete.
    Probes,
    /// Every non-`Disabled` component is `Ready`. Failed components
    /// abort the wait with a non-zero exit.
    All,
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct WaitArgs {
    /// Name of the running VM.
    #[arg(value_parser = clap_vm_name)]
    pub name: String,

    /// Which readiness component to wait on. Defaults to `all`.
    #[arg(long = "for", value_enum, default_value_t = WaitTarget::All)]
    pub target: WaitTarget,

    /// Maximum seconds to wait before giving up with exit code 75
    /// (`EX_TEMPFAIL`).
    #[arg(long, default_value_t = 60)]
    pub timeout: u64,

    /// Polling interval in milliseconds. Lower values shorten the
    /// last-mile latency at the cost of more vsock round-trips.
    #[arg(long, default_value_t = 250)]
    pub interval_ms: u64,

    /// Print the final `ReadinessReport` as JSON on success / timeout
    /// (failed components always exit non-zero regardless of `--json`).
    #[arg(long)]
    pub json: bool,
}

pub(in crate::commands) fn run_wait(_cli: &Cli, args: WaitArgs, _cfg: &MvmConfig) -> Result<()> {
    validate_vm_name(&args.name).with_context(|| format!("Invalid VM name: {:?}", args.name))?;

    let deadline = Instant::now() + Duration::from_secs(args.timeout);
    let interval = Duration::from_millis(args.interval_ms);

    loop {
        match fetch_readiness(&args.name) {
            Ok(report) => match evaluate(&report, args.target) {
                WaitOutcome::Ready => {
                    if args.json {
                        println!("{}", serde_json::to_string_pretty(&report)?);
                    } else {
                        ui::success(&format!(
                            "{}: {} ready",
                            args.name,
                            target_label(args.target)
                        ));
                    }
                    return Ok(());
                }
                WaitOutcome::Failed { component, message } => {
                    ui::warn(&format!("{}: {component} failed: {message}", args.name));
                    if args.json {
                        println!("{}", serde_json::to_string_pretty(&report)?);
                    }
                    // EX_DATAERR (65). Distinct from timeout (75)
                    // and from a generic CLI failure (1) so wrapper
                    // scripts can branch on the kind.
                    std::process::exit(65);
                }
                WaitOutcome::Pending => {
                    // Fall through to sleep + poll.
                }
            },
            Err(e) => {
                // A still-booting agent commonly fails the first few
                // polls — treat any transport error as transient and
                // retry until the deadline.
                tracing::debug!(err = %e, vm = %args.name, "readiness poll failed; will retry");
            }
        }

        if Instant::now() >= deadline {
            ui::warn(&format!(
                "{}: timed out waiting for {} after {}s",
                args.name,
                target_label(args.target),
                args.timeout
            ));
            std::process::exit(75);
        }
        std::thread::sleep(interval);
    }
}

// ============================================================================
// `mvmctl boot-report`
// ============================================================================

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct BootReportArgs {
    /// Name of the running VM.
    #[arg(value_parser = clap_vm_name)]
    pub name: String,

    /// Emit JSON instead of the human summary.
    #[arg(long)]
    pub json: bool,
}

pub(in crate::commands) fn run_boot_report(
    _cli: &Cli,
    args: BootReportArgs,
    _cfg: &MvmConfig,
) -> Result<()> {
    validate_vm_name(&args.name).with_context(|| format!("Invalid VM name: {:?}", args.name))?;

    let report = fetch_readiness(&args.name)?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_human_report(&args.name, &report);
    }
    Ok(())
}

/// Render a `ReadinessReport` as the same human summary `mvmctl up
/// --timings` uses. Public to the parent module so `up::run` can
/// reuse it post-launch.
pub(in crate::commands::vm) fn print_human_report(vm: &str, report: &ReadinessReport) {
    ui::info(&format!("{vm}: profile={:?}", report.profile));
    print_row("control plane", &report.control_plane);
    print_row("entrypoint", &report.entrypoint);
    print_row("warm pool", &report.warm_pool);
    print_row("integrations", &report.integrations);
    print_row("probes", &report.probes);
    print_row("volumes", &report.volumes);

    let t = &report.boot_millis;
    println!("  timings:");
    print_timing("    agent started", t.agent_started_ms);
    print_timing("    vsock bound", t.vsock_bound_ms);
    print_timing("    first accept", t.first_accept_ms);
    print_timing("    entrypoint ready", t.entrypoint_ready_ms);
    print_timing("    warm pool ready", t.warm_pool_ready_ms);
    print_timing("    integrations ready", t.integrations_ready_ms);
    print_timing("    probes ready", t.probes_ready_ms);
}

fn print_row(label: &str, state: &ComponentState) {
    let rendered = match state {
        ComponentState::Disabled => "disabled".to_string(),
        ComponentState::Starting => "starting".to_string(),
        ComponentState::Ready => "ready".to_string(),
        ComponentState::Failed { message } => format!("failed: {message}"),
    };
    println!("  {label:<14} {rendered}");
}

fn print_timing(label: &str, ms: Option<u64>) {
    match ms {
        Some(v) => println!("{label}: {v} ms"),
        None => println!("{label}: —"),
    }
}

// ============================================================================
// Shared fetcher
// ============================================================================

/// Single readiness round-trip over vsock. Used by `wait`,
/// `boot-report`, and `up --timings`.
pub(in crate::commands::vm) fn fetch_readiness(vm_name: &str) -> Result<ReadinessReport> {
    let transport: Box<dyn VsockTransport> = vsock_transport::for_vm(vm_name)?;
    let mut stream = transport.connect(GUEST_AGENT_PORT)?;
    let _ = negotiate_protocol(&mut stream, vec![GuestCapability::Readiness])?;
    let resp = send_request(&mut stream, &GuestRequest::ReadinessStatus)?;
    match resp {
        GuestResponse::ReadinessStatusReport(report) => Ok(report),
        GuestResponse::Error { message } => bail!("guest readiness error: {message}"),
        GuestResponse::UnsupportedInProfile { profile, verb } => bail!(
            "agent refused {verb} in profile {:?} — this should be impossible for ReadinessStatus",
            profile
        ),
        other => bail!("unexpected response to ReadinessStatus: {other:?}"),
    }
}

// ============================================================================
// Wait-target evaluation (pure; tested below)
// ============================================================================

#[derive(Debug, PartialEq, Eq)]
enum WaitOutcome {
    Ready,
    Pending,
    Failed {
        component: &'static str,
        message: String,
    },
}

fn evaluate(report: &ReadinessReport, target: WaitTarget) -> WaitOutcome {
    match target {
        WaitTarget::ControlPlane => classify_one("control_plane", &report.control_plane),
        WaitTarget::Entrypoint => classify_one("entrypoint", &report.entrypoint),
        WaitTarget::WarmPool => classify_one("warm_pool", &report.warm_pool),
        WaitTarget::Integrations => classify_one("integrations", &report.integrations),
        WaitTarget::Probes => classify_one("probes", &report.probes),
        WaitTarget::All => {
            for (name, state) in [
                ("control_plane", &report.control_plane),
                ("entrypoint", &report.entrypoint),
                ("warm_pool", &report.warm_pool),
                ("integrations", &report.integrations),
                ("probes", &report.probes),
            ] {
                match classify_one(name, state) {
                    WaitOutcome::Ready => continue,
                    WaitOutcome::Pending => return WaitOutcome::Pending,
                    failed @ WaitOutcome::Failed { .. } => return failed,
                }
            }
            WaitOutcome::Ready
        }
    }
}

fn classify_one(name: &'static str, state: &ComponentState) -> WaitOutcome {
    match state {
        // `Disabled` is "this component intentionally isn't running"
        // — that's a satisfied wait, not a failure. Cold-tier images
        // with no warm pool would otherwise spin forever on
        // `--for warm-pool`.
        ComponentState::Disabled | ComponentState::Ready => WaitOutcome::Ready,
        ComponentState::Starting => WaitOutcome::Pending,
        ComponentState::Failed { message } => WaitOutcome::Failed {
            component: name,
            message: message.clone(),
        },
    }
}

fn target_label(target: WaitTarget) -> &'static str {
    match target {
        WaitTarget::ControlPlane => "control plane",
        WaitTarget::Entrypoint => "entrypoint",
        WaitTarget::WarmPool => "warm pool",
        WaitTarget::Integrations => "integrations",
        WaitTarget::Probes => "probes",
        WaitTarget::All => "all components",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::security::AgentProfile;
    use mvm_guest::vsock::BootTimingReport;

    fn ready_report() -> ReadinessReport {
        ReadinessReport {
            control_plane: ComponentState::Ready,
            entrypoint: ComponentState::Ready,
            warm_pool: ComponentState::Disabled,
            integrations: ComponentState::Disabled,
            probes: ComponentState::Disabled,
            volumes: ComponentState::Disabled,
            profile: AgentProfile::SealedProd,
            boot_millis: BootTimingReport {
                agent_started_ms: Some(5),
                vsock_bound_ms: Some(5),
                first_accept_ms: Some(9),
                entrypoint_ready_ms: Some(40),
                ..Default::default()
            },
        }
    }

    #[test]
    fn evaluate_all_with_ready_or_disabled_components_returns_ready() {
        assert_eq!(
            evaluate(&ready_report(), WaitTarget::All),
            WaitOutcome::Ready
        );
    }

    #[test]
    fn evaluate_all_returns_pending_if_any_component_is_starting() {
        let mut r = ready_report();
        r.entrypoint = ComponentState::Starting;
        assert_eq!(evaluate(&r, WaitTarget::All), WaitOutcome::Pending);
    }

    #[test]
    fn evaluate_all_returns_failed_with_message() {
        let mut r = ready_report();
        r.entrypoint = ComponentState::Failed {
            message: "missing entrypoint marker".to_string(),
        };
        match evaluate(&r, WaitTarget::All) {
            WaitOutcome::Failed { component, message } => {
                assert_eq!(component, "entrypoint");
                assert_eq!(message, "missing entrypoint marker");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn evaluate_warm_pool_disabled_is_ready_not_pending() {
        // Cold-tier image: `--for warm-pool` must NOT spin forever
        // when the image opted out of warm pool entirely.
        let r = ready_report();
        assert_eq!(r.warm_pool, ComponentState::Disabled);
        assert_eq!(evaluate(&r, WaitTarget::WarmPool), WaitOutcome::Ready);
    }

    #[test]
    fn evaluate_entrypoint_starting_is_pending() {
        let mut r = ready_report();
        r.entrypoint = ComponentState::Starting;
        assert_eq!(evaluate(&r, WaitTarget::Entrypoint), WaitOutcome::Pending);
    }

    #[test]
    fn wait_target_value_enum_uses_kebab_case() {
        // clap renders these in `--help`; lock the wire format so a
        // future enum-variant addition doesn't silently change the
        // user-facing flag value.
        let names: Vec<&str> = WaitTarget::value_variants()
            .iter()
            .filter_map(|v| v.to_possible_value())
            .map(|v| {
                // PossibleValue::get_name returns &'static str via Box leak; cheat with leak-equivalent
                let n = v.get_name().to_string();
                Box::leak(n.into_boxed_str()) as &'static str
            })
            .collect();
        assert_eq!(
            names,
            vec![
                "control-plane",
                "entrypoint",
                "warm-pool",
                "integrations",
                "probes",
                "all",
            ]
        );
    }
}
