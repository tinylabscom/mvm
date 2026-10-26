//! Implicit standbys: an unnamed run leaves one standby of the image it booted.
//!
//! Nobody has to prepare anything before a run. The first run of an image
//! boots cold and, once its workload has been handed to the guest, starts a
//! detached `mvmctl pool refill` that prepares a standby of the same launch
//! shape; the next run of that image claims it, and leaves a replacement the
//! same way. The refill runs out of process so the run that started it neither
//! waits for it nor competes with it for its own startup budget.
//!
//! What the standbys may cost the host — a memory budget and an idle timeout —
//! is `mvm_client::standby`'s to enforce; this module decides when a run
//! leaves one and starts the process that prepares it.

use std::path::Path;

use anyhow::{Context, Result};
use mvm_core::user_config::MvmConfig;

use super::{
    SupervisorStandbyPool, WarmParams, WarmRequest, compat_for_launch, resolve_warm_launch,
    warm_to_target,
};
use crate::commands::vm::host_signer;

/// The launch shape a refill prepares a standby for: the arguments a
/// `pool warm` of the same image and sizing would take.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StandbyRefill {
    /// The OCI reference the run named, or `None` for the image a bare run
    /// boots.
    pub image: Option<String>,
    pub cpus: u32,
    pub memory_mib: u32,
    /// Whether the run booted the guest's egress client, so the standby it
    /// leaves can serve the next run that does.
    pub egress: bool,
}

impl StandbyRefill {
    /// The arguments the detached helper is started with.
    fn helper_args(&self) -> Vec<String> {
        let mut args = vec![
            "pool".to_string(),
            "refill".to_string(),
            "--cpus".to_string(),
            self.cpus.to_string(),
            "--memory-mib".to_string(),
            self.memory_mib.to_string(),
        ];
        if let Some(image) = &self.image {
            args.push("--image".to_string());
            args.push(image.clone());
        }
        if self.egress {
            args.push("--egress".to_string());
        }
        args
    }
}

/// The file the detached helper's output goes to, beside the pool it fills.
const REFILL_LOG: &str = "refill.log";

/// Start a detached helper that leaves a standby of `refill` ready for the
/// next run. Best-effort: a refill that cannot start costs the next run its
/// warm start, never this run its result, so a failure is logged and dropped.
///
/// Only the `mvmctl` binary starts one. Anything else that drives a launch
/// through this code — a test binary, an embedding — would re-execute itself
/// with arguments it does not understand.
pub fn schedule_standby_refill(refill: &StandbyRefill) {
    if let Err(error) = spawn_refill_helper(refill) {
        tracing::debug!(%error, "could not start the standby refill");
    }
}

fn spawn_refill_helper(refill: &StandbyRefill) -> Result<()> {
    let exe = std::env::current_exe().context("locating the running mvmctl")?;
    if !is_mvmctl(&exe) {
        return Ok(());
    }
    let pool_root = mvm_core::config::mvm_pool_dir()?;
    std::fs::create_dir_all(&pool_root)
        .with_context(|| format!("creating {}", pool_root.display()))?;
    let log = open_refill_log(&pool_root.join(REFILL_LOG))?;
    let mut command = mvm_core::env_hygiene::helper_command(exe);
    command
        .args(refill.helper_args())
        .stdin(std::process::Stdio::null())
        .stdout(
            log.try_clone()
                .context("duplicating the refill log handle")?,
        )
        .stderr(log);
    // Its own process group, so the terminal's Ctrl-C for the run does not
    // also cancel the standby it leaves behind.
    std::os::unix::process::CommandExt::process_group(&mut command, 0);
    command.spawn().context("starting the standby refill")?;
    let unix_us = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_micros());
    mvm_vmm::agent_debug::line(
        "pool-refill",
        format_args!("phase=scheduled unix_us={unix_us}"),
    );
    Ok(())
}

fn is_mvmctl(exe: &Path) -> bool {
    exe.file_stem().and_then(|s| s.to_str()) == Some("mvmctl")
}

fn open_refill_log(path: &Path) -> Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))
}

/// Record a step of the refill helper, with wall-clock time so it lines up with
/// the launch that scheduled it. The helper is detached, so the trace file the
/// warm claim writes (`MVM_HVF_AGENT_DEBUG`) carries these.
fn refill_phase(started: std::time::Instant, phase: &'static str) {
    mvm_vmm::agent_debug::phase("pool-refill", started, format_args!("phase={phase}"));
}

/// `mvmctl pool refill`: prepare the standby a run asked for, within budget,
/// then stay behind as the host's idle watcher if no other refill is.
pub(super) fn run_refill(
    pool: &SupervisorStandbyPool,
    cfg: &MvmConfig,
    refill: &StandbyRefill,
) -> Result<()> {
    let policy = mvm_core::residency::resolve_residency().0;
    let target = policy.standby_target();
    let idle_timeout = policy.standby_idle_timeout();
    if target == 0 {
        return Ok(());
    }
    let result = refill_one(pool, cfg, refill, target, idle_timeout);
    if let Err(error) = &result {
        tracing::warn!(%error, "standby refill failed");
    }
    mvm_client::standby::watch_idle(idle_timeout);
    result
}

fn refill_one(
    pool: &SupervisorStandbyPool,
    cfg: &MvmConfig,
    refill: &StandbyRefill,
    target: u32,
    idle_timeout: std::time::Duration,
) -> Result<()> {
    let started = std::time::Instant::now();
    refill_phase(started, "begin");
    let req = WarmRequest {
        source: super::WarmSource::Image(refill.image.clone()),
        cpus: refill.cpus,
        memory_mib: refill.memory_mib,
        target,
        egress: refill.egress,
    };
    let launch = resolve_warm_launch(&req)?;
    refill_phase(started, "launch_resolved");
    let want = compat_for_launch(&launch.start_config)?;
    let missing = target.saturating_sub(pool.idle_count_compatible(&want)? as u32);
    if missing == 0 {
        return Ok(());
    }
    let needed_mib = u64::from(missing).saturating_mul(u64::from(refill.memory_mib));
    let budget = mvm_client::standby::StandbyBudget {
        standby_mib: cfg.standby_memory_budget_mib(),
        host_mib: cfg.host_budget_memory_mib,
    };
    if !mvm_client::standby::make_room(budget, needed_mib, idle_timeout)? {
        crate::ui::info(&format!(
            "Not preparing a standby of {}: {needed_mib} MiB does not fit the standby memory \
             budget ({} MiB, `standby_memory_mib`).",
            req.label(),
            budget.standby_mib,
        ));
        return Ok(());
    }
    refill_phase(started, "room_made");
    let signer = host_signer::load_or_init()?;
    refill_phase(started, "signer_loaded");
    let result = warm_to_target(
        pool,
        &WarmParams {
            backend: &launch.backend,
            signer_id: &host_signer::host_signer_id(),
            signing_key_path: &signer.secret_path,
            target,
            launch: &launch.start_config,
        },
    )?;
    refill_phase(started, "warmed");
    mvm_core::audit_emit!(
        PoolWarm,
        "spawned={} failed={} target={target} trigger=run",
        result.spawned,
        result.failed
    );
    if result.failed > 0 && result.spawned == 0 {
        anyhow::bail!(
            "preparing a standby of {}: {}",
            req.label(),
            result.failures.join("; ")
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_helper_is_started_with_the_run_shape() {
        let refill = StandbyRefill {
            image: Some("alpine".into()),
            cpus: 2,
            memory_mib: 512,
            egress: false,
        };
        assert_eq!(
            refill.helper_args(),
            [
                "pool",
                "refill",
                "--cpus",
                "2",
                "--memory-mib",
                "512",
                "--image",
                "alpine"
            ]
        );
        let egress = StandbyRefill {
            egress: true,
            ..refill.clone()
        };
        assert!(egress.helper_args().iter().any(|a| a == "--egress"));
        let default = StandbyRefill {
            image: None,
            ..refill
        };
        assert!(!default.helper_args().iter().any(|a| a == "--image"));
        assert!(!default.helper_args().iter().any(|a| a == "--egress"));
    }

    #[test]
    fn only_the_mvmctl_binary_starts_a_helper() {
        assert!(is_mvmctl(Path::new("/usr/local/bin/mvmctl")));
        assert!(!is_mvmctl(Path::new(
            "/tmp/target/debug/deps/mvm_cli-0123abcd"
        )));
        assert!(!is_mvmctl(Path::new("/usr/bin/python3")));
    }
}
