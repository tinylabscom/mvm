//! The `mvmctl pool` command. The pool itself — compat keys, spawn, claim,
//! replenish, reap — lives in [`mvm_client::pool`]; this module is argument
//! parsing, launch-shape resolution, and rendering.

use anyhow::{Context, Result};
use clap::{Args as ClapArgs, Subcommand};
use mvm_core::user_config::MvmConfig;
use mvm_core::vm_backend::{StandbyHandle, StandbyState};

use super::Cli;
use mvm_client::audit::host_keypair as host_signer;
use mvm_client::pool::{SupervisorStandbyPool, WarmParams, warm_to_target};

mod refill;
mod select;
mod status;

pub use mvm_client::pool::{ColdStartReason, WarmClaimOutcome};
pub use refill::{StandbyRefill, schedule_standby_refill};
use select::{
    WarmSelection, announce_recent_selection, images_to_warm, recent_image_limit, warm_each,
};
use status::{PoolStatus, PoolStatusEntry};

// ── `mvmctl pool` command ───────────────────────────────────────────────────────────

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub action: PoolAction,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum PoolAction {
    /// Prepare standbys ahead of a run: of `--image REF`, of the image a bare
    /// run boots with `--default`, or with neither, of the most recently
    /// pulled images (the default image when nothing was pulled).
    ///
    /// Optional. Every unnamed run already leaves one standby of the image it
    /// booted, so the second run of an image starts warm without this verb;
    /// warming ahead makes the first one warm too, or keeps more than one.
    ///
    /// The pool is swept toward a target count of standbys per image. The
    /// shape is resolved the same way a real launch resolves it — same image,
    /// kernel, verity sidecars, runtime overlay and cmdline tokens — so a later
    /// run with the same image and sizing claims what this prepared. A launch
    /// that differs in image, kernel, vCPUs, memory or egress enablement boots
    /// cold instead. Default count 1.
    ///
    /// Which images are warmed:
    ///
    ///   --image REF   that OCI image.
    ///   --default     the image a bare `machine run` boots.
    ///   neither       the images most recently pulled into the local OCI
    ///                 cache (by `image pull`, or by a `machine run --image`
    ///                 that fetched one), newest first, at most as many as the
    ///                 residency standby target and never fewer than one. With
    ///                 no pulled images, the default image.
    #[command(verbatim_doc_comment)]
    Warm {
        /// How many idle standbys to warm each image toward (default 1).
        count: Option<u32>,
        /// OCI image the warmed parents boot, matching the `--image` the launch
        /// will pass.
        #[arg(long, conflicts_with = "default_image")]
        image: Option<String>,
        /// Warm the image a bare `machine run` boots, whatever was pulled
        /// recently.
        #[arg(long = "default")]
        default_image: bool,
        /// vCPUs the warmed parents boot with; must match the launch's `--cpus`
        /// (default: the configured `default_cpus`).
        #[arg(long)]
        cpus: Option<u32>,
        /// Memory the warmed parents boot with; must match the launch's
        /// `--memory` (default: the configured `default_memory_mib`).
        #[arg(long)]
        memory: Option<String>,
    },
    /// Show the standby pool — recorded standbys and their idle/claimed state.
    Status {
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Prepare the standby a run leaves behind, then release idle standbys
    /// on time. Started detached by the run itself; not meant to be typed.
    #[command(hide = true)]
    Refill {
        /// The OCI image the run named; omit for the image a bare run boots.
        #[arg(long)]
        image: Option<String>,
        /// The run's vCPUs.
        #[arg(long)]
        cpus: u32,
        /// The run's memory, in MiB.
        #[arg(long)]
        memory_mib: u32,
    },
}

/// What `pool warm` warms toward, expressed as the launch it must mirror.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::commands) struct WarmRequest {
    /// The OCI image, or `None` for the image a bare `machine run` boots.
    pub(in crate::commands) image: Option<String>,
    pub(in crate::commands) cpus: u32,
    pub(in crate::commands) memory_mib: u32,
    pub(in crate::commands) target: u32,
}

impl WarmRequest {
    /// One standby of `image` at the configured default sizing — the shape a
    /// `machine run` that passes no `--cpus` or `--memory` claims.
    pub(in crate::commands) fn one_at_default_sizing(image: Option<&str>, cfg: &MvmConfig) -> Self {
        Self {
            image: image.map(str::to_string),
            cpus: cfg.default_cpus,
            memory_mib: cfg.default_memory_mib,
            target: 1,
        }
    }

    fn label(&self) -> &str {
        self.image.as_deref().unwrap_or("the default image")
    }
}

/// Resolve the launch shape a warm parent must boot, without booting one.
///
/// This is the whole point of the verb working at all: a claimable parent needs
/// the rootfs *and* its verity sidecars, the runtime overlay carrying the guest
/// agent, the universal initramfs, and the cmdline-bearing policy fields — none
/// of which a rootfs path supplies, and all of which
/// [`crate::exec::resolve_launch`] produces. Resolving through the run path's
/// own function is what keeps the recorded compat key equal to the one a claim
/// will search for.
///
/// No admission hook is passed. A factory parent carries no workload authority
/// and `factory_parent_config` drops the tenant and plan from whatever it is
/// handed, so admitting one here would buy a signed plan that is discarded —
/// while giving a shared parent a workload's authority is exactly the posture
/// the pool is built to avoid. The launch that later claims the parent supplies
/// its own admitted plan.
fn resolve_warm_launch(req: &WarmRequest) -> Result<crate::exec::ResolvedLaunch> {
    let image = super::vm::exec::resolve_launch_image_source(req.image.as_deref(), false, None)
        .context("resolving the image the warm parents boot")?;
    // Deny-all is the default a `machine run` resolves to, and it is the half
    // of the policy the compat key reads: `StandbyCompat::vsock_egress` records
    // whether the guest boots an egress client, never a destination.
    let network_policy = mvm_core::network_policy::NetworkPolicy::default();
    let shape = crate::exec::LaunchShape {
        name: None,
        image: &image,
        cpus: req.cpus,
        memory_mib: req.memory_mib,
        mem_initial_mib: None,
        dir_shares: &[],
        disk_volumes: &[],
        pty: false,
        network_policy: &network_policy,
        assets: &[],
        warm_pool_size: req.target,
        // A warm standby boots before any workload claims it, so it binds no
        // host service and carries no sidecar.
        sdk_host_services: &[],
        declared_libc: mvm_contract::guest_libc::GuestLibc::Unknown,
        hypervisor: None,
        gpu: false,
        gpu_device: None,
    };
    crate::exec::resolve_launch(
        &shape,
        None,
        &mut crate::exec::LaunchResolveMarks::new(false),
        &mut crate::commands::vm::phase_timing::LaunchSubMarks::new(false),
    )
    .context("resolving the launch shape the warm parents mirror")
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, cfg: &MvmConfig) -> Result<()> {
    match args.action {
        PoolAction::Status { json } => run_status(&SupervisorStandbyPool::open()?, json),
        PoolAction::Refill {
            image,
            cpus,
            memory_mib,
        } => refill::run_refill(
            &SupervisorStandbyPool::open()?,
            cfg,
            &StandbyRefill {
                image,
                cpus,
                memory_mib,
            },
        ),
        PoolAction::Warm {
            count,
            image,
            default_image,
            cpus,
            memory,
        } => {
            let memory_mib = match memory.as_deref() {
                Some(raw) => mvm_core::util::parse_human_size(raw).context("Invalid --memory")?,
                None => cfg.default_memory_mib,
            };
            let selection = WarmSelection::from_flags(image, default_image);
            let recent = match selection {
                WarmSelection::Recent => {
                    super::image::recent_image_references(&super::image::oci_cache_root())?
                }
                _ => Vec::new(),
            };
            let images = images_to_warm(selection.clone(), &recent, recent_image_limit());
            if selection == WarmSelection::Recent {
                announce_recent_selection(&images);
            }
            let requests: Vec<WarmRequest> = images
                .into_iter()
                .map(|image| WarmRequest {
                    image,
                    cpus: cpus.unwrap_or(cfg.default_cpus),
                    memory_mib,
                    target: count.unwrap_or(1),
                })
                .collect();
            warm_each(&requests, warm_request)
        }
    }
}

/// Warm toward `req` — the one path `pool warm`, `image pull --warm` and
/// `image dev ensure --warm` all take.
pub(in crate::commands) fn warm_request(req: &WarmRequest) -> Result<()> {
    run_warm(&SupervisorStandbyPool::open()?, req)
}

fn run_warm(pool: &SupervisorStandbyPool, req: &WarmRequest) -> Result<()> {
    let target = req.target;
    let launch = resolve_warm_launch(req)?;
    // Ensure the host signer exists — the standby re-verifies the attach plan against it.
    let signer = host_signer::load_or_init()?;
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
    // A state-changing verb emits one audit record per attempt.
    mvm_core::audit_emit!(
        PoolWarm,
        "spawned={} failed={} target={target}",
        result.spawned,
        result.failed
    );
    let idle_after = result.spawned;
    if result.failed > 0 && idle_after < target {
        crate::ui::warn(&format!(
            "{}/{} standby(s) warmed; {} spawn(s) failed — check logs for details.",
            idle_after, target, result.failed,
        ));
        let details = result.failures.join("; ");
        return Err(anyhow::anyhow!(
            "pool warm: {}/{} standby(s) warmed, {} failed: {details}",
            idle_after,
            target,
            result.failed,
        ));
    } else if result.spawned == 0 && result.failed == 0 {
        crate::ui::info(&format!(
            "Pool already at or above target {target} for {}.",
            req.label()
        ));
    } else {
        crate::ui::success(&format!(
            "Warmed {} standby(s) of {} toward target {target}.",
            result.spawned,
            req.label(),
        ));
    }
    crate::ui::info(
        "A run claims one of these when it matches on image, kernel, vCPUs, memory and \
         egress enablement and is not given a --name.",
    );
    Ok(())
}

fn build_pool_status(standbys: &[StandbyHandle]) -> PoolStatus {
    let idle = standbys
        .iter()
        .filter(|h| h.state == StandbyState::Idle && SupervisorStandbyPool::is_live_or_saved(h))
        .count();
    let parked = standbys
        .iter()
        .filter(|h| h.state == StandbyState::Parked && SupervisorStandbyPool::is_live_or_saved(h))
        .count();
    let claimed = standbys
        .iter()
        .filter(|h| h.state == StandbyState::Claimed && SupervisorStandbyPool::is_live_or_saved(h))
        .count();
    let dead = standbys
        .iter()
        .filter(|h| !SupervisorStandbyPool::is_live_or_saved(h))
        .count();
    PoolStatus {
        idle,
        claimed,
        parked,
        dead,
        standbys: standbys
            .iter()
            .map(|h| PoolStatusEntry {
                id: h.id.clone(),
                state: if SupervisorStandbyPool::is_live_or_saved(h) {
                    match h.state {
                        StandbyState::Idle => "idle",
                        StandbyState::Claimed => "claimed",
                        StandbyState::Parked => "parked",
                    }
                } else {
                    "dead"
                },
                pid: h.pid,
                kernel_sha256: h.kernel_sha256.clone(),
                vcpus: h.vcpus,
                mem_mib: h.mem_mib,
                image_sha256: h.image_sha256.clone(),
            })
            .collect(),
    }
}

fn run_status(pool: &SupervisorStandbyPool, json: bool) -> Result<()> {
    let standbys = pool.list()?;
    let report = build_pool_status(&standbys);
    if json {
        crate::json_out::emit_json(&report)?;
        return Ok(());
    }
    println!(
        "Supervisor standby pool: {} idle, {} claimed, {} parked, {} dead",
        report.idle, report.claimed, report.parked, report.dead
    );
    for e in &report.standbys {
        let image_tag = e
            .image_sha256
            .as_deref()
            .map(|s| format!(" · image {}", &s[..s.len().min(12)]))
            .unwrap_or_default();
        println!(
            "  {} · {} · {} · {} vcpu / {} MiB · kernel {}{}",
            e.id,
            e.state,
            if e.pid == 0 {
                "saved-state".to_string()
            } else {
                format!("pid {}", e.pid)
            },
            e.vcpus,
            e.mem_mib,
            &e.kernel_sha256[..e.kernel_sha256.len().min(12)],
            image_tag,
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `pool warm` and the run path must resolve the *same* compat key for the
    /// same image and sizing, or the verb warms parents nothing claims — which
    /// is the failure this whole path exists to fix, and it is silent:
    /// `StandbyHandle::is_compatible` is exact equality, so a disagreement
    /// cold-boots every launch while the pool fills.
    ///
    /// Both sides go through `crate::exec::resolve_launch`, so this asserts the
    /// composition end to end rather than comparing two locally-built keys.
    #[cfg(feature = "test-support")]
    #[test]
    fn pool_warm_and_the_run_path_resolve_the_same_compat_key() {
        use mvm_client::pool::{compat_for_launch, warm_eligible_launch};
        use mvm_runtime::backend::AnyBackend;

        let _guard = mvm_runtime::vm::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(tmp.path());

        let kernel = tmp.path().join("vmlinux");
        std::fs::write(&kernel, b"kernel").unwrap();
        let rootfs = tmp.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"rootfs").unwrap();

        let image = crate::exec::ImageSource::Prebuilt {
            kernel_path: kernel.display().to_string(),
            rootfs_path: rootfs.display().to_string(),
            initrd_path: None,
            label: "fixture".into(),
            unpacked_oci_root: None,
        };
        let policy = mvm_core::network_policy::NetworkPolicy::deny_all();
        let shape = |name: Option<&'static str>| crate::exec::LaunchShape {
            name,
            assets: &[],
            image: &image,
            cpus: 2,
            memory_mib: 1024,
            mem_initial_mib: None,
            dir_shares: &[],
            disk_volumes: &[],
            pty: false,
            network_policy: &policy,
            warm_pool_size: 1,
            sdk_host_services: &[],
            declared_libc: mvm_contract::guest_libc::GuestLibc::Unknown,
            hypervisor: Some("mock"),
            gpu: false,
            gpu_device: None,
        };
        let resolve = |name| {
            crate::exec::resolve_launch(
                &shape(name),
                None,
                &mut crate::exec::LaunchResolveMarks::new(false),
                &mut crate::commands::vm::phase_timing::LaunchSubMarks::new(false),
            )
            .unwrap()
        };

        // The warm side resolves ahead of any launch; the run side resolves for
        // the launch itself. Only the VM name differs, and the compat key must
        // not depend on it — a claimed parent runs under its own standby id.
        let warmed = resolve(None);
        let launched = resolve(Some("the-launch"));
        assert_ne!(warmed.start_config.name, launched.start_config.name);

        let backend = AnyBackend::Mock(mvm_runtime::mock::MockBackend::new().with_standby());
        let warm_key = compat_for_launch(backend.as_vm_backend(), &warmed.start_config).unwrap();
        let claim_key = compat_for_launch(backend.as_vm_backend(), &launched.start_config).unwrap();
        assert_eq!(
            warm_key, claim_key,
            "a parent warmed for this image must be found by the launch that boots it"
        );
        assert!(
            warm_key.image_sha256.is_some(),
            "the warm key must name the rootfs, or it matches nothing"
        );
        assert!(
            warm_eligible_launch(&warmed.start_config),
            "the resolved warm shape must be one a shared parent can serve"
        );
    }

    fn idle_handle(id: &str, kernel: &str) -> StandbyHandle {
        StandbyHandle {
            id: id.into(),
            template_id: None,
            control_socket: format!("/p/{id}.sock"),
            pid: std::process::id(),
            kernel_sha256: kernel.into(),
            vcpus: 2,
            mem_mib: 1024,
            binding_nonce: "ab".repeat(32),
            spawned_unix_secs: 1,
            state: StandbyState::Idle,
            image_sha256: None,
            root_strategy: Default::default(),
            parent_checkpoint: None,
            vsock_egress: false,
            preloaded_child_vm_name: None,
        }
    }

    fn saved_idle_handle(id: &str, kernel: &str, image: &str) -> StandbyHandle {
        StandbyHandle {
            id: id.into(),
            template_id: None,
            control_socket: format!("/p/{id}/control.sock"),
            pid: 0,
            kernel_sha256: kernel.into(),
            vcpus: 2,
            mem_mib: 1024,
            binding_nonce: "cd".repeat(32),
            spawned_unix_secs: 1,
            state: StandbyState::Idle,
            image_sha256: Some(image.into()),
            root_strategy: Default::default(),
            parent_checkpoint: None,
            vsock_egress: false,
            preloaded_child_vm_name: None,
        }
    }

    #[test]
    fn build_pool_status_reports_dead_standbys_separately() {
        let live = idle_handle("live", "aa");
        let mut dead = idle_handle("dead", "aa");
        dead.pid = 999_999_999;
        let saved = saved_idle_handle("saved", "aa", "img");

        let report = build_pool_status(&[live, dead, saved]);

        assert_eq!(report.idle, 2, "live process + saved-state are idle");
        assert_eq!(report.claimed, 0);
        assert_eq!(report.parked, 0);
        assert_eq!(report.dead, 1);
        assert_eq!(report.standbys[0].state, "idle");
        assert_eq!(report.standbys[1].state, "dead");
        assert_eq!(report.standbys[2].state, "idle");
    }
}
