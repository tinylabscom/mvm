//! Starting and reaping the per-VM `mvm-netd` gateway.
//!
//! Mirrors the substitution endpoint's shape, for the same reasons: the
//! gateway is a separate process because it parses bytes a hostile guest
//! controls, it is detached so it outlives the `mvmctl` invocation that
//! started it, and it is reaped through a pid file on the stop path.
//!
//! The one thing that differs, and it matters: the gateway must be
//! **listening before the VM starts**. A guest boots and dials its network
//! channels immediately, so a gateway started afterwards would lose the
//! race and the guest would fail closed for no reason. `spawn_netd` waits
//! for the process to report both channels bound before returning.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};

/// Per-VM pid file, under the VM state directory.
pub const NETD_PID_FILE: &str = "netd.pid";

/// How long the gateway gets to bind both channels and report ready.
/// Generous: it covers process start plus two socket binds, and the failure
/// it guards is a hang rather than a slow host.
pub const NETD_READY_TIMEOUT: Duration = Duration::from_secs(10);

/// Marker the gateway prints once it is serving.
const READY_MARKER: &str = "MVM_NETD_READY";

/// Locate the `mvm-netd` binary. Compiled by mvmctl's build script
/// alongside the other per-VM helpers.
fn resolve_netd_path() -> Result<PathBuf> {
    crate::aux_bin::resolve(&crate::aux_bin::AuxBin {
        bin: "mvm-netd",
        env_var: "MVM_NETD_PATH",
    })
}

/// Everything the gateway needs, as the launch path knows it.
#[derive(Debug, Clone)]
pub struct NetdSpawnParams<'a> {
    /// Per-VM state directory; the pid file lands here.
    pub state_dir: &'a Path,
    /// The already-admitted configuration, serialized. Built by the caller
    /// from the signed plan so this module never re-derives policy.
    pub config_json: &'a str,
    /// Machine name, for the diagnostics log path.
    pub vm_name: &'a str,
}

/// Start the gateway and wait until it is serving.
///
/// Returns once both guest channels are bound, so the caller may start the
/// VM immediately afterwards without racing the guest.
pub fn spawn_netd(params: NetdSpawnParams<'_>) -> Result<()> {
    let bin = resolve_netd_path()?;

    // Diagnostics to a per-VM file rather than /dev/null: a gateway that
    // refuses to start is the difference between a workload with networking
    // and one without, and that must be observable after the fact.
    let stderr_log = PathBuf::from("/tmp").join(format!("mvm-netd-{}.log", params.vm_name));
    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&stderr_log)
        .map_err(|e| anyhow!("open netd stderr log {}: {e}", stderr_log.display()))?;

    let mut cmd = Command::new(&bin);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(log_file);
    // SAFETY: `pre_exec` runs post-fork, pre-exec; `setsid` has no
    // preconditions and touches no memory this process owns.
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| anyhow!("spawn mvm-netd ({}): {e}", bin.display()))?;
    let mut guard = NetdGuard::new(child.id(), &params.state_dir.join(NETD_PID_FILE));

    child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("mvm-netd stdin was not piped"))?
        .write_all(params.config_json.as_bytes())
        .map_err(|e| anyhow!("pipe the netd config: {e}"))?;
    // (stdin dropped here → EOF, so the gateway stops reading config.)

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("mvm-netd stdout was not piped"))?;
    wait_for_ready(stdout, NETD_READY_TIMEOUT).map_err(|e| {
        anyhow!(
            "{e}\nThe gateway's diagnostics are at {}.",
            stderr_log.display()
        )
    })?;

    let pid_file = params.state_dir.join(NETD_PID_FILE);
    if let Some(parent) = pid_file.parent() {
        std::fs::create_dir_all(parent).map_err(|e| anyhow!("create {}: {e}", parent.display()))?;
    }
    std::fs::write(&pid_file, child.id().to_string())
        .map_err(|e| anyhow!("write {}: {e}", pid_file.display()))?;
    guard.mark_pid_written();
    Ok(())
}

/// Read stdout until the ready marker appears, or give up.
fn wait_for_ready(stdout: std::process::ChildStdout, timeout: Duration) -> Result<()> {
    // The gateway prints the marker and then goes quiet, so a bounded
    // line read is enough; a process that dies first closes the pipe and
    // surfaces as EOF rather than hanging out the timeout.
    let deadline = Instant::now() + timeout;
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => {
                return Err(anyhow!(
                    "mvm-netd exited before reporting ready — the workload would have \
                     booted into networking that does not exist"
                ));
            }
            Ok(_) if line.starts_with(READY_MARKER) => return Ok(()),
            // A line that is not the marker is diagnostics; keep reading.
            Ok(_) => {}
            Err(e) => return Err(anyhow!("reading the netd ready marker: {e}")),
        }
        if Instant::now() > deadline {
            return Err(anyhow!(
                "mvm-netd did not report ready within {timeout:?} — refusing to start a \
                 workload whose networking is not listening"
            ));
        }
    }
}

/// Stop a VM's gateway. Idempotent: the stop path runs on teardown and on
/// failed startup alike, and neither should care which got there first.
pub fn reap_netd(state_dir: &Path) {
    let pid_file = state_dir.join(NETD_PID_FILE);
    let Ok(raw) = std::fs::read_to_string(&pid_file) else {
        return;
    };
    if let Ok(pid) = raw.trim().parse::<i32>()
        && pid > 0
    {
        // SAFETY: `kill` with a validated positive pid; a stale pid yields
        // ESRCH, which is the desired end state anyway.
        unsafe { libc::kill(pid, libc::SIGTERM) };
    }
    let _ = std::fs::remove_file(&pid_file);
}

/// Kills the child and clears its pid file unless the spawn completed.
///
/// Without this a gateway that failed partway through setup would keep
/// running with no record of it, holding the guest channel sockets that the
/// next boot needs to bind.
struct NetdGuard {
    pid: u32,
    pid_file: PathBuf,
    armed: bool,
}

impl NetdGuard {
    fn new(pid: u32, pid_file: &Path) -> Self {
        Self {
            pid,
            pid_file: pid_file.to_path_buf(),
            armed: true,
        }
    }

    fn mark_pid_written(&mut self) {
        self.armed = false;
    }
}

impl Drop for NetdGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        // `kill(0, …)` signals every process in this process group, and a
        // negative pid signals a whole group by id. Neither is ever what a
        // per-child cleanup wants, so only a strictly positive pid is
        // signalled — the file removal still happens either way.
        if let Ok(pid) = i32::try_from(self.pid)
            && pid > 0
        {
            // SAFETY: a validated positive pid for this process's own
            // child. A child that already exited yields ESRCH, which is
            // the desired end state.
            unsafe { libc::kill(pid, libc::SIGKILL) };
        }
        let _ = std::fs::remove_file(&self.pid_file);
    }
}

/// Start the gateway for a launch, if that launch needs one.
///
/// The single entry point every backend calls. It answers "does this
/// launch use the tunnel" from the admitted plan — the same source the
/// guest cmdline token comes from — so the host and the guest cannot
/// disagree about whether a gateway should exist.
///
/// A launch that is not on the tunnel is a no-op, so backends call this
/// unconditionally rather than each re-deriving the condition.
pub fn spawn_netd_if_needed(
    config: &mvm_core::vm_backend::VmStartConfig,
    state_dir: &Path,
) -> Result<()> {
    if crate::egress_shared::l3_cmdline_token(config).is_none() {
        return Ok(());
    }
    let netd_config = build_netd_config(config)?;
    spawn_netd(NetdSpawnParams {
        state_dir,
        config_json: &netd_config,
        vm_name: &config.name,
    })
}

/// Lower the admitted plan into the gateway's configuration.
///
/// Everything here comes from the plan the supervisor admitted; nothing is
/// re-derived from host state, so the gateway enforces the contract that
/// was signed rather than one assembled at launch time.
fn build_netd_config(config: &mvm_core::vm_backend::VmStartConfig) -> Result<String> {
    use mvm_net::l3::config::{
        DEFAULT_DNS_QPS, DEFAULT_QUEUE_DEPTH, NetdConfig, NetdEgress, NetdRule, NetdUdsLayout,
    };

    let plan_json = config
        .plan_json
        .as_deref()
        .ok_or_else(|| anyhow!("an l3-vsock launch carries no admitted plan"))?;
    let plan = mvm_core::plan::plan_from_admitted_json(plan_json)
        .map_err(|e| anyhow!("decoding the admitted plan for the l3 gateway: {e}"))?;
    let spec = plan
        .l3_network
        .as_ref()
        .ok_or_else(|| anyhow!("an l3-vsock plan carries no l3 network spec"))?;

    // One /30 per machine, from the host allocator. The lease is recorded
    // in the gateway's config so the guest's assigned address and the
    // anti-spoofing check come from the same place.
    let mut allocator = mvm_net::l3::AddressAllocator::with_defaults();
    let lease = allocator
        .allocate()
        .map_err(|e| anyhow!("allocating an address for {}: {e}", config.name))?;

    // The same allow-list the rest of the stack enforces, lowered into the
    // gateway's wire shape. `resolve_rules` returning `None` means the
    // policy is unrestricted; anything else is an explicit rule set, and a
    // rule whose host is not a literal address is dropped here because the
    // gateway matches on addresses — the name is resolved by the gateway's
    // own DNS path, which is what binds it.
    let egress = match config.network_policy.resolve_rules() {
        None => NetdEgress::Unrestricted,
        Some(rules) => NetdEgress::Rules(
            rules
                .iter()
                .filter_map(|rule| {
                    rule.host
                        .parse::<std::net::IpAddr>()
                        .ok()
                        .map(|ip| NetdRule {
                            proto: "tcp".to_string(),
                            cidr: format!("{ip}/32"),
                            port_lo: rule.port,
                            port_hi: rule.port,
                        })
                })
                .collect(),
        ),
    };

    let netd_config = NetdConfig {
        node_id: "local".to_string(),
        vm_id: config.name.clone(),
        // Fresh per boot: the plan id changes every synthesis, so two boots
        // of the same machine never share an identity.
        boot_id: plan.plan_id.0.clone(),
        plan_digest: plan.plan_id.0.clone(),
        uds_layout: NetdUdsLayout::PerVmDir,
        gateway_ipv4: lease.gateway,
        guest_ipv4: lease.guest,
        mtu: spec.mtu,
        egress,
        admitted_private_cidrs: spec.admitted_private_cidrs.clone(),
        icmp: Default::default(),
        policy_epoch: spec.policy_epoch,
        max_flows: spec.max_flows as usize,
        queue_depth: DEFAULT_QUEUE_DEPTH,
        dns_qps: DEFAULT_DNS_QPS,
        ingress: Vec::new(),
    };
    serde_json::to_string(&netd_config).map_err(|e| anyhow!("serializing the netd config: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reaping_an_absent_gateway_is_a_no_op() {
        let dir = tempfile::tempdir().expect("temp dir");
        reap_netd(dir.path());
        reap_netd(dir.path());
    }

    #[test]
    fn reaping_clears_the_pid_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        let pid_file = dir.path().join(NETD_PID_FILE);
        // A pid that is certainly not running; the point is the file goes.
        std::fs::write(&pid_file, "2147483espurious").unwrap();
        reap_netd(dir.path());
        assert!(
            !pid_file.exists(),
            "a stale pid file must not survive a reap, or the next boot \
             believes a gateway is running"
        );
    }

    #[test]
    fn a_guard_that_was_never_marked_removes_its_pid_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        let pid_file = dir.path().join(NETD_PID_FILE);
        std::fs::write(&pid_file, "1").unwrap();
        {
            // pid 0 would signal this whole process group — the guard must
            // refuse it. That refusal is the interesting half of this test:
            // an earlier cut killed the test runner here.
            let _guard = NetdGuard::new(0, &pid_file);
        }
        assert!(!pid_file.exists());
    }

    #[test]
    fn a_marked_guard_leaves_the_pid_file_alone() {
        let dir = tempfile::tempdir().expect("temp dir");
        let pid_file = dir.path().join(NETD_PID_FILE);
        std::fs::write(&pid_file, "1").unwrap();
        {
            let mut guard = NetdGuard::new(0, &pid_file);
            guard.mark_pid_written();
        }
        assert!(
            pid_file.exists(),
            "a completed spawn must keep its pid file so the stop path can reap it"
        );
    }
}

#[cfg(test)]
mod wiring_tests {
    use super::*;
    use mvm_core::plan::{L3NetworkSpec, NetworkMode};
    use mvm_core::vm_backend::VmStartConfig;

    fn config_for(mode: NetworkMode) -> VmStartConfig {
        let mut plan = mvm_core::plan::test_support::PlanFixture::new().build();
        plan.network_mode = mode;
        if mode.is_l3_vsock() {
            plan.l3_network = Some(L3NetworkSpec::v1());
        }
        VmStartConfig {
            name: "wiring".to_string(),
            plan_json: Some(serde_json::to_string(&plan).expect("plan serializes")),
            ..VmStartConfig::default()
        }
    }

    #[test]
    fn a_launch_that_is_not_on_the_tunnel_starts_no_gateway() {
        // The interesting assertion is that this does not even try: there is
        // no `mvm-netd` on a test host, so a spawn attempt would error.
        let dir = tempfile::tempdir().expect("temp dir");
        for mode in [NetworkMode::None, NetworkMode::HostVsockProxy] {
            spawn_netd_if_needed(&config_for(mode), dir.path())
                .unwrap_or_else(|e| panic!("{mode:?} must be a no-op, got {e}"));
        }
        spawn_netd_if_needed(
            &VmStartConfig {
                plan_json: None,
                ..VmStartConfig::default()
            },
            dir.path(),
        )
        .expect("a launch with no admitted plan is not on the tunnel");
        assert!(!dir.path().join(NETD_PID_FILE).exists());
    }

    #[test]
    fn the_gateway_config_comes_from_the_admitted_plan() {
        let config = config_for(NetworkMode::L3Vsock);
        let json = build_netd_config(&config).expect("an l3 plan lowers");
        let lowered: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        let spec = L3NetworkSpec::v1();
        assert_eq!(lowered["vm_id"], "wiring");
        assert_eq!(lowered["mtu"], spec.mtu);
        assert_eq!(lowered["policy_epoch"], spec.policy_epoch);
        assert_eq!(lowered["max_flows"], spec.max_flows);
        // The guest address and the gateway address are the two ends of one
        // lease; if they ever came from different places the anti-spoof
        // check would reject the guest's own traffic.
        let guest: std::net::Ipv4Addr = lowered["guest_ipv4"]
            .as_str()
            .expect("guest address")
            .parse()
            .expect("parses");
        let gateway: std::net::Ipv4Addr = lowered["gateway_ipv4"]
            .as_str()
            .expect("gateway address")
            .parse()
            .expect("parses");
        assert_ne!(guest, gateway);
    }

    #[test]
    fn an_l3_plan_without_a_spec_refuses_rather_than_defaulting() {
        // Synthesis derives the spec from the mode so this cannot arise
        // there, but the gateway must not invent a policy if it ever does.
        let mut plan = mvm_core::plan::test_support::PlanFixture::new().build();
        plan.network_mode = NetworkMode::L3Vsock;
        plan.l3_network = None;
        let config = VmStartConfig {
            plan_json: Some(serde_json::to_string(&plan).expect("serializes")),
            ..VmStartConfig::default()
        };
        let err = build_netd_config(&config).expect_err("must refuse");
        assert!(err.to_string().contains("no l3 network spec"), "{err}");
    }

    #[test]
    fn a_deny_all_policy_lowers_to_an_empty_rule_set_not_to_unrestricted() {
        // The difference is the whole claim: an empty `Rules` list denies
        // everything, `Unrestricted` allows everything.
        let mut config = config_for(NetworkMode::L3Vsock);
        config.network_policy = mvm_core::network_policy::NetworkPolicy::deny_all();
        let json = build_netd_config(&config).expect("lowers");
        let lowered: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        assert!(
            lowered["egress"]
                .get("rules")
                .is_some_and(|r| r.as_array().is_some_and(|a| a.is_empty())),
            "deny-all must lower to an empty rule set, got {}",
            lowered["egress"]
        );
    }
}
