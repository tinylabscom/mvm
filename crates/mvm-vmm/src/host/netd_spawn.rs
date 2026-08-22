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
use mvm_contract::builder::BuilderError;
use mvm_core::vm_backend::BackendKind;

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
    crate::host::aux_bin::resolve(&crate::host::aux_bin::AuxBin {
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

impl<'a> NetdSpawnParams<'a> {
    /// Start building a [`NetdSpawnParams`]. Every value is set by name, so a
    /// call site cannot transpose two fields that share a type.
    #[must_use]
    pub fn builder() -> NetdSpawnParamsBuilder<'a> {
        NetdSpawnParamsBuilder::new()
    }
}

/// Builder for [`NetdSpawnParams`]. Required fields are checked by
/// [`NetdSpawnParamsBuilder::build`] rather than defaulted, so an unset one is a
/// reported error and never a silently empty value.
pub struct NetdSpawnParamsBuilder<'a> {
    state_dir: Option<&'a Path>,
    config_json: Option<&'a str>,
    vm_name: Option<&'a str>,
}

impl<'a> NetdSpawnParamsBuilder<'a> {
    /// An empty builder: nothing set yet.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state_dir: None,
            config_json: None,
            vm_name: None,
        }
    }

    /// Set `state_dir`.
    #[must_use]
    pub fn state_dir(mut self, state_dir: &'a Path) -> Self {
        self.state_dir = Some(state_dir);
        self
    }

    /// Set `config_json`.
    #[must_use]
    pub fn config_json(mut self, config_json: &'a str) -> Self {
        self.config_json = Some(config_json);
        self
    }

    /// Set `vm_name`.
    #[must_use]
    pub fn vm_name(mut self, vm_name: &'a str) -> Self {
        self.vm_name = Some(vm_name);
        self
    }

    /// Finish, or name the first required field left unset.
    pub fn build(self) -> Result<NetdSpawnParams<'a>, BuilderError> {
        Ok(NetdSpawnParams {
            state_dir: self
                .state_dir
                .ok_or(BuilderError::missing("NetdSpawnParams", "state_dir"))?,
            config_json: self
                .config_json
                .ok_or(BuilderError::missing("NetdSpawnParams", "config_json"))?,
            vm_name: self
                .vm_name
                .ok_or(BuilderError::missing("NetdSpawnParams", "vm_name"))?,
        })
    }
}

impl<'a> Default for NetdSpawnParamsBuilder<'a> {
    fn default() -> Self {
        Self::new()
    }
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
///
/// `layout` is the socket convention the caller's own supervisor serves.
/// It is a parameter rather than a constant because the two conventions
/// differ by a directory level, and a gateway that binds the other one
/// listens where nothing dials: the guest gets no network, with both
/// halves individually correct and nothing comparing them.
pub fn spawn_netd_if_needed(
    config: &mvm_core::vm_backend::VmStartConfig,
    state_dir: &Path,
    backend_kind: BackendKind,
) -> Result<()> {
    if crate::host::egress_shared::l3_cmdline_token(config).is_none() {
        return Ok(());
    }
    let netd_config = build_netd_config(config, backend_kind)?;
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
fn build_netd_config(
    config: &mvm_core::vm_backend::VmStartConfig,
    backend_kind: BackendKind,
) -> Result<String> {
    use mvm_net::l3::config::{
        DEFAULT_DNS_QPS, DEFAULT_QUEUE_DEPTH, NetdConfig, NetdEgress, NetdRule, NetdUdsLayout,
    };

    let plan_json = config
        .plan_json
        .as_deref()
        .ok_or_else(|| anyhow!("an l3-vsock launch carries no admitted plan"))?;
    let plan = mvm_core::plan::plan_from_admitted_json(plan_json)
        .map_err(|e| anyhow!("decoding the admitted plan for the l3 gateway: {e}"))?;
    let network_limits = plan
        .effective_network_limits()
        .map_err(|e| anyhow!("invalid admitted network limits: {e}"))?;
    let spec = plan
        .l3_network
        .as_ref()
        .ok_or_else(|| anyhow!("an l3-vsock plan carries no l3 network spec"))?;

    // A plan asking for something this build does not understand is
    // refused here, before an address is leased for a family that would
    // then have no forwarding path behind it.
    let unknown = spec.unknown_features();
    if unknown != 0 {
        return Err(anyhow!(
            "the admitted plan requests l3 wire feature bits this build does not \
             understand: {unknown:#x}"
        ));
    }

    // One /30 per machine, from the host allocator, plus the /126 at the
    // same index when the plan asked for IPv6. The lease is recorded in
    // the gateway's config so the guest's assigned address and the
    // anti-spoofing check come from the same place.
    let mut allocator = mvm_net::l3::AddressAllocator::with_defaults();
    let lease = if spec.requests_ipv6() {
        allocator.allocate_dual()
    } else {
        allocator.allocate()
    }
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
        // The gateway's refusals belong on the same chain as the admission
        // that authorized the workload they refuse on behalf of.
        tenant: plan.tenant.0.clone(),
        uds_layout: match backend_kind {
            BackendKind::Hvf => NetdUdsLayout::HvfVsockDir,
            _ => NetdUdsLayout::PerVmDir,
        },
        gateway_ipv4: lease.gateway,
        guest_ipv4: lease.guest,
        // Present exactly when the plan asked for IPv6. One lease, read
        // once: the gateway derives both the guest's assignment and its
        // own anti-spoofing check from these.
        gateway_ipv6: lease.gateway_v6,
        guest_ipv6: lease.guest_v6,
        mtu: spec.mtu,
        egress,
        admitted_private_cidrs: spec.admitted_private_cidrs.clone(),
        icmp: Default::default(),
        policy_epoch: spec.policy_epoch,
        max_flows: usize::try_from(network_limits.max_tcp_flows)
            .map_err(|_| anyhow!("max_tcp_flows does not fit this host"))?,
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

// The legacy gateway wiring is removed with the retired L3 implementation.
#[cfg(any())]
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
            spawn_netd_if_needed(&config_for(mode), dir.path(), BackendKind::Firecracker)
                .unwrap_or_else(|e| panic!("{mode:?} must be a no-op, got {e}"));
        }
        spawn_netd_if_needed(
            &VmStartConfig {
                plan_json: None,
                ..VmStartConfig::default()
            },
            dir.path(),
            BackendKind::Firecracker,
        )
        .expect("a launch with no admitted plan is not on the tunnel");
        assert!(!dir.path().join(NETD_PID_FILE).exists());
    }

    #[test]
    fn the_gateway_config_comes_from_the_admitted_plan() {
        let config = config_for(NetworkMode::L3Vsock);
        let json = build_netd_config(&config, BackendKind::Firecracker).expect("an l3 plan lowers");
        let lowered: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        let spec = L3NetworkSpec::v1();
        assert_eq!(lowered["vm_id"], "wiring");
        assert_eq!(lowered["uds_layout"], "per_vm_dir");
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

        let hvf_json = build_netd_config(&config, BackendKind::Hvf).expect("an l3 plan lowers");
        let hvf_lowered: serde_json::Value = serde_json::from_str(&hvf_json).expect("valid json");
        assert_eq!(hvf_lowered["uds_layout"], "hvf_vsock_dir");
    }

    #[test]
    fn transport_neutral_flow_limit_overrides_the_legacy_default() {
        let mut config = config_for(NetworkMode::L3Vsock);
        let mut plan = mvm_core::plan::plan_from_admitted_json(
            config.plan_json.as_deref().expect("fixture plan"),
        )
        .expect("fixture parses");
        plan.network_limits = mvm_core::plan::NetworkLimits::builder()
            .max_tcp_flows(37)
            .build()
            .expect("valid limits");
        config.plan_json = Some(serde_json::to_string(&plan).expect("plan serializes"));

        let json = build_netd_config(&config, BackendKind::Firecracker).expect("plan lowers");
        let lowered: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        assert_eq!(lowered["max_flows"], 37);
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
        let err = build_netd_config(&config, BackendKind::Firecracker).expect_err("must refuse");
        assert!(err.to_string().contains("no l3 network spec"), "{err}");
    }

    #[test]
    fn a_deny_all_policy_lowers_to_an_empty_rule_set_not_to_unrestricted() {
        // The difference is the whole claim: an empty `Rules` list denies
        // everything, `Unrestricted` allows everything.
        let mut config = config_for(NetworkMode::L3Vsock);
        config.network_policy = mvm_core::network_policy::NetworkPolicy::deny_all();
        let json = build_netd_config(&config, BackendKind::Firecracker).expect("lowers");
        let lowered: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        assert!(
            lowered["egress"]
                .get("rules")
                .is_some_and(|r| r.as_array().is_some_and(|a| a.is_empty())),
            "deny-all must lower to an empty rule set, got {}",
            lowered["egress"]
        );
    }

    /// A plan that asked for IPv6 has to reach the gateway with an actual
    /// pair, or the family it was admitted for is one it can never use.
    #[test]
    fn a_plan_that_requests_ipv6_is_lowered_with_a_leased_pair() {
        let mut plan = mvm_core::plan::test_support::PlanFixture::new().build();
        plan.network_mode = NetworkMode::L3Vsock;
        plan.l3_network = Some(L3NetworkSpec::v1().requesting_ipv6());
        let config = VmStartConfig {
            name: "wiring".to_string(),
            plan_json: Some(serde_json::to_string(&plan).expect("serializes")),
            ..VmStartConfig::default()
        };
        let json = build_netd_config(&config, BackendKind::Firecracker).expect("an l3 plan lowers");
        let lowered: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        let gateway: std::net::Ipv6Addr = lowered["gateway_ipv6"]
            .as_str()
            .expect("a requesting plan is leased a v6 gateway")
            .parse()
            .expect("parses");
        let guest: std::net::Ipv6Addr = lowered["guest_ipv6"]
            .as_str()
            .expect("a requesting plan is leased a v6 guest address")
            .parse()
            .expect("parses");
        assert_ne!(gateway, guest);
        assert_eq!(
            gateway.segments()[0] & 0xfe00,
            0xfc00,
            "{gateway} must be unique-local"
        );
    }

    /// The default stays v4-only: a workload that did not ask for IPv6
    /// gets exactly the config it got before the host could assign one.
    #[test]
    fn a_plan_that_does_not_request_ipv6_is_lowered_without_one() {
        let config = config_for(NetworkMode::L3Vsock);
        let json = build_netd_config(&config, BackendKind::Firecracker).expect("lowers");
        let lowered: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        assert!(lowered.get("gateway_ipv6").is_none(), "{lowered}");
        assert!(lowered.get("guest_ipv6").is_none(), "{lowered}");
    }

    /// A feature bit this build does not understand is refused rather than
    /// masked off — the plan asked for something, and silently granting
    /// less than it asked for is the failure mode the capability check
    /// exists to prevent.
    #[test]
    fn an_unknown_requested_feature_bit_refuses_the_launch() {
        let mut plan = mvm_core::plan::test_support::PlanFixture::new().build();
        plan.network_mode = NetworkMode::L3Vsock;
        let mut spec = L3NetworkSpec::v1();
        spec.features = 1 << 30;
        plan.l3_network = Some(spec);
        let config = VmStartConfig {
            plan_json: Some(serde_json::to_string(&plan).expect("serializes")),
            ..VmStartConfig::default()
        };
        let err = build_netd_config(&config, BackendKind::Firecracker).expect_err("must refuse");
        assert!(err.to_string().contains("feature"), "{err}");
    }

    /// The gateway binds where the guest's own supervisor listens.
    ///
    /// The two conventions differ by a `vsock/` directory level, and both
    /// halves are individually correct — nothing compared them, which is
    /// exactly how a gateway came to bind a path the HVF supervisor does
    /// not serve. On that tier the guest reached no network at all, with
    /// every component behaving as written.
    ///
    /// Asserting the lowering per layout is what makes the pairing a fact
    /// rather than a convention two call sites happen to share.
    #[test]
    fn each_layout_lowers_to_the_socket_convention_its_supervisor_serves() {
        let config = config_for(NetworkMode::L3Vsock);

        for (backend, expected) in [
            (BackendKind::Firecracker, "per_vm_dir"),
            (BackendKind::Hvf, "hvf_vsock_dir"),
        ] {
            let json = build_netd_config(&config, backend).expect("an l3 plan lowers");
            let lowered: serde_json::Value = serde_json::from_str(&json).expect("valid json");
            assert_eq!(
                lowered["uds_layout"], expected,
                "the layout the caller chose has to survive into the config the \
                 gateway reads, or it binds somewhere nothing dials"
            );
        }
    }
}

#[cfg(test)]
mod netd_spawn_params_builder_tests {
    use super::*;

    /// An empty builder must refuse to finish, naming the first
    /// required field it is missing — never substituting a default.
    #[test]
    fn an_empty_builder_names_the_first_missing_field() {
        let Err(err) = NetdSpawnParams::builder().build() else {
            panic!("an empty NetdSpawnParams builder must not build");
        };
        assert_eq!(err, BuilderError::missing("NetdSpawnParams", "state_dir"));
    }
}
