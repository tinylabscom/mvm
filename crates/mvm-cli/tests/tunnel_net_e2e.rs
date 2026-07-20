//! Gated live smoke for raw-L3 host-forwarded egress over the vsock tunnel.
//!
//! Skipped by default. Set `MVM_TUNNEL_NET_SMOKE=1` on an operator-approved host
//! that can boot workload microVMs. The smoke drives the public CLI path:
//!
//! `mvmctl machine run --image <image> --allow-host <host:port> -- <probe>`
//!
//! The guest is a dumb L3 endpoint: admitted hostnames are injected as guest
//! `/etc/hosts` entries from the admission pin registry, so ordinary in-guest DNS
//! plus TCP/ICMP prove the packaged guest tunnel pump, host authority worker, the
//! host TUN + kernel NAT forward path, policy admission, and byte forwarding are
//! connected end to end. The HTTPS probe fetches a real cert with no MITM.
//!
//! The full workload path requires a **Linux** host running the **libkrun**
//! backend: host TUN forwarding (`/dev/net/tun` + nftables NAT) is Linux-only.
//! On macOS/HVF the tunnel enables but host forwarding is a pending follow-up, so
//! this witness does not exercise egress there.

#![cfg(unix)]

use assert_cmd::cargo::CommandCargoExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const ENABLE_VAR: &str = "MVM_TUNNEL_NET_SMOKE";
const IMAGE_VAR: &str = "MVM_TUNNEL_NET_IMAGE";
const HOST_VAR: &str = "MVM_TUNNEL_NET_HOST";
const PORT_VAR: &str = "MVM_TUNNEL_NET_PORT";
const EXPECT_VAR: &str = "MVM_TUNNEL_NET_EXPECT";
const HYPERVISOR_VAR: &str = "MVM_TUNNEL_NET_HYPERVISOR";
const ICMP_HOST_VAR: &str = "MVM_TUNNEL_NET_ICMP_HOST";
const KEEP_FAILED_VAR: &str = "MVM_TUNNEL_NET_KEEP_FAILED_VM";
const SCRATCH_VAR: &str = "MVM_TUNNEL_NET_SCRATCH";
const DEADLINE_VAR: &str = "MVM_TUNNEL_NET_DEADLINE_SECS";

const DEFAULT_IMAGE: &str = "docker.io/library/alpine:3.20";
const DEFAULT_HOST: &str = "example.com";
const DEFAULT_PORT: &str = "443";
const DEFAULT_EXPECT: &str = "Example Domain";
const DEFAULT_HYPERVISOR: &str = "libkrun";

const RUN_BUDGET: Duration = Duration::from_secs(900);
const STOP_BUDGET: Duration = Duration::from_secs(90);

const OK_MARKER: &str = "mvm-tunnel-net-ok";
const ICMP_OK_MARKER: &str = "mvm-tunnel-net-icmp-ok";
const DENIED_MARKER: &str = "mvm-tunnel-net-denied-ok";
const LEAK_MARKER: &str = "mvm-tunnel-net-LEAK";

struct Step {
    success: bool,
    output: String,
    timed_out: bool,
}

struct SmokeHarness {
    scratch: PathBuf,
    target_dir: PathBuf,
}

impl SmokeHarness {
    fn new() -> Self {
        let scratch = std::env::var_os(SCRATCH_VAR)
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                std::env::temp_dir().join(format!("mvm-tunnel-net-e2e-{}", std::process::id()))
            });
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(&scratch).expect("create scratch dir");
        Self {
            scratch,
            target_dir: target_dir_from_current_test(),
        }
    }

    fn run_mvmctl(&self, args: &[&str], label: &str, budget: Duration) -> Step {
        let out_path = self.scratch.join(format!("{label}.stdout.log"));
        let err_path = self.scratch.join(format!("{label}.stderr.log"));
        let out_f = std::fs::File::create(&out_path).expect("create stdout log");
        let err_f = std::fs::File::create(&err_path).expect("create stderr log");

        #[allow(deprecated)]
        let mut cmd = Command::cargo_bin("mvmctl").expect("locate mvmctl");
        cmd.args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::from(out_f))
            .stderr(Stdio::from(err_f))
            .process_group(0);
        self.configure_env(&mut cmd);

        let mut child = cmd.spawn().expect("spawn mvmctl");
        let pgid = child.id() as i32;
        let start = Instant::now();
        let mut timed_out = false;
        let status = loop {
            match child.try_wait().expect("poll mvmctl") {
                Some(status) => break Some(status),
                None if start.elapsed() >= budget => {
                    unsafe {
                        libc::kill(-pgid, libc::SIGKILL);
                    }
                    let _ = child.wait();
                    timed_out = true;
                    break None;
                }
                None => std::thread::sleep(Duration::from_millis(200)),
            }
        };

        let mut output = std::fs::read_to_string(&out_path).unwrap_or_default();
        output.push_str(&std::fs::read_to_string(&err_path).unwrap_or_default());
        Step {
            success: status.map(|s| s.success()).unwrap_or(false),
            output,
            timed_out,
        }
    }

    /// Stop the VM unless a failed run asked to keep it for post-mortem.
    fn maybe_stop(&self, vm_name: &str, run: &Step) {
        if !run.success && keep_failed_vm() {
            eprintln!(
                "[tunnel_net_e2e] keeping failed VM {vm_name}; scratch {}",
                self.scratch.display()
            );
            return;
        }
        let _ = self.run_mvmctl(
            &["machine", "stop", vm_name, "--yes"],
            "machine-stop",
            STOP_BUDGET,
        );
    }

    fn configure_env(&self, cmd: &mut Command) {
        let path = std::env::var("PATH").unwrap_or_default();
        cmd.env("PATH", format!("{}:{path}", self.target_dir.display()))
            .env("MVM_HOME", self.scratch.join("mvm-home"));
        set_helper_override_if_present(
            cmd,
            "MVM_LIBKRUN_SUPERVISOR_PATH",
            &self.target_dir.join("mvm-libkrun-supervisor"),
        );
        set_helper_override_if_present(
            cmd,
            "MVM_NETWORK_TUNNEL_WORKER_PATH",
            &self.target_dir.join("mvm-network-tunnel-worker"),
        );
    }
}

fn set_helper_override_if_present(cmd: &mut Command, env_var: &str, path: &Path) {
    if path.is_file() {
        cmd.env(env_var, path);
    }
}

fn target_dir_from_current_test() -> PathBuf {
    std::env::current_exe()
        .expect("current test exe")
        .ancestors()
        .nth(2)
        .expect("target profile dir")
        .to_path_buf()
}

fn smoke_enabled() -> bool {
    std::env::var(ENABLE_VAR).as_deref() == Ok("1")
}

fn keep_failed_vm() -> bool {
    std::env::var(KEEP_FAILED_VAR).as_deref() == Ok("1")
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn arm_watchdog(scratch: PathBuf) {
    let secs = std::env::var(DEADLINE_VAR)
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .unwrap_or(1200);
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(secs));
        eprintln!(
            "tunnel_net_e2e watchdog hit after {secs}s; logs are under {}",
            scratch.display()
        );
        std::process::exit(124);
    });
}

fn env_or(var: &str, default: &str) -> String {
    std::env::var(var).unwrap_or_else(|_| default.to_string())
}

fn skip_notice(test: &str) {
    eprintln!(
        "[tunnel_net_e2e] {test} skipped - set {ENABLE_VAR}=1 and run on a \
         Linux libkrun host (host TUN forwarding is Linux-only)"
    );
}

// -- Non-gated unit tests: assert the gate contract without booting a VM. ------

#[test]
fn tunnel_net_smoke_gate_env_names_are_stable() {
    assert_eq!(ENABLE_VAR, "MVM_TUNNEL_NET_SMOKE");
    assert_eq!(IMAGE_VAR, "MVM_TUNNEL_NET_IMAGE");
    assert_eq!(HOST_VAR, "MVM_TUNNEL_NET_HOST");
    assert_eq!(PORT_VAR, "MVM_TUNNEL_NET_PORT");
    assert_eq!(HYPERVISOR_VAR, "MVM_TUNNEL_NET_HYPERVISOR");
    assert_eq!(ICMP_HOST_VAR, "MVM_TUNNEL_NET_ICMP_HOST");
    assert_eq!(KEEP_FAILED_VAR, "MVM_TUNNEL_NET_KEEP_FAILED_VM");
    assert_eq!(SCRATCH_VAR, "MVM_TUNNEL_NET_SCRATCH");
}

#[test]
fn tunnel_net_defaults_are_stable() {
    assert_eq!(DEFAULT_IMAGE, "docker.io/library/alpine:3.20");
    assert_eq!(DEFAULT_HOST, "example.com");
    assert_eq!(DEFAULT_PORT, "443");
    assert_eq!(DEFAULT_HYPERVISOR, "libkrun");
}

#[test]
fn shell_quote_wraps_and_escapes_single_quotes() {
    assert_eq!(shell_quote("example.com"), "'example.com'");
    assert_eq!(shell_quote("can't"), "'can'\"'\"'t'");
}

// -- Gated live workload witnesses. --------------------------------------------

#[test]
fn tunnel_net_allow_host_resolves_and_fetches_https() {
    if !smoke_enabled() {
        skip_notice("tunnel_net_allow_host_resolves_and_fetches_https");
        return;
    }

    let harness = SmokeHarness::new();
    arm_watchdog(harness.scratch.clone());
    eprintln!("tunnel_net_e2e scratch: {}", harness.scratch.display());

    let image = env_or(IMAGE_VAR, DEFAULT_IMAGE);
    let host = env_or(HOST_VAR, DEFAULT_HOST);
    let port = env_or(PORT_VAR, DEFAULT_PORT);
    let expect = env_or(EXPECT_VAR, DEFAULT_EXPECT);
    let hypervisor = env_or(HYPERVISOR_VAR, DEFAULT_HYPERVISOR);
    let allow_host = format!("{host}:{port}");
    let url = format!("https://{host}/");
    let vm_name = format!("mvm-tunnel-https-{}", std::process::id());
    // Real DNS via /etc/hosts + TCP egress + end-to-end TLS to the real cert.
    let probe = format!(
        "set -eu\n\
         body=$(wget -q -O - {})\n\
         printf '%s' \"$body\" | grep -qi {}\n\
         printf '{OK_MARKER}\\n'\n",
        shell_quote(&url),
        shell_quote(&expect),
    );

    let args = [
        "machine",
        "run",
        "--name",
        &vm_name,
        "--hypervisor",
        &hypervisor,
        "--profile",
        "dev",
        "--image",
        &image,
        "--allow-host",
        &allow_host,
        "--timeout",
        "90",
        "--",
        "/bin/sh",
        "-c",
        &probe,
    ];
    let run = harness.run_mvmctl(&args, "machine-run-https", RUN_BUDGET);
    harness.maybe_stop(&vm_name, &run);

    assert!(
        !run.timed_out,
        "https tunnel smoke timed out after {RUN_BUDGET:?}; logs in {}\n{}",
        harness.scratch.display(),
        run.output
    );
    assert!(
        run.success,
        "https tunnel smoke failed; logs in {}\n{}",
        harness.scratch.display(),
        run.output
    );
    assert!(
        run.output.contains(OK_MARKER),
        "guest probe did not report success; output:\n{}",
        run.output
    );
}

#[test]
fn tunnel_net_allow_host_replies_to_icmp_echo() {
    if !smoke_enabled() {
        skip_notice("tunnel_net_allow_host_replies_to_icmp_echo");
        return;
    }

    let harness = SmokeHarness::new();
    arm_watchdog(harness.scratch.clone());
    eprintln!("tunnel_net_e2e scratch: {}", harness.scratch.display());

    let image = env_or(IMAGE_VAR, DEFAULT_IMAGE);
    let host = env_or(ICMP_HOST_VAR, &env_or(HOST_VAR, DEFAULT_HOST));
    let port = env_or(PORT_VAR, DEFAULT_PORT);
    let hypervisor = env_or(HYPERVISOR_VAR, DEFAULT_HYPERVISOR);
    let allow_host = format!("{host}:{port}");
    let vm_name = format!("mvm-tunnel-icmp-{}", std::process::id());
    // ICMP echo returns through the same host TUN + kernel path as TCP.
    let probe = format!(
        "set -eu\n\
         ping -c1 -W2 {}\n\
         printf '{ICMP_OK_MARKER}\\n'\n",
        shell_quote(&host),
    );

    let args = [
        "machine",
        "run",
        "--name",
        &vm_name,
        "--hypervisor",
        &hypervisor,
        "--profile",
        "dev",
        "--image",
        &image,
        "--allow-host",
        &allow_host,
        "--timeout",
        "90",
        "--",
        "/bin/sh",
        "-c",
        &probe,
    ];
    let run = harness.run_mvmctl(&args, "machine-run-icmp", RUN_BUDGET);
    harness.maybe_stop(&vm_name, &run);

    assert!(
        !run.timed_out,
        "icmp tunnel smoke timed out after {RUN_BUDGET:?}; logs in {}\n{}",
        harness.scratch.display(),
        run.output
    );
    assert!(
        run.success,
        "icmp tunnel smoke failed; logs in {}\n{}",
        harness.scratch.display(),
        run.output
    );
    assert!(
        run.output.contains(ICMP_OK_MARKER),
        "guest ping probe did not report success; output:\n{}",
        run.output
    );
}

#[test]
fn tunnel_net_without_grant_cannot_fetch() {
    if !smoke_enabled() {
        skip_notice("tunnel_net_without_grant_cannot_fetch");
        return;
    }

    let harness = SmokeHarness::new();
    arm_watchdog(harness.scratch.clone());
    eprintln!("tunnel_net_e2e scratch: {}", harness.scratch.display());

    let image = env_or(IMAGE_VAR, DEFAULT_IMAGE);
    let host = env_or(HOST_VAR, DEFAULT_HOST);
    let hypervisor = env_or(HYPERVISOR_VAR, DEFAULT_HYPERVISOR);
    let url = format!("https://{host}/");
    let vm_name = format!("mvm-tunnel-deny-{}", std::process::id());
    // No --allow-host: default-deny must drop egress. A successful fetch is a leak.
    let probe = format!(
        "set -u\n\
         if wget -q -O - {} >/dev/null 2>&1; then\n\
         \tprintf '{LEAK_MARKER}\\n'\n\
         \texit 1\n\
         fi\n\
         printf '{DENIED_MARKER}\\n'\n",
        shell_quote(&url),
    );

    let args = [
        "machine",
        "run",
        "--name",
        &vm_name,
        "--hypervisor",
        &hypervisor,
        "--profile",
        "dev",
        "--image",
        &image,
        "--timeout",
        "60",
        "--",
        "/bin/sh",
        "-c",
        &probe,
    ];
    let run = harness.run_mvmctl(&args, "machine-run-deny", RUN_BUDGET);
    harness.maybe_stop(&vm_name, &run);

    assert!(
        !run.timed_out,
        "deny tunnel smoke timed out after {RUN_BUDGET:?}; logs in {}\n{}",
        harness.scratch.display(),
        run.output
    );
    assert!(
        !run.output.contains(LEAK_MARKER),
        "egress leaked without an --allow-host grant; output:\n{}",
        run.output
    );
    assert!(
        run.output.contains(DENIED_MARKER),
        "guest probe did not report the expected denial; output:\n{}",
        run.output
    );
}
