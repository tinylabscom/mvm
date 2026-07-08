//! Gated live smoke for transparent guest networking over the vsock authority.
//!
//! This test is skipped by default. Set `MVM_TRANSPARENT_NET_SMOKE=1` on an
//! operator-approved host that can boot workload microVMs. The smoke drives the
//! public CLI path:
//!
//! `mvmctl machine run --image <image> --allow-host <host:port> -- <probe>`
//!
//! The probe uses ordinary in-guest DNS plus TCP (`wget`) so a passing run proves
//! the packaged guest bridge, host authority process, backend vsock relay, DNS
//! mapping, policy admission, and TCP byte forwarding are connected end to end.

#![cfg(unix)]

use assert_cmd::cargo::CommandCargoExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const ENABLE_VAR: &str = "MVM_TRANSPARENT_NET_SMOKE";
const IMAGE_VAR: &str = "MVM_TRANSPARENT_NET_IMAGE";
const HOST_VAR: &str = "MVM_TRANSPARENT_NET_HOST";
const PORT_VAR: &str = "MVM_TRANSPARENT_NET_PORT";
const URL_VAR: &str = "MVM_TRANSPARENT_NET_URL";
const EXPECT_VAR: &str = "MVM_TRANSPARENT_NET_EXPECT";
const HYPERVISOR_VAR: &str = "MVM_TRANSPARENT_NET_HYPERVISOR";
const SCRATCH_VAR: &str = "MVM_TRANSPARENT_NET_SCRATCH";
const DEADLINE_VAR: &str = "MVM_TRANSPARENT_NET_DEADLINE_SECS";
const DEFAULT_IMAGE: &str = "docker.io/library/alpine:3.20";
const DEFAULT_HOST: &str = "example.com";
const DEFAULT_PORT: &str = "80";
const DEFAULT_URL: &str = "http://example.com/";
const DEFAULT_EXPECT: &str = "Example Domain";
const DEFAULT_HYPERVISOR: &str = "hvf";
const RUN_BUDGET: Duration = Duration::from_secs(900);
const STOP_BUDGET: Duration = Duration::from_secs(90);

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
                std::env::temp_dir().join(format!("mvm-transparent-net-e2e-{}", std::process::id()))
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

    fn configure_env(&self, cmd: &mut Command) {
        let path = std::env::var("PATH").unwrap_or_default();
        cmd.env("PATH", format!("{}:{path}", self.target_dir.display()))
            .env("MVM_DATA_DIR", self.scratch.join(".mvm"))
            .env("MVM_STATE_DIR", self.scratch.join(".local/state/mvm"))
            .env("MVM_CONFIG_DIR", self.scratch.join(".config/mvm"))
            .env("MVM_SHARE_DIR", self.scratch.join(".local/share/mvm"))
            .env("MVM_CACHE_DIR", self.scratch.join(".cache/mvm"))
            .env_remove("XDG_STATE_HOME")
            .env_remove("XDG_DATA_HOME")
            .env_remove("XDG_CACHE_HOME")
            .env_remove("XDG_CONFIG_HOME");
        set_helper_override_if_present(
            cmd,
            "MVM_HVF_SUPERVISOR_PATH",
            &self.target_dir.join("mvm-hvf-supervisor"),
        );
        set_helper_override_if_present(
            cmd,
            "MVM_HOST_NETD_PATH",
            &self.target_dir.join("mvm-host-netd"),
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
            "transparent_net_e2e watchdog hit after {secs}s; logs are under {}",
            scratch.display()
        );
        std::process::exit(124);
    });
}

#[test]
fn transparent_net_smoke_gate_is_documented() {
    assert_eq!(ENABLE_VAR, "MVM_TRANSPARENT_NET_SMOKE");
    assert_eq!(IMAGE_VAR, "MVM_TRANSPARENT_NET_IMAGE");
    assert_eq!(HOST_VAR, "MVM_TRANSPARENT_NET_HOST");
    assert_eq!(PORT_VAR, "MVM_TRANSPARENT_NET_PORT");
}

#[test]
fn shell_quote_handles_single_quotes() {
    assert_eq!(shell_quote("can't"), "'can'\"'\"'t'");
}

#[test]
fn machine_run_allow_host_resolves_dns_and_fetches_http() {
    if !smoke_enabled() {
        eprintln!(
            "[transparent_net_e2e] skipped - set {ENABLE_VAR}=1 and run \
             `just e2e-transparent-net` on an operator-approved microVM host"
        );
        return;
    }

    let harness = SmokeHarness::new();
    arm_watchdog(harness.scratch.clone());
    eprintln!("transparent_net_e2e scratch: {}", harness.scratch.display());

    let image = std::env::var(IMAGE_VAR).unwrap_or_else(|_| DEFAULT_IMAGE.to_string());
    let host = std::env::var(HOST_VAR).unwrap_or_else(|_| DEFAULT_HOST.to_string());
    let port = std::env::var(PORT_VAR).unwrap_or_else(|_| DEFAULT_PORT.to_string());
    let url = std::env::var(URL_VAR).unwrap_or_else(|_| DEFAULT_URL.to_string());
    let expect = std::env::var(EXPECT_VAR).unwrap_or_else(|_| DEFAULT_EXPECT.to_string());
    let hypervisor =
        std::env::var(HYPERVISOR_VAR).unwrap_or_else(|_| DEFAULT_HYPERVISOR.to_string());
    let allow_host = format!("{host}:{port}");
    let vm_name = format!("mvm-net-smoke-{}", std::process::id());
    let probe = format!(
        "set -eu\n\
         body=$(wget -q -O - {})\n\
         printf '%s' \"$body\" | grep -qi {}\n\
         printf 'mvm-transparent-net-ok\\n'\n",
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
    let run = harness.run_mvmctl(&args, "machine-run", RUN_BUDGET);
    let _ = harness.run_mvmctl(
        &["machine", "stop", &vm_name, "--yes"],
        "machine-stop",
        STOP_BUDGET,
    );

    assert!(
        !run.timed_out,
        "transparent networking smoke timed out after {RUN_BUDGET:?}; logs in {}\n{}",
        harness.scratch.display(),
        run.output
    );
    assert!(
        run.success,
        "transparent networking smoke failed; logs in {}\n{}",
        harness.scratch.display(),
        run.output
    );
    assert!(
        run.output.contains("mvm-transparent-net-ok"),
        "guest probe did not report success; output:\n{}",
        run.output
    );
}
