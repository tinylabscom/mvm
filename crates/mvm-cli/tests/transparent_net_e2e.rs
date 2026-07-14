//! Gated live smoke for transparent guest networking over the vsock authority.
//!
//! This test is skipped by default. Set `MVM_TRANSPARENT_NET_SMOKE=1` on an
//! operator-approved host that can boot workload microVMs. The smoke drives the
//! public CLI path:
//!
//! `mvmctl machine run --image <image> --allow-host <host:port> -- <probe>`
//!
//! The probe uses ordinary in-guest DNS plus HTTPS (`wget`) so a passing run proves
//! the packaged guest bridge, host authority process, backend vsock relay, DNS
//! mapping, policy admission, TLS trust injection, and TCP byte forwarding are
//! connected end to end.

#![cfg(unix)]

use assert_cmd::cargo::CommandCargoExt;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

const ENABLE_VAR: &str = "MVM_TRANSPARENT_NET_SMOKE";
const IMAGE_VAR: &str = "MVM_TRANSPARENT_NET_IMAGE";
const HOST_VAR: &str = "MVM_TRANSPARENT_NET_HOST";
const PORT_VAR: &str = "MVM_TRANSPARENT_NET_PORT";
const PROFILE_VAR: &str = "MVM_TRANSPARENT_NET_PROFILE";
const URL_VAR: &str = "MVM_TRANSPARENT_NET_URL";
const EXPECT_VAR: &str = "MVM_TRANSPARENT_NET_EXPECT";
const ICMP_HOST_VAR: &str = "MVM_TRANSPARENT_NET_ICMP_HOST";
const HYPERVISOR_VAR: &str = "MVM_TRANSPARENT_NET_HYPERVISOR";
const SCRATCH_VAR: &str = "MVM_TRANSPARENT_NET_SCRATCH";
const DEADLINE_VAR: &str = "MVM_TRANSPARENT_NET_DEADLINE_SECS";
const KEEP_FAILED_VM_VAR: &str = "MVM_TRANSPARENT_NET_KEEP_FAILED_VM";
const DEFAULT_IMAGE: &str = "docker.io/library/alpine:3.20";
const DEFAULT_HOST: &str = "example.com";
const DEFAULT_PORT: &str = "443";
const DEFAULT_PROFILE: &str = "dev";
const DEFAULT_URL: &str = "https://example.com/";
const DEFAULT_EXPECT: &str = "Example Domain";
const DEFAULT_ICMP_HOST: &str = "one.one.one.one";
const DEFAULT_DENIED_URL: &str = "https://example.org/";
const DEFAULT_HYPERVISOR: &str = "hvf";
const RUN_BUDGET: Duration = Duration::from_secs(900);
const STOP_BUDGET: Duration = Duration::from_secs(90);
static LIVE_SMOKE_LOCK: Mutex<()> = Mutex::new(());

struct Step {
    success: bool,
    output: String,
    timed_out: bool,
}

struct SmokeHarness {
    scratch: PathBuf,
    target_dir: PathBuf,
    target_root: PathBuf,
}

impl SmokeHarness {
    fn new() -> Self {
        let scratch = std::env::var_os(SCRATCH_VAR)
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from("/tmp")
                    .join(format!("mvm-transparent-net-e2e-{}", std::process::id()))
            });
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(&scratch).expect("create scratch dir");
        let harness = Self {
            scratch,
            target_dir: target_dir_from_current_test(),
            target_root: target_root_from_current_test(),
        };
        harness.seed_cached_builder_kernel();
        harness
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
            .env("CARGO_TARGET_DIR", &self.target_root)
            .env("MVM_DATA_DIR", self.scratch.join(".mvm"))
            .env("MVM_STATE_DIR", self.scratch.join(".local/state/mvm"))
            .env("MVM_CONFIG_DIR", self.scratch.join(".config/mvm"))
            .env("MVM_SHARE_DIR", self.scratch.join(".local/share/mvm"))
            .env("MVM_CACHE_DIR", self.scratch.join(".cache/mvm"))
            .env_remove("XDG_STATE_HOME")
            .env_remove("XDG_DATA_HOME")
            .env_remove("XDG_CACHE_HOME")
            .env_remove("XDG_CONFIG_HOME");
    }

    fn seed_cached_builder_kernel(&self) {
        let source = PathBuf::from(mvm_core::config::mvm_cache_dir())
            .join("builder-vm")
            .join(host_arch())
            .join("vmlinux");
        if !source.is_file() {
            return;
        }
        let dest = self
            .scratch
            .join(".cache/mvm")
            .join("builder-vm")
            .join(host_arch())
            .join("vmlinux");
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).expect("create builder-kernel scratch cache");
        }
        std::fs::copy(&source, &dest).expect("seed cached builder kernel into scratch cache");
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

fn target_root_from_current_test() -> PathBuf {
    target_dir_from_current_test()
        .parent()
        .expect("target root dir")
        .to_path_buf()
}

fn host_arch() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "x86_64"
    }
}

fn smoke_enabled() -> bool {
    std::env::var(ENABLE_VAR).as_deref() == Ok("1")
}

fn acquire_live_smoke_lock() -> MutexGuard<'static, ()> {
    // The live smoke tests all exercise the same operator host and, when
    // enabled, often the same explicit scratch root. Serialize them so they
    // don't race over the OCI cache, partial unpack trees, or retained logs.
    match LIVE_SMOKE_LOCK.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn keep_failed_vm() -> bool {
    std::env::var(KEEP_FAILED_VM_VAR).as_deref() == Ok("1")
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn denied_probe(url: &str) -> String {
    format!(
        "set -eu\n\
         if wget -q -O - {} >/dev/null 2>&1; then\n\
           echo 'unexpected network success' >&2\n\
           exit 1\n\
         fi\n\
         printf 'mvm-transparent-net-denied-ok\\n'\n",
        shell_quote(url),
    )
}

fn denied_ping_probe(host: &str) -> String {
    format!(
        "set -eu\n\
         if ping -c 1 -W 1 {} >/dev/null 2>&1; then\n\
           echo 'unexpected icmp success' >&2\n\
           exit 1\n\
         fi\n\
         printf 'mvm-transparent-net-icmp-denied-ok\\n'\n",
        shell_quote(host),
    )
}

struct SmokeCase<'a> {
    label: &'a str,
    allow_host: Option<&'a str>,
    probe: String,
}

fn run_case(harness: &SmokeHarness, case: SmokeCase<'_>) -> Step {
    let image = std::env::var(IMAGE_VAR).unwrap_or_else(|_| DEFAULT_IMAGE.to_string());
    let profile = std::env::var(PROFILE_VAR).unwrap_or_else(|_| DEFAULT_PROFILE.to_string());
    let hypervisor =
        std::env::var(HYPERVISOR_VAR).unwrap_or_else(|_| DEFAULT_HYPERVISOR.to_string());
    let vm_name = format!("mvm-net-{}-{}", case.label, std::process::id());

    let mut args = vec![
        "machine",
        "run",
        "--name",
        &vm_name,
        "--hypervisor",
        &hypervisor,
        "--profile",
        &profile,
        "--image",
        &image,
    ];
    if let Some(allow_host) = case.allow_host {
        args.push("--allow-host");
        args.push(allow_host);
    }
    args.extend_from_slice(&["--timeout", "90", "--", "/bin/sh", "-c", &case.probe]);

    let run = harness.run_mvmctl(&args, case.label, RUN_BUDGET);
    if keep_failed_vm() && (!run.success || run.timed_out) {
        eprintln!(
            "transparent_net_e2e keeping failed VM {vm_name} for inspection; scratch: {}",
            harness.scratch.display()
        );
    } else {
        let _ = harness.run_mvmctl(
            &["machine", "stop", &vm_name, "--yes"],
            &format!("{}-stop", case.label),
            STOP_BUDGET,
        );
    }
    run
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
    assert_eq!(PROFILE_VAR, "MVM_TRANSPARENT_NET_PROFILE");
    assert_eq!(ICMP_HOST_VAR, "MVM_TRANSPARENT_NET_ICMP_HOST");
    assert_eq!(KEEP_FAILED_VM_VAR, "MVM_TRANSPARENT_NET_KEEP_FAILED_VM");
}

#[test]
fn shell_quote_handles_single_quotes() {
    assert_eq!(shell_quote("can't"), "'can'\"'\"'t'");
}

#[test]
fn machine_run_allow_host_resolves_dns_and_fetches_https() {
    if !smoke_enabled() {
        eprintln!(
            "[transparent_net_e2e] skipped - set {ENABLE_VAR}=1 and run \
             `just e2e-transparent-net` on an operator-approved microVM host"
        );
        return;
    }

    let _exclusive = acquire_live_smoke_lock();
    let harness = SmokeHarness::new();
    arm_watchdog(harness.scratch.clone());
    eprintln!("transparent_net_e2e scratch: {}", harness.scratch.display());

    let host = std::env::var(HOST_VAR).unwrap_or_else(|_| DEFAULT_HOST.to_string());
    let port = std::env::var(PORT_VAR).unwrap_or_else(|_| DEFAULT_PORT.to_string());
    let url = std::env::var(URL_VAR).unwrap_or_else(|_| DEFAULT_URL.to_string());
    let expect = std::env::var(EXPECT_VAR).unwrap_or_else(|_| DEFAULT_EXPECT.to_string());
    let allow_host = format!("{host}:{port}");
    let probe = format!(
        "set -eu\n\
         body=$(wget -q -O - {})\n\
         printf '%s' \"$body\" | grep -qi {}\n\
         printf 'mvm-transparent-net-ok\\n'\n",
        shell_quote(&url),
        shell_quote(&expect),
    );

    let run = run_case(
        &harness,
        SmokeCase {
            label: "allow-host",
            allow_host: Some(&allow_host),
            probe,
        },
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

#[test]
fn machine_run_without_network_grant_cannot_fetch_https() {
    if !smoke_enabled() {
        eprintln!(
            "[transparent_net_e2e] skipped - set {ENABLE_VAR}=1 and run \
             `just e2e-transparent-net` on an operator-approved microVM host"
        );
        return;
    }

    let _exclusive = acquire_live_smoke_lock();
    let harness = SmokeHarness::new();
    arm_watchdog(harness.scratch.clone());
    eprintln!("transparent_net_e2e scratch: {}", harness.scratch.display());

    let url = std::env::var(URL_VAR).unwrap_or_else(|_| DEFAULT_URL.to_string());
    let run = run_case(
        &harness,
        SmokeCase {
            label: "no-network",
            allow_host: None,
            probe: denied_probe(&url),
        },
    );

    assert!(
        !run.timed_out,
        "transparent networking no-network smoke timed out after {RUN_BUDGET:?}; logs in {}\n{}",
        harness.scratch.display(),
        run.output
    );
    assert!(
        run.success,
        "transparent networking no-network smoke failed; logs in {}\n{}",
        harness.scratch.display(),
        run.output
    );
    assert!(
        run.output.contains("mvm-transparent-net-denied-ok"),
        "guest probe did not report denied success; output:\n{}",
        run.output
    );
}

#[test]
fn machine_run_allow_host_denies_other_https_hosts() {
    if !smoke_enabled() {
        eprintln!(
            "[transparent_net_e2e] skipped - set {ENABLE_VAR}=1 and run \
             `just e2e-transparent-net` on an operator-approved microVM host"
        );
        return;
    }

    let _exclusive = acquire_live_smoke_lock();
    let harness = SmokeHarness::new();
    arm_watchdog(harness.scratch.clone());
    eprintln!("transparent_net_e2e scratch: {}", harness.scratch.display());

    let host = std::env::var(HOST_VAR).unwrap_or_else(|_| DEFAULT_HOST.to_string());
    let port = std::env::var(PORT_VAR).unwrap_or_else(|_| DEFAULT_PORT.to_string());
    let allow_host = format!("{host}:{port}");
    let run = run_case(
        &harness,
        SmokeCase {
            label: "deny-other-host",
            allow_host: Some(&allow_host),
            probe: denied_probe(DEFAULT_DENIED_URL),
        },
    );

    assert!(
        !run.timed_out,
        "transparent networking denied-host smoke timed out after {RUN_BUDGET:?}; logs in {}\n{}",
        harness.scratch.display(),
        run.output
    );
    assert!(
        run.success,
        "transparent networking denied-host smoke failed; logs in {}\n{}",
        harness.scratch.display(),
        run.output
    );
    assert!(
        run.output.contains("mvm-transparent-net-denied-ok"),
        "guest probe did not report denied-host success; output:\n{}",
        run.output
    );
}

#[test]
fn machine_run_allow_host_replies_to_icmp_echo() {
    if !smoke_enabled() {
        eprintln!(
            "[transparent_net_e2e] skipped - set {ENABLE_VAR}=1 and run \
             `just e2e-transparent-net` on an operator-approved microVM host"
        );
        return;
    }

    let _exclusive = acquire_live_smoke_lock();
    let harness = SmokeHarness::new();
    arm_watchdog(harness.scratch.clone());
    eprintln!("transparent_net_e2e scratch: {}", harness.scratch.display());

    let host = std::env::var(ICMP_HOST_VAR).unwrap_or_else(|_| DEFAULT_ICMP_HOST.to_string());
    let allow_host = format!("{host}:443");
    let probe = format!(
        "set -eu\n\
         ping -c 1 -W 1 {}\n\
         printf 'mvm-transparent-net-icmp-ok\\n'\n",
        shell_quote(&host),
    );

    let run = run_case(
        &harness,
        SmokeCase {
            label: "allow-icmp",
            allow_host: Some(&allow_host),
            probe,
        },
    );

    assert!(
        !run.timed_out,
        "transparent networking ICMP smoke timed out after {RUN_BUDGET:?}; logs in {}\n{}",
        harness.scratch.display(),
        run.output
    );
    assert!(
        run.success,
        "transparent networking ICMP smoke failed; logs in {}\n{}",
        harness.scratch.display(),
        run.output
    );
    assert!(
        run.output.contains("mvm-transparent-net-icmp-ok"),
        "guest probe did not report ICMP success; output:\n{}",
        run.output
    );
}

#[test]
fn machine_run_without_network_grant_cannot_ping() {
    if !smoke_enabled() {
        eprintln!(
            "[transparent_net_e2e] skipped - set {ENABLE_VAR}=1 and run \
             `just e2e-transparent-net` on an operator-approved microVM host"
        );
        return;
    }

    let _exclusive = acquire_live_smoke_lock();
    let harness = SmokeHarness::new();
    arm_watchdog(harness.scratch.clone());
    eprintln!("transparent_net_e2e scratch: {}", harness.scratch.display());

    let host = std::env::var(ICMP_HOST_VAR).unwrap_or_else(|_| DEFAULT_ICMP_HOST.to_string());
    let run = run_case(
        &harness,
        SmokeCase {
            label: "no-network-icmp",
            allow_host: None,
            probe: denied_ping_probe(&host),
        },
    );

    assert!(
        !run.timed_out,
        "transparent networking no-network ICMP smoke timed out after {RUN_BUDGET:?}; logs in {}\n{}",
        harness.scratch.display(),
        run.output
    );
    assert!(
        run.success,
        "transparent networking no-network ICMP smoke failed; logs in {}\n{}",
        harness.scratch.display(),
        run.output
    );
    assert!(
        run.output.contains("mvm-transparent-net-icmp-denied-ok"),
        "guest probe did not report denied ICMP success; output:\n{}",
        run.output
    );
}
