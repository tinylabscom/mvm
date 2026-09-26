//! Steps for the `DestructiveLabOnly` CVE-2026-80521 containment scenario
//! (`features/suites/s37_cve_containment/`).
//!
//! The scenario detonates the real, public CVE-2026-80521 container-escape
//! proof-of-concept inside a sealed guest and asserts, from host evidence only,
//! that the guest-kernel compromise crosses no boundary. It runs only in a
//! throwaway lab: cucumber never reaches these steps unless the operator raised
//! the risk ceiling (`MVM_BDD_DESTRUCTIVE_LAB=1`) alongside the live and
//! Firecracker opt-ins, which is nowhere in CI (see `scenario_gate`).
//!
//! The privileged, unrepeatable work — booting guests, delivering and running
//! the exploit, reading `/proc` — lives here. The decision logic (what the host
//! evidence means) lives in the crate library's `containment` module, where the
//! workspace test run exercises it without a VM.
//!
//! Two boot modes, selected by the suite's `kernel.vmlinux_sha256` pin:
//!
//! * Pin empty — the admitted `mvmctl machine run` path boots the victim on
//!   MVM's own workload kernel and runs the exploit as the admitted image. The
//!   PoC does not target that kernel, so the guest canary is a candidate
//!   observation only.
//! * Pin set — the victim boots the pinned, digest-verified target kernel
//!   through the low-level Firecracker driver (`FcDriver::boot`), NIC-less and
//!   agentless, from the staged detonation initramfs. This boot deliberately
//!   bypasses admission — that is what the destructive-lab ceiling exists to
//!   fence — and the guest canary becomes load-bearing: booting the PoC's exact
//!   target kernel and not seeing the compromise report is a failed experiment,
//!   not a pass.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Output;

use cucumber::{given, then, when};
use mvm_conformance::IsolatedHome;
use mvm_conformance::containment::{self, HostObservation, VictimBoot};
use sha2::{Digest, Sha256};

use crate::steps::cli::mvmctl_path;
use crate::steps::launch_e2e::e2e_home;
use crate::world::CliWorld;

const SIBLING_NAME: &str = "mvm-cve-bystander";
const VICTIM_NAME: &str = "mvm-cve-victim";

/// How long the target-kernel detonation gets to print its exit marker before
/// the victim is torn down. The guest serves no agent and dials no host
/// channel, so the wait reconciles against the durable console log rather than
/// blocking on a guest event that can never arrive.
const DETONATION_TIMEOUT_SECS: u64 = 300;
/// Cadence of the console-log / VMM-liveness reconciliation poll.
const DETONATION_POLL_MS: u64 = 250;

/// Read a `pins.toml` value under `[section] key`, from the suite directory.
///
/// A tiny hand parser rather than pulling the whole TOML into a typed struct:
/// only a few string values are read, and keeping the reader here means the pin
/// file is documentation the scenario also enforces, not a schema to maintain.
fn pin(section: &str, key: &str) -> Option<String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("features/suites/s37_cve_containment/pins.toml");
    let text = std::fs::read_to_string(path).ok()?;
    let table: toml::Value = text.parse().ok()?;
    table.get(section)?.get(key)?.as_str().map(str::to_string)
}

/// Run `mvmctl` in the lab home, capturing its output.
fn run_mvmctl(argv: &[&str], extra_env: &[(&str, &str)]) -> Output {
    let mut cmd = crate::steps::cli::mvmctl_command();
    // `isolated_home` moves HOME and MVM_HOME to the lab home together and
    // forwards the toolchain root — the sanctioned helper. Setting the home
    // variable by hand is rejected by the isolation-helper test and hides the
    // Rust toolchain from a compiling child.
    cmd.isolated_home(e2e_home());
    for (key, value) in extra_env {
        cmd.env(key, value);
    }
    cmd.args(argv);
    cmd.output()
        .unwrap_or_else(|e| panic!("spawn mvmctl {argv:?}: {e}"))
}

/// The sha256 of a file, as lowercase hex.
fn file_digest(path: &Path) -> String {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    hex::encode(hasher.finalize())
}

/// A content digest over an entire directory tree: every file's relative path
/// and bytes folded into one hash, so any change to any file — or the set of
/// files — moves the digest. Used for the bystander guest's on-host state.
fn dir_digest(root: &Path) -> String {
    let mut entries: Vec<PathBuf> = Vec::new();
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(read) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in read.filter_map(Result::ok) {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else {
                out.push(path);
            }
        }
    }
    walk(root, &mut entries);
    entries.sort();
    let mut hasher = Sha256::new();
    for path in &entries {
        hasher.update(
            path.strip_prefix(root)
                .unwrap_or(path.as_path())
                .to_string_lossy()
                .as_bytes(),
        );
        hasher.update([0u8]);
        if let Ok(bytes) = std::fs::read(path) {
            hasher.update((bytes.len() as u64).to_le_bytes());
            hasher.update(&bytes);
        }
        hasher.update([0u8]);
    }
    hex::encode(hasher.finalize())
}

/// The set of host process identities, as `pid:comm`, from `/proc`.
fn host_procs() -> BTreeSet<String> {
    let mut procs = BTreeSet::new();
    let Ok(read) = std::fs::read_dir("/proc") else {
        return procs;
    };
    for entry in read.filter_map(Result::ok) {
        let name = entry.file_name();
        let Some(pid) = name.to_str() else { continue };
        if !pid.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let comm = std::fs::read_to_string(entry.path().join("comm"))
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        procs.insert(format!("{pid}:{comm}"));
    }
    procs
}

/// Listening TCP sockets, as `tcp:hexlocaladdr`, from `/proc/net/tcp{,6}`.
///
/// Reads the raw proc tables rather than shelling out to `ss`, so the probe has
/// no tool dependency. State `0A` is `TCP_LISTEN`; the second column is the
/// local address the kernel already renders as hex, which is a stable key
/// without needing to decode it.
fn host_listeners() -> BTreeSet<String> {
    let mut listeners = BTreeSet::new();
    for (proto, file) in [("tcp", "/proc/net/tcp"), ("tcp6", "/proc/net/tcp6")] {
        let Ok(table) = std::fs::read_to_string(file) else {
            continue;
        };
        for line in table.lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() > 3 && cols[3] == "0A" {
                listeners.insert(format!("{proto}:{}", cols[1]));
            }
        }
    }
    listeners
}

/// The narrow set of host paths a guest escape would be expected to reach: the
/// `mvmctl` binary that launched the guest, plus a sentinel file written for
/// this scenario. The claim is not "no host file changed" but "no host file the
/// boundary protects changed"; the sentinel is a canary an escape that writes
/// arbitrary host files would trip.
fn watched_host_files() -> BTreeMap<String, String> {
    let mut files = BTreeMap::new();
    let mvmctl = mvmctl_path();
    if mvmctl.is_file() {
        files.insert(mvmctl.to_string_lossy().into_owned(), file_digest(&mvmctl));
    }
    let sentinel =
        std::env::temp_dir().join(format!("mvm-cve-host-sentinel-{}", std::process::id()));
    if !sentinel.exists() {
        let _ = std::fs::write(
            &sentinel,
            b"host sentinel: an escape that writes host files trips this\n",
        );
    }
    if sentinel.is_file() {
        files.insert(
            sentinel.to_string_lossy().into_owned(),
            file_digest(&sentinel),
        );
    }
    files
}

/// Re-read a host observation over the same watched file set recorded before.
fn observe_over(previous: &HostObservation) -> HostObservation {
    let files = previous
        .files
        .keys()
        .filter_map(|path| {
            let p = Path::new(path);
            p.is_file().then(|| (path.clone(), file_digest(p)))
        })
        .collect();
    HostObservation {
        files,
        procs: host_procs(),
        listeners: host_listeners(),
    }
}

/// The lab home directory that holds every machine's state
/// (`<home>/vms/`), routed through `mvm-core::config` rather than rebuilt
/// inline, per the repo's path rule.
fn machine_state_root() -> PathBuf {
    mvm_core::config::vms_dir_at(e2e_home())
}

/// The on-host state directory for a machine by name, if it exists.
fn machine_dir(name: &str) -> Option<PathBuf> {
    let dir = mvm_core::config::vm_state_dir_at(e2e_home(), name);
    dir.is_dir().then_some(dir)
}

/// Every audit-chain line under the lab home, across tenants and segments.
fn audit_lines() -> Vec<String> {
    let audit_dir = e2e_home().join("audit");
    let mut lines = Vec::new();
    let Ok(read) = std::fs::read_dir(&audit_dir) else {
        return lines;
    };
    for entry in read.filter_map(Result::ok) {
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "jsonl")
            && let Ok(text) = std::fs::read_to_string(&path)
        {
            lines.extend(text.lines().map(str::to_string));
        }
    }
    lines
}

// --- Given ------------------------------------------------------------------

#[given("the host surface is recorded")]
fn record_host_surface(world: &mut CliWorld) {
    world.cve_host_before = Some(HostObservation {
        files: watched_host_files(),
        procs: host_procs(),
        listeners: host_listeners(),
    });
}

#[given("a bystander sibling guest is booted and its rootfs digest recorded")]
fn boot_sibling(world: &mut CliWorld) {
    // Remove any residue from an interrupted earlier run, then boot the
    // bystander as a persistent machine so it is live while the victim runs.
    let _ = run_mvmctl(&["machine", "stop", SIBLING_NAME, "--yes"], &[]);
    let _ = run_mvmctl(&["machine", "rm", SIBLING_NAME, "--yes"], &[]);
    let out = run_mvmctl(
        &["machine", "start", SIBLING_NAME, "--image", "alpine"],
        &[],
    );
    assert!(
        out.status.success(),
        "failed to boot the bystander sibling guest\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let dir = machine_dir(SIBLING_NAME).unwrap_or_else(|| {
        panic!(
            "the bystander guest booted but left no state directory under {}",
            machine_state_root().display()
        )
    });
    world.cve_sibling = Some((SIBLING_NAME.to_string(), dir_digest(&dir)));
}

#[given("the CVE-2026-80521 exploit is staged from its pinned source")]
fn stage_exploit(world: &mut CliWorld) {
    let staged = std::env::var_os("MVM_BDD_CVE_EXPLOIT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            panic!(
                "MVM_BDD_CVE_EXPLOIT is unset. This scenario detonates the real \
             CVE-2026-80521 exploit; stage it first with \
             scripts/stage-cve-2026-80521-lab.sh and export the produced \
             artifact path. See features/suites/s37_cve_containment/README.md."
            )
        });
    assert!(
        staged.is_file(),
        "MVM_BDD_CVE_EXPLOIT does not name a readable file: {}",
        staged.display()
    );
    let pinned = pin("exploit", "artifact_sha256").unwrap_or_default();
    assert!(
        !pinned.trim().is_empty(),
        "pins.toml exploit.artifact_sha256 is empty. Run the staging script \
         once, record the printed digest in the pin, and re-run — a detonation \
         artifact must be pinned before it is delivered."
    );
    let observed = file_digest(&staged);
    assert!(
        containment::digest_matches_pin(&pinned, &observed),
        "staged exploit artifact digest does not match the pin.\n  pinned:   {pinned}\n  observed: {observed}\n\
         Refusing to deliver an artifact that is not the reviewed one."
    );
    world.cve_exploit = Some(staged);
}

// --- When -------------------------------------------------------------------

/// Resolve the operator-supplied staged kernel into a digest-checked candidate.
/// Env access and file IO live here; the decision itself is
/// [`containment::resolve_victim_boot`].
fn staged_kernel_candidate() -> Option<containment::KernelCandidate> {
    let path = std::env::var_os("MVM_BDD_CVE_KERNEL").map(PathBuf::from)?;
    assert!(
        path.is_file(),
        "MVM_BDD_CVE_KERNEL does not name a readable file: {}",
        path.display()
    );
    let sha256 = file_digest(&path);
    Some(containment::KernelCandidate { path, sha256 })
}

/// The operator-supplied detonation initramfs, when staged.
fn staged_initramfs() -> Option<PathBuf> {
    let path = std::env::var_os("MVM_BDD_CVE_INITRAMFS").map(PathBuf::from)?;
    assert!(
        path.is_file(),
        "MVM_BDD_CVE_INITRAMFS does not name a readable file: {}",
        path.display()
    );
    Some(path)
}

#[when("a sealed victim guest runs the staged exploit")]
fn run_victim(world: &mut CliWorld) {
    let exploit = world
        .cve_exploit
        .clone()
        .expect("a Given step must stage the exploit before the victim runs");

    let vmlinux_pin = pin("kernel", "vmlinux_sha256").unwrap_or_default();
    let vmlinuz_pin = pin("kernel", "vmlinuz_sha256").unwrap_or_default();
    let backend = containment::VictimBackend::parse(
        &std::env::var("MVM_BDD_CVE_HYPERVISOR").unwrap_or_default(),
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let boot = containment::resolve_victim_boot(
        &vmlinux_pin,
        &vmlinuz_pin,
        staged_kernel_candidate(),
        staged_initramfs(),
        backend,
    )
    .unwrap_or_else(|e| panic!("{e}"));
    eprintln!(
        "[cve-containment] victim boot mode: {}",
        match &boot {
            containment::VictimBoot::Admitted => "admitted (mvmctl machine run)".to_string(),
            containment::VictimBoot::TargetKernel { backend, .. } => format!(
                "target kernel (low-level {} driver)",
                match backend {
                    containment::VictimBackend::Firecracker => "Firecracker",
                    containment::VictimBackend::Qemu => "QEMU/KVM",
                }
            ),
        }
    );

    let _ = run_mvmctl(&["machine", "stop", VICTIM_NAME, "--yes"], &[]);
    let _ = run_mvmctl(&["machine", "rm", VICTIM_NAME, "--yes"], &[]);

    match &boot {
        VictimBoot::Admitted => run_victim_admitted(world, &exploit),
        VictimBoot::TargetKernel {
            kernel,
            initramfs,
            backend,
        } => {
            run_victim_target_kernel(world, kernel, initramfs, *backend);
        }
    }
    world.cve_victim_boot = Some(boot);
}

/// The admitted victim boot: the exploit rides in the image the plan admits —
/// delivery is through admission by construction, there is no host-to-guest
/// side channel to smuggle it in on. The admitted CLI boots MVM's own workload
/// kernel; it has no flag to boot an arbitrary distro vmlinux, which is what
/// the `kernel.vmlinux_sha256` pin gates.
fn run_victim_admitted(world: &mut CliWorld, exploit: &Path) {
    let image = exploit.to_string_lossy().into_owned();
    let out = run_mvmctl(
        &[
            "machine",
            "run",
            "--name",
            VICTIM_NAME,
            "--image",
            image.as_str(),
        ],
        &[],
    );
    world.cve_victim_name = Some(VICTIM_NAME.to_string());
    world.cve_victim_launch = Some(crate::world::LaunchRecord {
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        exit_code: out.status.code().unwrap_or(-1),
        dispatch_window_ms: None,
        wall: std::time::Duration::default(),
    });
}

/// The pinned-kernel victim boot: the low-level driver boots the staged,
/// digest-verified target kernel on a staged initramfs that runs the exploit,
/// with no NIC, no vsock channels, and no admission machinery — the guest's
/// only observable output is its serial console, captured by the driver under
/// the victim's state dir. The backend is Firecracker by default; QEMU/KVM is
/// selectable for PoCs proven under QEMU (see the suite README's boot modes).
///
/// This boot bypasses admission on purpose: the admitted path cannot boot an
/// arbitrary kernel, and the destructive-lab risk ceiling is what fences the
/// consequence. Which assertions still bind this mode, and on what evidence,
/// is scoped in the suite README.
fn run_victim_target_kernel(
    world: &mut CliWorld,
    kernel: &Path,
    initramfs: &Path,
    backend: containment::VictimBackend,
) {
    use mvm_runtime::driver::{ConsoleCapture, KernelImage, RunningVm, VmmDriver, VmmSpec};

    // The driver resolves its state dir from the process MVM_HOME; hold it on
    // the lab home so the victim's state lands next to the sibling's and the
    // residue check observes the same tree the driver wrote.
    if world.mvm_home_guard.is_none() {
        world.mvm_home_guard = Some(crate::world::MvmHomeGuard::new(&e2e_home()));
    }
    let state_dir = mvm_core::config::vm_state_dir_at(e2e_home(), VICTIM_NAME);

    let spec = VmmSpec {
        name: VICTIM_NAME.to_string(),
        kernel: KernelImage::Path(kernel.to_path_buf()),
        initramfs: Some(initramfs.to_path_buf()),
        // Full kernel log rather than the driver's `quiet` default: a PoC
        // oops or panic on the console is itself transcript evidence.
        cmdline: "console=ttyS0 reboot=k panic=1 net.ifnames=0".to_string(),
        vcpus: 2,
        cpu_grant: None,
        // The PoC's reference VM is 2 CPUs / 4096 MB (its vm/config.env); its
        // direct-map refinement is calibrated to that physical map. With less
        // RAM the refinement finds no RAM run and every pc-hijack attempt
        // fails — observed on the first lab run at 1024 MiB.
        memory_mib: 4096,
        mem_initial_mib: None,
        // No block devices and no vsock channels: the guest's whole reachable
        // world is its initramfs, and its only host-visible channel is the
        // write-only console capture.
        blocks: vec![],
        vsock: vec![],
        console: ConsoleCapture {
            log_path: state_dir.join("console.log"),
        },
        shares: vec![],
        trusted_builder: false,
        builder_egress_endpoint: None,
        plan_binding: None,
    };
    eprintln!(
        "[cve-containment] booting victim on pinned target kernel {} (initramfs {})",
        kernel.display(),
        initramfs.display()
    );
    let vm: Box<dyn RunningVm> = match backend {
        containment::VictimBackend::Firecracker => {
            use mvm_runtime::driver::FcDriver;
            FcDriver::new().boot(&spec).unwrap_or_else(|e| {
                let console = state_dir.join("console.log");
                let log = std::fs::read_to_string(&console).unwrap_or_default();
                panic!("the target-kernel victim boot failed: {e:#}\n--- console.log ---\n{log}");
            })
        }
        containment::VictimBackend::Qemu => {
            use mvm_runtime::driver::QemuDriver;
            QemuDriver::new().boot(&spec).unwrap_or_else(|e| {
                let console = state_dir.join("console.log");
                let log = std::fs::read_to_string(&console).unwrap_or_default();
                panic!("the target-kernel victim boot failed: {e:#}\n--- console.log ---\n{log}");
            })
        }
    };
    let started = std::time::Instant::now();

    // Wait out the detonation. The guest serves no agent and dials no host
    // channel, so no completion event exists to block on; reconcile against
    // the console log's exit marker and the VMM's liveness at a bounded
    // cadence, then tear the guest down whether or not it finished.
    let console_log = state_dir.join("console.log");
    let deadline = started + std::time::Duration::from_secs(DETONATION_TIMEOUT_SECS);
    loop {
        let log = std::fs::read_to_string(&console_log).unwrap_or_default();
        let finished = log.contains(containment::EXIT_MARKER_PREFIX);
        let alive = matches!(vm.status(), Ok(mvm_core::vm_backend::VmStatus::Running));
        if finished || !alive || std::time::Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(DETONATION_POLL_MS));
    }
    // A detonated guest is never left running: a kill failure is a lab
    // emergency, not a soft error.
    if let Err(e) = vm.kill() {
        panic!("failed to stop the detonated victim guest '{VICTIM_NAME}': {e:#}");
    }

    let stdout = std::fs::read_to_string(&console_log).unwrap_or_default();
    // The VMM's own log: firecracker.log or qemu.log, whichever this backend
    // wrote (both drivers log under the victim's state dir).
    let stderr = ["firecracker.log", "qemu.log"]
        .iter()
        .find_map(|name| std::fs::read_to_string(state_dir.join(name)).ok())
        .unwrap_or_default();
    world.cve_victim_name = Some(VICTIM_NAME.to_string());
    world.cve_victim_launch = Some(crate::world::LaunchRecord {
        exit_code: containment::exit_marker_code(&stdout).unwrap_or(-1),
        stdout,
        stderr,
        dispatch_window_ms: None,
        wall: started.elapsed(),
    });
}

// --- Then -------------------------------------------------------------------

#[then("the guest-side compromise report is recorded as a candidate observation")]
fn canary_candidate_observation(world: &mut CliWorld) {
    let launch = world
        .cve_victim_launch
        .as_ref()
        .expect("the victim must have run");
    let combined = format!("{}\n{}", launch.stdout, launch.stderr);
    // The guest's claim is always surfaced, prominently — whether the in-guest
    // PoC reported code execution is the point of the run. What it *means*
    // depends on the boot mode, and the verdict still comes from host evidence.
    let canaries = containment::canary_lines(&combined);
    if canaries.is_empty() {
        eprintln!("[cve-containment] guest candidate observation: (no guest canary observed)");
    } else {
        for line in &canaries {
            eprintln!("[cve-containment] guest compromise report: {line}");
        }
    }

    let Some(boot) = &world.cve_victim_boot else {
        return;
    };
    if !boot.is_target_kernel() {
        return;
    }
    // The pinned-kernel witness contract: prove the booted kernel is the pinned
    // target (the initramfs's boot marker carries its `uname -r`), then fail —
    // not pass — when a detonation on the exact target kernel produced no
    // compromise canary.
    let target = pin("kernel", "target_version").unwrap_or_default();
    assert!(
        !target.trim().is_empty(),
        "pins.toml kernel.target_version is empty; the boot-marker check would \
         pass vacuously. Record the PoC's target kernel version in the pin."
    );
    containment::require_booted_kernel_matches_pin(&combined, &target)
        .unwrap_or_else(|e| panic!("{e}"));
    eprintln!("[cve-containment] booted kernel confirmed as the pinned target: {target}");
    containment::require_witnessed_compromise(boot, &combined).unwrap_or_else(|e| panic!("{e}"));
    eprintln!(
        "[cve-containment] witness contract met: the exploit reported compromise on the pinned target kernel"
    );
}

#[then("no outbound connection was admitted from the victim guest")]
fn no_egress_admitted(world: &mut CliWorld) {
    let verdict = containment::classify_egress(&audit_lines());
    assert!(
        verdict.contained(),
        "containment FAILED: the audit chain records admitted egress from the \
         victim guest:\n{}",
        verdict.admitted.join("\n")
    );
    let basis = world
        .cve_victim_boot
        .as_ref()
        .map_or(VictimBoot::Admitted, Clone::clone);
    eprintln!(
        "[cve-containment] egress contained: {} refusal(s), 0 admitted (evidence basis: {})",
        verdict.refusals,
        basis.egress_evidence()
    );
}

#[then("the audit chain verifies intact")]
fn audit_verifies_intact(world: &mut CliWorld) {
    let out = run_mvmctl(&["trust", "audit", "verify"], &[]);
    assert!(
        out.status.success(),
        "the audit chain did not verify after the detonation\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    if world
        .cve_victim_boot
        .as_ref()
        .is_some_and(VictimBoot::is_target_kernel)
    {
        eprintln!(
            "[cve-containment] note: the victim booted outside admission by design, so the \
             chain records no admission of it; this assertion is that the host's audit \
             chain itself survived the detonation intact"
        );
    }
}

#[then("the host surface is unchanged")]
fn host_surface_unchanged(world: &mut CliWorld) {
    let before = world
        .cve_host_before
        .as_ref()
        .expect("a Given step must record the host surface");
    let after = observe_over(before);
    let drift = before.drift(&after);
    assert!(
        drift.is_empty(),
        "containment FAILED: the host surface changed during the detonation:\n{}",
        drift.join("\n")
    );
}

#[then("the bystander sibling guest's rootfs digest is unchanged")]
fn sibling_digest_unchanged(world: &mut CliWorld) {
    let (name, before) = world
        .cve_sibling
        .clone()
        .expect("a Given step must record the sibling digest");
    let dir = machine_dir(&name)
        .unwrap_or_else(|| panic!("the bystander guest {name} vanished during the detonation"));
    let after = dir_digest(&dir);
    assert_eq!(
        before, after,
        "containment FAILED: the bystander sibling guest's on-host state changed"
    );
}

#[then("both guests are torn down and leave no residue")]
fn teardown_no_residue(world: &mut CliWorld) {
    for name in [SIBLING_NAME, VICTIM_NAME] {
        let _ = run_mvmctl(&["machine", "stop", name, "--yes"], &[]);
        let _ = run_mvmctl(&["machine", "rm", name, "--yes"], &[]);
    }
    if world
        .cve_victim_boot
        .as_ref()
        .is_some_and(VictimBoot::is_target_kernel)
    {
        // The low-level victim boot has no machine-registry entry for
        // `machine rm` to sweep; its state dir is the driver's own, removed
        // here once the guest is dead (the When step killed it and fails the
        // scenario otherwise).
        let dir = mvm_core::config::vm_state_dir_at(e2e_home(), VICTIM_NAME);
        if dir.exists() {
            std::fs::remove_dir_all(&dir).unwrap_or_else(|e| {
                panic!(
                    "remove the victim's driver state dir {}: {e}",
                    dir.display()
                )
            });
        }
    }
    for name in [SIBLING_NAME, VICTIM_NAME] {
        assert!(
            machine_dir(name).is_none(),
            "residue: {name} still has an on-host state directory after teardown"
        );
    }
    world.cve_sibling = None;
    world.cve_victim_name = None;
    world.cve_victim_boot = None;
}
