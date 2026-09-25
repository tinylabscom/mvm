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
//! the exploit through admission, reading `/proc` — lives here. The decision
//! logic (what the host evidence means) lives in the crate library's
//! `containment` module, where the workspace test run exercises it without a
//! VM.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Output;

use cucumber::{given, then, when};
use mvm_conformance::IsolatedHome;
use mvm_conformance::containment::{self, HostObservation};
use sha2::{Digest, Sha256};

use crate::steps::cli::mvmctl_path;
use crate::steps::launch_e2e::e2e_home;
use crate::world::CliWorld;

const SIBLING_NAME: &str = "mvm-cve-bystander";
const VICTIM_NAME: &str = "mvm-cve-victim";
const CANARY_PREFIX: &str = "CVE-CANARY:";

/// Read a `pins.toml` value under `[section] key`, from the suite directory.
///
/// A tiny hand parser rather than pulling the whole TOML into a typed struct:
/// only two string values are read, and keeping the reader here means the pin
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
    // `isolated_home` moves HOME *and* MVM_HOME to the lab home and forwards the
    // toolchain root — the sanctioned helper. A raw `.env("HOME", …)` is
    // rejected by `isolate_home_tests::no_step_sets_home_without_the_isolation_helper`
    // and hides the Rust toolchain from a compiling child.
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

#[when("a sealed victim guest runs the exploit through admission")]
fn run_victim(world: &mut CliWorld) {
    let exploit = world
        .cve_exploit
        .clone()
        .expect("a Given step must stage the exploit before the victim runs");
    let image = exploit.to_string_lossy().into_owned();

    let _ = run_mvmctl(&["machine", "stop", VICTIM_NAME, "--yes"], &[]);
    let _ = run_mvmctl(&["machine", "rm", VICTIM_NAME, "--yes"], &[]);

    // The victim is the admitted `machine run` path: the exploit rides in the
    // image the plan admits — delivery is through admission by construction,
    // there is no host-to-guest side channel to smuggle it in on. The admitted
    // CLI boots MVM's own workload kernel; it has no flag to boot an arbitrary
    // distro vmlinux, which is exactly the "Known limit" the suite README
    // records. `MVM_BDD_CVE_KERNEL`, when set, is transcript context (which
    // kernel the operator intended), not a boot input this path can honor.
    if let Some(target) = std::env::var_os("MVM_BDD_CVE_KERNEL") {
        eprintln!(
            "[cve-containment] operator-noted target kernel: {}",
            PathBuf::from(target).display()
        );
    }
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

// --- Then -------------------------------------------------------------------

#[then("the guest-side compromise report is recorded as a candidate observation")]
fn canary_candidate_observation(world: &mut CliWorld) {
    let launch = world
        .cve_victim_launch
        .as_ref()
        .expect("the victim must have run");
    let combined = format!("{}\n{}", launch.stdout, launch.stderr);
    // A candidate observation, not an assertion: the verdict comes from host
    // evidence. We only surface what the guest claimed, so the transcript
    // records whether the in-guest PoC reported code execution on this kernel.
    let verdict = combined
        .lines()
        .find(|l| l.contains(CANARY_PREFIX))
        .map(str::trim)
        .unwrap_or("CVE-CANARY: (no guest canary observed)");
    eprintln!("[cve-containment] guest candidate observation: {verdict}");
}

#[then("no outbound connection was admitted from the victim guest")]
fn no_egress_admitted(_world: &mut CliWorld) {
    let verdict = containment::classify_egress(&audit_lines());
    assert!(
        verdict.contained(),
        "containment FAILED: the audit chain records admitted egress from the \
         victim guest:\n{}",
        verdict.admitted.join("\n")
    );
    eprintln!(
        "[cve-containment] egress contained: {} refusal(s), 0 admitted",
        verdict.refusals
    );
}

#[then("the audit chain verifies intact")]
fn audit_verifies_intact(_world: &mut CliWorld) {
    let out = run_mvmctl(&["trust", "audit", "verify"], &[]);
    assert!(
        out.status.success(),
        "the audit chain did not verify after the detonation\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
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
    for name in [SIBLING_NAME, VICTIM_NAME] {
        assert!(
            machine_dir(name).is_none(),
            "residue: {name} still has an on-host state directory after teardown"
        );
    }
    world.cve_sibling = None;
    world.cve_victim_name = None;
}
