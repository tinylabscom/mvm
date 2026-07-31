//! Steps locking the README's user-facing contract to the real `mvmctl`
//! surface — the slice checkable without booting a builder VM or a microVM.
//! Live-boot behaviours (a guest booted to completion, the verified-boot tamper
//! panic, egress enforcement, vsock secret substitution) are proven by the
//! live-KVM smokes, not here.

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

use assert_cmd::cargo::CommandCargoExt;
use cucumber::{then, when};

use crate::world::CliWorld;

/// Repo root — two levels above this crate's manifest dir, resolved at compile
/// time so the run is independent of the process working directory.
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

/// A private, empty `MVM_HOME` for one invocation so a refusal scenario never
/// reads or writes the developer's real `~/.mvm`. Uniqueness comes from the pid
/// plus a monotonic counter, avoiding a temp-dir crate dependency.
fn isolated_mvm_home() -> PathBuf {
    static SEQ: AtomicU32 = AtomicU32::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("mvm-readme-contract-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create isolated MVM_HOME");
    dir
}

/// Spawn the built `mvmctl` binary with the given whitespace-split argv,
/// capturing its `Output`. Panics with an actionable hint if the binary is
/// missing, mirroring the sibling `cli` steps.
fn spawn_mvmctl(args: &str, home: Option<PathBuf>) -> std::process::Output {
    #[allow(deprecated)] // matches the sibling cli.rs use of this API
    let mut cmd = Command::cargo_bin("mvmctl").unwrap_or_else(|e| {
        panic!("mvmctl binary not found ({e}) — run `cargo build --bin mvmctl` before `just bdd`")
    });
    if let Some(home) = home {
        // Reconcile-on-entry converges live-VM state; disable it so a refusal
        // guard runs against a clean slate with no host side effects.
        cmd.env("HOME", &home)
            .env("MVM_HOME", &home)
            .env("MVM_SKIP_RECONCILE", "1");
    }
    cmd.args(args.split_whitespace())
        .output()
        .expect("failed to spawn mvmctl")
}

/// Run the real `mvmctl` against a private, empty `MVM_HOME` so the README's
/// documented refusal/exit-code contracts are exercised hermetically.
#[when(expr = "I run mvmctl in a clean home with {string}")]
fn run_mvmctl_clean_home(world: &mut CliWorld, args: String) {
    world.last_run = Some(spawn_mvmctl(&args, Some(isolated_mvm_home())));
}

/// Count the README's enumerated security claims: `N. **…` items inside the
/// `## Security model` section only, so an unrelated numbered list elsewhere
/// cannot inflate the count.
fn readme_enumerated_claims() -> usize {
    let readme = std::fs::read_to_string(repo_root().join("README.md")).expect("read README.md");
    let mut in_section = false;
    let mut count = 0;
    for line in readme.lines() {
        if line.starts_with("## Security model") {
            in_section = true;
            continue;
        }
        if in_section && line.starts_with("## ") {
            break;
        }
        if in_section && is_numbered_bold_item(line) {
            count += 1;
        }
    }
    count
}

/// A README claim item opens with `<int>. **`.
fn is_numbered_bold_item(line: &str) -> bool {
    match line.split_once(". ") {
        Some((lead, rest)) => {
            !lead.is_empty() && lead.chars().all(|c| c.is_ascii_digit()) && rest.starts_with("**")
        }
        None => false,
    }
}

/// Count the `Shipped` numbered rows in the conformance claim catalog embedded
/// in the security-posture ADR (the machine-checked claim -> witness table
/// between its begin/end markers).
fn catalog_shipped_claims() -> usize {
    const BEGIN: &str = "<!-- claims-catalog:begin -->";
    const END: &str = "<!-- claims-catalog:end -->";
    let adr =
        std::fs::read_to_string(repo_root().join("specs/adrs/001-microvm-security-posture.md"))
            .expect("read the security-posture ADR");
    let mut in_catalog = false;
    let mut count = 0;
    for line in adr.lines() {
        if line.contains(BEGIN) {
            in_catalog = true;
            continue;
        }
        if line.contains(END) {
            break;
        }
        if in_catalog && is_shipped_claim_row(line) {
            count += 1;
        }
    }
    count
}

/// A catalog table row for a numbered, `Shipped` claim: `| <int> | … | Shipped |`.
fn is_shipped_claim_row(line: &str) -> bool {
    let cells: Vec<&str> = line.split('|').map(str::trim).collect();
    let numbered = cells
        .get(1)
        .is_some_and(|c| !c.is_empty() && c.chars().all(|ch| ch.is_ascii_digit()));
    let shipped = cells
        .iter()
        .rev()
        .find(|c| !c.is_empty())
        .is_some_and(|c| *c == "Shipped");
    numbered && shipped
}

/// Cross-check: the README's enumerated claim count and the catalog's `Shipped`
/// claim count both equal the documented number. Locks the README summary to the
/// machine-checked ledger — either one drifting fails this step.
#[then(expr = "the README and the claim catalog agree on {int} numbered claims")]
fn readme_and_catalog_agree(_world: &mut CliWorld, expected: usize) {
    let readme = readme_enumerated_claims();
    let catalog = catalog_shipped_claims();
    assert_eq!(
        readme, expected,
        "README enumerates {readme} security claims, expected {expected}"
    );
    assert_eq!(
        catalog, expected,
        "conformance catalog lists {catalog} Shipped claims, expected {expected}"
    );
}
