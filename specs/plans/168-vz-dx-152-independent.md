# Plan 168 — VZ DX layer (Plan-152-independent slice) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps
> use checkbox (`- [ ]`) syntax for tracking.
>
> **Design source:** `specs/notes/plan-159-dx-152-independent-slice-design.md`.
> **Parent plan:** `specs/plans/159-vz-inspired-macos-dx.md` (this is the
> 152-independent subset of S5 in `specs/plans/163-...`).

**Goal:** Ship the four Plan 159 DX features that need nothing from the
Plan 152 Rust supervisor — `mvmctl sign` (WS-3), session resume
ergonomics (WS-5 B), a shared `--json` helper + coverage (WS-5 C), and
resumable/honest-cost acquisition (WS-4).

**Architecture:** Pure host-side/CLI work. New CLI verb `mvmctl sign`
wraps a small public signing API added to `mvm-backend`; resume flags
extend the existing `session` construct and a new serde-default
`SessionRecord.ephemeral` field; a one-line `emit_json` helper unifies
JSON output; resumable downloads add curl's native `-C -` to the existing
hash-gated fetch. No guest-protocol change, no verb renames.

**Tech Stack:** Rust, clap (derive), anyhow, serde/serde_json, sha2,
codesign/curl subprocesses, `assert_cmd` for CLI integration tests,
`cargo nextest`.

---

## Guardrails (apply to every task)

- Never regress claims 1–14; no SSH; no in-guest agent injection.
- The claim-6 SHA-256 gate (`verify_artifact_hash`) and the
  `MVM_SKIP_HASH_VERIFY` escape hatch are **unchanged** by WS-4.
- Single-tenant invariant: one-shot `run`/`up` stay ephemeral and are
  **not** resumable; resume applies only to `session`.
- `cargo fmt` is CI-nightly: run `rustup run nightly cargo fmt --all`
  before each commit (see `reference_ci_lint_uses_nightly_rustfmt`).
- Per-task gate before commit:
  `cargo nextest run -p mvm-cli -p mvm-backend -p mvm-core` (scope to the
  crate(s) you touched) — `mvm-backend` test bins can be
  codesign-SIGKILL'd on this macOS host
  (`reference_mvm_backend_test_binary_macos_codesign_sigkill`); if so, run
  that crate's tests on Linux CI and proceed.
- Never run `core_demo_e2e` unbounded.

## File Structure

Created:

- `crates/mvm-cli/src/json_out.rs` — `emit_json` helper (WS-5 C).
- `crates/mvm-cli/src/commands/env/sign.rs` — `mvmctl sign` handler (WS-3).
- `crates/mvm-cli/tests/sign_cli.rs` — `mvmctl sign` surface tests (WS-3).

Modified:

- `crates/mvm-backend/src/providers/apple_container/mod.rs` — public
  `SignReport`, `sign_binaries`, `collect_sign_targets`,
  `entitlements_present` (WS-3).
- `crates/mvm-backend/src/providers/apple_container/macos.rs` — macOS
  helpers behind the new public API (WS-3).
- `crates/mvm-backend/src/vz.rs`, `.../libkrun.rs` — bump
  `resolve_supervisor_path` to `pub(crate)` (WS-3).
- `crates/mvm-cli/src/commands/mod.rs` — `Sign` variant + dispatch (WS-3).
- `crates/mvm-cli/src/commands/cmd_audit.rs` — `Sign` verb name (WS-3).
- `crates/mvm-cli/src/commands/env/mod.rs` — `mod sign;` (WS-3).
- `crates/mvm-cli/tests/audit_total_coverage.rs` — `sign` posture row (WS-3).
- `crates/mvm-cli/src/doctor.rs` — `signing` security check (WS-3).
- `crates/mvm-cli/src/lib.rs` — `pub mod json_out;` (WS-5 C).
- `crates/mvm-cli/src/commands/image.rs`, `.../vm/ps.rs`,
  `.../vm/sandbox.rs` — migrate inline JSON to `emit_json` (WS-5 C).
- `crates/mvm-cli/src/commands/ops/network.rs`,
  `.../vm/pause.rs` (snapshot ls), `.../ops/cache.rs`,
  `.../ops/audit.rs` — add `--json` via `emit_json` (WS-5 C).
- `crates/mvm-cli/src/commands/vm/session.rs` — resume flags + ephemeral
  teardown + most-recent helper (WS-5 B).
- `crates/mvm-core/src/domain/session.rs` — `ephemeral` field +
  `most_recent_running` (WS-5 B).
- `crates/mvm-cli/src/commands/env/artifact_verify.rs` — curl `-C -`
  resume + factored arg builder (WS-4).
- `crates/mvm-cli/src/commands/env/apple_container.rs` — honest-cost
  framing (WS-4).

---

# Phase 1 — WS-3: `mvmctl sign` + doctor signing status

### Task 1.1: Public signing API in mvm-backend (`SignReport`, `entitlements_present`)

**Files:**
- Modify: `crates/mvm-backend/src/providers/apple_container/mod.rs`
- Modify: `crates/mvm-backend/src/providers/apple_container/macos.rs`
- Test: `crates/mvm-backend/src/providers/apple_container/mod.rs` (inline `#[cfg(test)]`)

- [ ] **Step 1: Write the failing test** (append to `apple_container/mod.rs`)

```rust
#[cfg(test)]
mod sign_api_tests {
    use super::*;

    #[test]
    fn sign_report_is_serializable() {
        let r = SignReport {
            path: std::path::PathBuf::from("/tmp/mvmctl"),
            applied: true,
            entitlements_present: true,
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"applied\":true"));
        assert!(json.contains("entitlements_present"));
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn entitlements_present_is_none_off_macos() {
        assert!(entitlements_present(std::path::Path::new("/bin/sh")).is_none());
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn sign_binaries_is_noop_off_macos() {
        let targets = vec![std::path::PathBuf::from("/bin/sh")];
        assert!(sign_binaries(&targets).is_empty());
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo nextest run -p mvm-backend sign_api_tests`
Expected: FAIL — `SignReport`, `entitlements_present`, `sign_binaries` not found.

- [ ] **Step 3: Add the public API** (in `apple_container/mod.rs`, near the existing `pub fn ensure_signed()` at line ~108)

```rust
use std::path::{Path, PathBuf};

/// Outcome of attempting to sign one binary.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SignReport {
    pub path: PathBuf,
    /// Whether codesign was (re)applied during this call.
    pub applied: bool,
    /// Whether both VZ + Hypervisor entitlements are present after.
    pub entitlements_present: bool,
}

/// `Some(true/false)` on macOS (both required entitlements present?),
/// `None` on platforms where the question is meaningless.
pub fn entitlements_present(path: &Path) -> Option<bool> {
    #[cfg(target_os = "macos")]
    {
        Some(macos::entitlements_present(path))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = path;
        None
    }
}

/// Ad-hoc re-sign each target with the VZ + Hypervisor entitlements and
/// report the post-sign state. No-op (empty) off macOS.
pub fn sign_binaries(targets: &[PathBuf]) -> Vec<SignReport> {
    #[cfg(target_os = "macos")]
    {
        targets.iter().map(|p| macos::sign_path(p)).collect()
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = targets;
        Vec::new()
    }
}
```

- [ ] **Step 4: Add the macOS helpers** (in `macos.rs`; reuse `sign_binary` + `ENTITLEMENTS_PLIST`)

```rust
/// Read the binary's entitlements XML via codesign.
fn read_entitlements_xml(path: &std::path::Path) -> Option<String> {
    let out = std::process::Command::new("codesign")
        .args(["-d", "--entitlements", "-", "--xml"])
        .arg(path)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// True only when BOTH the virtualization and hypervisor entitlements
/// are present (the launch path requires both — see `ensure_signed`).
pub(super) fn entitlements_present(path: &std::path::Path) -> bool {
    match read_entitlements_xml(path) {
        Some(xml) => {
            xml.contains("com.apple.security.virtualization")
                && xml.contains("com.apple.security.hypervisor")
        }
        None => false,
    }
}

/// Sign `path` ad-hoc with both entitlements and report the result.
pub(super) fn sign_path(path: &std::path::Path) -> super::SignReport {
    let already = entitlements_present(path);
    if !already {
        sign_binary(&path.to_string_lossy());
    }
    super::SignReport {
        path: path.to_path_buf(),
        applied: !already,
        entitlements_present: entitlements_present(path),
    }
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo nextest run -p mvm-backend sign_api_tests`
Expected: PASS (on macOS run all three; on Linux the two `not(macos)` tests + the serialize test pass).

- [ ] **Step 6: Commit**

```bash
rustup run nightly cargo fmt --all
git add crates/mvm-backend/src/providers/apple_container/
git commit -m "feat(mvm-backend): public sign_binaries/entitlements_present API"
```

### Task 1.2: Aggregate signable targets

**Files:**
- Modify: `crates/mvm-backend/src/providers/apple_container/mod.rs`
- Modify: `crates/mvm-backend/src/vz.rs` (make `resolve_supervisor_path` `pub(crate)`)
- Modify: `crates/mvm-backend/src/libkrun.rs` (same)
- Test: `crates/mvm-backend/src/providers/apple_container/mod.rs`

- [ ] **Step 1: Write the failing test** (append to `sign_api_tests`)

```rust
    #[test]
    fn collect_sign_targets_includes_current_exe() {
        let targets = collect_sign_targets();
        let exe = std::env::current_exe().unwrap();
        assert!(targets.contains(&exe), "targets must include the running exe");
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo nextest run -p mvm-backend collect_sign_targets_includes_current_exe`
Expected: FAIL — `collect_sign_targets` not found.

- [ ] **Step 3: Bump resolver visibility**

In `crates/mvm-backend/src/vz.rs` change `fn resolve_supervisor_path()` to `pub(crate) fn resolve_supervisor_path()`. Do the same in `crates/mvm-backend/src/libkrun.rs`.

- [ ] **Step 4: Add the aggregator** (in `apple_container/mod.rs`)

```rust
/// The binaries that need VZ/Hypervisor entitlements to launch a VM:
/// the running CLI plus whichever supervisors resolve on this host.
/// Unresolved supervisors are silently skipped (a host may have only
/// one backend installed).
pub fn collect_sign_targets() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        out.push(exe);
    }
    if let Ok(p) = crate::vz::resolve_supervisor_path() {
        out.push(p);
    }
    if let Ok(p) = crate::libkrun::resolve_supervisor_path() {
        out.push(p);
    }
    out.dedup();
    out
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cargo nextest run -p mvm-backend collect_sign_targets_includes_current_exe`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
rustup run nightly cargo fmt --all
git add crates/mvm-backend/
git commit -m "feat(mvm-backend): collect_sign_targets aggregator"
```

### Task 1.3: `mvmctl sign` command handler

**Files:**
- Create: `crates/mvm-cli/src/commands/env/sign.rs`
- Modify: `crates/mvm-cli/src/commands/env/mod.rs`
- Modify: `crates/mvm-cli/src/commands/mod.rs`
- Modify: `crates/mvm-cli/src/commands/cmd_audit.rs`
- Modify: `crates/mvm-cli/tests/audit_total_coverage.rs`

- [ ] **Step 1: Create the handler** `crates/mvm-cli/src/commands/env/sign.rs`

```rust
//! `mvmctl sign` — re-sign mvmctl + supervisor binaries with the
//! VZ/Hypervisor entitlements (user-facing repair of the auto-sign
//! path). macOS-only; a no-op on other platforms.

use anyhow::Result;
use clap::Args as ClapArgs;

use mvm_core::user_config::MvmConfig;

use super::Cli;
use crate::ui;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    if !cfg!(target_os = "macos") {
        if args.json {
            crate::json_out::emit_json(&serde_json::json!({"platform": "non-macos", "signed": []}))?;
        } else {
            ui::info("mvmctl sign is macOS-only (codesign entitlements); nothing to do here.");
        }
        return Ok(());
    }

    let targets = mvm_backend::providers::apple_container::collect_sign_targets();
    let reports = mvm_backend::providers::apple_container::sign_binaries(&targets);

    if args.json {
        crate::json_out::emit_json(&reports)?;
        return Ok(());
    }

    for r in &reports {
        let verb = if r.applied { "signed" } else { "already signed" };
        let mark = if r.entitlements_present { "✓" } else { "✗" };
        ui::status_line(
            &format!("  {} {}:", mark, r.path.display()),
            verb,
        );
    }
    if reports.iter().all(|r| r.entitlements_present) {
        ui::success("All binaries carry the VZ + Hypervisor entitlements.");
        Ok(())
    } else {
        anyhow::bail!("one or more binaries failed to acquire both entitlements");
    }
}
```

- [ ] **Step 2: Declare the module** — add to `crates/mvm-cli/src/commands/env/mod.rs` next to the existing `doctor` declaration:

```rust
pub(in crate::commands) mod sign;
```

- [ ] **Step 3: Wire the enum variant** — in `crates/mvm-cli/src/commands/mod.rs`, add after the `Doctor` variant (~line 78):

```rust
    /// Re-sign mvmctl + supervisors with VZ entitlements (macOS)
    Sign(env::sign::Args),
```

- [ ] **Step 4: Wire the dispatch arm** — in the `match cli.command.clone()` (~line 289, after `Commands::Doctor`):

```rust
        Commands::Sign(a) => env::sign::run(&cli, a, &cfg),
```

- [ ] **Step 5: Wire the verb name** — in `crates/mvm-cli/src/commands/cmd_audit.rs` `verb_name()` (after the `Doctor` arm ~line 150):

```rust
            Commands::Sign(_) => "sign",
```

- [ ] **Step 6: Add the audit-posture row** — in `crates/mvm-cli/tests/audit_total_coverage.rs`, add `"sign"` to the AUDIT_POSTURE table following the existing `"doctor"` entry's shape (read-only diagnostic verb, same posture class as `doctor`).

- [ ] **Step 7: Build to verify it compiles**

Run: `cargo build -p mvm-cli`
Expected: builds; `mvmctl sign --help` lists `--json`.

- [ ] **Step 8: Commit**

```bash
rustup run nightly cargo fmt --all
git add crates/mvm-cli/
git commit -m "feat(mvm-cli): mvmctl sign command"
```

### Task 1.4: `mvmctl sign` surface test

**Files:**
- Create: `crates/mvm-cli/tests/sign_cli.rs`

- [ ] **Step 1: Write the test**

```rust
//! CLI surface tests for `mvmctl sign`.

use assert_cmd::cargo::CommandCargoExt;
use std::process::Command;

fn mvmctl(args: &[&str]) -> std::process::Output {
    #[allow(deprecated)]
    Command::cargo_bin("mvmctl")
        .expect("locate mvmctl")
        .args(args)
        .output()
        .expect("spawn mvmctl")
}

#[test]
fn sign_help_lists_json_flag() {
    let out = mvmctl(&["sign", "--help"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stderr:\n{}", String::from_utf8_lossy(&out.stderr));
    assert!(stdout.contains("--json"), "`mvmctl sign --help` missing --json; got:\n{stdout}");
}

#[cfg(not(target_os = "macos"))]
#[test]
fn sign_is_noop_off_macos() {
    let out = mvmctl(&["sign"]);
    assert!(out.status.success(), "sign should be a successful no-op off macOS");
}
```

- [ ] **Step 2: Run to verify**

Run: `cargo nextest run -p mvm-cli --test sign_cli`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add crates/mvm-cli/tests/sign_cli.rs
git commit -m "test(mvm-cli): mvmctl sign surface tests"
```

### Task 1.5: Doctor `signing` security check

**Files:**
- Modify: `crates/mvm-cli/src/doctor.rs`

- [ ] **Step 1: Write the failing test** (append to `doctor.rs`'s `#[cfg(test)] mod tests`, or add one)

```rust
#[test]
fn signing_check_is_in_security_category() {
    let c = security_signing_check();
    assert_eq!(c.category, "security");
    assert_eq!(c.name, "signing");
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo nextest run -p mvm-cli signing_check_is_in_security_category`
Expected: FAIL — `security_signing_check` not found.

- [ ] **Step 3: Implement the check** (in `doctor.rs`, near the other `security_*_check` fns)

```rust
fn security_signing_check() -> Check {
    // macOS-only: VM launch needs the VZ + Hypervisor entitlements on
    // the running binary. Off macOS the question is n/a.
    let exe = std::env::current_exe().ok();
    let present = exe
        .as_deref()
        .and_then(mvm_backend::providers::apple_container::entitlements_present);
    match present {
        None => Check {
            name: "signing",
            category: "security",
            ok: true,
            info: "n/a (macOS only)".to_string(),
        },
        Some(true) => Check {
            name: "signing",
            category: "security",
            ok: true,
            info: "VZ + Hypervisor entitlements present".to_string(),
        },
        Some(false) => Check {
            name: "signing",
            category: "security",
            ok: false,
            info: "entitlements missing — run `mvmctl sign`".to_string(),
        },
    }
}
```

- [ ] **Step 4: Push it into the report** — add to the security block (after the existing `checks.push(security_snapshot_dirs_check());` ~line 279):

```rust
    checks.push(security_signing_check());
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo nextest run -p mvm-cli signing_check_is_in_security_category`
Expected: PASS. `mvmctl doctor` shows a `signing:` line under "Security posture"; `mvmctl doctor --json` includes it (free via `DoctorReport` serialize).

- [ ] **Step 6: Commit**

```bash
rustup run nightly cargo fmt --all
git add crates/mvm-cli/src/doctor.rs
git commit -m "feat(mvm-cli): doctor signing security check"
```

### Task 1.6: Manual VZ verification (macOS dev host)

- [ ] On this Vz dev host, with an unsigned `target/debug/mvmctl`:
  `cargo run -p mvm-cli -- doctor` shows `signing: MISSING (entitlements missing — run \`mvmctl sign\`)`.
- [ ] `cargo run -p mvm-cli -- sign` reports `✓` for each resolved binary.
- [ ] `cargo run -p mvm-cli -- doctor` now shows `signing: OK`.
- [ ] A subsequent `mvmctl up`/dev boot succeeds without the auto-sign re-exec. Document the transcript in the PR.

---

# Phase 2 — WS-5 C: shared `--json` helper + coverage

### Task 2.1: `emit_json` helper

**Files:**
- Create: `crates/mvm-cli/src/json_out.rs`
- Modify: `crates/mvm-cli/src/lib.rs`

- [ ] **Step 1: Write the helper + its test** `crates/mvm-cli/src/json_out.rs`

```rust
//! Single JSON-output path for the CLI: pretty-printed, newline-
//! terminated, written to stdout. Keeps `--json` shape consistent
//! across commands (no envelope framework — YAGNI).

use anyhow::Result;
use serde::Serialize;

pub fn emit_json<T: Serialize>(value: &T) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

/// Render to a `String` (test seam; `emit_json` prints this + newline).
pub fn to_json_string<T: Serialize>(value: &T) -> Result<String> {
    Ok(serde_json::to_string_pretty(value)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_json_string_is_pretty() {
        let v = serde_json::json!({"a": 1, "b": [2, 3]});
        let s = to_json_string(&v).unwrap();
        assert!(s.contains("\n"), "pretty output should be multi-line");
        assert!(s.contains("\"a\""));
    }
}
```

- [ ] **Step 2: Declare the module** — add to `crates/mvm-cli/src/lib.rs` next to `pub mod doctor;`:

```rust
pub mod json_out;
```

- [ ] **Step 3: Run tests**

Run: `cargo nextest run -p mvm-cli json_out`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
rustup run nightly cargo fmt --all
git add crates/mvm-cli/src/json_out.rs crates/mvm-cli/src/lib.rs
git commit -m "feat(mvm-cli): emit_json shared output helper"
```

### Task 2.2: Migrate existing inline JSON sites to `emit_json`

**Files:**
- Modify: `crates/mvm-cli/src/commands/image.rs`
- Modify: `crates/mvm-cli/src/commands/vm/ps.rs`
- Modify: `crates/mvm-cli/src/commands/vm/sandbox.rs`

- [ ] **Step 1: image.rs** — replace both
  `println!("{}", serde_json::to_string_pretty(&rows)?);` and
  `println!("{}", serde_json::to_string_pretty(&output)?);`
  with `crate::json_out::emit_json(&rows)?;` and
  `crate::json_out::emit_json(&output)?;` respectively.

- [ ] **Step 2: ps.rs** — replace the trailing
  `println!("{}", serde_json::to_string_pretty(&rows)?); return Ok(());`
  with `crate::json_out::emit_json(&rows)?; return Ok(());`.

- [ ] **Step 3: sandbox.rs** — replace its
  `println!("{}", serde_json::to_string_pretty(&summary)?)` (GcSummary)
  with `crate::json_out::emit_json(&summary)?;`.

- [ ] **Step 4: Verify no behavior change**

Run: `cargo nextest run -p mvm-cli`
Expected: PASS (existing `--json` tests still green; output is byte-identical — same pretty serializer).

- [ ] **Step 5: Commit**

```bash
rustup run nightly cargo fmt --all
git add crates/mvm-cli/src/commands/image.rs crates/mvm-cli/src/commands/vm/ps.rs crates/mvm-cli/src/commands/vm/sandbox.rs
git commit -m "refactor(mvm-cli): route existing --json through emit_json"
```

### Task 2.3: Add `--json` to `cache info`

**Files:**
- Modify: `crates/mvm-cli/src/commands/ops/cache.rs`
- Test: `crates/mvm-cli/src/commands/tests.rs`

- [ ] **Step 1: Write the failing parse test** (in `commands/tests.rs`; add `use super::ops::cache;` if absent)

```rust
#[test]
fn test_cache_info_json_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "cache", "info", "--json"]).unwrap();
    assert!(matches!(
        cli.command,
        Commands::Cache(cache::Args { action: cache::CacheAction::Info { json: true } })
    ));
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo nextest run -p mvm-cli test_cache_info_json_parses`
Expected: FAIL — `Info` has no `json` field.

- [ ] **Step 3: Implement** — add `#[arg(long)] json: bool` to the `CacheAction::Info` variant in `cache.rs`; in its handler build a `#[derive(serde::Serialize)]` struct of the fields currently printed (path, size bytes, entry counts) and branch:

```rust
        CacheAction::Info { json } => {
            let info = collect_cache_info()?; // existing gather logic, returned as a Serialize struct
            if json {
                crate::json_out::emit_json(&info)?;
            } else {
                render_cache_info(&info); // existing human render
            }
            Ok(())
        }
```

If `cache info`'s current handler computes values inline, refactor the
gather into `fn collect_cache_info() -> Result<CacheInfo>` returning a
new `#[derive(serde::Serialize)] struct CacheInfo { ... }`, and have the
human path render from it (so JSON and text share one source).

- [ ] **Step 4: Run tests**

Run: `cargo nextest run -p mvm-cli test_cache_info_json_parses`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
rustup run nightly cargo fmt --all
git add crates/mvm-cli/src/commands/ops/cache.rs crates/mvm-cli/src/commands/tests.rs
git commit -m "feat(mvm-cli): cache info --json"
```

### Task 2.4: Add `--json` to `network list` and `network inspect`

**Files:**
- Modify: `crates/mvm-cli/src/commands/ops/network.rs`
- Test: `crates/mvm-cli/src/commands/tests.rs`

- [ ] **Step 1: Write the failing parse tests**

```rust
#[test]
fn test_network_list_json_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "network", "list", "--json"]).unwrap();
    assert!(matches!(
        cli.command,
        Commands::Network(ops::network::Args {
            action: ops::network::NetworkAction::List { json: true }
        })
    ));
}

#[test]
fn test_network_inspect_json_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "network", "inspect", "isolated", "--json"]).unwrap();
    assert!(matches!(
        cli.command,
        Commands::Network(ops::network::Args {
            action: ops::network::NetworkAction::Inspect { ref name, json: true }
        }) if name == "isolated"
    ));
}
```

(Add `use super::ops;` / `use super::ops::network;` to the alias block if
the exact path differs; match the real `NetworkAction` variant names from
`network.rs`.)

- [ ] **Step 2: Run to verify they fail**

Run: `cargo nextest run -p mvm-cli test_network_list_json_parses test_network_inspect_json_parses`
Expected: FAIL — variants lack `json`.

- [ ] **Step 3: Implement** — add `#[arg(long)] json: bool` to the `List` and `Inspect` variants of `NetworkAction`. In their handlers, ensure the gathered value is `Serialize` (the network record/list type) and branch:

```rust
        NetworkAction::List { json } => {
            let nets = list_networks()?;
            if json { crate::json_out::emit_json(&nets)?; } else { render_networks(&nets); }
            Ok(())
        }
        NetworkAction::Inspect { name, json } => {
            let net = inspect_network(&name)?;
            if json { crate::json_out::emit_json(&net)?; } else { render_network(&net); }
            Ok(())
        }
```

If the network types aren't `Serialize`, derive `serde::Serialize` on the
record struct(s) in `network.rs` (or `mvm-core`/`mvm-backend` if defined
there) — they are plain data.

- [ ] **Step 4: Run tests**

Run: `cargo nextest run -p mvm-cli test_network_list_json_parses test_network_inspect_json_parses`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
rustup run nightly cargo fmt --all
git add crates/mvm-cli/src/commands/ops/network.rs crates/mvm-cli/src/commands/tests.rs
git commit -m "feat(mvm-cli): network list/inspect --json"
```

### Task 2.5: Add `--json` to `snapshot ls`

**Files:**
- Modify: `crates/mvm-cli/src/commands/vm/pause.rs`
- Test: `crates/mvm-cli/src/commands/tests.rs`

- [ ] **Step 1: Write the failing parse test**

```rust
#[test]
fn test_snapshot_ls_json_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "snapshot", "ls", "--json"]).unwrap();
    match cli.command {
        Commands::Snapshot(ref a) => assert!(format!("{a:?}").contains("json")),
        _ => panic!("expected snapshot"),
    }
}
```

(Tighten the match to the real `SnapshotArgs`/`SnapshotAction::Ls`
shape once you read `pause.rs`; the `Debug`-contains check is a
fallback if the action is a flat struct.)

- [ ] **Step 2: Run to verify it fails**

Run: `cargo nextest run -p mvm-cli test_snapshot_ls_json_parses`
Expected: FAIL.

- [ ] **Step 3: Implement** — add `#[arg(long)] json: bool` to the snapshot-`ls` arm in `pause.rs`; build a `Serialize` row list of snapshots and branch through `crate::json_out::emit_json(&rows)?`, mirroring `image ls`.

- [ ] **Step 4: Run tests**

Run: `cargo nextest run -p mvm-cli test_snapshot_ls_json_parses`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
rustup run nightly cargo fmt --all
git add crates/mvm-cli/src/commands/vm/pause.rs crates/mvm-cli/src/commands/tests.rs
git commit -m "feat(mvm-cli): snapshot ls --json"
```

### Task 2.6: Add `--json` to `audit` list view

**Files:**
- Modify: `crates/mvm-cli/src/commands/ops/audit.rs`
- Test: `crates/mvm-cli/src/commands/tests.rs`

- [ ] **Step 1: Write the failing parse test** matching the real `audit` list subcommand/flag shape in `audit.rs` (read it first), e.g.:

```rust
#[test]
fn test_audit_ls_json_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "audit", "ls", "--json"]).unwrap();
    assert!(matches!(
        cli.command,
        Commands::Audit(ops::audit::Args { action: ops::audit::AuditAction::Ls { json: true, .. } })
    ));
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo nextest run -p mvm-cli test_audit_ls_json_parses`
Expected: FAIL.

- [ ] **Step 3: Implement** — add `#[arg(long)] json: bool` to the audit list arm; the audit entries are already serde types (they are written as JSONL), so collect the parsed entries into a `Vec` and `crate::json_out::emit_json(&entries)?` on the flag, else the existing human render.

- [ ] **Step 4: Run tests**

Run: `cargo nextest run -p mvm-cli test_audit_ls_json_parses`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
rustup run nightly cargo fmt --all
git add crates/mvm-cli/src/commands/ops/audit.rs crates/mvm-cli/src/commands/tests.rs
git commit -m "feat(mvm-cli): audit ls --json"
```

---

# Phase 3 — WS-5 B: session resume ergonomics

### Task 3.1: `most_recent_running` selector in mvm-core

**Files:**
- Modify: `crates/mvm-core/src/domain/session.rs`
- Test: `crates/mvm-core/src/domain/session.rs`

- [ ] **Step 1: Write the failing test** (in the session module's `#[cfg(test)]`)

```rust
#[test]
fn most_recent_running_prefers_latest_activity() {
    let mut a = SessionRecord::new_running("vm-a", "tmpl", SessionMode::Prod);
    a.started_at = "2026-01-01T00:00:00Z".to_string();
    a.last_invoke_at = Some("2026-01-01T05:00:00Z".to_string());
    let mut b = SessionRecord::new_running("vm-b", "tmpl", SessionMode::Prod);
    b.started_at = "2026-01-02T00:00:00Z".to_string();
    b.last_invoke_at = None; // falls back to started_at
    let mut killed = SessionRecord::new_running("vm-c", "tmpl", SessionMode::Prod);
    killed.started_at = "2026-09-09T00:00:00Z".to_string();
    killed.state = SessionState::Killed; // excluded

    let pick = most_recent_running(vec![a, b, killed]);
    // b's started_at (Jan 2) beats a's last_invoke (Jan 1 05:00).
    assert_eq!(pick.unwrap().vm_name, "vm-b");
}

#[test]
fn most_recent_running_none_when_empty() {
    assert!(most_recent_running(Vec::new()).is_none());
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo nextest run -p mvm-core most_recent_running`
Expected: FAIL — `most_recent_running` not found.

- [ ] **Step 3: Implement** (pure function over a Vec so it's unit-testable; a thin wrapper reads from disk)

```rust
/// The most-recently-active Running session, ranked by
/// `last_invoke_at` (falling back to `started_at`). Pure over the
/// input so it can be tested without touching disk.
pub fn most_recent_running(records: Vec<SessionRecord>) -> Option<SessionRecord> {
    records
        .into_iter()
        .filter(|r| r.state == SessionState::Running)
        .max_by(|a, b| {
            let ka = a.last_invoke_at.as_deref().unwrap_or(&a.started_at);
            let kb = b.last_invoke_at.as_deref().unwrap_or(&b.started_at);
            ka.cmp(kb)
        })
}

/// Disk-backed convenience: scan the session table and return the
/// most-recently-active Running session.
pub fn most_recent_running_on_disk() -> Result<Option<SessionRecord>> {
    Ok(most_recent_running(list_sessions()?))
}
```

(RFC-3339 second-precision timestamps sort lexicographically, so string
`cmp` is correct ordering here.)

- [ ] **Step 4: Run tests**

Run: `cargo nextest run -p mvm-core most_recent_running`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
rustup run nightly cargo fmt --all
git add crates/mvm-core/src/domain/session.rs
git commit -m "feat(mvm-core): most_recent_running session selector"
```

### Task 3.2: `--continue` / `--resume` on `session attach`

**Files:**
- Modify: `crates/mvm-cli/src/commands/vm/session.rs`
- Test: `crates/mvm-cli/src/commands/tests.rs`

- [ ] **Step 1: Write the failing parse tests** (in `commands/tests.rs`; add `use super::vm::session;`)

```rust
#[test]
fn test_session_attach_continue_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "session", "attach", "--continue"]).unwrap();
    match cli.command {
        Commands::Session(session::Args { command: session::Cmd::Attach(a) }) => {
            assert!(a.continue_latest);
            assert!(a.session_id.is_none());
            assert!(a.resume.is_none());
        }
        _ => panic!("expected session attach"),
    }
}

#[test]
fn test_session_attach_resume_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "session", "attach", "-r", "aaaaaaaaaaaaaaaa"]).unwrap();
    match cli.command {
        Commands::Session(session::Args { command: session::Cmd::Attach(a) }) => {
            assert_eq!(a.resume.as_deref(), Some("aaaaaaaaaaaaaaaa"));
        }
        _ => panic!("expected session attach"),
    }
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo nextest run -p mvm-cli test_session_attach_continue_parses test_session_attach_resume_parses`
Expected: FAIL — fields don't exist.

- [ ] **Step 3: Extend `AttachArgs`** (make the positional optional, add the two flags)

```rust
#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct AttachArgs {
    /// Session id to dispatch into (positional). Omit with --continue.
    pub session_id: Option<String>,
    /// Re-attach the most-recently-active running session.
    #[arg(short = 'c', long = "continue", conflicts_with_all = ["session_id", "resume"])]
    pub continue_latest: bool,
    /// Re-attach a specific session id (alias for the positional).
    #[arg(short = 'r', long = "resume", value_name = "ID", conflicts_with = "session_id")]
    pub resume: Option<String>,
    /// Path to stdin payload, or `-` for mvmctl's own stdin.
    #[arg(long, value_name = "PATH")]
    pub stdin: Option<String>,
    /// Wall-clock timeout for the call, in seconds. Default 30.
    #[arg(long, default_value = "30")]
    pub timeout: u64,
}
```

- [ ] **Step 4: Resolve the target id in `cmd_attach`** — replace the opening of `cmd_attach` so it computes the id from the three inputs before `require_running_session`:

```rust
fn cmd_attach(args: AttachArgs) -> Result<()> {
    let resolved_id: String = if args.continue_latest {
        let rec = mvm_core::session::most_recent_running_on_disk()?
            .ok_or_else(|| anyhow::anyhow!("no running session to --continue"))?;
        rec.id.into_string()
    } else if let Some(id) = args.resume.or(args.session_id) {
        id
    } else {
        bail!("provide a session id, --resume <id>, or --continue");
    };

    let (id, record) = require_running_session(&resolved_id)?;
    // ... unchanged body from here (stdin read, dispatch, bump) ...
```

(Keep the rest of the existing `cmd_attach` body verbatim from
`let stdin_bytes = ...` onward.)

- [ ] **Step 5: Run tests**

Run: `cargo nextest run -p mvm-cli test_session_attach_continue_parses test_session_attach_resume_parses`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
rustup run nightly cargo fmt --all
git add crates/mvm-cli/src/commands/vm/session.rs crates/mvm-cli/src/commands/tests.rs
git commit -m "feat(mvm-cli): session attach --continue/--resume"
```

### Task 3.3: `--ephemeral` on `session start`

**Files:**
- Modify: `crates/mvm-core/src/domain/session.rs`
- Modify: `crates/mvm-cli/src/commands/vm/session.rs`
- Test: both

- [ ] **Step 1: Write the failing record test** (mvm-core)

```rust
#[test]
fn session_record_ephemeral_defaults_false_and_roundtrips() {
    let mut r = SessionRecord::new_running("vm", "tmpl", SessionMode::Prod);
    assert!(!r.ephemeral);
    r.ephemeral = true;
    let json = serde_json::to_string(&r).unwrap();
    let back: SessionRecord = serde_json::from_str(&json).unwrap();
    assert!(back.ephemeral);
    // Back-compat: a record written before this field still parses.
    let legacy = json.replace(",\n  \"ephemeral\": true", "");
    let _legacy: SessionRecord = serde_json::from_str(&legacy).unwrap();
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo nextest run -p mvm-core session_record_ephemeral`
Expected: FAIL — no `ephemeral` field. (Note: `SessionRecord` has
`#[serde(deny_unknown_fields)]`, so the field MUST be added with
`#[serde(default)]` for the legacy-parse leg to pass.)

- [ ] **Step 3: Add the field** to `SessionRecord` (after `creator_pid`):

```rust
    /// When true, the session is torn down automatically after an
    /// attach completes (vz-style `--ephemeral`). Defaults false so
    /// records written before this field still parse.
    #[serde(default)]
    pub ephemeral: bool,
```

And set it in `new_running` (add `ephemeral: false,` to the struct
literal).

- [ ] **Step 4: Write the failing parse test** (mvm-cli, `commands/tests.rs`)

```rust
#[test]
fn test_session_start_ephemeral_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "session", "start", "tmpl", "--ephemeral"]).unwrap();
    match cli.command {
        Commands::Session(session::Args { command: session::Cmd::Start(a) }) => assert!(a.ephemeral),
        _ => panic!("expected session start"),
    }
}
```

- [ ] **Step 5: Add the flag + persist it** — add to `StartArgs`:

```rust
    /// Tear the session down automatically after the next attach
    /// completes (no manual `session kill` needed).
    #[arg(long)]
    pub ephemeral: bool,
```

In `cmd_start`, after `let mut record = SessionRecord::new_running(...)`:

```rust
    record.ephemeral = args.ephemeral;
```

- [ ] **Step 6: Tear down ephemeral sessions after attach** — in
  `cmd_attach`, after the invoke-counter bump and before the exit-code
  check, add:

```rust
    if record.ephemeral {
        ui::info(&format!("ephemeral session {id}: tearing down after attach"));
        let _ = crate::exec::tear_down_session_vm(crate::exec::SessionVm {
            vm_name: record.vm_name.clone(),
        });
        let _ = mvm_core::session::update_session(&id, |r| {
            r.state = mvm_core::session::SessionState::Reaped;
            Ok(())
        });
    }
```

- [ ] **Step 7: Run tests**

Run: `cargo nextest run -p mvm-core session_record_ephemeral && cargo nextest run -p mvm-cli test_session_start_ephemeral_parses`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
rustup run nightly cargo fmt --all
git add crates/mvm-core/src/domain/session.rs crates/mvm-cli/src/commands/vm/session.rs crates/mvm-cli/src/commands/tests.rs
git commit -m "feat: session start --ephemeral with post-attach teardown"
```

### Task 3.4: `--help` documents the resume/ephemeral semantics

**Files:**
- Create: `crates/mvm-cli/tests/session_resume_cli.rs`

- [ ] **Step 1: Write the surface test**

```rust
use assert_cmd::cargo::CommandCargoExt;
use std::process::Command;

fn mvmctl(args: &[&str]) -> std::process::Output {
    #[allow(deprecated)]
    Command::cargo_bin("mvmctl").expect("locate mvmctl").args(args).output().expect("spawn")
}

#[test]
fn session_attach_help_lists_continue_and_resume() {
    let out = mvmctl(&["session", "attach", "--help"]);
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success());
    assert!(s.contains("--continue"), "missing --continue:\n{s}");
    assert!(s.contains("--resume"), "missing --resume:\n{s}");
}

#[test]
fn session_start_help_lists_ephemeral() {
    let out = mvmctl(&["session", "start", "--help"]);
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success());
    assert!(s.contains("--ephemeral"), "missing --ephemeral:\n{s}");
}
```

- [ ] **Step 2: Run + commit**

Run: `cargo nextest run -p mvm-cli --test session_resume_cli`
Expected: PASS.

```bash
git add crates/mvm-cli/tests/session_resume_cli.rs
git commit -m "test(mvm-cli): session resume/ephemeral help surface"
```

---

# Phase 4 — WS-4: resumable + honest-cost acquisition

### Task 4.1: Factor curl args + add `-C -` resume

**Files:**
- Modify: `crates/mvm-cli/src/commands/env/artifact_verify.rs`
- Test: `crates/mvm-cli/src/commands/env/artifact_verify.rs`

- [ ] **Step 1: Write the failing test** (in `artifact_verify.rs` `#[cfg(test)]`)

```rust
#[test]
fn curl_download_args_request_resume() {
    let args = curl_download_args("/tmp/out", "https://example/x");
    assert!(args.contains(&"-C".to_string()), "must pass -C for resume: {args:?}");
    assert!(args.windows(2).any(|w| w == ["-C", "-"]), "expected `-C -`: {args:?}");
    assert!(args.contains(&"-fSL".to_string()));
    assert_eq!(args.last().unwrap(), "https://example/x");
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo nextest run -p mvm-cli curl_download_args_request_resume`
Expected: FAIL — `curl_download_args` not found.

- [ ] **Step 3: Refactor `download_file`** to build args via a pure
  helper, with `-C -` so an interrupted partial resumes. `-C -` is safe
  on a fresh file (curl starts at 0) and a complete file (curl reports
  nothing to do); a corrupt resume is still caught by the SHA-256 gate,
  which deletes on mismatch so the next run restarts clean.

```rust
/// Build the curl argv for a (resumable) download to `dest`.
/// `-C -` resumes from a partial `dest` if present.
pub(super) fn curl_download_args(dest: &str, url: &str) -> Vec<String> {
    vec![
        "-fSL".to_string(),
        "--progress-bar".to_string(),
        "-C".to_string(),
        "-".to_string(),
        "-o".to_string(),
        dest.to_string(),
        url.to_string(),
    ]
}

pub(super) fn download_file(url: &str, dest: &str) -> Result<()> {
    let status = std::process::Command::new("curl")
        .args(curl_download_args(dest, url))
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()
        .context("Failed to run curl")?;

    if !status.success() {
        let _ = std::fs::remove_file(dest);
        anyhow::bail!(
            "Download failed. Pre-built images for v{version} may not yet be\n\
             published — release tags are pushed before the artifact-build\n\
             job finishes. Retry shortly, or build locally from the flake.",
            version = env!("CARGO_PKG_VERSION")
        );
    }
    Ok(())
}
```

- [ ] **Step 4: Run tests**

Run: `cargo nextest run -p mvm-cli curl_download_args_request_resume`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
rustup run nightly cargo fmt --all
git add crates/mvm-cli/src/commands/env/artifact_verify.rs
git commit -m "feat(mvm-cli): resumable dev-image download (curl -C -)"
```

### Task 4.2: Honest one-time-cost framing

**Files:**
- Modify: `crates/mvm-cli/src/commands/env/apple_container.rs`

- [ ] **Step 1: Add the framing message** — in `download_dev_image_inner`,
  replace the existing `ui::info(&format!("Downloading dev image (v{version})..."));`
  with a payoff-framed pair:

```rust
    ui::info(&format!(
        "Downloading dev image (v{version}) — one-time setup. \
         Subsequent runs reuse the cached image and start in seconds."
    ));
```

- [ ] **Step 2: Verify build + existing tests**

Run: `cargo build -p mvm-cli && cargo nextest run -p mvm-cli`
Expected: builds, tests green (message-only change).

- [ ] **Step 3: Commit**

```bash
rustup run nightly cargo fmt --all
git add crates/mvm-cli/src/commands/env/apple_container.rs
git commit -m "feat(mvm-cli): honest one-time-cost framing for dev image download"
```

### Task 4.3: Manual resume verification (dev host)

- [ ] On the Vz dev host with an empty `MVM_CACHE_DIR`, start a dev-image
  download and interrupt it mid-stream (Ctrl-C). Re-run the same command;
  confirm curl resumes (progress starts above 0%) and the final
  `verify_artifact_hash` passes.
- [ ] Corrupt the partial file by appending a byte, re-run, and confirm
  the SHA-256 gate fails and deletes the file (claim-6 behavior intact).
  Document both transcripts in the PR.

---

## Deferred follow-ups (tracked, not in this plan)

- [ ] WS-5 D — verb-vocabulary rename pass (own reviewable commit).
- [ ] WS-5 E — streamed `exec` (guest vsock protocol change; own slice).
- [ ] WS-4 — `curl|sh` installer one-liner (release-pipeline work).
- [ ] WS-5 C — `--json` audit of the remaining commands not covered here.
      (Final review found ~15 inline `to_string_pretty` sites still
      unmigrated, e.g. `manifest/ls.rs`, `catalog.rs`, `bundle/fetch.rs`,
      `vm/cp.rs`, `vm/wait.rs`; `vm/session.rs:313` uses compact, not
      pretty. No CI gate stops new inline sites — consider a lint.)
- [ ] WS-3 — `doctor` `signing` check probes only the `mvmctl` binary,
      not the supervisors `mvmctl sign` also signs; an unsigned
      supervisor could still fail launch while doctor reads OK. Consider
      probing `collect_sign_targets()` and reporting the worst case.

## Self-review notes

- **Spec coverage:** WS-3 → Phase 1; WS-5 C → Phase 2; WS-5 B → Phase 3;
  WS-4 (in-binary) → Phase 4. Installer + deferred items recorded above.
- **Type consistency:** `SignReport` fields (`path`/`applied`/
  `entitlements_present`) are identical across mvm-backend definition,
  the macOS `sign_path` constructor, and the CLI consumer.
  `most_recent_running` signature matches both the pure test and the
  disk wrapper. `SessionRecord.ephemeral` is `#[serde(default)] bool`
  everywhere it's read/written.
- **Verification gates:** every code task ends with a real
  command + expected result; VZ/codesign live paths are explicit manual
  steps (Tasks 1.6, 4.3) because they can't run in CI.

## References

- Design: `specs/notes/plan-159-dx-152-independent-slice-design.md`
- Parent: `specs/plans/159-vz-inspired-macos-dx.md`
- Sign harness: `crates/mvm-backend/src/providers/apple_container/macos.rs:345-416`
- Doctor model: `crates/mvm-cli/src/doctor.rs:86-92,269-279,348-377,901-916`
- Sessions: `crates/mvm-cli/src/commands/vm/session.rs`,
  `crates/mvm-core/src/domain/session.rs`
- Download path: `crates/mvm-cli/src/commands/env/artifact_verify.rs`,
  `crates/mvm-cli/src/commands/env/apple_container.rs:1193-1283`
</content>
