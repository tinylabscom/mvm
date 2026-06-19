# Plan 205 Workstream A — Trust-gradient invariant — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make ADR-090's three-daemon trust gradient a machine-checked, CI-enforced invariant so later Plan 205 residency work cannot silently push authority (signing keys, plan admission, audit writing) below the host→builder vsock line.

**Architecture:** Three small, independent gates, repo-idiomatic. (1) A symbol-grep script proving the production workload agent links no host-signer/admission symbol, wired into `security.yml` exactly like the existing `prod-agent-no-exec`/`prod-agent-no-console` lanes. (2) A `mvm-hostd` integration test proving two tenants get isolated daemon sockets, PID groups, and audit chains. (3) A capstone `specs/claims/trust-gradient.md` ledger plus `xtask check-trust-gradient` that asserts the tier order is monotonic and every forbidden-authority row names a witness that exists on disk — mirroring `check-claim-catalog`. The ledger references gates (1) and (2) as its witnesses, so the capstone runs green only once they exist.

**Tech Stack:** Rust (xtask + `#[tokio::test]` integration test), Bash (symbol gate via `nm`), GitHub Actions, Markdown ledger.

## Global Constraints

- No placeholders anywhere — every step is real, landing code (CLAUDE.md; `feedback_no_placeholders_in_plans_or_code`).
- No spec/PR/ADR citations in code comments — keep the reasoning, drop the citation (`check-no-spec-refs-in-comments` is a CI gate).
- `cargo fmt --all -- --check` must pass (the `--all` matters).
- `cargo nextest run --workspace` green; `cargo clippy --workspace --all-targets -- -D warnings` zero warnings.
- `#[allow(clippy::too_many_arguments)]` is banned in hand-written code.
- All `~/.mvm` / `~/.cache/mvm` paths go through `mvm_core::config` helpers — never inline `$HOME`.
- Do not overclaim: local single-user `mvm` has one tenant and one host key, so per-tenant *key-material* isolation is a fleet (mvmd / Plan 202) concern; this workstream proves per-tenant *path/socket/chain* isolation only.
- Frequent commits — one per task, after its gate is green.

## Out of scope / blocked (tracked, not built here)

- **Builder-daemon no-authority symbol gate.** The `mvm-builderd` binary does not exist until Plan 204 (in-flight, parallel worktree `mvm-204-protocol`) lands. The ledger therefore ships with host + workload rows now; the builder row and its witness are added by a one-step follow-up once `mvm-builderd` exists (see "Deferred" at the end). Do **not** invent the binary here.

## File Structure

- Create `scripts/check-prod-agent-no-authority.sh` — symbol gate (Task 1).
- Modify `.github/workflows/security.yml` — add the `prod-agent-no-authority` lane (Task 1).
- Create `crates/mvm-hostd/tests/per_tenant_isolation.rs` — isolation test (Task 2).
- Create `specs/claims/trust-gradient.md` — the ledger (Task 3).
- Create `xtask/src/check_trust_gradient.rs` — the check (Task 3).
- Modify `xtask/src/main.rs` — register `check-trust-gradient` (Task 3).
- Modify `.github/workflows/ci.yml` — run the check in the existing lint job (Task 3).

---

### Task 1: Workload-agent no-authority symbol gate

Mirror `scripts/check-prod-agent-no-exec.sh`. The production `mvm-guest-agent` (built `--no-default-features`) must link none of the host-only authority symbols: host-signer key loading and plan admission. `handle_run_entrypoint` is the canary that proves the symbol table is populated, so the absence assertions are not vacuous.

**Files:**
- Create: `scripts/check-prod-agent-no-authority.sh`
- Modify: `.github/workflows/security.yml` (new lane beside `prod-agent-no-console`, ~line 111)

**Interfaces:**
- Consumes: the existing `mvm-guest` / `mvm-guest-agent` package+bin and the `nm` symbol-table convention from `scripts/check-prod-agent-no-exec.sh`.
- Produces: a CI lane literally named `prod-agent-no-authority` (Task 3's ledger names it as `ci:prod-agent-no-authority`).

- [ ] **Step 1: Write the gate script**

Create `scripts/check-prod-agent-no-authority.sh`:

```bash
#!/usr/bin/env bash
# Production guest-agent authority contract.
#
# On the `mvm-guest-agent` binary built in its PRODUCTION configuration (no
# `dev-shell` feature), assert the workload agent links NONE of the host-only
# authority symbols. The workload microVM is the untrusted edge: it must not
# carry signing-key loading or plan-admission code, which live host-side.
#
#   canary: `handle_run_entrypoint` PRESENT — proves the symbol table is
#           populated, so the absence checks below are not vacuously true.
#   absent: `load_host_signing_key`, `host_signer`, `admit_for_run` — host-side
#           authority. None may appear in the agent's own crate symbols.
set -euo pipefail

PKG=mvm-guest
BIN=mvm-guest-agent

echo "::group::Build production agent (release, no dev-shell)"
CARGO_PROFILE_RELEASE_STRIP=false \
  cargo build --release --locked -p "$PKG" --bin "$BIN" --no-default-features
echo "::endgroup::"
prod_syms=$(nm "target/release/$BIN")

fail=0

if grep -q 'mvm_guest_agent.*handle_run_entrypoint' <<<"$prod_syms"; then
  echo "ok: handle_run_entrypoint present (symbol table populated)"
else
  echo "::error::handle_run_entrypoint ABSENT — symbol table stripped; absence checks would be vacuous." >&2
  fail=1
fi

for sym in load_host_signing_key host_signer admit_for_run; do
  if grep -qE "mvm_(guest_agent|core|hostd).*${sym}" <<<"$prod_syms"; then
    echo "::error::host authority symbol \`${sym}\` is PRESENT in the production agent." >&2
    grep -E "mvm_(guest_agent|core|hostd).*${sym}" <<<"$prod_syms" >&2 || true
    fail=1
  else
    echo "ok: ${sym} absent from the production agent"
  fi
done

if [ "$fail" -ne 0 ]; then
  echo "::error::Production guest-agent authority contract FAILED — see annotations above." >&2
  exit 1
fi
echo "All assertions passed: prod agent carries no host-authority symbols."
```

- [ ] **Step 2: Make it executable and run it locally to verify it passes**

```bash
chmod +x scripts/check-prod-agent-no-authority.sh
./scripts/check-prod-agent-no-authority.sh
```

Expected: ends with `All assertions passed: prod agent carries no host-authority symbols.` and exit 0. If a symbol is unexpectedly present, that is a real finding — stop and report it rather than weakening the grep.

- [ ] **Step 3: Wire the CI lane**

In `.github/workflows/security.yml`, find the `prod-agent-no-console` job (~line 111) and add a sibling job modeled on it:

```yaml
  prod-agent-no-authority:
    name: prod agent carries no host-authority symbols
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - name: No host-signer / admission symbols in the production agent
        run: ./scripts/check-prod-agent-no-authority.sh
```

(Match the exact `uses:`/cache steps of the adjacent `prod-agent-no-console` job in this file — copy its preamble verbatim so toolchain/caching stay consistent.)

- [ ] **Step 4: Commit**

```bash
git add scripts/check-prod-agent-no-authority.sh .github/workflows/security.yml
git commit -m "test(plan-205): prod workload agent links no host-authority symbols (WS-A)"
```

---

### Task 2: Per-tenant daemon isolation test

Prove the host control daemon stays per-tenant: two tenants get distinct control sockets, distinct worker PID groups, and distinct workload audit chains, and an audit emit routed to tenant A's broker lands only in A's chain — never B's. Models the harness in `crates/mvm-hostd/tests/host_agent_restart.rs`.

**Files:**
- Create: `crates/mvm-hostd/tests/per_tenant_isolation.rs`

**Interfaces:**
- Consumes: `mvm_backend::{ensure_host_agent_daemon, register_vm, deregister_vm, load_host_signing_key}`; `mvm_core::config::{mvm_keys_dir, workload_audit_path, host_agent_dir, host_agent_worker_pid}`; `mvm_hostd::audit::host_keypair`; `mvm_hostd::audit_signer::verify::verify_workload_chain`; `mvm_core::protocol::broker::{ServiceCall, ServiceId, CorrelationId, ServiceResponse}`; `mvm_core::util::test_env::TestEnv`.
- Produces: a test fn literally named `per_tenant_daemon_paths_are_isolated` (Task 3's ledger names it as `fn:per_tenant_daemon_paths_are_isolated`).

- [ ] **Step 1: Write the failing test**

Create `crates/mvm-hostd/tests/per_tenant_isolation.rs`:

```rust
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use mvm_backend::{deregister_vm, ensure_host_agent_daemon, load_host_signing_key, register_vm};
use mvm_core::config;
use mvm_core::protocol::broker::{CorrelationId, ServiceCall, ServiceId, ServiceResponse};
use mvm_core::protocol::broker_control::RegisterVm;
use mvm_core::util::test_env::TestEnv;
use mvm_hostd::audit::host_keypair;
use mvm_hostd::audit_signer::verify::verify_workload_chain;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

const HOST_AGENT_BIN: &str = env!("CARGO_BIN_EXE_mvm-host-agent");
const SIGNER_HELPER_BIN: &str = env!("CARGO_BIN_EXE_mvm-signer-helper");

struct Tenant {
    id: String,
    vm: String,
    control_socket: PathBuf,
    broker_socket: PathBuf,
    chain: PathBuf,
    worker_pid_path: PathBuf,
    key_bytes: [u8; 32],
}

async fn start_tenant(data_root: &Path, id: &str) -> Tenant {
    let keys_dir = config::mvm_keys_dir();
    host_keypair::load_or_init_at(&keys_dir).expect("host signer");
    let key_bytes = load_host_signing_key().expect("host signer key bytes");
    let vm = format!("{id}-vm-1");
    let control_socket = ensure_host_agent_daemon(id).expect("start host-agent");
    let broker_socket = data_root.join(format!("{id}-broker.sock"));
    let chain = config::workload_audit_path(id, &vm);

    let reg = RegisterVm {
        vm_id: vm.clone(),
        workload_id: Some(format!("wl-{vm}")),
        tenant_id: id.to_string(),
        broker_listen_socket: broker_socket.clone(),
        workload_chain_path: chain.clone(),
        workload_chain_head_path: Some(data_root.join(format!("{id}-signer.head"))),
        audit_signer_uds_path: None,
        services_bindings: vec![],
    };
    register_vm(&control_socket, &key_bytes, reg).expect("register vm");

    Tenant {
        id: id.to_string(),
        vm,
        control_socket,
        broker_socket,
        chain,
        worker_pid_path: config::host_agent_worker_pid(id),
        key_bytes,
    }
}

async fn emit(sock: &Path, event: &str) -> Result<ServiceResponse> {
    let mut conn = UnixStream::connect(sock)
        .await
        .with_context(|| format!("connect broker {}", sock.display()))?;
    let call = ServiceCall {
        service: ServiceId::parse("host.audit.v1").expect("service id"),
        verb: "emit".into(),
        correlation_id: CorrelationId::new("ignored"),
        payload: serde_json::json!({ "ts": "2026-06-19T00:00:00Z", "fields": {"event": event} }),
    };
    let body = serde_json::to_vec(&call).unwrap();
    conn.write_all(&(body.len() as u32).to_be_bytes()).await?;
    conn.write_all(&body).await?;
    conn.flush().await?;
    let mut len = [0u8; 4];
    conn.read_exact(&mut len).await?;
    let mut buf = vec![0u8; u32::from_be_bytes(len) as usize];
    conn.read_exact(&mut buf).await?;
    Ok(serde_json::from_slice(&buf)?)
}

fn read_pid(path: &Path) -> Option<libc::pid_t> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn per_tenant_daemon_paths_are_isolated() {
    let mut env = TestEnv::new();
    let data_dir = tempfile::tempdir().expect("data dir");
    env.set("MVM_DATA_DIR", data_dir.path());
    env.set("MVM_HOST_AGENT_PATH", HOST_AGENT_BIN);
    env.set("MVM_SIGNER_HELPER_PATH", SIGNER_HELPER_BIN);

    let a = start_tenant(data_dir.path(), "tenant-a").await;
    let b = start_tenant(data_dir.path(), "tenant-b").await;

    // Distinct per-tenant surfaces.
    assert_ne!(a.control_socket, b.control_socket, "control sockets must differ");
    assert_ne!(a.chain, b.chain, "workload chains must differ");
    assert_ne!(a.worker_pid_path, b.worker_pid_path, "worker pid files must differ");
    assert_ne!(read_pid(&a.worker_pid_path), None);
    assert_ne!(read_pid(&a.worker_pid_path), read_pid(&b.worker_pid_path));

    // An emit to A's broker lands in A's chain only.
    assert!(matches!(emit(&a.broker_socket, "a-only").await.unwrap(), ServiceResponse::Ok { .. }));
    let key = host_keypair::load_or_init_at(&config::mvm_keys_dir()).unwrap().verifying;
    assert_eq!(verify_workload_chain(&a.chain, &key).unwrap(), 1, "A chain has the entry");
    assert!(!b.chain.exists() || verify_workload_chain(&b.chain, &key).unwrap() == 0,
        "B chain must not receive A's emit");

    deregister_vm(&a.control_socket, &a.key_bytes, &a.vm).expect("dereg a");
    deregister_vm(&b.control_socket, &b.key_bytes, &b.vm).expect("dereg b");
}
```

- [ ] **Step 2: Run it to verify behavior**

Run: `cargo nextest run -p mvm-hostd --test per_tenant_isolation`
Expected: PASS. If the two tenants collide on any path/socket (an assertion fires), that is a real per-tenant-isolation defect — stop and report it; do not relax the assertion.

Note on environment: `mvm-backend` unit-test binaries SIGKILL under macOS amfid codesign (`reference_mvm_backend_test_binary_macos_codesign_sigkill`); this is an `mvm-hostd` integration test and is unaffected, but if running the whole suite locally on macOS use `-E 'not package(mvm-backend)'`.

- [ ] **Step 3: Commit**

```bash
git add crates/mvm-hostd/tests/per_tenant_isolation.rs
git commit -m "test(plan-205): per-tenant daemon socket/chain isolation (WS-A)"
```

---

### Task 3: Trust-gradient ledger + `xtask check-trust-gradient` (capstone)

A machine-checked ledger ties the gradient together. It asserts (1) tier ranks strictly decrease host→workload, (2) the workload row forbids `signing-key`, `plan-admission`, and `audit-writer`, and (3) every witness token resolves on disk — reusing `check-claim-catalog`'s `fn:`/`ci:` resolution. Witnesses are the gates from Tasks 1 and 2, so this capstone is green only once they exist.

**Files:**
- Create: `specs/claims/trust-gradient.md`
- Create: `xtask/src/check_trust_gradient.rs`
- Modify: `xtask/src/main.rs:26` (module list) and `xtask/src/main.rs:97-100` (dispatch) and the help/error strings
- Modify: `.github/workflows/ci.yml` (the lint job that already runs `check-claim-catalog`)

**Interfaces:**
- Consumes: `anyhow::{Context, Result, bail}`; the `fn NAME(` / workflow-literal resolution semantics from `xtask/src/check_claim_catalog.rs`.
- Produces: subcommand `check-trust-gradient` with `pub fn run(workspace: &Path) -> anyhow::Result<()>`.

- [ ] **Step 1: Write the ledger**

Create `specs/claims/trust-gradient.md`:

```markdown
# Trust gradient ledger

Machine-checked by `xtask check-trust-gradient`. Authority and resident weight
decrease monotonically host → builder → workload. No daemon may hold authority
below its tier; `signing-key`, `plan-admission`, and `audit-writer` never exist
below the host. The builder row is added once the resident builder daemon binary
exists.

| Tier | Layer | Daemon | Forbidden authorities | Witnesses |
| --- | --- | --- | --- | --- |
| 2 | host | control-daemon | (none — holds all authority) | fn:per_tenant_daemon_paths_are_isolated |
| 0 | workload | guest-agent | signing-key, plan-admission, audit-writer, do-exec, console | ci:prod-agent-no-authority, ci:prod-agent-runentry-contract, ci:prod-agent-no-console |
```

- [ ] **Step 2: Write the failing test (drives the check module into existence)**

Create `xtask/src/check_trust_gradient.rs` with the test first, then run it to see it fail to compile (no `run`/`parse_rows` yet):

```rust
//! `xtask check-trust-gradient`
//!
//! Asserts the trust-gradient ledger stays true: tier ranks strictly decrease
//! down the layers, the workload row forbids the host-only authorities, and
//! every named witness still exists in the tree.

use anyhow::{Context, Result, bail};
use std::path::Path;

const REQUIRED_WORKLOAD_FORBIDDEN: [&str; 3] = ["signing-key", "plan-admission", "audit-writer"];

#[cfg(test)]
mod tests {
    use super::*;

    fn rows(md: &str) -> Vec<Row> {
        parse_rows(md).expect("parse")
    }

    #[test]
    fn monotonic_tiers_pass() {
        let md = "| Tier | Layer | Daemon | Forbidden authorities | Witnesses |\n\
                  | --- | --- | --- | --- | --- |\n\
                  | 2 | host | control-daemon | (none) | fn:foo |\n\
                  | 0 | workload | guest-agent | signing-key, plan-admission, audit-writer | ci:bar |\n";
        let mut errs = Vec::new();
        structural_checks(&rows(md), &mut errs);
        assert!(errs.is_empty(), "{errs:?}");
    }

    #[test]
    fn non_decreasing_tiers_fail() {
        let md = "| Tier | Layer | Daemon | Forbidden authorities | Witnesses |\n\
                  | --- | --- | --- | --- | --- |\n\
                  | 0 | host | control-daemon | (none) | fn:foo |\n\
                  | 2 | workload | guest-agent | signing-key, plan-admission, audit-writer | ci:bar |\n";
        let mut errs = Vec::new();
        structural_checks(&rows(md), &mut errs);
        assert!(errs.iter().any(|e| e.contains("monotonic")), "{errs:?}");
    }

    #[test]
    fn workload_missing_forbidden_authority_fails() {
        let md = "| Tier | Layer | Daemon | Forbidden authorities | Witnesses |\n\
                  | --- | --- | --- | --- | --- |\n\
                  | 2 | host | control-daemon | (none) | fn:foo |\n\
                  | 0 | workload | guest-agent | signing-key | ci:bar |\n";
        let mut errs = Vec::new();
        structural_checks(&rows(md), &mut errs);
        assert!(errs.iter().any(|e| e.contains("plan-admission")), "{errs:?}");
    }
}
```

Run: `cargo test -p xtask --lib check_trust_gradient 2>&1 | head`
Expected: FAIL — `cannot find function parse_rows` / `structural_checks` / type `Row`.

- [ ] **Step 3: Implement the check to make the tests pass**

Add above the `#[cfg(test)]` module in `xtask/src/check_trust_gradient.rs`:

```rust
pub fn run(workspace: &Path) -> Result<()> {
    let path = workspace.join("specs").join("claims").join("trust-gradient.md");
    let source =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let rows = parse_rows(&source).with_context(|| format!("parsing {}", path.display()))?;

    let mut errors: Vec<String> = Vec::new();
    structural_checks(&rows, &mut errors);

    for row in &rows {
        for token in &row.witnesses {
            if !witness_exists(workspace, token)? {
                errors.push(format!("{}: witness `{token}` not found in the tree", row.layer));
            }
        }
    }

    if !errors.is_empty() {
        for e in &errors {
            eprintln!("[error] {e}");
        }
        bail!("check-trust-gradient: {} problem(s) in specs/claims/trust-gradient.md", errors.len());
    }
    eprintln!("check-trust-gradient: clean ({} rows)", rows.len());
    Ok(())
}

pub(crate) struct Row {
    tier: i64,
    layer: String,
    forbidden: Vec<String>,
    witnesses: Vec<String>,
}

pub(crate) fn parse_rows(md: &str) -> Result<Vec<Row>> {
    let mut rows = Vec::new();
    for line in md.lines() {
        let line = line.trim();
        if !line.starts_with('|') {
            continue;
        }
        let cells: Vec<String> = line.trim_matches('|').split('|').map(|c| c.trim().to_string()).collect();
        if cells.len() != 5 || cells[0].eq_ignore_ascii_case("tier") || cells[0].starts_with("---") {
            continue;
        }
        let tier: i64 = cells[0].parse().with_context(|| format!("tier `{}` not an integer", cells[0]))?;
        let split = |s: &str| -> Vec<String> {
            s.split(',').map(|t| t.trim().to_string()).filter(|t| !t.is_empty() && !t.starts_with("(none")).collect()
        };
        rows.push(Row {
            tier,
            layer: cells[1].clone(),
            forbidden: split(&cells[3]),
            witnesses: split(&cells[4]),
        });
    }
    if rows.is_empty() {
        bail!("no ledger rows parsed");
    }
    Ok(rows)
}

pub(crate) fn structural_checks(rows: &[Row], errors: &mut Vec<String>) {
    for pair in rows.windows(2) {
        if pair[1].tier >= pair[0].tier {
            errors.push(format!(
                "tiers must be monotonic decreasing: `{}` (tier {}) is not below `{}` (tier {})",
                pair[1].layer, pair[1].tier, pair[0].layer, pair[0].tier
            ));
        }
    }
    if let Some(workload) = rows.iter().find(|r| r.layer == "workload") {
        for required in REQUIRED_WORKLOAD_FORBIDDEN {
            if !workload.forbidden.iter().any(|f| f == required) {
                errors.push(format!("workload row must forbid `{required}`"));
            }
        }
    } else {
        errors.push("ledger has no `workload` row".to_string());
    }
}

fn witness_exists(workspace: &Path, token: &str) -> Result<bool> {
    if let Some(name) = token.strip_prefix("fn:") {
        let needle = format!("fn {name}(");
        return Ok(grep_tree(&workspace.join("crates"), &needle)? || grep_tree(workspace, &needle)?);
    }
    if let Some(name) = token.strip_prefix("ci:") {
        return grep_tree(&workspace.join(".github").join("workflows"), name);
    }
    bail!("unknown witness token `{token}` (expected fn: or ci:)")
}

fn grep_tree(root: &Path, needle: &str) -> Result<bool> {
    if !root.exists() {
        return Ok(false);
    }
    for entry in walkdir(root)? {
        if let Ok(text) = std::fs::read_to_string(&entry) {
            if text.contains(needle) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn walkdir(root: &Path) -> Result<Vec<std::path::PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).with_context(|| format!("reading {}", dir.display()))? {
            let path = entry?.path();
            if path.is_dir() {
                if path.file_name().is_some_and(|n| n == "target") {
                    continue;
                }
                stack.push(path);
            } else {
                out.push(path);
            }
        }
    }
    Ok(out)
}
```

Run: `cargo test -p xtask --lib check_trust_gradient`
Expected: PASS (3 tests).

- [ ] **Step 4: Register the subcommand**

In `xtask/src/main.rs`: add `mod check_trust_gradient;` in the module list (alphabetical, after `check_spec_numbers` at line ~25); add a dispatch arm beside `check-claim-catalog` (~line 97):

```rust
        Some("check-trust-gradient") => {
            let workspace = workspace_root();
            check_trust_gradient::run(&workspace)
        }
```

Append `check-trust-gradient` to the `Available:` string at line ~123, and add a help line in the `None =>` block beside the other `check-*` lines.

- [ ] **Step 5: Run the check against the real ledger**

Run: `cargo run -p xtask -- check-trust-gradient`
Expected: `check-trust-gradient: clean (2 rows)`. (Tasks 1 and 2 must be landed first so `ci:prod-agent-no-authority` and `fn:per_tenant_daemon_paths_are_isolated` resolve. If a witness is missing, the check names it — land the missing gate, do not delete the row.)

- [ ] **Step 6: Wire CI**

Grep `.github/workflows/ci.yml` for `check-claim-catalog`; add `cargo run -p xtask -- check-trust-gradient` as the next step in that same lint job, copying the surrounding step's shape.

- [ ] **Step 7: Final gates + commit**

```bash
cargo fmt --all
cargo clippy -p xtask --all-targets -- -D warnings
cargo nextest run -p xtask
git add specs/claims/trust-gradient.md xtask/src/check_trust_gradient.rs xtask/src/main.rs .github/workflows/ci.yml
git commit -m "feat(plan-205): machine-checked trust-gradient ledger via xtask check-trust-gradient (WS-A)"
```

---

## Deferred (one-step follow-up once Plan 204 lands `mvm-builderd`)

- Add `scripts/check-builderd-no-authority.sh` (same shape as Task 1, target `mvm-builderd`, assert `load_host_signing_key` / `admit_for_run` absent); wire a `builderd-no-authority` security.yml lane.
- Add the builder row to `specs/claims/trust-gradient.md`: `| 1 | builder | mvm-builderd | signing-key, plan-admission, audit-writer | ci:builderd-no-authority |`. The monotonic check (2 > 1 > 0) and witness resolution then cover all three daemons.

## Sequencing for the rest of Plan 205 (not built here)

- **WS-B (residency policy)** needs the Plan 118 standby-pool surface; buildable next, independent of Plan 204.
- **WS-C (resident `mvm-builderd`)** is blocked on Plan 204 merging (parallel worktree `mvm-204-protocol`).
- **WS-D (snapshot park/resume)** needs Plan 159 (Vz) landed and Plan 175 (FC) for the Firecracker leg.
- **WS-E/F** follow D and the above.

## Self-Review

- **Spec coverage (Plan 205 WS-A bullets):** "codify the invariant in arch docs" → ADR-090 + the ledger (Task 3); "workload guest image has no key/admission/prod do_exec/console" → Task 1 (key/admission) + existing `prod-agent-no-exec`/`prod-agent-no-console` lanes referenced as ledger witnesses; "host control daemon stays per-tenant" → Task 2. "builder daemon links no key/admission" → explicitly deferred to the post-Plan-204 follow-up (binary does not exist yet). No silent gaps.
- **Placeholder scan:** none — every step has real bash/Rust/YAML or a precise, locatable instruction.
- **Type consistency:** the witness tokens in the ledger (`ci:prod-agent-no-authority`, `fn:per_tenant_daemon_paths_are_isolated`) match the CI lane name in Task 1 and the test fn name in Task 2 exactly; `run`/`parse_rows`/`structural_checks`/`Row` names are consistent between the test and the implementation.
