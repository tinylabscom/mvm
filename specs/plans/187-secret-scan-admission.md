# Plan 187 — Secret-scan admission gate (ADR-080 P7) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Close ADR-080 §5 / precondition P7 host-side: scan a recording for embedded **raw** secret material (env literals, argv, and the *decoded* bytes of every `FilesWrite`) using the existing Plan 129 `SecretsScanner`, and **hard-refuse** `run --mode plan` admission when any is found — the fix is a `SecretRef`, never an acknowledgement. `compile` warns (dev). Reuses the existing scanner; **no new dependency**.

**Architecture:** A new pure-ish module `crates/mvm-cli/src/commands/build/trace_secret_scan.rs` walks a `mvm_sdk::runtime::RuntimeRecording`, scanning every place raw bytes can hide (decoding `FilesWrite` base64 so a secret written to a file is caught, not just env vars). `SecretRef` env values are skipped by design — they carry no raw value. The scan runs inside `load_recording`/`auto_exec_record_script` (which already parse the recording), populating a new `LoadedRecording.secret_findings`. `run --mode plan` refuses on any finding before the admission loop; `compile` prints warnings. mvm-cli already depends on both `mvm-hostd` (the scanner) and `mvm-sdk` (the recording type), so this needs no cross-crate plumbing.

**Tech Stack:** Rust; existing deps only — `mvm_hostd::supervisor::secrets_scanner::SecretsScanner` (`pub`, confirmed at `crates/mvm-hostd/src/supervisor/mod.rs:78`; `scan(&[u8]) -> Vec<&'static str>` returns matched rule names, `with_default_rules()` builds the curated 17-vendor ruleset), `base64` (already used in the SDK lowering). `cargo nextest`.

**Plan number:** 187 (186 = trace-hardening, this stack's predecessor; 185 = idiomatic-rust-hygiene). Run `cargo run -p xtask -- check-spec-numbers` before merge.

**Branching:** Branch `feat/plan-187-secret-scan-admission` **stacks on `feat/plan-186-trace-hardening` (PR #809)** — it extends the same `load_recording` / `run --mode plan` gate surface #809 introduced. Worktree: `/Users/auser/work/tinylabs/mvmco/mvm-187-secretscan` (already created off the 186 branch). Merge order: #801 → #809 → this. If #809 merges first, rebase onto its merge commit.

**Existing code this plan builds on (read before starting):**
- `crates/mvm-hostd/src/supervisor/secrets_scanner.rs` — `SecretsScanner::with_default_rules()`, `scan(&self, body: &[u8]) -> Vec<&'static str>` (names of matched rules; empty = clean). `DEFAULT_RULES` includes `aws_access_key_id` = `AKIA[0-9A-Z]{16}`, `openai_api_key` = `sk-[A-Za-z0-9]{48}`, `github_personal_access_token` = `ghp_[A-Za-z0-9]{36}` (use these shapes for test fixtures).
- `crates/mvm-sdk/src/runtime.rs` — `RuntimeRecording { workload_id, create: SandboxCreate, ops: Vec<RecordedOp> }`; `SandboxCreate.env: BTreeMap<String, EnvValue>`; `RecordedOp::CommandStart { argv: Vec<String>, env: BTreeMap<String, EnvValue> }` / `FilesWrite { path, bytes_b64 }` / `Kill`. `EnvValue` (re-exported via `mvm_sdk::ir` — confirm the exact path by reading runtime.rs's `use`) has `Literal { value: String }` and `SecretRef { .. }`.
- `crates/mvm-cli/src/commands/build/sandbox_record.rs` — `LoadedRecording { workload, findings, digest_hex }` and `load_recording(path, expected_sha256)` (parses `recording: RuntimeRecording` then lowers — the scan site is right after the parse). `auto_exec_record_script` returns `LoadedRecording`. The module is `pub(in crate::commands)`.
- `crates/mvm-cli/src/commands/vm/run_plan.rs` — `run_plan_mode` calls `auto_exec_record_script` then `require_acknowledged(&findings, &args.ack_divergence)?` before the `for app in &workload.apps { admit_for_run(...) }` loop. The secret gate goes here, BEFORE `require_acknowledged` (secrets are the harder failure; surface first).
- `crates/mvm-cli/src/commands/build/compile.rs` — loads via `load_recording`/auto-exec, prints divergence findings as warnings; add the secret-warning print beside it.

---

### Task 1: the scan — `scan_recording_for_secrets`

**Files:**
- Create: `crates/mvm-cli/src/commands/build/trace_secret_scan.rs`
- Modify: `crates/mvm-cli/src/commands/build/mod.rs` (add `pub(in crate::commands) mod trace_secret_scan;` — read the file to match its `mod` declaration style)

- [x] **Step 1: Write the failing tests.** Create the module with the test block first:

```rust
//! Host-side secret scan over a runtime recording.
//!
//! A recording is the Tier-0 promotion input; a raw secret embedded
//! in it (an env literal, a command argument, or the bytes of a
//! written file) would ride into the workload definition and defeat
//! the host-substitution posture where raw secrets never reach the
//! guest. This walks every place raw bytes can hide — decoding the
//! base64 of each `FilesWrite` so a secret written to a config file
//! is caught, not just env vars — and reports findings. `SecretRef`
//! values are skipped: they carry a reference, never a raw value.

use base64::Engine;
use mvm_hostd::supervisor::secrets_scanner::SecretsScanner;
use mvm_sdk::ir::EnvValue;
use mvm_sdk::runtime::{RecordedOp, RuntimeRecording, SandboxCreate};
use std::collections::BTreeMap;

#[cfg(test)]
mod tests {
    use super::*;

    fn scanner() -> SecretsScanner {
        SecretsScanner::with_default_rules()
    }

    fn lit(v: &str) -> EnvValue {
        EnvValue::Literal { value: v.to_string() }
    }

    fn empty_create() -> SandboxCreate {
        SandboxCreate {
            template: "minimal".to_string(),
            env: BTreeMap::new(),
            include: Vec::new(),
            tags: BTreeMap::new(),
            ttl_seconds: None,
            resources: None,
            network: None,
        }
    }

    fn rec(create: SandboxCreate, ops: Vec<RecordedOp>) -> RuntimeRecording {
        RuntimeRecording { workload_id: "wl".to_string(), create, ops }
    }

    fn start(argv: &[&str], env: BTreeMap<String, EnvValue>) -> RecordedOp {
        RecordedOp::CommandStart {
            argv: argv.iter().map(|s| s.to_string()).collect(),
            env,
        }
    }

    // A realistic-shaped fake AWS key (AKIA + 16 upper/digits) and
    // OpenAI key (sk- + 48 alnum). These are not real credentials —
    // they match the DEFAULT_RULES regex shapes.
    const FAKE_AWS: &str = "AKIAIOSFODNN7EXAMPLE";
    const FAKE_OPENAI: &str =
        "sk-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV";

    #[test]
    fn clean_recording_has_no_findings() {
        let r = rec(empty_create(), vec![start(&["/bin/true"], BTreeMap::new())]);
        assert!(scan_recording_for_secrets(&r, &scanner()).is_empty());
    }

    #[test]
    fn create_env_literal_secret_is_flagged() {
        let mut env = BTreeMap::new();
        env.insert("AWS_ACCESS_KEY_ID".to_string(), lit(FAKE_AWS));
        let r = rec(
            SandboxCreate { env, ..empty_create() },
            vec![start(&["/bin/true"], BTreeMap::new())],
        );
        let f = scan_recording_for_secrets(&r, &scanner());
        assert_eq!(f.len(), 1);
        assert!(f[0].location.contains("AWS_ACCESS_KEY_ID"));
        assert!(f[0].rules.iter().any(|r| r == "aws_access_key_id"));
    }

    #[test]
    fn argv_secret_is_flagged() {
        let r = rec(
            empty_create(),
            vec![start(&["/bin/run", &format!("--key={FAKE_OPENAI}")], BTreeMap::new())],
        );
        let f = scan_recording_for_secrets(&r, &scanner());
        assert_eq!(f.len(), 1);
        assert!(f[0].location.contains("argv"));
        assert!(f[0].rules.iter().any(|r| r == "openai_api_key"));
    }

    #[test]
    fn files_write_decoded_secret_is_flagged() {
        // The secret is base64-encoded inside the recording — proving
        // the scan must decode, not scan the b64 surface.
        let body = format!("OPENAI_API_KEY={FAKE_OPENAI}\n");
        let b64 = base64::engine::general_purpose::STANDARD.encode(body.as_bytes());
        let r = rec(
            empty_create(),
            vec![
                RecordedOp::FilesWrite { path: "/app/.env".to_string(), bytes_b64: b64 },
                start(&["/bin/true"], BTreeMap::new()),
            ],
        );
        let f = scan_recording_for_secrets(&r, &scanner());
        assert_eq!(f.len(), 1, "decoded file content secret must be caught");
        assert!(f[0].location.contains("/app/.env"));
    }

    #[test]
    fn secret_ref_value_is_not_flagged() {
        // A SecretRef carries a reference, not raw bytes — it is the
        // CORRECT way to use a secret and must never be flagged.
        let mut env = BTreeMap::new();
        env.insert("TOKEN".to_string(), secret_ref_env());
        let r = rec(
            SandboxCreate { env, ..empty_create() },
            vec![start(&["/bin/true"], BTreeMap::new())],
        );
        assert!(scan_recording_for_secrets(&r, &scanner()).is_empty());
    }

    #[test]
    fn op_env_literal_secret_reports_op_index() {
        let mut env = BTreeMap::new();
        env.insert("GH".to_string(), lit("ghp_abcdefghijklmnopqrstuvwxyz0123456789"));
        let r = rec(empty_create(), vec![start(&["/bin/true"], env)]);
        let f = scan_recording_for_secrets(&r, &scanner());
        assert_eq!(f.len(), 1);
        assert!(f[0].location.contains("op#0"));
    }

    // Build a SecretRef EnvValue. The exact constructor depends on the
    // SecretRef type's shape — read mvm_sdk::ir and build a minimal
    // valid SecretRef here. If SecretRef requires fields, supply the
    // simplest valid value.
    fn secret_ref_env() -> EnvValue {
        // IMPLEMENTER: construct EnvValue::SecretRef { reference: <minimal SecretRef> }.
        // Read crates/mvm-sdk/src/ir/workload.rs for SecretRef's fields.
        unimplemented!("build a minimal EnvValue::SecretRef — see comment")
    }
}
```

**IMPLEMENTER NOTE:** replace the `secret_ref_env()` stub with a real minimal `EnvValue::SecretRef { .. }` once you've read `SecretRef`'s definition in `crates/mvm-sdk/src/ir/`. The test asserts SecretRef is NOT scanned — it must construct a valid one.

- [x] **Step 2: Run to verify failure.** `cargo nextest run -p mvm-cli trace_secret_scan` — compile error (`scan_recording_for_secrets`, `SecretFinding` not found).

- [x] **Step 3: Implement** (above the test module):

```rust
/// One location in a recording carrying raw secret-shaped material.
pub(in crate::commands) struct SecretFinding {
    /// Human-pointable location, e.g. `create env[AWS_ACCESS_KEY_ID]`,
    /// `op#2 argv[1]`, `op#3 file /app/.env`.
    pub location: String,
    /// Names of the `SecretsScanner` rules that matched.
    pub rules: Vec<String>,
}

/// Scan a recording for embedded **raw** secret material — env
/// literals, command argv, and the decoded bytes of every
/// `FilesWrite`. `SecretRef` values are skipped (they carry no raw
/// value). A non-empty result refuses promotion; the fix is to use a
/// `SecretRef`, not to acknowledge.
pub(in crate::commands) fn scan_recording_for_secrets(
    rec: &RuntimeRecording,
    scanner: &SecretsScanner,
) -> Vec<SecretFinding> {
    let mut out = Vec::new();
    scan_env(scanner, "create", &rec.create.env, &mut out);
    for (idx, op) in rec.ops.iter().enumerate() {
        match op {
            RecordedOp::CommandStart { argv, env } => {
                for (i, arg) in argv.iter().enumerate() {
                    push_if_hit(scanner, format!("op#{idx} argv[{i}]"), arg.as_bytes(), &mut out);
                }
                scan_env(scanner, &format!("op#{idx}"), env, &mut out);
            }
            RecordedOp::FilesWrite { path, bytes_b64 } => {
                // Decode so a secret written to a file is caught; a
                // malformed b64 is the lowering's problem, skip here.
                if let Ok(decoded) =
                    base64::engine::general_purpose::STANDARD.decode(bytes_b64)
                {
                    push_if_hit(scanner, format!("op#{idx} file {path}"), &decoded, &mut out);
                }
            }
            RecordedOp::Kill => {}
        }
    }
    out
}

/// Scan the `Literal` values of an env map; `SecretRef` values are
/// skipped by design.
fn scan_env(
    scanner: &SecretsScanner,
    ctx: &str,
    env: &BTreeMap<String, EnvValue>,
    out: &mut Vec<SecretFinding>,
) {
    for (key, val) in env {
        if let EnvValue::Literal { value } = val {
            push_if_hit(scanner, format!("{ctx} env[{key}]"), value.as_bytes(), out);
        }
    }
}

/// Run the scanner over `body`; push a finding only when it matches.
fn push_if_hit(scanner: &SecretsScanner, location: String, body: &[u8], out: &mut Vec<SecretFinding>) {
    let hits = scanner.scan(body);
    if !hits.is_empty() {
        out.push(SecretFinding {
            location,
            rules: hits.into_iter().map(|s| s.to_string()).collect(),
        });
    }
}
```

- [x] **Step 4: Verify pass.** `cargo nextest run -p mvm-cli trace_secret_scan` — 6 tests green. `cargo clippy -p mvm-cli -- -D warnings`, `cargo fmt --all`.

- [x] **Step 5: Commit**

```bash
git add crates/mvm-cli/src/commands/build/trace_secret_scan.rs crates/mvm-cli/src/commands/build/mod.rs
git commit -m "feat(cli): scan runtime recordings for embedded raw secrets (plan 187 P7)"
```

---

### Task 2: thread into load + the hard-refuse admission gate

**Files:**
- Modify: `crates/mvm-cli/src/commands/build/sandbox_record.rs`
- Modify: `crates/mvm-cli/src/commands/vm/run_plan.rs`
- Modify: `crates/mvm-cli/src/commands/build/compile.rs`

- [x] **Step 1: `LoadedRecording` carries findings.** Add `pub secret_findings: Vec<crate::commands::build::trace_secret_scan::SecretFinding>` to `LoadedRecording`. In `load_recording`, after the `recording` is parsed (and before/after lowering — it needs `&recording`), add:

```rust
    let secret_findings = crate::commands::build::trace_secret_scan::scan_recording_for_secrets(
        &recording,
        &mvm_hostd::supervisor::secrets_scanner::SecretsScanner::with_default_rules(),
    );
```

and include `secret_findings` in the returned `LoadedRecording { .. }`. (Constructing the scanner per load compiles the ruleset once per CLI invocation — fine.)

- [x] **Step 2: the gate (TDD the pure part first).** In `run_plan.rs`, add a pure refuse function + 3 unit tests (write tests first):

```rust
    #[test]
    fn secret_gate_passes_with_no_findings() {
        assert!(refuse_embedded_secrets(&[]).is_ok());
    }

    #[test]
    fn secret_gate_refuses_any_finding() {
        let findings = vec![crate::commands::build::trace_secret_scan::SecretFinding {
            location: "create env[AWS]".to_string(),
            rules: vec!["aws_access_key_id".to_string()],
        }];
        let err = refuse_embedded_secrets(&findings).unwrap_err();
        assert!(err.to_string().contains("SecretRef"));
    }

    #[test]
    fn secret_gate_is_not_acknowledgeable() {
        // Unlike divergence, there is no ack path — the message must
        // direct the user to remove the secret, not accept it.
        let findings = vec![crate::commands::build::trace_secret_scan::SecretFinding {
            location: "op#0 file /app/.env".to_string(),
            rules: vec!["openai_api_key".to_string()],
        }];
        let msg = refuse_embedded_secrets(&findings).unwrap_err().to_string();
        assert!(!msg.contains("--ack"), "secret refusal must not offer an ack escape hatch");
    }
```

Implementation:

```rust
use crate::commands::build::trace_secret_scan::SecretFinding;

/// Refuse promotion when a recording carries raw secret material.
/// Unlike a divergence finding, this is NOT acknowledgeable — a raw
/// secret in the workload definition defeats the host-substitution
/// posture, and the only fix is to replace the literal with a
/// `SecretRef`.
fn refuse_embedded_secrets(findings: &[SecretFinding]) -> Result<()> {
    if findings.is_empty() {
        return Ok(());
    }
    for f in findings {
        eprintln!("EMBEDDED SECRET: {} matched [{}]", f.location, f.rules.join(", "));
    }
    bail!(
        "refusing plan-mode admission: {} location(s) carry raw secret-shaped material. \
         Replace each literal with a SecretRef so the value substitutes host-side and never \
         enters the workload definition. This is not acknowledgeable — remove the secret.",
        findings.len()
    )
}
```

Wire into `run_plan_mode`: after the `LoadedRecording` is obtained and the digest printed, call `refuse_embedded_secrets(&loaded.secret_findings)?` **before** `require_acknowledged(...)`. (Read the current destructuring of the `LoadedRecording` and adapt — bind `secret_findings` out of it.)

- [x] **Step 3: compile warns.** In `compile.rs`, where divergence findings are printed as warnings, add a sibling loop over `loaded.secret_findings` printing `eprintln!("warning: embedded secret at {} [{}]", f.location, f.rules.join(", "))`. Compile is the dev shape-check verb — warn-only, parallel to its divergence handling.

- [x] **Step 4: behavior test.** Add an integration-style test (or extend an existing run_plan test) proving a recording with an embedded secret is refused. If `run_plan_mode` is hard to drive without a real interpreter, instead add a focused test that builds a `LoadedRecording`-shaped input through `scan_recording_for_secrets` + `refuse_embedded_secrets` and asserts the refusal — the gate composition is what matters. Prefer reusing the existing run_plan test harness pattern.

- [x] **Step 5: Verify + commit.** `cargo nextest run -p mvm-cli 2>&1 | tail -5` (all green; gate tests among them), `cargo clippy -p mvm-cli -- -D warnings`, `cargo fmt --all`.

```bash
git add crates/mvm-cli/src/commands
git commit -m "feat(cli): hard-refuse plan-mode admission on embedded secrets (plan 187 P7)"
```

---

### Task 3: gates + spec bookkeeping + PR

**Files:**
- Modify: `specs/adrs/080-wasm-preview-promotion-and-capability-policy.md` (§8 P7 row + §5 note)
- Modify: `specs/REFACTOR-STATUS.md`
- Modify: `specs/plans/187-secret-scan-admission.md` (tick boxes)

- [x] **Step 1: full gates** (environmental caveats as before: mvm-backend codesign SIGKILL; embedded-binary ELF test under skip-embed):

```bash
cd /Users/auser/work/tinylabs/mvmco/mvm-187-secretscan
cargo fmt --all -- --check || rustup run nightly cargo fmt --all
MVM_SKIP_EMBED_BINARIES=1 cargo nextest run --workspace 2>&1 | tail -6
MVM_SKIP_EMBED_BINARIES=1 cargo test --workspace --doc 2>&1 | tail -5
MVM_SKIP_EMBED_BINARIES=1 cargo clippy --workspace -- -D warnings 2>&1 | tail -6
cargo run -p xtask -- check-spec-numbers 2>&1 | tail -3
```

- [x] **Step 2: ADR-080 §8 P7 row.** Replace the P7 row (adapt to the table's current form):

```markdown
| P7 | Secret-scan admission (§5) | `scan_recording_for_secrets` (env literals + argv + decoded FilesWrite payloads, mvm-cli) + `refuse_embedded_secrets` hard-refuses `run --mode plan` (not acknowledgeable); reuses the Plan 129 `SecretsScanner`; `create_env_literal_secret_is_flagged` / `files_write_decoded_secret_is_flagged` / `secret_ref_value_is_not_flagged` / `secret_gate_refuses_any_finding` — landed by Plan 187. Paste-time detector deferred with the browser preview tier (no host preview surface yet). |
```

Also amend the §5 prose line that calls the scanner a precondition ("This scan is a §8 precondition: the promotion path does not enable without it") to note it has now landed for the `run --mode plan` path.

- [x] **Step 3: REFACTOR-STATUS** — add Plan 187 (glance + detail): P7 admission scan landed (recording env/argv/file-payload, hard refusal on run --mode plan); paste-time deferred with preview tier. Bump "Last updated".

- [x] **Step 4: tick this plan's boxes. Step 5: commit**

```bash
git add specs/
git commit -m "docs(specs): record plan 187 secret-scan admission (ADR-080 P7) (plan 187)"
```

---

## Out of scope (deliberately)

- **Paste-time detection** — the browser/SDK preview input path doesn't exist yet (deferred with the Tier-0 preview tier).
- **`compile` refusal** — compile is the dev shape-check verb; it warns. Only `run --mode plan` (the promotion-shaped path) hard-refuses.
- **Entropy/heuristic secret detection** — this uses the existing curated `DEFAULT_RULES` (known vendor token shapes); broader detection is a scanner-side concern, not this gate's.
- Other ADR-080 rows: P6 (component digest carry), P8 (relay session binding), full P2 (declarative materialization), and the kernel-side `CanonicalEgress` wiring (half-blocked on host-side DNS pins; carries a claim-10 whole-policy-fail-closed semantic decision — its own plan + maintainer call).
