# Plan 186 — Trace hardening: ADR-080 P1 + P3 + P4 (+ interim P2 pin) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden the SDK record-mode trace (the Tier-0 promotion input) per ADR-080 §8: structural limits + duplicate refusal + fuzz target (P1), the base64-`STANDARD`-alphabet injection pin (interim P2), content-digest verification of recording bytes (P3), and divergence findings that block plan-mode admission unless explicitly acknowledged (P4).

**Architecture:** All decision logic lands in `mvm-sdk::runtime` (pure, testable): limits validated at the top of `compile_recording`, a `Divergence` findings vocabulary returned by a new `compile_recording_with_findings` (plain `compile_recording` delegates and stays back-compat), and digest helpers over raw recording bytes. `mvm-cli` threads it through: `load_recording` returns `{workload, findings, digest}` with a byte-size cap, `compile --from-recording` gains `--recording-sha256`, and `run --mode plan` — the existing promotion-shaped admission path — refuses unacknowledged divergence (`--ack-divergence <kind>` to acknowledge). A new `crates/mvm-sdk/fuzz` harness joins the `security.yml` fuzz lane.

**Tech Stack:** Rust; existing deps only (`serde_json`, `base64`, `thiserror`, `sha2` — verify `sha2` is already an `mvm-sdk` dep; if not, add the workspace-pinned entry). Fuzz via `libfuzzer-sys` in a workspace-excluded crate (established pattern).

**Plan number:** 186 (185 = idiomatic-rust-hygiene, taken by a parallel session; 184 = this branch's predecessor). Run `cargo run -p xtask -- check-spec-numbers` before merge.

**Branching:** This plan's branch `feat/plan-186-trace-hardening` stacks on `feat/plan-184-projection-seam` (PR #801) because it edits ADR-080 §8 rows that only exist there. Code surfaces are disjoint (mvm-sdk/mvm-cli vs mvm-core). Worktree: `/Users/auser/work/tinylabs/mvmco/mvm-186-trace`. If #801 merges first, rebase onto origin/main before opening the PR.

**Existing code this plan builds on (read before starting):**
- `crates/mvm-sdk/src/runtime.rs` — `RuntimeRecording` (:60, `deny_unknown_fields` already present), `SandboxCreate` (:82), `RecordedOp` (:120 — `CommandStart`/`FilesWrite`/`Kill`), `LowerError` (:189 — `UnknownBaseImage`/`NoEntrypoint`/`InvalidFilesWriteB64`), `compile_recording` (:212–315; final `CommandStart` = entrypoint, earlier ones + `FilesWrite` → `before_start` hooks, `Kill` dropped; `FilesWrite` lowers to a `HookCmd::Shell` line interpolating the b64 token inside single quotes — safe only because the `STANDARD` alphabet has no quote), `shell_single_quote` (:320).
- `crates/mvm-cli/src/commands/build/sandbox_record.rs` — `auto_exec_record_script` (:61, returns `Result<Workload>`), `load_recording` (:124).
- `crates/mvm-cli/src/commands/vm/run_plan.rs` — `run_plan_mode` (:161, the admission path: record → lower → `synthesize_plan` → `admit_for_run`), `RunArgs` consumed via `super::exec::{RunArgs, RunMode}` (RunArgs defined in `crates/mvm-cli/src/commands/vm/exec.rs` — read it for the clap attr style before adding a flag).
- `crates/mvm-cli/src/commands/build/compile.rs` — `--from-recording` args (:58–68).
- Fuzz pattern: `crates/mvm-hostd/fuzz/` (standalone `[workspace]`, `[[bin]]` per target) + the `fuzz` job in `.github/workflows/security.yml` (one step per target, `RUSTUP_TOOLCHAIN: nightly`, `-max_total_time="$DURATION"`); root `Cargo.toml` `exclude` list carries every fuzz crate.

---

### Task 1: structural limits + duplicate-path refusal (P1)

**Files:**
- Modify: `crates/mvm-sdk/src/runtime.rs`

- [x] **Step 1: Write the failing tests** (add to runtime.rs's existing test module; reuse its existing fixture helpers if present — read the test module first and adapt fixture construction to what's there):

```rust
    fn start_op(argv: &[&str]) -> RecordedOp {
        RecordedOp::CommandStart {
            argv: argv.iter().map(|s| s.to_string()).collect(),
            env: BTreeMap::new(),
        }
    }

    fn write_op(path: &str, bytes: &[u8]) -> RecordedOp {
        RecordedOp::FilesWrite {
            path: path.to_string(),
            bytes_b64: base64::engine::general_purpose::STANDARD.encode(bytes),
        }
    }

    fn rec_with_ops(ops: Vec<RecordedOp>) -> RuntimeRecording {
        RuntimeRecording {
            workload_id: "wl-limits".to_string(),
            create: SandboxCreate {
                template: "minimal".to_string(),
                env: BTreeMap::new(),
                include: Vec::new(),
                tags: BTreeMap::new(),
                ttl_seconds: None,
                resources: None,
                network: None,
            },
            ops,
        }
    }

    #[test]
    fn too_many_ops_refuses() {
        let mut ops: Vec<RecordedOp> = (0..MAX_RECORDED_OPS).map(|_| RecordedOp::Kill).collect();
        ops.push(start_op(&["/bin/true"]));
        let err = compile_recording(&rec_with_ops(ops)).unwrap_err();
        assert!(matches!(err, LowerError::TooManyOps { .. }), "got {err:?}");
    }

    #[test]
    fn op_count_at_limit_is_accepted() {
        let mut ops: Vec<RecordedOp> =
            (0..MAX_RECORDED_OPS - 1).map(|_| RecordedOp::Kill).collect();
        ops.push(start_op(&["/bin/true"]));
        assert_eq!(ops.len(), MAX_RECORDED_OPS);
        compile_recording(&rec_with_ops(ops)).expect("at-limit recording must lower");
    }

    #[test]
    fn files_write_oversize_refuses() {
        let big = vec![0u8; MAX_FILES_WRITE_DECODED_BYTES + 1];
        let ops = vec![write_op("/app/big.bin", &big), start_op(&["/bin/true"])];
        let err = compile_recording(&rec_with_ops(ops)).unwrap_err();
        assert!(matches!(err, LowerError::FilesWriteTooLarge { .. }), "got {err:?}");
    }

    #[test]
    fn duplicate_files_write_path_refuses() {
        let ops = vec![
            write_op("/app/conf.toml", b"a = 1"),
            write_op("/app/conf.toml", b"a = 2"),
            start_op(&["/bin/true"]),
        ];
        let err = compile_recording(&rec_with_ops(ops)).unwrap_err();
        assert!(matches!(err, LowerError::DuplicateFilesWritePath { .. }), "got {err:?}");
    }
```

- [x] **Step 2: Run to verify failure**

Run: `cargo nextest run -p mvm-sdk runtime` — compile error (`MAX_RECORDED_OPS`, new variants not found).

- [x] **Step 3: Implement.** Module-level constants + a validation pass at the top of `compile_recording`, size check at the existing decode site:

```rust
/// Hard cap on ops per recording. A hand-authored script never
/// approaches this; a runaway loop or adversarial trace does.
pub const MAX_RECORDED_OPS: usize = 1024;

/// Hard cap on one `FilesWrite`'s decoded payload. Larger assets
/// belong in the source bundle or a dependency volume, not inlined
/// in the trace.
pub const MAX_FILES_WRITE_DECODED_BYTES: usize = 8 * 1024 * 1024;
```

New `LowerError` variants:

```rust
    #[error("recording has {count} ops, max {max} — a runaway or adversarial trace, not a script")]
    TooManyOps { count: usize, max: usize },
    #[error("FilesWrite for `{path}` decodes to {decoded} bytes, max {max} — ship large assets via the source bundle, not the trace")]
    FilesWriteTooLarge {
        path: String,
        decoded: usize,
        max: usize,
    },
    #[error("recording writes `{path}` more than once — ambiguous in a declarative scaffold; make the script write each file once")]
    DuplicateFilesWritePath { path: String },
```

At the top of `compile_recording` (before `resolve_base_image`):

```rust
    if rec.ops.len() > MAX_RECORDED_OPS {
        return Err(LowerError::TooManyOps {
            count: rec.ops.len(),
            max: MAX_RECORDED_OPS,
        });
    }
    let mut seen_paths = std::collections::BTreeSet::new();
    for op in &rec.ops {
        if let RecordedOp::FilesWrite { path, .. } = op {
            if !seen_paths.insert(path.clone()) {
                return Err(LowerError::DuplicateFilesWritePath { path: path.clone() });
            }
        }
    }
```

At the existing `FilesWrite` decode site, capture the decoded bytes (currently discarded) and check:

```rust
                let decoded = base64::engine::general_purpose::STANDARD
                    .decode(bytes_b64)
                    .map_err(|error| LowerError::InvalidFilesWriteB64 {
                        path: path.clone(),
                        error,
                    })?;
                if decoded.len() > MAX_FILES_WRITE_DECODED_BYTES {
                    return Err(LowerError::FilesWriteTooLarge {
                        path: path.clone(),
                        decoded: decoded.len(),
                        max: MAX_FILES_WRITE_DECODED_BYTES,
                    });
                }
```

- [x] **Step 4: Verify pass**: `cargo nextest run -p mvm-sdk runtime` — prior tests + 4 new green.

- [x] **Step 5: Commit**

```bash
git add crates/mvm-sdk/src/runtime.rs
git commit -m "feat(sdk): structural limits + duplicate-path refusal on runtime recordings (plan 186 P1)"
```

---

### Task 2: base64 alphabet pin + shell-quoting regression tests (interim P2)

**Files:**
- Modify: `crates/mvm-sdk/src/runtime.rs` (tests only — no production change expected; if a test FAILS, that's a real injection bug: fix production code and report)

- [x] **Step 1: Add the tests:**

```rust
    #[test]
    fn files_write_b64_with_single_quote_refuses() {
        // The lowering interpolates the b64 token inside single
        // quotes in a shell line; the STANDARD alphabet containing
        // no quote character is the property that makes that safe.
        // A decoder/alphabet change that lets a quote through is an
        // injection primitive — this pin must fail loudly first.
        let ops = vec![
            RecordedOp::FilesWrite {
                path: "/app/x".to_string(),
                bytes_b64: "ab'c=".to_string(),
            },
            start_op(&["/bin/true"]),
        ];
        let err = compile_recording(&rec_with_ops(ops)).unwrap_err();
        assert!(matches!(err, LowerError::InvalidFilesWriteB64 { .. }), "got {err:?}");
    }

    #[test]
    fn files_write_b64_url_safe_alphabet_refuses() {
        // URL_SAFE uses `-` and `_`; the lowering is pinned to
        // STANDARD. Accepting both alphabets silently would widen
        // the interpolation surface.
        let ops = vec![
            RecordedOp::FilesWrite {
                path: "/app/x".to_string(),
                bytes_b64: "a-b_".to_string(),
            },
            start_op(&["/bin/true"]),
        ];
        let err = compile_recording(&rec_with_ops(ops)).unwrap_err();
        assert!(matches!(err, LowerError::InvalidFilesWriteB64 { .. }), "got {err:?}");
    }

    #[test]
    fn files_write_hostile_path_is_single_quoted_in_hook() {
        // `shell_single_quote` is the only thing between a hostile
        // path and the generated shell line. Assert the quoted form
        // lands in the hook verbatim and the naked metacharacters
        // do not appear unquoted.
        let hostile = "/app/x'; rm -rf /tmp/pwn; echo '";
        let ops = vec![write_op(hostile, b"x"), start_op(&["/bin/true"])];
        let wl = compile_recording(&rec_with_ops(ops)).expect("must lower");
        let hooks = &wl.apps[0].hooks.before_start;
        let HookCmd::Shell { line } = &hooks[0] else {
            panic!("FilesWrite must lower to a Shell hook, got {hooks:?}");
        };
        // The single-quote escape sequence ('\'') must wrap every
        // embedded quote, leaving no bare `'; rm` breakout.
        assert!(line.contains(r#"'\''"#), "quotes not escaped: {line}");
        assert!(!line.contains("'; rm -rf"), "unescaped breakout: {line}");
    }
```

(Adjust `HookCmd` import if the test module doesn't already have it: `use crate::ir::hooks::HookCmd;` — match the module's existing import paths.)

- [x] **Step 2: Run.** `cargo nextest run -p mvm-sdk runtime` — all three should PASS against current code (they are pins). If any fails, STOP: that is a live injection bug — fix production, report prominently.

- [x] **Step 3: Commit**

```bash
git add crates/mvm-sdk/src/runtime.rs
git commit -m "test(sdk): pin FilesWrite b64 alphabet + shell-quoting against injection (plan 186 interim P2)"
```

---

### Task 3: divergence findings (P4, library half)

**Files:**
- Modify: `crates/mvm-sdk/src/runtime.rs`
- Modify: `crates/mvm-sdk/src/lib.rs` (export `Divergence`, `compile_recording_with_findings` alongside the existing runtime exports — read the existing export line at lib.rs:104 and extend it)

- [x] **Step 1: Write the failing tests:**

```rust
    #[test]
    fn kill_op_yields_divergence_finding() {
        let ops = vec![start_op(&["/bin/true"]), RecordedOp::Kill];
        let (_, findings) =
            compile_recording_with_findings(&rec_with_ops(ops)).expect("must lower");
        assert_eq!(findings.len(), 1);
        assert!(matches!(findings[0], Divergence::KillDropped { op_index: 1 }));
    }

    #[test]
    fn files_write_after_entrypoint_yields_divergence_finding() {
        // The script wrote this file AFTER starting the workload;
        // the replay materializes it BEFORE start. That reordering
        // is a real preview-vs-ship behavior difference.
        let ops = vec![
            start_op(&["/bin/server"]),
            write_op("/app/late.txt", b"late"),
        ];
        let (wl, findings) =
            compile_recording_with_findings(&rec_with_ops(ops)).expect("must lower");
        assert!(matches!(
            &findings[0],
            Divergence::FilesWriteAfterEntrypoint { op_index: 1, path } if path == "/app/late.txt"
        ));
        // Lowering behavior is unchanged: the hook still exists.
        assert_eq!(wl.apps[0].hooks.before_start.len(), 1);
    }

    #[test]
    fn clean_recording_yields_no_findings() {
        let ops = vec![write_op("/app/a.txt", b"a"), start_op(&["/bin/true"])];
        let (_, findings) =
            compile_recording_with_findings(&rec_with_ops(ops)).expect("must lower");
        assert!(findings.is_empty(), "got {findings:?}");
    }

    #[test]
    fn compile_recording_is_findings_agnostic_back_compat() {
        let ops = vec![start_op(&["/bin/true"]), RecordedOp::Kill];
        let rec = rec_with_ops(ops);
        let plain = compile_recording(&rec).expect("plain must lower");
        let (with, _) = compile_recording_with_findings(&rec).expect("must lower");
        assert_eq!(plain, with, "the two entry points must produce identical Workloads");
    }
```

- [x] **Step 2: Verify compile failure. Step 3: Implement:**

```rust
/// One place the trace replay knowingly differs from what the
/// recorded script actually did. Findings do not block lowering —
/// they block *admission* unless explicitly acknowledged, because
/// a preview that ran one way and a ship that behaves another is
/// exactly the dishonesty the promotion gate exists to refuse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Divergence {
    /// A `sb.kill()` was recorded and dropped: the replayed
    /// workload's lifetime is the orchestrator's TTL, not the
    /// script's explicit kill point.
    KillDropped { op_index: usize },
    /// The script wrote this file after starting the entrypoint;
    /// the replay writes it before boot. Anything the entrypoint
    /// did before the write existed will behave differently.
    FilesWriteAfterEntrypoint { op_index: usize, path: String },
}

impl Divergence {
    /// Stable slug used by `--ack-divergence` to acknowledge a
    /// finding class. Kept kebab-case to read naturally on a CLI.
    pub fn kind_slug(&self) -> &'static str {
        match self {
            Self::KillDropped { .. } => "kill-dropped",
            Self::FilesWriteAfterEntrypoint { .. } => "files-write-after-entrypoint",
        }
    }
}

impl std::fmt::Display for Divergence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KillDropped { op_index } => write!(
                f,
                "[kill-dropped] op #{op_index}: sb.kill() is dropped — replay lifetime is the orchestrator's TTL"
            ),
            Self::FilesWriteAfterEntrypoint { op_index, path } => write!(
                f,
                "[files-write-after-entrypoint] op #{op_index}: `{path}` was written after start; replay writes it before boot"
            ),
        }
    }
}
```

Refactor: rename the existing `compile_recording` body to

```rust
pub fn compile_recording_with_findings(
    rec: &RuntimeRecording,
) -> Result<(Workload, Vec<Divergence>), LowerError> {
```

collecting findings in the existing op loop — `RecordedOp::Kill` arm pushes `Divergence::KillDropped { op_index: idx }`; the `FilesWrite` arm pushes `Divergence::FilesWriteAfterEntrypoint { op_index: idx, path: path.clone() }` when `idx > final_cmd_pos`. Then:

```rust
/// Findings-agnostic wrapper kept for callers that only need the
/// Workload (tests, tooling). Admission paths use
/// [`compile_recording_with_findings`] and gate on the findings.
pub fn compile_recording(rec: &RuntimeRecording) -> Result<Workload, LowerError> {
    compile_recording_with_findings(rec).map(|(wl, _)| wl)
}
```

- [x] **Step 4: Verify pass** (`cargo nextest run -p mvm-sdk runtime`), then **Step 5: Commit**

```bash
git add crates/mvm-sdk/src/runtime.rs crates/mvm-sdk/src/lib.rs
git commit -m "feat(sdk): divergence findings on recording lowering (plan 186 P4)"
```

---

### Task 4: recording digest helpers (P3, library half)

**Files:**
- Modify: `crates/mvm-sdk/src/runtime.rs` (verify `sha2` is in `crates/mvm-sdk/Cargo.toml` — it should be, via the compile/addon machinery; if missing add `sha2.workspace = true`)

- [x] **Step 1: Failing tests:**

```rust
    #[test]
    fn recording_digest_is_stable_64_hex() {
        let d = recording_sha256_hex(b"{}");
        assert_eq!(d.len(), 64);
        assert_eq!(d, recording_sha256_hex(b"{}"));
        assert_ne!(d, recording_sha256_hex(b"{} "));
    }

    #[test]
    fn digest_verify_match_passes_mismatch_refuses() {
        let bytes = b"some recording bytes";
        let good = recording_sha256_hex(bytes);
        verify_recording_digest(bytes, &good).expect("matching digest must pass");
        let err = verify_recording_digest(bytes, &recording_sha256_hex(b"other")).unwrap_err();
        assert!(matches!(err, LowerError::DigestMismatch { .. }), "got {err:?}");
    }

    #[test]
    fn digest_verify_is_case_insensitive_on_expected() {
        let bytes = b"case test";
        let upper = recording_sha256_hex(bytes).to_uppercase();
        verify_recording_digest(bytes, &upper).expect("hex case must not matter");
    }
```

- [x] **Step 2: Verify failure. Step 3: Implement:**

```rust
/// SHA-256 of the raw recording bytes, lowercase hex. Captured the
/// moment the recording is read; verified again wherever the bytes
/// cross a tamperable boundary (a file at rest between record and
/// ship is exactly that boundary).
pub fn recording_sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let out = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for b in out {
        hex.push_str(&format!("{b:02x}"));
    }
    hex
}

/// Refuse recording bytes whose digest does not match the expected
/// hex (case-insensitive). Fail-closed: a mismatch means the bytes
/// changed between capture and use.
pub fn verify_recording_digest(bytes: &[u8], expected_hex: &str) -> Result<(), LowerError> {
    let actual = recording_sha256_hex(bytes);
    if !actual.eq_ignore_ascii_case(expected_hex) {
        return Err(LowerError::DigestMismatch {
            expected: expected_hex.to_ascii_lowercase(),
            actual,
        });
    }
    Ok(())
}
```

New `LowerError` variant:

```rust
    #[error("recording digest mismatch: expected {expected}, got {actual} — the bytes changed between capture and use")]
    DigestMismatch { expected: String, actual: String },
```

- [x] **Step 4: Verify pass. Step 5: Commit**

```bash
git add crates/mvm-sdk/src/runtime.rs crates/mvm-sdk/Cargo.toml
git commit -m "feat(sdk): recording content-digest capture + verification (plan 186 P3)"
```

---

### Task 5: CLI threading — loaded-recording struct, size cap, digest flag, admission gate (P3+P4 CLI half)

**Files:**
- Modify: `crates/mvm-cli/src/commands/build/sandbox_record.rs`
- Modify: `crates/mvm-cli/src/commands/build/compile.rs`
- Modify: `crates/mvm-cli/src/commands/vm/run_plan.rs`
- Modify: `crates/mvm-cli/src/commands/vm/exec.rs` (the `RunArgs` clap struct — read it first, match its attr style)
- Test: `crates/mvm-cli/tests/cli.rs` (help-text assertions, following the file's existing pattern — read a nearby example first)

This task is integration-shaped; exact code must adapt to the real clap structs. The contract to implement:

- [x] **Step 1: `sandbox_record.rs`.** Add a byte cap and a richer return type:

```rust
/// Hard cap on recording bytes read from disk — guards the JSON
/// parser against a multi-GiB file before serde ever runs. Far
/// above any legitimate recording (ops are capped downstream).
const MAX_RECORDING_BYTES: u64 = 64 * 1024 * 1024;

/// A recording loaded from disk: the lowered workload, the
/// divergence findings the admission path gates on, and the
/// content digest captured at read time.
pub(in crate::commands) struct LoadedRecording {
    pub workload: Workload,
    pub findings: Vec<mvm_sdk::runtime::Divergence>,
    pub digest_hex: String,
}
```

Rework `load_recording(path)` → `load_recording(path: &Path, expected_sha256: Option<&str>) -> Result<LoadedRecording>`:
1. `std::fs::metadata(path)` size check against `MAX_RECORDING_BYTES` (bail with a hint naming the cap).
2. Read bytes; `let digest_hex = mvm_sdk::runtime::recording_sha256_hex(&bytes);`
3. If `expected_sha256` is `Some`, `mvm_sdk::runtime::verify_recording_digest(&bytes, expected)?` (map through anyhow).
4. Parse + `compile_recording_with_findings`; return all three fields.

`auto_exec_record_script` returns `Result<LoadedRecording>` (it captures at the freshest possible moment — right after the subprocess exits — so its digest is the trusted baseline; pass `None` for expected). Update its doc comment to say the digest is captured here for downstream audit/verification.

- [x] **Step 2: `compile.rs`.** Add to the args struct (match existing clap style):

```rust
    /// Expected SHA-256 (hex) of the recording file. Refuses a
    /// recording whose bytes changed since capture. Only meaningful
    /// with --from-recording.
    #[arg(long, value_name = "HEX64", requires = "from_recording")]
    pub recording_sha256: Option<String>,
```

Thread it into the `load_recording` call. After loading, print each finding as a warning (`eprintln!("divergence: {finding}")`) — compile is the dev verb, warn-only. Fix the other `load_recording`/`auto_exec_record_script` call sites to use `.workload` and print findings the same way.

- [x] **Step 3: `run_plan.rs` — the admission gate.** Add to `RunArgs` (in `exec.rs`):

```rust
    /// Acknowledge a divergence class on the plan-mode admission
    /// path (repeatable). Unacknowledged divergence refuses
    /// admission: what you previewed is not what would ship.
    #[arg(long = "ack-divergence", value_name = "KIND")]
    pub ack_divergence: Vec<String>,
```

(Default `Vec::new()` in the test fixture `base_run_args()` in run_plan.rs and any other RunArgs constructor — grep for `RunArgs {` and fix all of them.)

In `run_plan_mode`, after `auto_exec_record_script` returns `LoadedRecording { workload, findings, digest_hex }`:

```rust
    eprintln!("recording sha256: {digest_hex}");
    require_acknowledged(&findings, &args.ack_divergence)?;
```

with the pure gate function + unit tests in run_plan.rs:

```rust
/// Refuse admission while any divergence finding's class is not
/// explicitly acknowledged. The preview ran one way; the replay
/// behaves another — shipping that silently is the failure mode
/// this gate exists to stop.
fn require_acknowledged(
    findings: &[mvm_sdk::runtime::Divergence],
    acks: &[String],
) -> Result<()> {
    let unacked: Vec<&mvm_sdk::runtime::Divergence> = findings
        .iter()
        .filter(|f| !acks.iter().any(|a| a == f.kind_slug()))
        .collect();
    if unacked.is_empty() {
        return Ok(());
    }
    for f in &unacked {
        eprintln!("UNACKNOWLEDGED divergence: {f}");
    }
    bail!(
        "refusing plan-mode admission: {} unacknowledged divergence finding(s). Re-run with \
         --ack-divergence <kind> for each class you accept (kinds above in brackets), or fix \
         the script so the recording lowers cleanly.",
        unacked.len()
    )
}
```

Unit tests (same file's test module): `gate_passes_with_no_findings`, `gate_refuses_unacknowledged`, `gate_passes_when_all_kinds_acked`, `gate_refuses_partial_acks` — construct findings directly (`Divergence::KillDropped { op_index: 0 }` etc.).

- [x] **Step 4: help-text tests.** In `crates/mvm-cli/tests/cli.rs`, following the file's existing assertion pattern, assert `mvmctl run --help` contains `--ack-divergence` and `mvmctl compile --help`'s relevant subcommand help contains `--recording-sha256`. (Find the compile verb's actual full path in the CLI tree first — it may be `mvmctl build compile` per Plan 178's verb regrouping; read `cli.rs`'s existing compile-help test to confirm.)

- [x] **Step 5: Verify**: `cargo nextest run -p mvm-cli` (full crate — RunArgs construction sites and help tests live here), plus `cargo nextest run -p mvm-sdk`. Fix any missed `RunArgs {` constructor.

- [x] **Step 6: Commit**

```bash
git add crates/mvm-cli/src/commands crates/mvm-cli/tests/cli.rs
git commit -m "feat(cli): recording digest + size cap; divergence gate on plan-mode admission (plan 186 P3+P4)"
```

---

### Task 6: fuzz target for the trace parser + lowering (P1, fuzz half)

**Files:**
- Create: `crates/mvm-sdk/fuzz/Cargo.toml`
- Create: `crates/mvm-sdk/fuzz/fuzz_targets/fuzz_runtime_recording.rs`
- Modify: root `Cargo.toml` (`exclude` list — add `"crates/mvm-sdk/fuzz"` with a one-line comment matching the neighbors)
- Modify: `.github/workflows/security.yml` (new step in the `fuzz` job + the corpus-upload path list)

- [x] **Step 1: the fuzz crate.** `crates/mvm-sdk/fuzz/Cargo.toml`:

```toml
[package]
name = "mvm-sdk-fuzz"
version = "0.0.0"
publish = false
edition = "2024"

# Detached from the parent workspace — same constraint as every
# other fuzz crate here: libfuzzer-sys only links under cargo-fuzz's
# wrapper, so the repo root Cargo.toml lists this dir under
# `workspace.exclude` and this empty table makes it standalone.
[workspace]

[package.metadata]
cargo-fuzz = true

[dependencies]
libfuzzer-sys = "0.4"
serde_json = "1"

[dependencies.mvm-sdk]
path = ".."

# Fuzz the runtime-recording parse + lowering. The recording is the
# Tier-0 promotion input: untrusted JSON from a tamperable tmpfile.
# Harness goal: never panic on any input — parse fails closed via
# deny_unknown_fields, and lowering errors (limits, duplicate paths,
# bad b64) are Err, not panics.
[[bin]]
name = "fuzz_runtime_recording"
path = "fuzz_targets/fuzz_runtime_recording.rs"
test = false
doc = false
bench = false
```

`fuzz_targets/fuzz_runtime_recording.rs`:

```rust
// Fuzz the SDK runtime-recording parse + lowering.
//
// The recording JSON is the promotion path's untrusted input: it is
// written by user-spawned code to a tmpfile and read back by the CLI.
// The harness contract is "never panic on any input": serde must fail
// closed on garbage (deny_unknown_fields), and every lowering refusal
// (op limits, duplicate paths, oversize or malformed FilesWrite b64,
// missing entrypoint) must surface as Err, never as a panic.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mvm_sdk::runtime::{RuntimeRecording, compile_recording_with_findings};

fuzz_target!(|data: &[u8]| {
    if let Ok(rec) = serde_json::from_slice::<RuntimeRecording>(data) {
        let _ = compile_recording_with_findings(&rec);
    }
});
```

- [x] **Step 2: seed corpus.** Create `crates/mvm-sdk/fuzz/corpus/fuzz_runtime_recording/seed-minimal.json` containing one valid recording (template `minimal`, one `CommandStart`, one `FilesWrite`, one `Kill`) so the fuzzer starts from structure, not noise. Generate it by serializing a `RuntimeRecording` in a quick `cargo test`-side snippet or by hand — it must parse cleanly (verify with a one-off `serde_json::from_str` test you then delete, or just feed it through `mvmctl compile --from-recording` mentally — simplest is hand-writing JSON matching the serde shape: `{"workload_id":"seed","create":{"template":"minimal"},"ops":[{"kind":"files_write","path":"/app/a.txt","bytes_b64":"aGk="},{"kind":"command_start","argv":["/bin/true"]},{"kind":"kill"}]}`).

- [x] **Step 3: workspace exclude + CI.** Root `Cargo.toml` exclude list gains `"crates/mvm-sdk/fuzz"` (comment: trace-parser harness, same libfuzzer-sys constraint). In `.github/workflows/security.yml`'s `fuzz` job, add a step after the existing SupervisorConfig ones, matching their exact shape:

```yaml
      - name: Fuzz runtime recording (SDK trace)
        working-directory: crates/mvm-sdk
        env:
          DURATION: ${{ steps.duration.outputs.secs }}
          RUSTUP_TOOLCHAIN: nightly
        # The recording JSON is the Tier-0 promotion input — user-
        # spawned code writes it to a tmpfile the CLI reads back.
        # Same "never panic on any input" contract as the other
        # config-parser targets.
        run: cargo fuzz run fuzz_runtime_recording -- -max_total_time="$DURATION"
```

and add `crates/mvm-sdk/fuzz/corpus/` + `crates/mvm-sdk/fuzz/artifacts/` to the corpus-upload artifact path list.

- [x] **Step 4: local verification.** If `cargo fuzz` is installed (check `cargo fuzz --version`): `cd crates/mvm-sdk && RUSTUP_TOOLCHAIN=nightly cargo fuzz run fuzz_runtime_recording -- -max_total_time=30 -runs=200000` and report findings. If not installed, at minimum `RUSTUP_TOOLCHAIN=nightly cargo check` inside the fuzz dir must pass; report which level of verification ran. Also `cargo build --workspace` must still succeed (proves the exclude entry is right).

- [x] **Step 5: Commit**

```bash
git add crates/mvm-sdk/fuzz Cargo.toml .github/workflows/security.yml
git commit -m "feat(fuzz): runtime-recording trace parser + lowering harness (plan 186 P1)"
```

---

### Task 7: full gates + spec bookkeeping

**Files:**
- Modify: `specs/adrs/080-wasm-preview-promotion-and-capability-policy.md` (§8 rows P1, P3, P4; P2 row note)
- Modify: `specs/REFACTOR-STATUS.md`
- Modify: `specs/plans/186-trace-hardening.md` (tick boxes)

- [x] **Step 1: gates** (in order; environmental caveats as in plan 184: mvm-backend codesign SIGKILL, embedded-binary ELF test under skip-embed):

```bash
cargo fmt --all -- --check || rustup run nightly cargo fmt --all
MVM_SKIP_EMBED_BINARIES=1 cargo nextest run --workspace 2>&1 | tail -5
MVM_SKIP_EMBED_BINARIES=1 cargo test --workspace --doc 2>&1 | tail -5
MVM_SKIP_EMBED_BINARIES=1 cargo clippy --workspace -- -D warnings 2>&1 | tail -5
cargo run -p xtask -- check-spec-numbers
```

- [x] **Step 2: ADR-080 §8 row updates.** Replace the P1, P3, P4 rows (keep P2's row but append a note):

```markdown
| P1 | Trace parser hardening (§2) | `fuzz_runtime_recording` in `security.yml` (crates/mvm-sdk/fuzz); `too_many_ops_refuses` + `files_write_oversize_refuses` + `duplicate_files_write_path_refuses` (mvm-sdk runtime) — landed by Plan 186. |
| P2 | Shell-surface shrink (§2) | declarative file-materialization lowering — OPEN (own plan; needs hook-executor recon). Interim pin landed by Plan 186: `files_write_b64_with_single_quote_refuses` + `files_write_b64_url_safe_alphabet_refuses` + `files_write_hostile_path_is_single_quoted_in_hook`. |
| P3 | Trace integrity (§2) | `recording_sha256_hex` captured at read in `load_recording`/auto-exec; `digest_verify_match_passes_mismatch_refuses` (mvm-sdk) + `--recording-sha256` refusal on `compile --from-recording`; 64 MiB byte cap before parse — landed by Plan 186. |
| P4 | Divergence gate (§2) | `require_acknowledged` refuses unacknowledged findings on the `run --mode plan` admission path (`gate_refuses_unacknowledged` + siblings, mvm-cli); findings vocabulary in `mvm_sdk::runtime::Divergence` — landed by Plan 186. Ship-verb wiring inherits this gate when the ship verb lands. |
```

(Adapt the exact table formatting to the file as it stands on this branch.)

- [x] **Step 3: REFACTOR-STATUS** — add Plan 186 to the glance list + a detail block (landed: P1/P3/P4 + interim P2 pin; open: full P2, P6–P8); bump "Last updated".

- [x] **Step 4: tick every checkbox in this plan doc. Step 5: Commit**

```bash
git add specs/
git commit -m "docs(specs): record plan 186 trace-hardening witnesses in ADR-080 P1/P3/P4 (plan 186)"
```

---

## Out of scope (deliberately)

- **Full P2** — `HookCmd`-executor recon + declarative file materialization (own plan; the executor surface in mvm-guest/mkGuest is unmapped).
- **P6** (component digest carry), **P7** (secret-scan admission — note: the scanner lives in `mvm-hostd`, which `mvm-sdk` must not depend on; the hook belongs at the CLI/admission layer), **P8** (relay).
- The ship verb itself — `run --mode plan` is the promotion-shaped path that exists today; the gate moves with it.
- ADR-002 Tier-0 threat-model note + claims 1–3/10 narrative updates (doc-only follow-up, after #801 merges).
