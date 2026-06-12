# Plan 191 — Declarative file materialization (ADR-080 P2-full close-out) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close ADR-080 precondition **P2-full**: replace the `FilesWrite`→`HookCmd::Shell` lowering (which materializes a file via a base64-decoding shell line at guest boot) with a **declarative `App.files` IR field** baked into the rootfs at *build time*. This removes the last shell-hook surface from the trace-promotion path entirely — file content/paths become pure data, never interpolated into a shell line.

**Architecture (from the P2-full recon):** A `FilesWrite` op currently lowers to a `before_start` shell hook. Replace it with a new IR field `App.files: Vec<MaterializedFile>` (`{ path, bytes_b64, mode }`). The SDK lowering pushes to `app.files` instead of building a shell line. The Nix factory (`mkFunctionService.nix`) reads `launch.files` and, for each, bakes the **build-time-decoded** bytes into the rootfs via the existing `extraFiles` map (a `pkgs.runCommand` base64-decode derivation referenced by `source =`, with the file's `mode`). **No guest-side executor change** — the file already exists on the rootfs at boot; nothing decodes at runtime, no shell runs. This is strictly *simpler* than the current path and adds correct file-mode control.

**Security framing:** The current shell hook was already hardened in Plan 186 (path + payload base64-encoded into the line, verified injection-safe against `/bin/sh`), so this is **defense-in-depth + architectural cleanup**, not a live-bug fix. The win: the trace's file content/paths never reach a shell context at all; arbitrary-path materialization is unchanged (the old hook also wrote `> "$p"` for any path — P2-full does not widen it).

**Tech Stack:** Rust (mvm-sdk IR + lowering; mvm-sdk compile/flake), Nix (`mkFunctionService.nix`). No new Cargo deps. `cargo nextest`.

**Plan number:** 191 (main holds up to 190). Run `cargo run -p xtask -- check-spec-numbers` before merge.

**Merge:** `main` now has a **merge queue** — open the PR and `gh pr merge <N> --squash --auto` (do NOT manually merge / re-sync). See [[reference_main_merge_queue]].

**Verification limitation (state honestly in the PR):** the full "file lands in the rootfs ext4" behaviour requires a real builder-VM Nix build (not in the standard CI lane), exactly as the *existing* hook-bake is unverified by `runtime_compile_e2e.rs` (which asserts flake generation, not a build). This plan verifies: the IR field + lowering (unit), and that the generated flake carries the file (e2e). The Nix factory change is verified by `nix flake check` / eval where possible + careful review; the rootfs bake is covered by the same builder-VM path that covers hooks today.

**Existing code this plan builds on (read before starting):**
- `crates/mvm-sdk/src/runtime.rs` — `compile_recording_with_findings`, the `FilesWrite` arm (~lines 368-401) that builds the `HookCmd::Shell` line; `MAX_FILES_WRITE_DECODED_BYTES`; the duplicate-path scan; `Divergence::FilesWriteAfterEntrypoint`; `LowerError::{InvalidFilesWriteB64, FilesWriteTooLarge}`.
- `crates/mvm-sdk/src/ir/workload.rs` — `App` struct (add `files`); `Workload`.
- `crates/mvm-sdk/src/ir/hooks.rs` — `HookCmd`/`Hooks` (unchanged, but FilesWrite no longer feeds them).
- `crates/mvm-sdk/src/compile/flake.rs` (~line 129) — `hooks = launch.hooks or {...}` in the generated flake; the launch-JSON assembly (add `files`).
- `nix/lib/factories/mkFunctionService.nix` — `extraFiles = { ... }` map (~line 157), hook-script baking (~lines 192-201), `renderHookCmd`/`hookScriptFor`. The base64-decode derivation goes here.
- `crates/mvm-sdk/tests/runtime_compile_e2e.rs` — asserts the current shell-hook form (must flip to assert `app.files`).
- Plan 186's injection pins in `runtime.rs` tests (`files_write_b64_with_single_quote_refuses`, `files_write_hostile_path_is_base64_encoded_in_hook`, `files_write_root_level_path_materializes`, etc.) — these test the SHELL form and become obsolete; replace per Task 2.

---

### Task 1: `MaterializedFile` IR field on `App`

**Files:**
- Modify: `crates/mvm-sdk/src/ir/workload.rs` (new struct + `App.files` field)
- Modify: `crates/mvm-sdk/src/ir/mod.rs` (export `MaterializedFile` if the module re-exports IR types — match the existing pattern)

- [ ] **Step 1: failing tests** (add to workload.rs's test module, matching its existing serde/schema test style):

```rust
    #[test]
    fn materialized_file_serde_roundtrip() {
        let f = MaterializedFile {
            path: "/app/.env".to_string(),
            bytes_b64: "aGk=".to_string(),
            mode: Some("0600".to_string()),
        };
        let json = serde_json::to_string(&f).unwrap();
        let back: MaterializedFile = serde_json::from_str(&json).unwrap();
        assert_eq!(f, back);
    }

    #[test]
    fn materialized_file_mode_defaults_to_none_and_is_omitted() {
        let f = MaterializedFile { path: "/app/x".to_string(), bytes_b64: "eA==".to_string(), mode: None };
        let v = serde_json::to_value(&f).unwrap();
        assert!(v.get("mode").is_none(), "None mode must be omitted from the wire");
    }

    #[test]
    fn app_files_defaults_empty_and_is_omitted_when_empty() {
        // An App with no materialized files must serialize without a `files` key
        // (back-compat with existing workloads).
        let json = serde_json::to_value(minimal_app()).unwrap();
        assert!(json.get("files").is_none(), "empty files must be skipped");
    }

    #[test]
    fn materialized_file_rejects_unknown_field() {
        let r: Result<MaterializedFile, _> =
            serde_json::from_str(r#"{"path":"/a","bytes_b64":"eA==","bogus":1}"#);
        assert!(r.is_err(), "deny_unknown_fields must reject extras");
    }
```

(If no `minimal_app()` helper exists in the test module, construct an `App` inline with empty `files`; read the module first.)

- [ ] **Step 2: verify failure** — `cargo nextest run -p mvm-sdk ir::workload` (or the module's path) — `MaterializedFile` not found.

- [ ] **Step 3: implement.** Add the struct + field:

```rust
/// A file materialized into the workload's rootfs at build time.
/// Replaces the legacy "write a file via a before_start shell hook"
/// path — content and destination are carried as data and baked
/// directly, so neither ever reaches a shell line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MaterializedFile {
    /// Absolute destination path in the guest rootfs.
    pub path: String,
    /// STANDARD-alphabet base64 of the file's bytes. Decoded at
    /// build time by the Nix factory; never decoded in a guest shell.
    pub bytes_b64: String,
    /// Octal mode string (e.g. `"0644"`). `None` → the factory's
    /// default (`0644`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
}
```

Add to `App` (after `hooks` or near `mounts` — match field grouping):

```rust
    /// Files baked into the rootfs at build time (was: FilesWrite
    /// before_start shell hooks).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<MaterializedFile>,
```

Every existing `App { .. }` construction site in NON-test code must set `files: Vec::new()` (or rely on `..Default`-style — but `App` has no Default; grep `App {` across crates/ and add `files: Vec::new(),`). The compiler will list them.

- [ ] **Step 4: verify pass** — `cargo nextest run -p mvm-sdk` (new IR tests + existing green; fix all `App {` sites until it compiles). `cargo clippy -p mvm-sdk -- -D warnings`, `cargo fmt --all`.

- [ ] **Step 5: commit**

```bash
git add crates/mvm-sdk/src/ir
git commit -m "feat(sdk): MaterializedFile IR field on App (plan 191 P2-full)"
```

---

### Task 2: lower `FilesWrite` to `app.files` (drop the shell hook)

**Files:**
- Modify: `crates/mvm-sdk/src/runtime.rs`
- Modify: `crates/mvm-sdk/tests/runtime_compile_e2e.rs`

- [ ] **Step 1: rewrite the lowering tests.** The Plan-186 injection pins tested the shell form and are now obsolete. In runtime.rs's test module:
  - REPLACE `files_write_hostile_path_is_base64_encoded_in_hook` with `files_write_lowers_to_materialized_file_not_a_hook`:

```rust
    #[test]
    fn files_write_lowers_to_materialized_file_not_a_hook() {
        let ops = vec![write_op("/app/conf.toml", b"a=1"), start_op(&["/bin/true"])];
        let wl = compile_recording(&rec_with_ops(ops)).expect("must lower");
        let app = &wl.apps[0];
        // No before_start hook is emitted for FilesWrite anymore.
        assert!(app.hooks.before_start.is_empty(), "FilesWrite must not produce a hook");
        assert_eq!(app.files.len(), 1);
        assert_eq!(app.files[0].path, "/app/conf.toml");
        assert_eq!(
            app.files[0].bytes_b64,
            base64::engine::general_purpose::STANDARD.encode(b"a=1")
        );
    }

    #[test]
    fn files_write_hostile_path_is_carried_as_data_never_a_shell_line() {
        // The old hostile-path concern is gone: the path is a plain
        // data field, never interpolated into a shell command.
        let hostile = "/app/x'; rm -rf /tmp/pwn; echo '";
        let ops = vec![write_op(hostile, b"x"), start_op(&["/bin/true"])];
        let wl = compile_recording(&rec_with_ops(ops)).expect("must lower");
        assert!(wl.apps[0].hooks.before_start.is_empty());
        assert_eq!(wl.apps[0].files[0].path, hostile);
    }
```
  - DELETE the obsolete shell-form pins: `files_write_b64_with_single_quote_refuses`, `files_write_b64_url_safe_alphabet_refuses`, `files_write_root_level_path_materializes`, `files_write_slashless_nested_path_materializes` (these exercised the removed `/bin/sh` hook). KEEP any test that asserts the b64 DECODE validation / size cap / duplicate-path / `FilesWriteAfterEntrypoint` divergence — those still apply (the lowering still decodes to validate + size-check, and still records the divergence). Adapt them if they reference `before_start`.
  - Update `files_write_decoded_secret_is_flagged`-style tests in the secret scanner only if they live here (they're in mvm-cli — leave; the recording shape is unchanged).

- [ ] **Step 2: verify failure**, then **Step 3: implement.** In the `FilesWrite` arm of `compile_recording_with_findings`: keep the decode (for `InvalidFilesWriteB64` validation) + the `MAX_FILES_WRITE_DECODED_BYTES` check + the `FilesWriteAfterEntrypoint` finding, but REPLACE the shell-line construction + `before_start.push(HookCmd::Shell{..})` with collecting into a `materialized_files: Vec<MaterializedFile>` accumulator:

```rust
            RecordedOp::FilesWrite { path, bytes_b64 } => {
                let decoded = base64::engine::general_purpose::STANDARD
                    .decode(bytes_b64)
                    .map_err(|error| LowerError::InvalidFilesWriteB64 { path: path.clone(), error })?;
                if decoded.len() > MAX_FILES_WRITE_DECODED_BYTES {
                    return Err(LowerError::FilesWriteTooLarge {
                        path: path.clone(),
                        decoded: decoded.len(),
                        max: MAX_FILES_WRITE_DECODED_BYTES,
                    });
                }
                if idx > final_cmd_pos {
                    findings.push(Divergence::FilesWriteAfterEntrypoint { op_index: idx, path: path.clone() });
                }
                materialized_files.push(MaterializedFile {
                    path: path.clone(),
                    bytes_b64: bytes_b64.clone(),
                    mode: None,
                });
            }
```

Declare `let mut materialized_files: Vec<MaterializedFile> = Vec::new();` next to `before_start`, and set `files: materialized_files` in the `App { .. }` construction. Remove any now-dead helper (e.g. a `shell_single_quote` if it lingers — grep). The duplicate-path scan at the top of `compile_recording_with_findings` already prevents two writes to the same path, so `app.files` has unique paths.

- [ ] **Step 4: e2e test.** In `crates/mvm-sdk/tests/runtime_compile_e2e.rs`, the assertion currently checks `app.hooks.before_start[0]` is a Shell line with the base64 path. Change it to assert `app.files` carries `/app/note.txt` with `bytes_b64 == base64("hi\n")` and `app.hooks.before_start` is empty. Keep the `compile(&workload, &out, ...)` flake-generation assertion (it now must also confirm the flake carries the file — see Task 3; for this task just assert flake.nix exists as before).

- [ ] **Step 5: verify + commit.** `cargo nextest run -p mvm-sdk`, `cargo clippy -p mvm-sdk -- -D warnings`, `cargo fmt --all`.

```bash
git add crates/mvm-sdk/src/runtime.rs crates/mvm-sdk/tests/runtime_compile_e2e.rs
git commit -m "feat(sdk): FilesWrite lowers to App.files, not a before_start shell hook (plan 191 P2-full)"
```

---

### Task 3: bake `App.files` into the rootfs (flake + Nix factory)

**Files:**
- Modify: `crates/mvm-sdk/src/compile/flake.rs` (pass `files` into the generated launch JSON / flake)
- Modify: `nix/lib/factories/mkFunctionService.nix` (consume `launch.files` → `extraFiles`)

This task touches the SDK→flake→Nix seam. READ FIRST, then implement; the exact launch-JSON shape + how `mkFunctionService` is invoked from the generated flake must be matched precisely.

- [ ] **Step 1: read the integration.** Read `crates/mvm-sdk/src/compile/flake.rs` fully — how the launch JSON is assembled from the `Workload`/`App`, how `hooks` is threaded into the generated `flake.nix` (line ~129), and how `mkFunctionService` is called. Read `nix/lib/factories/mkFunctionService.nix` fully — the `extraFiles` map (~157), the hook-script bake (~192), `renderHookCmd`. Confirm whether the launch data reaches Nix as a JSON file the flake reads, or is interpolated into the generated `flake.nix` string. Report the exact mechanism before writing.

- [ ] **Step 2: thread `files` through flake.rs.** Wherever `hooks` is put into the launch data, add the app's `files` (list of `{path, bytes_b64, mode}`). Mirror the `hooks = launch.hooks or {...}` pattern: e.g. `files = launch.files or [ ];` in the generated flake, and include `files` in the serialized launch JSON the flake reads.

- [ ] **Step 3: bake in mkFunctionService.nix.** For each entry in `launch.files`, add to the `extraFiles` map an entry that bakes the build-time-decoded bytes at the target path with the given mode. Use a base64-decode derivation (Nix decodes at build, never the guest):

```nix
  # Materialize declarative files (was: FilesWrite before_start shell hooks).
  # The bytes are base64-decoded at BUILD time into a store path; the rootfs
  # packer lands the file at the requested path. Nothing decodes in a guest shell.
  materializedFiles = builtins.listToAttrs (map (f: {
    name = f.path;
    value = {
      source = pkgs.runCommand "mvm-file-${builtins.hashString "sha256" f.path}" { } ''
        printf '%s' ${pkgs.lib.escapeShellArg f.bytes_b64} | ${pkgs.coreutils}/bin/base64 -d > "$out"
      '';
      mode = f.mode or "0644";
    };
  }) (launch.files or [ ]));
```

Then merge `materializedFiles` into the `extraFiles` map (e.g. `extraFiles = { ...existing... } // materializedFiles;` — check for path collisions with the `/etc/mvm/...` entries; user paths are typically `/app/...` so collisions are unlikely, but if a user file path equals a reserved `/etc/mvm/...` path, the reserved one must win — order the `//` so reserved entries override, or assert no overlap). Note: `escapeShellArg` on a STANDARD-base64 token is belt-and-suspenders (the alphabet has no shell metacharacters) but correct.

- [ ] **Step 4: verify.** `nix flake check` is not runnable without the builder VM in this loop; at minimum:
  - `cargo nextest run -p mvm-sdk` (the e2e flake-generation test — extend it to assert the generated `flake.nix` / launch JSON contains the file's `bytes_b64`).
  - If `nix` is available locally: `cd <generated flake dir>` from a test fixture and `nix eval` the `extraFiles` attr to confirm it includes the materialized path (best-effort; report whether it ran).
  - Read-review the Nix for correctness (the `runCommand` decode + the `//` merge + mode).
  Report which verification levels ran.

- [ ] **Step 5: commit.**

```bash
git add crates/mvm-sdk/src/compile/flake.rs nix/lib/factories/mkFunctionService.nix crates/mvm-sdk/tests/runtime_compile_e2e.rs
git commit -m "feat(build): bake App.files into the rootfs via mkFunctionService extraFiles (plan 191 P2-full)"
```

---

### Task 4: gates + spec bookkeeping + PR

**Files:**
- Modify: `specs/adrs/080-wasm-preview-promotion-and-capability-policy.md` (§8 P2 row + §2 note)
- Modify: `specs/REFACTOR-STATUS.md`, `specs/SPRINT.md`
- Modify: `specs/plans/191-declarative-file-materialization.md` (tick boxes)

- [ ] **Step 1: full gates** (match CI exactly — see [[feedback_ci_gate_list_completeness]]):

```bash
cargo fmt --all -- --check || rustup run nightly cargo fmt --all
cargo run -p xtask -- check-no-spec-refs-in-comments
cargo run -p xtask -- check-spec-numbers
RUSTFLAGS="-D warnings" cargo build --workspace --all-targets 2>&1 | tail -5
cargo nextest run --workspace 2>&1 | tail -6
cargo test --workspace --doc 2>&1 | tail -3
cargo clippy --workspace -- -D warnings 2>&1 | tail -5
```
(Environmental caveats: mvm-backend codesign SIGKILL; build `cargo build -p mvmctl` first so the mvm-cli assert_cmd integration tests can locate the binary.)

- [ ] **Step 2: ADR-080 §8 P2 row.** Update P2 to mark the full close-out landed: `P2 | Shell-surface shrink (§2) | DONE (Plan 191): FilesWrite lowers to the declarative App.files IR field, baked into the rootfs at build time via mkFunctionService extraFiles (base64 decoded at build, never in a guest shell) — the before_start shell hook is gone. Interim base64 hardening (Plan 186) superseded.` Also amend the §2 prose that described FilesWrite as lowering to an in-guest boot-time shell hook — note it is now a build-time bake with no shell.

- [ ] **Step 3: REFACTOR-STATUS + SPRINT.** Add Plan 191 (🟢 P2-full landed — declarative file materialization, shell hook removed); bump "Last updated". In SPRINT.md Sprint 62, move "P2 full" from the Deferred list to a landed line.

- [ ] **Step 4: tick boxes; commit; open PR (do NOT merge — use the queue).**

```bash
git add crates/ nix/ specs/
git commit -m "docs(specs): record Plan 191 P2-full (declarative file materialization) in ADR-080 (plan 191)"
git push -u origin feat/plan-191-declarative-file-materialization
gh pr create --base main --title "Plan 191 — declarative file materialization (ADR-080 P2-full)" --body "<describe: FilesWrite now lowers to a declarative App.files IR field baked into the rootfs at build time via mkFunctionService extraFiles; the before_start shell hook is removed entirely — file content/paths never reach a shell. Defense-in-depth over Plan 186's hardened hook. Verification note: rootfs bake covered by the same builder-VM path as hooks; flake generation + lowering unit/e2e tested.>"
```
Then enqueue: `gh pr merge <N> --squash --auto`.

---

## Out of scope (deliberately)

- **Command/legacy workloads' `/etc/mvm/entrypoint` path** — if FilesWrite appears in a non-function (command) workload lowering path, confirm it routes through the same `App.files` (it should — `compile_recording` produces one IR consumed by the factory). Do not build a second materialization path.
- **Runtime-mutable files** — `App.files` is build-time-baked (immutable in the rootfs). Files a workload writes at runtime are unaffected.
- **P6 / P8 / the WASI-context mapping** — separate ledger items, depend on the wasmtime runner (ADR-level).
