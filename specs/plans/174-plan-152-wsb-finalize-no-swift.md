# Plan 152 WS-B Finalization (no Swift) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:executing-plans (inline) — dispatched agents lack Bash in this environment, so the controller executes. Steps use `- [ ]`.

**Goal:** Make the Rust-native `objc2` VZ supervisor the sole supervisor — delete the Swift crate, flip the resolver, and clean up build/CI/docs — completing Plan 152's "native objc2 VZ support."

**Architecture:** Drop the Swift `.build` resolution leg (the cargo-built Rust `mvm-vz-supervisor` bin is found adjacent to `mvmctl`, mirroring `mvm-libkrun-supervisor`); delete `crates/mvm-vz-supervisor/` + its `mvm-build/build.rs` auto-build hook + CI Swift steps; the parity gate becomes Rust-only (supersedes #730).

**Tech Stack:** Rust, objc2-virtualization (already in `mvm-vm-host`), GitHub Actions.

**Spec:** `specs/notes/plan-152-wsb-finalize-no-swift-design.md`. **Worktree:** `../mvm-152-finalize`, branch `feat/plan-152-finalize-no-swift`.

**Invariant:** the entitled-TCB Rust supervisor was security-reviewed in #700 (claims 1/15/vsock preserved). This changes only the *default* supervisor (Swift→Rust), a correctness win (Swift deadlocks on PAUSE/RESUME/SAVE).

---

### Task 1: Flip the Vz supervisor resolver to the Rust bin

**Files:** `crates/mvm-backend/src/vz.rs` (resolver + module doc), `crates/mvm-build/src/vz.rs` (delete `source_tree_binary_path`).

- [ ] **Step 1:** In `crates/mvm-backend/src/vz.rs::resolve_supervisor_path`, delete the source-checkout `.build` block:
```rust
    // Source-checkout layout. CARGO_MANIFEST_DIR points at the
    // current crate; the workspace root is two `..` above.
    if let Some(workspace_root) = workspace_root_from_manifest_dir() {
        let candidate = vz::source_tree_binary_path(&workspace_root);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
```
(The adjacent-to-exe step above it already finds the cargo-built Rust bin in source-checkout `cargo run` and installed layouts.)

- [ ] **Step 2:** Replace the `bail!` message (no Swift `.build`/`build.sh`):
```rust
    bail!(
        "mvm-vz-supervisor binary not found. Looked for: \
         $MVM_VZ_SUPERVISOR_PATH, alongside the current exe, and \
         ~/.mvm/bin/mvm-vz-supervisor-{} (release-installed). Build it with \
         `cargo build -p mvm-vm-host --bin mvm-vz-supervisor`, or set \
         MVM_VZ_SUPERVISOR_PATH=/abs/path/to/the/binary.",
        env!("CARGO_PKG_VERSION")
    );
```

- [ ] **Step 3:** Update the resolver doc comment (`vz.rs` ~:1087) — remove enumerated step 3 (the `.build` source-checkout line); renumber so it reads override → adjacent → release, "paralleling the libkrun resolver."

- [ ] **Step 4:** Update the module header doc (`vz.rs:6-23`) — "Swift subprocess (lives in `crates/mvm-vz-supervisor/`)" → "Rust-native `objc2` supervisor (`mvm-vm-host` `[[bin]] mvm-vz-supervisor`)".

- [ ] **Step 5:** In `crates/mvm-build/src/vz.rs`, delete `source_tree_binary_path` (:389) and `current_arch_triple_macos` if it becomes unused (clippy `-D warnings` will flag), plus any `source_tree_binary_path` test. Keep `supervisor_binary_path` (release `~/.mvm/bin`, still used by the resolver).

- [ ] **Step 6:** If `workspace_root_from_manifest_dir` in `vz.rs` is now unused, remove it. Run `cargo build -p mvm-backend -p mvm-build` and `cargo clippy -p mvm-backend -p mvm-build -- -D warnings`; expect clean (fix any newly-dead-code).

- [ ] **Step 7:** Commit: `git commit -am "feat(vz): resolve the Rust supervisor bin; drop Swift .build leg"`

### Task 2: Flip the doctor supervisor-resolution chain

**Files:** `crates/mvm-cli/src/doctor.rs:850-895`.

- [ ] **Step 1:** In `locate_vz_supervisor`, delete the source-checkout `.build` block (the `if let Ok(exe) = current_exe() && workspace_root_from_target_layout(...)` arm that joins `crates/mvm-vz-supervisor/.build`). Replace with the adjacent-to-exe probe (mirror the vz.rs resolver): join `mvm-vz-supervisor` next to `current_exe`'s parent; if `is_file`, return it labeled "source-checkout / adjacent build".

- [ ] **Step 2:** Update the `locate_vz_supervisor` doc comment chain (remove the `.build` line). Remove `workspace_root_from_target_layout` / `arch_apple_macosx` if now unused (clippy will flag).

- [ ] **Step 3:** `cargo build -p mvm-cli` + `cargo clippy -p mvm-cli -- -D warnings`; expect clean. Commit: `git commit -am "feat(doctor): resolve the Rust vz supervisor bin; drop Swift .build leg"`

### Task 3: Delete the Swift crate + its build coupling

**Files:** `crates/mvm-vz-supervisor/` (delete), `crates/mvm-build/build.rs` (delete), `crates/mvm-build/Cargo.toml:13` (`build = "build.rs"`).

- [ ] **Step 1:** `git rm -r crates/mvm-vz-supervisor`
- [ ] **Step 2:** `git rm crates/mvm-build/build.rs` (it is *entirely* the Swift auto-build — verified: its `main()` only builds the Swift package).
- [ ] **Step 3:** Remove `build = "build.rs"` (line 13) from `crates/mvm-build/Cargo.toml`. Grep `crates/mvm-build/Cargo.toml` for any `[build-dependencies]` and remove if present + now-unused.
- [ ] **Step 4:** `cargo build -p mvm-build` (no build.rs now); expect clean. Commit: `git commit -m "feat(vz): delete the Swift mvm-vz-supervisor crate + its cargo build hook"`

### Task 4: Parity gate → Rust-only (supersedes #730)

**Files:** `crates/mvm-build/tests/vz_supervisor_parity.rs`.

- [ ] **Step 1:** Drop the Swift bin from `live_env()` (return `(rust, kernel, rootfs)` — remove `MVM_VZ_PARITY_SWIFT_BIN` / the `SWIFT_BIN` const). Boot/vsock/control/save tests probe **only** the Rust bin.
- [ ] **Step 2:** `control_verbs_rust_correct`: assert Rust replies == `["OK running","OK","OK","OK running"]` (no Swift probe). `save_restore_rust_correct`: assert `snapshot_written && sidecar_written && restore_reached_running` (no Swift probe). `boot_*` / vsock: assert the Rust outcome directly (drop the `== swift` compare; keep the reached-running assertion).
- [ ] **Step 3:** Carry the live-validated harness fixes (from the #731 spike): `probe_save_restore` sends `PAUSE` before `SAVE`; `create_dir_all` the restore dir before `build_boot_config`; add `MVM_VZ_PARITY_CMDLINE` (default = current `DEFAULT_CMDLINE`) via a `cmdline()` helper; the contract test compares to `cmdline()`.
- [ ] **Step 4:** `cargo clippy -p mvm-build --tests -- -D warnings` + `cargo test -p mvm-build --test vz_supervisor_parity` (live tests skip without env — expect the non-live config tests pass). Commit: `git commit -am "test(plan-152): vz parity gate is Rust-only (Swift deleted)"`

### Task 5: Docs — comments, ADR-056 addendum, REFACTOR-STATUS

**Files:** `crates/mvm-backend/src/vz_control.rs:1-7`, `crates/mvm-hostd/src/supervisor/gateway_bridge.rs:18`, `Cargo.toml:17,69,326`, `specs/adrs/056-vz-backend.md`, `specs/REFACTOR-STATUS.md`, `.github/workflows/{ci-full,security}.yml`.

- [ ] **Step 1:** Fix stale "Swift" comments: `vz_control.rs` header ("Rust client for the Swift `mvm-vz-supervisor`" → "client for the supervisor control socket"); `gateway_bridge.rs:18` ("Splice happens in Swift (`Network.swift`)" → "in-process in the Rust supervisor"); `Cargo.toml` comments at :17/:69/:326 (drop "Swift `mvm-vz-supervisor`").
- [ ] **Step 2:** CI — `ci-full.yml`: in the vz lane (~637-641, ~756-782) remove `MVM_VZ_BUILD_SUPERVISOR: "1"`; if the lane needs the supervisor, replace the Swift-build with `cargo build -p mvm-vm-host --bin mvm-vz-supervisor`; update the `crates/mvm-vz-supervisor/**` path-filter trigger to `crates/mvm-vm-host/**`. `security.yml:290-295`: update the comment (the fuzz target is the Rust `SupervisorConfig`; drop the "Swift binary" framing + the Swift-corpus-equivalence note). **Read each lane fully before editing** to keep YAML valid.
- [ ] **Step 3:** ADR-056 addendum — append a dated section: "Swift supervisor removed; the Rust-native objc2 supervisor (#700) is the sole VZ supervisor. Motivating defect: the Swift control socket self-deadlocked on async VZ ops (`synchronousVZCall` blocks the VM's serial queue awaiting a completion dispatched to that same queue); the Rust serial-queue→tokio bridge fixes it."
- [ ] **Step 4:** `specs/REFACTOR-STATUS.md` — Plan 152: tick WS-B finalize (resolver flip + Swift deletion); mark Plan 152 core (WS-A/WS-B/WS-E) ✅; WS-C (fork) / WS-D (nested KVM) remain as separate workstreams. Bump "Last updated".
- [ ] **Step 5:** Commit: `git commit -am "docs(plan-152): retire Swift supervisor — comments, ADR-056 addendum, CI, rollup"`

### Task 6: Full verification + grep-no-Swift + PR

- [ ] **Step 1:** `cargo build --workspace` + `cargo build -p mvm-vm-host --bin mvm-vz-supervisor` (the Rust bin builds).
- [ ] **Step 2:** `rustup run nightly cargo fmt --all -- --check`; `cargo clippy --workspace -- -D warnings`; `cargo nextest run --workspace -E 'not package(mvm-backend)'`; `cargo test --workspace --doc`. All green (mvm-backend test bins SIGKILL on this host — Linux CI covers them).
- [ ] **Step 3:** Grep gate — `grep -rn "mvm-vz-supervisor/.build\|tools/build.sh\|Swift" --include=*.rs --include=*.toml --include=*.yml crates .github Cargo.toml` returns no live references to the deleted Swift crate (doc-history mentions in ADR/specs are fine).
- [ ] **Step 4:** Live re-confirm the Rust-only gate (already proven in the #731 spike; re-run if a backend is bootable): `MVM_VZ_PARITY_RUST_BIN=... MVM_VZ_PARITY_KERNEL=... MVM_VZ_PARITY_ROOTFS=... MVM_VZ_PARITY_CMDLINE="...busybox sleep..." cargo test -p mvm-build --test vz_supervisor_parity -- --test-threads=1`.
- [ ] **Step 5:** Push + open PR (base main); body notes it supersedes #730 + closes it. Close #730 with a pointer. Merge when CI green.

---

## Self-Review

- **Spec coverage:** resolver flip (T1+T2), Swift crate + build hook delete (T3), gate Rust-only (T4), docs/ADR/CI/rollup (T5), verify+grep+PR (T6) — all spec §Changes covered.
- **Placeholder scan:** real code/commands throughout; the two "read the lane/file fully before editing" notes (CI YAML, doctor block) point at concrete files because the exact surrounding YAML/Rust must be matched — not deferred work.
- **Consistency:** `resolve_supervisor_path` / `locate_vz_supervisor` both flip the same way (drop `.build`, keep adjacent+release); `source_tree_binary_path` deleted in T1 is not referenced after; gate env set (`MVM_VZ_PARITY_{RUST_BIN,KERNEL,ROOTFS,CMDLINE}`) consistent T4.
