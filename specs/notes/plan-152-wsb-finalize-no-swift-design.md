# Design — Plan 152 WS-B finalization: native objc2 VZ supervisor, no Swift

> **Status (2026-06-08):** Approved direction. Completes Plan 152's headline goal —
> "VZ natively supported in Rust/objc2" — by making the Rust supervisor (#700) the
> *only* supervisor and deleting the Swift crate. WS-C (fork) and WS-D (nested KVM)
> are out of scope (separate future workstreams on top of the native supervisor).

## Goal

The Rust-native `objc2` VZ supervisor (`mvm-vm-host` `[[bin]] mvm-vz-supervisor`,
landed in #700, live-validated boot/control/save/restore) becomes the sole VZ
supervisor. The Swift crate is deleted; `mvmctl` resolves and runs only the Rust
binary. This also retires a real defect: the Swift control socket self-deadlocks on
async VZ ops (`synchronousVZCall` blocks the VM's serial queue waiting for a
completion dispatched to that same queue) — the Rust serial-queue→tokio bridge fixes
it. Removing Swift removes the buggy default.

## Scope

In: flip the supervisor resolver to the Rust bin, delete the Swift crate + its build
coupling, make the parity gate Rust-only, refresh docs/ADR/rollup.

Out (separate future plans, not needed for "no Swift / native objc2"):
- **WS-C** fork primitive (ties to Plan 148 fork-fanout). Snapshot/restore already
  shipped in #700.
- **WS-D** nested KVM `/dev/kvm` in guest (ties to Plan 147).

## Changes

### 1. Resolver flip — `crates/mvm-backend/src/vz.rs::resolve_supervisor_path` (:1102)

Current order: (1) `MVM_VZ_SUPERVISOR_PATH` override, (2) adjacent to `current_exe`,
(3) **Swift** `.build/<arch>-apple-macosx/<config>/mvm-vz-supervisor` source-checkout
path, (4) release `~/.mvm/bin/mvm-vz-supervisor-<version>`.

**Drop step (3)** (the Swift `.build` lookup). Keep (1) override, (2) adjacent-to-exe
(this already finds the cargo-built Rust bin: `cargo run`/installed `mvmctl` sits in
`target/<profile>/` or `~/.mvm/bin/` next to `mvm-vz-supervisor`), (4) release layout.
This mirrors `mvm-libkrun-supervisor`'s resolver (`libkrun.rs`, `MVM_LIBKRUN_SUPERVISOR_PATH`
+ adjacent + release). Update the "not found" message to point at
`cargo build -p mvm-vm-host --bin mvm-vz-supervisor` instead of `tools/build.sh`.

Same flip in `crates/mvm-cli/src/doctor.rs:850-887` (the doctor supervisor-resolution
chain references the Swift `.build` path — drop it, mirror vz.rs).

### 2. Delete the Swift crate + build coupling

- `rm -rf crates/mvm-vz-supervisor/` (Package.swift, Sources, Tests, tools/build.sh,
  Entitlements.plist, README.md).
- Delete `crates/mvm-build/build.rs`'s Swift auto-build hook (it shells out to
  `tools/build.sh` / `swift build`). If that's the file's only job, delete the whole
  `build.rs` + drop its `build = ...` / `[build-dependencies]` from `mvm-build/Cargo.toml`;
  if it does other work, excise only the Swift section. Verify by reading the file.
- Remove the Swift-build steps from `.github/workflows/ci-full.yml` and
  `.github/workflows/security.yml` (the lanes that `swift build` the supervisor /
  reference `mvm-vz-supervisor` Swift). The Rust bin builds via normal `cargo build`.

### 3. Parity gate → Rust-only — `crates/mvm-build/tests/vz_supervisor_parity.rs`

**Supersedes #730** (close it). With Swift gone there is nothing to compare against,
so the gate validates the Rust supervisor directly. Concretely:
- `boot_*`, `control_verbs_*`, `save_restore_*`, vsock round-trip → probe **only** the
  Rust bin; drop the Swift bin resolution + the `swift` probes.
- Carry the live-validated fixes (already proven on macOS 26): `probe_save_restore`
  PAUSEs before SAVE (VZ rejects saving a running VM) and `create_dir_all`s the restore
  state dir (else the supervisor's console-log open ENOENTs); add `MVM_VZ_PARITY_CMDLINE`
  so a long-lived guest can be supplied (dev `/init` self-exits on console EOF).
- Env vars collapse to the Rust set (`MVM_VZ_PARITY_{RUST_BIN,KERNEL,ROOTFS,CMDLINE}`);
  drop `MVM_VZ_PARITY_SWIFT_BIN`. Live tests still skip cleanly without them.

### 4. Docs + ADR + rollup

- Fix now-wrong "Swift" comments: `vz.rs` module header (:6-23), `vz_control.rs`
  (:1-7, "Rust client for the Swift supervisor" → "client for the supervisor control
  socket"), `gateway_bridge.rs:18` ("Splice happens in Swift" → in-process Rust),
  `Cargo.toml` workspace comments (:17/:69/:326).
- **ADR-056 addendum**: record the Swift→Rust completion + the Swift serial-queue
  control-socket deadlock as the motivating defect the Rust port fixes.
- `specs/REFACTOR-STATUS.md`: Plan 152 — tick WS-B finalize; mark Plan 152 core
  (WS-A/WS-B/WS-E) done, WS-C/WS-D remaining as separate workstreams.

## Invariants / risk

- The entitled-TCB Rust supervisor was security-reviewed in #700 (claims 1/15/vsock
  posture preserved; slice-8 flow-audit fail-closed). This PR adds no new supervisor
  behavior — it changes the *default* from Swift to Rust, which is a correctness win
  (Swift deadlocks; Rust doesn't).
- No `MVM_VZ_SUPERVISOR_PATH` behavior change (override still wins).
- Source-checkout contributors must `cargo build` the Rust bin (same as the libkrun
  supervisor today — `reference_libkrun_supervisor_separate_binary_rebuild`); doctor's
  hint + the resolver "not found" message guide this.

## Testing

- `cargo build --workspace` (the Rust `mvm-vz-supervisor` bin builds; no Swift).
- `cargo fmt --all -- --check` (nightly), `cargo clippy --workspace -- -D warnings`,
  `cargo nextest run --workspace -E 'not package(mvm-backend)'`, `cargo test --workspace --doc`.
- Rust-only parity gate validated **live on macOS 26 / Apple Silicon** (already done in
  the #731 spike: boot/control/save/restore green with the pause+mkdir+cmdline fixes).
- `core_demo_e2e` already tolerates the supervisor-not-built case (`core_demo_e2e.rs:78`);
  confirm its Swift-specific comment is updated.
- Grep gate: no remaining `crates/mvm-vz-supervisor` / `tools/build.sh` / "Swift"
  supervisor references in code, CI, or Cargo manifests.

## References

- `specs/plans/152-rust-native-vz-and-init-lifecycle-parity.md` — WS-B finalize steps.
- `specs/adrs/056-*.md` — entitled-TCB / drop-Swift rationale (gets the addendum).
- `crates/mvm-backend/src/libkrun.rs` — the Rust-supervisor resolver pattern to mirror.
- #700 (Rust supervisor, merged), #703 (parity gate, merged), #730 (gate-hardening — superseded by §3).
