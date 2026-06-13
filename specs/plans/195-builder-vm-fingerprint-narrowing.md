# Plan 195 — Narrow the builder-VM source fingerprint

> **For agentic workers:** steps use checkbox (`- [ ]`) syntax. Land the two
> commits in order; Commit 2 is droppable without affecting Commit 1's win.

> **Status: 🟡 planned.** Spun out of the build-perf finding recorded in
> [Plan 193](./193-rvproxy-network-substrate.md) §"Build slowness is the
> base-VM fingerprint churn". Plan number 194 is reserved for ADR-081 A3
> (see `specs/SPRINT.md`); this takes 195.

**Goal:** Stop routine multi-crate development from spuriously busting the
builder-VM image cache — the ~9s Stage 0 re-materialize that fires on most
`mvmctl dev up` runs — without ever reusing a genuinely-stale builder VM.

**Tech stack:** Rust (`crates/mvm-cli`), the `build.rs` host-binary
cross-compile, the `builder_vm_source_fingerprint` cache key.

---

## Diagnosis

`builder_vm_source_fingerprint` (in
`crates/mvm-cli/src/commands/env/dev_vz.rs`) is the cache key that decides
whether `mvmctl dev up` reuses the cached builder-VM image or rebuilds it
through the Stage 0 nix-seed bootstrap. On a fingerprint **hit** the flow
short-circuits to `UseCached`; on a **miss** it runs `prepare_assets`
(~9s materialize) + the in-VM nix build + bakes the rootfs.

Today the fingerprint folds five layers:

- **L1** — the builder-VM flake (`flake.nix` + `flake.lock`).
- **L2** — the **whole workspace `Cargo.lock`**.
- **L3** — the embedded host-binary identity (`name + sha256` of each of
  `mvm-host-vm-init`, `mvm-egress-proxy`), via `fold_embedded_binary_identity`.
- **L5** — `nix/lib` (recursive).

L2 is the dominant churn source: any workspace-wide dependency bump — common
under active development with several crates in flight — rewrites `Cargo.lock`
and busts the cache, forcing a full rebuild.

**L2 is redundant and over-broad.** Its in-code rationale —
"`rustPlatform.buildRustPackage` consumes it for every Rust binary baked into
the rootfs" — is false for this flake: `nix/images/builder-vm/flake.nix`
explicitly forbids `buildRustPackage` ("no rustPlatform.buildRustPackage
calls are permitted in this flake"). It installs `cargo`/`rustc` as in-VM
*tools*, but compiles no workspace crate. The only Rust baked into the
builder VM is the two embedded host binaries — and L3 already hashes their
exact output bytes, which captures their source, full dependency closure, and
cross-compile toolchain more precisely than a workspace-wide lockfile.

A second, pre-existing gap surfaced while tracing this: `build.rs` only
re-cross-compiles the embedded binaries when `crates/mvm-build/src/bin/`, the
workspace `Cargo.toml`, or `manifest.rs` change — **not** when the `mvm-build`
*lib* or a `Cargo.lock` dependency changes. So today a dep bump that affects
the host binaries leaves the embedded bytes stale (build.rs doesn't rerun),
and L2 merely triggers a pointless rebuild that re-bakes the *same stale
bytes*. L2 never actually protected binary freshness.

## Security analysis

This is a build-performance change inside a host-trusted, non-workload tier.
It changes **no** security guarantee. Claim-by-claim:

- **Not a claim witness.** `builder_vm_source_fingerprint` is a local
  dev-build cache key — absent from `specs/claims/catalog.md`, the `xtask`
  claim gates, and every CI workflow. It governs *whether to rebuild the
  builder VM*, nothing about what runs as a workload.
- **Wrong tier for the guest-hardening claims.** The builder VM is the
  dev/build environment, not a workload guest. Claims 1–5 and 15 (no-exec,
  no-console, verified boot, setpriv confinement) apply to the workload/prod
  guest — see ADR-002's tier matrix and "dev builder VM ≠ prod runtime tiers".
- **Claims 8 / 9 / 14** (signed `ExecutionPlan`, content-addressed bundles,
  OCI provenance) verify *artifacts* at fetch/admit time, downstream of and
  independent from the builder-VM cache key. A stale builder VM cannot smuggle
  anything past admission.
- **Claim 11** (sealed app-deps volume) is the one claim adjacent to the
  embedded host binaries (`mvm-host-vm-init` runs the Install arm). Commit 1
  does not alter *what* is embedded or the `MVM_SKIP_EMBED_BINARIES` stub
  guard — it drops a redundant cache input. Commit 2 makes the binaries
  rebuild on *more* inputs, strictly improving freshness. The sealed volume
  is hash-chained and re-verified by `verify_sealed_volume` at admit
  regardless of builder-VM caching.
- **Claim 6** (dev image hash-verified) is the `download_dev_image` SHA-256
  manifest check — a different mechanism on the download path, not involved.
- **Claim 7** (`deny.toml` + reproducible double-build) is untouched.

The only residual risk is *build correctness* — reusing a builder VM stale
relative to its inputs. Commit 1 is strictly safer than today (it removes an
input that gates nothing, since the flake forbids `buildRustPackage`); Commit
2 adds the real freshness protection. L1 (flake) and L5 (`nix/lib`) stay in
the fingerprint, so ADR-046's "a contributor's flake edit shows up in the
next `dev up`" invariant holds.

---

## Commit 1 — drop L2 (the perf win)

**Files:**
- Modify: `crates/mvm-cli/src/commands/env/dev_vz.rs` —
  `builder_vm_source_fingerprint` (the L2 block + its missing-`Cargo.lock`
  bail) and the fingerprint unit tests.

- [ ] **Step 1: Invert the Cargo.lock test to assert non-invalidation.**
      Rewrite `builder_vm_source_fingerprint_changes_with_cargo_lock` →
      `builder_vm_source_fingerprint_is_unaffected_by_cargo_lock`:

```rust
#[test]
fn builder_vm_source_fingerprint_is_unaffected_by_cargo_lock() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let flake = write_builder_vm_workspace(tmp.path());
    let first = builder_vm_source_fingerprint(flake.to_str().unwrap()).expect("fingerprint");

    // The builder-VM flake forbids `buildRustPackage`; no flake artifact
    // consumes the workspace lockfile. The only baked Rust is the embedded
    // host binaries, whose identity rides on L3 (their output-byte sha256).
    // A `cargo update` therefore must NOT bust the builder-VM cache.
    std::fs::write(tmp.path().join("Cargo.lock"), "# stub Cargo.lock — updated\n")
        .expect("rewrite Cargo.lock");
    let second = builder_vm_source_fingerprint(flake.to_str().unwrap()).expect("fingerprint");

    assert_eq!(
        first, second,
        "a workspace Cargo.lock edit must not invalidate the builder-vm cache key"
    );
}
```

- [ ] **Step 2: Run it; watch it fail.**
      `cargo nextest run -p mvm-cli -E 'test(builder_vm_source_fingerprint_is_unaffected_by_cargo_lock)'`
      → FAIL (`assert_eq` — L2 still hashes `Cargo.lock`).

- [ ] **Step 3: Delete L2 + drop the now-dead missing-lockfile test.**
      Remove the "Layer 2: workspace Cargo.lock" block (the `cargo_lock`
      read, its `is_file()` bail, and the `hash_named_file(... "Cargo.lock"
      ...)` call) from `builder_vm_source_fingerprint`. Delete
      `builder_vm_source_fingerprint_errors_when_cargo_lock_missing`. Update
      the function's layer comment so it states the remaining layers are L1
      (flake) + L3 (embedded host-bin identity, authoritative for all baked
      Rust) + L5 (`nix/lib`), and why L2 was removed (no `buildRustPackage`
      in the flake).

- [ ] **Step 4: Confirm the inverted test passes and the L3-authority test
      still holds.**
      `cargo nextest run -p mvm-cli -E 'test(/builder_vm_source_fingerprint|fold_embedded_binary_identity/)'`
      → all PASS. `fold_embedded_binary_identity_distinguishes_inputs` and
      `builder_vm_source_fingerprint_changes_with_flake_inputs` are the
      remaining cache-invalidation guards.

- [ ] **Step 5: Commit.**
      `feat(dev): drop redundant workspace Cargo.lock from builder-VM fingerprint (plan 195)`

## Commit 2 — tighten `build.rs` (the correctness floor)

**Files:**
- Modify: `crates/mvm-cli/build.rs` — broaden the `rerun-if-changed` set so
  the embedded host binaries rebuild when their real inputs change, making L3
  genuinely authoritative.

- [ ] **Step 1: Add rerun-if-changed for the binaries' real inputs.**
      In the embed loop / trailer of `build.rs`, emit `cargo:rerun-if-changed`
      for the workspace `Cargo.lock` and the `mvm-build` lib source, alongside
      the existing `crates/mvm-build/src/bin`, workspace `Cargo.toml`, and
      `manifest.rs` triggers:

```rust
println!(
    "cargo:rerun-if-changed={}",
    workspace_root.join("Cargo.lock").display()
);
println!(
    "cargo:rerun-if-changed={}",
    workspace_root.join("crates/mvm-build/src").display()
);
```

- [ ] **Step 2: Verify the host binaries still cross-compile + embed.**
      Clean-build mvmctl (no `MVM_SKIP_EMBED_BINARIES`) and confirm the
      embedded table is populated with non-empty bytes:
      `cargo build -p mvm-cli 2>&1 | grep -i 'cargo zigbuild'` shows the
      cross-compile ran; the build succeeds.

- [ ] **Step 3: Confirm an `mvm-build` lib edit now retriggers the embed.**
      Touch a file under `crates/mvm-build/src/` (a no-op whitespace change),
      rebuild `-p mvm-cli`, and confirm `[build.rs] cargo zigbuild` runs again
      (it would not have before this commit). Revert the no-op edit.

- [ ] **Step 4: Commit.**
      `fix(build): rebuild embedded host binaries on mvm-build/Cargo.lock changes (plan 195)`
      If reproducible-cross-compile flakiness or over-rebuilding shows up,
      this commit is droppable; Commit 1's perf win stands alone.

---

## Verification

- [ ] `cargo nextest run -p mvm-cli` — all dev/fingerprint tests green.
- [ ] `cargo clippy -p mvm-cli --all-targets -- -D warnings` (note: a
      pre-existing `checkpoint.rs:1199` nit may fire on local clippy 1.95.0;
      it is not introduced here and CI's pinned clippy does not flag it).
- [ ] `rustup run nightly cargo fmt --all`.
- [ ] **Manual macOS-26:** two consecutive `mvmctl dev up` runs with an
      intervening unrelated-crate `Cargo.lock` bump both report cache `hit`
      (the `Builder VM source cache decision:` progress line, with
      `--verbose`); editing `nix/lib` or `flake.nix` still reports
      `fingerprint_mismatch` and rebuilds.

## Success criteria

- [ ] A workspace `Cargo.lock` change no longer triggers a builder-VM rebuild.
- [ ] A builder-VM flake or `nix/lib` change still triggers a rebuild.
- [ ] An embedded-host-binary byte change still triggers a rebuild (L3).
- [ ] Editing the `mvm-build` lib retriggers the host-binary cross-compile
      (Commit 2), so L3 reflects the change.
- [ ] No security claim or CI gate regresses (analysis above).

## Deferred follow-ups

- [ ] Make the musl host-binary cross-compile byte-reproducible (so an
      unchanged source can never churn L3 even on a forced rebuild). Separate
      effort; not the churn driver.
- [ ] Consider folding the Stage 0 seed/flavor version into the fingerprint
      (today stable + pinned in `mvm-build`; not a churn source, but it is an
      uncovered input to the built image).
