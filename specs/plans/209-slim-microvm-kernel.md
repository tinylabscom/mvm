# Slim microVM Kernel Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Collapse mvm's two kernels into one slim `vmlinux` we own, served to both Firecracker and libkrun, then publish it as an independently-versioned, hash-verified, CVE-bumpable artifact.

**Architecture:** Promote the slim kernel from `nix/images/builder-vm/kernel/` to a shared `nix/images/kernel/`. Feed it to libkrun via the already-wired `krun_set_kernel()` FFI (replacing the bundled libkrunfw kernel on the modes that still use `set_root`). Version it `(kernel_version, config_hash) → artifact_hash` and join the ADR-046 hash-verified prebuilt release stream so a kernel CVE is a kernel-only release, not an `mvmctl` rebuild.

**Tech Stack:** Nix (`linuxManualConfig`, flakes), Rust (`mvm-backend`, `mvm-build`, `crates/deps/libkrun-sys`, `xtask`), GitHub Actions, SHA-256 hash verification.

**Spec:** [ADR-093](../adrs/093-slim-microvm-kernel.md). This plan implements its §Sequencing 1–5; §6 follow-ups (detection watcher, mvmd rollout) are out of scope and tracked under "Deferred follow-ups" below.

## Global Constraints

- **Naming hygiene:** No reference to any sibling project in filenames, branches, PRs, commits, code, or specs. Neutral mvm-native language only ("slim microVM kernel").
- **No spec refs in code comments:** Plan/PR/ADR citations never appear in code comments — reasoning only. They belong in specs/commits/PRs. (`xtask check-no-spec-refs-in-comments` gates this.)
- **Local-build invariant (ADR-046):** Source checkouts build the kernel locally from `nix/images/kernel/`; never make a source-checkout workflow depend on a published prebuilt. No external build-cache providers.
- **Attack surface is the organizing principle (ADR-002):** Every kernel-config removal cites *why nothing uses it*, framed as a CVE-class eliminated.
- **Kernel pin:** Linux `pkgs.linux_6_12` (Firecracker/builder) and `linux-6.12.91.tar.xz` (libkrunfw); keep both on the same 6.12 LTS line.
- **Test gates:** `cargo nextest run --workspace`, `cargo test --workspace --doc`, `cargo clippy --workspace -- -D warnings`, `cargo fmt --all -- --check`. Nix changes: `nix flake check --no-build` must stay green (no IFD on configfile).
- **No `#[allow(clippy::too_many_arguments)]`:** use a params struct + builder.
- **Commits:** No `Co-Authored-By: Claude` trailer; attribute to the user.

---

## File Structure

**Moved (Phase 1):**
- `nix/images/builder-vm/kernel/base.nix` → `nix/images/kernel/base.nix` — shared config foundation (`mkKernel`, `mkConfigfile`, `baseEnables`/`baseDisables`).
- `nix/images/builder-vm/kernel/default.nix` → `nix/images/kernel/builder.nix` — builder delta (virtio-fs, namespaces, netfilter).
- `nix/images/builder-vm/kernel/README.md` → `nix/images/kernel/README.md`.
- New: `nix/images/kernel/workload.nix` — workload delta (dm-verity), extracted from the inline `workloadEnables` currently in `builder-vm/flake.nix`.
- New: `nix/images/kernel/flake.nix` — standalone flake exposing `vmlinux`, `configfile`, and `artifact-manifest` outputs for both deltas.

**Modified:**
- `nix/images/builder-vm/flake.nix` — import kernel from `../kernel` instead of `./kernel`.
- `crates/mvm-backend/src/libkrun.rs` — ensure the unified kernel path flows through `set_kernel` on every libkrun mode we own (`build_supervisor_config`, `libkrun_kernel_for_host`).
- `crates/mvm-build/src/stage0.rs`, `crates/mvm-build/src/builder_vm_runtime.rs` — switch the Stage-0/builder libkrun launch from bundled-kernel `set_root` mode to our `vmlinux` (only if Gate 0 proves the slim kernel boots in that mode; otherwise documented to stay on bundled).
- `.github/workflows/` — new dedicated kernel-build + publish workflow.

**New (Rust):**
- `crates/mvm-core/src/kernel_artifact.rs` — `KernelArtifactId { kernel_version, config_hash, artifact_hash }`, hashing + serde + pin-resolution.
- `xtask/src/check_kernel_config_budget.rs` — CI size gate.

---

## Phase 1 — Promote + unify the kernel (no behavior change)

### Task 1: Move the kernel module to `nix/images/kernel/`

**Files:**
- Create: `nix/images/kernel/base.nix`, `nix/images/kernel/builder.nix`, `nix/images/kernel/README.md`
- Modify: `nix/images/builder-vm/flake.nix` (kernel import paths)
- Delete: `nix/images/builder-vm/kernel/{base.nix,default.nix,README.md}`

**Interfaces:**
- Produces: `(import ../kernel/base.nix { inherit pkgs; })` exposes `{ kernelArch, baseEnables, baseDisables, mkConfigfile, mkKernel }` — unchanged signature.
- Produces: `import ../kernel/builder.nix { inherit pkgs; base = …; }` returns the builder kernel package (was `./kernel`).

- [ ] **Step 1: Move files with git (preserve history)**

```bash
cd nix/images
git mv builder-vm/kernel/base.nix      kernel/base.nix
git mv builder-vm/kernel/default.nix   kernel/builder.nix
git mv builder-vm/kernel/README.md     kernel/README.md
```

- [ ] **Step 2: Repoint `builder-vm/flake.nix` imports**

In `nix/images/builder-vm/flake.nix`, change the two kernel references:

```nix
# was: kernelBaseFor pkgs = import ./kernel/base.nix { inherit pkgs; };
kernelBaseFor = pkgs: import ../kernel/base.nix { inherit pkgs; };
# was: kernelPkg = import ./kernel { inherit pkgs; base = kernelBaseFor pkgs; };
kernelPkg = import ../kernel/builder.nix { inherit pkgs; base = kernelBaseFor pkgs; };
```

Update the `kernel/base.nix`-relative comments in `builder.nix` to say `nix/images/kernel/`.

- [ ] **Step 3: Verify the flake still evaluates**

Run: `nix flake check ./nix/images/builder-vm --no-build`
Expected: PASS (no IFD error; `allowImportFromDerivation = false` preserved).

- [ ] **Step 4: Verify the resolved config is byte-identical (no accidental drift)**

Run:
```bash
nix build ./nix/images/builder-vm#kernel-configfile -o /tmp/k-after
git stash; nix build ./nix/images/builder-vm#kernel-configfile -o /tmp/k-before; git stash pop
diff <(grep '=y$' /tmp/k-before|sort) <(grep '=y$' /tmp/k-after|sort)
```
Expected: empty diff (move is mechanical, config unchanged).

- [ ] **Step 5: Commit**

```bash
git add -A nix/images
git commit -m "refactor(nix): promote slim kernel to nix/images/kernel/ (shared by both backends)"
```

### Task 2: Extract the workload delta into `workload.nix`

The builder flake currently defines the workload kernel inline (`workloadEnables = [ "MD" "BLK_DEV_DM" "DM_VERITY" ]`). Give it a named home so both backends consume one source.

**Files:**
- Create: `nix/images/kernel/workload.nix`
- Modify: `nix/images/builder-vm/flake.nix` (consume `workload.nix`)

**Interfaces:**
- Produces: `import ../kernel/workload.nix { inherit pkgs; base = …; }` returns the dm-verity workload kernel package (the sealed-guest kernel, claim 3).

- [ ] **Step 1: Write `workload.nix`**

```nix
# Workload-guest delta over the shared base: dm-verity (verified boot,
# ADR-002 claim 3). A sealed guest opens a dm-verity device at boot;
# the builder never does, so this lives outside the base.
{ pkgs, base }:
base.mkKernel {
  extraEnables = [ "MD" "BLK_DEV_DM" "DM_VERITY" ];
}
```

- [ ] **Step 2: Repoint the inline workload kernel in `builder-vm/flake.nix`**

Replace the inline `workloadEnables` + `mkKernel { extraEnables = workloadEnables; }` block with `import ../kernel/workload.nix { inherit pkgs; base = kernelBaseFor pkgs; }`.

- [ ] **Step 3: Verify both kernels still resolve identically**

Run:
```bash
nix build ./nix/images/builder-vm#workload-kernel-configfile -o /tmp/w-after
# compare against pre-change stash as in Task 1 Step 4
```
Expected: empty `=y` diff.

- [ ] **Step 4: `nix flake check --no-build` green; commit**

```bash
git commit -am "refactor(nix): name the workload kernel delta (workload.nix)"
```

---

## Phase 2 — Gate 0: prove the slim kernel boots under libkrun

This is a **hard go/no-go spike**, not production code. The libkrun `set_kernel` FFI is already wired (`crates/deps/libkrun-sys/src/sys.rs::set_kernel`, used by `mvm-backend/src/libkrun.rs`), so the risk is narrow: does the *unified slim* kernel boot and reach the agent over vsock under libkrun?

### Task 3: libkrun boot-feasibility spike

**Files:**
- Create (throwaway branch `spike/libkrun-slim-kernel`, not merged): a smoke driver
- Modify (spec, merged): append a "Gate 0 findings" subsection to this plan

- [ ] **Step 1: Build the unified slim workload `vmlinux`**

Run: `nix build ./nix/images/kernel#workload-vmlinux -o /tmp/slim-vmlinux` (output added in Phase 4 Task 8; for the spike, reuse `builder-vm#…` kernel output).

- [ ] **Step 2: Boot it under libkrun with an agent rootfs**

Use the existing workload launch path on this macOS/Vz-or-libkrun box (memory: this Mac boots via Vz; for libkrun set `--builder libkrun`):
```bash
MVM_CACHE_DIR=/tmp/mvm-spike-cache MVM_DATA_DIR=/tmp/mvm-spike-data \
  cargo run -- up --flake examples/agent_ping --builder libkrun --name slimk -d
cargo run -- vm wait slimk --timeout 60
```
Acceptance: VM reaches `running`; `~/.cache/mvm/.../console.log` shows kernel boot to userspace; the agent answers a vsock ping (`examples/agent_ping`).

- [ ] **Step 3: Probe each Gate-0 risk and record findings**

Confirm and write down in the findings subsection: (a) PVH/entry + load address accepted by `set_kernel` (no `krun_set_kernel` error); (b) virtio-mmio/PCI device discovery parity; (c) `hvc0` console output present; (d) gvproxy/virtio-net up without the bundled TSI kernel.

- [ ] **Step 4: Record the go/no-go decision in this plan**

Append:
```markdown
## Gate 0 findings (YYYY-MM-DD)
- Result: BOOTS / DOES-NOT-BOOT
- Evidence: <console.log excerpt, agent-ping output>
- Decision: proceed with unified path  /  fall back to Option 2 (slim libkrunfw config) for macOS only
```
Commit the findings (spec only): `git commit -am "docs(plan-209): record Gate 0 libkrun boot findings"`.

- [ ] **Step 5: Branch on outcome**

If **BOOTS** → continue to Phase 3. If **DOES-NOT-BOOT** → Phase 3 narrows to Firecracker-only unification; macOS keeps the bundled kernel and Phase 4 publishes only the Firecracker `vmlinux`. (The findings note is the authority; do not silently proceed.)

---

## Phase 3 — Measure + shrink (priority C)

### Task 4: Baseline measurement harness

**Files:**
- Create: `nix/images/kernel/measure.nix` (a derivation emitting size/symbol metrics)

**Interfaces:**
- Produces: `nix build ./nix/images/kernel#metrics` writes a JSON `{ vmlinux_bytes, vmlinux_compressed_bytes, y_symbol_count }` to `$out/metrics.json`.

- [ ] **Step 1: Write `measure.nix`**

```nix
{ pkgs, kernelPkg, configfile }:
pkgs.runCommand "mvm-kernel-metrics" { } ''
  mkdir -p $out
  img=$(ls ${kernelPkg}/{Image,bzImage,vmlinux} 2>/dev/null | head -1)
  y=$(grep -c '=y$' ${configfile})
  raw=$(stat -c%s "$img")
  comp=$(gzip -c "$img" | wc -c)
  printf '{"vmlinux_bytes":%d,"vmlinux_compressed_bytes":%d,"y_symbol_count":%d}\n' \
    "$raw" "$comp" "$y" > $out/metrics.json
''
```

- [ ] **Step 2: Capture the baseline number**

Run: `nix build ./nix/images/kernel#metrics -o /tmp/m && cat /tmp/m/metrics.json`
Record the baseline `y_symbol_count` and sizes in this plan (used as the budget ceiling in Task 6).

- [ ] **Step 3: Commit**

```bash
git commit -am "feat(nix): kernel size/symbol metrics derivation"
```

### Task 5: Audit-driven subtraction pass

**Files:**
- Modify: `nix/images/kernel/base.nix` (`baseDisables`)

- [ ] **Step 1: Enumerate remaining `=y` subsystems**

Run: `grep '=y$' /tmp/m/../configfile | sort` (from Task 4) and list every subsystem not already justified in `base.nix` comments.

- [ ] **Step 2: For each candidate, trace usage before disabling**

For netfilter (builder-only — confirm workload needs none), block layer beyond ext4/overlay, RTC, balloon, etc.: grep the guest init + agent + `mvm-host-vm-init` for any dependency. Only disable where nothing references it.

- [ ] **Step 3: Add justified disables, one subsystem per edit**

Each entry gets an attack-surface-framed comment (no spec refs), e.g.:
```nix
# No SCSI/ATA transport behind virtio — drops that driver class and its
# CVE surface. olddefconfig drops the subtree.
"SCSI" "ATA"   # (illustrative — keep only genuinely-unused removals)
```

- [ ] **Step 4: Re-measure and confirm boot still works**

Run: rebuild `#metrics`; re-run the Phase-2 agent-ping boot smoke. Expected: `y_symbol_count` strictly lower, VM still boots + agent answers.

- [ ] **Step 5: Commit**

```bash
git commit -am "perf(nix): shrink slim kernel by NN symbols (attack-surface subtraction)"
```

### Task 6: CI size-budget gate

**Files:**
- Create: `xtask/src/check_kernel_config_budget.rs`
- Modify: `xtask/src/main.rs` (register the subcommand)

**Interfaces:**
- Produces: `cargo run -p xtask -- check-kernel-config-budget` exits nonzero if the kernel `=y` count exceeds the recorded budget or the justified-disable list regressed.

- [ ] **Step 1: Write the failing test**

```rust
// xtask/src/check_kernel_config_budget.rs
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn over_budget_config_is_rejected() {
        let cfg = "CONFIG_A=y\nCONFIG_B=y\nCONFIG_C=y\n";
        assert!(evaluate_budget(cfg, 2).is_err()); // 3 > 2
    }
    #[test]
    fn within_budget_passes() {
        let cfg = "CONFIG_A=y\n# CONFIG_X is not set\n";
        assert!(evaluate_budget(cfg, 5).is_ok());
    }
}
```

- [ ] **Step 2: Run it, watch it fail**

Run: `cargo test -p xtask over_budget_config_is_rejected`
Expected: FAIL (`evaluate_budget` not defined).

- [ ] **Step 3: Implement `evaluate_budget`**

```rust
pub fn evaluate_budget(config: &str, budget: usize) -> anyhow::Result<()> {
    let y = config.lines().filter(|l| l.trim_end().ends_with("=y")).count();
    if y > budget {
        anyhow::bail!("kernel =y symbol count {y} exceeds budget {budget}");
    }
    Ok(())
}
```

Wire a `check-kernel-config-budget` arm in `xtask/src/main.rs` that builds `#configfile`, reads it, and calls `evaluate_budget(&cfg, BUDGET)` with `BUDGET` set to the Task-4 baseline.

- [ ] **Step 4: Run tests, then the gate**

Run: `cargo test -p xtask` then `cargo run -p xtask -- check-kernel-config-budget`
Expected: tests PASS; gate PASS at current size.

- [ ] **Step 5: Add the gate to the Lint job and commit**

Add the invocation to `.github/workflows/ci.yml`'s Lint lane (sibling to `check-spec-numbers`). Commit:
```bash
git commit -am "feat(xtask): CI gate pinning the slim-kernel symbol budget"
```

---

## Phase 4 — Kernel as an independently-versioned, published artifact

### Task 7: `KernelArtifactId` identity type

**Files:**
- Create: `crates/mvm-core/src/kernel_artifact.rs`
- Modify: `crates/mvm-core/src/lib.rs` (`pub mod kernel_artifact;`)

**Interfaces:**
- Produces: `KernelArtifactId { kernel_version: String, config_hash: String, artifact_hash: String }` with `compute_artifact_hash(vmlinux_bytes) -> String` (sha256 hex) and serde derive. Consumed by Task 9 (publish) and Task 10 (pin-resolution).

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn artifact_hash_is_stable_sha256_hex() {
    let h = compute_artifact_hash(b"vmlinux-bytes");
    assert_eq!(h.len(), 64);
    assert_eq!(h, compute_artifact_hash(b"vmlinux-bytes"));
    assert_ne!(h, compute_artifact_hash(b"other"));
}

#[test]
fn artifact_id_serde_roundtrip() {
    let id = KernelArtifactId {
        kernel_version: "6.12.91".into(),
        config_hash: "abc".into(),
        artifact_hash: "def".into(),
    };
    let j = serde_json::to_string(&id).unwrap();
    assert_eq!(serde_json::from_str::<KernelArtifactId>(&j).unwrap(), id);
}
```

- [ ] **Step 2: Run, verify failure**

Run: `cargo test -p mvm-core kernel_artifact`
Expected: FAIL (module missing).

- [ ] **Step 3: Implement the type**

```rust
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelArtifactId {
    pub kernel_version: String,
    pub config_hash: String,
    pub artifact_hash: String,
}

pub fn compute_artifact_hash(vmlinux: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(vmlinux);
    hex::encode(h.finalize())
}
```

(Reuse workspace `sha2`/`hex` — both already deps; do not add new ones.)

- [ ] **Step 4: Run tests, pass**

Run: `cargo test -p mvm-core kernel_artifact && cargo clippy -p mvm-core -- -D warnings`
Expected: PASS, zero warnings.

- [ ] **Step 5: Commit**

```bash
git commit -am "feat(core): KernelArtifactId — (version, config_hash, artifact_hash)"
```

### Task 8: Standalone kernel flake with publishable outputs

**Files:**
- Create: `nix/images/kernel/flake.nix`

**Interfaces:**
- Produces flake outputs: `workload-vmlinux`, `builder-vmlinux`, `workload-configfile`, `builder-configfile`, `metrics`, and `artifact-manifest` (writes `KernelArtifactId` JSON + a `*-checksums-sha256.txt`).

- [ ] **Step 1: Write the flake exposing both deltas + a manifest**

The `artifact-manifest` derivation computes `config_hash = sha256(configfile)`, `artifact_hash = sha256(vmlinux)`, `kernel_version = "6.12.91"`, and writes `kernel-<arch>-checksums-sha256.txt` in the claim-6 download format.

- [ ] **Step 2: Build the manifest locally**

Run: `nix build ./nix/images/kernel#artifact-manifest -o /tmp/km && cat /tmp/km/*.json /tmp/km/*checksums*`
Expected: well-formed `KernelArtifactId` JSON + a `<sha256>  vmlinux` line.

- [ ] **Step 3: `nix flake check ./nix/images/kernel --no-build`; commit**

```bash
git commit -am "feat(nix): standalone kernel flake with publishable vmlinux + manifest"
```

### Task 9: Dedicated kernel build + publish CI workflow

**Files:**
- Create: `.github/workflows/kernel.yml`

- [ ] **Step 1: Author the workflow**

Triggers: changes under `nix/images/kernel/**` (build + verify on PR) and release tags (publish). Steps: `nix build .#{workload,builder}-vmlinux #artifact-manifest`; on release, upload `vmlinux` + `kernel-<arch>-checksums-sha256.txt` to the GitHub release (extends the ADR-046 prebuilt stream). Off the hot PR critical path — only this workflow compiles the kernel.

- [ ] **Step 2: Validate workflow syntax**

Run: `actionlint .github/workflows/kernel.yml` (or `gh workflow view` after push).
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git commit -am "ci: dedicated kernel build/publish workflow (off the hot PR path)"
```

### Task 10: Host pin-resolution — build-local or fetch-verified

**Files:**
- Modify: `crates/mvm-build/src/runtime_overlay.rs` (reuse its hash-verify helper) or create `crates/mvm-build/src/kernel_fetch.rs`
- Modify: `crates/mvm-backend/src/libkrun.rs` + the Firecracker path to resolve the kernel by `KernelArtifactId`

**Interfaces:**
- Consumes: `KernelArtifactId` (Task 7), the `*-checksums-sha256.txt` (Task 8/9), and `runtime_overlay`'s existing SHA-256 stream-verify (claim-6 pattern; honors `MVM_SKIP_HASH_VERIFY`).
- Produces: `resolve_kernel(id: &KernelArtifactId) -> Result<PathBuf>` — returns a locally-built `vmlinux` in a source checkout (`find_builder_vm_flake().is_some()`), else fetches the prebuilt and verifies its `artifact_hash` before returning.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn fetched_kernel_rejected_on_hash_mismatch() {
    let id = KernelArtifactId { kernel_version: "6.12.91".into(),
        config_hash: "c".into(), artifact_hash: "expected".into() };
    let tmp = tempfile::tempdir().unwrap();
    let bad = tmp.path().join("vmlinux");
    std::fs::write(&bad, b"tampered").unwrap();
    assert!(verify_fetched_kernel(&bad, &id).is_err());
}
```

- [ ] **Step 2: Run, verify failure**

Run: `cargo test -p mvm-build fetched_kernel_rejected_on_hash_mismatch`
Expected: FAIL (`verify_fetched_kernel` undefined).

- [ ] **Step 3: Implement `verify_fetched_kernel` + `resolve_kernel`**

`verify_fetched_kernel` streams the file through `Sha256`, compares to `id.artifact_hash`, deletes + errors on mismatch (mirror `runtime_overlay`'s reject-and-delete). `resolve_kernel` branches on `find_builder_vm_flake()`: build-local vs fetch+verify. Source checkouts never fetch (local-build invariant).

- [ ] **Step 4: Run tests + the source-checkout-builds-local assertion**

```rust
#[test]
fn source_checkout_builds_local_never_fetches() {
    // with a stub flake-present probe, resolve_kernel must not hit the network
}
```
Run: `cargo nextest run -p mvm-build kernel && cargo clippy -p mvm-build -- -D warnings`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git commit -am "feat(build): resolve kernel by KernelArtifactId (build-local or fetch-verified)"
```

---

## Phase 5 — Single-VM remediation primitive

### Task 11: Rebuild-from-new-pin + relaunch

**Files:**
- Modify: `crates/mvm-backend/src/libkrun.rs` (and Firecracker path) to read the kernel pin at start
- Modify: `crates/mvm-cli/src/commands/` (a `vm rekernel <name>` or extend relaunch) — wire the single-VM remediation verb

**Interfaces:**
- Consumes: `resolve_kernel` (Task 10).
- Produces: relaunching a stopped VM with a changed `KernelArtifactId` boots it on the new `vmlinux` with no `mvmctl` rebuild.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn relaunch_with_new_pin_uses_new_kernel_path() {
    let old = KernelArtifactId{ kernel_version:"6.12.90".into(), config_hash:"c".into(), artifact_hash:"a".into() };
    let new = KernelArtifactId{ kernel_version:"6.12.91".into(), config_hash:"c".into(), artifact_hash:"b".into() };
    let cfg = VmStartConfig::for_test().with_kernel_pin(new.clone());
    assert_eq!(resolved_kernel_id(&cfg), &new);
    assert_ne!(resolved_kernel_id(&cfg), &old);
}
```

- [ ] **Step 2: Run, verify failure**

Run: `cargo test -p mvm-backend relaunch_with_new_pin`
Expected: FAIL.

- [ ] **Step 3: Thread the pin through `VmStartConfig` → `build_supervisor_config`**

Add `kernel_pin: Option<KernelArtifactId>` to the start config; `build_supervisor_config` calls `resolve_kernel(pin)` when present, falling back to the literal `kernel_path` otherwise (back-compat for in-tree dev). Use a params struct if the arg count trips clippy.

- [ ] **Step 4: Run tests + clippy**

Run: `cargo nextest run -p mvm-backend && cargo clippy -p mvm-backend -- -D warnings`
Expected: PASS.

- [ ] **Step 5: Live smoke (KVM box or this Mac)**

```bash
cargo run -- up --flake examples/agent_ping --name rk -d
cargo run -- vm stop rk
# bump the pin, then:
cargo run -- vm rekernel rk --to <new-artifact_hash>
cargo run -- vm wait rk --timeout 60   # boots on new kernel, agent answers
```

- [ ] **Step 6: Commit**

```bash
git commit -am "feat: single-VM rekernel — relaunch on a new kernel pin without mvmctl rebuild"
```

---

## Phase 6 — Docs + status bookkeeping

### Task 12: Update kernel README, CLAUDE.md pointers, refactor status

**Files:**
- Modify: `nix/images/kernel/README.md` (now the canonical home; document both deltas + the artifact/publish model)
- Modify: `CLAUDE.md` (the libkrunfw/`extract_bundled_kernel` paragraph — note libkrun now boots our unified slim kernel via `set_kernel`)
- Modify: `specs/REFACTOR-STATUS.md` + `specs/SPRINT.md` (tick the workstream; bump "Last updated")

- [ ] **Step 1: Rewrite the README** for the unified, published, two-backend kernel; drop builder-VM-specific framing.

- [ ] **Step 2: Correct the CLAUDE.md macOS-kernel claim** to reflect `set_kernel` of our `vmlinux` (bundled kernel only the historical fallback).

- [ ] **Step 3: Update `specs/REFACTOR-STATUS.md` + `specs/SPRINT.md`** per the repo's "move together with the plan checkboxes" rule.

- [ ] **Step 4: Run the full gate**

Run: `cargo fmt --all -- --check && cargo nextest run --workspace && cargo test --workspace --doc && cargo clippy --workspace -- -D warnings && cargo run -p xtask -- check-spec-numbers && cargo run -p xtask -- check-no-spec-refs-in-comments && cargo run -p xtask -- check-kernel-config-budget`
Expected: all green.

- [ ] **Step 5: Commit**

```bash
git commit -am "docs(plan-209): unified slim-kernel docs + status rollup"
```

---

## Deferred follow-ups

- [ ] **Detection watcher** — sibling plan: flag when `linux_6_12.y` trails the latest LTS point release or is hit by a published Linux CVE (sibling to ADR-002 claim 7's `cargo audit`). Not in this plan.
- [ ] **mvmd fleet rollout** — drain-and-roll across running microVMs lives in the mvmd repo. mvm exposes the single-VM primitive (Task 11); mvmd consumes it. Not in this repo.
- [ ] **Option 2 fallback wiring** — only if Gate 0 (Task 3) says DOES-NOT-BOOT: slim `nix/packages/libkrunfw.nix`'s bundled config for macOS. Tracked here, built only on that branch.
</content>

## Gate 0 findings (2026-06-21)

**Regression caught — and fixed — before the unified path could mislead us.**

- **Setup:** libkrun 1.18.0 + libkrunfw 5.3.0 + gvproxy 0.8.8 on macOS 26.5.1 (arm64); binaries signed with the Hypervisor entitlement (`mvmctl env sign`); isolated `MVM_CACHE_DIR`/`MVM_DATA_DIR`; no host nix / no linux-builder (all builds via the libkrun builder VM, per the project invariant).
- **First result: BROKE at Stage 0 eval.** `mvmctl build kernel build --which workload --source compile` failed:
  `error: path '/nix/store/kernel/workload.nix' does not exist` (impure Stage 0) / `access to absolute path … forbidden` (pure host repro).
- **Root cause:** Tasks 1–2 imported the promoted kernel via `import ../kernel/X.nix`. That resolves fine when the repo is a **`git+file`** flake (whole tree copied to the store — which is why `nix flake check` and the `.drv`-hash proofs passed), but the libkrun builder VM fetches `builder-vm` as a **`path:`** flake — nix copies only that subtree, so `..` escapes the store copy. The two byte-identical-`.drv` proofs were in the wrong resolution mode to see it; CI's flake-check lane (also `git+file`) would not have caught it either. **Gate 0 was the only thing that would.**
- **Fix (commit 07dd9c12):** route the kernel imports through `workspaceRoot` (`MVM_WORKSPACE_PATH`) — the exact mechanism `builder-vm/flake.nix` already uses for `nix/lib`. Verified via fast host repro (no Stage 0 / no linux-builder needed): `nix eval --impure` against `path:…#workload-kernel.drvPath` and `#builder-kernel.drvPath` both resolve; `git+file` mode produces the identical `.drv`; `flake check --no-build` stays green.
- **Process consequence:** the byte-identical-`.drv` verification used for Tasks 1–2 is insufficient on its own for the kernel-promotion class of change — it must be paired with a `path:`-mode eval (`nix eval --impure -L path:…/builder-vm#…-kernel.drvPath` with `MVM_WORKSPACE_PATH` set). Added to the task checklist below.
- **Decision: PROCEED with the unified path** — the `set_kernel` FFI is already wired and the slim kernel now resolves under the builder VM. Live boot-to-agent confirmation continues (real Stage 0 compile in progress).

### Added verification step (applies to any kernel-flake-structure change)
- [ ] `nix eval --impure path:$PWD/nix/images/builder-vm#packages.<arch>-linux.workload-kernel.drvPath` with `MVM_WORKSPACE_PATH=$PWD` must resolve (catches `path:`-flake escapes that `git+file`/`flake check` miss).

### Gate 0 result: PASS (live on macOS 26.5.1 / libkrun, 2026-06-21)

End-to-end on this host, all via the libkrun builder VM (no host nix / no linux-builder):
- `mvmctl build kernel build --which workload --source compile` → slim workload **vmlinux compiled inside the builder VM** (20.2 MiB) after the flake fix.
- `mvmctl dev up --no-shell --builder libkrun` → **full builder image built** (rootfs.ext4 780 MB + kernel) via Stage 0.
- `mvmctl up --flake examples/sleeper --hypervisor libkrun -d` → **workload booted under libkrun** (`backend=libkrun`, `mvm-libkrun-supervisor` pid alive).
- `mvmctl vm wait` → exit 0; `mvmctl vm boot-report` → **control plane ready, vsock bound, first accept 44s** = guest agent reachable over vsock.

**Decision: PROCEED with the unified path.** libkrun boots a workload to a live vsock agent on the promoted+fixed kernel tree. (Note: `--builder` selects the *builder* backend; `--hypervisor` selects the *workload runtime* — on macOS 26 the workload defaults to Vz, so libkrun workload boot needs explicit `--hypervisor libkrun`. Both Vz and libkrun workload boots reached the agent.)
