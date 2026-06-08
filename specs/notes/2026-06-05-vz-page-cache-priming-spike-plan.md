# Vz Page-Cache Priming Spike — Implementation Plan (runbook)

> **For agentic workers:** REQUIRED SUB-SKILL: use superpowers:executing-plans to run
> this task-by-task. This is a **measurement runbook**, not a TDD feature build — the
> per-step "verify" is an observed command output or an abort gate, not a unit test.
> Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Get a real number on whether a warm guest page cache speeds first-read after
a **Vz workload** snapshot restore — to decide the fate of the Plan 157 page-cache-priming
follow-up (ADR-073 §1).

**Architecture:** Boot a fat dev-shell **workload** microVM on `VzBackend`, snapshot-save
it twice (once with the working set pre-read = *primed*, once untouched = *cold*),
restore each, and time the first read of the working set via `mvmctl console --command`.
The builder/dev VM appears in exactly one step — building the measurement image — and is
never the thing measured. Everything else is workload-on-Vz.

**Tech stack:** `mvmctl` CLI (`up --hypervisor vz`, `snapshot save/restore`, `console
--command`), the codesigned Swift `mvm-vz-supervisor`, a copied dev-shell Nix flake.

**Design source:** `specs/notes/2026-06-05-vz-page-cache-priming-spike.md` (read its
Security constraints + Success threshold sections — they are the decision criteria).

---

## Environment & lifecycle (do once, up front)

- **Isolation:** all builder + workload state goes to scratch dirs so nothing races the
  shared persistent builder or parallel sessions:
  ```bash
  export MVM_CACHE_DIR="$HOME/.cache/mvm-spike-pagecache"
  export MVM_DATA_DIR="$HOME/.mvm-spike-pagecache"
  mkdir -p "$MVM_CACHE_DIR" "$MVM_DATA_DIR"
  ```
  These persist across the spike's builds (warm nix store for the image build + any B/C
  rebuild), then are removed at teardown (Task 9).
- **Worktree:** run from a dedicated git worktree (the spike branch is already
  `spike/vz-page-cache-priming`); the design + this plan live there.
- **Scratch dir for snapshots/results:**
  ```bash
  export SPIKE="$HOME/spike-pagecache"; mkdir -p "$SPIKE"
  ```

---

## Task 0: Build the Vz supervisor + mvmctl

**Files:** none created. Builds existing crates.

- [ ] **Step 1: Build the codesigned Swift supervisor** (Vz refuses an unsigned/missing one)

```bash
crates/mvm-vz-supervisor/tools/build.sh release
export MVM_VZ_SUPERVISOR_PATH="$(pwd)/crates/mvm-vz-supervisor/.build/$(uname -m)-apple-macosx/release/mvm-vz-supervisor"
test -x "$MVM_VZ_SUPERVISOR_PATH" && echo "supervisor OK: $MVM_VZ_SUPERVISOR_PATH"
```
Expected: prints `supervisor OK: …`. If the path differs, `find crates/mvm-vz-supervisor/.build -name mvm-vz-supervisor -type f`.

- [ ] **Step 2: Build mvmctl release**

```bash
cargo build --release --bin mvmctl
export MVMCTL="$(pwd)/target/release/mvmctl"
"$MVMCTL" --version
```
Expected: prints a version. Use `$MVMCTL` for all subsequent commands so we run the build we just made.

- [ ] **Step 3: Confirm host tier**

```bash
sw_vers   # expect ProductVersion 26.x (macOS 26+), arch arm64 (uname -m = arm64)
```
Expected: macOS 26+ on arm64 — required for `macos_supports_vz_snapshots()` (macOS 14+) and the Vz default tier. If `< 14`, **abort**: Vz snapshots are unavailable.

---

## Task 1 (GATE): Boot a trivial dev workload on Vz, confirm it stays alive + console works

This is the **cheap feasibility gate** — prove the Vz workload path + console exec work
*before* spending a fat image build. Uses the in-repo busybox dev image.

**Files:** none.

- [ ] **Step 1: Boot the busybox dev image on Vz, detached**

```bash
"$MVMCTL" up --flake 'nix/images/default-tenant#dev' \
  --hypervisor vz --accept-tier2-isolation \
  --name spike-probe --cpus 2 --memory 1G --detach
```
Expected: builds (first time, via the isolated builder) then reports the VM started. Note: first build is cold and may take minutes.

- [ ] **Step 2: Confirm it stays alive >60s** (the workload PID 1 idles — the dev-VM init-EOF quirk does NOT apply to workloads)

```bash
sleep 60
"$MVMCTL" ps 2>/dev/null || "$MVMCTL" list 2>/dev/null   # whichever lists running VMs
```
Expected: `spike-probe` still listed as running. **Abort gate:** if it died ~5s after boot, the workload-on-Vz path has a liveness bug — stop, capture `"$MVMCTL" console spike-probe --command 'true'` error + `<vm_state_dir>/console.log`, and report. Do not proceed.

- [ ] **Step 3: Confirm `console --command` returns guest stdout**

```bash
"$MVMCTL" console spike-probe --command 'echo SPIKE_OK; uname -a'
```
Expected: prints `SPIKE_OK` + a Linux uname line (proves the vsock `Exec` path + dev-shell `accessible=true`). **Abort gate:** if it refuses (sealed image) or hangs, stop and report — without console exec there is no measurement channel.

- [ ] **Step 4: Tear down the probe**

```bash
"$MVMCTL" stop spike-probe 2>/dev/null; "$MVMCTL" rm spike-probe 2>/dev/null || true
```

---

## Task 2 (GATE): Snapshot save/restore round-trip on the trivial guest

Prove the Vz snapshot mechanism works end-to-end *before* the fat build. Re-boot the
busybox dev image, save, stop, restore, confirm console still works post-restore.

**Files:** snapshot blob under `$SPIKE`.

- [ ] **Step 1: Boot + save**

```bash
"$MVMCTL" up --flake 'nix/images/default-tenant#dev' --hypervisor vz \
  --accept-tier2-isolation --name spike-snap --cpus 2 --memory 1G --detach
sleep 20
"$MVMCTL" snapshot save spike-snap --path "$SPIKE/probe.vzsnap" --hypervisor vz
ls -la "$SPIKE/probe.vzsnap"
```
Expected: snapshot save succeeds; blob exists (non-zero size). Emits a `vm.snapshot_saved` audit entry.

- [ ] **Step 2: Stop, then restore** (restore requires the VM not be running)

```bash
"$MVMCTL" stop spike-snap
"$MVMCTL" snapshot restore spike-snap --path "$SPIKE/probe.vzsnap" --hypervisor vz
sleep 5
"$MVMCTL" console spike-snap --command 'echo RESTORED_OK'
```
Expected: restore succeeds; console prints `RESTORED_OK`. **Abort gate:** if restore fails or the restored guest is unreachable, stop and report — this is the core mechanism the spike depends on.

- [ ] **Step 3: Tear down**

```bash
"$MVMCTL" stop spike-snap 2>/dev/null; "$MVMCTL" rm spike-snap 2>/dev/null; rm -f "$SPIKE/probe.vzsnap" || true
```

> Both gates green → the mechanism works; invest in the fat image. Either gate red →
> stop here; the spike's blocker is the Vz workload/snapshot path, not page-cache priming.

---

## Task 3: Build the measurement image (fat dev-shell flake)

The busybox image's `/nix/store` is too thin to be a working set. Copy the working
default-tenant flake and add a fat, representative closure (python + numpy — also sets
up scope B). The builder builds it once.

**Files:**
- Create: `$SPIKE/flake/` (copy of `nix/images/default-tenant/`)
- Modify: `$SPIKE/flake/flake.nix` (the `packages` line)

- [ ] **Step 1: Copy the flake**

```bash
cp -R nix/images/default-tenant "$SPIKE/flake"
```

- [ ] **Step 2: Fatten the dev variant's package set**

In `$SPIKE/flake/flake.nix`, change the `packages` line (currently line ~101):
```nix
            packages = [ pkgs.busybox ];
```
to:
```nix
            packages = [ pkgs.busybox (pkgs.python3.withPackages (ps: [ ps.numpy ])) ];
```
(This adds a ~200 MB closure to the rootfs — the working set — and gives scope B a real `import numpy`.)

- [ ] **Step 3: Build + boot the fat dev image on Vz**

```bash
"$MVMCTL" up --flake "$SPIKE/flake#dev" --hypervisor vz \
  --accept-tier2-isolation --name spike-fat --cpus 4 --memory 4G --detach
```
Expected: cold build (slower — fetches the python/numpy closure through the isolated builder), then VM starts. Confirm alive: `sleep 30; "$MVMCTL" console spike-fat --command 'echo FAT_OK; du -sh /nix/store'`.
Expected: `FAT_OK` + a `/nix/store` size in the hundreds of MB.

- [ ] **Step 4: Pick the working set + record its size + a baseline read time**

```bash
"$MVMCTL" console spike-fat --command \
  'WS=$(ls -d /nix/store/*python3*-env 2>/dev/null | head -1 || ls -d /nix/store/*numpy* | head -1); echo "WS=$WS"; du -sh "$WS"; sync; time sh -c "find $WS -type f -exec cat {} + >/dev/null"'
```
Expected: prints `WS=/nix/store/…`, a size (tens–hundreds of MB), and a `real` time. **Record `WS` and this warm baseline.** If `WS` read is <~50 ms, it's too small to measure — widen to the whole store: `WS=/nix/store`.

- [ ] **Step 5: Tear down the boot-build VM** (we re-boot fresh for each A/B arm)

```bash
"$MVMCTL" stop spike-fat 2>/dev/null; "$MVMCTL" rm spike-fat 2>/dev/null || true
```

---

## Task 4: Primed snapshot

**Files:** `$SPIKE/primed.vzsnap`

- [ ] **Step 1: Boot fresh, prime the working set, save**

```bash
WS="<the WS path recorded in Task 3 Step 4>"
"$MVMCTL" up --flake "$SPIKE/flake#dev" --hypervisor vz --accept-tier2-isolation \
  --name spike-primed --cpus 4 --memory 4G --detach
sleep 20
# prime: read the working set into the guest page cache
"$MVMCTL" console spike-primed --command "find $WS -type f -exec cat {} + >/dev/null; echo PRIMED"
"$MVMCTL" snapshot save spike-primed --path "$SPIKE/primed.vzsnap" --hypervisor vz
"$MVMCTL" stop spike-primed
```
Expected: prints `PRIMED`; snapshot saved (non-zero blob).

---

## Task 5: Cold snapshot

**Files:** `$SPIKE/cold.vzsnap`

- [ ] **Step 1: Boot fresh, do NOT touch the working set, save**

```bash
"$MVMCTL" up --flake "$SPIKE/flake#dev" --hypervisor vz --accept-tier2-isolation \
  --name spike-cold --cpus 4 --memory 4G --detach
sleep 20
# deliberately do NOT read WS — leave its pages cold
"$MVMCTL" snapshot save spike-cold --path "$SPIKE/cold.vzsnap" --hypervisor vz
"$MVMCTL" stop spike-cold
```
Expected: snapshot saved (non-zero blob). (Boot reads /init + the agent, never WS, so WS stays cold.)

---

## Task 6: Measure — restore each, time the first read, ≥5 trials

**Files:** `$SPIKE/results.tsv`

- [ ] **Step 1: Primed trials**

```bash
WS="<recorded WS path>"
echo -e "arm\ttrial\treal_seconds" > "$SPIKE/results.tsv"
for i in 1 2 3 4 5; do
  "$MVMCTL" snapshot restore spike-primed --path "$SPIKE/primed.vzsnap" --hypervisor vz
  sleep 3
  t=$("$MVMCTL" console spike-primed --command \
      "S=\$(date +%s.%N); find $WS -type f -exec cat {} + >/dev/null; E=\$(date +%s.%N); echo \$(echo \"\$E - \$S\" | bc)")
  echo -e "primed\t$i\t$t" | tee -a "$SPIKE/results.tsv"
  "$MVMCTL" stop spike-primed
done
```
Expected: 5 `primed` rows with `real_seconds`. (Times the read *inside* the guest with `date +%s.%N`, avoiding PTY round-trip noise in the number itself.)

- [ ] **Step 2: Cold trials**

```bash
for i in 1 2 3 4 5; do
  "$MVMCTL" snapshot restore spike-cold --path "$SPIKE/cold.vzsnap" --hypervisor vz
  sleep 3
  t=$("$MVMCTL" console spike-cold --command \
      "S=\$(date +%s.%N); find $WS -type f -exec cat {} + >/dev/null; E=\$(date +%s.%N); echo \$(echo \"\$E - \$S\" | bc)")
  echo -e "cold\t$i\t$t" | tee -a "$SPIKE/results.tsv"
  "$MVMCTL" stop spike-cold
done
```
Expected: 5 `cold` rows. Each cold restore starts from the same untouched-WS snapshot, so every cold trial faults WS from the virtual disk anew.

> Note the host-page-cache confound (design doc): across cold trials the *host's* cache
> for the rootfs image warms up, which may shrink the cold cost over trials. Record the
> per-trial values (don't just average) so the trend is visible.

---

## Task 7: Analyze + decide (apply the two gates)

**Files:** append a "Results" section to `specs/notes/2026-06-05-vz-page-cache-priming-spike.md`.

- [ ] **Step 1: Summarize**

```bash
awk -F'\t' 'NR>1{a[$1]=a[$1]" "$3} END{for(k in a)print k": "a[k]}' "$SPIKE/results.tsv"
```
Compute per-arm median + min/max.

- [ ] **Step 2: Apply the thresholds** (from the design doc Success threshold):
  - **Robustness:** does primed clearly separate from cold (slowest primed ≤ fastest cold, or medians clearly apart with no overlap)?
  - **Materiality:** is the median saving on the order of ≥100 ms?
  - **Verdict:** both pass → *mechanism viable, proceed to B/C*. Either fails → *kill the Plan 157 follow-up*.

- [ ] **Step 3: Write the Results section** into the design note — the per-trial table, medians, the host-cache trend, and the explicit verdict (proceed-to-B/C **or** kill, with the one-line reason). Commit:

```bash
git add specs/notes/2026-06-05-vz-page-cache-priming-spike.md
git commit -m "docs(spike): Vz page-cache priming results + verdict"
```

---

## Task 8: Decision handoff (no code either way)

- [ ] **Step 1:** If **proceed**: open a short note recommending scope B (`python -c "import numpy"` on the *same* fat image — it's already built) to quote a realistic number, and flag that the actual feature work is still gated behind Plan 140 + Plan 123-C (ADR-073 sequencing). If **kill**: note that the Plan 157 follow-up `- [ ]` should be struck (or annotated "measured no benefit on Vz, <date>"), and propose that doc edit as a follow-up PR.

---

## Task 9: Teardown

- [ ] **Step 1: Remove VMs, snapshots, scratch, and the isolated builder**

```bash
for n in spike-probe spike-snap spike-fat spike-primed spike-cold; do
  "$MVMCTL" stop "$n" 2>/dev/null; "$MVMCTL" rm "$n" 2>/dev/null
done
"$MVMCTL" dev down 2>/dev/null || true            # shut down the job-specific builder
rm -rf "$SPIKE" "$MVM_CACHE_DIR" "$MVM_DATA_DIR"   # never touched the shared persistent builder
```
Expected: scratch gone; the user's shared `~/.cache/mvm` / `~/.mvm` untouched (we only ever used the `*-spike-pagecache` dirs).

- [ ] **Step 2:** Decide whether the design note + results land on `main` (recommended — it's the durable decision record) via a small PR, independent of the throwaway spike branch.

---

## Out of scope (carried from the design)

- Implementing page-cache priming or any freeze/restore change.
- Firecracker / cloud-hypervisor measurement (different snapshot mechanism — only if Vz shows a signal worth generalizing).
- Scope B/C execution (gated on Task 7 verdict).
