# Decision: should a non-prod OCI run verity-boot? (incident follow-up #3)

**Date:** 2026-07-13
**Status:** proposed — needs a maintainer decision, then graduates to an ADR.
**Companion:** `specs/notes/2026-07-13-oci-run-workload-kernel-verity.md` (the
incident that raised this; follow-ups 1/2/4 already landed via #1689 + #1691).
**Decides:** whether a **non-prod** `machine run --image` (and the OCI runtime
path generally) should dm-verity-boot like `--prod`, or boot **unsealed**.

## Why this is a decision and not just a bug

The incident fix (#1684) removed a wrong-kernel reuse: a verity-sealed rootfs was
booting on a non-dm-verity builder kernel and panicking the guest in
`mvm-verity-init` at `open /dev/mapper/control`. That fix forced every OCI run —
**including non-prod** — to resolve (and, on a source checkout, *build*, ~3–5 min
cold) a real dm-verity workload kernel. That is correct given the current boot
shape, but it made the first non-prod OCI run slow, and it exposed a deeper
question the incident note deferred: *should non-prod verity-boot at all?*

## Current behavior (verified, not assumed)

A code trace (host-side, `main` as of #1691) establishes:

1. **The rootfs is verity-backed unconditionally.** `materialize_run_rootfs`
   applies `.with_verity()` with **no prod/sealed branch**
   (`crates/mvm-build/src/run_image.rs:412`), so every OCI `--image` run —
   prod or dev — writes `rootfs.verity` + `rootfs.roothash` beside the image
   (`crates/mvm-build/src/rootfs.rs:515`).
2. **The presence of a roothash drives the whole boot.** `probe_verity_sidecar`
   sets `VmStartConfig.roothash`/`verity_path` from those sidecars
   (`crates/mvm-cli/src/exec.rs:975`, `:1034`); a block-ext4 OCI root then
   short-circuits to `RequiredOverlay` regardless of the `sealed` flag
   (`crates/mvm-cli/src/exec.rs:179`), and the verity initrd is assembled
   on demand (`crates/mvm-cli/src/commands/vm/up.rs:1274`). So non-prod OCI
   **verity-boots**.
3. **Therefore a dm-verity kernel is mandatory** for every OCI run:
   `ensure_workload_kernel(prod)` + `assert_workload_kernel_supports_verity`
   both run unconditionally (`crates/mvm-cli/src/commands/vm/exec.rs:751`,
   `:755`), and `resolve_workload_kernel_bootstrap` resolves a real workload
   kernel for `prod=false` too (the builder-kernel reuse is gone —
   `crates/mvm-cli/src/commands/env/dev_vz/default_microvm.rs:164`).
4. **The `sealed`/`--prod` flag is a *separate, weaker* layer** — the pre-baked
   `rootfs.initrd`, the `sealed:true`/`accessible:false` sidecar (claim-15
   interactivity refusal), the `prod` variant marker, and `verb-trust.json`. It
   is gated on `sealed`, but on a **fresh pull that flag is hardcoded `false`**
   for both prod and dev (`crates/mvm-cli/src/commands/image/mod.rs:1282`,
   `:738`), and the `prod`-keyed reseal is dead-gated behind *absent* verity
   sidecars that `.with_verity()` always makes present. So the "seal" layer is
   largely not exercised — while the verity **boot** always is.
5. **`--flake` dev already boots unsealed.** A dev mkGuest build emits no
   roothash (`DefaultMicrovmVariant::required_outputs`,
   `default_microvm.rs:306`; `isSealed = !isDev` in `nix/lib/mk-guest.nix`), so
   `probe_verity_sidecar` returns `(None, None)` → plain `root=/dev/vda ro`
   boot, no verity initrd, **no dm-verity kernel needed**.

The upshot: **the OCI path and the flake path disagree for dev.** `--flake` dev
boots unsealed and cheap; `--image` dev verity-boots and pays the kernel build.
The unconditional `.with_verity()` at `run_image.rs:412` looks like an
unintended defect — it defeats the intended dev-fast virtiofs-root path (which is
now unreachable for OCI, because a roothash is always present so
`select_root_strategy` always picks `BlockExt4`).

## Cost, precisely

The dominant first-run cost is the **workload-kernel build**
(`build_kernel_via_stage0(KernelVariant::Workload)`), not the seal — the rootfs
verity is pure in-process work (seconds). So an "unsealed non-prod" mode saves
minutes **only** by letting dev reuse the already-cached builder kernel and skip
the workload-kernel build; skipping the seal itself saves ~nothing.

## The two options

### Option 1 — Verity-everywhere (make it deliberate)

Keep non-prod verity-booting; make `--flake` dev *also* verity-boot so the two
sources agree, and accept the kernel-build cost on dev.

- **Pro:** one boot path; claim-3 (tamper-evident rootfs) applies uniformly;
  kernel↔rootfs agreement is trivially always-true (my #1688 guard stays
  unconditional); dev exercises the exact prod boot, so verity/kernel bugs
  surface in dev (the busybox panic was, in that sense, *useful*).
- **Con:** every cold dev iteration pays ~3–5 min for a workload kernel it does
  not need for safety; the intended dev-fast virtiofs-root path stays dead;
  works against the "instant first use" goal; and it means *slowing flake dev
  down* to match, which contributors will feel.

### Option 2 — Unsealed non-prod (restore the intended dev-fast path)

Make non-prod OCI boot unsealed — plain/virtiofs root, non-verity kernel, no
verity initrd — matching what `--flake` dev already does. Verity stays on for
`--prod`.

- **Pro:** fast dev (reuse the cached builder kernel, no workload-kernel build,
  virtiofs-root or plain block); **makes OCI dev consistent with flake dev**
  (this *reduces* the current divergence rather than adding it); honours the
  security model — dev is Tier 2, never deploys, and carries no prod guarantees,
  so verity buys little there (see `feedback_dev_vm_vs_prod_security_tiers`).
- **Con:** two boot shapes exist (verity vs plain) — a "works in dev, breaks in
  prod" risk around the verity initrd + overlay that only prod exercises; and it
  reintroduces builder-kernel reuse for `prod=false`, which **must** be gated to
  strictly non-verity rootfs or the exact #1684 panic returns.

## Recommendation

**Option 2, with a hard gate and a kept prod regression.** The current state is
not a deliberate "verity-everywhere" posture — it is an unconditional
`.with_verity()` that (a) defeats the intended dev-fast path and (b) makes OCI
dev inconsistent with flake dev. Option 2 is the "restore intended behaviour"
direction, and the security cost is low because the dev tier never deploys.

Guards that make Option 2 safe:

- **Single source of truth for "is this run sealed":** derive verity boot,
  kernel choice, and the #1688 guard all from one `sealed`/`prod` decision, so
  they can never disagree (the invariant the incident named). Concretely: thread
  `sealed` into `materialize_run_rootfs` and skip `.with_verity()` when
  non-prod; then every downstream check is presence-driven and degrades
  automatically.
- **Keep the #1688 guard, gated on sealed:** it must still fire for `--prod` (a
  sealed rootfs on a non-verity kernel), just not for an unsealed dev run.
- **Keep a prod verity-boot regression in CI** so the prod path never rots while
  only dev exercises the fast path.

If the team prefers maximal dev/prod parity over dev speed, Option 1 is the
defensible alternative — but then *flake dev must be sealed too*, and the
"instant first use" work should account for the kernel-build cost.

## Appendix — exact touchpoints for Option 2

Minimal surface to make non-prod boot unsealed (plain rootfs, non-verity kernel,
no verity initrd). Everything downstream is presence-driven, so removing the
roothash cascades:

1. `crates/mvm-build/src/run_image.rs:412` (+ call site `:149`) — the linchpin:
   thread `sealed`/`prod` into `materialize_run_rootfs`, skip `.with_verity()`
   when non-prod, so no `rootfs.roothash` lands.
2. `crates/mvm-cli/src/commands/vm/exec.rs:751`, `:755` — resolve a non-verity
   kernel for non-prod; gate `assert_workload_kernel_supports_verity` on sealed.
3. `crates/mvm-cli/src/commands/env/dev_vz/default_microvm.rs:164` — reinstate a
   non-verity (builder-kernel-reuse) branch in `resolve_workload_kernel_bootstrap`
   for `prod=false`, gated so it can only pair with an unsealed rootfs.
4. `crates/mvm-cli/src/exec.rs:179` (`runtime_source_policy_for`) and
   `crates/mvm-cli/src/commands/vm/up.rs:1274` (`persistent_oci_effective_initrd`)
   — stop forcing `RequiredOverlay` / assembling a verity initrd when there is no
   roothash; key both off `probe_verity_sidecar` presence.
5. No change at `exec.rs:975`/`:980`/`:1034` or `builder_vm.rs:299` — with the
   roothash absent, `resolve_virtiofs_root`/`select_root_strategy` naturally pick
   the virtiofs-root or plain-block path and the sidecar is already
   `sealed:false`.
