# Plan 223 — Virtiofs root filesystem (Plan 221 Option A)

**Status:** proposed
**Owner:** _tbd_
**Related:** ADR-107 (virtiofs-root integrity — the gating decision), ADR-106
(in-process materialize — Option B, block+verity, stays for prod + Firecracker),
ADR-002 (security posture — claim 3, tier matrix), Plan 214 (in-house HVF VMM),
Plan 221 (Option A lives here; B4 fallback stays), #1388 seam
(`admit_and_start`).

## Why

Plan 221 Option B made the run-path materialize **in-process** (pure-Rust ext4 +
dm-verity, no builder VM, no subprocess). Option A goes one step further for
**virtiofs-capable backends**: boot the guest with the **unpacked OCI directory
as a virtiofs root** — no ext4, no `mkfs`, no image at all. That is the
supermachine model and the Plan-214 in-house-HVF end state; it deletes rootfs
materialization entirely on the dev/local loop.

The hard part was never the plumbing — it was the **integrity model**, because
dm-verity (claim 3) is block-device-specific and a virtiofs root is a host
directory. **ADR-107 settles that**: virtiofs-root is a **dev/local-tier**
mechanism (unpack-time verification + read-only virtiofs + trusted host), and
**prod stays on Option B** (block + ext4 + dm-verity), so no numbered claim is
weakened. This plan implements Option A under that decision.

## Non-goals

- **Prod-on-virtiofs.** Sealed / `--prod` workloads keep Option B on every
  backend (ADR-107 §Decision). A future signed-content-manifest path (ADR-107
  candidate (ii)) is the only way that changes, and it is out of scope here.
- **Firecracker.** Firecracker has no virtiofs root device; it always uses
  Option B. This plan touches only the virtiofs-capable backends.
- **Deleting Option B.** Option B remains the prod path, the Firecracker path,
  and the Plan 221 B4 fallback.

## Phases

### A0 — Integrity decision (ADR-107) — **done (Accepted)**

`specs/adrs/107-virtiofs-root-integrity.md` (**Accepted**). Decision: tiered
posture, prod stays on Option B, claim 3 scoped to block+ext4. Everything below
assumes that decision.

**Parked.** A1–A5 are not scheduled: Option B already meets the "no subprocess
on the run path" goal, so Option A is a dev-loop optimization, and A1 depends on
Plan 214's in-house-HVF backend exposing a virtiofs **root** device. Pick this up
when that lands; until then this plan is the accepted design, not active work.

### A1 — Virtiofs **root** device on virtiofs-capable backends

libkrun and Vz already expose virtiofs *shares* (`krun_add_*` / `vz_objc.rs`
`VZVirtioFileSystemDeviceConfiguration`); the in-house HVF backend (Plan 214)
needs the same primitive. Extend all three to attach a **root** virtiofs device
(tag `root`, or the conventional `virtiofs`/`myfs` tag the guest init expects)
backed by the unpacked-tree host directory, read-only.

- [ ] in-house HVF backend: attach a read-only virtiofs device for the root tree.
- [ ] libkrun / Vz: confirm a share can serve as the root (tag + read-only).
- [ ] host-side: the served directory is the unpack-verified tree; never a
  writable or post-unpack-mutable path.

### A2 — Guest boot model

- [ ] kernel cmdline carries `rootfstype=virtiofs root=<tag>` (or the
  equivalent the chosen VMM/kernel expects); the guest kernel has `VIRTIO_FS`
  built in (already true for the Plan-209 managed-volume path).
- [ ] `/init` mounts the virtiofs root read-only and pivots to it; the
  `mvm-guest` agent + entrypoint run on a virtiofs root exactly as on ext4.
- [ ] the mvm runtime injection (agent, netinit, `/mvm/runtime`,
  `/etc/mvm/entrypoint`) is applied to the **unpacked tree on the host** before
  it is served (reuse `mvm_build::oci_runtime_inject::inject_mvm_runtime`), so no
  materialize step is needed — injection writes into the dir, virtiofs serves it.

### A3 — Integrity enforcement per ADR-107 (dev tier)

- [ ] unpack-time verification is **load-bearing and un-bypassable** on the
  virtiofs path: per-layer sha256 (mvm-oci) + cosign when policy demands, run
  **before** the tree is exposed to the guest, failing closed.
- [ ] the served directory is mounted **read-only** in the guest and is not
  mutated by the host after unpack (no writable overlay on the root; writable
  state goes to a separate tmpfs/volume, as today).
- [ ] audit: the admission log records that the boot used the virtiofs-root
  dev-tier posture (so a reader can tell a dev virtiofs boot from an Option-B
  claim-3 boot).

### A4 — Run-path tier gate + wiring

- [ ] a single selection gate: virtiofs-root is chosen **iff** the backend is
  virtiofs-capable **and** the tier is dev/local **and** the workload is not
  sealed / not `--prod`. Otherwise Option B (materialize + verity). Firecracker
  and every prod/sealed path always take Option B.
- [ ] wire the gate into the shared run orchestration
  (`mvm_build::run_image` — the module Plan 221 Option B introduced and that the
  CLI + `mvm-client` local backend already share), so both drivers get the same
  virtiofs-vs-materialize decision.
- [ ] the gate is unit-testable in isolation (backend capability × tier ×
  sealed-flag → virtiofs | block).

### A5 — Retire materialize for virtiofs-capable dev boots

- [ ] on a virtiofs-capable dev boot, **no ext4 is produced** — the boot goes
  straight from unpacked+injected dir → virtiofs root. Materialize
  (`materialize_run_rootfs`) is not on that path.
- [ ] Option B stays wired for: Firecracker (all tiers), prod/sealed (all
  backends), and the Plan 221 B4 builder-VM fallback.

## Validation

- **Live boot.** `mvmctl run --image <ref>` on the in-house HVF backend (and Vz)
  boots off a virtiofs root and round-trips the guest agent (the same marker
  round-trip Option B was validated with on a live Vz microVM) — with **no**
  `rootfs.ext4` produced on that path.
- **Tier gate.** Automated: dev + virtiofs-capable → virtiofs; `--prod` → Option
  B; Firecracker → Option B; sealed image → Option B.
- **Integrity fail-closed.** A layer whose sha256 mismatches the manifest is
  refused before the tree is ever served (regression test on the unpack gate).
- **Claims catalog.** Add the ADR-107 scoping note: claim 3's witness
  (dm-verity) is the block+ext4 backends; the virtiofs-root dev path carries the
  weaker ADR-107 contract. `xtask check-claim-catalog` stays green.
- **No numbered-claim regression.** Prod + Firecracker still witness claim 3
  unchanged; the `verified-boot-artifacts` lane is untouched.

## Sequencing / risk

A1–A2 are backend + guest plumbing (Plan-214-adjacent; the in-house HVF backend
is where the value concentrates). A3–A4 are the security-relevant gate and are
where review attention should focus — the one-line risk is a path that reaches
virtiofs-root for a prod/sealed workload, which A4's gate + A3's fail-closed
unpack must make unrepresentable. A5 is cleanup once A1–A4 are proven. ADR-107 is
accepted, so the design is settled; scheduling waits on Plan 214's in-house-HVF
virtiofs-root device (see A0 — parked).
