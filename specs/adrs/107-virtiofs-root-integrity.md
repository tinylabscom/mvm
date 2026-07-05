# ADR-107: Integrity model for a virtiofs root filesystem

- Status: Accepted
- Date: 2026-07-04
- Owner: MVM Project
- Related: ADR-002 (microVM security posture — **claim 3**, threat model, tier
  matrix), ADR-106 (in-process rootfs materialization — Option B, block+verity),
  ADR-050 (materialize + verity; ADR-106 supersedes its mechanism, preserves its
  guarantee), ADR-051 (runtime overlay sealed like the rootfs), Plan 214
  (in-house HVF VMM), Plan 221 (this is its Option A / A0 deliverable),
  Plan 223 (virtiofs-root implementation, gated on this ADR).

## Context

Plan 221 Option A proposes booting a guest with the **unpacked OCI directory as
a virtiofs root** — no ext4, no `mkfs`, no image at all. The host serves files
to the guest on demand over virtiofs. This is the supermachine model and the
Plan-214 in-house-HVF end state, and it deletes the last piece of
image-materialization on the virtiofs-capable run path (Option B's in-process
ext4 + dm-verity, ADR-106).

It runs straight into **claim 3** ("a tampered rootfs ext4 fails to boot"):

> dm-verity over the read-only ext4 lower layer; root hash on the (signed)
> kernel cmdline; `mvm-verity-init` mounts it; the guest kernel panics before
> userspace on a flipped data block.

dm-verity is **block-device-specific**. A virtiofs root is a host *directory*,
not a block device — there is no fixed block layout to build a Merkle tree over,
and the guest kernel cannot dm-verity a filesystem it does not own the blocks
of. So Option A cannot satisfy claim 3 by its current mechanism, and claim 3 is
a **numbered security claim**. This ADR decides what integrity a virtiofs root
provides, and therefore whether Option A can carry prod workloads.

### What does claim 3 actually buy, given the threat model?

ADR-002 puts a **trusted host** at the center: "mvmctl trusts the host with the
hypervisor and private build keys… a malicious host is out of scope." So claim 3
is **not** defending against a host that tampers with the rootfs at serve time.
What it *does* buy, on top of the trusted host:

1. **End-to-end binding of rootfs content to the signed plan.** The roothash
   lives on the signed `ExecutionPlan` cmdline. The guest kernel enforces every
   block against it. So the *bytes the guest actually executes* are
   cryptographically tied to what was admitted — not to whatever happens to be
   on disk at boot.
2. **Detection of at-rest tampering / corruption between admit and boot.** A
   flipped bit in `rootfs.ext4` — cache corruption, a stray writer, a swapped
   file across reboots, a tampered published `.mvm` artifact or registry layer —
   is caught at read time, not trusted blindly.
3. **A guest-side enforcement point** independent of the host userspace that
   assembled the image.

For a virtiofs root, the content's authenticity is instead established **at pull
/ unpack time**: `mvm-oci` verifies every layer's sha256 against the manifest,
and `--prod` additionally cosign-verifies the resolved manifest digest before
the layers are unpacked (ADR-002 claim 14). After that, the *trusted host*
serves those exact files read-only. The gap versus claim 3 is precisely
properties (1)–(3): there is **no guest-enforced, plan-bound, continuous
re-verification** of the served files. A corruption or substitution of the
unpacked tree *after* unpack and *before/while* the guest reads it is not caught
by the guest — it rests entirely on the trusted-host axiom.

### The candidate mechanisms

- **(i) Per-file fs-verity.** Enable fs-verity on each file in the host tree and
  have the guest verify each file's Merkle root against a signed manifest.
  Problems: fs-verity is a **host-kernel** feature that virtiofs does not
  transparently propagate to the guest; the guest would need its own enforcement
  layer; it requires the host filesystem to support fs-verity (ext4/f2fs/btrfs
  with the feature enabled); and it re-introduces a per-file Merkle build that is
  most of the cost Option A set out to remove.
- **(ii) Signed content manifest + guest-side verification.** Ship a manifest
  (path → sha256 for every file), signed and bound to the plan; the guest
  verifies files against it — either a full scan at mount (expensive: rehash the
  whole tree in-guest on every boot) or lazily per-read via a FUSE/overlay shim
  (complex: a new in-guest verification component on the read path). This is
  essentially re-implementing dm-verity at the file layer inside the guest.
- **(iii) Tiered posture.** Treat virtiofs-root as a **dev/local-tier** boot
  mechanism whose integrity contract is *unpack-time verification + read-only
  virtiofs + trusted host* — explicitly weaker than claim 3 — and keep **prod on
  Option B** (block + ext4 + dm-verity), where claim 3 holds unchanged. This
  mirrors the existing per-tier matrix, where dev/test tiers already carry
  relaxed guarantees (e.g. the QEMU/microvm_nix builder deliberately omits
  claim-10 egress enforcement as a Tier-2 dev/test backend).

## Decision

**Adopt (iii): virtiofs-root is a dev/local-tier mechanism; prod stays on
Option B.** Concretely:

1. **virtiofs-root does not witness claim 3.** Its integrity contract is a
   distinct, explicitly weaker property:

   > **Virtiofs-root integrity (dev tier).** The rootfs content is verified at
   > unpack time (per-layer sha256 against the manifest; cosign on the manifest
   > digest when a registry policy demands it), then served **read-only** from a
   > trusted host over virtiofs. There is no guest-enforced, plan-bound
   > re-verification of served files; integrity after unpack rests on the
   > trusted-host axiom (ADR-002 threat model).

   This is recorded as a documented posture, **not** promoted into ADR-002's
   numbered claim-3 prose. The claims catalog gains a note that claim 3's
   witness (dm-verity) applies to the **block+ext4** backends
   (Firecracker + Option B), and that the virtiofs-root dev path carries the
   weaker contract above.

2. **Prod refuses virtiofs-root.** A sealed / `--prod` workload continues to
   require Option B: in-process (or builder-VM) ext4 + dm-verity + roothash on
   the signed cmdline. The run path selects virtiofs-root **only** for the
   dev/local tier on virtiofs-capable backends (in-house HVF, libkrun, Vz);
   `--prod` and any sealed-image admission path fall back to Option B, on every
   backend. **Firecracker always uses Option B** (it has no virtiofs root
   device; ADR-106).

3. **A stronger path is left open but deferred.** If prod-on-virtiofs is ever
   required, candidate (ii) — a plan-bound **signed content manifest** with
   guest-side verification — is the promotion path to a claim-3-equivalent
   guarantee, and would get its own ADR. Candidate (i) (fs-verity) is recorded
   as considered-and-not-chosen for the reasons above. Nothing here forecloses
   them; this ADR only declines to block Option A's dev-tier value on solving
   prod-grade virtiofs integrity first.

### Why this is the right call

- **It respects the threat model rather than overclaiming.** The trusted host
  already serves the guest's memory, devices, and vsock; a trusted host serving
  a read-only, unpack-verified directory adds no new *host* trust. What it drops
  versus claim 3 is defense-in-depth against **at-rest tampering between admit
  and boot** — a real property, but one whose value is concentrated in the
  **prod** distribution story (published artifacts, registry layers, long-lived
  caches), exactly where we keep Option B.
- **It keeps Option A's whole point.** Option A exists to delete
  materialization on the fast dev/local loop. Gating it behind a full guest-side
  file-verification subsystem would erase that win. The tiered decision ships the
  dev-loop speedup now without weakening any *numbered* prod guarantee.
- **It matches the existing architecture.** ADR-002 already grades guarantees by
  tier; this is one more per-tier distinction, made explicit and CI-notable
  rather than implicit.

## Consequences

- **Claim 3 is unchanged for prod and for Firecracker.** No numbered claim is
  weakened. The claims catalog gains a scoping note (block+ext4 backends witness
  claim 3; virtiofs-root dev path carries the weaker contract).
- **The run path grows a tier gate.** Selecting virtiofs-root requires: a
  virtiofs-capable backend, the dev/local tier, and a non-sealed / non-`--prod`
  workload. Everything else routes to Option B. This gate is testable and is a
  named deliverable of Plan 223.
- **Unpack-time verification becomes load-bearing for the virtiofs path.** The
  per-layer sha256 check in `mvm-oci` (and cosign for policy-gated pulls) is the
  *only* content-authenticity step for a virtiofs boot, so it must run before the
  tree is exposed to the guest and must fail closed. (It already does for the
  materialize path; the virtiofs path must not bypass it.)
- **Documentation debt is explicit, not hidden.** A reader of ADR-002 will find
  claim 3 scoped to block+ext4 and a pointer to this ADR for the virtiofs-root
  posture, so no one mistakes a dev-tier virtiofs boot for a claim-3 boot.

## Alternatives considered

- **Make virtiofs-root witness claim 3 via a signed manifest now (ii).** Correct
  end state for prod-on-virtiofs, but it re-adds a full guest-side verification
  component (mount-time rescan or per-read FUSE shim) that negates Option A's
  performance rationale and is a large surface to get right. Deferred, not
  rejected.
- **fs-verity (i).** Host-fs-dependent, does not cross the virtiofs boundary to
  the guest transparently, and re-introduces per-file Merkle builds. Rejected as
  the primary mechanism.
- **Ship virtiofs-root for all tiers and quietly relax claim 3.** Rejected:
  claim 3 is CI-enforced and load-bearing for the prod distribution story;
  silently weakening it to cover a dev optimization is exactly the overclaiming
  ADR-002's discipline exists to prevent.
- **Never ship virtiofs-root; keep Option B everywhere.** Rejected as the
  default: it forfeits the dev-loop speedup and the Plan-214 end state for a
  prod property the dev tier does not need. Option B remains the prod path.
