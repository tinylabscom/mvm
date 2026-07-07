# ADR-106: The Phase-A / Phase-B build boundary — in-process rootfs materialization on the host

- Status: Proposed
- Date: 2026-07-04
- Owner: MVM Project
- Related: ADR-050 (supersedes its **mechanism**, preserves its **guarantee**),
  ADR-002 (microVM security posture — claim 3, claim 7, claim 11),
  ADR-046 / ADR-013 (no host tools / no host Nix),
  ADR-093 (builder auto-fallback), ADR-107 (virtiofs-root integrity — future),
  Plan 221 (this decision is its B0 deliverable), Plan 214 (HVF VMM),
  the `#1388` seam (`mvm_hostd::plan_admission::admit_and_start`).

## Context

"Build a microVM" is routinely treated as one indivisible act that must happen
inside the builder VM. It is not. It is two phases with completely different
security and portability profiles, and conflating them is what forces the
builder VM onto code paths that do not need it — including the last mandatory
subprocess on the local **run** path (`mkfs.ext4 + cp + veritysetup` shelled
inside a booted builder VM).

**Phase A — Nix evaluation + build.** Fetch sources, evaluate derivations,
compile, and *execute build logic* (nixpkgs, third-party flakes, `uv pip
install`, `pip-audit`). Produces a Nix closure / unpacked layer set. This phase
runs semi-untrusted, attacker-influenced code.

**Phase B — rootfs materialization.** Assemble an already-resolved closure /
unpacked OCI tree into an ext4 image + dm-verity Merkle tree + roothash. This
phase runs **no untrusted code** — it is deterministic byte-assembly over a
fixed input tree.

ADR-050 mandated materialize + verity *inside the builder VM* because that is
where `veritysetup` and `mkfs.ext4` live and where the result is deterministic.
But ADR-050's **security property is the roothash**, not the *location* the
roothash is computed in. Once a pure-Rust, memory-safe writer can produce a
byte-identical ext4 + verity tree, the location constraint is incidental.

Two forces make the split worth formalizing now:

1. **Portability.** macOS (and a hypothetical Windows host) has no `mkfs.ext4` /
   `veritysetup`. Phase B done in-process in pure Rust works on every host for
   free; shelling host tools never could.
2. **Operational fragility.** Nearly all builder-VM pain — Stage 0 nix
   fetcher-cache corruption, degraded-store `dev up` loops, cold-cache
   `BadActivate`, stale-supervisor stdio — is Phase-B *plumbing*, not Phase A.
   In-process materialize deletes that surface without touching the Nix
   boundary.

The tension: moving Phase B onto the host **removes the VM sandbox that
currently isolates materialize**. Materialize consumes attacker-influenced OCI
trees and its output feeds dm-verity (claim 3), so the writer becomes a new
host-side trusted-input surface. The host is nominally trusted (ADR-002 lists
"malicious host" out of scope), but that governs what we *defend*, not an
invitation to *widen* the host attack surface carelessly.

## Decision

Draw and enforce the **Phase-A / Phase-B boundary** as the rule that decides
what may run on the host versus what must stay in a VM:

**Phase B (materialize) MAY run in-process on the host** — and becomes the
default for the local run path — subject to the three preservation invariants
and the trusted-input posture below.

**Phase A (Nix evaluation + build execution) MUST stay in a VM we launched.**
Three independent reasons, any one sufficient:

- **Portability / physics.** On macOS there is no native path to Linux closures;
  a Linux userland is mandatory.
- **Determinism (ADR-046/013).** Host Nix is never used, even when present, so
  the same `mvmctl` yields byte-identical artifacts on every host. Building on
  the host reintroduces the host-variance this invariant exists to kill, and
  is where claim 7's reproducibility double-build lives.
- **Supply-chain blast radius (claim 11).** Phase A executes untrusted build
  input. The VM is what stops a poisoned nixpkgs / flake / app-dep package from
  reaching the key-holding host at build time. App-deps install *in a builder
  microVM, never on host* — this ADR makes that a boundary rule, not a habit.

**The deciding invariant, stated once:** *work that executes attacker-influenced
code stays in a VM; work that only assembles bytes from an already-resolved,
trusted-input tree may run in-process on the host — provided it is memory-safe
and its input surface is fuzzed.*

### Preservation invariants (Phase B in-process must hold all three)

1. **Claim 3 — integrity at boot.** The pure path emits a dm-verity roothash
   proving the rootfs bytes match a known-good hash — a pure-Rust SHA-256 Merkle
   tree replacing `veritysetup`. CI byte-diffs the hash tree against real
   `veritysetup` (`ext4-real-mount` lane).
2. **Claim 8 — signed-plan admission.** Unchanged. `admit_and_start` gates every
   boot regardless of how the rootfs was materialized.
3. **Determinism / reproducibility.** Fixed block size, zero verity salt, fixed
   inode order, zeroed timestamps, fixed allocation → same input tree yields a
   byte-identical rootfs and roothash.

### Trusted-input-surface posture (the price of moving off the VM)

Removing the builder-VM sandbox around materialize is only acceptable because:

- The writer is `#![forbid(unsafe_code)]` (`crates/mvm-ext4`): worst case is a
  returned error or a caught panic, **never host memory corruption**. The
  105-`unsafe`-block `am-fs-ext4` / `fs_ext4` crate is a **dev-only differential
  oracle**, never a runtime dependency.
- The writer's surface is **minimal**: create-dir / create-file / extents /
  symlink / perms (+ xattr only if a real OCI image needs it — open, see
  Consequences). No journaling, htree, casefold, ACL, inline-data, or fsck in
  the trust base.
- The writer's input surface **is** fuzzed and adversarially tested before the
  run path is flipped to the pure default. `build_image` carries a `cargo-fuzz`
  target (sibling to the OCI `unpack_layer` fuzz, wired into the `security.yml`
  fuzz lane) and a deterministic adversarial-tree suite (deep / huge /
  symlink-loop / malformed) mounted through the independent reader. That suite
  hardened the writer's contract — a malformed or impossible tree now returns
  `Err` (`NotADirectory`, `DuplicatePath`, tightened `BadPath`) rather than
  emitting an unreachable inode. A clean `deny.toml` over the writer's (tiny)
  dependency set completes the posture. **Wiring the run path to the pure path
  before this coverage is on `main` is out of order.**

## Consequences

- **ADR-050 is superseded in mechanism, preserved in guarantee.** Materialize +
  verity move from the builder VM to in-process pure Rust; the roothash +
  determinism + no-host-tools guarantees are unchanged. A vendored pure-Rust
  crate is *not a host tool*, so this does not weaken ADR-046/013.
- **No claim regression, one claim arguably strengthened.** Claims 3/7/8/11 all
  hold. We now own the verity computation in audited, memory-safe Rust instead
  of trusting a shelled `veritysetup`, which is a modest claim-3 improvement.
- **The trust-base foundation has landed.** The pure-Rust ext4 writer, the
  pure-Rust dm-verity Merkle roothash + hash tree (byte-diffed against real
  `veritysetup` in CI), the real-kernel loop-mount lane, the fuzz target, and the
  adversarial-tree suite are all on `main`. What remains is integration
  (`materialize_ext4_pure` OCI-dir walk), run-path wiring, and the default flip.
- **The local run path can become fully in-process, zero-shell** once the run
  path wires `LocalBackend::run_machine` to `materialize_ext4_pure` with an
  ADR-093-style auto-fallback to the builder VM on pure-path failure.
- **A new host-side trusted-input surface exists** and is gated by the posture
  above. This is a real, accepted cost; the `#![forbid(unsafe_code)]` floor
  bounds it to availability failures, not memory-safety failures.
- **Open — xattrs.** The current `Node` model (`Dir`/`File`/`Symlink` + `mode`)
  has no xattr channel. If any target OCI image carries capabilities/xattrs the
  writer silently drops them today. Resolve before the default flip (either prove
  no target needs them, or add a faithful xattr path with its own oracle).
- **Open — large images.** The writer currently caps at a single 128 MiB block
  group (over-cap input returns `Err(TooLarge)`). Multi-block-group support is a
  mechanical follow-up; until it lands, the pure path must fall back to the
  builder VM for larger rootfs.
- **Windows, if ever a target, gets Phase B for free** — no host `mkfs` needed.

## Alternatives considered

- **Full host build, including Phase A.** Rejected. Violates the determinism
  invariant (ADR-046/013), hands claim 11's threat model a host-level
  code-execution path, and is impossible on macOS anyway. The out-of-scope
  "malicious host" caveat is not license to widen the surface.
- **Keep materialize in the builder VM (status quo, ADR-050 as-is).** Rejected as
  the default — it keeps the last mandatory subprocess on the run path and all
  its plumbing fragility, and is unavailable where the host lacks `mkfs`. Retained
  only as the auto-fallback when the pure path can't handle an input (e.g. an
  over-cap image before multi-block-group lands).
- **Adopt `am-fs-ext4` / `ext4_rs` as the runtime writer.** Rejected. `ext4_rs`
  needs nightly and can't mkfs from scratch; `am-fs-ext4` carries ~105 `unsafe`
  blocks and ~80% unused attack surface for a read-only rootfs — unacceptable in
  the host trust base. Both survive as dev-only test oracles.
- **Virtiofs root (Option A), deleting materialize entirely.** The end state
  (supermachine / Plan 214), but claim 3 for a virtiofs dir needs a new integrity
  mechanism — deferred to ADR-107. Option B ships the "never shell out" run path
  without waiting on that decision.

## Scope / sequencing (Plan 221 Option B)

**Landed on `main`:** the `mvm-ext4` pure-Rust writer; pure-Rust dm-verity
roothash + hash tree with the `veritysetup` CI differential; the real-kernel
loop-mount lane; the `build_image` fuzz target; and the adversarial-tree
regression suite (which hardened the writer's error contract).

**In flight:** `materialize_ext4_pure` — the OCI-dir walk that turns an unpacked
tree into the writer's node set, behind a `pure-mkfs` feature.

**Remaining:** wire the run path (`LocalBackend::run_machine` → pure materialize,
builder-VM fallback); resolve the xattr and multi-block-group open items; flip
the pure path to the run-path default and update the CLAUDE.md "never on the
host — ADR-050" note to cite this ADR.

Note the order things actually landed diverged from a strict "ADR first" plan:
the writer, verity, and fuzz coverage merged before this record. That is fine for
a foundation with no consumers yet — but the **default flip** must not precede
this ADR's ratification and the full trusted-input posture being green on `main`.

Phase A stays in the VM indefinitely; this ADR does not touch the Nix-build
boundary. Option A (virtiofs root) continues under ADR-107.
