# Plan 221 — In-process rootfs materialization (no builder-VM, no subprocess)

**Status:** Option B shipped (B0–B5 landed: pure-Rust `mvm-ext4` writer +
in-process dm-verity + multi-block-group + fuzz + adversarial suite; ADR-106
records the Phase-A/Phase-B boundary; the run path materializes in-process by
default with an ADR-093-style auto-fallback to the builder VM on a pure-writer
limit or an xattr-bearing tree). Option A (virtiofs root) remains, gated on
ADR-107. Native inline-xattr support in the writer is a possible follow-up to
keep capability-bearing images on the pure path (today they fall back).
**Owner:** _tbd_
**Related:** ADR-106 (Phase-A/Phase-B boundary — the in-process materialize
decision), ADR-050 (OCI verity posture — superseded *mechanism*), ADR-046/013
(no host tools / no host Nix), ADR-093 (builder auto-fallback), Plan 214
(in-house HVF VMM), #1388 seam (synthesis→admission→`admit_and_start`).

## Why

The local **run path** currently materializes a rootfs by **booting a builder
VM** and shelling `mkfs.ext4 + cp` (and `veritysetup`) inside it. That is the
last mandatory subprocess/shell on the boot path and the reason a
fully-in-process `LocalBackend::run` isn't possible. Goal: **the run path never
subprocesses or shells out.**

The `#1388` seam already made admission + boot in-process
(`mvm_hostd::plan_admission::admit_and_start`). The only remaining in-process
blocker is materialize. Two options, sequenced:

- **Option B (now):** build the ext4 rootfs *in-process in pure Rust* on the
  host. Keeps the virtio-blk boot model; drops the builder VM + `mkfs`/`veritysetup`.
- **Option A (next):** boot the guest with the unpacked OCI dir as a **virtiofs
  root** — deletes materialize entirely. This is the supermachine/Plan-214 end state.

### Prior art (researched 2026-07)

- **supermachine** — shares unpacked OCI layers via **virtiofs** on HVF/KVM; no
  `mkfs`, no image. (This is Option A, and it's the VMM Plan 214 is building.)
- **smolvm** — libkrun; still shells `mkfs.ext4` (what we're removing).
- Pure-Rust ext4 writers exist, all fully userspace (no root/loop/subprocess):
  `am-fs-ext4` (`fs_ext4::mkfs` — formats an empty ext4, no populate), `ext4_rs`
  (read+write an *existing* image: `create`/`write_at`/`dir_mk`/`link`, but no
  from-scratch mkfs), `tpdenk/mkfs` (library API not implemented — CLI only).
  → **Viable combo: `am-fs-ext4` (format) + `ext4_rs` (populate).** Needs
  end-to-end validation; fallback is to own a minimal writer (see B1).

## Security invariants to PRESERVE (both options)

1. **Claim 3 (integrity at boot).** ADR-050: a verity roothash proves the rootfs
   bytes match a known-good hash. Any new materialize must still produce that
   guarantee (Option B: pure-Rust dm-verity Merkle tree; Option A: an equivalent
   — see A0).
2. **Claim 8 (signed-plan admission).** Unchanged — `admit_and_start` already
   gates every boot.
3. **Determinism / reproducibility.** ADR-050 pins block size + zero salt so the
   roothash is content-addressable. The pure path must be byte-deterministic.
4. **No host tools / no host Nix (ADR-046/013).** A *vendored pure-Rust crate is
   not a host tool*, so in-process pure-Rust materialize satisfies this — unlike
   shelling a host `mkfs`/`veritysetup` (which macOS lacks anyway). This is the
   key reason Option B does not weaken ADR-046's posture.

**On superseding ADR-050:** ADR-050 mandates materialize+verity *in the builder
VM* because that's where `veritysetup`/`mkfs` live and it's deterministic. Its
*security property* is the roothash, not the location. Option B preserves the
roothash + determinism + no-host-tools while moving the work in-process. ADR-106
(below) records this: it supersedes ADR-050's **mechanism**, not its **guarantee**.

## Option B — pure-Rust in-process ext4 materialize (NOW)

Replace the builder-VM `mkfs+cp+veritysetup` with in-process pure Rust. Boot
model unchanged (virtio-blk ext4 + verity sidecar).

- **B0 — ADR-106.** Record the decision + trusted-input-surface posture (a
  filesystem writer over untrusted OCI trees is a new attack surface → fuzz +
  `deny.toml` + adversarial tests). Supersede ADR-050's mechanism, preserve its
  guarantee. _[deliverable: `specs/adrs/106-in-process-rootfs-materialize.md`]_

- **B1 — feasibility + selection (GATING).** Prototype `am-fs-ext4` (format) +
  `ext4_rs` (populate from the unpacked OCI dir). Validation gates — **all** must pass:
  1. **Round-trips in userspace:** write the tree, read it back with `ext4_rs`;
     files/dirs/symlinks/perms/sizes match. (Runs on macOS — no mount needed.)
  2. **Mounts on Linux read-only:** a CI live-mount lane (sibling to
     `verified-boot-artifacts`) mounts the image and diffs the tree.
  3. **dm-verity:** a pure-Rust SHA-256 Merkle-tree generator (replacing
     `veritysetup`) yields a roothash; the guest boots verity-sealed; roothash is
     stable across runs.
  4. **Deterministic:** same unpacked tree → byte-identical rootfs + roothash
     (reproducibility gate).
  5. **Faithful:** perms, symlinks, sizes; xattrs iff real OCI images need them.
  6. **Auditable:** `cargo-audit`/`deny.toml` clean; crate maintained.
  - **Fallback if the combo fails a gate:** (a) own a **minimal deterministic
    no-journal ext4 writer** — the read-only rootfs case is bounded and known
    (Firecracker/microVM ecosystems have done it); or (b) keep the builder-VM
    path as an ADR-093-style auto-fallback. B0/ADR-106 records which.

  - **B1 initial probe (2026-07-03) — candidate selected: `am-fs-ext4` v0.4.0.**
    - `ext4_rs` v1.3.3: **rejected** — requires **nightly** (`#![feature(error_in_core)]`);
      non-starter for a stable-toolchain production dep. Also can't mkfs from scratch.
    - `tpdenk/mkfs`: **rejected** — library API "not implemented" (CLI-only).
    - **`am-fs-ext4` v0.4.0: functionally viable** — stable, single-crate,
      userspace, complete R/W ext4 (`mkfs::format_filesystem` + `apply_mkdir` /
      `apply_create` / `apply_pwrite` / `apply_symlink` + xattr/ACL + `fsck` +
      read path). **But rejected as a runtime dependency on security grounds** (below).

  - **B1 decision (2026-07-03) — OWN a minimal writer; `am-fs-ext4` is a
    dev-only test oracle, never a runtime dep.** Security review of `am-fs-ext4`:
    - **~105 `unsafe` blocks** (60 + 45 in `am-fs-core`); not `#![forbid(unsafe_code)]`.
      Its input is attacker-influenced (arbitrary OCI trees) and its output feeds
      dm-verity (**claim 3**), so a bug is potential **host** memory corruption —
      and Option B *removes the builder-VM sandbox* that currently isolates `mkfs`.
    - **~80% is unused attack surface** for a read-only rootfs: full journaling
      (jbd2/transaction), htree, **casefold (pulls `unicode-normalization`/`caseless`)**,
      ACL, inline-data, fsck — all linked + trusted but never exercised.
    - Early-stage (v0.4.0, no RUSTSEC history); determinism unverified.
    - **Therefore B2 owns a `#![forbid(unsafe_code)]`, no-journal, read-only ext4
      writer** — memory-safe (worst case = caught panic, never corruption),
      deterministic by construction (fixed inode order, zeroed timestamps, fixed
      allocation), minimal surface (create-dir/create-file/extents/symlink/perms/
      xattr only). `am-fs-ext4` + real `mkfs.ext4` become **differential-test
      oracles** (dev-deps / CI): our writer's bytes must mount + read identically.
      This keeps the 105-`unsafe` crate out of the production trust base while
      still proving our writer correct.
    - Remaining validation gates unchanged (Linux mount, pure-Rust dm-verity
      Merkle roothash to drop `veritysetup`, byte-determinism, faithful
      perms/symlinks/xattrs, fuzz).

- **B2 — `materialize_ext4_pure`.** New fn in `mvm-build` mirroring
  `materialize_ext4`'s API (`MaterializeExt4Input → MaterializedExt4`), behind a
  `pure-mkfs` feature. Pure-Rust ext4 build + pure-Rust dm-verity roothash.
  `deny.toml` entries for the chosen crate(s).

- **B3 — security tests + CI lane.** Fuzz target for the writer (trusted-input
  surface, sibling to the OCI `unpack_layer` fuzz); verity-compat test;
  determinism test; adversarial tree (deep/huge/symlink-loop/malformed). Add a
  `pure-materialize` CI lane.

- **B4 — wire the run path (the payoff).** Prefer the pure path; auto-fallback to
  the builder VM only on pure-path failure (reuse ADR-093
  `run_with_builder_fallback`). Then `mvm-client-local::LocalBackend::run_machine`
  gains deps on `mvm-build` + `mvm-oci` (**cycle-safe** — neither depends on
  `mvm-client`/`mvm-sdk`), resolves the image → materializes **in-process** →
  `admit_and_start` → boot. **Fully in-process, zero shell.**

- **B5 — flip default + docs.** Pure materialize becomes the run-path default;
  the builder VM stays for **Nix builds** (which genuinely need a VM). Update the
  CLAUDE.md "never on the host — ADR-050" note to cite ADR-106 for the run path.

## Option A — virtiofs rootfs (NEXT; deletes materialize)

Boot the guest with the unpacked OCI dir as a **virtiofs root**. No ext4, no
`mkfs`, no verity-of-a-block-device. This is supermachine's model and the
Plan-214 in-house-HVF end state.

- **A0 — ADR-107 (the hard part).** Integrity model for a virtiofs root:
  dm-verity is block-device-specific and does **not** apply to a virtiofs dir, so
  **claim 3 needs a new mechanism**. Candidates: (i) trusted immutable host dir +
  per-file **fs-verity**; (ii) a **signed content manifest** the guest verifies
  at mount; (iii) a distinct posture for the local/dev tier (with prod staying on
  Option B's block+verity). This is a **numbered-claim decision** and blocks A
  shipping. _[deliverable: `specs/adrs/107-virtiofs-root-integrity.md`]_

- **A1 — virtiofs device in the in-house HVF backend** (Plan 214). libkrun/vz
  already expose virtiofs *shares* (`vz_objc.rs`, `krun_add_*`); extend to a
  **root** device.
- **A2 — guest boot model:** `root=virtiofs` kernel cmdline + init mounts the
  virtiofs root; `mvm-guest` agent + `/init` work on a virtiofs root.
- **A3 — integrity impl** per A0.
- **A4 — wire run path** to virtiofs-root for virtiofs-capable backends
  (in-house HVF, libkrun, vz). **Firecracker stays block+ext4** via Option B.
- **A5 — retire ext4 materialize** for virtiofs-capable backends (Option B path
  remains for Firecracker + as the B4 fallback).

## Open questions / risks

- **Crate maturity** (`am-fs-ext4`/`ext4_rs` are early-stage) → B1 gates +
  own-a-minimal-writer fallback.
- **Pure-Rust dm-verity** → bounded (SHA-256 Merkle tree over 4K blocks); vet a
  crate or own it (~150 LoC).
- **xattrs / large files / determinism** in the pure writer → B1 gate 5.
- **virtiofs-root integrity (claim 3)** → the ADR-107 blocker for Option A.
- **Windows** (if ever a target) has no host `mkfs` — Option B's pure path fixes
  this for free; Option A sidesteps it.

## Sequencing

```
B0 (ADR-106) → B1 (gate) → B2 → B3 → B4 (in-process run!) → B5 (flip default)
                                              ↓
                              A0 (ADR-107) → A1 → A2 → A3 → A4 → A5 (delete materialize)
```

Option B delivers the "never shell out" run path without touching the boot
model. Option A is the architectural end state that removes materialize entirely
— gated on the virtiofs-root integrity ADR.
