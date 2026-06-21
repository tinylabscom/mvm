# ADR-093 — One slim microVM kernel, two backends, published and CVE-versioned

**Status:** Proposed
**Date:** 2026-06-21
**Relates to:** [ADR-002](002-microvm-security-posture.md),
[ADR-046](046-builder-vm-via-libkrun.md),
[ADR-055](055-passt-virtio-net.md)

## Context

mvm boots two different kernels today, in very different states.

**Linux / Firecracker + the builder VM** boot a slim, hand-rolled kernel
(`nix/images/builder-vm/kernel/`): built from `defconfig` plus aggressive
enable/disable deltas and `make olddefconfig`, with `CONFIG_MODULES=n` so
everything we need is built in and there is no `/lib/modules` tree. Audio,
USB, video, DRM/FB, wireless, BT, HID, the entire SoC platform tree,
SCSI/ATA/MMC, Xen, and (on arm64) ACPI are already compiled out. A workload
variant adds dm-verity; the builder variant adds virtio-fs, namespaces +
cgroups, and an iptables egress lockdown. On this path the "tiny custom
kernel" property is largely already true — it is simply unmeasured, unnamed,
and unmarketed.

**macOS / libkrun** boots the kernel **bundled inside Homebrew's `libkrunfw`
dylib** — upstream libkrunfw 5.5.0's own config (Linux 6.12.91). We do not
control that config. This is the genuinely un-slimmed kernel in the fleet,
and the larger untapped attack-surface win.

Three forces converge on changing this:

1. **Attack surface (primary).** Every subsystem we do *not* compile in is an
   entire class of kernel CVEs that cannot apply to us. ADR-002's posture is
   the frame; a smaller kernel is fewer things that can be exploited *and*
   fewer bumps to chase when a CVE lands.
2. **Resources (secondary).** Smaller kernels boot faster and carry a smaller
   per-VM footprint — measured before/after, kept only where it moves.
3. **Claim (tertiary).** A measured, reproducible, named kernel size lets us
   credibly state a "tiny custom microVM kernel" property.

The macOS path also means a kernel CVE could otherwise force a full `mvmctl`
release, and there is no story today for rebuilding and relaunching microVMs
when a kernel vulnerability is published.

## Decision

### 1. One slim kernel, two backends

Collapse the two kernels into a **single slim `vmlinux` we own**, consumed two
ways:

- **Firecracker** — kernel path, as today.
- **libkrun** — handed our `vmlinux` at runtime via the existing
  `krun_set_kernel()` FFI in `crates/deps/libkrun-sys`, **replacing** the
  bundled libkrunfw kernel. Homebrew `libkrun`/`libkrunfw` stay installed
  (libkrun is the VMM; the bundled kernel is just a fallback we stop using).
  The historical TSI-patch requirement is moot — networking moved to
  passt/gvproxy over virtio-net (ADR-055), so a stock slim kernel has no TSI
  dependency.

The kernel module is promoted out of `nix/images/builder-vm/kernel/` to a
shared **`nix/images/kernel/`**: it is no longer builder-VM-specific, it is
*the* kernel. The existing base / builder-delta / workload-delta structure
carries over unchanged.

### 2. Gate 0 — libkrun boot-feasibility spike (hard go/no-go)

Nothing else ships until a stock slim kernel is proven to boot under libkrun.
The spike boots the *current* slim workload kernel via `krun_set_kernel()` and
must reach the guest agent over vsock, exercising: PVH/entry-point + load-
address expectations (`libkrun-sys` already computes these for `set_kernel`),
virtio-mmio/PCI discovery parity, `hvc0` console, and gvproxy/virtio-net
networking without the bundled kernel.

- **Boots →** proceed with Decision 1 as written.
- **Does not boot →** documented fallback: slim libkrunfw's *own* bundled
  config (`nix/packages/libkrunfw.nix`) for the macOS path only; Linux still
  gets the unified slim kernel. We are betting on the unified path; the spike
  is the honest off-ramp.

The spike is a throwaway branch plus a findings note appended to the
implementation plan — not production code.

### 3. Shrink methodology — disciplined subtraction

The kernel is already aggressive, so this is audit-driven subtraction, not a
rewrite:

- **Measure first.** Build the resolved `.config` and the `vmlinux`; record
  compressed + uncompressed size, `=y` symbol count, and built-object count.
  No claim without a number.
- **Subtract by audit, not by guess.** For each remaining subsystem, trace
  whether any boot path or the guest agent actually uses it (the audit
  discipline already documented in `base.nix`/`default.nix`). Each removal
  cites *why nothing uses it* in the config comment, framed in attack-surface
  terms.
- **CI size gate.** A test asserts the `=y` set stays within a named budget
  and the disabled-subsystem list does not silently regrow on a kernel bump.
  This keeps the "tiny" property true over time, not just at landing.
- **Stop rule.** Stop when the next removal breaks boot / agent-reachability
  or saves trivially. We do not chase bytes past the point of risk.

### 4. Kernel as an independently-versioned, published artifact

The kernel becomes a first-class artifact with identity
**`(kernel_version, config_hash) → artifact_hash`**:

- `kernel_version` = the upstream Linux pin; `config_hash` = hash of the
  resolved `.config`; `artifact_hash` = content hash of the built `vmlinux`.
  Any of the three changing yields a new pin.
- **Source stays in-tree** under `nix/images/kernel/`. The local-build
  invariant holds (ADR-046): a contributor editing the kernel config sees it
  in the very next `mvmctl dev up`, no release round-trip, no external cache.
- **Publish layer.** The slim kernel joins the ADR-046 prebuilt release stream
  as a **hash-verified download** — the same pattern as the dev-image
  download (per-arch `*-checksums-sha256.txt`, stream-through SHA-256,
  reject + delete on mismatch). This extends the hash-keyed GHA prebuilt the
  current `base.nix` already references.
- **Host resolves by pin.** `mvmctl` references the kernel by `artifact_hash`;
  source checkouts build locally, end-users fetch + verify the prebuilt. A new
  kernel is a new pin the host swaps in — **no `mvmctl` recompile**.
- **Dedicated kernel CI workflow** so kernel rebuilds (slow, novel,
  un-substitutable) stay off the hot PR critical path and fire only on
  config/version change.

This is what makes a kernel CVE a **kernel-only release**.

### 5. Vulnerability lifecycle — rebuild-and-relaunch

- **Model: cattle, not pets.** No in-place patching of a sealed, dm-verity
  image; live kernel patching (kpatch/livepatch) is rejected as antithetical
  to verified boot. A kernel CVE → bump `kernel_version` → new `artifact_hash`
  → relaunch on the new pin. Every image is rebuilt reproducibly from its
  definition, so remediation *is* rebuild-from-pin.
- **In scope (mvm):** the single-VM primitive — rebuild a VM from a new kernel
  pin and relaunch it.
- **Designed-for follow-ups (named, not built here):**
  - **Detection watcher** — sibling to ADR-002 claim 7's `cargo audit`: flags
    when the `linux_6_12.y` pin trails the latest LTS point release or is hit
    by a published Linux CVE. New sibling plan.
  - **Fleet rollout** — drain-and-roll across running microVMs lives in
    **mvmd**, not mvm. mvm exposes the primitive; mvmd orchestrates the fleet.

The artifact identity in Decision 4 is shaped to serve both follow-ups from
day one.

### 6. Naming hygiene

All work uses neutral, mvm-native language ("slim microVM kernel"). No
reference to any sibling project in filenames, branches, PRs, commits, code,
or specs.

## Consequences

**Positive**

- One kernel to audit, slim, version, and patch — instead of two, one of which
  we did not control.
- macOS guests stop booting an un-slimmed third-party kernel; priority C
  (attack surface) is realized uniformly across both backends.
- A kernel CVE ships as a kernel-only artifact bump — no `mvmctl` rebuild,
  no full release — and the rebuild-and-relaunch model gives a concrete
  remediation primitive.
- The "tiny custom kernel" claim becomes measured, reproducible, and
  CI-guarded rather than aspirational.

**Negative / costs**

- libkrun boot under `krun_set_kernel()` is unproven for a stock slim kernel;
  Gate 0 may force the Option 2 fallback for macOS, leaving two kernels on
  that path.
- The kernel build is slow and un-substitutable (`cache.nixos.org` has no
  hit for a novel `.config`); mitigated by the prebuilt stream + dedicated
  CI, but the first source build still pays 3–5 min.
- A published-prebuilt kernel adds release-pipeline surface (checksums,
  per-arch artifacts) that must stay hash-verified to preserve claim-6-style
  integrity.

## Alternatives considered

- **Separate repo for kernel/images** (mirroring how some peer tools structure
  their image builds). Rejected: the kernel has exactly one consumer (mvm), so
  the main benefit of a split — decoupled downstream consumers — does not
  apply, while it would add a cross-repo pin-bump to every kernel change and
  fight the ADR-046 local-build invariant. Revisit only if the kernel gains a
  consumer outside mvm. Cadence-decoupling is obtained in-tree via a dedicated
  CI workflow + the hash-keyed prebuilt.
- **Slim libkrunfw's bundled config (Option 2)** as the primary macOS path.
  Held as the Gate 0 fallback only: lower boot risk, but it keeps two kernels
  and makes us own a libkrunfw fork + its distribution against the Homebrew
  install path.
- **Live kernel patching** for CVE response. Rejected: incompatible with a
  sealed, dm-verity-verified boot image and a large new complexity/trust
  surface.
- **Welding the kernel into the `mvmctl` binary.** Rejected: it would force a
  full `mvmctl` release on every kernel CVE — the exact coupling Decision 4
  exists to break.

## Sequencing

1. **Gate 0** — libkrun boot-feasibility spike. Go/no-go.
2. **Promote + unify** — move kernel to `nix/images/kernel/`; wire libkrun's
   `krun_set_kernel()` to our `vmlinux`; reach parity on both backends.
3. **Measure + shrink** — baseline, audit-subtract, land the CI size gate.
4. **Artifact + publish** — `(version, config_hash) → artifact_hash`, the
   hash-verified prebuilt stream, host pin-resolution, dedicated kernel CI.
5. **Single-VM remediation primitive** — rebuild-from-new-pin + relaunch.
6. **Deferred follow-ups** — detection watcher (sibling plan); mvmd fleet
   rollout (mvmd repo).

The implementation plan carries the task breakdown and the Gate 0 findings
note.
</content>
</invoke>
