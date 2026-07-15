# ADR 051: Mvm runtime overlay disk

- Status: Proposed
- Date: 2026-05-14
- Owner: MVM Project
- Related: ADR-002 (microVM security posture, claims 2 + 3 + 4), ADR-014 (builder VM via libkrun), ADR-041 (claim-safe sandbox parity), ADR-049 (TLS substitution mechanism), ADR-050 (verity posture for pulled OCI images), Plan 74 W1 + W3 + W4

> **Consolidation (2026-05-31 — see [ADR-066](066-target-architecture.md) §"ADR consolidation"):** ADR-051 is the **canonical** image & runtime-overlay ADR. It **consolidates** ADR-039 (runtime-overlay composition) and ADR-050 (OCI image verity posture); those are **superseded** and physically archived to `archive/adrs/` in Stage E. The universal verity-sealed runtime overlay (this ADR's "Option B") is the one-agent-everywhere path.

## Context

Plan 74 W1 lets users launch arbitrary OCI images in microVMs. An
OCI image's rootfs is **user content**: bytes the user pulled from
a registry, pinned by a content digest the user controls. mvm
needs the *guest agent*, the *seccomp shim*, and the per-language
*SDK runtime library* (ADR-049 vsock substitution hooks) present
in every microVM regardless of how that rootfs got there.

Today mvm-built images bake the agent in:
`nix/lib/mk-guest.nix` adds `mvm-guest-agent` to the closure,
`mvm-seccomp-apply` is invoked from the systemd-style service
launch line, and image-builders bring their own SDK runtime by
including it in their flake. None of that machinery applies to a
pulled `alpine:3.19` or `python:3.12`.

Two ways to fix it:

**Option A — Inject into the OCI rootfs at unpack time.** Layer
unpack (W1.3) writes the agent + SDK runtime into the rootfs
between the last OCI layer and the verity seal. Pros: the rootfs
"just works" — every binary inside the guest can find the agent
without env tweaks. Cons: the digest of the rootfs no longer
matches the OCI image's digest (we mutated it), so the
content-addressable identity is lost. Every layer-unpack PR has
to special-case the "post-OCI, pre-verity" injection point.
Conflates user content with mvm content in one ext4 blob.

**Option B — A separate verity-sealed disk attached at boot.** mvm
builds a small ext4 containing the agent + SDK runtime, verity-
seals it the same way it seals rootfs, and attaches it as a
second virtio-blk device at every microVM start. The OCI rootfs
is left byte-for-byte identical to what the registry served.
Both Nix-built and OCI-pulled images get the same agent story.

This ADR picks Option B and makes it the default for *every*
microVM, not just OCI-pulled ones. Unifying the agent story is
the most valuable side-effect — it eliminates the "where is the
agent today vs. where will it live tomorrow" split that would
otherwise haunt W1 and every future image factory.

## Decision

**Every mvm microVM boots with two block devices: a rootfs
(`/dev/vda`, user content, ext4) and an mvm-runtime overlay
(`/dev/vdc`, mvm content, ext4). Both are verity-sealed; both
roothashes appear on the kernel cmdline; mvm-verity-init
validates both before pivot_root.** The overlay is mounted
read-only at `/mvm/runtime` inside the guest. Service launches
inject the language-specific path env vars (`PYTHONPATH`,
`NODE_PATH`, …) before forking the workload.

**The host does not attach an unchecked cache entry.** Before any
backend threads the overlay paths into a boot config, mvm
re-hashes the cached `overlay.ext4`, `overlay.verity`,
`overlay.roothash`, and `VERSION` files and compares them to the
recorded SHA-256 manifest stored beside the artifact in
`~/.cache/mvm/runtime-overlay/<version>/<arch>/`. A mismatch is an
admission-time error that forces a rebuild or re-download. The
guest then mounts only the dm-verity device, never the raw ext4
payload directly.

### Overlay contents (per-arch, ~10-20 MB)

```text
/mvm/runtime/
├── agent                       (mvm-guest-agent, statically linked,
│                                uid 901)
├── seccomp-apply               (mvm-seccomp-apply shim)
├── runner                      (mvm-runner, function-workload runtime)
├── sdk-py/                     (mvm-sdk-runtime Python wheel +
│                                deps; importable via PYTHONPATH)
├── sdk-ts/                     (mvm-sdk-runtime npm package +
│                                deps; importable via NODE_PATH)
├── certs/                      (CA bundle for outbound TLS from
│                                the agent itself; user TLS uses
│                                the rootfs's trust store)
└── VERSION                     (semver matching the mvm release
                                 that produced this overlay)
```

The overlay does NOT contain a shell, libc, or anything a
workload could `execve`. It is a *data* disk plus three mvm-
controlled binaries. The shell + libc that workloads use live in
the rootfs — Nix-built or OCI-pulled, the user's choice.

### Boot path

1. Firecracker starts the kernel with the verity initramfs as
   PID 1, and the cmdline:
   ```text
   root=/dev/mapper/root
   mvm.roothash=<rootfs-roothash>
   mvm.runtime_roothash=<overlay-roothash>
   ```
2. `mvm-verity-init` constructs `/dev/mapper/root` over `/dev/vda`
   + `/dev/vdb` (existing rootfs verity sidecar), and
   `/dev/mapper/runtime` over `/dev/vdc` + `/dev/vdd` (overlay
   verity sidecar). Either roothash panics on tamper.
3. Mount `/dev/mapper/root` at `/sysroot`.
4. Mount `/dev/mapper/runtime` at `/sysroot/mvm/runtime` (ro,
   bind-mount the verity device over the rootfs's `/mvm/runtime`
   directory; `/mvm` is reserved per the path-collision rule
   below).
5. pivot_root to `/sysroot`.
6. Exec `/mvm/runtime/agent` as PID 1 of userspace, which spawns
   the service supervisor.

Service supervisor injects per-service env vars (PYTHONPATH /
NODE_PATH / …) before forking the workload's entrypoint.

### Verity story

Identical to rootfs verity:

- Deterministic `veritysetup format` with pinned block sizes and
  pinned salt (same parameters as `nix/flake.nix::verityArtifacts`).
- Sidecar emitted alongside the overlay ext4 as part of the
  release artifacts: `runtime-overlay-{arch}-{version}.ext4`,
  `.verity`, `.roothash`.
- The cached artifact also carries a local `checksums-sha256.txt`
  over the canonical cache filenames (`overlay.ext4`,
  `overlay.verity`, `overlay.roothash`, `VERSION`). mvm rechecks
  those hashes before attach so a drifted cache entry cannot be
  mounted.
- mvmctl picks the overlay whose `VERSION` matches the running
  `mvmctl` semver. Mismatched versions are an admission-time
  error, not a silent boot.

### Path reservation

`/mvm/` is reserved. An OCI image that ships content at `/mvm`
collides with the mount point. Admission-time check rejects such
images with a clear error: `error: OCI image carries content at
/mvm — this path is reserved for the mvm runtime overlay`. Easy
to surface in W1.3 layer unpack: walk the layer tarballs once,
fail if any entry starts with `/mvm/` (any directory or file).

### Refactor consequences for `mkGuest`

`nix/lib/mk-guest.nix` stops baking `mvm-guest-agent`,
`mvm-seccomp-apply`, and `mvm-runner` into the per-image closure.
Those binaries come from the overlay at boot. Net effect:

- mvm-built rootfs gets smaller (~10-15 MB drop, since the agent
  and runner aren't duplicated per image).
- One code path for "where does the agent live" across Nix-built
  and OCI-pulled. Easier to reason about, easier to test, easier
  to ship a security fix to (single overlay rebuild, not N
  per-image flake bumps).
- A microVM running an old mvmctl with an old overlay still boots
  — the agent's vsock protocol is versioned (ADR-002 §W4.1 with
  `#[serde(deny_unknown_fields)]`), so a newer host talking to an
  older guest agent fails admission cleanly rather than silently
  misbehaving.

This is a one-time refactor of `mkGuest` (estimated 1-3 days). It
lands inside plan 74 W1 because that's the workstream that forces
the issue.

## Consequences

### Positive

- OCI rootfs stays byte-for-byte identical to the registry
  content. Digest pins hold; reproducibility for the OCI half of
  the story is the registry's reproducibility, full stop.
- Mvm controls its own runtime story in one place. A CVE in the
  guest agent ships one fix (rebuild the overlay, bump the
  roothash, push the artifact) rather than N flake bumps.
- The SDK runtime library (per-language, ADR-049 vsock hooks)
  has a stable mount point. SDK upgrades become "rebuild the
  overlay"; no per-image work.
- Verity claim 3 is *strengthened*: a tampered overlay panics
  the kernel just like a tampered rootfs would. Two roothashes,
  both load-bearing.
- Snapshot/fork (claim 8 / instance pause+resume) is unaffected.
  The overlay is read-only and content-addressed; it's not in
  the snapshot delta.

### Negative

- A second block device per microVM. Firecracker and libkrun
  both support N drives, well under any practical cap, so no
  hard limit issue. Verify Apple Container backend's drive count
  (W3 verity shipped 2026-04-30 with two drives already; three
  is on the edge of what's tested).
- An additional release artifact per arch
  (`runtime-overlay-{arch}.tar.gz` + `.tar.gz.sha256`), whose
  contents are still the canonical `overlay.ext4` + `.verity` +
  `.roothash` + `VERSION` set.
  Adds ~10-20 MB per arch to the release payload.
- `/mvm` path reservation is a contract with users. Documented
  on the public `oci-ingest` status row; admission-time check
  for OCI images.
- `mkGuest` refactor is real surface area — every existing
  Nix-built image rebuilds when the overlay-vs-baked split
  lands. One-time cost.

## Non-goals

- **User-supplied overlays.** v1 ships one mvm-controlled
  overlay per arch. Custom overlays (e.g. a vendor-supplied
  language-specific SDK pack) can be a future ADR; out of scope
  here.
- **Writable overlay.** The overlay is read-only and
  verity-sealed. Workloads that need writable shared state use
  `--add-dir`, volumes, or the snapshot upper layer — those have
  their own contracts.
- **Replacing initramfs.** `mvm-verity-init` stays in the
  initramfs blob, not in the overlay. The initramfs needs to run
  before any disk is mounted; chicken-and-egg.
- **Multi-version coexistence on one host.** Each running mvmctl
  uses one overlay version. Snapshot restore across mvmctl
  versions is governed by the existing snapshot epoch contract,
  not by the overlay.
- **Embedded language interpreters.** The overlay does not ship
  Python, Node, or any other interpreter. Those come from the
  user's rootfs (Nix-built or OCI-pulled). The overlay's
  `sdk-py/` is the *library*; the interpreter is the user's
  responsibility.

## Open questions

- **Versioning policy for the overlay.** Mvm semver bumps roll
  the overlay too. Should the overlay carry a *separate* semver
  for backward-compat windows ("any agent v2.x speaks to any
  host v2.y for y >= x")? Probably yes; the vsock protocol
  already has this shape (`#[serde(deny_unknown_fields)]` +
  versioned envelope per ADR-002 W4.1). Pin the policy in the
  W1.3 implementation PR.
- **Overlay size budget.** ~10-20 MB is the rough target. Hard
  cap of 32 MB is reasonable; bump only with an ADR amendment.
  Constrains future SDK additions: if Python + TS + Rust SDKs
  combined exceed 32 MB, we either trim, split overlays per
  language, or amend.
- **Apple Container backend with three drives.** Verified-boot
  shipped 2026-04-30 with two drives (rootfs + verity sidecar);
  adding the overlay makes three. Confirm
  `setInitialRamdiskURL` + three virtio-blk devices is supported
  on the macOS path before flipping the overlay to default.
- **Bootloader path for cross-arch.** Firecracker handles the
  drives identically on aarch64 and x86_64, but the kernel
  cmdline parameters differ in subtle ways. The overlay's
  `mvm.runtime_roothash=` parameter needs the same cmdline shape
  the existing `mvm.roothash=` uses, on every backend.

## Implementation Plan

Tracked in [`specs/plans/74-claim-safe-sandbox-parity.md`](../plans/74-claim-safe-sandbox-parity.md)
§W1.3 (layer unpack — needs the `/mvm` collision check) and §W1.4
(verity generation — extends to also generate the overlay).
ADR-051's task list folds into W1 as:

- `nix/images/runtime-overlay/flake.nix` — new flake building the
  per-arch overlay ext4 + verity sidecar + roothash.
  Deterministic; pinned `cryptsetup` per #223.
- `mvm-build/src/runtime_overlay.rs` — host-side path resolver
  that picks the right overlay artifact for the running mvmctl
  version. Cached under `~/.cache/mvm/runtime-overlay/<version>/`.
- `mvm-backend` — attach the overlay drive + sidecar at every
  microVM start; thread `mvm.runtime_roothash=<hex>` into the
  cmdline alongside the existing `mvm.roothash=`.
- `crates/mvm-guest/src/bin/mvm-verity-init.rs` — extend to
  construct the second dm-verity target and bind-mount it at
  `/mvm/runtime`. Add `mvm.runtime_roothash=` to the cmdline
  parser; absence is an admission-time error.
- `nix/lib/mk-guest.nix` — drop `mvm-guest-agent`,
  `mvm-seccomp-apply`, `mvm-runner` from the per-image closure.
  Add a build-time check that the rootfs does not contain
  `/mvm`.
- `mvm-build/src/oci_to_rootfs.rs` (W1.3) — walk OCI layers
  before unpack; fail if any entry starts with `/mvm/`.
- Service supervisor — inject `PYTHONPATH=/mvm/runtime/sdk-py:...`
  and `NODE_PATH=/mvm/runtime/sdk-ts:...` per service.
- Release pipeline — emit the overlay artifact alongside the
  existing per-arch kernel + dev image + default microvm image
  artifacts.

W1 plan workstream additions:

| Task                                                | Lives in W1 sub-PR |
| --------------------------------------------------- | ------------------ |
| Build the overlay flake                             | W1.3 prep          |
| Attach the overlay at boot                          | W1.4 (alongside verity wiring) |
| `mkGuest` refactor + per-image closure shrink       | W1.4               |
| `/mvm` collision check on OCI unpack                | W1.3               |
| Apple Container three-drive verification             | W1.4               |

### Tests

- **Positive boot.** Cold-boot an mvm-built image + the overlay;
  agent comes up at uid 901; `/mvm/runtime/sdk-py/` is importable
  from a Python service.
- **Tamper test.** Flip a byte in the overlay ext4 between
  mvmctl pull and microvm start; assert kernel panics with the
  expected verity message, agent never starts.
- **Path collision test.** Construct an OCI manifest whose layer
  ships `/mvm/foo`; assert admission-time rejection with the
  documented error.
- **Version mismatch.** Manually point mvmctl at an overlay
  produced by a different mvmctl version; assert
  admission-time error.
- **Snapshot restore.** Snapshot a running microvm, restore on
  the same host; assert the overlay is re-attached with the same
  roothash and verity holds.
- **Apple Container.** Same set against the macOS backend.

The overlay becomes a first-class CI artifact gated by the same
deterministic-build checks the kernel and dev image already get
(claim 7 — Cargo deps audited + reproducibility double-build).
