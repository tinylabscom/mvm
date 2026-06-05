# On-device Vz sandbox — feature-parity gap analysis

Compares mvm against a second adjacent product (distinct from the
libkrun embeddable SDK in
[`embeddable-sandbox-sdk-dx-gap-analysis.md`](embeddable-sandbox-sdk-dx-gap-analysis.md)):
an Apache-2.0, **macOS-only, `Virtualization.framework`-native** microVM
sandbox for running untrusted agents on the user's own Mac. Rust core,
no Swift binary — it drives VZ directly via the `objc2-virtualization`
stack. Single-shot CLI (`run a command in a fresh VM → exit with its
code`) plus an MCP server and a desktop/computer-use mode. (Named
obliquely per repo policy — "the on-device sandbox" throughout. Captured
2026-06-03.)

The point of this doc: separate the features worth borrowing from the
ones we already lead on or deliberately don't do, and route each
borrowable item to the plan that owns it. The Rust-native VZ mechanism
and the guest `/init` exit-code contract are written up separately in
[`../plans/152-rust-native-vz-and-init-lifecycle-parity.md`](../plans/152-rust-native-vz-and-init-lifecycle-parity.md)
and the [[reference_on_device_vz_objc2]] memory — this doc is the
product/feature surface.

## TL;DR

Same shape as the other adjacent products: **they win on developer
ergonomics, we win on the security spine.** The on-device sandbox is
lighter than the libkrun SDK (no signed/audited execution, no verified
boot, no SBOM/CVE gate) but ships a tight on-device DX we should mine in
four specific places. Most of its headline features we already have, and
often with a stronger guarantee.

- **They have, we should borrow:** a **brokered `fetch_url`** agent tool
  (controlled HTTP without flipping default-deny off), **one-line MCP
  install** + ready client configs, a **published ~1s boot number** as a
  first-class metric, and a unified `--rootfs <scheme>://` quick-import
  ergonomic (weigh against hermetic-Nix).
- **We have, they don't:** signed + audited execution (claim 8),
  content-addressed signed bundles (9), default-deny egress *bound to an
  audit chain* (10) vs their bare `--net` flag, verified boot / dm-verity
  (3), app-deps SBOM+CVE+attestation (11), OCI image provenance in the
  audit chain (14), always-on seccomp `standard` + `setpriv`, the
  supervisor control socket (pause/resume/balloon/snapshot).
- **We both have, different mechanism:** OCI rootfs (theirs pull-and-cache,
  ours signed-provenance via `mvm-oci`), snapshots (theirs disk, ours
  live save/restore on macOS 14+), ephemeral fresh guest, named host
  shares.

## What the on-device sandbox offers

- **Runtime:** Rust-native VZ via `objc2-virtualization` (no Swift
  binary; C in-tree is only a cbindgen FFI header). Per-VM private serial
  dispatch queue, no run loop. ~1s local boot claimed.
- **CLI:** `--rootfs <src> --exec '<cmd>'` one-shot; `providers` to list
  rootfs sources. Flags: `--net` (default-deny egress, opt-in),
  `--mem-mib`, `--scratch <SIZE>` (ephemeral ext4 spill for a writable
  root; tmpfs overlay otherwise), `--share name=path` (virtio-fs host
  dir), `--kernel`/`--initramfs`, `--build-snapshot`/`--resume-snapshot`
  (Apple-Silicon only).
- **Rootfs providers (one `--rootfs`, four schemes):** local dir,
  `oci://`/bare `alpine:3.20`, `tar+https://`/`tar+file://`,
  `squashfs+file://`. OCI cached at `~/Library/Caches/.../oci/` (first
  pull ~30s, then ~3s). Immutable squashfs base + tmpfs overlay,
  content-addressable.
- **MCP server:** exposes `execute`, **`fetch_url`**, a `workspace_*`
  family (ephemeral per-call microVMs), and a `desktop_*` family.
  One-line install (`claude mcp add … -- <mcp-bin> --allow-network`) +
  documented JSON for several clients. `--default-image`,
  `--allow-network`.
- **Daemon:** a long-lived background service over a Unix socket, line-
  delimited JSON, streams `stdout`/`stderr`/`exit` frames — amortizes
  per-invocation cost; owns the desktop session registry.
- **Desktop / computer-use:** headless Xvfb + openbox, VNC view
  (`vnc://…`, Screen Sharing compatible), agent+human co-control,
  software-rendered, ~2 GB/session idle-evicted.
- **Embedding:** a `lib<name>.dylib` C ABI (cbindgen header) +
  `<name>_*` functions + per-provider Rust crates.
- **Exit code:** guest writes `.exit` to a host-visible path, `sync`,
  `poweroff -f`; host reads it back (`--exec 'exit 42'` → host exits 42).
- **Posture:** hardware VM + own kernel; default-deny egress *and*
  filesystem (only `--share`d dirs mount); ephemeral guest. No signed
  execution, no verified boot, no deps audit. Threat model is host-trusting,
  like ours.

## Feature gap table

| Capability | on-device sandbox | mvm today | gap → action |
|---|---|---|---|
| Brokered URL fetch for agents | `fetch_url` MCP tool | none; `--net` is all-or-nothing | **borrow** — a `host.fetch.v1` broker handler (controlled HTTP, no default-deny flip) → **Plan 104** |
| One-line MCP install + client configs | `claude mcp add …`; JSON for many clients | MCP transport exists, install DX doesn't | **borrow** — install one-liner + client config docs → **Plan 32/33** |
| Published boot-time metric | "~1s local" headline | fast-boot work exists, no published number | **borrow** — make boot latency a first-class tracked/published metric → **Plan 127** (bench), 139/118 |
| Unified `--rootfs <scheme>://` import | dir/oci/tar/squashfs in one flag | `--flake` (Nix) + `mvm-oci` | **weigh** — quick non-Nix rootfs path is nice DX but cuts against hermetic-Nix (**ADR-046**); note, don't adopt blindly |
| Guest exit-code → poweroff | `.exit` file + `poweroff -f` | reboots instead (core-demo blocker) | **already owned** → **Plan 152 WS-A** / Plan 120 |
| Rust-native VZ (no Swift binary) | `objc2-virtualization` | separate codesigned Swift supervisor | **adopting** (2026-06-04 reversal) — drop Swift, Rust-`objc2` supervisor kept as a separate process; entitled-TCB argues for separation, not Swift → **Plan 152 WS-B** |
| OCI rootfs | pull + cache, unverified | claim 14 (`mvm-oci`), signed provenance + cosign + dm-verity | **we lead** |
| Default-deny egress | bare `--net` opt-in | claim 10, **audit-bound**, ack-gated | **we lead** |
| Snapshots | disk, Apple-Silicon only | live save/restore (macOS 14+), audit-bound | **we lead** → Plan 97 E / 140 |
| Named host shares | `--share name=path` | volumes (Plan 45/132), claim-1 explicit-shares | parity |
| Ephemeral fresh guest | yes | yes | parity |
| Signed + audited execution | **no** | claim 8 | **we lead** |
| Verified boot (dm-verity) | **no** | claim 3 | **we lead** |
| App-deps SBOM/CVE audit | **no** | claim 11 | **we lead** |
| Always-on seccomp + setpriv | not advertised | claims 1/2, always on | **we lead** |
| Desktop / VNC / computer-use | full `desktop_*` surface | none, **headless by design** | **out of scope** (ADR-001) |
| C ABI embedding (a `.dylib`) | yes | none | **out of scope** — CLI + SDK is our model |
| Client daemon (amortize one-shots) | `…d` Unix-socket service | standby pool (Plan 118); serve = mvmd | parity via different mechanism |

## Recommended actions

1. **`host.fetch.v1` brokered fetch (highest value).** A destination-
   scoped, audited HTTP fetch handler on the host-services broker gives
   agents controlled egress without flipping claim 10 off — and slots
   into the existing binding-gated dispatch + audit chain (claims 12/13).
   Propose as a deferred follow-up on **Plan 104**, not here.
2. **MCP install DX.** Add an install one-liner and client config snippets
   to the MCP surface → **Plan 32/33** / docs.
3. **Boot-time metric.** Promote boot latency to a tracked, published
   number on the existing bench rig → **Plan 127**.
4. **`--rootfs` quick-import.** Open question only — record the
   hermetic-Nix tension (**ADR-046**) before anyone builds it.

Everything else is either already owned (Plan 152 WS-A, the security
claims) or out of scope (desktop/VNC, C ABI). Do not regress posture to
match the lighter model — the same conclusion the other two prior-art
docs reach.

## See also

- [`embeddable-sandbox-sdk-dx-gap-analysis.md`](embeddable-sandbox-sdk-dx-gap-analysis.md) — the libkrun embeddable-SDK reference (sibling).
- [`sandboxes-for-ai-cardoso-gap-analysis.md`](sandboxes-for-ai-cardoso-gap-analysis.md) — the Cardoso minimum-viable-policy gap analysis.
- [`../plans/152-rust-native-vz-and-init-lifecycle-parity.md`](../plans/152-rust-native-vz-and-init-lifecycle-parity.md) — the Vz-mechanism + `/init` findings this doc's features sit alongside.
- [`../plans/159-vz-inspired-macos-dx.md`](../plans/159-vz-inspired-macos-dx.md) — the vz-inspired DX/feature build-out (warm path, checkpoints/fork, self-sign) this doc's feature table feeds.
- [`../plans/104-host-services-broker.md`](../plans/104-host-services-broker.md) — owner of the `host.fetch.v1` idea.
