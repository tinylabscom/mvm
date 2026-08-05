# Lightweight microVM campaign — design

**Date:** 2026-07-27
**Status:** approved design; WS-1, the static overlay cut, and the first WS-5/WS-6 gates implemented
**Scope:** shrink the workload-guest footprint across four dimensions, gated so it
cannot silently regrow. WS-1, WS-2, the static runtime-overlay cut, and the first
WS-5/WS-6 gates are implemented; the remaining WS-4..6 measurements stay sequenced.

## Problem

The workload guest is already small — a real OCI-guest `rootfs.ext4` measures ~10 MiB
and the runtime overlay 5.3–7.3 MiB on this host — but the base carries weight it does
not need. The rootfs drags the full `util-linux` package and its **glibc** closure in
solely to get `setpriv`'s `--reuid/--regid/--clear-groups`, which `pkgsStatic.busybox`'s
stripped applet lacks. glibc is also bundled into the runtime overlay (`lib/` loader +
`libc.so.6` + `libgcc_s.so.1`) even though the host build path already produces
static-musl binaries. Nothing enforces a footprint budget beyond the `minimal` template's
rootfs, so wins are not durable and there is no scoreboard to drive further cuts.

"Lightness" is not vanity: a smaller closure fetches faster, hashes fewer dm-verity
blocks, and mounts quicker — feeding the warm-start / density SLOs directly — and a
smaller package set carries fewer CVEs, strengthening the security posture. It is a lever
on speed *and* security.

## Goal

Minimize the total footprint of the **mvm-owned** base across four dimensions, each with a
CI-enforced budget that ratchets down. The workload's own libc (a Python/Node runtime, an
SDK app) stays the workload's business — this campaign makes only the base static, not user
code.

## Scoreboard (four dimensions)

| Dim | What | Measured today | Existing gate | Direction |
|-----|------|----------------|---------------|-----------|
| A | Rootfs bytes | ~10 MiB (OCI guest) | `xtask perf rootfs-size` — 20 MiB, `minimal` only | drop glibc → tighten + extend the gate beyond `minimal` |
| B | Overlay bytes (agent + helpers) | 5.3–7.3 MiB | 16 MiB hard cap | unify on static-musl → drop the bundled glibc loader → tighten the cap |
| D | Guest RSS | agent ~8 MB (goal) | none (aspirational) | add a measured gate |
| E | Attack surface | crate closure ≤266 | `xtask check-closure-budget` | drop the `util-linux` package + its CVE surface; add a rootfs-package-count assertion |

Kernel size (a fifth notion of "light") stays a referenced-but-separate program with its
own symbol budget (`xtask check-kernel-config-budget`); it is out of scope here.

## Mechanism — the ratchet

Extend the existing perf-budget system (`xtask/src/perf.rs`, `all_budgets()`) into one
footprint ledger. Each workstream lands a cut, then **tightens its own budget** so the win
is permanent. No workstream may loosen another dimension's budget. New budget `source:`
fields use concept-based labels, never plan/ADR/issue tokens (CI-gated in code).

## The spine — delete glibc from the mvm-owned base

Most of A and B collapse into one architectural theme. glibc reaches the guest via two
paths today: the rootfs `setpriv` (WS-1) and the overlay `lib/` bundle (WS-3). Remove both
and everything mvm ships in the guest becomes pure musl-static: `busybox-static` + a handful
of static helpers + config + kernel modules, with no dynamic loader and no `patchelf` step.

## Guardrails (invariants — non-negotiable)

Every cut keeps the security witnesses green. A lightness change that breaks a claim is a
regression, not a win.

- setpriv uid / group / no-new-privs drops preserved exactly (host-fs confinement; guest
  cannot elevate to uid 0).
- dm-verity roothash still seals the rootfs (tampered rootfs fails to boot).
- production-safe runs still refuse DevOnly verbs and console access through the runtime profile and signed grant.
- seccomp tiers still applied per service.

## WS-1 — static setpriv, glibc out of the rootfs (implemented from this spec)

**Change.** The first cut swapped `pkgs.util-linux` → `pkgs.pkgsStatic.util-linux` at
the four `setpriv` references in `nix/lib/mk-guest.nix`. WS-2 replaces that baseline
with the smaller static-musl `mvm-setpriv` helper.

**Faithful capability surface.** The replacement is the same `setpriv`, static-linked, so
the flag surface is preserved by construction:

- `--reuid=<uid> --regid=<uid>` — drop to the service uid.
- `--clear-groups --no-new-privs` — empty supplementary groups + `PR_SET_NO_NEW_PRIVS`.
- `--inh-caps=+net_bind_service --ambient-caps=+net_bind_service` — addon-DNS + egress-client
  only, so they can bind `:53` / `:1080` as non-root.
- `-- <cmd> [args…]` then exec.

**Lock-in (what makes this a lever, not a one-off).**

1. A `nix/tests/` eval assertion that the rootfs closure carries **no glibc** and no
   dynamically-linked `util-linux`.
2. Measure the `minimal`-guest rootfs before/after; record the byte delta and the
   closure-package delta; tighten / extend `ROOTFS_MAX_BYTES` accordingly.

**Witnesses.** Existing setpriv / uid-drop unit + conformance tests stay green (same flags),
plus the new closure assertion. WS-1 does not touch the security semantics — only the
provenance of the `setpriv` binary.

**Measurement seeds the campaign.** The before/after numbers populated the scoreboard and
justified replacing util-linux with the custom helper in WS-2.

## Roadmap (named + sequenced)

- **WS-2 (lever E).** The static-musl `mvm-setpriv` helper is implemented as a dedicated
  `mvm-agentd` binary and Nix package. It implements the exact generated flag surface via
  `setresuid` / `setresgid` / `setgroups([])` / `prctl(NO_NEW_PRIVS)` / ambient-cap
  raise, then `execvp`, with no `util-linux` build dependency.
- **WS-3 (lever B).** Unify the overlay binaries on static-musl; drop the glibc loader /
  `libc.so.6` / `libgcc_s.so.1` bundle from `nix/images/runtime-overlay/flake.nix` `lib/`.
  Snag: `libmvm_host_services.so` (the FFI cdylib language SDKs dlopen) is glibc-built and
  lives in that same `lib/`; moving it to an SDK-workload sidecar needs its own mini-design.
  The static runtime overlay is now capped at 16 MiB; automatic sidecar attachment remains.
- **WS-4 (lever D).** Add a measured guest-RSS gate (agent ≤ ~8 MB). The tokio-free agent
  already lands most of this — measurement + gate, not new architecture.
- **WS-5 (lever A/E).** Rootfs closure minimization — the module metadata audit is
  implemented; CA-bundle trim and the rootfs package-count budget remain.
- **WS-6.** The first `xtask perf footprint` ledger is implemented for the Nix-built
  rootfs, runtime overlay, and dm-verity sidecars; closure, kernel, and RSS entries
  remain for the follow-up slices.

## WS-3 — static runtime overlay

The runtime-overlay flake now instantiates every guest executable from
`pkgs.pkgsStatic` (including the runner, addon DNS, egress client, and exit reporter).
The ext4 staging step therefore copies self-contained musl binaries directly and no
longer runs `patchelf` or carries a dynamic loader, `libc.so.6`, or `libgcc_s.so.1`.

The SDK FFI is deliberately not linked into those binaries. It remains a glibc
`cdylib`, so the flake publishes it as `packages.<system>.sdk-sidecar`, containing
the FFI plus its matching loader, libc, and libgcc under `/mvm/sdk/lib`. Python
and TypeScript SDK defaults point at that sidecar mount, while
`MVM_HOST_SERVICES_LIB` remains the override for custom arrangements. The runtime-overlay attachment path must mount
the sidecar only for workloads that use host services; until that attachment is
selected, a workload must not call the SDK host-service verbs.

## Deliverables of this spec's implementation (WS-1 only)

- The `mk-guest.nix` setpriv swap.
- A no-glibc / no-dynamic-util-linux rootfs closure test under `nix/tests/`.
- Rootfs before/after measurement + `ROOTFS_MAX_BYTES` tighten/extend.
- Remaining WS-3..6 work is tracked as deferred follow-ups in the implementation plan.

## Risks / open questions

- **`mvm-setpriv` static build.** The dedicated helper must cross-build with musl and retain
  the ambient-cap behavior used by the DNS and egress helpers; the Linux execution tests
  and builder-backed Nix build are the witnesses.
- **Glibc anchor completeness.** WS-1 removed the original util-linux anchor and WS-2 removes
  the remaining util-linux dependency from the workload rootfs. The closure test proves or
  disproves that another store path pulls glibc, surfacing any remainder as a WS-5 item.
- **Gate scope beyond `minimal`.** Extending `rootfs-size` past the `minimal` template must
  not penalize workloads that legitimately bundle large app deps — the gate targets the
  mvm-owned base, not user payload; decide the boundary during WS-1.
