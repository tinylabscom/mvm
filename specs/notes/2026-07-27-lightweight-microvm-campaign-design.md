# Lightweight microVM campaign — design

**Date:** 2026-07-27
**Status:** approved design; WS-1 and the static overlay cut implemented
**Scope:** shrink the workload-guest footprint across four dimensions, gated so it
cannot silently regrow. WS-1 and the static runtime-overlay cut are implemented;
WS-2 and WS-4..6 remain named + sequenced follow-ups.

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
| B | Overlay bytes (agent + helpers) | 5.3–7.3 MiB | 32 MiB hard cap | unify on static-musl → drop the bundled glibc loader → tighten the cap |
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
- production agent still links no `do_exec` and no console symbol.
- seccomp tiers still applied per service.

## WS-1 — static setpriv, glibc out of the rootfs (implemented from this spec)

**Change.** Swap `pkgs.util-linux` → `pkgs.pkgsStatic.util-linux` at the four `setpriv`
references in `nix/lib/mk-guest.nix` (the `setprivWrap` helper plus the agent / addon-DNS /
egress-client fork sites). The static-musl `setpriv` binary's runtime closure is just
itself — no glibc — so glibc garbage-collects out of the rootfs closure.

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

**Measurement seeds the campaign.** The before/after numbers populate the scoreboard and
decide whether WS-2 (a custom helper) is worth building.

## Roadmap (named + sequenced, not built this pass)

- **WS-2 (lever E follow-up).** Custom `mvm-setpriv` static-musl helper in `mvm-agentd`,
  built through the existing guest-helper pipeline (`guest_agent_build.rs`, sibling to
  `seccomp-apply` / `netinit` / `verity-init`): implements exactly the flags above via
  `setresuid` / `setresgid` / `setgroups([])` / `prctl(NO_NEW_PRIVS)` / ambient-cap raise,
  then `execvp`. ~400 KiB, minimal attack surface, no `util-linux` build dep. Decided on
  WS-1's measurements — build it only if shaving ~1 MiB and removing setpriv's other code
  paths is worth owning a security primitive.
- **WS-3 (lever B).** Unify the overlay binaries on static-musl; drop the glibc loader /
  `libc.so.6` / `libgcc_s.so.1` bundle from `nix/images/runtime-overlay/flake.nix` `lib/`.
  Snag: `libmvm_host_services.so` (the FFI cdylib language SDKs dlopen) is glibc-built and
  lives in that same `lib/`; moving it to an SDK-workload sidecar needs its own mini-design.
  Tighten the overlay cap after.
- **WS-4 (lever D).** Add a measured guest-RSS gate (agent ≤ ~8 MB). The tokio-free agent
  already lands most of this — measurement + gate, not new architecture.
- **WS-5 (lever A/E).** Rootfs closure minimization — CA-bundle trim, kernel-module audit,
  rootfs package-count budget.
- **WS-6.** Fold the scattered budgets (rootfs / overlay / closure / kernel / RSS) into one
  `xtask perf footprint` ledger + a single doc.

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
- WS-2..6 tracked as deferred follow-ups in the implementation plan.

## Risks / open questions

- **`pkgsStatic.util-linux` build.** `setpriv` builds and runs static under musl (Alpine
  ships full util-linux on musl); confirm the derivation evaluates and the ambient-cap flags
  behave identically to the glibc build during WS-1.
- **Glibc anchor completeness.** WS-1 assumes `util-linux setpriv` is the sole glibc anchor
  in the rootfs. The closure test proves or disproves this; if another store path pulls
  glibc, it surfaces as a WS-5 item.
- **Gate scope beyond `minimal`.** Extending `rootfs-size` past the `minimal` template must
  not penalize workloads that legitimately bundle large app deps — the gate targets the
  mvm-owned base, not user payload; decide the boundary during WS-1.
