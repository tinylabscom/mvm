# Universal initramfs + vsock-activated boot — session kickoff

**Date:** 2026-07-28
**Status:** SUPERSEDED — the plan it calls for has since been written and merged.
**Successor:** `specs/plans/270-universal-initramfs-vsock-activated-boot.md` (landed
via #1903). This note took the number 269, but 269 was already taken by the
backend-shim-removal plan, so the universal-initramfs plan landed as 270; treat
every `269-universal-initramfs-*` reference below as pointing at 270.

Kept for provenance only: the design originated in a Kimi CLI session, so the
reasoning behind it is not in `~/.claude/projects` and would otherwise be lost.
Read the merged plan, not this, for what to build.

## Provenance

The design came out of a Kimi CLI session titled **"New thought"**, not a Claude Code
session — which is why it is absent from `~/.claude/projects`.

| | |
|---|---|
| Session | `dbf93c76-c828-42fc-a141-b1df05a21448` |
| Store | `~/.kimi/sessions/132ddba61eed4a5ab98281238c39de68/dbf93c76-c828-42fc-a141-b1df05a21448/` |
| Resume | `kimi-cli --resume dbf93c76-c828-42fc-a141-b1df05a21448` |
| Shape | 13 user turns, 41 assistant turns, 47 tool calls, 5 subagents |

Within that store: `context.jsonl` = model-visible turns, `wire.jsonl` = full event
stream (reasoning, tool calls, approvals, pasted images), `subagents/<id>/output` =
the worktree/branch/PR sweep. Note that `context.jsonl` **strips pasted images**; turn
7 carried a screenshot of the session sidebar that only exists in `wire.jsonl`.

Exports (durable copies): `~/work/tinylabs/mvmco/session-archive/`

Secondary input — session `27d45ee4-bdf8-4cd1-b4f0-c34961a53021` ("Continue a large
in-flight mvm session"), same store. It is fully closed out: its subject PR #1804
(OCI multi-layer unpack) merged 2026-07-25. It contributes exactly one constraint,
recorded below.

## Verified repo state (2026-07-28)

- `ActivateEnvironment` does not exist in the codebase. This plan introduces it.
- Zero open PRs.
- The three prerequisites are unmerged local worktrees: `feat/vsock-control-conformance`,
  `feat/firecracker-vsock-only-final`, `feat/hvf-converge-vsock`.
- `specs/plans/268-backend-shim-removal.md` is untracked in the main checkout alongside
  a modified `specs/SPRINT.md`. It stays a separate future workstream.
- `269` is free locally; confirm against open PRs and worktrees before claiming it.

## Kickoff prompt

Paste the block below into a fresh session.

```text
Write the universal-initramfs plan for mvm as specs/plans/269-universal-initramfs-vsock-activated-boot.md.

The design work is already done — do not re-derive it. Two prior sessions feed this:

1. PRIMARY (design): ~/work/tinylabs/mvmco/session-archive/kimi-new-thought-full.md —
   a 13-turn design conversation ("New thought"). Read it first. Its final assistant
   turn ends by proposing exactly this plan; you are writing it. Also
   session-archive/kimi-turn7-sidebar.png.
2. SECONDARY (constraint only): PR #1804 (merged 2026-07-25) landed OCI multi-layer
   unpack with prior-layer path replacement (mvm_fs unpack_layer_with_prior_paths,
   UnpackReport::paths_written). The plan must keep OCI-sourced rootfs and Nix-built
   rootfs booting through one identical path.

If the archive is gone, the source of truth is
~/.kimi/sessions/132ddba61eed4a5ab98281238c39de68/dbf93c76-c828-42fc-a141-b1df05a21448/
(context.jsonl = turns, wire.jsonl = reasoning + tool calls, subagents/ = the
worktree/branch/PR sweep).

DESIGN — settled, carry forward as-is:
- One generic mvm-agentd is PID 1. Built once per architecture at BUILD time, never
  runtime. Ships twice: in the initramfs and in the runtime overlay at /mvm/runtime/agent.
- One initramfs per (arch, agent version, kernel version), content-addressed, selected
  by hash at VM start. Its hash goes in the attestation statement — the initramfs is TCB.
- Boot sequence: generic VM boots -> agent listens on vsock -> host sends signed
  ActivateEnvironment -> agent mounts rootfs + overlay -> ready -> RunEntrypoint.
- Explicit state machine: boot -> agent-listen -> activate-environment -> ready ->
  workload. Activation after ready is a protocol error. Every transition emits a
  chain-signed audit event.
- ActivateEnvironment is bound to a unique per-microVM checksum / VM id so a valid
  frame replayed at another VM is rejected. It is the ONLY verb allowed before the
  agent drops from root to uid 901.
- Fail closed: no activation, or roothash mismatch -> time out and shut down. Never
  boot half-initialized. Boot-failure attribution must distinguish "host sent bad
  data" from "guest failed to mount".
- Mount policy: fixed order rootfs -> runtime-overlay -> custom volumes. Custom
  volumes only after ready, and NEVER able to shadow rootfs/overlay — deny-prefix set
  at minimum /, /mvm, /mvm/runtime, /dev, /dev/vda, /dev/vdc. Every mount attempt
  audited, allowed or denied. Device identifiers are passed explicitly in the
  activation command, not implied by naming.
- vsock is the only ingress/egress. Non-negotiable. No NIC, no DNS, no S3 fetch
  during activation.
- No secrets in the initramfs. Its only trust anchor is the host-signer public key.
- PID 1 duties need explicit tests: SIGTERM/SIGINT handlers (Linux ignores them for
  PID 1 by default) and zombie reaping.
- Capability negotiation: agent advertises ActivateEnvironment support; a peer that
  lacks it fails closed rather than silently skipping activation.
- Mounting logic lives in a library, not in the vsock listener.
- REJECTED, do not revisit: streaming rootfs contents over vsock.

SCOPE:
- In: FC, libkrun, HVF, mock drivers. HVF support is non-negotiable but gated on its
  existing rootfs work — coordinate, don't duplicate.
- Out: WASM backend (does not boot Linux — scope it out explicitly so nobody assumes
  otherwise). linux-in-wasm is a separate future research spike (container2wasm /
  TinyEMU), not this plan. WHP is a future note only; it conflicts with ADR-009.
- Out: the builder VM keeps its own boot path — it runs Nix, needs broad network, is
  not a workload.
- Sub-200 ms is NOT a cold-boot target. It comes from warm snapshot restore. Snapshot
  format may need to record the initramfs hash; restore must keep working.

ALSO COVER:
- VmmDriver::workload_base_bootargs shrinks to console/panic/vsock — the initramfs
  owns root/init selection. Touches all three drivers.
- MockDriver must simulate vsock + ActivateEnvironment or warm-path tests break.
- Dev console/PTY over vsock must still work with the agent as PID 1.
- Footprint: initramfs under 5-10 MiB, charged against the 50 MiB light-guest budget.
- Rollout behind a flag (old path default) until BDD + live smoke pass; version
  negotiation so a host can downgrade the agent without breaking existing snapshots.
- Bundles: initramfs may not need to ship in .mvmpkg, but compatibility range must be
  recorded.
- mvm-setpriv interaction if light-guest WS5 lands it — initramfs-available or folded
  into the agent's privilege-drop path.

CURRENT STATE (verified 2026-07-28):
- ActivateEnvironment does not exist in the codebase yet. This plan introduces it.
- Zero open PRs. The three prerequisites are unmerged local worktrees:
  feat/vsock-control-conformance, feat/firecracker-vsock-only-final,
  feat/hvf-converge-vsock. Sequence the plan behind them; say so explicitly.
- specs/plans/268-backend-shim-removal.md is UNTRACKED in the main checkout, alongside
  a modified specs/SPRINT.md. It stays a separate future workstream — reference it,
  don't absorb it.
- 269 is free locally; confirm against open PRs and worktrees before claiming it.

CONVENTIONS:
- Work in a dedicated worktree, not main.
- Plan uses - [ ] checkbox tasks with explicit files per task, like 268 does.
- Update specs/SPRINT.md in the same change.
- No Plan N / ADR-NNN / #NNNN / W# tokens in code or code comments (CI-gated); spec
  docs may use them.
- No Co-Authored-By trailer, no AI-tool attribution.

Start by reading the archived transcript and specs/plans/268-backend-shim-removal.md,
then confirm the task breakdown with me before writing the full plan.
```

## Open loop from the source session

Its last line was *"Want me to write the universal-initramfs plan next?"* — never
answered. Only the cleanup plan (268) was written. Writing 269 closes this out.
