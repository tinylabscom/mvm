---
title: Lifecycle states
description: Running, stopped, paused, cold, restoring, and cleaned sandbox states.
---

Sandbox lifecycle is a product-level contract. Backends implement it with
different primitives, but the user-facing states should stay explicit so
automation can decide when compute is active, when state is sensitive, and when
cleanup is still required.

The names below are the product vocabulary, not machine-readable status values.
The status a local machine actually reports is one of `Starting`, `Running`,
`Stopped`, `Paused`, `Failed`; a fleet instance reports one of `Created`,
`Ready`, `Running`, `Warm`, `Sleeping`, `Stopped`, `Destroyed`. Neither enum
has a `Cold`, `Restoring`, `Cleaned`, `Built`, or "No image" value — do not
match on those strings.

Most of the `machine <verb>` commands in the tables below (`wait`,
`boot-report`, `fs`, `pause`, `resume`, `checkpoint`, `sandbox`) are hidden
advanced operations: they work, but they do not appear in
`mvmctl machine --help`.

## State model

| State | What it means | Common next action | Security note |
| --- | --- | --- | --- |
| No image | No build artifact exists for the workload yet. | `mvmctl machine build` | Build inputs still need policy and secret review before launch. |
| Built | A launchable artifact exists, but no sandbox is running. | `mvmctl machine run` or `mvmctl run` | Artifact metadata can reveal package, path, and configuration choices. |
| Starting | The backend is creating the VM, attaching drives, and waiting for readiness. | `mvmctl machine wait` or `mvmctl machine boot-report` | Admission failures should be reported without leaking secrets. |
| Running | Guest compute is active and can execute commands, expose ports, write files, and emit logs. | `mvmctl machine exec`, `mvmctl machine logs`, `mvmctl machine fs`, `mvmctl machine stop`, or snapshot commands | Treat command output, files, logs, ports, and receipts as boundary-crossing data. |
| Paused | Guest execution is suspended and can be resumed by the backend path that created the pause. | `mvmctl machine resume` | Paused memory can contain tokens, browser sessions, plaintext files, and process state. |
| Cold | Compute is released while recoverable state is retained through a backend snapshot or checkpoint. | `mvmctl machine resume` or `mvmctl machine checkpoint restore` | Cold state is persistence, not a security boundary. Protect it like sensitive data. |
| Restoring | The backend is loading saved state and re-establishing runtime control. | Wait for readiness, then verify workload health | Restore can fail because of backend, host, image, or policy drift. |
| Stopped | Guest compute is no longer running, while build artifacts, logs, receipts, volumes, or snapshots may remain. | `mvmctl machine run`, `mvmctl machine sandbox gc`, or `mvmctl env cleanup` | Stop is not erase. Review retained state before reusing or sharing the host. |
| Cleaned | Local registry entries and selected generated state have been removed by cleanup commands. | Rebuild from source if needed | Strong erasure depends on filesystem, volume, snapshot, and cache behavior. |

## Command map

| Transition | CLI surface |
| --- | --- |
| Source to image | `mvmctl machine build` |
| Image to running sandbox | `mvmctl machine run` or `mvmctl run` |
| Wait for readiness | `mvmctl machine wait`, `mvmctl machine boot-report` |
| Run work | `mvmctl machine exec`, `mvmctl machine fs`, `mvmctl machine logs`; ingress is declared at boot with `mvmctl machine run --port HOST:GUEST` |
| Running to paused or cold | `mvmctl machine pause`, `mvmctl machine checkpoint create` |
| Paused or cold to running | `mvmctl machine resume`, `mvmctl machine checkpoint restore` |
| Running to stopped | `mvmctl machine stop` |
| Remove retained local state | `mvmctl machine sandbox gc`, `mvmctl env cleanup`, snapshot and volume cleanup commands |

## Backend behavior

Lifecycle names are shared across the product, but the implementation varies:

- Recovery is backend-specific: live-memory restore, machine-state restore,
  disk-only CoW warm start, standby, and cold boot are separate capabilities.
- `mvmctl doctor` is authoritative for the selected backend; an unsupported
  request fails with an actionable error rather than falling back to another
  tier.
- Pool-backed flows may sleep an instance internally, but public docs should
  still describe the user-facing CLI state rather than provider internals.

SDKs should expose these states directly instead of hiding backend differences.
When a backend cannot restore a state, the SDK should return a typed capability
or restore error rather than silently falling back to a fresh VM.

## Security rules

- Treat snapshots, machine-state files, logs, receipts, copied files, and
  volumes as sensitive artifacts.
- Do not assume `down` or cleanup commands securely erase guest memory, disk
  blocks, host caches, or external copies.
- Require explicit retention decisions for browser sessions, credentials,
  agent workspaces, and long-running service data.
- Keep restore failures observable without printing secrets from guest state or
  host configuration.
- Make detach, pause, cold, and restore policies visible in automation so a
  sandbox cannot quietly outlive its owner or intended TTL.

## Related pages

- [Sandbox management](/working/sandbox-management/)
- [Persistence, pause & resume](/working/persistence/)
- [Cold mode](/working/cold-mode/)
- [Snapshots](/working/snapshots/)
- [Lifecycle matrix](/sdk/lifecycle-matrix/)
