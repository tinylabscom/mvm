---
title: Lifecycle matrix
description: Current CLI and SDK support for sandbox create, command, file, log, network, snapshot, cold, and cleanup operations.
---

This page is the parity checkpoint for runtime lifecycle APIs. It separates
what is available through the local CLI today from what the Python and
TypeScript SDKs expose today and what remains a target for product-level SDK
parity.

Use it when deciding whether to write an SDK script, call `mvmctl` directly, or
keep a workflow documented as planned.

## Status terms

| Status | Meaning |
| --- | --- |
| Shipped | Usable in the named surface today. |
| Partial | Usable for a narrower path; read the notes before depending on it. |
| Target | Product shape we want, but not shipped in that SDK surface. |
| Not claimed | Deliberately outside the current surface. |

## Lifecycle support

| Operation | CLI | Python SDK | TypeScript SDK | Notes |
| --- | --- | --- | --- | --- |
| Create named sandbox | Shipped | Partial | Partial | SDK live mode calls `mvmctl machine run`; record mode records `Sandbox.create(...)`. |
| One-shot run | Shipped | Target | Target | `mvmctl run -- <cmd>` is current; SDK convenience helpers should preserve receipts and policy. |
| Start command | Shipped | Partial | Partial | SDK exposes `commands.start(...)`; result capture is still a target. |
| Command result capture | Shipped | Target | Target | CLI one-shot JSON/receipt paths exist; SDK `commands.run(...)` result shape is a target. |
| File write | Shipped | Shipped | Shipped | SDK supports `files.write(...)`; live mode shells to `mvmctl machine fs write`. |
| File read/list/remove | Shipped | Target | Target | CLI filesystem verbs exist; SDK wrappers need shared tests. |
| Logs | Shipped | Target | Target | SDK log helpers should keep payload redaction rules explicit. |
| Port forwarding | Shipped | Target | Target | SDK helpers should require explicit host and guest port binding. |
| Snapshot save/restore | Shipped | Target | Target | Backend behavior differs; SDK type model needs to expose that. |
| Cold mode | Shipped | Target | Target | SDK should make running, cold, restoring, stopped, and destroyed states explicit. |
| Stop/down | Shipped | Partial | Partial | Python context managers, TypeScript `using`, and explicit `kill()` clean up live sandboxes. |
| Destroy/delete state | Shipped | Target | Target | Strong deletion guarantees depend on backend and storage layer. |
| Detach/keep alive | Shipped for selected CLI flows | Target | Target | SDK detach must bind owner, TTL, and cleanup semantics. |
| Receipts and audit IDs | Shipped | Target | Target | SDK result objects should expose run/audit correlation without exposing payloads. |

## Recommended surface by workflow

| Workflow | Use today | Why |
| --- | --- | --- |
| Generated code execution | `mvmctl run --profile restrictive --receipt ...` | Mature policy and receipt path. |
| Local SDK smoke script | Python or TypeScript `Sandbox.create(...)` in record mode | Produces Workload IR without booting a VM. |
| Live SDK experiment | `mvmctl run --mode live ./script.py` or `.ts` | Exercises current live transport and cleanup helpers. |
| Deployable workload declaration | Static declaration workflow | Avoids importing user modules during compile. |
| Persistent service | `mvmctl build`, `mvmctl machine run`, `mvmctl machine logs`, `mvmctl machine stop` | CLI has the broadest lifecycle coverage today. |
| Cold recovery test | `mvmctl pause/resume` or `mvmctl checkpoint create/restore` | Backend-specific state handling is visible. |

## SDK parity rules

Runtime SDK parity should not mean hiding security detail behind a short method
name. New SDK helpers should preserve these invariants:

- every created sandbox has a cleanup story: context manager, `using`, explicit
  stop, TTL, or detach;
- command results include exit status, timeout state, bounded output, and
  audit/run correlation when available;
- file APIs reject traversal and make host/guest boundaries explicit;
- port helpers require explicit bindings and policy;
- snapshot and cold-mode helpers label sensitive state and backend limitations;
- errors distinguish policy denial, timeout, transport failure, and guest
  command failure;
- receipts remain verifiable outside the SDK process.

## What to implement next

The next SDK work should close the highest-value gaps in this order:

1. `commands.run(...)` with typed result, timeout, bounded output, and receipt
   correlation.
2. `files.read/list/remove(...)` with path validation tests.
3. `logs(...)` with redaction and bounded streaming.
4. Declarative `network.ports` ingress with explicit policy.
5. `snapshot(...)`, `cold()`, `resume()`, `destroy()`, and `detach()` with
   backend-aware state types.

Each item needs Python and TypeScript fixture parity before the docs move it
from Target to Shipped.

## Related pages

- [Runtime SDK](/sdk/runtime/)
- [Runtime modes](/sdk/runtime-modes/)
- [Lifecycle states](/working/lifecycle-states/)
- [Operations cookbook](/sdk/operations-cookbook/)
- [Sandbox management](/working/sandbox-management/)
- [Audit and receipts](/guides/audit-and-receipts/)
