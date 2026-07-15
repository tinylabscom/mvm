# ADR-005: `RunEntrypoint` — the production call-and-return verb

## Status

Accepted

## Context

The only production-safe way to run guest code today is `do_exec`, an
arbitrary-shell vsock verb that is compiled out of every non-dev build
(claim 4). That is correct for interactive/dev use, but it leaves no path
for a production workload that just wants call-and-return semantics: send
a payload, run the one program the image was built for, get the result
back.

A function-call workload is not an arbitrary program — it is an *implicit*
one. The image bakes a single language-specific wrapper that reads a
payload from stdin, dispatches to the declared function, and writes the
result to stdout. The guest agent does not need to understand Python or
Node; it needs a verb that spawns the one baked program with stdin piped
in and stdout/stderr/control output captured, under the same confinement
every other guest service gets.

## Decision

### The verb

`GuestRequest::RunEntrypoint { stdin, timeout_secs }` is a `ProdSafe` vsock
verb, present in every guest agent build. The response is a stream of
`EntrypointEvent`s — `Stdout`, `Stderr`, `Control`, and the terminal
`Exit`/`Error` — read by the host in a loop until a terminal event. v1
buffers each stream fully; the wire shape already supports progressive
chunking without a protocol break. There is no argv tail: the wrapper is
built for one function with one declared payload shape, so stdin is the
only input channel.

`do_exec` stays gated behind the `dev-shell` Cargo feature and is absent
from every production agent binary; `RunEntrypoint` is feature-independent
and present in both. A production agent binary is asserted to carry
`RunEntrypoint` and not carry `do_exec` from the same build artifact.

### The entrypoint contract

`/etc/mvm/entrypoint` is a regular file on the verity-protected rootfs
whose content is a single absolute path to the wrapper binary. The agent
reads it at boot, resolves it, and refuses `RunEntrypoint` unless the
resolved path lives under `/usr/lib/mvm/wrappers/` on the same filesystem,
owned root, mode 0755, not setuid. A missing or invalid entrypoint fails
every subsequent call closed rather than falling back to any other
program.

### Baking the wrapper

`mkFunctionService` in `nix/lib/factories/` is the one generic Nix factory
for function-call images. It dispatches on a `language` input to a
registry under `nix/lib/factories/languages/` that currently carries
Python and Node entries (each bakes its interpreter package plus the
wrapper from `nix/wrappers/<language>/`); a WASM entry is not yet
registered. `mkFunctionWorkload` is the one-call helper that reads a
workload IR file, composes the factory with `mkGuest`, and returns the
rootfs derivation directly for the common single-app case;
`mkFunctionService` remains the composition point for anything more
custom.

### Caps, timeouts, and per-call hygiene

The agent enforces stdin/stdout size caps and a call timeout independent
of the wrapper. A cap or timeout breach kills the wrapper's process group
and reports `EntrypointEvent::Error`. Every call gets a fresh, agent-owned
`TMPDIR` under `/tmp`, removed on drop regardless of how the call ended.
`RLIMIT_CORE=0` is set on the agent itself so every spawned worker
inherits a disabled coredump — a wrapper crash never writes in-flight
payload memory to disk.

### Concurrency: a warm worker pool, not one shot per VM

The agent maintains a pool of warm wrapper processes rather than
respawning cold per call. A call binds to an available worker over a
length-prefixed JSON pipe (`WorkerCallRequest`/`WorkerCallResponse`); when
every worker is busy, additional callers queue FIFO up to a configured
depth and receive `EntrypointEvent::Error { kind: Busy }` once that depth
is exceeded, rather than blocking indefinitely. Parallelism comes from
pool sizing and warm-VM count, not from concurrent calls inside one
worker.

### The control channel

`EntrypointEvent::Control` and the worker pipe's `WorkerCallResponse.controls`
field carry structured records (error envelopes, captured logs) that user
code writing to stdout/stderr cannot spoof — the wrapper writes them on a
channel stdout/stderr never touches. **This is a shipped wire shape ahead
of its emitter**: the variant and the field exist and round-trip today,
but the in-tree Python and Node wrappers do not yet emit control records,
so `controls` is empty on real calls until that wiring lands.

### Session surface

`mvmctl session` exposes `ls`, `info`, `kill`, `set-timeout`, `start`,
`attach`, `exec`, `run-code`, `console`, and `reap`. `start` boots a
microVM and registers a session without dispatching into it; `attach`
re-attaches a fresh client and dispatches a `RunEntrypoint` call — the
mechanism behind the SDK's `Session.attach()`. `exec` (arbitrary shell)
and `run-code` (interpreted by the wrapper's runtime) are refused outright
on a session that was not started in dev mode; the session's mode is
fixed at start time and checked before dispatch, not left to the caller.
Every verb emits its own `LocalAuditKind` (`SessionAttach`, `SessionExec`,
`SessionRunCode`, …).

### Snapshot integrity

A Firecracker snapshot's memory image is a separate trust path from the
dm-verity-protected rootfs disk. Every snapshot pair is HMAC-SHA256'd at
create time using a host-local key generated on first use
(`~/.mvm/snapshot.key`, 32 random bytes, mode 0600), with the digest
recorded in a versioned `integrity.json` sidecar written atomically.
Restore recomputes and compares; a mismatch refuses the resume.

### Network defaults to deny for function workloads

A function-call workload's IR validation forbids `network.mode = "host"`
outright and treats an absent network declaration as deny-all — a
function entrypoint gets no egress, no DNS, and no route unless the
workload explicitly declares a network mode and (for anything beyond
`none`) a granular egress allowlist.

## Consequences

- Production workloads get call-and-return semantics without touching the
  dev-only shell path: `mvmctl exec`/`do_exec` and `mvmctl session
  exec`/`run-code` are visibly dev-gated, `RunEntrypoint` is the only verb
  a sealed prod agent answers for guest-code execution.
- The warm worker pool means a call's latency is dominated by pool
  availability, not by cold-spawning an interpreter per call; the cost is
  a FIFO queue and `Busy` responses under load rather than unbounded
  concurrency inside one VM.
- The control channel is deliberately future-shaped: hosts can already
  deserialize `Control` events safely, so wiring a real emitter into the
  wrapper templates is additive, not a protocol break.
- Snapshot HMAC adds a host-local secret and a verify step on every
  restore; compromise of that key is equivalent to a compromised host,
  which is out of scope per the standing threat model.
- The single generic `mkFunctionService` factory plus a language registry
  means adding a language is a registry entry, not a new factory; WASM
  support is an open registry slot, not yet decided between a tagged
  `wrapperKind` and a sibling factory.
