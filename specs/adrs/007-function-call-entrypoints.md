---
title: "ADR-007: Function-call entrypoints"
status: Proposed
date: 2026-05-04
related: ADR-002 (microVM security posture); ADR-005 (sealed signed builder image); plan 41 (function-call entrypoints implementation)
---

## Status

Proposed. Lays the substrate for `mvmforge`'s function-call SDKs
(decorationer ADR-0009, plan 0003) to wire a Modal-style
`f.remote(...)` call surface onto mvm. Adopting this ADR commits mvm
to shipping a constrained `RunEntrypoint` verb in production guest
agents — alongside, not instead of, the dev-only `do_exec` (W4.3).

## Context

Today, mvm's only path for "boot a VM and run something" is
`mvmctl exec`, which dispatches via the dev-only `do_exec` vsock
verb (`crates/mvm-guest/Cargo.toml:38` gates it behind `dev-shell`;
production builds reject all calls per W4.3 / `prod-agent-no-exec`
CI lane). That's correct for arbitrary-shell use cases — exec is
unsafe in production by construction — but it leaves no path for
production workloads that want call-and-return semantics: send args,
run a baked program, get output.

`mvmforge` (decorationer) wants to add Modal-style function calls:
decorate a Python or TS function, call it from the host, body runs
inside the microVM, return value flows back. The user's hard rule
(captured in CLAUDE.md memory) is that **everything is written at
build time, ALWAYS** — no closure shipping, no runtime registration,
no dynamic dispatch by name. The function, format, allowlist, and
wrapper are all baked into the rootfs.

This ADR decides how mvm's substrate exposes that. The key insight
is that a function call is an *implicit program*: the image bakes a
language-specific wrapper (Python/Node runner) that reads stdin,
dispatches to the IR-declared function, and writes the return on
stdout. mvm doesn't need to learn Python or TS — it needs a verb
that runs the baked program with stdin piped and stdout/stderr
captured, with all the security invariants ADR-002 demands.

## Threat model (additive over ADR-002)

The adversary set inherits ADR-002 §1: a malicious or compromised
guest workload, plus the call-payload dimension introduced here.

New threats:

1. **Hostile stdin payloads.** Caller-supplied bytes feed a
   deserializer in the wrapper. Resource exhaustion (deep nesting,
   billion laughs), code-executing decoder vulnerabilities, schema
   violations.
2. **Cross-call state leakage on warm session VMs.** Wrapper
   globals, `/tmp`, env, file descriptors persist across invocations.
   An adversary holding `mvmctl invoke` against an existing session
   sees data from prior calls.
3. **Snapshot tampering.** Warm-pool resume (and a future `--reset`
   mode) restores a Firecracker memory snapshot from disk. A swapped
   snapshot file = arbitrary code at boot, dm-verity (W3) bypassed
   because verity covers rootfs disk reads, not memory images.
4. **Logging-channel disclosure.** Default log paths capturing
   stdin/stdout content leak secrets to operator logs, captured bug
   reports, screenshots.
5. **Coredump disclosure.** Wrapper crash with core enabled writes
   in-flight payload memory to disk.
6. **Implicit network grant.** Guests with network on by default
   reach the internet, the host, or peer VMs without the IR
   declaring it — exfiltration on the day a vulnerable dep lands.
7. **TOCTOU / symlink redirection on `/etc/mvm/entrypoint`.** A file
   written at image build time but resolved at every call could
   redirect to a writable mount.

Out of scope (inherited from ADR-002): malicious host, multi-tenant
guests within one VM, microarch side channels.

## Decision

mvm ships **`RunEntrypoint`**, a vsock verb distinct from `do_exec`.
It runs *the* baked program (one per image), with stdin piped in and
stdout/stderr captured. It is the only path by which a production
guest agent will execute guest code on demand.

Concretely:

1. **Wire protocol.** `GuestRequest::RunEntrypoint { stdin: Vec<u8>,
   timeout_secs: u64 }` → `GuestResponse::EntrypointEvent(...)` where
   `EntrypointEvent` is an event-shaped enum (`Stdout`, `Stderr`,
   `Exit`, `Error`). v1 emits one `Stdout` and one `Stderr` event
   (buffered up to 1 MiB each); v2 chunks progressively without
   breaking the wire. `#[serde(deny_unknown_fields)]` on every type.
   Fuzzed (W4.2 extended).
2. **Stdin only.** No argv tail. The wrapper is built for a single
   function with a single declared payload format; argv adds a
   parallel encoding path with no benefit.
3. **`/etc/mvm/entrypoint` is the contract.** A regular file on the
   verity-protected rootfs whose content is a single absolute path
   to the wrapper binary. The agent reads it at boot, calls
   `realpath`, asserts the resolved path is on the verity partition
   under a known prefix (`/usr/lib/mvm/wrappers/`), is owned root
   (mode 0755, regular file, not setuid), and caches a held fd for
   `fexecve`-style spawn. Refuses `RunEntrypoint` if any check fails.
4. **`do_exec` stays dev-only.** Production builds gate it out with
   the existing `dev-shell` Cargo feature; `RunEntrypoint` is
   feature-independent, present in all builds. CI gate becomes
   `prod-agent-runentry-contract`: ONE binary, ONE step, asserts
   `do_exec` absent AND `RunEntrypoint` present.
5. **Caps and timeouts enforced in agent.** stdin ≤ 1 MiB v1
   (parametric in the IR up to a hard ceiling of 16 MiB); stdout
   symmetric; timeout enforced guest-side (poll-based) and host-side
   (drop after `timeout_secs * 1.2`). Cap breach kills the wrapper
   process and emits `EntrypointEvent::Error { kind: PayloadCap }`.
6. **Per-call hygiene runs from the agent, not the wrapper.** A new
   per-call `TMPDIR=/tmp/call-<uuid>` is created by the agent before
   spawn and `rm -rf`'d after the wrapper exits regardless of how
   it exited. Wrapper is re-spawned per call (process state — env,
   FDs — is fresh; warmth is in the VM page cache + loaded
   interpreter, not the wrapper process).
7. **Concurrency: serialize per-VM.** Agent holds a mutex around
   `RunEntrypoint`; concurrent callers get
   `EntrypointEvent::Error { kind: Busy }` immediately; pool grows
   warm VMs for parallelism instead of allowing intra-VM concurrency.
8. **Coredumps disabled on prod wrappers.** The Nix factory's
   wrapper template calls `prctl(PR_SET_DUMPABLE, 0)` and the init
   sets `RLIMIT_CORE=0` for the wrapper service. Dev wrappers may
   relax.
9. **Logging policy: metadata only.** Agent + mvmctl default
   logging records timestamp, workload id, exit code, duration,
   payload sizes, error kind. Never bytes from stdin/stdout/stderr.
   `MVM_LOG_PAYLOADS=1` is dev-only and refused if
   `/etc/mvm/variant` reads `prod`.
10. **Snapshot integrity: HMAC-keyed.** Each Firecracker snapshot
    pair (state file + memory image) is HMAC-signed at create-time
    using a host-local key at `~/.mvm/snapshot.key` (mode 0600,
    generated on first run). Restore verifies; mismatch refuses.
    Snapshot dir is mode 0700 (W1.5). Atomic create via
    write-then-rename.
11. **Network defaults flip to deny for function workloads.** Today's
    mvmforge `network.mode` defaults are too permissive; in this
    layering, function-entrypoint workloads default to
    `network.mode = "none"` (no TAP, no DNS, no default route, no
    bridge MAC learning). Explicit IR declaration grants network.
    See ADR-0009 (decorationer) for the IR-side surface; mvm honors
    whatever the IR plumbs through.
12. **Per-language seccomp tiers.** mvm exposes a tier-loading
    mechanism (already W2.4); language-specific tiers
    (`standard-python`, `standard-node`) live in mvmforge's Nix
    factories. mvm just takes a tier name from the manifest and
    applies it.

## Invariants

- The prod guest agent contains `RunEntrypoint` and does not contain
  `do_exec`; the combined `prod-agent-runentry-contract` CI gate
  asserts both on the same binary that ships.
- `/etc/mvm/entrypoint` resolves to a file on the verity partition
  under `/usr/lib/mvm/wrappers/`, owned root, mode 0755, regular
  file, not setuid. The agent caches a held fd at boot and uses it
  for `fexecve`; it does not re-open per call.
- `RunEntrypoint` runs only the baked entrypoint. There is no argv
  override, no shell, no env injection beyond what the wrapper
  template defines.
- stdin/stdout caps and call timeouts are enforced; cap breach kills
  the wrapper and poisons the session VM.
- One in-flight `RunEntrypoint` per session VM.
- Coredumps are disabled on prod wrappers via `PR_SET_DUMPABLE=0` +
  `RLIMIT_CORE=0`.
- Default logs do not contain stdin/stdout/stderr content.
- Firecracker snapshots are HMAC-verified on restore.
- Function-entrypoint workloads default to `network.mode = "none"`;
  any network grant is IR-declared. Implicit grants are forbidden.
- Per-call TMPDIR cleanup runs from the agent regardless of wrapper
  exit path.

## Consequences

Benefits:

- A clean, prod-safe path for function-call workloads. mvmforge
  builds Modal-class ergonomics on this; mvm stays language-agnostic.
- Mental hygiene: `mvmctl exec` (dev, arbitrary shell) and
  `mvmctl invoke` (prod, baked entrypoint) are visibly different
  surfaces with different CI gates and different security postures.
- Streaming-shaped wire from v1 means LLM/long-tail workloads don't
  force a future protocol break.
- Network deny-default fixes a long-standing implicit grant.

Costs:

- Adds a new vsock verb and CI lane. Modest surface, but real.
- Snapshot HMAC adds a host-local secret (`~/.mvm/snapshot.key`) and
  a verify step on every resume. ~µs cost; key rotation is a
  follow-up question.
- Network deny-default is a backward-incompatible flip for any
  workload that relied on the implicit grant. Function entrypoints
  are new, so no existing workloads break — but the same flip should
  propagate to all workload kinds eventually, which is a separate
  decision.
- Per-language seccomp tiers add review surface in the Nix factory.

Risks:

- HMAC key compromise on the host = snapshot integrity gone. Same
  threat as compromising the host generally; acceptable per
  ADR-002's "malicious host out of scope" carve-out.
- Wire-format ossification. The `EntrypointEvent` enum needs to
  cover streaming, partial errors, and back-pressure cleanly enough
  that v2 doesn't break v1 callers. Addressed via
  `deny_unknown_fields` plus deliberate v2 design.

## Implementation Impact

See plan 41. Files touched:

- `crates/mvm-guest/src/vsock.rs` — `RunEntrypoint` request,
  `EntrypointEvent` response, `RunEntrypointError` enum, roundtrip +
  tampered-frame tests.
- `crates/mvm-guest/src/bin/mvm-guest-agent.rs` — handler. Reads
  `/etc/mvm/entrypoint` at boot, validates, caches fd, dispatches
  with caps, mutex, per-call TMPDIR cleanup.
- `crates/mvm-guest/fuzz/` — fuzz targets for new types.
- `crates/mvm-cli/src/commands/vm/invoke.rs` (new) — `mvmctl invoke`
  CLI verb; reuses session-VM primitives in
  `crates/mvm-cli/src/exec.rs`.
- `crates/mvm-runtime/src/vm/microvm.rs` — snapshot HMAC at
  create/restore; key handling.
- `crates/mvm-cli/src/commands/ops/doctor*` — verify
  `/etc/mvm/entrypoint` contract live; verify snapshot dir mode.
- `.github/workflows/ci.yml` — `prod-agent-runentry-contract` lane.
- mvmforge side: ADR-0009 + plan 0003 cover wrapper templates,
  per-language seccomp tier files, IR network field changes.

## Validation

- `cargo test --workspace` covers wire roundtrip, tampered-frame
  rejection, agent handler unit tests with a fake
  `/etc/mvm/entrypoint`, snapshot HMAC create+verify+tamper.
- Vsock fuzz lane extended; runs in CI per W4.2.
- `prod-agent-runentry-contract` CI lane: builds the prod agent
  once, asserts `do_exec` symbol absent AND `RunEntrypoint` present
  on the same binary; pipes that binary forward to the release-image
  step so nothing else can be substituted.
- Integration test: build a fake "echo function" rootfs, run
  `mvmctl invoke` with stdin, assert stdout. Run on Linux/KVM CI
  (vsock unsupported on Lima/QEMU per known pitfall).
- `mvmctl doctor` reports live posture: entrypoint contract, snapshot
  dir mode, network mode for any running VM.

## Out of scope

- Multi-tenant guests within one VM (ADR-002).
- Authenticated invoke from non-local callers — vsock socket mode
  0700 (W1.2) gates to local user; cross-host authn is mvmd's
  problem.
- Closure shipping at call time. Forbidden by the build-time-everything
  rule and by ADR-0009 invariants.
- Code-executing serializer formats. Forbidden by ADR-0009;
  serialization format is a closed enum at the IR level.
- Pool sizing / eviction / per-tenant isolation. Tracked separately
  in a future session-pool plan; this ADR pre-bakes the invariant
  *single-tenant for lifetime*.
- SLSA-style attestation of mvmforge artifacts. Future follow-up;
  v1 leans on reproducibility (W5.3) + dm-verity (W3).

## Supersedes

None.

## Superseded By

None.
