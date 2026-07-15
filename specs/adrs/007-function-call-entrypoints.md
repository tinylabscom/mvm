---
title: "ADR-007: Function-call entrypoints"
status: Proposed
date: 2026-05-04
related: ADR-002 (microVM security posture); ADR-005 (sealed signed builder image); plan 41 (function-call entrypoints implementation)
---

> **Consolidation:** ADR-007 is the **canonical** function-entrypoints ADR. An earlier draft of this note anticipated consolidating ADR-008 + ADR-010 (function-service-factories — a duplicate-numbered pair) and ADR-011 (entrypoint control protocol) with physical archival to `archive/adrs/`; that specific mechanism was never carried out at the time. A later ADR-wide consolidation pass completed the merge for real: ADR-008, ADR-010, ADR-011, and ADR-039 (runtime overlay composition) are folded into this document below (their content is removed from the tree, retrievable via git history, not moved to a separate archive directory). The dev-only fd-3 control channel stays compiled out of prod (claim 4).

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
- `crates/mvm/src/vm/microvm.rs` — snapshot HMAC at
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
  `mvmctl invoke` with stdin, assert stdout. Runs on Linux/KVM CI
  via the Firecracker backend, and on macOS dev hosts via the
  libkrun backend (ADR-005); both expose vsock natively.
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


## Consolidated from ADR-010 — Per-language function-service factories live in mvm.lib

## Status

Proposed. Counterpart to mvmforge ADR-0010 §3 (amended 2026-05-06,
Option A), which states the factories live in mvm. This ADR records
the substrate-side commitment.

## Context

Per ADR-007, function-call entrypoints are a first-class workload
shape in mvm. mvmforge generates the artifacts (`flake.nix`,
`launch.json`, source bundle) that `mvmctl up` consumes for these
workloads. Today mvmforge also ships the Nix factories that bake
per-language wrappers into the rootfs
(`mkPythonFunctionService.nix`, `mkNodeFunctionService.nix`,
`mkWasmFunctionService.nix` at `mvmforge/nix/factories/`). The
wrappers implement a wire contract (single-shot respawn, structured
error envelope, decoder hardening, payload caps) that lives next to
`mvmctl invoke`'s side of the same protocol.

The factories belong with the substrate, not with the SDK. The wrapper
contract is the substrate's contract. Putting the factories on the
mvm side gives:

- **User-visible artifacts contain zero internal-toolchain files.**
  Today's generated `flake.nix` imports `./nix/factories/...`; under
  this ADR it references `mvm.lib.<system>.mk<Lang>FunctionService`.
- **Single source of truth for wire contract.** Wrapper invariants
  (single-shot respawn, envelope marker, decoder hardening, payload
  caps) live next to `mvmctl invoke` in mvm.
- **mvm version pin = wrapper version pin.** Upgrading mvm upgrades
  wrappers atomically.

## Decision

Expose three new attributes on `mvm.lib.<system>` for each supported
arch (`x86_64-linux`, `aarch64-linux`):

- `mkPythonFunctionService`
- `mkNodeFunctionService`
- `mkWasmFunctionService`

Each accepts the args specified in
`mvmforge/specs/contracts/mvm-mkfunctionservice.md` and returns the
record `{ extraFiles, servicePackages, service }`. The contract is
the binding interface; mvm guarantees backward compatibility under
the schema-version rules in ADR-007.

The factories live at `mvm/nix/lib/factories/` (mirroring the
existing `mvm/nix/lib/minimal-init/` precedent). They are exposed
from `outputs.lib.<system>` in `nix/flake.nix`.

The wrapper templates that the factories reference live at
`mvm/nix/wrappers/` (per Plan 49 — wrapper relocation).

## Invariants

- The `{ extraFiles, servicePackages, service }` return shape is
  versioned by the contract document
  (`mvmforge/specs/contracts/mvm-mkfunctionservice.md`), not by
  independent ADR. Breaking changes require a contract revision
  (mvmforge cross-repo coordination).
- The factory's `service` attribute composes into `mkGuest`'s
  `services` attrset using the existing merge semantics (caller-wins
  per-service).
- Per-call hygiene (fresh subprocess per call, env baseline, FD
  reset, per-call TMPDIR, cleanup) is the substrate's responsibility,
  encoded in the factory output and enforced by the `mkGuest`-emitted
  init.
- Function-service factories return a **different** shape from
  existing service factories (`mkPythonService`, `mkNodeService`,
  `mkStaticSite`) which return `{ package, service, healthCheck }`.
  The two surfaces remain side by side; no migration of the existing
  factories.
- `mvmctl doctor` grows a check that asserts the factory symbols are
  exposed — protects against accidental removal during refactors.

## Consequences

- mvmforge's bundled factory copies (`nix/factories/`) become dead
  code once `flake.lock` here bumps. mvmforge's cleanup PR (cross-
  repo plan §F) deletes them.
- New surface area on `mvm.lib`: any future per-language factory
  (e.g. `mkRustFunctionService` if function-entrypoint Rust support
  lands per mvmforge ADR-0015's deferred work) lives here too.
- Contract drift risk: the binding contract is on mvmforge's side
  (`mvm-mkfunctionservice.md`). When that contract is revised,
  mvm's factories must update in lock-step. CI lanes on both sides
  should fail-closed on divergence — proposed: a CI job that
  fetches the contract file and asserts the mvm factories' arg
  shape matches.
- **Out of scope:** Rust function-service support (deferred);
  migration of existing service factories (no migration — the two
  surfaces coexist).


## Consolidated from ADR-011 — Function-entrypoint runtime control protocol — fd-3, session attach, dev verbs

## Status

Proposed. Largest substrate change in the upstream coordination
workstream.

## Context

The function-entrypoint wire contract (ADR-007 + mvmforge ADR-0009)
currently relies on stderr scanning for a `MVMFORGE_ENVELOPE: {...}`
marker to convey structured errors from the in-VM wrapper to the
host. User code can print this marker on stderr and forge errors —
documented in mvmforge plan-0010 §B4. The fix is a separate fd-3
control channel.

Concurrently, mvmforge's typed `Session` class wants three
operations the substrate doesn't yet expose: `attach` (re-attach a
fresh client to a warm session), `exec_cmd` (run an ad-hoc command),
and `run_code` (run an ad-hoc code snippet). The latter two are
dev-only; production sessions never open them.

The fd-3 channel and the new session verbs share the same wire path
(`mvmctl invoke` extended with a control fd; `session attach`
reuses the dispatch loop) and so are decided together.

## Decision

### fd-3 control channel

Extend `mvmctl invoke`'s vsock protocol so the agent's wrapper
writes:

- **User stdout/stderr to fd 1/fd 2 unmodified**.
- **Structured control records to fd 3** (inherited from parent via
  `pass_fds` / `RawFd`).

Frame format on fd 3: length-prefixed records, each with a small
JSON header followed by raw bytes. Header schema:

```json
{ "stream": "envelope" | "log_out" | "log_err",
  "len": <u32>,
  "ts_ns": <u64> }
```

Bytes follow the header. The full record framing is
`<header_len:u32_le><header_json><payload_len:u32_le><payload_bytes>`,
chosen so the host can read deterministically without parsing JSON
to find boundaries.

The wrapper emits exactly one `envelope` record on error (replacing
today's `MVMFORGE_ENVELOPE:` stderr scan) and zero or more `log_*`
records when `capture_logs=true` is set in
`/etc/mvm/wrapper.json`. The host parses fd 3 in a dedicated
reader; user stdout/stderr can never impersonate the control
channel.

### `session attach`

`mvmctl session attach -- <session-id>` connects a fresh client to
an existing warm session and dispatches one or more invokes against
it.

**Trust model:** session ids are trusted within the local-machine
substrate boundary — anyone with filesystem/process access to the
control socket already has equivalent privileges. Cross-host attach
requires authentication, which is mvmd's concern, not mvm's.

**Implementation:** `attach` reuses the existing
`dispatch_in_session(session_id, ...)` runtime primitive in
`crates/mvm/src/vm/lifecycle.rs`. It does not boot a new
VM, does not increment a refcount that would prevent teardown, and
does not modify the session's idle-timer.

### Dev-only `session exec` and `session run-code`

`mvmctl session exec -- <session-id> [--] <command> [args...]` and
`mvmctl session run-code -- <session-id> <code>` run ad-hoc
operations against a warm session. These verbs are **refused unless
the session was started with `mode=dev`** (per mvmforge ADR-0009's
two-mode wrapper config). On a `mode=prod` session, both verbs
return non-zero with a structured envelope `kind="session-not-dev"`.

The session's mode is fixed at session-start time and recorded in
the session registry. Verbs check the registry before dispatch.

## Invariants

- fd 3 is **never** allocated for non-function-entrypoint
  invocations — legacy command-entrypoint workloads see exactly the
  same I/O topology they see today (stdin/stdout/stderr only).
- The fd-3 reader has a hard cap on cumulative log bytes per
  invocation (default 1 MiB; configurable via wrapper config). Beyond
  the cap, the wrapper emits a single truncation record and stops.
- `session attach` from a fresh process must dispatch a call against
  a session started by another process (cross-process session id is
  the contract).
- `session exec` and `session run-code` on a `mode=prod` session are
  **hard refusals at the substrate layer** — not gated on client-side
  checks alone. Production sessions never grant these capabilities.
- Audit emit: `session attach`, `session exec`, `session run-code`
  each get their own `LocalAuditKind` variant
  (`SessionAttach`, `SessionExec`, `SessionRunCode`). `attach` is
  recorded even for read-only invokes because it's a session-state
  observation worth auditing.
- `#[serde(deny_unknown_fields)]` on every new vsock type (W4
  invariant). Fuzz corpus extended with `ControlRecord` shapes.

## Consequences

- The wrapper templates (Plan 49) need a parallel update to write
  control records to fd 3 instead of stderr-scanning. Coordinated
  with mvmforge's cleanup PR for the host-side reader.
- **Spoof-attempt regression test:** a function that prints
  `MVMFORGE_ENVELOPE: {...}` to stderr is **not** treated as an
  envelope by the host; the literal bytes appear in captured logs
  and the call returns the function's actual value.
- **New attack-surface review.** fd 3 is a privileged channel from
  the guest's perspective. The agent must treat fd-3 framing as
  untrusted-input deserialization (same `deny_unknown_fields`
  posture as the rest of the vsock protocol per W4).
- Backward-compat fallback: if fd 3 is not opened by the parent
  (legacy invoke), wrappers fall back to stderr-marker behavior.
  Lets old hosts keep working until they upgrade.
- **Out of scope:** cross-host `session attach` (mvmd's concern),
  session mode change after start (rejected — mode is fixed at
  session-start), fd-3 for non-function-entrypoint invocations.

## Pushback opportunities

- **fd-3 frame format.** mvmforge plan-0010 §B4 sketches "len:bytes"
  with JSON headers. The format above is more concrete; confirm with
  mvmforge before locking in.
- **session-info JSON schema** (plan 51, related). Surface a draft
  and ask mvmforge for sign-off.
- **Temp-dir layout** for archive extraction (plan 50, related).
  Document on the substrate side and ask mvmforge to reference.


## Consolidated from ADR-039 — Runtime overlay composition — transparent dev-rich vs prod-slim images

## Status

Proposed. Implementation sequenced in plan 61.

## Context

Two features need to coexist:

1. **A slim, secure production rootfs** — minimal attack surface, dm-verity-able, signed, hash-stable, suitable for the seven security claims of ADR-002.
2. **A fully-featured dev experience** — bash, coreutils, debugging tools (strace, tcpdump, gdb), interactive shell, the things a developer expects when they `mvmctl dev` into a microVM.

Post-Lima (ADR-005), `mvmctl dev` boots a real microVM via apple-container (macOS 26+) or libkrun (Linux). So whatever tools the developer uses live *inside* a microVM. The question is **how to put them there without compromising claim #1**.

User constraint, stated explicitly: "the tooling needs to be transparent to the user. This library/repo should be able to determine what needs to be in the binary in which what context the user is operating in." This rules out:

- A `debugTools = "basic" | "full"` knob on `mkGuest` — pushes the choice onto the user.
- A `.dev` flake output convention alongside `.default` — same problem.
- Per-purpose catalog entries (`foo`, `foo-dev`) — user-visible variant taxonomy.
- mvm rewriting / extending the user's flake at evaluation time — slow, brittle (Nix surprises), ties debug freshness to user `nix build`.

The "rootless vs busybox containers" framing the question began with is a category error: every mvm image is already rootless-by-construction (W2.1–W2.4) and busybox-based by default (`mkGuest`). The real axis is *what extra tools live in the rootfs at boot*, decided per invocation.

## Decision

**One canonical artifact (the workload). One mvm-shipped curated dev-tools overlay. Composition picked by command at runtime.**

### What the user writes

Exactly one thing in their flake — the workload:

```nix
packages.aarch64-darwin.default = mvm.lib.aarch64-darwin.mkGuest {
  entrypoint.command = "/usr/local/bin/myservice";
  packages = [ pkgs.myservice ];
};
```

No `.dev` output. No `devExtras`. No `debugTools` knob. No `dev=true`. The workload artifact is the prod artifact: signed, dm-verity-able, hash-stable.

### What mvm ships

A curated dev-tools overlay — a small versioned ext4 image (~30–50 MB), built by mvm CI per arch, fetched and hash-verified at runtime. Contents target the 80% debugging case:

- bash + bash-completion
- coreutils, util-linux, busybox-extras
- curl, wget, jq, less, vim-tiny
- strace, lsof, tcpdump, dig
- htop, procps
- git (small)

**Versioning**: pinned to mvmctl release. Cached at `~/.mvm/dev/overlay/v<mvmctl-version>/<arch>.ext4`. Hash-verified using the W5.1 verifier (cosign + SHA-256), reused from the prebuilt-image fetcher.

### Composition by command

| Command | Rootfs composition | Entrypoint behavior |
|---|---|---|
| `mvmctl run` | workload only | as declared (sealed) |
| `mvmctl run --debug` | workload + overlay | as declared, PTY console available |
| `mvmctl dev` | workload + overlay | drops into `/bin/bash` (overlay-provided) |
| `mvmctl dev --run-service` | workload + overlay | runs declared entrypoint + side-shell via `mvmctl console` |
| `mvmctl debug <vm>` | live-attach overlay to running VM | PTY console, no entrypoint change |

The user types `mvmctl dev` against any project — even one that only declared a sealed workload — and gets a usable shell with debugging tools. Zero opt-in. Zero parallel images.

### Mount mechanics

The overlay is attached as an additional virtio-blk disk (Apple Virtualization on macOS, libkrun on Linux). At boot, the workload's init script (`nix/lib/mk-guest.nix`'s embedded init) detects the overlay disk by label, mounts it RO at `/usr/dev`, and prepends `/usr/dev/bin` to `PATH`. Mode 0555. The workload's own paths and binaries are untouched.

For `mvmctl debug <vm>` (live attach), the runtime hot-attaches the overlay disk at the hypervisor level. Apple Virtualization supports virtio-blk hot-add; libkrun does not yet — first cut falls back to "stop, restart with overlay attached, restore state" with a clear warning.

`mvmctl dev` overrides the workload's declared entrypoint to `/bin/bash` via kernel cmdline (`mvm.entrypoint=/bin/bash`). The init script honors this when the overlay is mounted. `--run-service` omits the override.

## Consequences

**Positive:**
- **Transparent**: user declares a workload, types a command, gets the right thing. No flake-level dev/prod split, no knobs.
- **Honest about prod**: workload rootfs is byte-identical between `mvmctl run` and `mvmctl dev`. SHA-256 of workload artifact does not change.
- **Single security floor**: W2.x (rootless, RO `/etc`, setpriv, seccomp) applies regardless of overlay presence. Overlay can only add files, not grant privileges.
- **W3 verified boot preserved**: workload rootfs verifies under its own dm-verity roothash. Overlay has its own roothash. Separate block devices = no rootfs-hash drift.
- **W4.3 unaffected**: `prod-agent-no-exec` CI lane gates the guest *agent*; the overlay is rootfs-side.
- **CI surface bounded**: one workload artifact path through CI, plus one overlay artifact (per arch). No combinatorial dev/prod-flavored variants.

**Negative:**
- **Overlay update cadence pinned to mvmctl**: a CVE in (say) `curl` on the overlay ships its fix on the next mvmctl release. Acceptable for dev-only scope; if a critical CVE lands mid-cycle, users can `MVM_OVERLAY_VERSION=<patched>` to override.
- **libkrun live-attach is deferred**: `mvmctl debug <vm>` falls back to stop/restart on Linux until libkrun upstream supports virtio-blk hot-add.
- **No project-specific dev tools**: a Postgres workload that wants `psql` in the dev shell either adds it to `packages` (and accepts prod-bloat) or lives without it. If this friction is real, a future ADR can add a secondary per-project overlay.

**Neutral:**
- Catalog (`mvm-core::catalog::CatalogEntry`) stays purpose-agnostic. No dev/prod taxonomy in the catalog.
- The existing `dev-shell` cargo feature on the guest agent (gating `do_exec`, per W4.3) is unrelated and stays as-is.

## Alternatives considered

**`debugTools = "basic" | "full"` knob on `mkGuest`** — rejected. Violates the transparency constraint; user has to choose at flake-authoring time.

**`.dev` flake output convention** — rejected. Same problem; user has to declare both `default` and `dev` outputs and remember which `mvmctl` command builds which.

**Two pre-built variants per catalog entry** — rejected. Doubles CI surface, reopens W4.3 audit per variant, expands drift risk.

**mvm rewrites the user's flake at eval time to add packages** — rejected. Brittle (Nix evaluation surprises, cross-system targets, store path interactions); slower (per-user `nix build` for the dev variant); ties dev tooling freshness to the user's build cache rather than to mvm releases.

**OverlayFS instead of additional disk + RO mount** — considered. Overlay would need a writable upper layer (tmpfs is fine), which is fine for dev but adds an init-script complexity and slightly more boot cost. Pure RO secondary disk + `PATH` prepend is simpler and sufficient for the 80% case (developers don't typically write into `/usr/dev`).

## Threat model impact

- **No rootfs hash drift**: prod artifact is the same bytes whether or not the overlay is attached. The dm-verity check covers only the workload rootfs; the overlay is verified separately by its own roothash.
- **Capability containment**: the overlay can add binaries but not grant capabilities. setpriv `--bounding-set=-all --no-new-privs` (W2.3) is set per-service in init *after* the overlay mounts. A SUID binary in the overlay would be neutered by `--no-new-privs`.
- **Live-attach trust**: `mvmctl debug <vm>` requires host-side authority to invoke. The hypervisor enforces who can attach disks; the running VM cannot self-attach. No new vsock RPC for disk attach.
- **Audit**: every overlay attach emits a `DiskAttached { kind: Overlay }` usage event (per ADR-040), making the dev/debug path observable in the audit log.

## Compliance impact

- **SOC 2**: positive. The dev/prod boundary is enforced by a runtime-determined invariant (overlay never present in `mvmctl run`) rather than a build-time convention that can drift.
- **CIS**: neutral — adds no new privileged components.

## Consolidated from ADR-008 — Per-language function-service factories live in mvm.lib

`specs/adrs/008-function-service-factories.md` was a byte-identical duplicate of `specs/adrs/010-function-service-factories.md` (both titled "ADR-010: Per-language function-service factories live in mvm.lib", same content throughout — an apparent numbering-collision artifact rather than two distinct decisions). Its content is not repeated here a second time; see "Consolidated from ADR-010" above for the full decision record.
