# Plan 41 — function-call entrypoints (mvm side)

> Substrate work for Modal-style `f.remote(...)` semantics. mvmforge
> ships the language SDKs and Nix factories (decorationer plan 0003);
> this plan covers the mvm pieces: a constrained `RunEntrypoint`
> vsock verb, the `mvmctl invoke` CLI, snapshot integrity, and a flip
> of network defaults to deny.

## Context

ADR-007 lays out the architecture and invariants. Build-time-everything
is the load-bearing rule (CLAUDE.md feedback memory): the wrapper, the
function body, the format, and the allowlist are all baked into the
rootfs at image-build time; only stdin bytes are runtime data.

mvm's job is to expose a vsock verb that runs *the* baked program with
stdin piped, stdout/stderr captured, caps and timeouts enforced — and
nothing else. The verb is distinct from `do_exec` (which stays
dev-only) so the production posture (`prod-agent-no-exec`) can be
strengthened to also assert the new contract is present.

This is plan 41 (Sprint 42 follow-up). It does not implement the
language-specific wrappers — those belong to mvmforge per ADR-0007's
flake-contract.

## Approach

Six workstreams, each independently shippable. W1–W3 are the
end-to-end functional path; W4–W6 are the security-invariant wraps
around it.

### W1 — Wire protocol additions

Lands in `crates/mvm-guest/src/vsock.rs`.

- Add `GuestRequest::RunEntrypoint { stdin: Vec<u8>, timeout_secs:
  u64 }`.
- Add `GuestResponse::EntrypointEvent(EntrypointEvent)` where
  `EntrypointEvent` is `Stdout { chunk: Vec<u8> } | Stderr { chunk:
  Vec<u8> } | Exit { code: i32 } | Error { kind:
  RunEntrypointError, message: String }`.
- Add `RunEntrypointError` enum: `PayloadCap`, `Timeout`, `Busy`,
  `WrapperCrashed`, `EntrypointMissing`, `InternalError`.
- `#[serde(deny_unknown_fields)]` on all three (W4.1).
- Roundtrip test + tampered-frame rejection test for each.
- v1 implementation emits exactly one `Stdout` event, one `Stderr`
  event, and one `Exit` (or `Error`) — the wire is streaming-shaped
  but the impl buffers up to 1 MiB per stream. This avoids a future
  protocol break when v2 chunks progressively.

Acceptance: serde roundtrips, tampered frames rejected, fuzz target
added under `crates/mvm-guest/fuzz/`. Vsock fuzz lane in CI updated.

### W2 — Agent handler

Lands in `crates/mvm-guest/src/bin/mvm-guest-agent.rs`.

Boot-time:

- Read `/etc/mvm/entrypoint` once at boot. File contains a single
  absolute path string.
- `realpath` it. Assert the resolved path:
  - starts with `/usr/lib/mvm/wrappers/`,
  - is on the same fs as `/usr` (verity rootfs, not overlay),
  - is owned uid 0, gid 0,
  - is a regular file, mode 0755, not setuid.
- Open and hold an fd for `fexecve`. Refuse `RunEntrypoint` if any
  check fails.

Per-call:

- Acquire a mutex (one in-flight call per VM).
- Create `/tmp/call-<uuid>` (mode 0700, owned by wrapper uid).
- Spawn the held-fd via `fexecve`, with:
  - cwd = the per-call TMPDIR
  - env = the wrapper template's baked baseline (no inheritance)
  - stdin piped from the request's `stdin` bytes
  - stdout/stderr captured into bounded buffers (1 MiB each).
- Enforce timeout via poll loop (same shape as today's `do_exec`).
  On timeout: SIGTERM, then SIGKILL after a grace period.
- On any of {cap breach, timeout, wrapper exit}: tear down the
  child's process group, `rm -rf` the TMPDIR, release the mutex,
  emit the appropriate `EntrypointEvent`(s).
- Coredumps disabled: parent sets `RLIMIT_CORE=0` before spawn; the
  wrapper image's `mvm-init` already enforces `PR_SET_DUMPABLE=0`
  (mvmforge factory contract).

Acceptance: handler unit tests with a fake `/etc/mvm/entrypoint`
script (`/bin/cat`, `/bin/false`, a fixture that sleeps past the
timeout, a fixture that floods stdout). Live-KVM integration test
in CI's vsock-capable lane.

### W3 — `mvmctl invoke` CLI

Lands in `crates/mvm-cli/src/commands/vm/invoke.rs` (new) plus
wiring in `crates/mvm-cli/src/commands/mod.rs`.

Surface:

```
mvmctl invoke <vm-or-template> [--stdin <file>|-] [--timeout 30s]
              [--fresh | --reset]
```

- `--stdin <file>|-` — bytes to feed the wrapper (default: empty).
- `--timeout` — host-side timeout (drops at `timeout * 1.2` if guest
  doesn't respond).
- `--fresh` — boots a transient VM, runs once, tears down (matches
  today's `mvmctl exec` semantics).
- `--reset` — runs in a session VM; restores from the post-boot
  snapshot before next call. Deferred to phase 2 — wire the flag,
  but no-op until session-pool plan lands.
- Default — session VM reuse via existing `boot_session_vm` /
  `dispatch_in_session` / `tear_down_session_vm` primitives in
  `crates/mvm-cli/src/exec.rs` (today used by `mvmctl mcp`).

Output:

- Forward `Stdout` events to mvmctl's stdout, `Stderr` to mvmctl's
  stderr, exit with the guest's exit code.
- On `Error` events: structured error to stderr (kind + message,
  no payload contents per logging policy), exit non-zero.

Acceptance: integration test against a fake-rootfs template (echoes
stdin to stdout). Argv parsing tests in `crates/mvm-cli/tests/`.

### W4 — Snapshot integrity (HMAC)

Lands in `crates/mvm-runtime/src/vm/microvm.rs`.

- On first run, generate `~/.mvm/snapshot.key` (32 random bytes,
  mode 0600). New helper in `mvm-core` for HMAC-SHA256 keyed-mac
  using existing `signing.rs` primitives.
- `snapshot_create()` writes state file and memory image to
  `<file>.tmp`, fsyncs, computes HMAC over the concatenation
  (with explicit length prefixes to prevent splice ambiguity),
  writes a sidecar `<file>.hmac`, then renames atomically.
- `run_from_snapshot()` reads sidecar, recomputes HMAC, refuses
  resume on mismatch.
- Snapshot dir asserted mode 0700 at create+restore; doctor verifies.
- Refuse to resume snapshots whose `mvmctl_version` metadata
  doesn't match the current binary unless `--allow-stale-snapshot`
  is passed.

Acceptance: unit tests for create-verify roundtrip, tampered file
rejected, tampered hmac rejected, missing sidecar rejected, version
mismatch rejected. Concurrent-create test (atomic rename).

### W5 — CI gates + doctor

Lands in `.github/workflows/ci.yml` and
`crates/mvm-cli/src/commands/ops/doctor*`.

- New CI step `prod-agent-runentry-contract`: builds the prod
  `mvm-guest-agent` binary once with the same flags the release
  pipeline uses, asserts on that *exact* binary:
  - `do_exec` symbol absent (`! nm "$BIN" | grep '\bdo_exec\b'`)
  - `run_entrypoint` symbol present
  - SHA-256 matches the release artifact path (link CI input ↔
    release input so nothing can be substituted between check and
    ship).
- Doctor checks (live host, optional live guest):
  - `~/.mvm` mode 0700, `~/.cache/mvm` mode 0700, snapshot dir
    mode 0700.
  - `~/.mvm/snapshot.key` exists, mode 0600.
  - For a running VM: agent reports `/etc/mvm/entrypoint` resolved
    OK (new vsock query verb `EntrypointStatus { ok: bool, path:
    String }`, prod-safe).
  - For a built rootfs (offline): mount-and-inspect mode in doctor
    asserts `/etc/mvm/entrypoint` exists, mode 0644, points at a
    file under `/usr/lib/mvm/wrappers/` mode 0755.

Acceptance: CI lane added, runs on every PR. Doctor commands
exercised in `crates/mvm-cli/tests/doctor.rs`.

### W6 — Network: deny-default for function workloads

Lands across `mvm-runtime/src/vm/network.rs`,
`mvm-core/src/dev_network.rs`, and the IR consumer paths.

- Recognize a new IR-derived signal that the workload is a
  function-entrypoint kind. (Comes from the IR — `entrypoint.kind ==
  "function"` in mvmforge's emit.)
- For function-entrypoint workloads, default to *no* TAP creation
  and *no* bridge attachment unless `network.mode = "bridge"` is
  explicitly set in the IR.
- Reject IR that names `network.peers` referencing workloads outside
  the build graph or `network.egress.allowlist` containing literal
  wildcards. Surfaces in mvmforge's `validate`; mvm honors the
  result.
- `mvmctl doctor --network` prints the live posture for a running
  VM: TAP present yes/no, firewall rule count, peer reachability
  matrix.

Acceptance: integration test booting a function-entrypoint rootfs
with no network IR — assert TAP not created, guest cannot resolve
DNS or reach `1.1.1.1`. Same test with `network.mode = "bridge"`
declared — assert TAP created.

### Hardening (cross-cutting)

Folded into the workstreams above:

- M1 (caps + timeouts) — W1 + W2.
- M2 (forbidden formats) — IR-level (mvmforge); mvm just doesn't
  add any "set format" verb.
- M3 (entrypoint hardening) — W2 + W5.
- M4 (combined CI gate) — W5.
- M5 (session leakage) — W2 (per-call TMPDIR + agent-side cleanup);
  pool single-tenancy invariant pre-baked for the future
  session-pool plan.
- M6 (error envelope sanitization) — wrapper concern, lives in
  mvmforge factory; mvm just forwards the bytes the wrapper emits.
- M7 (build-time bundling) — mvmforge concern.
- M8 (network deny-default) — W6.
- M9 (snapshot integrity) — W4.
- M10 (no-payload logging) — agent + mvmctl logging changes
  threaded through W2 + W3.
- M11 (coredumps off) — W2 sets `RLIMIT_CORE=0` parent-side; Nix
  factory sets `PR_SET_DUMPABLE=0` wrapper-side (mvmforge).
- M12 (serialize per-VM) — W2 mutex.
- M13 (secrets path) — agent doesn't add a "set runtime secret"
  verb; existing `/run/mvm-secrets/<svc>/` mechanism is the only
  path.
- M14 (crash hygiene from agent side) — W2.
- M15 (per-language seccomp) — mvm exposes tier-loading (already
  W2.4); per-language tier files live in mvmforge.
- M16 (supply chain) — chain documented in ADR-007 + ADR-0009; no
  new mvm-side work for v1.

## Acceptance Criteria

- All workstreams ship green on `cargo test --workspace`,
  `cargo clippy --workspace -- -D warnings`, and the new
  `prod-agent-runentry-contract` CI lane.
- An end-to-end demo path exists: a fake "echo" rootfs (built in
  CI fixtures) boots, accepts `mvmctl invoke` with stdin, returns
  stdout, tears down. Same path works against a session VM.
- Network deny-default is observable: function-entrypoint rootfs
  without explicit `network.mode = bridge` cannot reach `1.1.1.1`.
- Snapshot integrity is observable: tampering with a snapshot file
  causes `run_from_snapshot()` to refuse with a clear error.
- Doctor reports the live posture for entrypoint, snapshot dir,
  and network — and flags any violation.

## Risks

- Vsock unsupported on Lima/QEMU (existing pitfall) — full
  integration test gated to native Linux/KVM CI.
- Snapshot HMAC adds a key file that needs survive-rotation
  semantics if we ever rotate it. v1 punts; if the key changes, all
  warm pools cold-restart, no data loss.
- mvmforge IR network-field surface is moving (decorationer plan
  0003). mvm depends on the IR but doesn't define it; coordinate
  cutover so the deny-default flip lands at the same time as
  mvmforge's wrapper template.
- Wrapper coredump policy is split between agent (parent rlimit) and
  Nix factory (`PR_SET_DUMPABLE`). Belt-and-suspenders by design;
  document the split clearly in ADR-007.

## Decisions

- **HMAC key rotation policy:** never rotate `~/.mvm/snapshot.key`.
  Warm pools regenerate naturally on key change; the operational
  simplicity outweighs crypto-agility for a local-host-only key
  whose threat model already excludes a malicious host (ADR-002).
- **`--reset` mode timing:** wire the flag in W3 but no-op it. The
  implementation primitive (`reset_session_vm()` from the post-call
  snapshot) lands with the session-pool follow-up plan, not plan 41.
  Plan 41 stays small.
- **Network deny-default scope:** function-entrypoint workloads
  only. Flipping the default for other workload kinds is a separate
  ADR with user-visible breakage; named as a future follow-up but
  explicitly out of plan 41 scope.
- **Format default** (joint with mvmforge): **JSON** in v1; msgpack
  opt-in via the IR `format` field. JSON debugs cleanly with
  `mvmctl invoke ... --stdin <(echo '...')` + `cat`; msgpack is the
  upgrade path for byte-/float-fidelity workloads. Both decoders
  pinned to stdlib / audited libraries per M1.
- **Schema-bound payloads** (joint with mvmforge): **v2.** v1 ships
  size + depth + format caps only. v2 derives JSON Schema from type
  hints (Python `pydantic` / TS `zod`) and validates inbound bytes
  before user code runs. v1 caps are sufficient defense for the
  immediate threat surface; schema generation is non-trivial work
  best landed once the substrate is solid.
- **Granular network IR fields** (joint with mvmforge): **v2.** v1
  ships the deny-default flip with the existing one-bit
  `network.mode`. v2 lands `egress` / `peers` / `ingress` / `dns`
  granular grants. Flipping the safe default now (deny) is the
  breaking change; growing the explicit-grant surface later is
  additive.
