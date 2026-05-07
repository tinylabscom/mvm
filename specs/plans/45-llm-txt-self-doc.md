# Plan 45 — `/.mvm/llm.txt` self-doc convention

Status: **Proposed.**

## Background

Sandbox-as-a-service products like sprites.dev ship a self-doc
convention inside every sandbox (`/.sprite/llm.txt`) so an LLM-driven
agent can self-orient when dropped into the box: discover checkpoint
semantics, mount layout, RPC entry points, and substrate identity
without needing host-side context.

mvm/mvmd is explicitly aimed at agent workloads (function-call
entrypoints per ADR-007, `RunEntrypoint`, plan 41). Cheap to ship
the equivalent now while the API shape is still wet; hard to
retrofit later because every existing template would need rebuild.

## Goal

Bake `/.mvm/llm.txt` into every guest rootfs by default. Verity-sealed,
owned `root:root`, mode `0644`. Caller-supplied `extraFiles` overrides
via attrset merge.

## Implementation

### Where it lands

`mvm/nix/flake.nix` — `mkGuest`'s `extraFiles` argument is the seam.
Around line 241 it accepts a caller map; around line 346–360 it
renders the populate-block. Add a default entry to the merged
`extraFiles` so every built rootfs gets `/.mvm/llm.txt` for free.

### Content

A small markdown document with these sections, templated with build-
time substitutions:

- Header: substrate name, agent version, variant (prod/dev), verity
  flag, build timestamp.
- "What is this?" — one-paragraph identification of the rootfs as a
  mvm guest.
- "RPC entry points" — vsock CID/port for the guest agent
  (`GUEST_AGENT_PORT=52`), the verb families (fs/proc/share), the
  control-socket location.
- "Checkpoint semantics" — pause/resume, how `PostRestore` works,
  where state lives in `~/.mvm/instances/`.
- "Where to find more" — `/etc/mvm/`, `mvmctl --help`, links to
  ADR-002 (security posture) and ADR-007 (function-call entrypoints)
  in canonical doc-site URLs.

### Override semantics

Callers can override the default by supplying their own
`/.mvm/llm.txt` entry in `extraFiles`. Implement via Nix attrset
merge with caller-wins:

```nix
extraFilesEffective = defaultExtraFiles // extraFiles;
```

where `defaultExtraFiles` contains the `/.mvm/llm.txt` entry. The
existing `extraFiles` arg is the caller's; `defaultExtraFiles` is
new and library-internal.

### Test

Extend `mvm/tests/smoke_invoke.rs:76-150` (the live-KVM smoke test
that already builds and boots `nix/images/examples/echo-fn/`) to
assert:

- `/.mvm/llm.txt` exists on the rootfs.
- File mode is `0644`.
- Content begins with the expected header (e.g. starts with
  `"# mvm guest"`).
- Content contains the agent version string.

The smoke test runs under `MVM_LIVE_SMOKE=1`. A unit-level Nix-eval
test (no boot required) is also viable: `nix eval` on a `mkGuest`
output and assert the rootfs derivation references the file by path.

## Critical files

- Modified: `mvm/nix/flake.nix` — `mkGuest` body around line 241
  (extraFiles arg) and 346–360 (populate-block renderer).
- Possibly new: `mvm/nix/lib/llm-txt.nix` — a function that renders
  the llm.txt content from build-time vars. Inline in flake.nix is
  also fine for v1.
- Modified: `mvm/tests/smoke_invoke.rs` — add assertion block.
- Reference precedent: `mvm/nix/images/examples/echo-fn/flake.nix:70-79`
  (uses `extraFiles` to bake a wrapper + marker into a rootfs).

## Verification

- Build any guest fixture (`nix/images/examples/echo-fn/` is
  smallest); inspect the derivation output to confirm
  `files/.mvm/llm.txt` is present with mode 0644.
- Run smoke test: `MVM_LIVE_SMOKE=1 cargo test --workspace
  smoke_invoke -- --nocapture`.
- Override test: a fixture flake that supplies its own `/.mvm/llm.txt`
  in `extraFiles` overrides the default — content matches caller's,
  not the library's.

## Effort

~half-day. File mode + content templating + one test assertion.

## Out of scope

- Runtime mutability — `/.mvm/llm.txt` is verity-sealed and read-only
  in production. Agent-written runtime self-doc is a separate plan.
- Per-template content customization beyond what `mkGuest`'s build-
  time vars expose — a caller who wants richer custom content
  overrides via `extraFiles`.
