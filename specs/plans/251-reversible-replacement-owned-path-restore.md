# Plan 251: Reversible replacement on owned request/response paths

**Status:** Implemented; workspace-wide validation closeout pending a clean host pass
**Date:** 2026-07-13
**ADR:** [`../adrs/111-runtime-owned-reversible-replacement.md`](../adrs/111-runtime-owned-reversible-replacement.md)
**Goal:** land the first runtime-owned detect -> replace -> reinject slice for
secrets and PII on owned cleartext request/response paths without weakening the
existing substitution/redaction posture.

## Scope

- signed-plan policy field in `mvm-core`
- destination-scoped resolution of reversible replacement policy
- request-scoped opaque token replacement in `mvm-hostd`
- exact-token reinjection on the owned response path
- plaintext-free proof/audit metadata

## Completed work

- [x] Add shared `mvm-core` policy/proof/token/correlation types for reversible
      replacement and thread the policy through signed execution-plan
      structures.
- [x] Resolve per-destination reversible replacement actions in `mvm-hostd`
      alongside the existing redaction-policy resolution.
- [x] Replace detected secret and PII spans on owned outbound request headers
      and bodies with request-scoped opaque tokens before one-way redaction and
      declared-secret substitution.
- [x] Reinject exact token echoes on owned inbound response headers and bodies
      using the same request-scoped flow state.
- [x] Emit plaintext-free rewrite proof records into the existing audit path.
- [x] Add focused tests for policy roundtrip, token reuse, outbound
      replacement, and exact-token reinjection.

## Validation

- `cargo check --workspace` (green in this worktree session)
- Focused reversible-replacement tests in `mvm-core` / `mvm-hostd` plus
  isolated `cargo test -p mvm-guest --test entrypoint_execute -- --nocapture`
  (green in this session)
- `cargo test --workspace` and `cargo clippy --workspace --all-targets -- -D warnings`
  still need a fresh host pass without PTY interference and without the
  host-wide `ENOSPC` condition that interrupted the session reruns
