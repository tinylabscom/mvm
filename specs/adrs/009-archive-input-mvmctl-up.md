---
title: "ADR-009: mvmctl up accepts deterministic .tar.gz archive input"
status: Proposed
date: 2026-05-06
supersedes: none
related: ADR-007 (function-call entrypoints); plan 50-archive-intake; mvmforge ADR-0012 (single-archive artifact)
---

## Status

Proposed. The mvmforge side has shipped the producer (deterministic
archiver in `mvmforge/crates/mvmforge/src/archive.rs:47-76`); this
ADR records the consumer contract on the mvm substrate side.

A counterpart contract document at
`mvmforge/specs/contracts/mvm-archive-input.md` does **not yet
exist** on the mvmforge side. This ADR proposes the consumer contract
and asks mvmforge to add the contract file mirroring
`mvm-mkfunctionservice.md`.

## Context

`mvmctl up --flake <path>` today accepts only a directory or a remote
git URI (`crates/mvm-cli/src/commands/vm/up.rs:1-50`). Distribution
of compiled workload artifacts wants a single-file shape: easier to
hash, easier to transmit, easier to cache.

mvmforge ADR-0012 specifies a deterministic gzipped POSIX ustar shape
produced by `mvmforge compile --out <path>.tar.gz`. The archive
contains `flake.nix`, `launch.json`, and `source/...` at the top
level. Same input always produces the same `sha256sum` (asserted in
mvmforge's `examples-check` CI lane). The substrate must accept this
shape directly without an external extraction step.

## Decision

Extend `mvmctl up --flake <path>` to accept paths ending in `.tar.gz`
or `.tgz` (case-insensitive). On such input, mvmctl:

1. **Validates the archive shape** before extraction:
   - Reject path-traversal entries (any entry whose normalized path
     escapes the extraction root). Error: `E_ARCHIVE_PATH_TRAVERSAL`.
   - Reject entries whose decompressed cumulative size exceeds the
     configurable cap (default 1 GiB; env
     `MVMCTL_MAX_ARCHIVE_INFLATED_BYTES`). Error: `E_ARCHIVE_TOO_LARGE`.
2. **Extracts** to a temporary directory under the mvmctl runtime
   working area:
   - `/run/mvmctl/...` if available, else
   - `$XDG_RUNTIME_DIR/mvmctl/...`, else
   - `$TMPDIR`-based location.
3. **Asserts layout**: the extracted root must contain `flake.nix`,
   `launch.json`, and `source/`. Otherwise: `E_ARCHIVE_LAYOUT_INVALID`.
4. **Treats the extracted directory as the flake input** for the rest
   of the up flow — no behavioral difference between
   `mvmctl up --flake artifact.tar.gz` and
   `mvmctl up --flake artifact-dir/` for the same logical workload.
5. **Cleans up the temp dir** on both success and failure (RAII).

## Invariants

- The archive parser must use a streaming, traversal-safe library;
  Rust's `tar` crate with explicit `Entry::path()` validation is
  acceptable.
- The cap is checked against decompressed size **as bytes flow
  through the decoder**, not after extraction completes
  (compression-bomb payloads must not consume disk).
- The temp directory mode is `0700`; mvmctl never extracts archives
  in a world-readable location.
- Audit emit: `mvmctl up` emits a single audit record at success with
  the source identified as `archive` (vs `directory` vs `git-uri`)
  so forensic queries can distinguish the input shape. The
  `LocalAuditKind::VmExec` variant's payload gains a `source`
  discriminator field — no new variant needed.

## Consequences

- mvmforge stops needing an extract-to-tempdir shim around `mvmctl up`
  for `.tar.gz` artifacts (today's `mvmforge up` does this).
- Distribution becomes single-file: one sha256, one transfer, one
  cache key.
- New error surface: three new error codes
  (`E_ARCHIVE_PATH_TRAVERSAL`, `E_ARCHIVE_TOO_LARGE`,
  `E_ARCHIVE_LAYOUT_INVALID`) join the existing `mvmctl up` failure
  modes.
- **Out of scope:** signed archives (deferred to a follow-up ADR if
  artifact integrity becomes a multi-host distribution concern), zip
  format (rejected — POSIX ustar+gzip is the contracted shape),
  layouts other than `flake.nix + launch.json + source/` (rejected —
  contracted layout).
