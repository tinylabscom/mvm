# Plan 50 — `mvmctl up --flake <path>.tar.gz` archive intake

Status: **Proposed.** Implements ADR-009.

## Background

`mvmctl up --flake <path>` today accepts only directories or remote
git URIs (`mvm/crates/mvm-cli/src/commands/vm/up.rs:1-50`).
Distribution of compiled workload artifacts wants single-file shape
— easier to hash, transmit, cache.

mvmforge ADR-0012 (single-archive artifact) specifies a deterministic
gzipped POSIX ustar shape produced by
`mvmforge compile --out <path>.tar.gz`. The archive contains
`flake.nix`, `launch.json`, and `source/` at the top level. Same
manifest twice = byte-identical archive (asserted in mvmforge's
`examples-check` CI lane).

The substrate must accept this shape directly without external
extraction. ADR-009 records the consumer contract; this plan
implements it.

## Goal

`mvmctl up --flake artifact.tar.gz` succeeds with the same boot
outcome as `mvmctl up --flake artifact-dir/` for the same logical
workload, with three new error codes for archive-specific failure
modes.

## Implementation

### Step 1: Safe archive extractor

New module `mvm/crates/mvm-cli/src/commands/vm/archive.rs`. Public
function:

```rust
pub fn extract_archive_safely(
    archive_path: &Path,
    target_dir: &Path,
    max_inflated_bytes: u64,
) -> Result<(), ArchiveError>;
```

Implementation:

- Open archive via `flate2::read::GzDecoder` wrapping the file.
- Wrap with `tar::Archive`.
- Iterate entries with `Entries::next()`. For each entry:
  - Validate `entry.path()?` doesn't escape `target_dir` after
    normalization (`Path::components()` walk: reject `..` segments
    and absolute components). Error: `ArchivePathTraversal`.
  - Track cumulative decompressed bytes against `max_inflated_bytes`
    *as bytes flow*, not after extraction completes. Error:
    `ArchiveTooLarge`.
  - Extract the entry to `target_dir`.

Use streaming reads — never buffer the full decompressed archive in
memory.

### Step 2: Layout assertion

After extraction, assert the extracted root contains:

- `flake.nix` (regular file)
- `launch.json` (regular file)
- `source/` (directory)

Otherwise: `ArchiveLayoutInvalid`.

### Step 3: Wire into `up`

Modify `mvm/crates/mvm-cli/src/commands/vm/up.rs`:

- Parse `--flake` argument.
- Detect `.tar.gz` / `.tgz` suffix (case-insensitive).
- If archive: create `tempfile::TempDir` rooted at the runtime
  working area (`/run/mvmctl/...` if available, else
  `$XDG_RUNTIME_DIR/mvmctl/...`, else `$TMPDIR`); mode 0700.
- Call `extract_archive_safely(archive, tempdir.path(), cap)`.
- Pass the extracted path to the existing `up` flow as if it were a
  directory input.
- TempDir is RAII-cleaned on both success and failure.

Cap default: 1 GiB. Configurable via env
`MVMCTL_MAX_ARCHIVE_INFLATED_BYTES`.

### Step 4: Error variants + audit emit

Three new error variants:

```rust
ArchivePathTraversal { entry: String },
ArchiveTooLarge { limit: u64, encountered: u64 },
ArchiveLayoutInvalid { missing: Vec<&'static str> },
```

Per the audit-emit gate in `mvm/CLAUDE.md`, `up` already emits
`LocalAuditKind::VmExec` at success. Extend the audit payload with a
new `source` discriminator: `ArchiveInput | DirectoryInput | GitUri`.
No new `LocalAuditKind` variant required — the discriminator goes in
the existing variant's payload.

## Critical files

- New: `mvm/crates/mvm-cli/src/commands/vm/archive.rs`
- Modified: `mvm/crates/mvm-cli/src/commands/vm/up.rs:29-50` (flake
  arg parser + dispatch)
- Modified: `mvm/crates/mvm-cli/src/error.rs` (new error variants)
- Modified: `mvm/crates/mvm-core/src/policy/audit.rs` (extend
  `VmExec` payload with `source` discriminator)
- New: `mvm/tests/archive_intake.rs` integration test
- Reference contract: mvmforge ADR-0012 Decision section.

## Acceptance per contract

- `mvmctl up --flake artifact.tar.gz` succeeds with the same boot
  outcome as the equivalent directory input.
- Path-traversal entries fail with `E_ARCHIVE_PATH_TRAVERSAL`.
- Default 1 GiB inflated-size cap (configurable via
  `MVMCTL_MAX_ARCHIVE_INFLATED_BYTES`); exceeding fails with
  `E_ARCHIVE_TOO_LARGE`.
- Missing `flake.nix` / `launch.json` / `source/` fails with
  `E_ARCHIVE_LAYOUT_INVALID`.
- Temp extraction dir cleaned on both success and failure.
- Audit emit per the audit-emit gate.

## Verification

- Integration test (`mvm/tests/archive_intake.rs`):
  - Happy path: produce a fresh archive via
    `mvmforge compile -o test.tar.gz` against a corpus entry, then
    `mvmctl up --flake test.tar.gz`.
  - Path-traversal entry rejected (synthesize an archive with
    `../../../etc/passwd` entry).
  - 1 GiB+1 byte inflated rejected (synthesize via repeated
    compressible content).
  - Missing `launch.json` rejected.
  - Temp dir cleaned on success.
  - Temp dir cleaned on failure (use a deliberately-corrupt archive).
- Unit tests on the path-normalization logic.

## Effort

~3-4 days.

## Pushback to mvmforge

- The contract file referenced as
  `mvmforge/specs/contracts/mvm-archive-input.md` does not exist on
  the mvmforge side. ADR-009 (this plan's ADR) proposes the consumer
  contract; surface back to mvmforge and ask them to add the file
  mirroring `mvm-mkfunctionservice.md`.
- Document the temp-dir layout convention
  (`/run/mvmctl/...` → `$XDG_RUNTIME_DIR/mvmctl/...` → `$TMPDIR`) on
  the mvm side and ask mvmforge to reference it.

## Out of scope

- Signed archives. Deferred until artifact integrity becomes a
  multi-host distribution concern.
- Zip format. Rejected — POSIX ustar+gzip is the contracted shape.
- Other layouts beyond `flake.nix + launch.json + source/`. Rejected.
