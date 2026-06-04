# Plan 147 — Portable runnable artifacts (`mvmctl artifact run`)

Status: proposed (no code lands yet). Sequenced after Plan 120 `core_demo_e2e`
green and the Plan 134 artifact-model slices, both of which this depends on for
a working boot path and the typed artifact model.

## Goal

Close the one missing leg in the `.mvm` packed-artifact story: **execution**.
We already `pack` / `verify` / `inspect` a signed, content-addressed,
single-file artifact (kernel + rootfs + cmdline + optional verity sidecars).
You cannot yet boot one. `mvmctl artifact run <file.mvm>` should verify the
artifact against the operator's trust root, extract it to a staging dir, and
boot it through the same admission + audit path every other workload takes —
turning `.mvm` into a portable "ship-one-file, run-anywhere-the-arch-matches"
unit without inventing a second boot path or a second trust model.

## Motivation

The pattern — a microVM workload baked into a single self-describing file that
rehydrates on any host of the right architecture, zero install step — is proven
by peer libkrun-based tooling in the ecosystem. We already have the harder half
(a *signed* such format). What we deliberately do **not** copy is the
self-executing-binary shape some peers ship (`./artifact run`): a blob that
boots itself bypasses the operator's verify-before-run decision and would
undercut Claim 8 (every workload runs from a signed, admitted `ExecutionPlan`)
and Claim 9 (every bundle re-verified at admit time). Keeping `mvmctl` as the
launcher is the stronger posture; this plan adds the run verb, not a runnable
blob.

## Current state (verified 2026-06-03)

**Packed-artifact format exists, run leg does not.**
`crates/mvm-build/src/packed_artifact.rs`:
- `pub fn pack(inputs: &PackInputs, signing_key: &SigningKey, out_path: &Path)`
  (`:190`) — writes a `tar.gz` with `manifest.json` first, `signature` second,
  then payload entries at fixed in-archive paths: `kernel/vmlinux`,
  `rootfs/rootfs.ext4`, `cmdline.txt`, and optional `rootfs/rootfs.verity`,
  `rootfs/roothash`, `initrd/verity-initrd.cpio.gz` (`:197-210`).
- `pub fn verify(path, verifying_key) -> Result<Manifest>` (`:308`) — re-reads
  manifest + signature, re-canonicalises the manifest, checks the Ed25519
  signature. **Explicitly does not extract payload bytes to disk** (`:306`).
- `pub fn inspect_unverified(path) -> Result<Manifest>` (`:290`).
- `Manifest` carries `target_arch: GuestArch`, `files: BTreeMap<String, FileEntry>`
  (per-entry `sha256_hex` + `size_bytes`), `security: SecurityPosture`,
  `build_provenance: Option<String>` (`:150-160`).
- **There is no `extract` function** — `verify` deliberately stops before payload.

**CLI surface.** `crates/mvm-cli/src/commands/vm/artifact.rs`:
- `enum Cmd` (`:41`) has `Pack` / `Verify` / `Inspect` (`.mvm` ops) and the
  `model-*` group (artifact-model dirs). **No `Run`.**
- `run_verify` (`:314`) resolves the verifying key: `--key <path>` or, by
  default, the host signer's public half via `host_signer::load_or_init()` →
  `signer.public_path`. This is the trust-root resolution `run` must reuse.

**Existing boot path.** `crates/mvm-cli/src/commands/shared/start.rs` already
builds a `mvm_core::vm_backend::VmStartConfig` from a kernel/rootfs/cmdline +
arch and dispatches `VmBackend::start_with_mode(&VmStartConfig, StartMode)`
(`crates/mvm-core/src/vm_backend.rs`). `mvmctl run` / `mvmctl up` route through
the Claim-8 admission flow (`admit_for_run`, `AuditEmitter`) before that
dispatch. `artifact run` must reuse both — not fork them.

**Elastic memory is already built — out of scope here.** `mvm-supervisor`'s
`BalloonController` + `balloon_runtime::run_balloon_loop` +
`VmBackend::balloon_set_target` / `balloon_state` already implement host-
pressure-driven elastic RAM (Sprint 52 W1). The libkrun FFI leg is unwired
(no `krun_*` balloon binding), but that is a separate libkrun-capability item,
not part of this plan.

## What changes

### W1 — `extract_verified` in `mvm-build::packed_artifact`

`verify` stops before payload by design; `run` needs the bytes on disk. Add a
sibling that does the full verify **and then** materialises payloads, so the
extraction never trusts an unverified archive.

- [ ] Add to `crates/mvm-build/src/packed_artifact.rs`:

```rust
/// On-disk result of [`extract_verified`]: absolute paths to the
/// materialised payload files plus the verified manifest.
#[derive(Debug, Clone)]
pub struct ExtractedArtifact {
    pub manifest: Manifest,
    pub kernel: PathBuf,
    pub rootfs: PathBuf,
    pub cmdline: PathBuf,
    /// Present only when the archive carried the SealedProd verity trio.
    pub verity: Option<PathBuf>,
    pub roothash: Option<PathBuf>,
    pub initrd: Option<PathBuf>,
}

/// Verify `path` against `verifying_key`, then extract every payload
/// entry into `dest_dir` (created if absent). Each entry is re-hashed
/// during extraction and compared against `manifest.files[path].sha256_hex`;
/// a mismatch deletes the partially-written file and returns
/// `ArtifactError::PayloadHashMismatch`. Returns the on-disk layout.
pub fn extract_verified(
    path: &Path,
    verifying_key: &VerifyingKey,
    dest_dir: &Path,
) -> Result<ExtractedArtifact, ArtifactError>;
```

- [ ] Implementation composes existing pieces: run the full `verify` signature
  + canonicalisation check first (reuse `read_manifest_and_signature` + the
  signature path from `verify`), then a second streaming pass over the archive
  that, for each known in-archive path, streams the entry through SHA-256 while
  writing to `dest_dir`, and compares the digest to the manifest's recorded
  `sha256_hex` before accepting the file. Reuse `MAX_ENTRY_BYTES` /
  `MAX_ARCHIVE_BYTES` caps. Refuse any in-archive path not present in the
  manifest's `files` map (no path traversal, no surprise entries).
- [ ] Add `ArtifactError::PayloadHashMismatch { path: String }` to the existing
  error enum.

**Tests** (`crates/mvm-build/src/packed_artifact.rs` `#[cfg(test)]`, matching
the file's existing rejection-ladder tests):
- [ ] `extract_verified_roundtrips_dev_profile` — pack a Dev artifact, extract,
  assert the three core files exist with byte-identical content to the inputs.
- [ ] `extract_verified_rejects_wrong_key` — extraction fails before any file is
  written when the verifying key doesn't match.
- [ ] `extract_verified_rejects_flipped_payload_byte` — flip one byte of
  `rootfs/rootfs.ext4` inside a packed archive; assert `PayloadHashMismatch`
  and that no partial rootfs is left in `dest_dir`.
- [ ] `extract_verified_sealed_prod_materialises_verity_trio` — SealedProd
  artifact yields `Some` for `verity` / `roothash`.

### W2 — shared boot helper + `mvmctl artifact run`

Do not write a second boot path. Factor the kernel+rootfs+cmdline→`VmStartConfig`
→`start_with_mode` core out of `shared/start.rs` so both `mvmctl run` and
`mvmctl artifact run` call it.

- [ ] In `crates/mvm-cli/src/commands/shared/start.rs`, extract the existing
  config-build-and-dispatch core into a helper (keep `mvmctl run`'s current
  behaviour byte-for-byte — it calls the new helper):

```rust
/// Boot a microVM from already-on-disk kernel/rootfs/cmdline. The
/// single place that constructs `VmStartConfig` and calls
/// `VmBackend::start_with_mode`. Callers: `mvmctl run`, `mvmctl artifact run`.
pub(in crate::commands) fn boot_from_files(
    ctx: &BootContext,         // arch, backend selection, networking, name, mode
    kernel: &Path,
    rootfs: &Path,
    cmdline: &Path,
) -> Result<VmId>;
```

  `BootContext` carries exactly the fields `start.rs` already derives today
  (target arch, resolved backend, networking mode, vm name, `StartMode`); this
  task moves them into a struct, it does not invent new config.

- [ ] Add `Run(RunArgs)` to `Cmd` in `crates/mvm-cli/src/commands/vm/artifact.rs`
  and wire it in `run()`'s match:

```rust
/// Verify a `.mvm` artifact against the operator's trust root, extract
/// it to a staging dir, and boot it through the standard admission +
/// audit path. Exits 65 (`EX_DATAERR`) on a verification failure,
/// identical to `mvmctl artifact verify`.
Run(RunArgs),
```

```rust
#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct RunArgs {
    /// Path to the `.mvm` artifact to run.
    pub path: PathBuf,
    /// Verifying-key file (32-byte raw Ed25519). Defaults to the host
    /// signer's public half at `~/.mvm/keys/host-signer.pub` — same
    /// default as `mvmctl artifact verify`.
    #[arg(long)]
    pub key: Option<PathBuf>,
    /// Name for the booted VM. Defaults to the artifact file stem.
    #[arg(long)]
    pub name: Option<String>,
    /// Detach after boot instead of streaming the console.
    #[arg(long, default_value_t = false)]
    pub detach: bool,
}
```

- [ ] `run_artifact_run`: resolve the verifying key with the **same** code path
  as `run_verify` (`--key` or `host_signer` public half — factor the
  key-resolution block out of `run_verify` into a private
  `resolve_verifying_key(key: Option<&Path>) -> Result<VerifyingKey>` and call
  it from both). Choose a staging dir under the artifacts cache
  (`mvm_data_dir()/artifacts/run/<file-stem>-<archive-sha-prefix>/`; reuse the
  manifest signature bytes' hex prefix for the suffix so re-running the same
  artifact reuses the dir). Call `extract_verified`. Map
  `manifest.target_arch` into `BootContext`. Hand off to W3.
- [ ] Reject SealedProd-only invariants the runner can't honour on the selected
  backend up front (e.g. a SealedProd artifact requires the verity sidecars be
  passed to the boot path) — mirror `pack`'s `SealedProdMissingVerity` posture
  at run time so a sealed artifact never boots without its roothash wired.

**Tests** (`crates/mvm-cli/tests/cli.rs`, matching existing help/parse tests):
- [ ] `artifact_run_help_lists_run` — `mvmctl artifact run --help` parses and
  documents `--key` / `--name` / `--detach`.
- [ ] `artifact_run_rejects_unsigned_artifact_exit_65` — running a tampered
  artifact exits 65 and boots nothing (assert no VM state dir created).

### W3 — admission + audit integration (Claims 8 / 9)

`artifact run` is a workload launch; it must not skip admission.

- [ ] Before `boot_from_files`, synthesize and admit an `ExecutionPlan` for the
  extracted artifact through the existing flow (`admit_for_run`), exactly as
  `mvmctl run` does. The plan's image identity is the artifact's content
  address (the manifest signature / archive digest), and the plan carries the
  artifact's `SecurityPosture` (`verity_protected`, `requires_auth`,
  `allows_volumes`, `allows_egress`) so the resolved network policy and gate
  decisions match what the producer declared.
- [ ] Emit a `plan.admitted` → `plan.launched` (or `plan.failed`) chain to
  `~/.mvm/audit/<tenant>.jsonl` via `AuditEmitter`, plus a new
  `plan.artifact_run` entry recording: artifact path, archive digest,
  `target_arch`, `build_provenance`, and the resolved security posture. Model
  the emitter method on the existing `AuditEmitter::emit_oci_provenance`
  (`crates/mvm-cli/src/commands/vm/audit_chain.rs`) so `verify_audit_chain`
  continues to detect drift.

**Tests:**
- [ ] `artifact_run_emits_admitted_and_launched_entries` — assert the audit
  chain after a (mock-backend) run contains the admit + launch + `artifact_run`
  entries and that `verify_audit_chain` accepts them.
- [ ] `artifact_run_tamper_breaks_audit_chain` — flip one byte in the emitted
  `artifact_run` entry; assert `verify_audit_chain` (and `mvmctl audit verify`)
  exits nonzero.

### W4 — docs + claim catalog

- [ ] `public/src/content/docs/reference/cli-commands.md`: document
  `mvmctl artifact run`, the verify-before-boot default, and the `--key`
  trust-root override.
- [ ] `public/src/content/docs/contributing/development.md`: one line in the
  artifact section noting `pack` → `verify` → `run` is now a complete loop.
- [ ] If the `plan.artifact_run` audit entry is named as a witness for Claim 8
  in `specs/claims/catalog.md`, add the row so `xtask check-claim-catalog`
  stays green. (It is a new admission surface under the Claim-8 flow — treat it
  like the OCI provenance entry, which has its own claim doc.)

## Explicitly untouched

- `pack` / `verify` / `inspect` behaviour and the `.mvm` wire format — `run`
  is additive; `extract_verified` is a new function, not a change to `verify`.
- `mvmctl run` / `mvmctl up` external behaviour — W2 factors a helper out from
  under `mvmctl run` with no observable change.
- The balloon / elastic-memory machinery in `mvm-supervisor`.
- The artifact-model `model-*` command group (separate surface).

## Out of scope

- **Stateful / writable packed machines.** Peer tooling packs a mutable VM
  whose installed packages survive restarts; our SealedProd `.mvm` is read-only
  by design (ADR-002 W3 dm-verity requires RO rootfs). A writable-overlay
  packed artifact needs the overlay design and conflicts with the sealed
  posture — its own plan if we want it. This plan runs read-only artifacts only.
- **Self-executing artifact binaries.** Rejected on Claim-8/9 grounds (see
  Motivation). `mvmctl` stays the launcher.
- **OCI quick-run friction.** `mvmctl run --image <oci-ref>` ergonomics are
  owned by Plan 74; do not duplicate distribution/ext4-materialisation here.
- **libkrun balloon FFI leg.** Tracked separately as a libkrun-capability item.
- **`--allow-host` egress sugar.** A thin alias over the existing policy
  resolver; nice-to-have, not blocking the run leg.

## Verification

- [ ] `cargo test --workspace` green (W1–W3 unit + CLI tests).
- [ ] `rustup run nightly cargo fmt --all -- --check` clean (CI Lint uses
  nightly rustfmt).
- [ ] `cargo clippy --workspace -- -D warnings` clean.
- [ ] Manual, on a host with a working backend: `mvmctl build` a Dev artifact,
  `mvmctl artifact pack … --profile dev --out demo.mvm`,
  `mvmctl artifact run demo.mvm`, confirm boot via `examples/agent_ping`.
- [ ] `mvmctl audit verify` exits 0 after a successful `artifact run` and
  nonzero after a hand-edited `artifact_run` entry.

## Success criteria

- [ ] A `.mvm` produced by `pack` boots end-to-end via `artifact run` with no
  other inputs, on a host of the matching architecture.
- [ ] A tampered / wrong-key artifact exits 65 and boots nothing.
- [ ] Every `artifact run` admission is recorded in the chain-signed audit log
  and survives `verify_audit_chain`.
- [ ] `mvmctl run` behaviour is unchanged (it now calls the shared
  `boot_from_files` helper).

## Sequencing

Depends on Plan 120 (`core_demo_e2e` green — needs a working boot path to run
artifacts through) and the Plan 134 artifact-model slices (typed model +
`model-*` commands already merged on `feat/artifact-model`). Land after both.
W1 is independent and can land first; W2 depends on W1; W3 depends on W2.
