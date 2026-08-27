# Build action identity and a real artifact manifest: bind "what was requested" to "what bytes came out"

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax for tracking.

**Status:** Proposed. Sourced from `specs/research/deterministic-attestable-builds-and-lean4.md`. WS1 depends on plan 276 WS6 landing first; WS2–WS4 do not.

**Goal:** Give mvm a typed **action identity** (`ActionDigest` — what was requested) and a faithful **artifact identity** (`ArtifactManifest` — what bytes and filesystem metadata resulted), then bind the two with a host-signed attestation. Today those two questions are answerable only by inference: the build fingerprint is a private `String` in `mvm-build` with nothing tying it to its outputs, and the one tree hasher that could address an artifact cannot see a permission bit.

**Architecture:** Four workstreams, each its own PR.

- **WS1** `ActionDigest` — promote the build fingerprint into the identity taxonomy.
- **WS2** `ArtifactManifest` — a Merkle tree manifest that represents mode, xattrs, symlinks, and hard links, sharing one walk with the ext4 materializer.
- **WS3** Bind them — extend `PackManifest` with the action digest, sign host-side, emit to the chain-signed audit log.
- **WS4** Decision gate — measure, then decide whether the fetch/build network split is worth its risk.

**Tech Stack:** Rust. `sha2`, `serde_jcs`, `ed25519-dalek`, `mvm_core::packs` / `pack_cache`, `mvm_fs::rootfs`, `mvm_hostd::host_signer`, `cargo-nextest`, `xtask` gates. **No new runtime dependency, no new hash axis, no new build system.**

**What mvm already has (extend, do not rebuild):**

- `mvm_core::pack_cache` — a content-addressed cache with verify-on-read, quarantine staging and atomic-rename publish. Every use re-verifies. This *is* the CAS; it does not need writing.
- `mvm_core::packs::PackManifest` — already carries `PackInputs { flake_locks, derivations, nar_hashes, oci_images, setup_commands, source_revisions, toolchain_versions }`, `PackProvenance { builder_identity, build_environment_identity, build_timestamp, reproducibility, sbom, signature_bundle }`, `ReproducibilityStatus`, `SbomReference`, `TransparencyLogReference`, and both Ed25519 and Sigstore/keyless signature formats. It is a SLSA-shaped provenance manifest already.
- `mvm_fs::rootfs::collect_nodes` — a walk that already captures mode and guest-semantic xattrs (including file capabilities) and has an explicit `UnsupportedNodePolicy::{Skip,Reject}` for device/FIFO/socket nodes.
- `mvm_fs::ext4` — a byte-deterministic writer (uid/gid forced to 0, timestamps zeroed).
- `mvm_core::workload_address` — the identity taxonomy (semantic / exact-byte / trust / ephemeral) stated in prose *and* enforced by the absence of conversions between the families.
- `mvm_core::plan::content_id` + `xtask check-content-address-determinism` — the content-address pattern and its CI gate.
- `mvm_hostd::host_signer` + the chain-signed audit log.

## Provenance

A source read of the current build/cache/rootfs/snapshot paths, recorded in `specs/research/deterministic-attestable-builds-and-lean4.md`. Two findings drive this plan:

1. `~/.mvm/dev/builds/<rev>/` is served on a hit if `rootfs.ext4` merely exists as a file. There is no digest and no signature, so content substitution is undetected — and `record_provenance` then signs whatever bytes are on disk, making the audit log faithfully record a substituted image as legitimate. **Closing this is plan 276 WS6, not this plan.**
2. `mvm_fs::hash::hash_dir` does not hash permission bits or xattrs, so two trees differing only by `chmod +x` share an address. Harmless for the opaque snapshot blobs it addresses today; disqualifying for anything bootable.

## Global Constraints

- Work in a dedicated worktree per workstream; `git -C <wt-abs>`.
- No `Plan N` / `ADR-\d+` / `#NNNN` / `W\d.` tokens in code or code comments (CI `check-no-spec-refs-in-comments`).
- Never `#[allow]` a clippy lint. `rustup run nightly cargo fmt --all` before push (CI Lint uses nightly rustfmt).
- `cargo nextest run --workspace` + `cargo test --workspace --doc` green before any task is marked done.
- Every new gate goes in **both** `ci.yml` and `ci-full.yml` Lint jobs — the gate list is duplicated and a gate in only one silently does not run.
- Every new gate gets a `specs/VERIFICATION.md` §Falsifiability row recording the planted defect that proved it fires.
- No `Co-Authored-By` trailer and no AI-tool attribution in commits or PR bodies.
- Scratch under `/tmp/`, never in the working tree.
- Tick these checkboxes and update `specs/SPRINT.md` + `specs/REFACTOR-STATUS.md` in the same commit as the work.

## Non-goals (do not re-propose)

- **No new build system.** This layer has no dependency graph, no scheduler, no dynamic dependency discovery, and no evaluation language. It is identity + cache + attestation over backends that build.
- **No REAPI internally.** Its `Directory`/`FileNode` model carries `is_executable` and nothing else — no mode bits, uid/gid, xattrs, or device nodes — so a verity-sealed bootable rootfs is not expressible in it. Revisit only as an export format at the mvmd boundary.
- **No BuildKit/LLB, no BuildStream.** The first makes containers the core abstraction; the second buys no capability mvm lacks at a Python-runtime cost.
- **No second hash axis.** SHA-256 stays canonical.
- **No hash-as-authorization.** Every check here is integrity only; the signed `ExecutionPlan` remains the sole admission authority.
- **No change to the dm-verity roothash chain.** Additive provenance only.

## Security considerations — settle before writing code

- **S1 — address ≠ authorization.** An `ArtifactDigest` proves bytes, never permission. It must never become an admission input.
- **S2 — the assurance ladder must be stated, never skipped.** A CAS blob proves bytes; an action-cache entry is a claim; a signature is a claim by a named key; policy-compliant evidence adds a monitor's word; only an independent rebuild removes single-builder trust. Prose describing any of these must not borrow a higher rung's language — `check-no-overclaim` is the instrument.
- **S3 — no silent skips in the manifest.** `hash_dir` today drops device/FIFO/socket nodes silently. The new manifest **rejects** by default with an explicit opt-in that represents them. A skipped node is an unrepresented input.
- **S4 — bytes, not meaning.** The artifact manifest does **not** Unicode-normalize paths; raw bytes are the identity. This is deliberately the opposite of `WorkloadAddress`, which NFC-normalizes because it addresses meaning. Document the asymmetry at both sites so neither is "fixed" to match the other.
- **S5 — cross-tenant dedup is a leak.** A shared address confirms two tenants hold identical content. Keep any cache keyed within the existing per-tenant boundary.
- **S6 — domain separation is mandatory.** Every new digest carries a `"mvm.<kind>.v<n>\0"` prefix. Without it a manifest and a plan that serialize alike address alike.

## Workstreams

### WS1 — `ActionDigest`: promote the build fingerprint into the taxonomy

- [ ] New `mvm-core::action` module with an `ActionDigest` newtype, `sha256:<64-hex>` shape validated through the shared `digest_shape` validator, and **no** `From`/`Into`/`Deref` to `WorkloadAddress`, `CheckpointDigest`, `OciDigest`, `Sha256Hex`, or `KeyId`.
- [ ] Add the `"mvm.action.v1\0"` domain separator (the current fingerprint's scheme tag is a string prefix, not a separated field) and keep the existing tagged, length-delimited `fold_field` framing — it is already correct.
- [ ] Move the environment contract into the digest explicitly: declared variables only, `PATH` constructed from the toolchain root rather than inherited, `TZ`/`LC_ALL`/`SOURCE_DATE_EPOCH` pinned. An undeclared caller variable is dropped and its presence is not hashed.
- [ ] `mvm-build`'s `workload_build_fingerprint` returns `ActionDigest`; the cache is keyed by it.
- [ ] Accept the one-time total cache miss from the new separator. **Do not migrate old keys** — a schema change must be a clean miss, never a silent reinterpretation.
- [ ] Tests: determinism, dev/prod non-aliasing, undeclared-env-invariance, cross-family type confusion does not compile (trybuild or a doc-test).

### WS2 — `ArtifactManifest`: a tree identity that can address a rootfs

- [ ] New `mvm-fs::manifest`: a Merkle `TreeNode` over `File { name_bytes, mode, size, content, xattrs }` / `Dir { name_bytes, mode, children }` / `Symlink { name_bytes, target_bytes }` / `HardLinkTo`, children sorted by raw `name_bytes`.
- [ ] **Share one walk with `rootfs::collect_nodes`.** Two walks would drift, and the reuse rule is binding.
- [ ] Normalization decisions, each with a test: `..` rejected not normalized; no Unicode normalization (S4); case preserved and a case-collision rejected rather than merged; mode masked to `0o7777`; uid/gid normalized to 0 and unrepresented; timestamps excluded; xattrs sorted and hashed; hard links represented; special files rejected by default (S3).
- [ ] `mvm_fs::hash::hash_source` becomes a thin adapter so the snapshot store is unaffected.
- [ ] Golden vectors: Unicode edge cases, deep nesting, path traversal attempts, duplicate entries, a device node, a non-UTF-8 filename, an astral-plane component.
- [ ] Regression witness: a tree differing only by `chmod +x` must produce a different digest — the defect this workstream exists to fix.

### WS3 — Bind action to artifact and attest it

- [ ] Extend `PackManifest` with `action_digest` and `evidence_digest`. Reuse `SignatureBundle`, `PackInputs`, `PackProvenance` unchanged.
- [ ] Host signs `(action_digest, artifact_digest, materials, policy_digest, evidence_digest)` on build completion via the existing host signer. **Never in the guest.**
- [ ] `AuditEmitter` emits a `build.attested` entry; `verify_audit_chain` covers it unchanged.
- [ ] `mvmctl trust verify <artifact>` — offline: recompute the manifest, check the signature against the local trust store, check the audit entry.
- [ ] Cache-hit verification order, each step fail-closed: signature → unexpired/unrevoked → exact action-digest equality → blobs present → **recompute** blob digests. Mismatch evicts *and* emits an audit entry; a tamper signal must be visible, not silently retried.
- [ ] Set `ReproducibilityStatus` honestly: `NotChecked` for dev; `Reproduced` only after an independent rebuild under a distinct signer identity.
- [ ] Export mapping to in-toto Statement v1 in a DSSE envelope with a SLSA v1 predicate, on publish/release only. `PackInputs` already matches `resolvedDependencies`; `action_digest` rides as an `mvm.` extension because SLSA has no slot for it.

### WS4 — Decision gate: is the fetch/build network split worth it?

- [ ] Run the benchmark harness in the research doc §3.5 under an isolated `MVM_HOME`; record cold / warm / no-op / cache-hit and the four attribution deltas.
- [ ] Record what `trusted_build_egress()` actually costs: it is currently `unrestricted()`, so a build action has ambient network. The tight `PRODUCTION_HOSTNAMES` allowlist governs only the app-deps install path.
- [ ] Answer the open question: can `nix build` run fully offline for an **arbitrary user flake** against a pre-seeded closure, or only for the builder VM's own known closure? The seeded-closure mechanism exists in the builder pack; its generality does not.
- [ ] Decide with the measurement in hand. If yes: `FetchAction` (network on, allowlisted, every blob hash-pinned) and `BuildAction` (`deny_all`), release profile refuses a build whose fetch resolved anything unpinned. If no: record why and keep the honest claim narrow.
- [ ] Whatever is decided, no prose may describe the current build as hermetic until a `BuildAction` genuinely runs with `deny_all`.

## Sequencing

WS2 first — it depends on nothing and unblocks the rest. WS1 in parallel, but land it **after** plan 276 WS6 so the cache gains verify-on-read before it gains a new key (otherwise the one-time miss and the new verification land together and a regression is hard to attribute). WS3 needs WS1 + WS2. WS4 is measurement and can start immediately; its outcome gates any hermeticity claim.

## Relationship to other plans

- **Plan 276 WS6** owns verify-on-read for the build cache. This plan does not duplicate it and should not start WS1 before it lands.
- **Plan 276 WS3/WS4** own the golden-vector corpus and the two-verifier oracle bar. WS2's vectors should join that corpus rather than starting a second one.
- The **Lean 4** question is answered in `specs/research/uor-hologram-cross-project-recon.md` §9 and is **out of scope here**: Lean proves the verifier and address algebra sound; the sandbox proves hermeticity; neither substitutes. The research doc's §9 adds two candidate first theorems (manifest path-confinement, entry-uniqueness) that would attach to WS2's manifest once it is stable — a later assurance phase, not this plan. Kani on the path normalizer and the tar/OCI entry parsers is the cheap phase-1 alternative and needs no Lean toolchain decision.

## Deferred (out of scope)

Remote execution, a shared CAS, builder-identity federation, and any REAPI export live at the mvmd boundary and are design-only here. Snapshot attestation (a snapshot is content-addressable but **not** a reproducible artifact — entropy, clocks, machine-id, credentials, agent session state) needs its own scrub specification before it gets an attestation model.
