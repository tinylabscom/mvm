# Fast, attestable, content-addressed builds in mvm — and what Lean 4 should verify

**Status:** Research / proposal. Not scheduled. No code changes accompany this document.
**Grounded on:** worktree `/Users/auser/work/tinylabs/mvmco/mvm`, branch `main`, commit `4414ddc195785f23039e09d02d61b0194f28ab57`, working tree clean at the time of investigation.
**Method:** source read of the current checkout + safe local measurements on this host (macOS 26, Apple Silicon). Every claim is tagged **[fact]** (observed in code/on disk), **[measured]** (timed here), **[inference]** (derived from architecture, not measured), or **[recommendation]**.
**Revised 2026-08-01:** three framing corrections from an adversarial audit — Milestone A's local T9 ceiling (the signer key is co-located with the cache; §10/§12), the builder-tier egress posture (a deliberate ADR-001 Tier-2 choice, not a violation; §2.3/§5.3), and a measurement caveat on the unmeasured latency ranking (§1).

---

## 1. Executive decision

### 1.1 Primary recommendation

**Keep Nix. Wrap it. Do not replace it, and do not adopt an external build system.**

Introduce a thin, MVM-native **action/artifact layer** that sits *above* Nix and *below* the CLI, and promote the content-addressed, signed, verify-on-read machinery mvm already ships for **published packs** so it also covers **every local build output**.

The single sentence version: mvm already owns a signed content-addressed artifact store with verify-on-read (`mvm_core::pack_cache`), a SLSA-shaped provenance manifest (`mvm_core::packs::PackManifest`), a deterministic in-process filesystem materializer (`mvm_fs::rootfs`), a signed-plan admission chain (`mvm_core::plan` + `mvm_hostd::supervisor`), and a typed vsock build control plane (`mvm-builderd`). What it does **not** have is a first-class **action identity** binding "what was requested" to "what bytes came out", and the one cache that stands between a user and a rebuild — `~/.mvm/dev/builds/` — is **unauthenticated and unverified on read**. That is the gap, and it is small.

### 1.2 Fallback

If distributed execution demand outgrows the local layer, adopt **REAPI (Bazel Remote Execution API)** *only at the `mvmd` boundary*, as an external wire protocol for shipping actions to remote workers — never as the internal identity. mvm's action digest and artifact manifest stay authoritative; REAPI's `Action`/`Command`/`Directory` messages become a serialization of them. This is deliberately the fallback, not the primary: REAPI's `Directory` node model does not represent the filesystem metadata a bootable rootfs needs (see §6.4), and adopting it as the internal identity would import that limitation permanently.

**Rejected outright:** BuildKit/LLB (makes containers the core abstraction, which collides with the microVM + dm-verity posture — see ADR-001 and `specs/adrs/017-oci-image-verity-posture.md`), BuildStream (Python runtime + ecosystem ownership cost for no capability mvm lacks), and a from-scratch build system (§4.6).

### 1.3 What should happen to Nix

Nix stays as the **default `BuildBackend`** — the thing that turns a flake into a store path. Three changes around it:

1. **Nix stops being on the cache-hit path.** It already partly is not: `dev_build_via_builder_vm` short-circuits on a host-side fingerprint before booting the builder VM (`crates/mvm-build/src/pipeline/dev_build.rs:484-493`). That short-circuit becomes typed, signed, and verified rather than a plaintext `fingerprint → revision` file.
2. **Nix stops being the only producer of an attestable artifact.** OCI-derived rootfs (`mvm_fs::oci_to_rootfs`) and future backends emit the same `ArtifactManifest` + attestation. The artifact layer becomes backend-independent.
3. **The nix source filter gets narrowed** (`nix/lib/workspace-filter.nix`). It is currently a basename blacklist over the entire workspace root, so editing a Markdown file under `specs/` changes `mvmSrc`'s store path and forces a guest-agent rebuild. This is the single cheapest latency win available and it requires no architecture change at all (§3.4).

**Measurement caveat.** No successful end-to-end build, warm cache-hit, or no-op was timed on this host — the warm cache never engaged and builds appear to have failed before completion (§3.1). Every latency figure here is **[inference]**, and the §3.3 bottleneck ranking (H2 > H1 > H3 > H4) is provisional pending the §3.5 benchmark.

### 1.4 Answers to the six closing questions

1. **Retain, wrap, reduce, or replace Nix?** *Retain and wrap.* Reduce its blast radius by narrowing its source filter and keeping it off the warm path. Do not replace.
2. **What owns action identity, content identity, the CAS, attestations?** Action identity → a new `mvm-core::action` module (sibling to `plan/content_id.rs`). Content identity → `mvm-fs` (an extended `hash.rs` tree manifest) rendered as the existing `mvm_core::packs::Sha256Hex`. CAS → a generalized `mvm_core::pack_cache`. Attestation → an extended `mvm_core::packs::PackManifest`, signed by the existing host signer, audit-chained by the existing `AuditEmitter`.
3. **Adopt REAPI or another protocol?** Not now, and never internally. Later, at the `mvmd` boundary only, as an export format.
4. **Where should build execution occur?** Unchanged — inside the builder VM (libkrun / HVF / QEMU), driven over the existing typed vsock control plane. Add an explicit **network-off build phase** distinct from a **network-on fetch phase** (§5.3). This is not a fix for a violated invariant: the builder tier *deliberately* runs unrestricted egress (ADR-001 Tier-2 dev/test — it carries no untrusted workload, so claim-10 egress enforcement is not wired there). It is a **stricter posture proposed for reproducible release builds**, tightening beyond what the tier matrix requires.
5. **What should Lean 4 verify?** The *verifier*, not the build. First target: output-manifest construction — path normalization cannot escape the declared root, and every accepted path appears exactly once. Second: `verify plan result = true → PolicyCompliant plan result` for a deliberately small `PolicyCompliant`. Lean sits in a later assurance phase and produces a golden-vector corpus that the Rust verifier is differentially tested against (§8).
6. **Smallest first implementation with immediate value?** Milestone A (§10): make `~/.mvm/dev/builds/<rev>/` a verify-on-read content-addressed entry with a typed `ActionDigest` key. It makes cache hits self-checking (recompute-on-read, fail closed) — closing a corruption/skew class outright — and is a prerequisite for everything else. Its value *against a hostile local build script* (T9) is bounded: on a single-user host the host signer key sits in the same account as the cache, so signing raises the bar to corruption/skew detection, not supply-chain proof, until key custody is separated (§10). It is roughly one PR against `mvm-build` + `mvm-core`.

---

## 2. Current-state repository map

### 2.1 End-to-end call path: `mvmctl build --flake . `

| Step | Location | What happens |
|---|---|---|
| 1 | `crates/mvm-cli/src/commands/dispatch.rs:28` | `Commands::Build` → `build::group::run` |
| 2 | `crates/mvm-cli/src/commands/build/build.rs:308-345` | `build_flake` validates the flake ref, ensures the Stage-0 builder image exists |
| 3 | `crates/mvm-cli/src/commands/build/build.rs:363` | calls `mvm_build::dev_build::dev_build(env, resolved, profile, mode)` |
| 4 | `crates/mvm-build/src/pipeline/dev_build.rs:272-324` | `dev_build` — honours the `MVM_BUILD_STUB_OUTDIR` test escape hatch, then dispatches to the builder-VM path |
| 5 | `crates/mvm-build/src/pipeline/dev_build.rs:473-504` | `dev_build_via_builder_vm` — **host-side cache short-circuit** |
| 5a | `crates/mvm-build/src/pipeline/build_cache.rs:76-120` | `workload_build_fingerprint` = SHA-256 over `{scheme tag, profile, mode, mvmctl version, user-flake tree hash, workspace tree hash}` |
| 5b | `crates/mvm-build/src/pipeline/build_cache.rs:133-153` | `read_cached_revision` — plaintext `~/.mvm/dev/build-cache/<fingerprint>` → nix store hash |
| 5c | `crates/mvm-build/src/pipeline/dev_build.rs:540-560` | `cached_build_result` — reconstructs the result **if `rootfs.ext4` exists as a file**. No hash check. |
| 6 | `crates/mvm-build/src/pipeline/dev_build.rs:602-626` | on miss: route to the resident `mvm-builderd` over the typed vsock control plane if a persistent session is alive |
| 7 | `crates/mvm-build/src/pipeline/dev_build.rs:639-646` | otherwise single-shot builder VM, honouring `--builder` / `MVM_BUILDER_BACKEND` / auto-detect with ADR-007 fallback |
| 8 | `crates/mvm-build/src/pipeline/dev_build.rs:701-807` | `dev_build_with_builder_vm` — mounts flake source + staging out-dir, runs `BuilderVm::run_build`, gets `BuilderArtifacts::Image { revision_hash }` |
| 9 | `crates/mvm-build/src/pipeline/dev_build.rs:772-784` | rename (or sparse-copy) staging → `~/.mvm/dev/builds/<revision_hash>/` |
| 10 | `crates/mvm-build/src/pipeline/dev_build.rs:500-502` | record `fingerprint → revision` (best-effort, unsigned) |

The launch path (`mvmctl up` / `run`) then synthesizes a signed `ExecutionPlan`, records artifact digests via `mvm_build::provenance::record_provenance` (`crates/mvm-build/src/provenance.rs:42-65`), admits it through the supervisor, and emits `plan.admitted` / `plan.launched` to the chain-signed audit log.

### 2.2 The identity primitives that already exist

This is the most important finding in the report: **mvm has already done most of this work, in a different room.**

| Concept | Where | Notes |
|---|---|---|
| Identity taxonomy (semantic / exact-byte / trust / ephemeral) | `crates/mvm-core/src/workload_address.rs:28-41` | Explicitly enumerated in prose *and* enforced by the type system — no `From`/`Into`/`Deref` between the four families. This is exactly the four-way split §5 of the brief asks for, already articulated. |
| Plan content-address | `crates/mvm-core/src/plan/content_id.rs:44-56` | `sha256(serde_json(plan − plan_id))`. Deterministic because `serde_json::Value` is a `BTreeMap`. |
| Determinism gate for the above | `xtask/src/check_content_address_determinism.rs:1-56` | CI-enforced: `serde_json`'s `preserve_order` feature must not be reachable from `mvm-core`/`mvm-contract`. |
| Signed, content-addressed workload bundle | `crates/mvm-core/src/plan/bundle.rs` | `.mvmpkg` = tar of `manifest.json` + `manifest.sig` + `artifacts/`; `BundleRegistry` is a CAS keyed by `bundle_sha256` (`bundle.rs:269-300`); out-of-band trust store; re-verified at fetch **and** at admit. |
| SLSA-shaped provenance manifest | `crates/mvm-core/src/packs.rs:136-147, 191-199, 275-297, 346-350` | `PackManifest { inputs, outputs, provenance, trust }` where `PackInputs` already carries `flake_locks`, `derivations`, `nar_hashes`, `oci_images`, `setup_commands`, `source_revisions`, `toolchain_versions`, and `PackProvenance` carries `builder_identity`, `build_environment_identity`, `build_timestamp`, `ReproducibilityStatus`, `SbomReference`, `SignatureBundle` (Ed25519 **or** Sigstore keyless) and `TransparencyLogReference`. |
| Verify-on-read CAS | `crates/mvm-core/src/pack_cache.rs:1-40` | Staged → verified in place → copied to a same-filesystem quarantine → atomic `rename` onto the content-addressed dir. **Every use re-verifies.** Exactly the discipline plan 276 WS6 wants, already implemented for packs. |
| Content-addressed snapshot store | `crates/mvm-fs/src/snapshot_store.rs:1-33` | Reflink-CoW clones; `materialize` clones content only, so re-hashing reproduces the id. |
| Filesystem-tree hash | `crates/mvm-fs/src/hash.rs:36-86` | Sorted relative-path manifest, raw-byte path components (no lossy UTF-8), `f`/`d`/`l` kinds. See §2.4 for its gaps. |
| Deterministic ext4 materializer | `crates/mvm-fs/src/rootfs.rs:1-14, 274-300`; `crates/mvm-fs/src/ext4/mod.rs:1044-1046` | Pure, in-process, no `mkfs`, no subprocess. uid/gid forced to 0, all timestamps zeroed, mode + xattrs (incl. file capabilities) preserved, explicit `UnsupportedNodePolicy::{Skip,Reject}` for device/FIFO/socket. |
| Hash-pinned bootstrap seed | `crates/mvm-build/src/stage0.rs:18-31` | Nix release tarball pinned by SHA-256 in source, re-verified at extract. |
| Signed builder pack producer | `crates/mvm-build/src/builder_pack.rs:1-45` | Pure: "every timestamp is an input", so the caller controls the bytes. |
| Chain-signed audit log | `crates/mvm-hostd/src/supervisor/audit_file.rs` | `prev_hash` spine over Ed25519-signed envelopes; `mvmctl trust audit verify` exits nonzero on drift. |

### 2.3 What is missing

1. **No first-class action identity.** `workload_build_fingerprint` (`build_cache.rs:76-120`) is a well-built hash — domain-separated, length-delimited fields via `fold_field` (`build_cache.rs:196-203`), scheme-tagged `mvm-workload-build-fingerprint-v1` — but it is a private `String` inside `mvm-build`, not a typed `ActionDigest` in the identity taxonomy, and nothing binds it to the artifacts it produced.

2. **The dev build cache is unauthenticated and unverified on read.** `read_cached_revision` reads a plaintext file (`build_cache.rs:144-153`); `cached_build_result` accepts the hit if `rootfs.ext4` is a regular file (`dev_build.rs:543-546`). There is no digest, no signature, and no recompute-and-compare. Path-traversal is defended (`is_safe_component`, `build_cache.rs:175-182`) but content substitution is not. **[fact]**

3. **`BuildProvenance` is recorded at launch, from whatever bytes are on disk.** `record_provenance` (`provenance.rs:42-65`) hashes the files it is handed and records the digests in the signed plan. That makes the launch *traceable* — the audit log says exactly which bytes booted — but it cannot *detect substitution*, because there is no independently-established expected value to compare against. This is a genuine and important distinction: it is provenance-of-record, not integrity enforcement.

4. **Four different "canonical" JSON forms coexist.** **[fact]**
   - `mvm_contract::ir::canonicalize` — hand-rolled `no_std` JCS writer feeding `ir_hash`.
   - `serde_jcs` over an NFC-normalized value — `WorkloadAddress` (`workload_address.rs:9-26`).
   - `serde_json::to_vec` over a `serde_json::Value` (sorted keys, but *not* JCS number/string rules) — `compute_plan_id` (`content_id.rs:47-55`).
   - `serde_json::to_vec` over the struct directly (**declaration order**, not sorted) — `canonical_manifest_bytes` (`bundle.rs:104-106`) and `PackManifest::canonical_bytes` (`packs.rs:150-152`).

   `canonicalizer_equivalence.rs:1-23` locks the first two together and documents the known astral-plane divergence in `serde_jcs` 0.1.0 (UTF-8 byte order vs RFC 8785's UTF-16 code-unit order). The third and fourth are unlocked. The fourth is the one that signs bundles and packs — reordering a struct field silently changes the signature payload. This is not currently a bug (Rust field order is stable per build), but it is a canonicalization hazard with no gate, and it is precisely what a Lean spec would eliminate.

5. **Build actions cannot run with networking off.** `trusted_build_egress()` is literally `unrestricted()` (`crates/mvm-contract/src/policy/network_policy.rs:262-272`), and that is the policy the builder VM runs under. The tight allowlist (`crates/mvm-build/src/egress_proxy/allowlist.rs:59-72` — pypi, npm, crates.io, cache.nixos.org, github, cdn.kernel.org, port 443 only) applies to the **app-deps install** path, not to `nix build`. There is no network-off build mode today — but the framing matters: this is an *external* goal, not an mvm invariant. ADR-001 makes the builder a Tier-2 dev/test tier where claim-10 egress enforcement is deliberately unwired, so unrestricted builder egress is a **tier decision, not a violation**. A network-off build is therefore a *proposed stricter posture* for reproducible release builds (§5.3), not a today-broken requirement. **[fact/inference]**

### 2.4 Gaps in the existing tree hasher

`mvm_fs::hash::hash_dir` (`crates/mvm-fs/src/hash.rs:44-59`) emits `"{relpath}\0{kind}\0{payload}\n"` per sorted entry, where payload is the file's SHA-256 (`f`), the symlink target (`l`), or empty (`d`). Against the metadata list the brief requires:

| Property | Status |
|---|---|
| Relative path normalization | Partial — raw bytes, sorted, `/`-joined. No NFC/NFD decision, no case-fold decision. |
| File type | Yes (`f`/`d`/`l`). |
| **Executable / permission bits** | **Not hashed.** Two trees differing only by `chmod +x` produce the same address. |
| Symlink targets | Yes (raw bytes). |
| Hard links | Not represented — each link hashes as an independent file. |
| UID/GID | Not hashed. |
| Timestamps | Not hashed (correct — they should be excluded). |
| xattrs / capabilities | **Not hashed.** A `security.capability` xattr change is invisible. |
| Sparse files | Not represented (hashed as dense content — correct for identity). |
| Device nodes / sockets / FIFOs | **Silently skipped** (`hash.rs:82-83`), not rejected. |
| Ordering | Yes, sorted by relative path bytes. |
| Case sensitivity | Undefined — inherits the host filesystem. APFS is case-insensitive by default; ext4 is not. |
| Unicode normalization | Undefined — raw bytes, so a macOS-normalized name and a Linux-normalized name are different addresses for the same logical tree. |
| Domain separator / schema version | **Absent.** |

For its current job (addressing an opaque `mem.bin` or a `{vmstate.bin, mem.bin}` pair) none of this bites. As the general artifact-tree hasher it is not sufficient — and the executable-bit and xattr omissions are exactly the ones that matter for a bootable rootfs. **[fact]** Note the contrast with `mvm_fs::rootfs::collect_nodes`, which *does* capture mode and guest-semantic xattrs and *does* have an explicit `Reject` policy for special files — the correct model already exists one module over.

---

## 3. Performance findings

### 3.1 What was measured here

All on this host (Apple Silicon, macOS 26), current checkout, debug binary at `target/debug/mvmctl` (109 MB). **[measured]**

| Measurement | Result |
|---|---|
| `mvmctl --version` (process start → exit, debug build) | 0.00–0.03 s, 3 runs |
| Fingerprint scope: files / bytes | 1,996 files / 24.8 MB (with `EXCLUDED_BASENAMES` pruned) |
| Shell approximation of `hash_source_tree` over that scope (sorted walk + read + SHA-256) | 0.25 s cold, 0.14–0.15 s warm, 3 runs |
| `~/.mvm/cache` total | ~9.2 GB (`builder-vm` 6.2 G, `oci` 1.1 G, `guest-agent-build` 1.1 G, `runtime-overlay-bins` 398 M, `default-microvm` 208 M, `stage0` 136 M) |
| `~/.mvm/dev/build-cache/` | **Does not exist** — the fingerprint→revision cache has never been written on this host |
| `~/.mvm/dev/builds/` | 15 entries, **all empty `.staging-<pid>-<ns>` directories**, all dated 2026-07-13; zero completed revisions |

Two things follow immediately. First, **CLI startup and configuration loading are not a bottleneck** — even the debug binary starts in tens of milliseconds. Second, **the warm-path cache has never actually engaged on this machine**, and the staging directories leak on failure (`dev_build.rs:742-784` renames staging → final on success but only removes staging on the cache-hit branch; a failure between `create_dir_all` and `rename` leaves the directory behind). That leak is cosmetic but it is also evidence that builds here have been failing before completion.

### 3.2 What was *not* measured, and why

I did not run `mvmctl build`, `mvmctl up`, or any builder-VM boot. Doing so would boot a VM, write into `~/.mvm`, and on a cache miss run a full `nix build` (this repo's own guidance records 45-minute builds under memory pressure). That is outside "safe and isolated" for a research task on a shared working tree. The numbers below are therefore **[inference]**, and §3.5 gives the harness to replace them with facts.

### 3.3 Ranked bottleneck hypotheses

**H1 — Builder-VM boot + Nix evaluation on every non-fingerprint-hit build. [inference, high confidence]**
The module documentation states this directly: *"Even when the resulting image is byte-identical to the previous run, the build leg pays the full builder-VM boot + nix evaluation (~tens of seconds) just to rediscover the cache hit — because the cache key is the nix revision, and the revision is only knowable after the eval produces a store path."* (`build_cache.rs:5-8`). The persistent-builder route (`dev_build.rs:602-626`) removes the boot but not the eval. **Expected impact: seconds to tens of seconds per build.**

**H2 — Over-broad Nix source filter forcing spurious guest-agent rebuilds. [fact + inference, high confidence]**
`nix/lib/workspace-filter.nix:29-56` is a **basename blacklist over the entire workspace root**. Everything not named `target`/`result`/`node_modules`/`.git`/… enters the store as `mvmSrc`. The guest agent is `buildRustPackage { src = mvmSrc; }`, whose output path derives from the whole filtered NAR (`build_cache.rs:27-30`). Therefore **editing any file under `specs/`, `public/`, `sdks/`, `features/`, `tests/`, `schema/`, or `scripts/` changes the store path and rebuilds the guest agent.** In the measured scope that is 421 files / ~3.8 MB of pure documentation and fixture data — small in bytes, but each edit costs a full rebuild cycle. For a repository whose workflow is documentation-heavy (every plan requires a spec edit in the same commit), this is likely the *most frequently paid* unnecessary cost. **Expected impact: a full rebuild cycle on edits that cannot affect the artifact.**

**H3 — Artifact copy / materialization. [inference, medium confidence]**
`copy_staged_artifacts` → `copy_sparse_file` for `rootfs.ext4` (`dev_build.rs:921-985`). The sparse path exists precisely because a dense copy of a multi-hundred-MB rootfs is expensive. On a same-filesystem success the `rename` at `dev_build.rs:778` is free; the copy is the fallback. The typed persistent route (`finalize_typed_persistent_build`, `dev_build.rs:870-918`) *always* copies from the `/job` share rather than renaming. **Expected impact: hundreds of ms to seconds per build on the persistent route.**

**H4 — The fingerprint walk itself. [measured]**
~150 ms warm for 1,996 files / 24.8 MB, paid on *every* build including no-ops, and computed twice (user flake tree + workspace tree — though for a source checkout they overlap). This is the **floor of the warm path**. It is not the problem today, but it becomes the problem once H1 and H2 are fixed, and it is trivially fixable with an mtime/size-keyed memo (§6.6).

**H5 — Genuine compiler/linker work.** Not an orchestration cost. Out of scope for this proposal except insofar as H2 causes it to be paid unnecessarily.

**Ranking: H2 > H1 > H3 > H4.** H2 first because it is a one-file change with no architectural risk. H1 second because the fingerprint short-circuit already addresses it — it just needs to actually work and be trustworthy.

### 3.4 The cheapest available win

Narrow `nix/lib/workspace-filter.nix` from a basename **blacklist over everything** to a path **allowlist** of what actually feeds a derivation: `crates/`, `src/`, `xtask/`, `nix/`, `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `build.rs`. Mirror the same allowlist in `build_cache.rs`.

Two cautions:

- The existing soundness binding is a **subset** test in the *blacklist* direction (`build_cache.rs:364-385`: every basename mvm excludes must also be excluded by the nix filter). Converting to an allowlist inverts the direction of the required proof: the fingerprint's *included* set must be a **superset** of the nix filter's included set. The test must be rewritten, not merely retargeted, or the soundness argument silently reverses.
- The comment at `workspace-filter.nix:11-16` ties the filter to `.gitignore`. That coupling should be dropped in favour of an explicit allowlist; a gitignore-derived filter answers a different question ("is this a build artifact?") than the one that matters ("does this feed a derivation?").

### 3.5 Benchmark plan (to be run, not yet run)

Use an isolated `MVM_HOME` so no measurement touches the real cache. `mvm-core::config` honours `MVM_HOME` for every path (this is a CI-gated invariant — `xtask check-single-home`, `check-test-home-isolation`).

```sh
# Isolated home; never point this at ~/.mvm
export MVM_HOME=/tmp/mvm-bench-$(date +%s)
mkdir -p "$MVM_HOME" && chmod 700 "$MVM_HOME"
BIN=./target/release/mvmctl        # release, not debug
FLAKE=examples/python/hello-app-with-deps

hyperfine --warmup 0 --runs 3 --export-json /tmp/mvm-cold.json \
  --prepare "rm -rf $MVM_HOME/dev" \
  "$BIN build image --flake $FLAKE --json"                      # (1) cold

hyperfine --warmup 1 --runs 5 --export-json /tmp/mvm-warm.json \
  "$BIN build image --flake $FLAKE --json"                      # (2) warm + (3) no-op

hyperfine --warmup 1 --runs 5 --export-json /tmp/mvm-nocache.json \
  "env MVM_NO_BUILD_CACHE=1 $BIN build image --flake $FLAKE --json"   # (4) fingerprint disabled

hyperfine --warmup 1 --runs 5 --export-json /tmp/mvm-nopersist.json \
  "env MVM_NO_PERSISTENT_BUILDER=1 $BIN build image --flake $FLAKE --json"  # (5) single-shot builder
```

`--json` emits a machine-readable `{status, revision, cached, kernel, rootfs}` record (`crates/mvm-cli/src/commands/build/build.rs:383-405`), so `cached: true|false` distinguishes a real cache hit from a re-evaluation.

**Deltas that answer the question:**

| Delta | Isolates |
|---|---|
| (4) − (2) | The value of the host-side fingerprint short-circuit = builder-VM boot + Nix eval |
| (5) − (4) | Persistent-builder benefit = builder-VM boot alone |
| (2) alone | The warm floor: fingerprint walk + artifact stat + process start |
| (1) − (4) | Genuine Nix realization + compiler cost |

**Sub-step attribution.** The build path is already `tracing`-instrumented (`#[instrument]` on `dev_build`, an explicit `build_image` span at `dev_build.rs:381`, and a `build_image_duration_ms` metric at `dev_build.rs:385-390`). Run with `RUST_LOG=mvm_build=debug,mvm_runtime=debug` and a JSON subscriber to attribute time across: fingerprint → dispatch decision → VM create → guest handshake → nix eval → nix realize → export → host copy. Add spans where they are missing rather than building a separate harness.

**A separate micro-benchmark should isolate H4:** time `workload_build_fingerprint` directly as a `criterion` bench in `mvm-build`, with and without an mtime memo, over this repository. That is a pure-function benchmark with no VM involvement and can be run today.

**Do not** measure with `MVM_BUILD_STUB_OUTDIR` set (`dev_build.rs:284-307`) — it skips the build entirely and would measure nothing.

---

## 4. Decision matrix

Scored 0–5 against mvm's requirements, weighted by how much mvm actually needs each column. "Cost" columns are inverted (5 = cheap).

| Criterion | Optimize Nix in place | **Hybrid: Nix backend + MVM CAS/action layer** | REAPI | BuildKit/LLB | BuildStream | Custom build system |
|---|---|---|---|---|---|---|
| Deterministic builds | 5 | 5 | 3 | 2 | 4 | 2 |
| Content-addressed artifacts | 4 (store paths ≠ content) | **5** | 5 | 4 | 4 | 3 |
| Action-addressed caching | 3 (drv-addressed) | **5** | 5 | 5 | 4 | 3 |
| Provenance / attestation | 2 | **5** (packs already SLSA-shaped) | 3 | 4 (SLSA out of the box) | 2 | 2 |
| Local cache-hit latency | 2 | **5** | 4 | 4 | 3 | 4 |
| Remote execution | 3 (remote builders) | 3 (deferred, clean seam) | **5** | 4 | 3 | 1 |
| **Rootfs / fs-artifact fidelity** | 4 | **5** (`mvm_fs::rootfs` already) | 2 (`Directory` lacks mode/xattr/device) | 3 (container fs, not verity rootfs) | 4 | 3 |
| Incremental granularity | 3 | 3 | 5 | 4 | 3 | 2 |
| Rust / existing-code fit | 4 | **5** | 2 (gRPC/protobuf stack) | 1 (Go, daemon) | 1 (Python) | 4 |
| Runs in an MVM worker with **no guest network** | 2 | **4** (with §5.3) | 3 | 1 (needs registry) | 3 | 4 |
| macOS + Linux practicality | 3 | **5** | 3 | 2 | 2 | 4 |
| Operational complexity (inv.) | 4 | **4** | 2 | 2 | 2 | 1 |
| Security / trust model fit | 3 | **5** | 3 | 2 | 3 | 3 |
| Migration cost (inv.) | **5** | 4 | 1 | 1 | 1 | 1 |
| Ecosystem maturity | 5 | 4 | 5 | 5 | 3 | 1 |
| Long-term ownership (inv.) | 4 | 3 | 2 | 3 | 2 | **1** |

### 4.1 Notes per candidate

**Optimize Nix in place.** Cheapest, and §3.4 says do some of it regardless. But it cannot deliver the attestation story: a Nix store path is *derivation*-addressed, not *content*-addressed, and CA-derivations remain experimental. It also cannot make OCI-derived rootfs and Nix-derived rootfs share one identity — and mvm already ships both (claim 14 / `specs/claims/claim-10-oci-image-provenance.md`). **Necessary, not sufficient.**

**Hybrid (recommended).** Wins because ~70% of it is already built and hardened in this repository. The remaining work is a typed action digest, a proper output manifest, and rewiring one cache. It preserves both existing backends, preserves the security posture, and leaves a clean seam for `mvmd`.

**REAPI.** Technically the closest external fit and genuinely excellent at remote execution and action caching. Two disqualifiers as an *internal* boundary: (a) REAPI's `Directory`/`FileNode` model carries `is_executable` and nothing else — no mode bits beyond that, no uid/gid, no xattrs, no device nodes — so a bootable, verity-sealed rootfs is not expressible; (b) it brings a gRPC + protobuf runtime into a workspace that has fought hard to keep `mvm-core` async-free (`xtask check-core-runtime-free`) and `mvm-contract` `no_std`. Correct as an *export* format at the `mvmd` boundary later.

**BuildKit/LLB.** Excellent caching and first-class SLSA provenance, but it is an OCI-native system with a privileged daemon. Making containers the core abstraction contradicts ADR-001's "no Docker/containers on the runtime path". mvm already extracts what it needs from the OCI ecosystem (`mvm_fs::oci`) without adopting its execution model.

**BuildStream.** Artifact-oriented and genuinely good at whole-stack filesystem artifacts, which is the right *shape*. But a Python runtime, a separate remote-artifact-cache protocol, and a small ecosystem make the ownership cost worse than the hybrid for no capability mvm lacks.

**Custom build system.** Rejected. The brief's own checklist is the argument: cache correctness, GC, concurrency, dynamic dependencies, remote execution, cross-platform behaviour. Nix already solves all of them. Note carefully what the recommendation is *not*: the hybrid layer is **not** a build system. It has no dependency graph, no scheduler, no dynamic dependency discovery, and no evaluation language. It is an identity + cache + attestation shim over backends that do the actual building. That is why it is affordable and a custom build system is not.

**Also considered, correctly out of scope:** Guix (same model as Nix, no advantage, worse macOS story), OSTree (Linux-only, wrong artifact shape), apko/melange (APK-based, container-oriented). Worth a mention only for the *idea* apko embodies — declarative, reproducible, from-a-lockfile image assembly with no build step — which `mvm_fs::rootfs::materialize_ext4_pure` already realizes better for this use case.

---

## 5. Proposed architecture

### 5.1 Components

```
┌─ host (trusted) ─────────────────────────────────────────────────────────┐
│                                                                          │
│  mvmctl / mvm-client                                                     │
│      │                                                                   │
│      ▼                                                                   │
│  BuildPlan  ──canonicalize──▶  ActionDigest        [mvm-core::action]    │
│      │                              │                                    │
│      │                              ▼                                    │
│      │                        ActionCache ──hit──▶ AttestationBundle     │
│      │                       [mvm-core::pack_cache, generalized]         │
│      │                              │                    │               │
│      │                            miss                verify             │
│      ▼                              │                    │               │
│  BuildExecutor ─────────────────────┘                    ▼               │
│  [mvm-build]                                    ArtifactManifest ✓       │
│      │                                                   │               │
│      │ 1. FetchAction  (network ON, allowlisted)          │              │
│      │ 2. BuildAction  (network OFF)         ┌────────────┘              │
│      │                                       ▼                           │
│      │                              ContentStore (CAS)                   │
│      │                             [mvm-core::pack_cache]                │
│      ▼                                       ▲                           │
│  canonicalize outputs ──▶ ArtifactManifest ──┘                           │
│      │            [mvm-fs::manifest, extended hash.rs]                   │
│      ▼                                                                   │
│  Attestor  ──sign(action_digest → artifact_digest)──▶ AuditEmitter       │
│  [mvm-hostd::host_signer]                        [chain-signed log]      │
│                                                                          │
└──────────────────────────┬───────────────────────────────────────────────┘
                           │ vsock (typed control plane, mvm-builderd)
┌──────────────────────────▼───────────────── build guest (UNTRUSTED) ─────┐
│  inputs/     read-only, digest-pinned                                    │
│  toolchain/  read-only, digest-pinned                                    │
│  scratch/    writable, discarded                                         │
│  out/        writable, declared outputs only                             │
│  NO signing key. NO network device during BuildAction.                   │
└──────────────────────────────────────────────────────────────────────────┘
```

### 5.2 Trust boundaries

| Boundary | Rule |
|---|---|
| Host ↔ build guest | vsock only. The guest never holds a signing key, never reaches the trust store, never writes the CAS. This matches the existing supervisor model (`mvm-hostd`) exactly. |
| CAS blob ↔ trust | A CAS blob is trusted **for its bytes only**, verified by recomputing its digest. It carries no claim about what produced it. |
| Action-cache entry ↔ trust | An entry claims "action A produced artifact B". That claim is worth exactly the signature over it, plus whatever the signer's evidence is worth. |
| Signer | Host-side only, `~/.mvm/keys/host-signer.ed25519` mode 0600, existing `mvm_hostd::host_signer`. Unchanged. |
| Independent rebuild | The only evidence that upgrades "a builder said so" to "two independent builders agree". Recorded as `ReproducibilityStatus::Reproduced` (`packs.rs:286-290` — the enum already exists). |

### 5.3 The fetch/build split (the one real posture change)

Today `nix build` runs inside the builder VM with `trusted_build_egress()` == `unrestricted()`. To satisfy "normal build actions should be able to run with networking disabled", split into two actions:

- **`FetchAction`** — network **on**, restricted to the existing `PRODUCTION_HOSTNAMES` allowlist over the vsock-brokered proxy (`egress_proxy/allowlist.rs:59-72`), and it is the *only* action permitted to produce new CAS blobs from the network. Every fetched blob is hash-verified against a lockfile pin before admission (the pattern `stage0.rs` and `kernel_fetch.rs` already implement). Its output is a **seeded Nix store closure** — which `builder_pack.rs` already supports as a first-class pack file ("the optional seeded Nix store closure (a `nix-store --export` NAR)").

- **`BuildAction`** — network **off**, `NetworkPolicy::deny_all()`, `--offline` Nix evaluation against the pre-seeded store.

This is not speculative: the seeded-closure mechanism exists (see the memory of Plan 213 SP3 and `builder_pack.rs`'s closure file), and the ADR-007 "contributor path doesn't download" rationale already argues for it. The change is to make the offline build the *default* for a `--release`-profile build and to make the fetch a distinct, separately-attested action rather than an ambient capability.

**Honest caveat:** getting `nix build` fully offline for an arbitrary user flake requires a complete pre-seeded closure, which requires an evaluation to know. The realistic staging is: (a) evaluate with network on in a `FetchAction`, capturing the closure; (b) realize with network off in a `BuildAction`. Only (b) is hermetic-by-construction; (a) is hermetic-by-pinning (`flake.lock` + hash verification). Both facts must be recorded in the attestation, and the release profile must refuse a build whose fetch phase resolved anything unpinned. Claiming more than this would be exactly the over-claim `xtask check-no-overclaim` exists to prevent.

### 5.4 Action and artifact lifecycle

1. CLI constructs a `BuildPlan` (inert canonical data — no code, no evaluation).
2. Host canonicalizes it and computes `ActionDigest`.
3. Host looks up `ActionCache[action_digest]`.
   - **Hit:** verify the attestation signature; verify the recorded `artifact_digest` is present in the CAS; **recompute** the artifact digest from the stored bytes (verify-on-read, fail closed, evict on mismatch — plan 276 S3). Return. *No Nix, no VM, no compiler.*
   - **Miss:** continue.
4. Materialize inputs + toolchain into the guest read-only from the CAS.
5. `FetchAction` if needed (network on, allowlisted, every blob hash-pinned).
6. `BuildAction` (network off) over the typed vsock control plane.
7. Host canonicalizes the declared outputs → `ArtifactManifest` → `artifact_digest`.
8. Host writes blobs to the CAS via the existing quarantine + atomic-rename publish.
9. Host signs `(action_digest, artifact_digest, materials, policy_digest, evidence_digest)` → `AttestationBundle`.
10. `ActionCache[action_digest] := attestation`.
11. `AuditEmitter` appends `build.attested` to the chain-signed log.

Steps 8–10 are the existing `pack_cache::promote` flow with an added key. Step 11 is the existing audit emitter with an added entry type.

### 5.5 Local now, distributed later

Everything above is local-only and needs nothing from `mvmd`. The seams that make distribution possible later without rework:

- `ContentStore` and `ActionCache` are traits, with the local filesystem impl first. A remote impl is additive.
- The attestation records `builder_identity` + `build_environment_identity` (already fields on `PackProvenance`), so a remote worker's claims are distinguishable from the local host's.
- The action digest is host-computed and platform-explicit, so a remote worker cannot influence its own cache key.
- Trust policy is per-signer: a local dev host may accept its own unsigned/self-signed dev attestations while requiring a release key for `--prod`. `LocalPackPolicy` (`packs.rs:352-360`) already carries `allowed_channels` for exactly this shape.

---

## 6. Data formats and APIs

### 6.1 Action digest

```
action_digest = SHA-256(
  "mvm.action.v1\0"                       // domain separator + schema version
  ‖ field("plan",       JCS(BuildPlan))   // canonical, inert data
  ‖ field("inputs",     input_merkle_root)
  ‖ field("toolchain",  toolchain_merkle_root)
  ‖ field("platform",   PlatformId)
  ‖ field("env",        JCS(declared_env))
  ‖ field("policy",     execution_policy_digest)
)
```

`field(tag, v)` is the existing `fold_field` shape from `build_cache.rs:196-203` — `tag ‖ \0 ‖ len_le_u64 ‖ \0 ‖ value ‖ \0`. It is already correct (tagged and length-delimited, so no two field sequences can alias). Reuse it verbatim rather than inventing a new framing.

**In the digest:** the canonical build plan; input and toolchain Merkle roots; the target platform triple + ABI + the *declared* CPU feature baseline (never the host's detected features); every declared environment variable; the sandbox/network policy digest; the schema version.

**Deliberately out of the digest:** wall-clock time; the output paths' absolute location; the builder's hostname; resource limits that do not change output (cpu count, memory — *unless* the build is known parallelism-sensitive, in which case parallelism must be declared and pinned); log content; the attestation signature; anything the guest can influence.

**Environment variables.** Default **deny**: only variables named in the plan are passed, each with a declared value. `PATH` is constructed from the toolchain root, not inherited. `TZ=UTC`, `LC_ALL=C`, `SOURCE_DATE_EPOCH` pinned. An undeclared variable present in the caller's environment is dropped, and its *presence* is not hashed (so a developer's shell cannot move the cache key). This is stricter than Nix's default and matches what `mvm-core::config`'s hermetic-`HOME` discipline already enforces for tests (`xtask check-test-home-isolation`).

**Dynamic dependencies.** Reject, do not model. If a build discovers a dependency at execution time, the action was under-declared and its digest is a lie. Detect it structurally: the `BuildAction` has no network, and the only readable inputs are the digest-pinned read-only mounts, so a dynamic fetch fails rather than silently succeeding. Nix's own fixed-output derivations are the escape hatch, and they are already hash-pinned — they map to `FetchAction`.

### 6.2 Artifact digest and the output Merkle model

```
artifact_digest = SHA-256("mvm.artifact.v1\0" ‖ JCS(ArtifactManifest))

ArtifactManifest {
  schema_version: u32,
  root: TreeNode,           // Merkle: dir node commits to sorted child (name, digest) pairs
}

TreeNode =
  | File   { name_bytes, mode: u16, size: u64, content: Sha256Hex, xattrs: [(k, Sha256Hex)] }
  | Dir    { name_bytes, mode: u16, children: [(name_bytes, node_digest)] }   // sorted by name_bytes
  | Symlink{ name_bytes, target_bytes }
  | HardLinkTo { name_bytes, target_path_bytes }   // second and later links, canonical first-link order
```

**Normalization decisions — state them, gate them:**

| Property | Decision |
|---|---|
| Path | Relative to the declared root. Raw bytes, never lossy UTF-8 (keep `os_str_bytes`, `hash.rs:104-113`). No `.`/`..` components — **rejected**, not normalized. |
| Unicode | **No normalization.** Bytes are the identity. (Deliberately *unlike* `WorkloadAddress`, which NFC-normalizes because it addresses *meaning*; an artifact tree addresses *bytes*.) Document the asymmetry explicitly. |
| Case | Preserved. A tree built on a case-insensitive host that would collide on ext4 is **rejected at manifest time**, not silently merged. |
| Mode | Preserved, masked to `0o7777`. |
| uid/gid | **Normalized to 0** and not represented — matching `ext4/mod.rs:1044-1046`. Guest-visible ownership comes from the image, not the builder's account. |
| Timestamps | **Excluded.** Matching the ext4 writer's zeroed times. |
| xattrs | **Represented**, sorted by key, value hashed. This is required: `security.capability` is load-bearing (`mvm_fs::rootfs::XattrPolicy::GuestSemantic`), and the OCI materializer already falls back to the builder VM specifically for trees carrying it. |
| Hard links | Represented. First link in sorted order is the `File`; later links are `HardLinkTo`. |
| Sparse files | Not represented — logical content only. Sparseness is a storage property, not identity. |
| Device / socket / FIFO | **Rejected by default**, with an explicit opt-in that represents `(major, minor)`. Reuse `UnsupportedNodePolicy` (`rootfs.rs:23-37`) rather than `hash.rs`'s silent skip. |
| Ordering | Children sorted by raw `name_bytes`. |

Making it a **Merkle tree** rather than the current flat manifest buys incremental identity: an unchanged subtree's digest is reusable, which matters for a rootfs where most of the tree is a stable Nix closure.

### 6.3 Canonical representation and digest algorithm

**Use JCS (RFC 8785) everywhere, via one implementation.** The repository already has two conformant realizations locked together by `canonicalizer_equivalence.rs`. The plan and pack/bundle manifests currently do not use either. Converging on one canonicalizer:

- removes the "declaration order is the signature payload" hazard in `bundle.rs:104-106` and `packs.rs:150-152`;
- gives the Lean spec (§8) a single object to model;
- makes cross-language SDK conformance free (the IR path already relies on it).

**Caveat that must be recorded, not papered over:** `serde_jcs` 0.1.0 sorts object keys by UTF-8 byte order, not RFC 8785's UTF-16 code-unit order, so astral-plane keys diverge from a strictly conformant implementation (`workload_address.rs:19-26`). Every new manifest schema should therefore constrain keys to ASCII, which sidesteps the divergence entirely and is enforceable with a `deny_unknown_fields` + fixed-key schema.

**SHA-256, single axis.** Plan 276 WS0 already pins this and the reasoning holds: `Sha256Hex` is a workspace-wide newtype, `digest_shape::validate_sha256_prefixed` is the one shape validator, and the audit chain, OCI digests, dm-verity, bundle hashes, pack hashes, and `plan_id` all agree. BLAKE3 would be faster for large-tree hashing but a second axis is a real cost (dual-hashing every artifact, or a migration) for a benefit that §3 does not show as a bottleneck. **Recommendation: SHA-256 only. Revisit only if H4 becomes the dominant cost after H1/H2 are fixed.**

**Domain separation.** Every digest gets a `"mvm.<kind>.v<n>\0"` prefix. This is the one thing the existing digests are inconsistent about: `build_cache.rs:86` does it (`mvm-workload-build-fingerprint-v1\0`), `content_id.rs` does not, `hash.rs` does not. Without it, a manifest and a plan that happen to serialize identically address identically — the schema-confusion attack in §9.

**Schema migration.** Bump the version *inside* the domain separator. All prior keys become unreachable — a clean, total cache miss, never a silent reinterpretation. Never migrate a cache key in place.

### 6.4 Rust seams

Placement follows the existing dependency direction (`mvm-cli` → `mvm-runtime` → `{mvm-fs, mvm-net, mvm-build}` → `mvm-core` → `mvm-contract`).

| Proposed | Home | Relationship to existing code |
|---|---|---|
| `BuildPlan`, `Material`, `ExecutionPolicy` | `mvm-contract::build` | New DTOs, `no_std`+alloc, `deny_unknown_fields`. Siblings of `plan::` types. |
| `ActionDigest`, `ArtifactDigest` | `mvm-core::action` | New newtypes joining the taxonomy in `workload_address.rs:28-41`. **No `From`/`Into` to `WorkloadAddress`, `CheckpointDigest`, `OciDigest`, `Sha256Hex`, or `KeyId`.** |
| `ArtifactManifest`, `TreeNode` | `mvm-fs::manifest` | Extends `hash.rs`. Shares the walk with `rootfs::collect_nodes` — **one walk implementation**, per the repo's reuse rule. |
| `ContentStore` (trait) | `mvm-core::pack_cache` | Generalizes the existing promote/resolve pair. |
| `ActionCache` (trait) | `mvm-core::pack_cache` | New; replaces `build_cache::{read,write}_cached_revision`. |
| `AttestationBundle` | `mvm-core::packs` | `PackManifest` + an `action` field. Reuse `SignatureBundle`, `PackInputs`, `PackProvenance`, `ReproducibilityStatus`, `SbomReference`, `TransparencyLogReference` **unchanged**. |
| `BuildBackend` (trait) | `mvm-build` | `NixBackend` (existing `dev_build` path) and `OciBackend` (existing `oci_to_rootfs`) as the first two impls. |
| `BuildExecutor` | `mvm-build` | The orchestration above; wraps the existing `BuilderVm` trait. |
| `PolicyVerifier` | `mvm-core::policy` | Consumes `ExecutionEvidence`; returns a typed verdict. **This is the Lean target.** |
| `Attestor` | `mvm-hostd::host_signer` | Existing signer, one new request type. |

Per the repository's binding conventions: `BuildPlan` and `ExecutionPolicy` get **builders**, not positional constructors; backend variation is a **trait with impls**, never a `match` at call sites; and no function acquires enough parameters to trip `too_many_arguments` (which is banned outright).

### 6.5 Operational concerns

| Concern | Approach |
|---|---|
| Concurrent writers | Content-addressed writes are idempotent. Quarantine dir + atomic `rename` is already the publish primitive (`pack_cache.rs:33-40`). Two writers racing produce identical bytes; the loser's rename is a no-op. |
| Duplicate work suppression | An in-process `HashMap<ActionDigest, Shared<Future>>`, plus an advisory lock file for cross-process. Deliberately advisory: a lost race costs duplicate work, never a wrong result. |
| Interrupted builds | Nothing is published until the atomic rename. Quarantine dirs are named `<pid>-<counter>` and reaped by `mvmctl cache prune`. **Fix the existing `.staging-*` leak in `dev_build.rs` at the same time** — 15 orphans were observed on this host. |
| Partial downloads | Never admitted: verify-then-rename. Already the pattern in `kernel_fetch.rs:32-45` (delete on mismatch). |
| GC and pinning | Extend `mvmctl cache prune`. Pin roots: any artifact referenced by a live VM, a template's `current` symlink, or a plan inside the audit retention window. Mark-and-sweep over the action cache → artifact → blob graph. Action-cache entries are *not* roots; they are reconstructible. |
| Log storage | Logs are CAS blobs; `evidence_digest` in the attestation binds them. Logs are **never** in the action digest. |
| Offline verification | `mvmctl trust verify <artifact>` recomputes the manifest, checks the attestation signature against the local trust store, and checks the chain-signed audit entry — all with no network. `verify_audit_chain` already works this way. |
| Export / import | The `.mvmpkg` bundle format already does this (`bundle.rs`). Extend its manifest with the action digest; the archive layout is unchanged. |
| Cache portability | Portable by construction — content-addressed keys with no absolute paths. The trust decision (do I accept this signer?) is what does not travel, and that is correct. |

### 6.6 Making the warm path fast

Measured floor: ~150 ms of tree hashing (§3.1). To make a no-op build feel instant:

1. **mtime+size+inode memo** for file hashes, keyed under `MVM_HOME`. Standard, safe against everything except a same-second same-size content change — for which a `--no-cache` escape and a nanosecond-resolution mtime check are adequate. Nix, Bazel, and git all do this.
2. **Merkle subtree reuse** — an unchanged directory's digest is reusable without descending.
3. **One walk, not two.** In a source checkout the user flake is inside the workspace; hash once.

Expected result: no-op fingerprint in the low tens of milliseconds. **[inference]** — must be confirmed by the criterion bench in §3.5.

---

## 7. Rootfs, template, and snapshot identity

### 7.1 Separate artifact classes

Each of these gets its **own manifest and its own attestation**, because each has a different reproducibility claim:

| Class | Reproducible? | Attestation claim |
|---|---|---|
| Source tree | Yes | "these bytes, this pin" |
| Toolchain tree | Yes | "these bytes, this pin" |
| Build output tree | Yes | "action A produced these bytes" |
| Complete rootfs (ext4) | **Yes** — `materialize_ext4_pure` is byte-deterministic for a given (tree, options) pair (`rootfs.rs:12-14`) | "tree T + options O produced this image, roothash R" |
| Kernel / initrd | Yes (pinned upstream + hash-verified) | "this pinned artifact" |
| MVM template | Yes | "this rootfs + this config" |
| **Memory/device snapshot** | **No** | see §7.2 |
| Launchable machine bundle | Composite | "these components, this config" |

### 7.2 Snapshots are not reproducible artifacts

**A memory snapshot must never be treated as a reproducible software artifact.** It is content-addressable (the store already does this — `snapshot_store.rs:1-33`), which is a completely different property. A snapshot captures:

- entropy pool state and seeded PRNGs;
- the guest clock and any derived timers;
- machine-id, boot-id, and any generated identity;
- DHCP leases and network state (less relevant here — mvm's posture is vsock-only, `NetworkMode::None` by default);
- **credentials and secrets in memory**, including anything the broker delivered;
- open file handles, page cache, and in-flight I/O;
- guest-agent session state and any negotiated keys.

Recommended model:

1. **Address it** — `SnapshotDigest`, its own newtype, in the taxonomy, with no conversion to `ArtifactDigest`. The existing store gives this for free.
2. **Bind it, don't reproduce it.** A snapshot attestation asserts *lineage*: "captured from artifact A, under runtime config C, at plan P's `snapshot_at` trigger". `ExecutionPlan.snapshot_at` is already part of the signed contract (`execution_plan.rs:87-93`) — the capture point is admitted, not host-chosen. That is the right foundation.
3. **Set `ReproducibilityStatus::NotChecked` and never `Reproduced`.** The enum already exists; use it honestly. An over-claim gate (plan 276 WS2) should make "reproducible snapshot" unwritable in claim prose.
4. **Scrub list before capture** (must be specified and tested, not assumed): re-seed `/dev/urandom` on restore; regenerate machine-id/boot-id per child; zeroize any broker-delivered secret material (the `zeroize` discipline already exists — `zeroize_drop_zeros_secret_bytes` is a claim-13 witness); drop the agent's session keys and force re-handshake; refuse capture if the plan carries `secrets` bindings unless an explicit scrub attestation is produced.
5. **Fork lineage is already hash-chained.** Checkpoint lineage is content-addressed and hash-linked with fail-closed behaviour on a tampered parent (`crates/mvm-core/src/checkpoint.rs:29-41`). Snapshot attestation should reuse that spine rather than invent one.

The residual honest statement: **a snapshot's integrity is verifiable; its contents are not attestable as secret-free without a scrub step whose completeness is itself an assumption.** Say that, and gate `--prod` snapshot reuse behind an explicit acknowledgement.

---

## 8. Attestation and verification design

### 8.1 Use interoperable formats — as an export, with an internal native form

**Internal:** the extended `PackManifest`. It already carries everything SLSA v1 provenance needs and it is already signed, verified, cached, and revocation-checked. Replacing it with in-toto would be a rewrite for no capability gain.

**External:** emit **in-toto Statement v1 wrapped in DSSE**, with a `https://slsa.dev/provenance/v1` predicate, on `mvmctl bundle publish` and on release. Mapping:

| in-toto / SLSA field | mvm source |
|---|---|
| `subject[].digest.sha256` | `artifact_digest` (and per-file digests from `ArtifactManifest`) |
| `predicate.buildDefinition.buildType` | `https://mvm.dev/buildtypes/nix-flake/v1` \| `.../oci-image/v1` |
| `predicate.buildDefinition.externalParameters` | canonical `BuildPlan` |
| `predicate.buildDefinition.internalParameters` | `ExecutionPolicy` + platform |
| `predicate.buildDefinition.resolvedDependencies` | `PackInputs` — already exactly this shape (`packs.rs:191-199`) |
| `predicate.runDetails.builder.id` | `PackProvenance::builder_identity` |
| `predicate.runDetails.builder.version` | `build_environment_identity` |
| `predicate.runDetails.metadata.startedOn` | `build_timestamp` |
| *(mvm extension)* `mvm.actionDigest` | `action_digest` — the field SLSA has no slot for |
| *(mvm extension)* `mvm.evidenceDigest`, `mvm.reproducibility` | `ExecutionEvidence` digest, `ReproducibilityStatus` |

**Signer placement:** host-side, always. `mvm-hostd::host_signer` for local/dev; Sigstore keyless for release — `SignatureFormat::Sigstore` and `KeylessTrust` already exist (`packs.rs:309-314, 370-374`), and `TransparencyLogReference` is already a field. Note the operational dependency recorded in memory: cosign ≥ 2.4 for the current bundle format.

**SBOM:** `SbomReference { uri, sha256 }` already exists and the app-deps volume already emits CycloneDX (`sbom.cdx.json`) with a CVE sidecar. Reference it from the attestation; do not inline it.

### 8.2 The assurance ladder — say the level, never more

This is the section the brief is most insistent about, and it deserves to be stated as a ranked ladder that maps onto the code:

| Level | What it proves | mvm mechanism |
|---|---|---|
| 0. CAS blob | These bytes hash to this digest. **Nothing about origin.** | `pack_cache` verify-on-read |
| 1. Action-cache entry | *Someone* recorded "A produced B". Worthless unsigned. | `ActionCache` |
| 2. Signed builder claim | A holder of key K asserts "A produced B under policy P". Trust = trust in K + K's honesty. | `SignatureBundle` |
| 3. + policy-compliant evidence | The host observed the execution and found no policy violation. Trust additionally = trust in the monitor's completeness. | `ExecutionEvidence` + `PolicyVerifier` |
| 4. + independent reproduction | Two independently-keyed builders produced the same `artifact_digest`. A single dishonest builder can no longer forge the binding. | `ReproducibilityStatus::Reproduced` |

**A content hash is level 0 and nothing more.** "Content-addressed" is not a synonym for "reproducible" and not a synonym for "provenance-backed". The `workload_address.rs:28-41` module docs already make this argument for workload addresses; the same discipline must be applied to build artifacts. Claim prose should be gated: plan 276 WS1's `tier:` field and WS2's over-claim verb gate are the right instruments, and this ladder gives them a vocabulary.

### 8.3 Cache verification rules

On every action-cache hit, in order, each step fail-closed:

1. Attestation signature verifies against a trusted key for the current profile.
2. Attestation is unexpired and unrevoked (`PackRevocationChecker` exists).
3. `attestation.action_digest == requested action_digest` — **exact, not prefix**.
4. Every referenced blob exists in the CAS.
5. **Recompute** each blob's digest from its bytes and compare (verify-on-read).
6. `--prod` only: `reproducibility == Reproduced` with ≥2 distinct signer identities.

Mismatch at 3–5 ⇒ **evict and rebuild**, and emit an audit entry — a mismatch is a tamper/skew signal, not a cache miss, and it should be visible. Absence of a hash must never fall back to trusting the path (plan 276 S3).

**Cross-tenant dedup is a leak (plan 276 S2).** A shared address confirms two tenants hold identical content, and an address fingerprints known content. Key the CAS within the existing per-tenant boundary. On a single-user local host this is vacuous; it is load-bearing the moment `mvmd` shares a store.

### 8.4 Independent rebuild policy

- **Dev profile:** `NotChecked`. No rebuild required. Fast, honest, and labelled.
- **Release profile:** at least one independent rebuild whose `artifact_digest` matches, with a distinct signer. Non-matching digests are a **release blocker** and both manifests are retained for diffing.
- Rebuild divergence is a first-class finding, not a flake to retry. The repository already runs a reproducibility double-build (claim 7, W5.3); this extends it from "the workspace builds twice the same" to "the artifact reproduces under a different builder identity".

---

## 9. Lean 4 recommendation

> **Convergent prior art.** `specs/research/uor-hologram-cross-project-recon.md`
> §9 landed independently while this investigation was running, and reaches the
> same verdict from the audit-verifier side: model the small `no_std` verifier
> plus the canonicalization/address algebra as a Lean *specification*, make the
> Rust verifiers conform over a golden-vector corpus, and hold the honest
> boundary that Lean proves the **verifier and address algebra** sound — **not**
> that builds are hermetic (an operational property discharged by the sandbox,
> the nix pins, and the reproducibility double-build) and **not** SHA-256
> collision resistance. It also prices the work as a bounded spike on one
> target rather than a proof lane. That framing is authoritative; this section
> adopts it and adds only the *build*-side pieces — the manifest-construction
> theorems in §9.2 and the Kani-before-Lean ordering in §9.3.

### 9.1 Verdict

**The starting hypothesis is correct, and I recommend it — with one narrowing and one addition.**

> Lean should prove the soundness of a small build-result verifier and policy checker once; each build supplies ordinary canonical evidence checked quickly. Lean should not do per-build theorem proving.

**Narrowing:** do not compile the production verifier from Lean, and do not adopt Aeneas-style extraction on day one. Both add a bootstrap dependency and a binary-size cost for a component that must run on every cache hit inside a latency budget measured in milliseconds.

**Addition:** Lean's *highest-value output in phase 1 is not a proof at all — it is a golden-vector corpus.* An executable Lean model of the canonicalizer and manifest builder generates the `(input → expected digest)` vectors that the Rust implementation is differentially tested against. That is plan 276 WS3 exactly, with a mechanized oracle instead of a hand-frozen one. It delivers value before any theorem is proved, and it is the artifact the proofs later attach to.

**Phase: 2, not 1.** Ship the architecture first. Lean attaches to a stable spec; attaching it to a moving one wastes the proof effort.

### 9.2 First proof target (narrowly scoped)

Two theorems about `ArtifactManifest` construction. Chosen because they are small, self-contained, mechanically checkable, and cover the two failure modes that would silently corrupt every downstream guarantee.

```lean
-- 1. No declared path escapes its root.
theorem manifest_paths_confined
    (root : Path) (tree : HostTree) (m : ArtifactManifest)
    (h : buildManifest root tree = .ok m) :
    ∀ p ∈ m.paths, root.IsPrefixOf (root.join p) ∧ ¬ p.HasParentComponent

-- 2. Every accepted entry appears exactly once.
theorem manifest_entries_unique
    (root : Path) (tree : HostTree) (m : ArtifactManifest)
    (h : buildManifest root tree = .ok m) :
    m.paths.Nodup ∧ ∀ e ∈ tree.accepted, ∃! n ∈ m.nodes, n.path = e.path
```

Then, once `PolicyCompliant` is pinned to a deliberately small predicate:

```lean
theorem verify_sound (plan : BuildPlan) (result : ActionResult) :
    verify plan result = true → PolicyCompliant plan result
```

where `PolicyCompliant` asserts exactly four things and nothing more: (a) the recomputed action digest equals the plan's; (b) the recomputed artifact digest equals the attested one; (c) the evidence records no network egress during the `BuildAction` window; (d) every declared output path is confined to the declared root. Resisting the urge to make `PolicyCompliant` say more is the whole discipline — a large predicate is a large lie surface.

Ordering by leverage after those: closure-validation completeness (no referenced dependency omitted); action-vs-content identity non-confusion (the domain-separation theorem — a manifest digest can never equal a plan digest); canonicalization injectivity (`JCS(a) = JCS(b) → a ≡ b` for the restricted ASCII-key schema).

### 9.3 Implementation strategy

**Lean as specification + oracle; Rust as implementation; differential testing as the bridge.**

1. Model `BuildPlan`, `ArtifactManifest`, canonicalization, and `verify` in Lean 4 with `mathlib` only where genuinely needed.
2. Prove the theorems above.
3. Compile the Lean model to a **development-time** executable (`lake build`), never shipped.
4. That executable generates the golden-vector corpus — including Unicode edge cases, deep nesting, path-traversal attempts, duplicate entries, astral-plane keys.
5. Corpus is committed and consumed by a `nextest` test in `mvm-core`/`mvm-fs`, plus the `no_std` verifier and the riscv32 edge verifier (plan 276 WS4's multi-oracle bar).
6. Production verifier stays **safe Rust**, `forbid(unsafe_code)`, no new runtime dependency.

**Why not the alternatives:**
- *Lean-compiled production verifier:* bootstrap dependency, binary size, and a Lean runtime in the launch path. Not worth it for a millisecond-budget check.
- *Aeneas / Creusot / Prusti on the Rust directly:* strictly better in principle — proofs about the shipped code, not a model. But all three have real limits on the Rust this codebase writes (trait objects, iterators, `serde` derive), and the verifier would have to be written to suit the tool. **Revisit for the `PolicyVerifier` alone** once it is stable and small; it is the one component whose shape might suit Creusot.
- *Kani (bounded model checking):* genuinely complementary and much cheaper. **Recommend it for phase 1** on the parsers and the path-normalizer, where bounded exhaustive checking over small inputs catches the realistic bugs. Kani now, Lean later, is the right order.
- *Dafny / Coq / Isabelle:* Dafny would mean a third language for a verifier that must be Rust. Coq/Isabelle are viable but Lean 4's compilation story (which is what makes the oracle approach work) is better, and Lean's mathlib momentum lowers the proof-engineering cost.
- *TLA+:* wrong level. It models concurrent protocols, not data-structure invariants. It *would* be the right tool for the concurrent-publish/GC protocol (§6.5) if that ever grows non-trivial.

### 9.4 Trusted computing base

Everything below is **assumed**, not proved:

- SHA-256 collision resistance; Ed25519 unforgeability.
- Correctness of `sha2`, `ed25519-dalek`, `serde`, `serde_json`, `serde_jcs`.
- Completeness and correctness of the host's execution monitor — *the largest and least examinable assumption.*
- The OS/hypervisor actually enforces the sandbox (guest isolation, read-only mounts, absent NIC).
- Signing-key confidentiality (`~/.mvm/keys/host-signer.ed25519`, mode 0600) — and note that on a developer laptop this is protected by filesystem permissions alone.
- Lean's kernel, compiler, and runtime (for the oracle path, only the *generated vectors* need be trusted, which is a much weaker assumption than trusting a Lean-compiled verifier).
- Rust `unsafe` at the boundaries — `mvm-contract` is `forbid(unsafe_code)`, and `mvm-net`/`mvm-client` have been converted, but the FFI layers (`libkrun-sys`, `mvm-host-services-ffi`) are not.
- The compiler compiles correctly (unaddressed by anything here — this is a diverse-double-compilation problem).

### 9.5 What Lean cannot prove

- **That the build ran at all.** Lean proves properties of a verifier over evidence. It cannot prove the evidence describes reality.
- **That the monitor observed every event.** A monitor gap is invisible to a proof about what the monitor reported. This is the single most important limitation and it should be stated wherever the attestation is described.
- **That an arbitrary compiler compiled the source correctly.** Out of scope for anything short of CompCert-class work.
- **That a signing key was not compromised.** Cryptography assumes key secrecy; proofs inherit the assumption.
- **That the sandbox held.** A hypervisor escape invalidates every downstream claim.

### 9.6 A hazard worth naming explicitly

**Do not let Lean projects become the build-recipe format.** Evaluating or building Lean code executes code — elaboration is Turing-complete and `#eval` runs arbitrary programs. A build plan must stay **inert canonical data** (JSON/CBOR conforming to a fixed schema) that is *parsed*, never *evaluated*. Lean models the schema and the checker; it is never the input language. This is the same reason `--impure` Nix evaluation is a hazard in the current build path and why the `FetchAction`/`BuildAction` split matters.

### 9.7 Cost estimate

| Item | Estimate |
|---|---|
| Lean model of canonicalizer + manifest builder | 2–3 weeks (one engineer, Lean-familiar) |
| The two manifest theorems | 2–4 weeks |
| `verify_sound` with a small `PolicyCompliant` | 4–8 weeks |
| Oracle → golden-vector generation + CI wiring | 1 week |
| **Per-build verification cost** | **Zero.** No Lean at runtime. |
| Shipped binary size impact | **Zero.** |
| Developer workflow impact | Low — Lean is a dev-time gate, like `cargo-fuzz` (already release-tag/nightly-only, so the precedent and the CI shape exist). |
| Bootstrap concern | Lean toolchain in CI only; contributors never need it. |
| Policy/schema upgrade cost | **Real and recurring.** Every schema change invalidates proofs. This argues for a *small, stable* `PolicyCompliant` and for deferring Lean until the schema settles. |

**Recommendation: Kani in phase 1 (cheap, immediate, on parsers and the path normalizer). Lean in phase 2 as spec + oracle. Never Lean at runtime.**

---

## 10. Threat model

| # | Threat | Prevention | Detection | Evidence retained | Residual assumption | Recovery |
|---|---|---|---|---|---|---|
| T1 | Malicious build guest | No signing key in guest; no network in `BuildAction`; read-only inputs; host canonicalizes outputs | Output manifest recomputed host-side | `ArtifactManifest`, evidence | Hypervisor isolation holds | Rebuild; revoke builder identity |
| T2 | Malicious source archive | Digest-pinned inputs; allow-listed unpacker (`mvm_fs::oci::unpack`, already fuzzed) | Hash mismatch at fetch | Fetch attestation | Pin was correct when made | Re-pin; audit downstream artifacts |
| T3 | Path traversal / symlink escape | `..` rejected (not normalized); symlink targets recorded but not followed; `ensure_safe_path` exists (`bundle.rs:775`) | Manifest build fails | Rejection log | **Lean theorem 1 target** | Reject the artifact |
| T4 | Undeclared inputs | Network off; only pinned read-only mounts readable | Build fails for lack of the input | Evidence | Monitor completeness | Declare and re-run |
| T5 | Environment-variable leakage | Default-deny env; `PATH` constructed, not inherited | Cache-key divergence across hosts | Declared env in action digest | Nothing else reads the ambient env | Narrow the declaration |
| T6 | Nondeterminism (clock, RNG, locale, readdir order, uid) | `SOURCE_DATE_EPOCH`, `TZ=UTC`, `LC_ALL=C`, sorted walk, uid/gid→0, timestamps zeroed | Independent rebuild mismatch | Both manifests | Unenumerated sources exist | Diff manifests; fix the source |
| T7 | Unauthorized network access | `NetworkPolicy::deny_all()` during `BuildAction`; vsock-only data plane | Evidence records any connect attempt | Evidence digest | Monitor sees all egress paths | Fail the build; investigate |
| T8 | Dependency substitution | `flake.lock` + `PackInputs.nar_hashes` + allowlisted fetch | Hash mismatch | Fetch attestation | Upstream pin integrity | Re-pin; rebuild |
| T9 | **Cache poisoning (today's live hole)** | *Currently: 0700 dir permissions only.* Proposed: signed action-cache entry + verify-on-read | **Currently: none.** Proposed: digest recompute on hit | Proposed: eviction audit entry | Local-account compromise = game over regardless (the signer key is co-located with the cache) | **Milestone A: corruption/skew detection locally; T9 supply-chain closure only once key custody is separated (mvmd shared-store or hardware key)** |
| T10 | Malicious action-cache mapping | Signature over `(action, artifact)`; exact action-digest equality | Signature/equality check | Attestation | Signer honesty (→ T15) | Evict; distrust signer |
| T11 | Corrupted / truncated CAS data | Verify-on-read | Digest mismatch | Eviction entry | — | Evict + refetch |
| T12 | TOCTOU between hash and use | Immutable CAS (content-addressed, never rewritten); atomic rename publish; verify at point of use | Digest mismatch at use | — | Filesystem honours rename atomicity | Evict |
| T13 | Compromised builder identity | Per-profile trust; `--prod` requires ≥2 identities | Reproduction mismatch | Both attestations | ≥2 builders not jointly compromised | Revoke; rebuild everything signed by it |
| T14 | Compromised signing key | 0600 host-only; keyless/Sigstore + transparency log for release | Transparency-log monitoring | Rekor entry | Key custody | Revoke (`PackRevocationChecker`); re-sign |
| T15 | Replay / rollback | Validity windows + nonce ledger (existing, claim 8); attestation expiry | Nonce replay refusal | Audit chain | Ledger persistence | Refuse admission |
| T16 | Schema confusion | Domain separator + schema version in **every** digest | Prefix mismatch | — | Separators are actually distinct | Bump version |
| T17 | Cross-tenant cache leakage | Per-tenant CAS partition (plan 276 S2) | Audit review | Audit entry | Partition is correctly keyed | Repartition |
| T18 | Secret leakage into outputs / logs / snapshots | Secrets never enter the guest (claim 13, host-side egress substitution); snapshot scrub (§7.2) | Trace secret scan (`commands/build/trace_secret_scan.rs` exists) | Scan report | Scanner recall | Purge + rotate |
| T19 | Unsafe tar/OCI/NAR extraction | Allow-listed unpacker; `ensure_safe_path`; existing fuzz targets | Rejection | Rejection log | Unpacker correctness (fuzzed, not proved) | Reject |
| T20 | Concurrency race / partial publish | Quarantine + atomic rename | Never observable | — | Rename atomicity | — |
| T21 | Compromised remote `mvmd` worker | Host recomputes the artifact digest from returned bytes; worker identity distinct | Digest mismatch; reproduction mismatch | Both attestations | — | Distrust worker; rebuild |

**T9 deserves emphasis.** Today, anything that can write `~/.mvm/dev/builds/<rev>/rootfs.ext4` can cause a subsequent `mvmctl up` to boot substituted bytes. The 0700 permission on `~/.mvm` means this requires the user's own account — so it is not a privilege-escalation vector — but it *is* a persistence and supply-chain vector (a compromised dev tool, a malicious `cargo` build script, a bad `npx`), and the audit log will faithfully record the substituted digest as if it were legitimate. Milestone A makes this **detectable** (recompute-on-read, fail closed) and cache hits self-consistent — the strongest *local* argument for prioritizing it. But note the ceiling: on a single-user host the host signer key (`~/.mvm/keys/host-signer.ed25519`, 0600) lives in the same account that can write the cache, so a local attacker can read the key, forge a valid signature over substituted bytes, and pass verify-on-read. Signing therefore *closes* T9-as-supply-chain only once the signer sits outside the workload's account — the `mvmd` shared-store trust topology, or hardware-backed key custody (ADR-001 lists hardware attestation as out of scope). **[inference]**

---

## 11. Reproducibility policy

Two named profiles. The distinction that matters: **which optimizations preserve reproducibility and which merely improve iteration while lowering assurance.**

### Development profile — `ReproducibilityStatus::NotChecked`

| Optimization | Preserves reproducibility? |
|---|---|
| Warm/persistent builder VM | **Yes** — same inputs, same sandbox; only boot cost is amortized |
| Local CAS + action cache with verify-on-read | **Yes** — verified content |
| Merkle subtree reuse | **Yes** — pure hashing optimization |
| mtime-keyed hash memo | **Mostly** — sound modulo same-second same-size edits |
| Incremental compilation (`cargo` incremental, `sccache`) | **No** — output depends on prior state |
| Persistent compiler servers | **No** — same reason |
| Lazy materialization | **Yes** — changes when, not what |
| Network **on** during build | **No** — the build is not hermetic |
| Unsigned / locally-signed results | **No assurance change to bytes**, but the *claim* is weaker; must be labelled |

Dev results are labelled `dev-evidence`, are never promoted to a release channel, and `LocalPackPolicy::allowed_channels` (`packs.rs:352-359`) is the existing mechanism to enforce that.

### Release profile — `ReproducibilityStatus::Reproduced` required

Mandatory: clean policy-pinned execution; digest-pinned inputs and toolchains; **network disabled for `BuildAction`**; normalized metadata (uid/gid 0, timestamps zeroed); full output rehashing (no memo shortcuts); signed provenance with a release key or keyless identity; verified runtime evidence; SBOM linkage; **≥1 independent rebuild with a matching `artifact_digest` under a distinct signer identity**.

Forbidden in release: incremental compilation, compiler servers, mtime memos, network during build, `MVM_SKIP_HASH_VERIFY` (already documented as emergency-only and never in CI), `MVM_BUILD_STUB_OUTDIR`, `MVM_NO_BUILD_CACHE` masking a genuine failure.

The profile is part of `ExecutionPolicy` and therefore inside the action digest — a dev-profile artifact and a release-profile artifact of the same source have **different action digests** and cannot alias in the cache. This mirrors the existing `BuildMode::{Dev,Prod}` fold at `build_cache.rs:93`.

---

## 12. Phased migration plan

No flag day. Each milestone is independently useful and independently revertible.

### Milestone A — Verified, typed build cache *(the smallest thing worth doing)*
**Delivers:** cache hits self-checking (recompute-on-read, fail closed) — closes the corruption/skew class outright; closes T9 supply-chain substitution *only where the signer key is not co-located with the cache* (mvmd shared-store or hardware-backed custody). On a single-user local host it raises the bar but the key stays forgeable by a local-account attacker (§10).
- Introduce `ActionDigest` newtype in `mvm-core::action`; `workload_build_fingerprint` returns it (add the domain separator; this is a **cache-key break** — accept the one-time miss, do not migrate).
- Replace `read/write_cached_revision` with an `ActionCache` recording `{action_digest → {revision, artifact digests, signature}}`.
- Verify-on-read on every hit: recompute each artifact's SHA-256, fail closed, evict on mismatch, emit an audit entry.
- Fix the `.staging-*` leak.
- **Files:** `crates/mvm-build/src/pipeline/{build_cache,dev_build}.rs`, new `crates/mvm-core/src/action/`.
- **Compatibility:** additive; old plaintext records are ignored (cold miss).
- **Rollback:** `MVM_NO_BUILD_CACHE=1`.
- **This is plan 276 WS6**, done properly.

### Milestone B — Narrow the Nix source filter
**Delivers:** the H2 latency win. Independent of A.
- `nix/lib/workspace-filter.nix` → path allowlist.
- Mirror in `build_cache.rs`; **rewrite the soundness test in the superset direction**.
- **Rollback:** revert one file.

### Milestone C — `ArtifactManifest`
**Delivers:** backend-independent artifact identity.
- `mvm-fs::manifest` with mode/xattr/hardlink/device coverage, Merkle-structured, domain-separated.
- Share the walk with `rootfs::collect_nodes`.
- `hash.rs::hash_source` becomes a thin adapter (snapshot store unaffected).
- Golden vectors including Unicode and traversal cases.
- **Depends on:** nothing. **Enables:** D, E.

### Milestone D — Attestation
**Delivers:** signed action→artifact binding.
- Extend `PackManifest` with `action_digest` + `evidence_digest`.
- Host signs on build completion; `AuditEmitter` emits `build.attested`.
- `mvmctl trust verify <artifact>`.
- **Depends on:** A, C.

### Milestone E — Fetch/build split
**Delivers:** genuinely network-free build actions.
- `FetchAction` (allowlisted) vs `BuildAction` (`deny_all`).
- Seeded closure via the existing `builder_pack` closure file.
- **Depends on:** A, D. **Highest risk** — validate on QEMU/Linux first.

### Milestone F — OCI backend on the same identity
- `mvmctl run --image` emits the same `ArtifactManifest` + attestation.
- Folds claim 14 into the general model.
- **Depends on:** C, D.

### Milestone G — Reproducibility gate
- Release CI performs an independent rebuild; `ReproducibilityStatus::Reproduced` required for release-channel promotion.
- **Depends on:** D, E.

### Milestone H — Lean phase
- Kani on parsers + path normalizer (can start any time — genuinely independent).
- Lean model → oracle → golden vectors → theorems.
- **Depends on:** C, D stable.

### Milestone I — `mvmd` seam (design only)
- `ContentStore`/`ActionCache` remote impls; builder identity federation; optional REAPI export.
- **Explicitly not implemented in `mvm`.**

**Avoiding frontend lock-in:** at no point does `mvm` depend on Buck2, Bazel, BuildKit, or Nix *as a library*. `BuildBackend` is a trait; Nix is one impl invoked as a subprocess inside the builder VM (which is already true and already gated — `xtask check-no-host-nix`).

---

## 13. Proof-of-concept plan

**Scope:** one flake, one host, no `mvmd`, no Lean, no fetch/build split. Validates that the hybrid layer delivers the latency and integrity claims.

**Target:** `examples/python/hello-app-with-deps` (already exercised by the `app-deps-audit` CI lane).

**Deliverables** (all under `/tmp` or as a scratch branch; nothing merged):
1. `BuildPlan` for the target, canonicalized and printed.
2. `action_digest` printed, stable across runs, changing on a source edit and not on a `specs/*.md` edit *(this last assertion fails today — that is the point of the PoC)*.
3. Inputs imported into a CAS under an isolated `MVM_HOME`.
4. Build via the existing `dev_build` path, unmodified.
5. `BuildAction` with `NetworkPolicy::deny_all()` — *stretch; document if it cannot be reached without Milestone E*.
6. `ArtifactManifest` + `artifact_digest` over `~/.mvm/dev/builds/<rev>/`.
7. Artifact in the CAS.
8. Host-signed attestation.
9. Cache hit with **zero** Nix and **zero** VM boot, proved by the absence of any builder-VM process and by `cached: true` in the `--json` output.
10. Independent rebuild in a second isolated `MVM_HOME`; compare `artifact_digest`.
11. Cold / warm / no-op / cache-hit latency via §3.5.

**Acceptance criteria:**

| # | Criterion |
|---|---|
| AC1 | `action_digest` byte-identical across 5 runs with no source change |
| AC2 | A one-byte edit under `crates/` changes it; an edit under `specs/` does **not** (post-Milestone-B) |
| AC3 | Cache-hit path spawns no VM process and no `nix` process |
| AC4 | Cache-hit wall clock **< 250 ms** on this host (target < 100 ms after the §6.6 memo) |
| AC5 | Flipping one byte in a cached `rootfs.ext4` makes the next hit **fail closed** and evict — with a red-proof recorded in `specs/VERIFICATION.md` |
| AC6 | Tampering with the attestation signature ⇒ rejection before any artifact byte is read |
| AC7 | Independent rebuild yields the same `artifact_digest`, **or** the divergence is diagnosed and documented (a negative result here is a finding, not a failure) |
| AC8 | An artifact-tree `chmod +x` changes the manifest digest (regression against the `hash.rs` gap) |

**Failure cases to exercise deliberately:** truncated CAS blob; action-digest prefix collision attempt; symlink escaping the output root; duplicate path entries; a device node in the output tree; a non-UTF-8 filename; an astral-plane path component.

**Explicitly out of scope:** production wiring, `mvmd`, REAPI, Lean, snapshot attestation, any change to the dm-verity chain.

---

## 14. Open questions

Only questions that genuinely cannot be settled from the repository or a safe local experiment.

1. **How much of the observed build latency is Nix evaluation vs. realization vs. VM boot?** The doc comment says "tens of seconds" but there is no measurement in the repository. §3.5 resolves this; it needs a run, not more reading.
2. **Can `nix build` be made fully offline for an arbitrary user flake with a pre-seeded closure?** The mechanism exists (`builder_pack` closure file, plan 213 SP3), but whether it covers arbitrary user flakes — as opposed to the builder VM's own known closure — is unvalidated. Milestone E depends on the answer.
3. **Does `materialize_ext4_pure` reproduce byte-identically across macOS and Linux hosts for the same input tree?** The writer is deterministic by construction, but the *walk* reads host filesystem metadata (mode, xattrs), and APFS vs ext4 differ on case sensitivity and xattr namespaces. This is testable but has not been tested cross-platform.
4. **What is the acceptable dev-profile trust posture for unsigned local attestations?** Requiring a signature for every local build adds ceremony; not requiring one weakens T9's defence. My inclination is to always sign with the existing auto-provisioned host key (it costs microseconds and the key already exists), but this is a product decision.
5. **Should the semantic/artifact Unicode asymmetry be documented as intentional or converged?** `WorkloadAddress` NFC-normalizes; the artifact manifest should not. Plan 276 S5 defers the NFC decision; this proposal takes a position (asymmetry is correct) that the owner should ratify or overrule.
6. **Is there an appetite for a Lean toolchain in CI at all?** The cost is real and recurring. If the answer is no, the golden-vector corpus should be hand-frozen (plan 276 WS3 as written) and §9 reduces to "Kani only".

---

## Appendix A — Constraint compliance

| Constraint | Status |
|---|---|
| Security / isolation / auditability over convenience | **Met.** Every proposed mechanism fails closed. |
| No SSH in production | **Met.** Nothing here touches interactive access. |
| Guest networking not required for compilation | **Not a violation — a deliberate tier choice:** the builder is ADR-001 Tier-2 (claim-10 egress enforcement is not wired there), so `trusted_build_egress() == unrestricted()` is by design. Milestone E proposes a **stricter release-build posture** (an offline build phase) on top — a tightening, not a fix. |
| Existing trusted transport (vsock/UDS) | **Met.** Uses the existing typed vsock control plane unchanged. |
| No signing keys in an untrusted guest | **Met.** Host-side signer only; explicitly stated as non-negotiable. |
| Inputs/toolchains digest-pinned, read-only | **Met** by design; partially true today (Stage-0 seed and kernel are pinned; the workspace mount is not read-only). |
| Outputs traceable to complete inputs and policies | **Met** post-Milestone D. Today `BuildProvenance` is traceable but not enforcing. |
| No flag-day migration for Nix templates / OCI inputs | **Met.** Nine independently-revertible milestones; Nix stays a supported backend throughout. |
| Local-first, clean `mvmd` path, no cross-repo churn | **Met.** Milestones A–H are `mvm`-only; I is design-only. |
| Warm/no-op/cache-hit extremely fast | **Addressed.** §3 separates orchestration cost from compiler cost; §6.6 targets the warm floor. |
| macOS/Linux differences identified | **Partially.** Case sensitivity, xattr namespaces, and reflink support (APFS clonefile vs. XFS/btrfs) differ; open question 3 flags the untested part. |
| Never discard unrelated worktree work | **Met.** Read-only investigation; this file is the only addition. |
