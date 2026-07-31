# SDK sidecar release acquisition — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give an end-user running a downloaded `mvmctl` a published, hash-verified SDK-sidecar artifact, so a workload whose signed plan binds an SDK-served host service boots instead of refusing.

**Why this exists.** Plan 266's WS-3 follow-up landed the whole decision → verify → attach → mount chain, and it fails closed by design: a bound SDK host service with no resolvable sidecar refuses the launch. On a source checkout that is fine — the refusal names `nix build ./nix/images/runtime-overlay#sdk-sidecar-image`. On a downloaded `mvmctl` there is nothing to run: `mvm-build` has no sidecar acquisition module, and no release workflow publishes a `sdk-sidecar` asset. The runtime overlay already solved exactly this problem; this plan mirrors it rather than inventing a second mechanism.

**Architecture:** The sidecar becomes a fifth per-arch release artifact set alongside the runtime overlay's, published by `release.yml`, fetched and integrity-verified by a new `mvm_build::sdk_sidecar` module that mirrors `mvm_build::runtime_overlay`'s download path, and reached from the existing `resolve_sdk_sidecar_attachment_for_host` seam.

**Tech Stack:** Rust (`mvm-build`, `mvm-cli`), the existing `curl_download` / `fetch_expected_hashes` / `verify_file_sha256` helpers in `crates/mvm-build/src/runtime_overlay.rs`, `mvm_fs::sdk_sidecar` for post-install verification, GitHub Actions (`.github/workflows/release.yml`).

## Global Constraints

- The artifact set is exactly what `mvm_fs::sdk_sidecar::SdkSidecarResolver::resolve` already verifies: `sdk.ext4`, `VERSION`, `checksums-sha256.txt`. Do not add files the resolver does not check, and do not change the resolver's contract to accommodate the transport.
- Fail closed everywhere. A missing archive checksum, a hash mismatch, an unsafe archive entry, or a post-install `resolve` failure aborts with `Err`. There is no degraded attach — the guest would hit an unactionable `dlopen` failure.
- Reuse `runtime_overlay`'s integrity helpers (`fetch_expected_hashes`, `curl_download`, `verify_file_sha256`, the `MVM_SKIP_HASH_VERIFY` escape hatch) rather than writing a second downloader. If a helper needs to be shared, lift it — do not copy it.
- Install atomically: stage under `cache_root` and rename into `<cache_root>/sdk-sidecar/<version>/<arch>/`, so a mid-install crash never leaves a partially-overwritten cache entry. Mirror `install_overlay_into_cache`.
- `MVM_SKIP_HASH_VERIFY=1` stays the single documented emergency escape, never set in CI.
- No `Plan N` / `ADR-\d+` / `#NNNN` / `W\d.` tokens in code or code comments (CI `check-no-spec-refs-in-comments`).
- Rust: never `#[allow]` a clippy lint; `rustup run nightly cargo fmt --all` before push; `cargo nextest run --workspace --no-fail-fast -j 6` before push (full parallelism flakes the process-spawning suites).
- No `Co-Authored-By: Claude` trailer and no AI-tool attribution in commits or the PR body.

---

### Task 1: Publish the sidecar as a per-arch release artifact

**Files:**
- Modify: `.github/workflows/release.yml` — add an `sdk-sidecar-image` job mirroring `runtime-overlay-image` (line ~424).

**Interfaces:**
- Produces: `sdk-sidecar-<arch>.tar.gz` + `sdk-sidecar-<arch>.tar.gz.sha256` release assets, per arch, whose tarball contains `sdk.ext4`, `VERSION`, and `checksums-sha256.txt`.
- Consumes: `./nix/images/runtime-overlay#packages.<system>.sdk-sidecar-image`, which already emits exactly those three files.

- [x] **Step 1: Add the release job**

Copy the `runtime-overlay-image` job's shape (same `if:`, same aarch64/x86_64 matrix and runners, same `nix-installer-action`) and swap the flake attribute and file list. The `sdk-sidecar-image` derivation already writes `checksums-sha256.txt` itself, so — unlike the overlay job — do **not** regenerate it; copy it through and let the archive carry the derivation's own manifest. That keeps the bytes the resolver verifies identical to the bytes Nix produced.

- [x] **Step 2: Assert the asset names match the Rust side**

The names come from a Rust constructor (Task 2). Add the naming assertion to `tests/release_assets.rs` if that harness exists, or to the `verify-release-assets` pack-gate the Lint job already runs (it reported "11 passed" as of this writing). A mismatch between the workflow's filename and the downloader's expected filename is the failure mode this catches.

---

### Task 2: `mvm_build::sdk_sidecar` — fetch, verify, install

**Files:**
- Create: `crates/mvm-build/src/sdk_sidecar.rs`.
- Modify: `crates/mvm-build/src/lib.rs` — register the module.
- Modify: `crates/mvm-build/src/runtime_overlay.rs` — make `fetch_expected_hashes`, `curl_download`, `verify_file_sha256`, and `SKIP_HASH_VERIFY_ENV` reachable from the sibling module (`pub(crate)` is enough; do not widen to `pub`).

**Interfaces:**
- Produces:
  - `SdkSidecarArtifactNames::for_arch(&str) -> Self` with `archive` / `archive_checksum`, mirroring `RuntimeOverlayArtifactNames`.
  - `download_sdk_sidecar(version, arch, cache_root) -> Result<SdkSidecarArtifact, SdkSidecarBuildError>`.
  - `resolve_or_seed_from_default_cache(&SdkSidecarResolver, GuestArch)` for the cache-hit fast path.
- Consumes: `mvm_fs::sdk_sidecar::{SdkSidecarLayout, SdkSidecarResolver, SdkSidecarArtifact, verify_sidecar_dir_integrity, validate_sidecar_payload}`.

- [x] **Step 1: Write the failing tests first**

In `crates/mvm-build/src/sdk_sidecar.rs`'s `#[cfg(test)] mod tests`, against a local `MVM_SIDECAR_BASE_URL` served from a tempdir (mirror how the overlay download tests stage a release fixture — see `seed_release_fixture` in `crates/mvm-cli/src/commands/vm/up/runtime_source.rs` for the archive-building pattern):

- a well-formed release fixture downloads, installs, and `SdkSidecarResolver::resolve` accepts the result;
- a missing archive-checksum sidecar aborts before the tarball is fetched;
- an archive whose sha256 disagrees with the committed checksum is refused and nothing lands in the cache;
- a tarball entry with a traversal path (`../`) or an absolute path is refused;
- a tarball missing `sdk.ext4` is refused;
- an archive whose inner `checksums-sha256.txt` disagrees with the extracted bytes is refused;
- a crash between stage and rename leaves no partial artifact dir (assert only `.tmp.*` remains).

- [x] **Step 2: Implement against those tests**

Follow `download_runtime_overlay`'s four steps verbatim in structure: fetch the archive checksum, download + verify the archive, safe-extract into canonical filenames, verify the extracted dir, then atomically install. Reuse the overlay's extraction guard rather than writing a second entry validator — if `extract_runtime_overlay_archive`'s allow-list is generalizable, lift it to take the expected file set; if not, say why in a comment and write the sidecar's own with the same refusals.

- [x] **Step 3: Verify after install, not just before**

End with a `SdkSidecarResolver::resolve` call against the installed cache entry and return its `SdkSidecarArtifact`. The transport already checked the archive; this proves the *installed* bytes satisfy the same contract the launch path will enforce, so a transport bug cannot produce a cache entry that only fails later at boot.

---

### Task 3: Reach it from the launch path

**Files:**
- Modify: `crates/mvm-cli/src/commands/vm/up/runtime_source.rs` — `resolve_sdk_sidecar_attachment_for_host`.
- Modify: `crates/mvm-cli/src/commands/runtime_overlay.rs` — or add a sibling — for the acquire-mode decision.

**Interfaces:**
- Consumes: `runtime_overlay_acquire_mode()` / `runtime_overlay_source_checkout_root()`, the existing build-vs-download resolver the overlay uses. The sidecar must make the *same* choice for the same host, so a contributor never silently downloads while their overlay is source-built.

- [x] **Step 1: Write the failing tests**

- a cold cache on a host resolving to `DownloadPublishedArtifact` calls the downloader and attaches the result;
- a cold cache on a host resolving to `BuildFromSourceCheckout` keeps today's behaviour: refuse with the `nix build` instruction, since building the sidecar needs the builder VM and must not happen implicitly inside a launch;
- a warm cache never touches the network (assert with an unreachable base URL);
- the refusal message still names the binding that required the sidecar in both modes.

- [x] **Step 2: Implement**

Mirror `attach_runtime_overlay_if_cached_version`'s ladder: resolve from cache, and only on a miss consult the acquire mode. Keep the existing fail-closed message as the source-checkout arm.

- [x] **Step 3: BDD**

Add a scenario to `features/suites/s21_host_services/sdk_sidecar_attachment.feature`: a workload binding an SDK host service on a host with a published artifact and a cold cache acquires it and boots. Wire it in `crates/mvm-conformance/tests/steps/sdk_sidecar.rs` against a staged local release fixture, not the real network.

---

### Task 4: Docs + rollup

**Files:**
- Modify: `public/src/content/docs/reference/cli-commands.md` — the `--host-service` row's failure sentence, once a download can satisfy it.
- Modify: `specs/adrs/018-mvm-runtime-overlay-disk.md` — the sidecar paragraph's acquisition sentence.
- Modify: `specs/plans/266-lightweight-microvm-guest.md` — tick the deferred entry that points here.
- Modify: `specs/SPRINT.md`, `specs/REFACTOR-STATUS.md`.

- [x] **Step 1: Update all five in the same change as Task 3.** Per the Definition of Done, the plan checkboxes, `specs/SPRINT.md`, and `specs/REFACTOR-STATUS.md` move together; leaving one stale is not done.

---

## Deferred follow-ups (not built in this plan)

- **Cosign-verified sidecar.** The overlay's artifacts are sha256-pinned but not signature-verified at fetch. Extending the `manifest-verify` cosign path to both the overlay and the sidecar is one workstream covering both, and should not be bolted onto the sidecar alone.
- **Sidecar closure minimization.** The 8 MiB allocation is a fixed cap, not a measured floor; the loader + `libc.so.6` + `libgcc_s.so.1` + the cdylib have not been closure-audited the way the base rootfs was. Worth a measurement pass before the cap is treated as tight.

## Self-review

- **Spec coverage:** the gap is exactly "no published artifact, no downloader, no launch-path wiring"; Tasks 1–3 close those three and Task 4 keeps the docs honest.
- **Placeholder scan:** every file path, function name, and line-number anchor above was read from the tree at authoring time. The one value left to execution is the release asset filename, which Task 1 Step 2 pins with an assertion rather than a guess.
- **Fail-closed check:** no task introduces a path where a required sidecar is absent and the launch proceeds. Task 2 Step 3 deliberately re-verifies post-install so the transport cannot widen the launch-time contract.
