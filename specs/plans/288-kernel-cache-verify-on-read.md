# Kernel cache verify-on-read: connect the verification that already exists, and make the unverified read unrepresentable

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax for tracking.

**Status:** WS1–WS3 and WS5 landed; WS4 (shared sidecar helper) open. The 2026-08-10 bootstrap-readiness repair closed the remaining producer interruption gaps and routed the default workload-kernel acquisition through the verified resolver. Completes plan 276 WS6 — its dev-build-artifact half shipped in #2053; this is the kernel half.

**2026-08-11 — WS1's type did not reach two of its callers.** `VerifiedKernel` made the unverified read unrepresentable only for code that resolved through the seam. `cached_kernel_path` stayed public (callers need the location for error messages), and two paths took it and booted on presence: the Firecracker/qemu arm of `mvm_client`'s per-backend resolution, and the CLI's kernel-less-image fallback, which formatted the cache path itself. So the backend carrying real workloads on Linux had the weakest kernel check of any boot route, next to an HVF arm that required a digest match — after this plan's WS1 shipped. Both now resolve through the seam, and WS5's gate is aimed at that shape rather than the one it was originally written for.

**Goal:** No workload or builder kernel is booted from cache without its bytes being checked against a recorded digest. The check must fail closed, evict what it rejects, and be impossible for a future caller to skip by accident.

## The finding this plan exists for

`mvm_build::kernel_fetch::verify_fetched_kernel` already does the right thing: it streams the file, compares against `KernelArtifactId::artifact_hash`, and deletes the file on mismatch. It is correct, it is tested, and it has **zero production callers** — not on the fetch path, not on the read path. Its own doc comment says installed builds "should still [verify] it against the pin before boot", and nothing ever has.

So this is not "write verification". The verification is written. This plan connects it, and then removes the shape that let it drift unconnected.

**Why it drifted, and the durable fix.** `resolve_kernel` returns `KernelResolution::Cached(PathBuf)` whenever `path.exists()`. A bare `PathBuf` is a perfectly usable value, so `resolve_pinned_kernel_with` does the natural thing — `Cached(p) => Ok(p.display().to_string())` — and nothing anywhere signals that a step was skipped. Adding a call at that one site fixes today's bug and leaves the same trap for the next caller. The fix that lasts is to make a path you have not verified **unrepresentable**, per the workspace rule that illegal states should not be constructible.

## Corrections found while implementing

Two of this plan's assumptions were wrong, both in the safe direction:

- **The fetch path already verifies.** `mvmctl`'s `download_kernel` fetches `kernel-<arch>-checksums-sha256.txt`, finds the asset line and compares before admitting the file. WS2's "verify against the published manifest" was already done. What was missing is that nothing *recorded* the result, so no later read had anything to check against.
- **`resolve_kernel` had a second bypass.** `mvm-client`'s HVF path called `cached_kernel_path` + `path.exists()` directly, never touching the resolver. Changing `KernelResolution::Cached` to carry a verified type surfaced the first bypass as a compile error; this one only appeared by grepping, which is an argument for the type carrying further than it currently does.

## Architecture

Five workstreams, each its own PR:

- **WS1** A verified-kernel type: `resolve_kernel` stops handing out bare paths.
- **WS2** Producers record a digest — the download path and the Stage 0 build path.
- **WS3** Consumers verify on read, fail closed, and evict both artifact and sidecar.
- **WS4** Unify with the apple-container sidecar helper instead of growing a second one.
- **WS5** Tests, falsifiability rows, and the CI gate that keeps it connected.

**Tech Stack:** Rust. `mvm_build::kernel_fetch`, `mvm_core::kernel_artifact`, `mvm_cli::update` (`checksums-sha256.txt` parsing), `mvm_runtime::apple_container::artifacts`, `sha2`, `cargo-nextest`, `xtask` gates. **No new dependency, no new hash implementation.**

## What mvm already has (extend, do not rebuild)

- `verify_fetched_kernel(path, &KernelArtifactId)` — streams, compares, deletes on mismatch, honours `SKIP_HASH_VERIFY_ENV`. Needs callers, not authorship.
- `KernelArtifactId { kernel_version, config_hash, artifact_hash }` and `compute_artifact_hash` (SHA-256).
- `cached_kernel_path(cache_dir, arch, variant)` → `<cache>/builder-vm/<arch>/kernels/<variant>/vmlinux`.
- **Precedent A — a per-artifact digest sidecar, already shipped.** `mvm_runtime::apple_container::artifacts` requires a `vmlinux.blake3` beside the kernel and returns a typed `ArtifactUntrusted` when it is absent or mismatched. A fetched kernel is not trusted unpinned. This is the pattern; do not invent a second one.
- **Precedent B — a checksum manifest over a published artifact set.** `checksums-sha256.txt` (`mvm_fs::overlay`, `mvm_fs::initramfs`), parsed by `mvm_cli::update`. This is how a *downloaded* artifact earns its first digest.
- `mvm_core::cache_verify` (#2057 lineage) and the #2053 dev-build cache — the same verify-on-read discipline one layer over.

## Provenance

Plan 276 WS6, second half. Recon §7.1 (`specs/research/uor-hologram-cross-project-recon.md`) reframed integrity-on-read as the one attestation property no surveyed system enforces — verified on write at best, never on read. The kernel cache is mvm's clearest instance: verified on neither.

## Non-goals (do not re-propose)

- **No new hash implementation and no new sidecar format.** Reuse the apple-container sidecar shape (WS4).
- **No signature layer.** A digest sidecar is an integrity control (S1). Authenticity for released kernels is the release-signing path (plan 277), not this plan.
- **No change to dm-verity.** The rootfs roothash chain (claim 3) is untouched; this covers the kernel image only.
- **No kernel config or size work** — that is plan 286, in flight, and must not be entangled with this.
- **No removal of `MVM_SKIP_HASH_VERIFY`.** It stays the documented emergency escape and stays forbidden in CI.

## Security considerations — settle before writing code

- **S1 — this is integrity, not authenticity.** A sidecar written beside an artifact by the same producer detects corruption, truncation, cache skew and accidental substitution. It does **not** defend against an actor who can write both files; ADR-001 puts a malicious host out of scope. Say this in the module doc rather than implying a stronger property — `check-no-overclaim` will bite otherwise, and it should.
- **S2 — a locally built kernel has no published digest.** A source checkout builds via Stage 0 and is never fetched, so there is no upstream hash to compare against. Its sidecar records *what we built*, which makes the read check meaningful (bit-rot, skew, partial write) without pretending to be provenance. Two producers, two provenance stories, one read path.
- **S3 — fail closed, and evict what you reject.** A missing sidecar is untrusted, not "assume fine" — absence of a hash must never degrade into trusting the path. On mismatch, remove **both** the kernel and its sidecar. #2053 landed this lesson on the dev-build cache: evicting only the record leaves the poisoned artifact under a name the next resolve re-adopts.
- **S4 — one axis per artifact, and name the divergence.** `KernelArtifactId` is SHA-256; the apple-container sidecar is BLAKE3. Pick SHA-256 for `kernel_fetch` (it matches `compute_artifact_hash` and the published `checksums-sha256.txt` manifests) and record the apple-container BLAKE3 sidecar as a second axis in the same tree. Do not silently re-hash one into the other. Recon §7.8's σ-set framing is the eventual reconciliation; this plan only has to stop the two from being confused.

## Workstreams

### WS1 — Make an unverified kernel path unrepresentable

- [x] Replace `KernelResolution::Cached(PathBuf)` with a variant carrying a type that cannot be constructed without a successful verification (`VerifiedKernel`, private field, constructor only in `kernel_fetch`).
- [x] `NeedsBuild` / `NeedsFetch` keep bare paths — they are *destinations*, not artifacts to trust.
- [x] The only way to a bootable path is a method on the verified type, so a future caller that skips verification does not compile.
- [x] Compile-fail test pinning that boundary (mirror `apple_container`'s existing compile-fail test for its asserter anchor).

### WS2 — Producers record a digest

- [x] **Fetch path:** after `crate::update::download_kernel`, verify the bytes against the published `checksums-sha256.txt` entry *before* admitting them to the cache, then write the sidecar. This is verify-on-write, which S3's read check then rests on.
- [x] **Build path:** after `build_kernel_via_stage0` produces a kernel, write the sidecar from the bytes just built (S2 — records what we built, claims nothing more).
- [x] Both writes are atomic (temp + rename) so an interrupted producer cannot leave a sidecar that disagrees with the artifact beside it.
- [x] A producer that cannot write a sidecar must not leave the kernel in place — an unverifiable artifact is worse than a missing one, because the next resolve will trust the path.

### WS3 — Consumers verify on read

- [x] `resolve_kernel` verifies before returning `Cached`, via `verify_fetched_kernel` — giving that function the production callers it has never had.
- [x] On mismatch or missing sidecar: fail closed, evict kernel + sidecar, and fall through to `NeedsBuild` / `NeedsFetch` so the next step re-derives rather than re-adopting.
- [x] Update `resolve_pinned_kernel_with` (`crates/mvm-cli/src/commands/vm/up/kernel.rs`) and `mvm_client::local`'s `cached_kernel_path` use to the verified type.
- [x] Log the eviction at warn with the reason — a silent re-download is indistinguishable from a slow one.

### WS4 — One sidecar helper, not two

- [ ] Lift the apple-container digest-sidecar logic (parse `<hex>` or `<hex>  <name>`, typed untrusted error, fail-closed on absence) into a shared helper both call, parameterised by hash axis (S4).
- [ ] `apple_container::artifacts` keeps its BLAKE3 axis and its typed `ArtifactUntrusted`; only the mechanism is shared.
- [ ] Delete the duplicated parse rather than leaving both — a second copy is how the two axes get confused later.

### WS5 — Keep it connected

- [x] Tests: verified-hit boots; tampered kernel rejected + evicted; missing sidecar rejected; **intact-but-wrong kernel** (swap two variants' kernels — both complete, each the other's) rejected; sidecar/artifact mismatch after an interrupted write rejected.
- [x] `specs/VERIFICATION.md` falsifiability rows, each with its planted defect recorded and proved red.
- [x] An `xtask` gate — `check-verified-kernel-reads`, wired into **both** `ci.yml` and `ci-full.yml` Lint jobs. **It does not police what this line asked for**, because that target stopped being the right one: WS3 routed the read path through `verify_cached_kernel` against the sidecar, so `verify_fetched_kernel` legitimately has no production caller and a gate demanding one would fail on correct code. The live risk is the other direction — `cached_kernel_path` is public, returns a usable `PathBuf`, and two call sites took it and booted on `is_file()` *after* WS1 shipped the type that was supposed to prevent exactly that. The gate gives that its evidence: a file naming the cache location must also call `resolve_kernel`. Co-presence per file, not a proof the resolved value is the one used — a type that made the bare path unusable would be stronger, but the location is legitimately needed for diagnostics at the same sites that must not boot from it.
- [x] Confirm `MVM_SKIP_HASH_VERIFY` is absent from every workflow (`rg MVM_SKIP_HASH_VERIFY .github/` — no hits).

## Sequencing

WS1 first — the type change is what makes the rest mechanical and stops the regression recurring. WS2 before WS3, or the first verified read finds no sidecar anywhere and every kernel evicts itself once. WS4 can land any time after WS2. WS5 last, except the falsifiability rows, which land with the workstream they witness.

## Open question for the owner

Whether a **fetched** kernel should additionally require the release signature (plan 277's `mvm_build::release_signature`) rather than only the checksum manifest. It would upgrade the fetch path from integrity to authenticity and close S1's gap for the one producer that actually has an upstream identity to check against. It is out of scope here because it changes the trust story rather than connecting an existing check, and because it should be decided alongside the other release-artifact consumers, not just for kernels.
