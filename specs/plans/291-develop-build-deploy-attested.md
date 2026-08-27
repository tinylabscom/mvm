# Develop → build → deploy: one stupidly simple path to an attested workload image

**Status:** Complete. WS1–WS3 are merged and their required queue gates are
green; WS4 now has the runtime tier boundary, universal guest-agent artifact,
and conformance witnesses. The persistent-OCI console-listener hardening is
merged as PR #2157.

**Goal:** A developer starts from an OCI image or a Nix flake, iterates on a
machine until the workload actually works — including discovering the
dependencies it needs — and then runs one command that seals, hashes, and
records the result as an attested image. If a remote (`mvmd`) is configured,
authenticated transport is required before it can be shipped; until that
contract exists, the developer still ends up holding a sealed, recorded
artifact locally.

## Why this plan exists

The pieces are mostly built and hard to see. The risk is not that this is
difficult — it is that someone rebuilds machinery that already ships, or that
"sealed" keeps meaning three different things.

## What already exists (do not rebuild)

| Capability | Where |
|---|---|
| OCI **and** Nix flake as workload bases | the existing build pipeline; both already unify |
| Declared dependencies, with **hash-pinned lockfiles enforced** | `mvm_sdk::compile::deps::validate_lockfiles` — `uv.lock`, `yarn.lock`, and friends; any entry lacking an integrity hash is rejected |
| Sealed dependency volume: SBOM, CVE scan, hash-chained `meta.json` | `mvm_sdk::compile::deps_audit::{seal_volume, reseal_volume, verify_sealed_volume, derive_volume_hash}` (claim 11) |
| Admission-time refusal of a tampered dep volume | supervisor admission verifier |
| Workload content address | `mvmctl build address` (workload address + `ir_hash`) |
| Image + environment pinned into the signed plan | `SignedImageRef`, `EnvironmentRef` |

**`reseal_volume` is the capture primitive.** Installing a package inside a dev
sandbox and then resealing produces a new volume hash, a refreshed SBOM, and a
fresh CVE scan for free. The security-sensitive half of "capture what I
installed" is already written; what is missing is the loop around it.

## What "sealed" means, stated once

The word currently carries three jobs. They must be separated or this stays
confusing:

1. **Image contents** — whether console/exec are compiled into the agent.
   *This distinction goes away.* One image, always the same bytes.
2. **Run tier** — whether a given run may be interacted with.
   *Follows from the admitted run and, once available, its attestation — not
   from image bytes.*
3. **Attestation** — the image is hashed, recorded, and traceable.
   *This is what `deploy` produces, and it is not going away.*

So sealing is **not** removed and **not** a build variant. It becomes an
attestation over a fixed image: same bytes, now hashed and recorded.

## Addressing: BLAKE3 for identity, SHA-256 for interop

`blake3` is already a workspace dependency, so this adds nothing new to the
tree.

- **BLAKE3 is the mvm-native artifact address.** It is a tree hash, so it
  supports verified streaming and incremental verification — a large rootfs can
  be verified in part without reading all of it. That directly serves
  verify-on-read and content-addressed reuse. SHA-256 cannot do this.
- **SHA-256 stays wherever the outside world specifies it**, and cannot be
  replaced: OCI registry digests (`sha256:…`), cosign signatures, and in-kernel
  dm-verity, which has no BLAKE3 support and therefore keeps claim 3's roothash
  on SHA-256.

A deployed artifact therefore carries **both**. This is the σ/κ distinction plan
276 already formalised, not a new concept. The rule, stated once: **BLAKE3 is
identity, SHA-256 is interop, and anything that pins a digest says which it
means.** A single unlabelled "hash" field anywhere in the deploy record is a
bug.

## Workstreams

### WS1 — `mvmctl deploy`

- [x] Seal the built image, compute its BLAKE3 identity, and write a deploy
      record: workload address (`ir_hash`), image BLAKE3, image SHA-256, the
      environment pin, sealed dep-volume hash, and the SBOM/CVE verdicts already
      produced by claim 11's pipeline.
- [x] If a remote is configured, use the authenticated shipping contract. Until
      mvmd exposes that contract, fail closed after writing the local record;
      without a remote, stop at the local sealed artifact.
- [x] Refuse to record an artifact whose dep volume fails
      `verify_sealed_volume`, so a deploy cannot launder a tampered volume.
      The SDK path and tamper regression are covered by the merged PR's branch
      and merge-group Test, Lint, and Nix gates.

The control-plane split is settled: sealing, hashing, and recording remain
artifact construction in mvm; authenticated shipping, tenants, and placement
remain mvmd responsibilities. `mvmctl deploy` performs the former and delegates
the latter through mvmd's authenticated upload contract.

### WS2 — `mvmctl watch`

- [x] Watch the workload source and rebuild the image on change.
      The file-backed IR watcher polls local source inputs and invokes the
      existing deterministic compiler when the input fingerprint changes.
- [x] Reuse the existing content addresses to skip no-op rebuilds: if the
      `ir_hash` and inputs are unchanged, do nothing.
- [x] Surface what changed and what it cost, so the loop teaches the developer
      what their workload actually depends on.
      Each iteration reports whether it rebuilt or found an unchanged state;
      rebuilds identify whether IR or source inputs changed and report compile
      duration in milliseconds. Long-running watches keep polling after a
      transient input or compile error and retry when the fingerprint changes;
      `--once` remains fail-fast for automation.

### WS3 — capture dependencies from the sandbox

- [x] `mvmctl deps capture` imports a sandbox-installed dependency tree and
      its fresh SBOM, fetch log, and CVE result, then reseals it atomically
      through the existing volume verifier and lockfile index.
- [x] Install into a development sandbox, then reseal via `reseal_volume` to
      capture it — new volume hash, refreshed SBOM, fresh CVE scan. The SDK's
      existing development `install_package` helpers perform the install;
      `mvmctl deps capture-live` requires a running development VM, exports
      bounded regular-file content and matching guest sidecars, and hands them
      to the atomic reseal path. `mvmctl deps install` covers the declared
      lockfile route.
- [x] Emit the captured set back out as the canonical dependency declaration
      the developer can commit,
      so an interactively-discovered dependency becomes a declared one. The
      capture path must converge on the declared path, not fork from it. The
      capture command verifies the supplied lockfile bytes against the sealed
      SHA-256 and emits the same `Dependencies` IR shape used by normal builds.
      It refuses declaration targets that would overwrite the lockfile or
      enter the sealed dependency cache.
- [x] Keep the lockfile hash-pin requirement intact: a captured dependency is
      pinned like a declared one, or the seal refuses.

**The opencv case, end to end:** the developer either declares it (works today)
or installs it in the sandbox and lets WS3 capture it. Both routes end at the
same sealed, hash-pinned, CVE-scanned volume.

### WS4 — the tier follows the attestation

- [x] Make the agent-verb grant depend on the admitted run shape rather than
      the image sidecar: a baked-entrypoint boot on a non-dev profile receives
      ProdSafe verbs; a PTY or ad-hoc argv receives DevOnly verbs.
- [x] Make the run tier come from whether the run uses an attested artifact,
      not from a build variant and not from an unattested CLI flag. Local
      `mvmctl machine run --deployment DIR` now verifies the signed deploy
      record and exact `rootfs.ext4`, persists the canonical deployment
      directory, and revalidates it on restart. Remote record extraction and
      boot are merged; the cross-path acceptance matrix is complete and
      tracked child issues #2144 and mvmd #208 are closed.
- [x] Keep host-side console listeners aligned with the run profile: persistent
      OCI boots pre-open the console data range only for `dev`, while sealed
      production boots expose no host-side console listeners (PR #2157).
- [x] Retire the `interactive` Cargo feature fork so one agent binary serves
      both tiers; the existing `RequestClass::{ProdSafe, DevOnly}` gate and the
      signed `VerbGrant` already do the enforcement.
- [x] Replace the symbol-absence CI witnesses with conformance scenarios
      asserting an attested run refuses DevOnly verbs. Note that those
      symbol-grep jobs live in `security.yml`, which does not run on pull
      requests, so a conformance scenario in the PR-gating suite is stronger
      than what it replaces, not weaker. The universal-agent runtime-boundary
      lane and grant-enforcement unit prove that a complete ProdSafe grant
      refuses the complete DevOnly request set.

## Non-goals

- Changing what claim 11 already guarantees about dependency volumes.
- Replacing SHA-256 where OCI, cosign, or dm-verity specify it.
- Moving tenant lifecycle or placement out of mvmd.

## Sequencing

WS1 is independently useful and unblocks the rest, because the deploy record is
what the WS4 tier signal reads. The run-shape prerequisite landed early so the
grant no longer depends on an image artifact bit. WS2 is standalone and WS3
converges on WS1's sealed record. WS4 now completes the path: one universal
agent artifact, with runtime profile and signed grant deciding whether DevOnly
requests are reachable.
