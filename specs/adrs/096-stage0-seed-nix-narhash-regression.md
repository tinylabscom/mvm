# ADR-096 — Stage 0 seed Nix (2.31.1) computes divergent flake narHashes; fresh-machine builder-VM build is broken

**Status:** Proposed — **decision needed** (do not merge a fix from this doc; this is the write-up + the question)
**Relates:** [ADR-071](071-stage0-bootstrap-trust-model.md) (Stage 0 seed Nix is URL+SHA-256 pinned), [ADR-093](093-linux-builder-libkrun-fallback.md) (builder auto-fallback — why this stays masked), Plan 160 (the nix-seed Stage 0 cutover that introduced the seed version).

## Symptom

On a machine **without a warm builder-VM cache**, the very first
`mvmctl machine run --image <oci>` (and any builder-VM build) fails: the Stage 0
bootstrap's `nix build path:/work/nix/images/builder-vm#packages.<arch>.dev`
exits 1 with:

```
error: mismatch in field 'narHash' of input
  '{"__final":true,"lastModified":1778430510,
    "narHash":"sha256-Ti+ZBvW6yrWWAg2szExVTwCd4qOJ3KlVr1tFHfyfi8Q=",
    "owner":"NixOS","repo":"nixpkgs",
    "rev":"8fd9daa3db09ced9700431c5b7ad0e8ba199b575","type":"github"}',
  got
  '{… "narHash":"sha256-hOlf/RVFs9vVyapFtW6+/jp209mi+UAat/cqa2hrc+Y=" …}'
```

Both builder backends fail it (vz first, then the ADR-093 libkrun fallback), so
the log shows two failures. The command can still *appear* to succeed — see
"Why it's masked".

## Why it's masked (and how it was found)

It was observed on a macOS-26 dev box where `mvmctl machine run --image alpine`
still printed its output. That only worked because the ADR-093 builder fallback,
after both rebuilds failed, reused a **pre-existing cached `rootfs.ext4` +
`vmlinux`** under `~/.cache/mvm/builder-vm/<arch>/`. The narHash check is
input-deterministic (it fails on every evaluation, independent of cache), so the
failure is real — a clean machine has no cached image to fall back to and the
command fails. The on-disk failed job
(`~/.cache/mvm/builder-vm/jobs/<id>/{cmd.sh,result,nix-stderr.log}`) is the
clean-build attempt.

## Evidence / root cause

Same nixpkgs **rev** (`8fd9daa3…`) and same **lastModified**, but a **different
narHash** depending on the Nix version computing it:

| Who | nixpkgs narHash for rev `8fd9daa3` | Agrees with the lock? |
|---|---|---|
| repo flake.locks (generated ~2026-05-15, `c05f5666`) | `sha256-Ti+ZBvW6…` | — (this *is* the lock) |
| **Stage 0 seed Nix 2.31.1** (the builder bootstrap) | `sha256-hOlf/RVFs9…` | **NO** |
| Nix 2.34.7 (an independent modern Nix) | `sha256-Ti+ZBvW6…` | **YES** |

So the **locks are correct** (a modern Nix 2.34.7 agrees with them); the
**Stage 0 seed Nix 2.31.1 is the outlier** — it computes a divergent flake-input
narHash for the identical source tree. Same rev + same lastModified + different
narHash ⇒ a Nix-version narHash-*computation* difference, not a content change.

**Timeline.** The flake.locks date to ~2026-05-15. Plan 160 cut Stage 0 over to
a pinned **`nix-2.31.1`** seed on 2026-06-05
(`crates/mvm-build/src/stage0.rs:61` `NIX_SEED_VERSION = "2.31.1"`, plus the
per-arch URLs + SHA-256). From that cutover onward, the seed Nix's narHash
diverges from the (correct) locks, so **every fresh builder-VM build on `main`
has been broken since ~2026-06-05**, masked by warm caches.

This is **not** caused by any in-flight bridge/Plan-209 work — it's pre-existing
on `main` and touches no bridge code.

## Affected

All four flake.locks pin the same nixpkgs rev with the same `Ti+ZBvW6` narHash:
`nix/flake.lock`, `nix/images/builder-vm/flake.lock`,
`nix/images/runtime-overlay/flake.lock`, `nix/images/default-tenant/flake.lock`.
(The `builder-vm` and other locks also carry a `microvm` input whose narHash was
locked by the same older Nix — see open question 3.)

## Options

1. **Bump the Stage 0 seed Nix off 2.31.1 to a version whose narHash matches the
   locks (e.g., 2.34.7, verified above).** Update `stage0.rs`
   `NIX_SEED_VERSION` + both per-arch URLs + SHA-256 pins (ADR-071 trust anchor)
   + the stage0 tests that assert the version. **This is the likely-correct
   fix** — it aligns the seed with the (correct) locks and modern Nix.
   - Pro: locks, CI, and modern Nix already agree on `Ti+ZBvW6`; only the seed is
     wrong. Built artifacts are unchanged (same nixpkgs rev), so dm-verity
     roothashes (claim 3) and image-hash manifests (claim 6) are unaffected.
   - Con: it's a bootstrap **trust-anchor** change (new pinned SHA-256s); needs
     the right tarball hashes for both arches and a clean-build verification.
2. **Re-lock the flakes with Nix 2.31.1 (so the locks carry `hOlf/RVFs9`).**
   **Rejected** — it makes the locks match the anomalous seed but mismatch
   modern Nix 2.34.7, CI's Nix, and anyone else's toolchain; it spreads the bug
   instead of fixing it.
3. **Revert Stage 0 to the pre-Plan-160 bootstrap.** Not viable — Plan 160
   deliberately removed the Alpine/apk path; the nix-seed is the only Stage 0
   path now.

## Open questions (the decision)

1. **Which Nix version do we bump the seed to?** 2.34.7 is verified to match the
   locks and is a real upstream release; is that the target, or the latest
   stable at fix time (confirm its narHash matches the locks before pinning)?
2. **Is 2.31.1's divergence a known upstream Nix bug** (so *any* 2.31.x seed is
   unsafe), or specific to 2.31.1? Worth a quick upstream check so we pick a
   version on the right side of the fix.
3. **Does the *in-builder runtime* Nix also diverge?** The seed Nix builds the
   builder-VM image; the resulting builder VM then runs *its own* Nix (from the
   pinned nixpkgs `nixos-25.11`, rev `8fd9daa3`) for subsequent in-VM builds
   (dev-image / default-microvm). If that runtime Nix is also 2.31.x, those
   later builds would diverge on *their* locks too — meaning bumping only the
   seed is insufficient and we'd also need to bump the nixpkgs pin or override
   the in-image Nix package. **Needs verification** (what Nix does rev
   `8fd9daa3` ship, and does it compute `Ti+ZBvW6` or `hOlf/RVFs9`?).
4. **Regression gate?** Should CI assert the Stage 0 seed Nix and the committed
   flake.locks agree on narHash (a cheap check that would have caught this at the
   Plan 160 cutover), so a future seed bump can't silently break fresh installs?

## Verification plan (once a direction is chosen)

On the Hetzner x86_64 KVM box (or any clean Linux KVM host): build `mvmctl` with
the bumped seed, **clear `~/.cache/mvm/builder-vm/`**, run
`mvmctl machine run --image alpine -- echo hi`, and confirm the builder-VM image
builds from scratch (no narHash error) and the workload boots. Cross-check that a
built artifact's hash is unchanged vs. a warm-cache build (claims 3/6).
