# ADR-086 — The mvmctl distribution is a relocatable, dependency-free, signed bundle

**Status:** Accepted — Option A (vendor + sign the VMM ourselves), staged. One pre-merge checklist item remains (see §"Why Option A, and how it's staged")
**Date:** 2026-06-17
**Owner:** MVM Project
**Builds on:** [Plan 199](../plans/199-host-runtime-packaging-and-crate-boundaries.md) (host runtime packaging); [ADR-085](085-bundled-egress-gateway.md) (bundled gateway)
**Touches the trust model:** [ADR-002](002-microvm-security-posture.md) — who builds and signs the in-box VMM
**Preserves:** [ADR-046](046-builder-vm-via-libkrun.md) two-artifact-layers rule; claim 6 (hash-verified download)

## Context

Plan 199 (WS-A done) made the default install a signed release binary / one-line
installer, added an optional Nix host package for `mvmctl`, kept native VMM
linkage explicit and opt-in, and forbade source-checkout builds from downloading
published artifacts. It deliberately stopped short of one thing: vendoring the
VMM so the published artifact is dependency-free.

That is the remaining first-run cliff. On macOS a user must `brew install
slp/krun/{libkrun,libkrunfw,gvproxy}` before `mvmctl` works. The trio is where
we lose the comparison against tools that install with one command and run. The
security substrate behind `mvmctl` is irrelevant to a developer who never gets
past step one — DX is the gate, the substrate is the moat behind it.

The mechanics of a relocatable bundle are well understood and already partly in
our toolbox:

- Ship the CLI, the VMM dylibs, the gateway (ADR-085), the guest kernel, and the
  agent rootfs in one directory.
- Make dynamic linkage load-relative: `$ORIGIN`-relative rpath on Linux
  (patchelf), `@loader_path` install names on macOS. Nothing resolves to a
  system prefix.
- Bake the guest kernel at build time rather than extracting it from the dylib's
  `.rodata` at runtime (today's `extract_bundled_kernel()` path). Runtime
  extraction keeps working; baking is the cleaner bundle shape, not a hard
  requirement.
- Produce the whole thing from one root flake that is *both* the dev shell and
  the release packager, sharing derivations. The end-user Nix consumer derivation
  merely **relocates** the prebuilt signed tarball.

`mvm-cli/build.rs` already cross-compiles and embeds the host-VM binaries; this
ADR extends the same "ship what the runtime needs in the artifact" instinct from
those binaries to the VMM, kernel, and gateway.

This does **not** weaken the source-checkout invariant. Source checkouts still
build every image locally from the in-repo flakes (ADR-046). Only the *published*
artifact is prebuilt — the same posture the GitHub-release prebuilts already
hold. The consumer-relocates-prebuilt path is an end-user path, never a
source-checkout prerequisite.

## Decision

We adopt **Option A** — vendor, pin, build, and sign the VMM ourselves — staged
so the VMM-vendoring is the last, separable step (see §"Why Option A, and how
it's staged").

The published `mvmctl` distribution is a single **relocatable, signed,
dependency-free bundle**. On a supported host the one-line installer drops a
self-contained directory and `mvmctl machine run ...` works with **no
package-manager prerequisites**.

- The bundle vendors: the CLI, the egress gateway (ADR-085), libkrun, libkrunfw,
  the guest kernel (baked at build time), and the agent rootfs.
- Dynamic linkage is load-relative (`$ORIGIN` / `@loader_path`); a wrapper points
  the CLI at the bundled rootfs.
- One root flake builds all components and emits the bundle; its dev shell and
  release packager share derivations. The Nix consumer path relocates the signed
  prebuilt; source checkouts continue to build locally from in-repo flakes.
- The bundle is signed and the installer verifies before install — an extension
  of the existing dev-image hash-verify posture (claim 6), not a new mechanism.

## Why Option A, and how it's staged

The choice was whether to vendor and sign the C VMM (libkrun/libkrunfw)
ourselves, or keep it from the third-party slp/krun Homebrew tap. We vendor it,
for three reasons:

- **The alternative does not solve the problem.** Keeping the VMM on the tap
  leaves `brew install slp/krun/{libkrun,libkrunfw}` in the first-run path — the
  trio becomes a duo, the user still hits a package-manager wall, and the
  zero-to-running metric does not move. A half-open gate is a closed gate.
- **It is a supply-chain upgrade, not a downgrade.** Today we depend on whatever
  version the tap ships: unpinned, mutable, signed by someone else, and a
  `brew upgrade` can silently break our FFI (`extract_bundled_kernel` from the
  dylib `.rodata`, `krun_add_net_unixgram`, the `libkrun-sys` bindings). ADR-002
  already trusts the host with the hypervisor binary; vendoring does not widen
  that boundary, it changes the *origin* to a pinned-rev, reproducible,
  release-key-signed build. Pinned + signed + reproducible beats mutable +
  foreign on every axis the threat model cares about.
- **The VMM-vendoring is the last, separable step**, so committing now is
  low-risk: the expensive machinery (gateway bundle, kernel, rootfs, rpath
  rewriting, signed installer) lands first regardless and proves itself before
  any VMM source is pinned.

**Staging.** Each step ships and is useful on its own. macOS first — the trio
pain is worst there and gateway interop is proven (ADR-085 / ADR-082
§Validation):

1. **Bundle machinery.** Gateway (ADR-085) + kernel + agent rootfs in one
   relocatable, load-relative, signed artifact with a verifying installer. These
   are components we already build; this proves the plumbing.
2. **Vendor the VMM.** Add libkrun + libkrunfw as pinned submodules built by the
   root flake into the same artifact. This is the only A-specific increment and
   it lands last, after step 1 is trusted. After this, macOS first-run is
   genuinely zero-dependency.
3. **Linux.** Follows ADR-085 / Plan 193 gateway timing (passt replacement).

**Pre-merge checklist** (gates the step-2 vendoring, not this decision):

- [ ] Confirm libkrunfw kernel redistribution terms. libkrun is Apache-2.0;
  libkrunfw embeds a GPL Linux kernel. Redistributing that binary in the bundle
  is expected to be fine under GPL (source is public / offered), but confirm and
  record the obligation (offer-of-source / license notices shipped in the
  artifact) before step 2 lands.

## Consequences

- macOS first-run becomes genuinely zero-dependency once step 2 lands: one signed
  artifact, reproducible and pinned VMM, no Homebrew prerequisite.
- We take on building libkrun/libkrunfw in the release pipeline — a reproducible
  kernel compile across platform targets. A one-time pipeline investment; tracked
  with bundle-size growth under [Plan 156](../plans/156-binary-size-reduction.md).
- One more C codebase falls under our review + signing umbrella. This does not
  widen the runtime trust boundary (the VMM is already load-bearing in-process);
  it moves supply-chain origin in-house and pins it.
- The bundle is the **end-user** path only; source-checkout builds are unchanged
  (Plan 199 non-goal preserved).
- `mvmctl doctor` reports bundle provenance (signed, pinned-VMM rev) so the
  install path is observable.

## Out of scope

- GPU passthrough — a separate strategic decision, not a packaging one.
- Inbound TLS (mvmd's edge, per ADR-058).
- The `machine` / pack UX surface ([Plan 200](../plans/200-machine-ux-dx-layer.md), [Plan 155](../plans/155-portable-runnable-artifacts.md)) — this ADR ships the substrate that surface runs on, not the surface.
- Bring-up performance (kernel prebuilt / store persistence own it — ADR-082
  §"not a performance decision").

## References

- [Plan 199](../plans/199-host-runtime-packaging-and-crate-boundaries.md) — host runtime packaging (this ADR is its missing "dependency-free bundle" decision)
- [ADR-085](085-bundled-egress-gateway.md) — bundled egress gateway
- [ADR-082](082-rust-native-egress-gateway.md) — Rust-native gateway
- [ADR-002](002-microvm-security-posture.md) — security posture / who builds the VMM
- [ADR-046](046-builder-vm-via-libkrun.md) — two artifact layers, two acquisition paths
- [ADR-013](013-libkrun-microvm-nix-pivot.md) — libkrun pivot (runtime kernel extraction)
- [Plan 155](../plans/155-portable-runnable-artifacts.md), [Plan 156](../plans/156-binary-size-reduction.md), [Plan 200](../plans/200-machine-ux-dx-layer.md)
