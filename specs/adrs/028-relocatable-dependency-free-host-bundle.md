# ADR-028: The mvmctl distribution is a relocatable, dependency-free, signed bundle

## Status

Accepted — staged. The bundling machinery this ADR describes has not
landed yet; today's install still requires the Homebrew VMM trio on
macOS. One pre-merge checklist item remains before the VMM-vendoring step
can land (see "Why Option A, and how it's staged").

## Context

Today, on macOS, a user must `brew install slp/krun/{libkrun,libkrunfw}`
before `mvmctl` can run its libkrun-backed builder VM. That
package-manager step is the first-run cliff: a developer who never gets
past it never sees the security substrate behind `mvmctl` at all — DX is
the gate, the substrate is the moat behind it.

The mechanics of a relocatable bundle are well understood: ship the CLI,
the VMM dylibs, the egress gateway, the guest kernel, and the agent
rootfs in one directory; make dynamic linkage load-relative
(`$ORIGIN`-relative rpath on Linux via patchelf, `@loader_path` install
names on macOS) so nothing resolves to a system prefix; bake the guest
kernel at build time rather than extracting it from a dylib's `.rodata`
at runtime; and produce the whole thing from one root flake that is both
the dev shell and the release packager, so the end-user Nix consumer path
merely relocates the prebuilt signed tarball.

This does not weaken the source-checkout invariant. A source checkout
still builds every image locally from the in-repo flakes. Only the
published artifact is prebuilt — the same posture the existing
GitHub-release prebuilts already hold. The consumer-relocates-prebuilt
path is an end-user path, never a source-checkout prerequisite.

## Decision

Adopt **Option A** — vendor, pin, build, and sign the VMM ourselves —
staged so VMM-vendoring is the last, separable step.

The published `mvmctl` distribution is a single relocatable, signed,
dependency-free bundle. On a supported host the one-line installer drops
a self-contained directory and `mvmctl machine run ...` works with no
package-manager prerequisites.

- The bundle vendors: the CLI, the egress gateway, libkrun, libkrunfw,
  the guest kernel (baked at build time), and the agent rootfs.
- Dynamic linkage is load-relative; a wrapper points the CLI at the
  bundled rootfs.
- One root flake builds every component and emits the bundle; its dev
  shell and release packager share derivations. The Nix consumer path
  relocates the signed prebuilt; source checkouts keep building locally
  from in-repo flakes.
- The bundle is signed and the installer verifies the signature before
  install — an extension of the existing dev-image hash-verify posture,
  not a new mechanism.

## Why Option A, and how it's staged

The choice was whether to vendor and sign the VMM (libkrun/libkrunfw)
ourselves, or keep it sourced from the third-party Homebrew tap. We
vendor it:

- **Keeping it on the tap doesn't solve the problem.** The trio becomes a
  duo; the user still hits a package-manager wall, and the
  zero-to-running metric doesn't move. A half-open gate is a closed
  gate.
- **It's a supply-chain upgrade, not a downgrade.** Today the tap's
  version is unpinned, mutable, and signed by someone else — a routine
  package upgrade can silently break the FFI surface mvm depends on.
  mvm already trusts the host with the hypervisor binary; vendoring
  doesn't widen that trust boundary, it changes the binary's origin to a
  pinned revision, reproducibly built and signed under mvm's own release
  key. Pinned, signed, and reproducible beats mutable and foreign on
  every axis the threat model cares about.
- **VMM-vendoring is the last, separable step**, so committing to it now
  is low-risk: the bundle machinery (gateway, kernel, rootfs, rpath
  rewriting, the signed installer) lands first and proves itself
  regardless of when the VMM source gets pinned.

**Staging.** Each step ships and is useful on its own, macOS first, since
the package-manager pain is worst there:

1. **Bundle machinery.** The egress gateway, kernel, and agent rootfs in
   one relocatable, load-relative, signed artifact with a verifying
   installer — components already built today, so this step proves the
   plumbing.
2. **Vendor the VMM.** Add libkrun and libkrunfw as pinned sources built
   by the root flake into the same artifact. This is the only
   Option-A-specific increment, and it lands last, after step 1 is
   trusted. After this, macOS first-run is genuinely zero-dependency.
3. **Linux.** Follows the same gateway-vendoring timing as the macOS
   path.

**Pre-merge checklist gating the VMM-vendoring step:**

- [ ] Confirm libkrunfw's kernel-redistribution terms. libkrun is
  Apache-2.0; libkrunfw embeds a GPL Linux kernel. Redistributing that
  binary in the bundle is expected to be fine under GPL (source is
  public and offered), but the obligation — offer-of-source, license
  notices shipped in the artifact — needs to be confirmed and recorded
  before this step lands.

## Consequences

- macOS first-run becomes genuinely zero-dependency once the VMM is
  vendored: one signed artifact, a reproducible and pinned VMM, no
  Homebrew prerequisite.
- mvm takes on building libkrun/libkrunfw in its own release pipeline —
  a reproducible kernel compile across platform targets — a one-time
  pipeline investment.
- One more C codebase falls under this project's review and signing
  umbrella. This doesn't widen the runtime trust boundary — the VMM is
  already load-bearing in-process — it moves the supply-chain origin and
  pins it.
- The bundle is the end-user path only; source-checkout builds are
  unchanged.
- `mvmctl doctor` reports bundle provenance (signed, pinned VMM revision)
  so the install path stays observable.

## Out of scope

GPU passthrough is a separate strategic decision, not a packaging one.
Inbound TLS is the fleet orchestrator's edge concern. The higher-level
"run a portable artifact" UX surface ships on top of this substrate, not
as part of it. Cold-start performance is a separate decision (kernel
prebuild, store persistence) from packaging.
