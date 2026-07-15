# ADR-004: Builder VM trust — hash-pinned seed, no host Nix, no runtime cargo

## Status

Accepted

## Context

Every artifact `mvmctl` produces — a workload rootfs, a kernel, a template —
is built by running Nix inside a VM mvm launched, never by shelling out to a
Nix installation the host happens to have. That promise only holds if the VM
doing the building is itself something the operator can trust bit-for-bit,
and if getting from a stock host with nothing installed to a working builder
VM doesn't quietly depend on trusting an intermediary: a third-party Linux
distribution, a package manager's release key, or an unpinned network fetch.

The bootstrap has an unavoidable chicken-and-egg shape: the first Nix on a
machine with no cache can't itself be built by Nix. Something has to seed it
from outside a Nix build, and that something is the actual root of trust for
everything the builder VM later produces.

Separately, mvm ships its own Linux binaries — a builder-VM PID 1, an
egress helper — that have to exist inside the guest before Nix ever runs.
Building them by shelling `cargo`/registry fetchers at bootstrap time makes
every fresh install depend on a registry being reachable and well-behaved,
for code that isn't the user's, it's mvm's own.

## Decision

**Nix is the only build authority mvm ever runs, and it always runs inside a
VM mvm launched.** The host's own Nix — even if the operator has one
installed and configured — is never consulted, never shelled out to, and
never a fallback.

**The first Nix on a fresh host is seeded from a hash-pinned, upstream Nix
release tarball — no PGP, no third-party distribution, no external
userland.** The tarball is pinned by URL and SHA-256 per supported guest
architecture; that hash is the entire binding trust check, verified both
when the tarball is fetched and again when it's extracted. A small, static
Rust binary is the seed's PID 1: it brings up the pseudo-filesystems, makes
the extracted `/nix/store` writable, wires DNS, and runs the first `nix
build` that produces the steady-state builder VM's kernel and rootfs. Once
that steady-state builder VM exists, its cache is reused; the seed path
only runs again from a cold cache.

**mvm's own Linux binaries are cross-compiled once, at `mvmctl`'s own build
time, and embedded in the `mvmctl` binary itself.** `cargo build` of the CLI
cross-compiles each of them to a pinned static target and bakes the bytes
plus a SHA-256 into the binary. At runtime `mvmctl` only ever extracts these
bytes to a content-hash-addressed cache directory — it never invokes
`cargo`, never resolves a crate registry, and never looks in a `target/`
directory. A contributor who edits one of these binaries' source rebuilds
`mvmctl` to pick up the change; there is no separate runtime build step to
keep in sync.

**Three VMM backends implement the `BuilderVm` trait, and they produce
byte-identical artifacts from the same flake.** libkrun, QEMU, and HVF each
drive `nix build` against the builder-VM flake and hand back the same
kernel-and-rootfs pair regardless of which one ran. Selection auto-detects
by platform — macOS 26+ Apple Silicon uses HVF, native Linux uses QEMU,
everything else uses libkrun — and is overridable per invocation. Which VMM
ran a given build is never visible in the output.

**Building an artifact is two phases, and only one of them has to happen
inside a VM.** Evaluating and running Nix build logic — fetching sources,
compiling, executing arbitrary derivation or package-install code —
executes attacker-influenced input and always runs inside the builder VM;
there is no exception. Assembling an already-resolved, trusted-input closure
or unpacked tree into an ext4 image is pure byte-assembly over a fixed
input, and may run in-process on the host through a memory-safe,
`unsafe`-free writer. When that assembly also needs a dm-verity Merkle tree
and roothash, for a workload rootfs being sealed, the same writer produces
it; a builder-VM-shelled path exists as a fallback for inputs the in-process
writer can't yet faithfully represent.

**The builder VM's own rootfs is not dm-verity sealed.** Verity is a
property mvm applies to sealed workload rootfs, not to the builder itself.
The builder's trust rests on being deterministically reconstructible from
the hash-pinned seed and on content-addressed caching keyed to the
workspace, the embedded-binary content hash, and the flake — not on a
block-level integrity check at its own boot.

**Published release artifacts are cosign-signed, and the signed manifest —
not the artifacts individually — is the trust anchor.** A release's
manifest records the SHA-256 of every artifact it covers plus the closure
that produced them: Nix store hash, source revision, flake lockfile hashes.
It is signed keylessly under the release pipeline's own CI identity.
`mvmctl` verifies this signature on download and again on every cache
reuse, and treats a manifest past its expiry or on a revocation list as
untrusted.

## Consequences

Dropping PGP and a third-party distribution from the seed narrows the
bootstrap's trust surface to one thing: a SHA-256 pin on a single
upstream-published artifact. That pin has to be kept current by hand when
the seed's own Nix version changes, and a seed Nix version whose narHash
computation disagrees with the workspace's committed flake locks silently
breaks every fresh install until the seed is repinned.

Embedding mvm's own binaries in `mvmctl` makes the CLI binary measurably
bigger and its own build measurably longer, in exchange for a bootstrap
that requires nothing beyond `mvmctl` itself: no crate-registry
reachability, no separate release artifacts for Linux binaries, no drift
between what a contributor's `mvmctl` was built with and what it hands to
the builder VM's flake.

Three backends producing byte-identical artifacts means switching which VMM
builds on a given host is invisible to everything downstream, but it also
means a divergence between backends is a correctness bug by definition, not
a tolerated difference — there is no "backend-specific" artifact shape to
fall back on.

Keeping the builder VM unsealed while treating workload-rootfs sealing as
security-relevant is an explicit split in what gets which guarantee: an
operator who wants a dm-verity story for the build environment itself, not
just its output, doesn't get one today. That gap is accepted because the
builder VM does not carry the untrusted workload — it produces the
workload's rootfs — and its own trust story is deterministic
reconstruction plus signed release manifests, not boot-time block
verification.
