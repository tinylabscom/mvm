# ADR-004: Builder VM trust — hash-pinned seed, no host Nix, no runtime cargo

## Status

Accepted

**Amended 2026-10-05 by ADR-054**
(`specs/adrs/054-image-boundary-linux-layer.md`,
[#4100](https://github.com/tinylabscom/mvm/issues/4100)). Three statements
below are narrowed; the seed, the builder boot payload and the builder trust
model are unchanged.

- *"Every artifact `mvmctl` produces ... is built by running Nix inside a
  VM"* holds for images. mvm's guest runtime (the guest agent and helpers,
  the initramfs agent, `mvm-setpriv`, `libmvm_host_services.so`, the GPU
  shims) is cargo-zigbuild output from the pinned toolchain, assembled into
  the runtime overlay, initramfs and SDK sidecar on the host by the pure-Rust
  ext4 writer: the mechanism this ADR already uses for the builder binaries.
  In a source checkout `mvmctl` already compiles the overlay's guest binaries
  that way on first use. A release binary never invokes cargo: today it
  fetches those pieces from the image set, and under ADR-054 from its own
  release.
- *"No separate release artifacts for Linux binaries"* stops holding for the
  guest runtime. It becomes one signed CLI release asset, version-locked to
  the CLI and fetched through the CLI-train verifier
  ([#4103](https://github.com/tinylabscom/mvm/issues/4103)). The builder
  binaries stay embedded in `mvmctl`.
- *The builder image's key folding mvm source* has one remaining term today:
  the ABI 1 image still bakes `mvm-setpriv`, which `mvm-images` compiles from
  mvm's source. The host now includes it in every builder boot payload, and
  `mvm-host-vm-init` prefers that copy. An ABI 2 image carries no mvm binary,
  and its cache key folds no mvm binary source.

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

**Four VMM backends implement the `BuilderVm` trait, and they produce
byte-identical artifacts from the same flake.** HVF, Firecracker, libkrun and
QEMU each drive `nix build` against the builder-VM flake and hand back the
same kernel-and-rootfs pair regardless of which one ran. Selection
auto-detects by platform — Apple Silicon macOS uses HVF, Linux with KVM uses
Firecracker, every other host uses QEMU — and is overridable per invocation;
libkrun runs only when named. Which VMM ran a given build is never visible in
the output.

**mvm's own builder binaries travel beside the builder image, not inside
it.** At every builder boot, `mvmctl` assembles a deterministic initramfs —
the *builder boot payload* — from its embedded builder binaries
(`mvm-host-vm-init`, `mvm-builderd`, `mvm-setpriv`), each re-verified
against the SHA-256 compiled into `mvmctl`. The VMM loads it the way it loads the kernel. Its
`/init` mounts the image read-only, copies the binaries to a tmpfs, pivots,
and continues as the builder's PID 1. The payload digest travels on the
kernel command line, and the guest refuses a payload that does not match
it. That check catches host-side mix-ups; a malicious host is outside this
ADR's threat model, and a host that can rewrite the payload can rewrite the
command line too.

**The image declares a builder boot ABI, and the payload refuses an image
outside its supported range.** The contract is versioned, and each version's
meaning is fixed once released:

- *Where it lives.* The image declares an integer in
  `/etc/mvm/builder-boot-abi`; a published image set repeats it as
  `builder_boot_abi` in its signed `[compatibility]` section, and
  `images.lock` copies it. The payload side is `mvm_build::builder_boot`: the
  payload format, the command line every backend boots with, the ABIs a
  payload supports, and the stage-1 checks the guest runs.
- *ABI 0* is the legacy image: no marker, and it bakes the builder binaries
  and `mvm-setpriv` at `/sbin`. It boots with the payload, whose binaries
  then win and whose baked copies are never executed, or without one on a
  host that has none.
  A published set published before the field existed omits it and means 0.
  An omitted field currently means ABI 0 for both published and locally built sets.
- *ABI 1* bakes no builder daemon or init binary. It boots only with the
  payload, but still bakes `mvm-setpriv` from mvm's source.
- *ABI 2* carries no mvm binary. The payload supplies `mvm-setpriv` as well
  as the two builder binaries, and the guest prefers its copy on older images.
- *What every ABI promises the payload:* `/run` is a mount point; busybox,
  `nix`, `iptables` and `/usr/bin/firecracker` sit at their paths; the
  builder uid 902 exists; the persistent store lives on `/dev/vdb`; the root
  is ext4 on `/dev/vda`. Changing any of these is a new ABI number, never a
  reinterpretation of an old one.
- *What the host guarantees:* every builder boot carries the payload of the
  running `mvmctl`, whatever the image's ABI; the payload is assembled per
  boot into the booting VM's own state directory, never a shared cache; the
  image is attached read-only at the VMM on every backend; a host that
  cannot supply a payload refuses an image above ABI 0 before booting it,
  naming both numbers; and a persistent builder booted with other builder
  binaries is stopped rather than reused.

Only the payload's digest and the image's ABI cross the boundary. In a
release, the builder's host binaries are authenticated by the `mvmctl`
archive signature rather than by the image set, and they always match the
running CLI.

**A builder job has its own versioned contract, separate from the boot
ABI.** The boot ABI says which images a payload can boot; the job contract
says what a staged job directory means to the guest that runs it, and what
that guest reports back. Its owner is `mvm_build::builder_job_contract`.

- *Request.* Every job directory the host stages, one-shot or persistent
  dispatch, carries a contract-version marker file. The guest's init reads it
  before running anything in the directory and refuses a directory without
  one, with a malformed one, or with a version other than its own. The
  refusal is the job's outcome, so it surfaces as a failed build naming both
  versions rather than as a build that ran under the wrong assumptions.
- *Result.* The guest writes its outcome as JSON: the contract version it
  speaks, the exit code, a stderr tail bounded at 4 KiB, a failure category
  (evaluation, build, fetch, timeout, output contract, and the rest of the
  categories the typed `mvm-builderd` protocol uses), and how long the job
  ran. The host denies unknown fields and refuses an outcome
  from another version, or one without a version at all, before reading its
  shape. The full build log stays in a file beside the outcome; the result
  names where it is.
- *Policy.* Exact match, as with the `mvm-builderd` handshake. The payload
  makes the two sides one build in the normal case; the check is for a boot
  without a payload, where the image's baked init answers.

The builder VM never receives the host signing key. A build's output leaves
the guest as files and an outcome; the host verifies them, and only then does
`mvmctl bundle export` or `mvm_client::builder_bundle` sign a `.mvmpkg`
under the host signer.

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
the hash-pinned seed and on content-addressed caching keyed to the flake and
the Nix and Rust sources it compiles — not on a block-level integrity check
at its own boot. mvm no longer builds the builder image: it comes from the
signed image set, or from a paired `mvm-images` checkout. While that image
still bakes the builder binaries (ABI 0), a pair build's cache key folds the
source identity of the package that builds them, because its target contract
says the image needs host binaries; that term leaves the key when the image
moves to ABI 1. Below ABI 2 the key also folds the source identity of
`mvm-setpriv`, which the image compiles; at ABI 2 the payload carries that
helper and the term leaves the key too.

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

A Rust-only change to `mvmctl` no longer needs a new builder image to reach
the builder: the next boot carries it. Once the builder images declare ABI 1
and a pair build's key drops the host-binary term, such a change no longer
rebuilds a paired builder image either.

Four backends producing byte-identical artifacts means switching which VMM
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
