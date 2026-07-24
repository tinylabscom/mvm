# ADR-018: mvm runtime overlay disk

## Status

Accepted.

## Context

A microVM's rootfs can come from two different sources: an mvm-built Nix
image, or a pulled OCI image whose bytes are user content — content the
user pinned by a registry digest they control. Every microVM regardless
of rootfs source needs the same mvm-controlled binaries alive inside it:
the guest agent, the per-service seccomp shim, the function-workload
runner, the network-init blackhole-route installer, and the SDK runtime
library each language binding depends on.

Baking those binaries into the rootfs at unpack time would work for
Nix-built images, but for an OCI-pulled image it mutates the very bytes
the registry served — the rootfs digest would no longer match the OCI
image's own digest, breaking the content-addressable identity that pull
is supposed to preserve. It would also mean every rootfs source
(mkGuest, OCI unpack, any future image factory) has to re-implement the
same "inject the agent" step.

## Decision

**Every mvm microVM boots two block devices: a rootfs (`/dev/vda`, user
content) and an mvm-runtime overlay (`/dev/vdc`, mvm content). Both are
verity-sealed; both roothashes appear on the kernel cmdline
(`mvm.roothash=`, `mvm.runtime_roothash=`); `mvm-verity-init` validates
both before `pivot_root`.** The overlay mounts read-only at
`/mvm/runtime` inside the guest. The OCI rootfs stays byte-for-byte
identical to what the registry served — mvm never mutates pulled image
content to inject its own binaries.

**The overlay is the sole source of these binaries — there is no baked
fallback.** `mkGuest` does not copy the agent, seccomp shim, or runner
into any image's rootfs closure. If the overlay is absent, unattached, or
its resolved agent binary is missing, boot fails closed rather than
falling back to a rootfs-baked copy: an unbound vsock control port is a
silent, unrecoverable failure mode, so `/init` refuses to proceed instead
of booting agent-less.

**The overlay carries its own dynamic loader.** Because it is mounted
into arbitrary guest userspaces — including OCI rootfs trees that carry
no `/nix/store` and no compatible libc layout — every overlay executable
is relinked to load against `/mvm/runtime/lib/*` (a bundled dynamic
loader, libc, and libgcc) rather than the build host's paths. The overlay
is launchable regardless of what libc the surrounding rootfs ships or
whether it ships one at all.

**The host re-verifies the cached overlay before every attach.** Before
any backend threads the overlay's paths into a boot config, mvm re-hashes
the cached overlay artifacts against the SHA-256 manifest recorded beside
them at fetch or build time. A mismatch is an admission-time error that
forces a rebuild or re-download — the guest never mounts an unchecked
raw ext4 payload, only the dm-verity device built from a
freshly-reverified artifact.

**`/mvm/` is a reserved path.** An OCI image that ships content at `/mvm`
collides with the overlay's mount point and is rejected at admission time
with an explicit error, checked by walking the image's layers before
unpack.

**The overlay has a fixed size budget.** 32 MiB, enforced by
pre-allocating the ext4 image at that size at build time. Today's
contents — the agent (prod and dev-shell variants), the seccomp shim,
the netinit binary, the runner, the egress client, the addon
binaries, the in-guest host-services FFI shared object, and the Python
SDK runtime package — fit well under that cap, leaving headroom for
per-language SDK runtime additions without re-sizing the image on every
release. A TypeScript SDK runtime is reserved space in the overlay layout
but not yet populated; the guest-side koffi native addon it needs is not
yet cross-built for the guest architecture.

**The overlay is version-pinned to the running mvmctl.** Its `VERSION`
file must match the running binary's semver; a mismatch is an
admission-time error, never a silent boot with an incompatible overlay.

**Build determinism matches the rootfs verity pipeline exactly.** ext4
generation and `veritysetup` parameters (UUID, hash seed, block sizes,
salt, hash algorithm) are pinned constants shared with the OCI-unpack
verity path, so two builds against the same workspace state produce a
byte-identical overlay and roothash.

## Consequences

**Positive.** OCI rootfs content stays byte-for-byte identical to the
registry's bytes — digest pins hold, and reproducibility for the OCI half
of the story is exactly the registry's own reproducibility. mvm's own
runtime story lives in one place: a security fix to the agent ships as
one overlay rebuild, not N per-image flake bumps. Every Nix-built image
is smaller because it no longer carries a duplicated copy of the agent,
shim, and runner. Verity coverage is strengthened, not diluted — a
tampered overlay panics the kernel exactly like a tampered rootfs would,
and both roothashes are load-bearing.

**Negative.** Every microVM now carries a second block device and a
second verity Merkle tree to validate at boot. The overlay is an
additional release artifact per architecture. The `/mvm/` path
reservation is a contract with users that admission has to enforce on
every OCI pull. Because there is no baked fallback, an overlay resolution
bug is a hard boot failure for every image, not a degraded one.

**Non-goals.** The overlay is not user-customizable in this design — one
mvm-controlled overlay per architecture, not a per-vendor or per-tenant
variant. It is not writable — workloads needing writable shared state use
volumes or the snapshot upper layer, which have their own contracts. It
does not ship a shell, a libc for the workload's own use, or any
interpreter — those come from the rootfs the user chose. It does not
replace the verity initramfs: `mvm-verity-init` still runs before any
disk beyond the initramfs cpio is mounted.
