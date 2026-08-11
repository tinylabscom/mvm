# Plan 315: Bootstrap means machine-ready

## Status

**COMPLETE.** Opened 2026-08-10 after
an explicit `mvmctl bootstrap` prepared the builder VM but left the workload
kernel absent, causing the next `machine run --image` to launch Stage 0. The
interrupted repair then exposed a second defect: Stage 0 copied the resolved Nix
kernel config as a zero-byte file across the ext4-to-virtio-fs boundary, while a
byte-marker probe falsely rejected the valid KALLSYMS-free ARM64 kernel.

## Outcome

`mvmctl bootstrap` is one idempotent readiness command for the foundational
machine path. It prepares host tooling, the builder VM, and the verified workload kernel.
An interrupted producer never replaces a usable cache entry or leaves a partial
entry that can be served, and the next retry explains that its persistent Nix
store remains reusable.

## Work

- [x] Make bootstrap acquire the builder image and workload kernel in dependency
      order, fail if either is unavailable, and report both as ready.
- [x] Hard-rename the installer opt-out to the accurate
      `MVM_SKIP_BOOTSTRAP=1` name.
- [x] Route default workload-kernel acquisition through the shared verified
      resolver and re-enter it after every producer.
- [x] Stage release downloads in the destination directory, verify before
      publish, preserve an existing cache on checksum failure, and remove a
      newly published kernel if its digest sidecar cannot be recorded.
- [x] Publish local kernels only after non-empty kernel and config validation;
      require workload configs to enable device mapper and dm-verity; write live
      files atomically and require the digest sidecar.
- [x] Replace Stage 0 cross-filesystem artifact copies with explicit buffered
      reads/writes that follow Nix output symlinks and reject empty output.
- [x] Remove the raw-image byte-marker capability probe. Use the resolved config
      for local builds and the variant-specific release checksum identity for
      published kernels, so stripped/KALLSYMS-free kernels are accepted.
- [x] Track in-process Stage 0 ownership for truthful Ctrl-C messaging, retain
      the persistent Nix store, and sweep only matching orphan staging
      directories under the shared Stage 0 lock on retry.
- [x] Give QEMU Stage 0 a persistent Nix-store disk, synchronize its guest
      clock before TLS/Nix access, use the correct architecture console, and
      allow a real cold kernel compile to run for up to two hours with honest
      first-build messaging.
- [x] Keep the ARM64 workload kernel bootable across Firecracker, HVF/QEMU,
      and libkrun by building in both 8250 and PL011/HVC console support. Pin
      its measured built-in-symbol ratchet at 959 while leaving x86_64 at 917.
- [x] Follow only bounded, HTTPS OCI blob redirects to the exact trusted Docker
      CDN origins, stripping registry authorization at the origin boundary and
      refusing redirects for manifests.
- [x] Cover bootstrap ordering/failure, verified resolution, incompatible-cache
      eviction, KALLSYMS-free acceptance, config rejection, atomic publication,
      interrupted-staging cleanup, buffered symlink copy, and Ctrl-C messaging.
- [x] Close repository-wide verification. Formatting, focused tests, `cargo
      check --workspace`, host `cargo clippy --workspace --all-targets -- -D
      warnings`, the complete serialized workspace suite including doctests,
      the exact 461-test `xtask --features man` CI lane, and all 172 BDD
      scenarios pass. A KVM-backed ARM64 acceptance run completed a cold
      bootstrap, reused the persistent Stage 0 Nix store, rebuilt and published
      the workload kernel with dm-verity plus 8250 console support, and then ran
      Alpine twice from the fully warm cache without launching Stage 0.

## Security properties

- Cache presence is never evidence: only `VerifiedKernel` reaches a consumer.
- Published bytes are checked against the release manifest before replacement.
- Locally built bytes have integrity identity, not overstated upstream
  provenance; their sidecar detects truncation, skew, and later replacement.
- A local workload capability claim is derived from the resolved kernel config,
  not from an attacker-controlled filename or an unreliable binary substring.
- Interrupted staging directories are exact-name scoped and removed only while
  holding the same lock that excludes a live Stage 0 producer.
