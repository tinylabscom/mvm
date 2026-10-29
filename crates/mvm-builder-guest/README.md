# mvm-builder-guest

`mvm-builder-guest` contains the builder-VM guest binaries and the contracts
they share with the host that boots them. Keeping these in a separate crate
lets the nested static-musl build compile the guest dependency closure without
pulling in the host-side build pipeline.

## Binaries

- `mvm-host-vm-init` initializes the builder guest.
- `mvm-builderd` is the resident builder-VM control daemon, using the typed
  `builderd_protocol` over a Linux AF_VSOCK listener.
- `stage0-init` is PID 1 of the nix-tarball Stage 0 seed. It is installed as
  the seed's `/init`, not in a builder rootfs.

`mvm-cli/build.rs` cross-compiles these binaries to static musl and embeds
them in `mvmctl`. Their names are also used by the host payload manifest and
Nix host-binary packaging, so renaming one requires updating those consumers.

## Shared contracts

The library provides the builder boot contract and guest paths, payload
manifest, job and daemon protocols, disk transport, readiness probes, rootfs
injection helpers, seed store entries, and Stage 0 constants. Unix-only
modules are gated with `cfg(unix)`.

`mvm-build` depends on this crate and re-exports the moved modules under
their existing paths. Dependencies must not point back to `mvm-build`: doing
so would bring the host pipeline back into the embedded-binary build.
Host-side orchestration, artifact acquisition, VM drivers, and the egress
proxy remain outside this crate.

## Developing

Run `cargo test -p mvm-builder-guest` for the host-supported tests.
Linux-only binary paths and AF_VSOCK behavior require Linux validation in
the project builder VM. Nix builds and evaluations also run only in that VM.

The crate's `mvm-fs` dependency is test-only; production guest code must not
depend on it merely to share artifact file names. Tests pin the guest-side
names to the corresponding filesystem constants.
