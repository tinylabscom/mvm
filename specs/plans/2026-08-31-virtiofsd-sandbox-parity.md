# virtiofsd sandbox parity

Backing: shipped-source
Validation: check-sprint-append

**Status: SUPERSEDED — do not implement.** This plan hardens the confinement of
a `virtiofsd` this repo no longer spawns. `crates/mvm-vmm/src/host/virtiofsd.rs`
was deleted once both QEMU call sites moved off it (the builder to the disk
transport, the workload driver to a refusal), so there is no `--sandbox`
argument left to pass and no flavour left to pass it to. Implementing this now
would mean re-adding the file.

The underlying concern — `--sandbox none` disabling virtiofsd's own
namespace/seccomp confinement, with no comment and no ADR — is resolved by
removal rather than by configuration. See
`specs/plans/2026-08-31-remove-virtio-fs.md`.

## Goal

Make QEMU's host-directory file server use the same explicit confinement policy
regardless of which supported `virtiofsd` implementation a host installed.

## Checklist

- [x] Trace every `virtiofsd` caller and confirm the helper is QEMU-only.
- [x] Establish the supported sandbox modes for both daemon flavours.
- [x] Replace the Rust daemon's unconfined mode with an explicit namespace
      sandbox and make the C daemon's matching policy explicit.
- [x] Add focused argv regressions for both daemon flavours, including the
      read-only and DAX options that must compose with confinement.
- [x] Run workspace validation and merge the repair through the queue.
