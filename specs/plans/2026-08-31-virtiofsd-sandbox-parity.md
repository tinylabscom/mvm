# virtiofsd sandbox parity

Backing: shipped-source
Validation: check-sprint-append

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
