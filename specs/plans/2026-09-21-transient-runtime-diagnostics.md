# Transient runtime diagnostics

Backing: shipped-source
Validation: check-sprint-append

**Status: COMPLETE**

## Scope

Make the two facts exposed by a named, image-backed transient run explicit:

- a name does not make `machine run` persistent, so registered volume mounts
  are not attached; and
- a contributor checkout may compile MVM guest runtime helpers on a cold cache,
  rather than compiling the requested OCI base image.

The normal OCI launch path does not yet consume `MVM_IMAGES_DIR`; routing
`mvm-images` into that artifact-acquisition path is intentionally outside this
small diagnostic change.

- [x] Preserve a regression-tested warning for named transient runs with registered volumes.
- [x] Name the locally built guest runtime helpers, distinguish them from the OCI base image, and provide the bootstrap prewarm command.
- [x] Run focused tests, formatting, workspace check, workspace Clippy, and the host workspace test suite.
