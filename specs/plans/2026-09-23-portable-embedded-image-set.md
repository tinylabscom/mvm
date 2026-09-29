# Portable embedded image set

Backing: shipped-source
Validation: check-sprint-append

**Issue:** #3551  
**Status:** IN PROGRESS

## Goal

Make one signed `.mvmpkg` carry a backend-neutral image set whose structure,
completeness, protocols, capabilities, sizes, and hashes are checked without a
boot or a silent local rebuild.

## Consumer slice

- [x] Add a schema-v3 typed `embedded_image_set` member that names the ordinary
      bundle artifact containing the image-set manifest; do not encode backend
      names in the bundle schema.
- [x] Reuse `mvm_core::image_set` for structure, current-train completeness,
      protocol, boot-format, architecture, and device-capability checks.
- [x] Bind every image-set artifact name, size, and digest to a signed outer
      bundle artifact and reject partial or tampered input.
- [x] Populate a manifest-content-hash-keyed image-set cache during bundle
      install, and re-verify an existing cache entry before accepting it.
- [x] Extend `machine check-artifact` to verify `.mvmpkg` files, including all
      embedded image hashes, without booting; optional backend selection names
      incompatibilities before a VMM starts.
- [x] Cover complete, partial, nested-tamper, unsupported-capability,
      content-cache re-verification, and deterministic cross-host byte identity.

## Remaining issue acceptance

- [ ] Wire the verified embedded paths into every live Linux-direct backend and
      capture one physical boot witness per supported backend and architecture.
- [ ] Add the sealed checkpoint/state member and cross-host re-admission owned
      by the active #3384 checkpoint worktree; do not duplicate that state
      format here.
- [ ] Run the portable artifact plus checkpoint witnesses on distinct physical
      hosts and close #3551 only after those records are attached.

