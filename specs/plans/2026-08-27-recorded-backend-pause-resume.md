# Recorded-backend pause and resume

Backing: shipped-source
Validation: check-sprint-append

**Status: IN PROGRESS**

## Problem

`machine pause` and `machine resume` construct a local client from the CLI's
`--hypervisor` default. An existing machine may have been launched by a
different backend, so a lifecycle operation can be sent to Firecracker even
when the machine's live marker records HVF as its owner.

## Scope

- Resolve the backend that owns an existing machine from its live state marker.
- Preserve the explicit backend as the fallback for marker-less machines and
  the hermetic mock test path.
- Preserve Firecracker's sealed snapshot and replay-refusal lifecycle.
- Dispatch non-Firecracker pause/resume operations through the owning backend's
  native lifecycle implementation.

## Acceptance

- [ ] Regression coverage proves a live backend marker wins over the client's
      default and that a marker-less mock remains hermetic.
- [ ] Pause and resume dispatch through the resolved owner without weakening
      Firecracker snapshot verification.
- [ ] Focused tests, workspace tests/check, Clippy, and gated target checks pass.
- [ ] Sprint and refactor rollups describe the delivered behavior.
