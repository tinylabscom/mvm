# Agent spawn descriptor isolation

Backing: shipped-source
Validation: check-sprint-append

## Issue #3404

- [x] Audit agent-owned child spawn paths after the entrypoint-path hardening.
- [x] Apply the shared close-range defense to RPC, streaming-exec, and warm-worker children while retaining the validated worker executable descriptor.
- [x] Add Linux regression coverage that holds an extra descriptor open while exercising RPC and streaming spawn paths.
- [x] Run host, Linux-gated, and repository validation gates.
- [ ] Promote through PR, merge queue, and first-public-disclosure recording.
