# Flake exit-code propagation

Backing: shipped-source
Validation: check-sprint-append

## Goal

Make `machine run --flake` wait for the image's baked workload and return its
reported exit code instead of dispatching an empty guest command that masks a
nonzero result as success.

## Checklist

- [x] Trace the flake run path from its generated manifest slot through guest
      command dispatch and backend workload waiting.
- [x] Distinguish an image-baked entrypoint from an explicit inline command.
- [x] Return the backend's reported workload exit code and fail closed when no
      exit report exists.
- [x] Add focused regressions for command selection, nonzero propagation, and
      a missing exit report.
- [x] Run workspace and gated validation.
- [ ] Merge the repair through the queue.
