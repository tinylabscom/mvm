# Cold-boot guest wall clock

- [x] The universal-initramfs PID 1 consumes the host epoch already emitted by
      every block-root and virtiofs workload launch.
- [x] Clock synchronization happens before signed-grant time validation and
      before any workload process can perform TLS validation.
- [x] The shared decoder rejects missing, malformed, zero, and duplicated
      tokens, while focused tests prove application and syscall-error paths.

Owning plan: `specs/plans/2026-08-27-cold-boot-wall-clock.md`.
