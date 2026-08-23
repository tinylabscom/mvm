# Guest hostname follows the machine name

Backing: shipped-source
Validation: workload_cmdline_carries_the_machine_name_as_the_guest_hostname

## Status

**COMPLETE**

## Goal

Give every workload guest the same stable, user-visible hostname as the machine
name shown by `mvmctl machine ls`, without creating backend-specific boot paths.

## Work

- [x] Carry a validated `mvm.hostname=<machine-name>` token through the shared
      workload cmdline assembler consumed by Firecracker, HVF, libkrun, and the
      other workload drivers.
- [x] Reject malformed machine names at the whitespace-delimited cmdline seam so
      an internal launch config cannot inject another kernel argument.
- [x] Parse and validate the token in the guest, then call Linux `sethostname`
      during privileged bootstrap before any workload privilege drop.
- [x] Preserve legacy boots that carry no hostname token and report syscall
      failures without panicking.
- [x] Keep shared warm parents identity-free, then deliver and validate the
      final child hostname in the existing post-restore identity handshake.
- [x] Cover valid, missing, malformed, syscall-error, shared-assembler, and
      boot-argument-validator paths with focused tests, plus cold/warm cmdline
      parity and backward-compatible wire round trips.
- [x] Regenerate the protocol schema and Python and TypeScript bindings for the
      optional post-restore hostname field, and pass the code-generation drift
      gate.
- [x] Add a live BDD scenario that runs `/bin/hostname` in a named machine.
- [x] Update delivery and refactor status for issue #2789.

## Security and compatibility

The host and guest both accept only the existing RFC-1123 machine-name subset:
lowercase ASCII letters, digits, and interior hyphens, at most 63 bytes. The
guest receives no new authority and the hostname carries no secret data.
The optional post-restore field defaults absent for older peers; a supplied
invalid value makes the handshake fail instead of silently naming the guest.
