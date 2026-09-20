# Preserve libkrunfw's x86_64 kernel addresses (#3532)

Linux/x86 libkrun Stage 0 extracted the kernel bundled in libkrunfw, wrote only
its flat bytes to the cache, and then selected libkrun's raw kernel loader. The
firmware reported a load address of `0x01000000` and an entry address of
`0x01000123`; libkrun v1.19.4's x86 raw loader replaced both with
`0x80000000`. The VM consequently reported `KVM_EXIT_SHUTDOWN` immediately and
left a zero-byte console.

## Address-preserving artifact

`KrunContext` now records whether its kernel is an external caller-owned file
or a bundled libkrunfw payload. The distinction is serialized with an
`External` default so existing supervisor JSON remains compatible, while Stage
0 selects the bundled source explicitly.

Extraction now produces a host-appropriate artifact:

- aarch64 retains the raw libkrunfw Image;
- x86_64 wraps the bytes in a minimal ELF64 executable with one read-execute
  `PT_LOAD` segment at the firmware load address and the ELF entry point at the
  firmware entry address.

The cache compares the complete expected artifact rather than accepting a file
with the same length. This replaces a stale pre-fix raw payload even when its
size happens to match. External kernels keep their caller-selected format and
are never silently replaced.

## Regression coverage

The pure artifact builder is tested without loading the host libkrun libraries.
The tests pin the x86_64 ELF entry point, segment offset, virtual and physical
load addresses, payload length, and payload bytes; they also cover the raw
aarch64 decision and reject unaligned load addresses and entry points outside
the payload. Context tests cover the explicit bundled source and its JSON
round trip, and the Stage 0 builder regression proves it constructs that source
rather than an ordinary external-kernel context.

## Live validation

Ubuntu 24.04 x86_64 with `/dev/kvm`, libkrun v1.19.4 built with `BLK=1`,
libkrunfw v5.6.1, and a cold isolated `MVM_HOME`:

| Leg | Evidence |
|---|---|
| firmware metadata | load `0x01000000`, entry `0x01000123`, payload 21,626,880 bytes |
| kernel artifact | `readelf` reports entry `0x1000123` and one `PT_LOAD` at virtual and physical address `0x1000000`, with a 21,626,880-byte payload |
| guest entry | non-empty console and `stage0-init: backend = libkrun` |
| storage and egress | Stage 0 store mounted; Nix substitutions and builds ran through the host endpoint |
| output | x86_64 builder image derivation completed; store usage 9,337,912 KiB, below the 25,165,824 KiB cap |
| completion | `stage0-init: done; halting` followed by the kernel halt banner; the complete cold `mvmctl --builder libkrun bootstrap` command exited 0 |

This is the same library pair and KVM host shape that reproduced the immediate
shutdown. No root-directory-mode control or alternate kernel was used.
