---
title: Adding an architecture or backend
description: How to extend the architecture-aware artifact model with a new CPU architecture or microVM backend.
---

The artifact model (Plan 134) is **data-driven on purpose**: architecture and
backend capabilities live in typed enums and one compatibility table, so adding
support is a small, local change — validation and config generation pick it up
automatically because they both read the same table. You should never have to
hunt down scattered `match` statements.

## The pieces

| Concept | Type | Lives in |
|---|---|---|
| Guest CPU architecture | `GuestArch` | `mvm_core::arch` |
| Kernel artifact format | `KernelFormat` | `mvm_core::kernel_format` |
| MicroVM backend identity | `MicrovmBackend` | `mvm_backend::compat` |
| Rootfs format | `RootfsFormat` | `mvm_backend::compat` |
| Capability matrix | `BackendCompat` + `compat()` | `mvm_backend::compat` |

`mvm-core` holds only pure types (no runtime deps); `mvm-backend` owns backend
identity and the capability table.

## Add a new architecture

1. Add a variant to `GuestArch` (`crates/mvm-core/src/arch.rs`), e.g. `Riscv64`.
2. Extend `FromStr` to normalize its aliases (e.g. `riscv64`, `riscv`), and add
   its `nix_system()` string (e.g. `"riscv64-linux"`). Add a case to `Display`.
3. Update `GuestArch::host()`'s `cfg` chain so the new host arch isn't silently
   coerced (the function documents this assumption — read its doc comment).
4. For each `BackendCompat` row that supports the new arch, add it to
   `guest_arches` and add a `(GuestArch::Riscv64, &[…])` entry to
   `kernel_formats`.
5. Add a test asserting alias normalization and that the relevant backends
   accept it (`cargo test -p mvm-core arch::`, `cargo test -p mvm-backend compat::`).

That's it — `ArtifactValidator` and the config writers consume the table, so no
other file changes.

## Add a new backend

1. Add a variant to `MicrovmBackend` (`crates/mvm-backend/src/compat.rs`).
2. Add a `static` `BackendCompat` row describing its real capabilities —
   `guest_arches`, per-arch `kernel_formats`, `rootfs_formats`,
   `required_boot_args`, `supports_snapshots`, `supports_jailer`, `networking` —
   and add its arm to `compat()`. Ground each value in the backend's actual
   behavior (read the backend impl); where a capability is genuinely uncertain
   (e.g. a backend with no runtime yet), pick the conservative value and leave a
   `//` comment citing the source or stating the assumption. The model is allowed
   to *declare* requirements for a backend that has no runtime impl yet.
3. (Optional, when you want config generation) add a `BackendConfigWriter` impl
   under `crates/mvm-backend/src/artifacts/config/` and wire it into the
   `mvmctl artifact model-config --backend <name>` dispatch.
4. Add accept/reject tests to `compat::tests`.

`ArtifactValidator` enforces arch ↔ backend ↔ kernel-format ↔ rootfs-format
compatibility from this table before launch, so a new row is immediately
enforced.

## Kernel formats: why there's no boot-protocol code

Every backend mvm targets — Firecracker, libkrun, and the Tier-2 Vz/QEMU
paths — is a **direct-boot** VMM: it loads an uncompressed ELF `vmlinux`
(x86_64) or a flat arm64 `Image` and jumps straight to the kernel entry point.
None of them run the x86 real-mode setup stub, the UEFI/PE handoff, or construct
a `boot_params` page. So mvm carries **none** of that machinery, and `KernelFormat`
has no `BzImage` variant.

The practical trap this avoids: an x86 `bzImage` (`arch/x86/boot/bzImage`) is the
real-mode setup code *plus* a compressed payload — exactly the wrapper these VMMs
don't unwrap. An x86 backend needs the uncompressed ELF `vmlinux`, not the
`bzImage`. The Nix image build is where this bites (it once copied
`${kernel}/bzImage` to a file *named* `vmlinux`), so `sniff_kernel_format`
(`crates/mvm-backend/src/artifacts/builders/nix.rs`) detects a stray bzImage by
its setup-header magic `HdrS` at offset `0x202` and classifies it `Raw`.
`Raw` isn't in any direct-boot backend's `kernel_formats`, so `ArtifactValidator`
rejects it with a clear format error at build time — instead of the kernel
panicking before userspace at boot.

If mvm ever genuinely needs to *read* a setup header — extract a kernel version
for `KernelArtifact.version`, or support bzImage on some future firmware-boot
backend — reuse the `linux-boot-params` crate (pure `boot_params`/`setup_header`
structs, from the Asterinas project) rather than hand-defining the layout. It's a
new third-party dependency, so weigh it against the ADR-002 trust model first;
no current backend needs it.

## What stays out of scope

Production rootfs images are built **inside the builder VM** (`mke2fs`,
ADR-050) — the artifact model validates and configures them, it does not build
ext4 on the host. Pure-Rust host-side rootfs creation, QEMU/vfkit config
writers, dynamic boot smoke-tests, and `microvm.nix` integration are tracked as
their own follow-up slices (see `specs/plans/134-architecture-aware-artifact-model.md`
§"Out of scope").
