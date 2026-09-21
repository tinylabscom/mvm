# Generic builder machinery (#3323)

Generic builder image/cache management, Stage 0 store preparation, disk
transport, runtime-overlay attachment, egress supervision, job identity, seed
identity, and common resource defaults now live in VMM-neutral modules. QEMU,
the driver-backed HVF paths, runtime, and CLI callers no longer reach through
`libkrun_builder` for generic behavior.

Generic builder capability remains unconditional. The optional
`builder-libkrun` feature now owns the optional `libkrun-sys` and `mvm-net`
dependencies and gates only the libkrun-specific adapter/provider modules. A
no-default-feature build therefore retains the generic surface without pulling
libkrun into its dependency closure.

## Regression witnesses

- `generic_builder_surface` refuses QEMU imports from `libkrun_builder`, pins
  the optional dependency/feature wiring, and refuses revival of the retired
  `mvm-build/builder-vm` switch.
- Shared helper tests cover the timestamp/PID job identity, order-independent
  Stage 0 seed hash, and missing-store error path.
- Existing image, Stage 0, transport, egress, runtime-overlay, QEMU, HVF, and
  persistent-builder tests continue to exercise the moved implementations.
- The trusted-build-egress policy gate recognizes the VMM-neutral endpoint and
  still refuses every workload caller.

## Validation

- `cargo nextest run --workspace`: 14,706 passed, 27 skipped.
- `cargo test --workspace --doc`: green.
- `just lint`: formatting, all-target workspace Clippy, BDD-target Clippy,
  model gates, and fast-Cargo policy green.
- `just check-gated`: Linux all-target cross-check and feature-gated BDD target
  green.
- `cargo run -p xtask -- check-all`: all 74 repository gates green.
- `cargo check -p mvm-build --no-default-features --lib`: green.
- `cargo test -p mvm-build --no-default-features --test generic_builder_surface`:
  2 passed.
- `cargo tree -p mvm-build --no-default-features -e normal`: no libkrun
  dependency in the generic-only closure.

The remaining delivery step is the protected merge queue; the PR closes #3323
when it lands.
