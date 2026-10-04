set working-directory := "../.."

# `--all-targets` is narrower than it sounds: it skips any target behind
# `required-features`, and on macOS it cannot compile `cfg(target_os = "linux")`
# files at all. `gated` covers both.

# Type-check without codegen
check:
    ./scripts/cargo-fast.sh check --workspace --all-targets

# Cross-compile every crate's lib for Linux (glibc) via zig — no Docker — so
# cfg(target_os="linux") code a macOS host never compiles is caught locally.
# --all-features reaches feature-gated modules (e.g. libkrun_builder). Lib-only:
# linking the libkrun-sys bins needs target libkrun, which CI provides. Needs
# `cargo install cargo-zigbuild`, a `zig` on PATH, and
# `rustup target add x86_64-unknown-linux-gnu`. musl is intentionally not the
# default — libc's ioctl request arg is c_int there vs c_ulong on glibc, so the
# COW FICLONE path (mvm-runtime) only type-checks against glibc.

# Cross-compile every crate's lib for Linux via zig
linux TARGET="x86_64-unknown-linux-gnu":
    ./scripts/cargo-stable.sh zigbuild --target {{ TARGET }} --workspace --lib --all-features

# Type-check the targets `just check::check` cannot see. Two blind spots, both of which
# have shipped a red CI run that named neither:
#
#   1. `cfg(target_os = "linux")` *test* files. `linux` above is --lib
#      only, so a Linux-gated test target is checked by nothing local. This
#      surfaces in CI as `check-nextest-groups` failing with "cargo nextest list
#      failed" — a message that never names the file or the field.
#   2. Targets behind `required-features` (mvm-conformance's cucumber runner).
#      `--all-targets` skips them silently: without `--features bdd` the same
#      broken tree reports zero errors.
#
# `check` rather than a build, so nothing links — that is the constraint that
# forces `linux` to stay lib-only. Same prerequisites as `linux`
# (cargo-zigbuild, zig on PATH, the rustup target). Note the binary is invoked
# as `cargo-zigbuild check`: `cargo zigbuild check` is a different subcommand
# and errors on the argument.
#
# Not folded into `ci`: it needs a zig toolchain that not every contributor has
# (the same reason `linux` is opt-in), and a cold run costs ~8 min because
# it type-checks the whole workspace for a second target. Run it before pushing
# anything that changes a shared type's shape; a warm run is far cheaper.

# Type-check the linux-gated and feature-gated targets `just check::check` cannot see
gated TARGET="x86_64-unknown-linux-gnu":
    ./scripts/cargo-stable.sh --direct cargo-zigbuild check --target {{ TARGET }} --workspace --all-targets
    ./scripts/cargo-stable.sh check -p mvm-conformance --all-targets --features bdd

# A `-none-elf` target exposes only core + alloc with no std to leak into, so
# this is a stricter no_std check than the wasm32 gate. riscv32imac is the
# mainline stand-in for the RISC-V microcontrollers the on-device verifier
# targets; lib-only means an rlib with no final link, so no cross-linker is
# needed. Note: riscv32imc parts (no atomics) and Xtensa parts need extra
# shims/toolchains — see specs/notes for the embedding track.

# Bare-metal no_std proof for the embeddable foundation crate (mvm-contract)
embedded TARGET="riscv32imac-unknown-none-elf":
    rustup target add {{ TARGET }}
    cargo build -p mvm-contract --lib --target {{ TARGET }}

# Run mvmctl with arguments
run *ARGS:
    ./scripts/cargo-fast.sh run -- {{ ARGS }}


# The release and MSRV lanes build with the stable-compatible configuration;
# the nightly fast path must stay pinned and must not leak into it.

# Verify the nightly fast path stays pinned and isolated from stable builds
fast-cargo:
    ./scripts/check-fast-cargo.sh

# Requires nightly Rust and `cargo install bpf-linker`.

# Build the host-side eBPF object for vsock egress telemetry
ebpf:
    #!/usr/bin/env bash
    set -euo pipefail
    cd crates/mvm-hostd/ebpf
    PATH="${HOME}/.cargo/bin:${PATH}" cargo +nightly build --release --target bpfel-unknown-none -Z build-std=core

# Later required-overlay boots reuse it without rebuilding guest binaries on
# the hot path. Pass through extra args like `--force` or `--source download`.

# Prebuild or refresh the version-matched read-only runtime overlay
overlay *ARGS:
    bin/dev build runtime-overlay build {{ ARGS }}
