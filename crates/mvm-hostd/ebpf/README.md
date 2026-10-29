# mvm-hostd-ebpf

Kernel-side eBPF program for host-side vsock egress telemetry.

## Build

This crate is **not** part of the main workspace because it requires the
`bpf` target and nightly Rust. Build it separately inside the Linux builder
VM (or any Linux host with nightly + `bpf-linker`):

```bash
cd crates/mvm-hostd/ebpf
cargo +nightly build --release --target bpfel-unknown-none -Z build-std=core
```

`just check::ebpf` runs exactly that, and is what the CI lane runs.

The resulting object file is the one cargo hardlinks into the release
directory:

```
crates/mvm-hostd/ebpf/target/bpfel-unknown-none/release/mvm-hostd-ebpf
```

The userspace loader (`mvm-hostd/src/supervisor/ebpf_telemetry/loader.rs`)
reads that path by default, or the path configured via
`ProbeConfig::ebpf_object_path`.

BTF is not a separate step: `.cargo/config.toml` passes `-C debuginfo=2
-C link-arg=--btf` to the linker, so the object carries its own BTF.

## Tooling

- Rust nightly
- `rust-src` component
- `bpf-linker`, pinned to the version the CI lane installs
- LLVM, matching the version the pinned `bpf-linker` is built against

### The `bpf-linker` / LLVM / `aya` pairing

These three move together, and the CI lane pins all of them:

| Piece | Pinned to | Where |
| --- | --- | --- |
| `bpf-linker` | `0.11.1` | `.github/workflows/ci-main.yml` |
| LLVM | `23.1` (the `apt.llvm.org` `llvm-23` suite) | `.github/workflows/ci-main.yml` |
| `aya` / `aya-obj` | `0.13.1` / `0.2.1` | `Cargo.lock` |

`bpf-linker` links LLVM bitcode, and bitcode is versioned: the LLVM that
produced it has to be the LLVM that reads it. Since `bpf-linker 0.11.0` the
linker no longer borrows rustc's bundled LLVM, so it is built against a named
LLVM instead and the LLVM has to be installed:

```bash
cargo +nightly install --locked --version 0.11.1 \
  --no-default-features --features llvm-23 bpf-linker
```

`--no-default-features --features llvm-23` is not optional. The default
feature set is a *different* LLVM, and taking it silently is how the pairing
drifts apart: the linker then links a library whose ABI does not match the
one `llvm-sys` declares, or reads bitcode it was not built for.

The nightly is floating, so its bundled LLVM moves on rustc's schedule. The
CI lane checks the two against each other before installing the linker and
fails with a one-line explanation when they disagree. Do the same locally
when the build fails in `bpf-linker`'s own build script:

```bash
rustc +nightly --version --verbose | grep LLVM
```

`bpf-linker` writes the BPF ELF and `aya` reads it, so the two move together.
`bpf-linker 0.12.0` changed what the linker emits for programs with external
definitions, which `aya` has to be able to read; for *this* program 0.11.1
and 0.12.0 emit byte-identical objects, so the move did not drag the `aya`
version in `Cargo.lock` with it. The next version that changes the output
will.
