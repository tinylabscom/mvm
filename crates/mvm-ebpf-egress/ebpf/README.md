# mvm-ebpf-egress-ebpf

Kernel-side eBPF program for host-side vsock egress telemetry.

## Build

This crate is **not** part of the main workspace because it requires the
`bpf` target and nightly Rust. Build it separately inside the Linux builder
VM (or any Linux host with nightly + `bpf-linker`):

```bash
cd crates/mvm-ebpf-egress/ebpf
cargo build --release --target bpfel-unknown-none
```

The resulting object file lands at:

```
target/bpfel-unknown-none/release/mvm-ebpf-egress/mvm-ebpf-egress
```

Copy or symlink it to:

```
crates/mvm-ebpf-egress/ebpf/target/bpfel-unknown-none/release/mvm-ebpf-egress/mvm-ebpf-egress.o
```

The userspace loader (`mvm-ebpf-egress/src/lib.rs`) looks for the object at
that path by default, or at the path configured via
`ProbeConfig::ebpf_object_path`.

## Tooling

- Rust nightly
- `rust-src` component
- `bpf-linker` (`cargo install bpf-linker`)
- `bpftool` for BTF generation
