# Faster Rust compilation

Delivered 2026-08-19.

The contributor edit/build loop now follows the useful parts of the referenced
Rust compilation workflow: dated nightly Rust, eight parallel frontend threads,
line-table-only development debug information, and Cranelift for development
code generation. A cold `mvm-contract` build on the same Apple Silicon host
fell from 172.14 seconds with stable LLVM to 66.48 seconds with the fast path, a
61.4% reduction.

The optimization is deliberately scoped. Tests and release builds explicitly
retain LLVM. Linting remains on stable Rust 1.96 because current nightly Clippy
reports an annotation synthesized by async-trait as redundant; no lint is
suppressed. Nightly-only Cargo settings live in `.cargo/fast.toml`, so stable,
MSRV, and release lanes can still load the baseline workspace configuration.

The repository's embedded-host and runtime-overlay guest binaries exposed the
main compatibility edge: outer nightly flags and a host-global compiler wrapper
could leak into their nested builds. Both paths now resolve the already
Nix-pinned Rust 1.91.1 toolchain explicitly, isolate their target directories,
and discard outer nightly flags and wrappers. The Rust, Zig, and
cargo-zigbuild versions participate in the embedded-host binary cache key, and
the runtime-overlay source fingerprint covers its build implementation and
workspace metadata.

The fast path is used by the ordinary Just build, check, run, and test recipes.
A configuration regression script pins the nightly, Cranelift component,
parallel frontend flags, LLVM exceptions, stable lint lane, Nix shell, and BDD
workflow so these paths cannot silently drift apart.

A live libkrun builder-VM validation refreshed the locked `rust-overlay` input,
passed the full flake evaluation, and realized the aarch64 Linux development
shell with the pinned nightly and Cranelift component.

Pull-request validation also pins the integration edges: required stable
Clippy components are installed in every stable lint lane, the dated nightly
includes the WASI target used by the browser guest, and the BDD harness receives
the exact `mvmctl` path built in the isolated target directory.
