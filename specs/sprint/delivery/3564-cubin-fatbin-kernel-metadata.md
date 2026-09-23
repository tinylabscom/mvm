# Issue #3564 — cubin and fatbin kernel-parameter metadata

## Delivered behavior

`mvm-gpu-shim-core` now exposes one bounded `kernel_param_sizes` parser for
PTX, cubin ELF, and basic fatbin v1 images. Cubins recover each kernel's layout
from `EIATTR_KPARAM_INFO` records in the exact `.nv.info.<entry>` section and
order the sizes by the records' explicit ordinals. Uncompressed fatbins walk
all bounded entries, accept cubin and PTX payloads, and refuse disagreement
between payload layouts.

The CUDA guest shim recognizes fatbin lengths before copying an image, caps
NUL-terminated PTX scanning at the 64 MiB wire ceiling, and uses the generic
parser during `cuModuleGetFunction`. A missing, compressed, malformed,
truncated, out-of-bounds, unsupported-endian, or over-cap layout leaves the
function without parameter metadata; `cuLaunchKernel` therefore returns
`CUDA_ERROR_NOT_SUPPORTED` without reading a guessed parameter array.

## Bounded format surface

| Input | Accepted surface | Refusal surface |
|---|---|---|
| PTX | existing `.entry` / `.param` behavior, at most 256 parameters | invalid UTF-8, missing entry, parameter cap |
| cubin | ELF64 little-endian, bounded section table and names, exact `.nv.info.<entry>` | other class/endian, malformed/truncated/range failures, duplicate or sparse ordinals |
| fatbin | v1, bounded headers and payloads, uncompressed cubin/PTX entries | other version, compressed-only cubin metadata, inconsistent layouts |

The implementation adds no parser or decompression dependency.

## Test evidence

Focused tests cover cubin ordinal recovery, zero-parameter kernels, basic
fatbin cubin and PTX payloads, PTX compatibility, image and parameter caps,
missing entries, ELF class/endian refusal, truncated and out-of-bounds tables,
malformed parameter records, duplicate/sparse ordinals, compressed fatbins,
and bounded module-length discovery.

- `cargo test -p mvm-gpu-shim-core` — 17 passed.
- `cargo test -p mvm-gpu-cuda-shim` — 2 passed.
- Focused all-target Clippy for both crates — zero warnings.
- `cargo test --workspace -- --test-threads=1` — every unit and integration
  suite passed. The final `mvm-build` doctest initially hit a transient missing
  dependency artifact; its isolated retry rebuilt the dependency and passed.
- `cargo clippy --workspace --all-targets -- -D warnings` — passed.
- `just check-gated` — Linux all-target and BDD required-feature checks passed.
- `cargo run -p xtask -- check-all` — all 74 repository gates passed.
- `cargo fmt --all -- --check` — passed.
