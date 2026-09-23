# Cubin and fatbin kernel-parameter metadata

Backing: shipped-source
Validation: check-sprint-append

**Issue:** [#3564](https://github.com/tinylabscom/mvm/issues/3564)

## Outcome

CUDA Driver API workloads can pass an nvcc-produced cubin or basic fatbin to
`cuModuleLoadData` and launch its kernels through the remoted GPU plane. The
guest shim recovers the parameter count and byte sizes from the cubin's
`.nv.info.<entry>` section. PTX remains the fallback, and an image whose layout
cannot be proved returns `CUDA_ERROR_NOT_SUPPORTED` at launch rather than
guessing through workload pointers.

## Security boundary

- Module input is capped at the GPU protocol's 64 MiB frame ceiling before it
  controls allocation or copying.
- ELF, section-table, section-name, fatbin-entry, and metadata-record ranges
  use checked arithmetic and must remain inside the supplied image.
- Cubins are accepted only as ELF64 little-endian images. Basic fatbin v1
  entries may contain uncompressed cubin or PTX payloads; compressed cubins
  are refused explicitly because this slice adds no decompressor.
- Parameter ordinals are dense, unique, and capped at the wire contract's 256
  parameters. A sparse or conflicting layout is never interpreted.
- A fatbin with multiple parseable payloads must report the same parameter
  layout in each one.

## Work items

- [x] Write red fixtures for PTX, cubin ELF, fatbin, malformed records,
      truncation, bounds, endian, compression, and ordinal caps.
- [x] Add the allocation-bounded dependency-free metadata parser with typed
      failures and the existing PTX parser as its bounded text path.
- [x] Teach the CUDA shim to measure basic fatbins, bound PTX scans, and use
      generic module metadata at function lookup.
- [x] Update the GPU plan, crate documentation, sprint rollup, refactor rollup,
      and delivery evidence.
- [x] Pass the exact full workspace test suite, all-target workspace Clippy,
      gated-target compile, repository gates, and formatting check.
- [ ] Land the issue-closing pull request through the protected merge queue.

## Tests

- `cargo test -p mvm-gpu-shim-core`
- `cargo test -p mvm-gpu-cuda-shim`
- `cargo test --workspace -- --test-threads=1`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `just check-gated`
- `cargo run -p xtask -- check-all`
- `cargo fmt --all -- --check`
