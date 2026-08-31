# Wasmtime security update

Backing: shipped-source
Validation: check-sprint-append

**Issues:** [#3018](https://github.com/tinylabscom/mvm/issues/3018),
[#3020](https://github.com/tinylabscom/mvm/issues/3020)

## Outcome

The optional Wasm backend uses Wasmtime 46.0.3 or newer in the 46.x line, so
the filesystem trailing-slash sandbox escape (RUSTSEC-2026-0269) and the WASIp3
stream allocation vulnerability (RUSTSEC-2026-0268) are absent from the locked
dependency graph. Scheduled Security and claim-freshness workflows return to
green after the repair lands.

## Delivery checklist

- [x] Reproduce the scheduled Security failure and identify both advisories in
      Wasmtime 46.0.2.
- [x] Update the complete exact-version Wasmtime and Cranelift family to the
      patched 46.0.3 release.
- [x] Verify `cargo audit` reports no vulnerabilities.
- [x] Compile and test the optional Wasm backend with zero Clippy warnings.
- [x] Pass repository policy and sprint consistency gates.
- [ ] Merge the corrective pull request through the queue.
- [ ] Run fresh Security and claim-witness-freshness workflows on merged
      `main`, then close both issues with the green evidence.
