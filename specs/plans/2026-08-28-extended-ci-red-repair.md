# Extended CI red repair

Backing: shipped-source
Validation: check-sprint-append

**Issue:** [#2979](https://github.com/tinylabscom/mvm/issues/2979)

## Outcome

The scheduled Extended CI witnesses use platform-correct prerequisites and a
launchable macOS runner, and an installed portable bundle can be launched by
the SHA-256 address printed by `mvmctl bundle install`. The repair preserves
the bundle protocol's existing SHA-256 content address; it does not introduce
a competing BLAKE3 address or re-hash the archive.

## Failure boundaries

- Linux invoked a combined helper recipe that enabled `libkrun-sys`, even
  though the Linux job neither uses libkrun nor installs its headers.
- Both documented-surface jobs invoked the SDK codegen witness through `uvx`
  without installing `uv`, and neither warmed the source-matched SDK sidecar.
- `bundle install` printed a launch command using the installed bundle's
  64-character SHA-256, but `resolve_manifest_arg` treated every such value as
  a manifest-path slot and never reached the existing slot-or-bundle runtime
  dispatcher.
- `macos-latest` selected an arm64 hosted VM whose Hypervisor.framework call
  returned `HV_UNSUPPORTED`. The live witness now uses the current Intel runner
  label rather than pretending a skipped arm64 boot is evidence.

## Delivery checklist

- [x] Reproduce all three failed jobs from Extended CI run 33192385988.
- [x] Add structural regressions for platform-scoped helper builds, `uv`, the
      source-matched SDK sidecar, and the live macOS runner selection.
- [x] Add a resolver regression proving an installed bundle SHA-256 reaches
      the bundle registry while materialized slots retain identity checking.
- [x] Build libkrun and HVF helpers only on macOS while retaining the portable
      network endpoint on every host.
- [x] Install `uv` in both documented-surface jobs and build the checkout's SDK
      sidecar once before the live scenarios.
- [x] Reuse `template_load_dispatched` for ambiguous 64-character slot or
      bundle addresses.
- [x] Pin the live HVF witness to `macos-15-intel` instead of the unsupported
      arm64 hosted VM selected by `macos-latest`.
- [x] Pass focused Extended CI contracts, all shared resolver tests, formatting,
      and zero-warning `mvm-cli` Clippy.
- [x] Rebase onto the latest merged `main` and pass full workspace and repository
      gates.
- [ ] Pass a fresh Extended CI run containing all repaired witness lanes.
- [ ] Merge the corrective pull request and close #2979 through its linkage.
