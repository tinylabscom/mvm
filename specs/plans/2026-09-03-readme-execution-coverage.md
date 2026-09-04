# Execute the documented README surface

Backing: shipped-source
Validation: check-sprint-append

**Status: IN PROGRESS**

## Goal

Make the README example register truthful and executable for the 0.18 release:
run every supported example, leave only an explicit unsupported exemption, and
fix product defects uncovered by exercising the documented commands.

## Delivery

- [x] Replace the bootstrap, kernel-download, template-generation, and peer
      exemptions with executable hermetic or live witnesses.
- [x] Remove the unreachable dependency workflow from the README and preserve
      its restoration criteria in a dedicated follow-up plan.
- [x] Start the outbound guest path for peer-only network policies and prove a
      documented guest-to-peer exchange against a real backend.
- [x] Require builder backends to declare capabilities, fall back when an
      automatically selected backend declines an operation, and report an
      unusable builder as a normal error instead of a panic.
- [x] Bind witness matching to enum-valued CLI modes so one behavior mode
      cannot falsely cover another.
- [x] Render the real Clap help tree in-process for exhaustive command-path and
      entry-form coverage while retaining real-binary probes.
- [x] Run the complete hermetic BDD suite and focused suites for every touched
      crate.
- [x] Give each bounded phase of the aarch64 TCG witness a fresh runner window:
      transfer exact source and release-helper binaries, source-built bootstrap
      artifacts, and the sealed bundle through immutable artifacts; pin every
      handoff and explicit QEMU builder selection with a structural regression
      test.
- [ ] Run the documented surface end to end on Linux/Firecracker and collect
      the macOS/HVF evidence required by the release gate.
- [ ] Merge the implementation through the queue.

## Decisions

- A reviewed exemption names missing execution; it never points at a lane that
  exercises adjacent machinery but not the documented command.
- Flag values are part of the witness identity when Clap defines a closed value
  set, because those values select distinct behavior rather than ordinary data.
- Help coverage calls the binary's own dispatch arm without a process boundary.
  Three subprocess probes retain coverage of the executable integration edge.
- Explicit builder selection remains authoritative. Fallback is available only
  when automatic selection chose a backend that truthfully declines the
  requested operation.
- Three aarch64 hosted jobs were terminated by the runner service after
  27–28 minutes despite a 300-minute job timeout. After binary compilation was
  split out, a fourth fresh runner was terminated after 14 minutes 20 seconds:
  source-matched bootstrap had completed, but left only 5 minutes 15 seconds
  for the workload build. Compilation, bootstrap, sealed bundle build/export,
  and installed-bundle boot therefore occupy separate jobs connected by
  immutable artifacts. No live phase rebuilds or substitutes the exact source
  binary under test.
