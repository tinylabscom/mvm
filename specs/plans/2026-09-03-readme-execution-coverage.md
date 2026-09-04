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
- [ ] Replace the hosted aarch64 lifecycle witness whose runner is repeatedly
      terminated with a staged x86_64 witness: prepare the sealed bundle with
      QEMU/KVM, then transfer it to a fresh runner that deliberately denies KVM
      and installs and boots it under QEMU TCG. Retain the native aarch64
      workspace lane and the full local Apple Silicon aarch64 TCG lifecycle
      script, and collect a successful hosted run before completion.
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
- The first split build job then proved the handoff and failed immediately on
  the obsolete top-level `build --flake` spelling. The lane now invokes the
  shipped `machine build --flake` surface, and its structural regression test
  pins that exact command so CI cannot silently drift back to a parser-invalid
  entry point.
- The corrected split build entered the real workload build, then a fifth
  hosted arm64 runner was terminated after only 6 minutes 3 seconds (4 minutes
  29 seconds in the build). Effective lifetimes now vary from 6 to 28 minutes,
  so no phase split or retry can make that substrate a reliable witness. The
  hosted lifecycle therefore moves to stable x86_64 with `/dev/kvm`
  deliberately inaccessible; native aarch64 tests and the local Apple Silicon
  lifecycle script preserve the architecture-specific coverage without making
  a false hosted claim.
- The first x86_64 replacement proved source-matched bootstrap on a stable
  hosted runner, but its unaccelerated workload build was also terminated by
  the runner service after 7 minutes 6 seconds. Hosted CI therefore makes the
  shorter claim it can sustain: QEMU/KVM prepares and signs the bundle, and a
  fresh runner denies KVM before installing and booting that exact bundle with
  QEMU TCG. The committed Apple Silicon script remains the full unaccelerated
  build, seal, install, and boot lifecycle witness.
- The full workspace runs exposed parallel-test races in the wasm endpoint-plan
  and workload broker-path witnesses: they read `MVM_HOME` without holding the
  shared environment guard used by the tests mutating that variable. Both now
  pin an isolated home for their whole assertion, including the platform-
  specific short-socket path resolver; all 886 runtime library tests pass
  concurrently and the complete workspace suite is green.
