# Aux host-helper contract verification

Backing: shipped-source
Validation: check-sprint-append

**Issue:** recurring "unknown field" spawn failure when a release `mvmctl` is
answered by a stale helper binary from the other cargo profile
(`target/debug/mvm-hvf-supervisor`), or by any helper built from an older
revision. The failure surfaced only at supervisor spawn — after the guest
runtime build — and earlier mitigation only improved the error message.

## Outcome

A host helper is never spawned unless it provably speaks the same config
contract as the running `mvmctl`. Helpers carry a compiled-in contract version
and answer a `--contract-version` probe. `mvmctl` probes before spawn: a
matching helper runs; a stale helper found in a source checkout is rebuilt
automatically in the running binary's profile; anything else fails immediately
with an error naming both versions and the exact rebuild command. Cross-profile
silent fallback is gone.

## Delivery checklist

- [x] `mvm-vmm::host::helper_contract`: `HOST_HELPER_CONTRACT_VERSION`, probe
      flag, response emission, and strict response parsing.
- [x] All host helpers answer the probe: `mvm-hvf-supervisor`,
      `mvm-libkrun-supervisor`, `mvm-network-endpoint`, and `mvmctl` itself
      (the qemu bridge re-execs the `mvmctl` binary).
- [x] `aux_bin::resolve_verified`: probe, compare, auto-rebuild in checkout,
      hard error elsewhere; stale picks are never returned.
- [x] Spawn call sites use the verified resolver; availability probes and
      codesign enumeration keep the pure resolver.
- [x] Config-shape hash pin next to the version const forces a version bump
      when `HvfSupervisorConfig` changes.
- [x] Profile-mismatch warning machinery removed (subsumed by verification).
- [x] Tests green on host; workspace clippy and gated-target checks green in
      the builder VM.
- [x] `specs/SPRINT.md` updated; merged via #3132 (squash `2eff78c623`).
