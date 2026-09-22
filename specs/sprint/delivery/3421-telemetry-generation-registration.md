# Telemetry boot-generation registration

Issue #3421, part of W2b of `2026-09-17-host-mediated-telemetry`; epic #3419
remains open.

`mvm_vmm::host::telemetry_registration` binds a guest's telemetry key to one
boot: a per-VM `telemetry-registration.json` carrying the VM name, a fresh
16-byte hex boot id, a per-state-dir monotonic generation, and the guest
verifying key — written atomically, validated before writing, superseding any
earlier record. `resolve_expected_telemetry_peer` and `assert_peer_is_current`
are the sequence a dialer must run before authenticating; refusals name the
failure (never registered, wrong VM, invalid key, stale boot/generation).

Wiring is at the single identity seam in the workload runner's endpoint
spawner: both `prepare_observation_identity` (identity-only boots, standby,
inherit on claim/restore) and the full endpoint spawn (minted and inherited
arms) register the boot immediately after establishing the identity, so
cold, standby, warm-claim and restore paths all produce a current
registration without a second code path.

Why generation matters at all: a warm child restores its parent's signing key
from memory, so the cryptographic session authenticates both boots equally.
The integration witness
(`a_stale_boot_expectation_is_refused_even_though_the_session_still_authenticates`)
pins exactly that: after a same-key re-registration the encrypted handshake
still succeeds under the old expectation, and only `assert_peer_is_current`
refuses the superseded boot. The registration gate is the boot discriminator,
which is why the dialer's sequence is resolve → assert-current → connect.

## Validation

- Seven focused registration tests (first/re-registration semantics, the
  stale-boot refusal with an unchanged key, wrong-VM and missing-record
  refusals, invalid-key refusal at registration and resolve, fail-closed
  parsing with unknown fields), plus the transport-level integration witness
  above, plus extended spawner tests asserting the registration file and
  resolved peer on the mint and inherit arms.
- Affected crates: 1,815 tests pass across `mvm-vmm` and `mvm-runtime`
  (11 skipped). Full battery results are recorded on the PR after rebase.

Not claimed: no guest listener on the telemetry port, no host dialer or
collector, no over-the-wire routing witness, and no runtime consumer of the
resolver yet — the future collector is its consumer, and W2b stays open on
those. Registration alone certifies no capture. Do not close #3421 or #3419
on this delivery.
