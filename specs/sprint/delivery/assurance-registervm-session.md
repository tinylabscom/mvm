# The assurance session reaches the process that serves probes

Plan: `specs/plans/2026-08-17-admission-bound-ai-assurance-sessions.md` (W9b)

## What landed

An admitted assurance session now travels on `RegisterVm` and is opened by
`daemon::register` against the handler it has just built. That closes the
topology gap: the plane is installed when the registry is built, so the daemon
is the only process where a session can usefully exist, and it is now the
process that opens one.

## Why `RegisterVm` and not `SubprocessConfig`

An earlier attempt put the session on `SubprocessConfig` and had `mvm-broker`
open it. Two things were wrong, and both were found by tracing the destination
rather than reasoning outward from the ledger:

- **It is not the live path.** Nothing in production constructs a
  `broker::config::SubprocessConfig`; the `mvm-broker` subprocess is not
  spawned. Registration goes through the `mvm-host-agent` daemon.
- **It is the wrong trust envelope.** `SubprocessConfig`'s own docs record that
  it is unsigned and that a compromised supervisor could redirect the audit
  back-channel. `RegisterVm` is host-signed.

Adding a security-relevant field to an unsigned envelope on a dead path is
worse than adding none, so that work was reverted rather than landed.

## Signature stability is the constraint that shaped the field

`ControlRequest` is signed over its JCS canonical bytes. A field that
serialized on every registration would move those bytes and invalidate every
signature produced before it existed — which is exactly why
`capability_bindings` is skip-serialized when empty. The assurance field
follows that precedent, and two tests hold it: an absent campaign leaves the
serialized bytes free of the key, and a registration written without the field
still parses.

## Where the types live, and why it is not arbitrary

`PlanIdentity`, `DeclaredEdge` and `AdmittedAssuranceSession` are in
`mvm-contract`. The carrier decides: `RegisterVm` is declared there, and its
production constructor is in `mvm-vmm`, which sits *below* `mvm-hostd`. A
session type defined beside the ledger could not be named at either end of the
hop it has to make.

`PlanIdentity` carries the six fields `supervisor::for_plan` reads and nothing
else, so the receiving process still never holds a plan.

## Nothing is judged twice

Every field that crosses is a decision already taken: the binding names a plan
the supervisor verified, the authority is post-intersection, the destinations
are resolved. The daemon narrows nothing and resolves nothing — the same shape
as `services_bindings`, which is also decided elsewhere and merely enforced.

Both refusals open nothing rather than something partial. A session whose
service is not bound, and a session with no audit route, each describe a
registration this daemon should not serve; the probe verb answers `NotBound` or
`AuditUnavailable` either way.

## What this still does not do

Nothing populates `RegisterVm.assurance` yet. The supervisor must mint the
session at admission and pass it through `HostAgentServicesParams`, which is a
cross-repo change: mvmd constructs that struct too. That is the last hop, and
it is now a parameter-threading job rather than a design question.
