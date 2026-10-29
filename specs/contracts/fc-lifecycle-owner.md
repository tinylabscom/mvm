# Firecracker persistent lifecycle owner

Status: **Preparatory contract and test model. No process host, positive
factory, protocol version or native mechanism is enabled.**

Scope: [PS-06 #3716](https://github.com/tinylabscom/mvm/issues/3716), coordinated
with [#4414](https://github.com/tinylabscom/mvm/issues/4414) and
[#4839](https://github.com/tinylabscom/mvm/issues/4839).
[ADR-022](../adrs/022-target-architecture.md#3-host-process-model--separate-role-binaries-across-three-tiers)
still describes direct Firecracker driving without a separate supervisor.
Changing that accepted process model requires a recorded FC-specific decision.
HVF owner approval does not supply it.

## Proposed boundary

One invoking-user Linux process would host one typed client lifecycle and create
the original Firecracker process. CLI and Studio would use the same library
service, not execute mvmctl or replay CLI arguments. No new crate, privileged
service, generic backend framework or broker/host-agent role reuse is proposed.
Executable packaging and identity must be reviewed before launch wiring.

The live owner must retain admission, final configuration, original frozen boot
inputs, volume/runtime leases, output and independent errors through uncertainty.
Neither an owner nor native completion is serialized. PID markers, endpoint
paths, persisted generations and audit metadata cannot restore original custody.
FC terminal Exec, same-session Sync, original-process exit, cleanup and audit
outcome remain separate requirements for successful execution; HVF `ConfirmedExit`
is not an FC proof. Safe abort instead requires original child-free preparation
or confirmed original-process exit, plus cleanup/audit and durable retirement.
It must not fabricate Exec/Sync success or a successful execution receipt.

## Operation semantics

| Event | Required behavior |
| --- | --- |
| Start | Register the operation and exact request binding before native effects. An identical retry observes it; conflicting reuse refuses. Never redispatch to resolve a lost response. |
| Activate | Require durable quarantine, current admission and qualified native enforcement before birth. Returning start acceptance alone does not prove activation. |
| Observe | Authenticate the same controlling principal and connection-bound operation. Missing owner means unknown, not “never started.” |
| Detach | Commit explicitly after actual activation/readiness/accounting. Losing its response does not undo commitment; query the same operation. EOF cannot commit detach. |
| Disconnect | Before detach commitment, request bounded cancellation. After commitment, disconnect does not implicitly cancel detached execution. |
| Cancel/stop | Serialize with activation/dispatch and remain serviceable under slow output or guest I/O. Use the original owner; pre-execution or uncertain cleanup uses abort, never successful completion. |
| Result ACK | Acknowledge delivery of the exact terminal revision only. Early/stale ACK refuses; repeated delivery cannot repeat cleanup or audit sealing. |
| Owner death | Keep generation-bound quarantine. No original-owner reconstruction, automatic restart, generation replacement or numeric-PID cleanup. |

Record quarantine durably before native effects. All volume reuse, image deletion,
generation replacement and automatic restart must honor it. Only the original
live owner may retire the matching quarantine after the applicable successful
execution or safe-abort proof, cleanup/audit and durable retirement. Failed or
interrupted retirement refuses reuse. Administrative reconciliation after owner
loss is outside this API.

## Authentication and key custody prerequisites

Same UID, a private socket and knowledge of the generation are insufficient.
Enroll the controlling principal under independently authorized policy at start.
Later control requires fresh proof by that same principal over the actual
connection, challenge, tenant, operation/request digest, plan/configuration,
owner incarnation, native generation, verb and sequence. No delegated recovery,
socket forwarding or plaintext bearer state is proposed.

Bindings are phase-appropriate: before admission/birth, Observe and cancellation
bind the original request and owner incarnation, without inventing an admitted
plan, effective configuration or native generation. Add each actual binding when
established; every subsequent request must bind the applicable retained values.

The reviewed admission context contains a key-bearing audit emitter. It cannot
simply move into a new parser process. Narrow independently authorized key-holder
operations are required for admission, canonical audit closure and lifecycle
authentication/control. Existing plan/telemetry or caller-registration signing
purposes are not implicitly reusable. No raw key, unrestricted sign-bytes oracle
or local-key fallback is permitted. Missing reviewed services refuse activation.

## Native containment prerequisites

Both the host and FC must be bounded from birth under the invoking UID. No
sudo, shell, setpriv, systemd-run, post-spawn cgroup move or privilege escalation
qualifies. Missing delegated cgroup/controller/kernel support refuses before birth.

Linux `clone3` with `CLONE_INTO_CGROUP` and `CLONE_PIDFD` is a candidate for
review, not an existing factory. It would retain an original pidfd and reap
responsibility, not reconstruct a `std::process::Child`. Native boundary safety,
descriptor lifetime and actual permission/controller support require review.

Parent-death signaling alone is not qualified containment. The creation-to-arming
race, spawning-thread lifetime, exec transitions, descendants and bounded cessation
must be closed by the selected mechanism and demonstrated on Linux. Frontend death
must not kill a deliberately detached host. Quarantine is a refusal record, not
execution containment or terminal evidence.

The following qualification ceilings are proposals, not approved defaults or
measurements. Signed policy/operator ceilings can only narrow them.

| Surface | Proposed maximum |
| --- | --- |
| Bootstrap / included stdin | 256 KiB / 64 KiB |
| Control frame / whole control exchange | 4 KiB / 2 seconds monotonic |
| Connections / mutating operations | 4 including handshakes / 1, no waiting mutation queue |
| Combined captured output / chunk | 16 MiB / 16 KiB |
| Startup / guest execution / one stop attempt | 30 / 300 / 15 seconds |
| Owner | 256 MiB memory, no swap, 32 tasks, 128 FDs, 60 CPU seconds |
| FC | 4 vCPUs, 2 GiB guest RAM, 2560 MiB host memory, no swap, 64 tasks, 256 FDs, 1200 CPU seconds |

Cancellation intent must have independently reserved/coalesced intake and cannot
wait for the active mutation or output queue to drain. This is a required scheduler
property, not something established by the synchronous test model.

Guest RAM is not host RSS; CPU time is not a share quota; per-UID limits are not
per-VM limits. Supporting processes need their own reviewed bounds and closed
role inventory. No caller-authored “limits verified” flag can replace enforcement.
Until each mechanism and profile is approved and qualified, no positive factory
may be connected.

## Evidence boundary

`crates/mvm-client/tests/fc_owner_contract.rs` is an executable **test-only
model** of sequencing/refusal rules. Its integer identity labels and simulated
persistence/terminal facts are not authentication, durable storage, native proof
or an implementation of the proposed service. It intentionally imports no runtime
or production owner and cannot enable execution.

Its binding fixture prepopulates synthetic plan/configuration/generation labels;
it does not model their phase-dependent acquisition. Comparison of those labels
is not connection/challenge/sequence authentication. Other unmodeled requirements
include admission count/refusal, native enforcement, readiness/accounting, frame
parsing, real I/O backpressure and concurrent cancellation scheduling.

Next stages require independently reviewed keyless services and native placement/
death containment, then actual library/CLI persistent wiring and failure injection.
The original-member metadata checks, producer A/B releases, authenticated A hash H,
current independent revocations, signatures/attestations, consumer lifecycle and
resource census remain separate PS-06 acceptance. H and protected-observer
authorization remain closed. Model tests, source review and compilation cannot
check those acceptance boxes.
