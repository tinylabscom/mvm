# Native HVF owned-instance shutdown

Scope: [#4276](https://github.com/tinylabscom/mvm/issues/4276), a prerequisite
for native lifecycle validation under
[#4184](https://github.com/tinylabscom/mvm/issues/4184).

## Authority and wire boundary

The local trusted operator's existing host Ed25519 root authorizes instance
control. The root is the same identity used for signed host-agent registration,
not a producer append credential or a caller-registration credential. Possession
of that root already grants host-control authority. Private directory and socket
permissions do not isolate another process with the same user identity or an
authorized root holder. This contract does not claim host-administrator
resistance or non-exportable signing keys.

`SignedControl` retains its canonical JCS and Ed25519 signature construction.
The additive `hvf_instance_v1` domain distinguishes three operations:

- `challenge`: the supervisor's signed response binding the current VM,
  ownership-generation nonce, fresh client nonce, and connection nonce.
- `stop_hvf_instance`: the operator's signed command binding that same VM,
  generation and connection, with an issuance time.
- `finalized`: the supervisor's signed terminal record for that generation,
  issued only after guest quiescence and successful capture finalization.

The broker daemon refuses all three operations without changing registrations.
Only the instance supervisor implements their lifecycle. A terminal record is
not a client command, and a stop signature is not a terminal record.

The 32-byte nonces are public identifiers, not bearer credentials. Root
verification uses independently located trusted host state; a request cannot
select its own root. The stop path opens the existing root without provisioning,
repairing or replacing it. Bootstrap uses the existing supported host-root
initialization path before admitting any new supervisor, including operational
builders and diagnostic opt-outs.

## Required lifetime binding

Connect only to the expected canonical private control endpoint. Read the peer
PID from that connected socket using the platform kernel API, then arm a
kernel process-exit observer. Only afterward generate and send the client
challenge. Validate the signed response on that same socket before sending stop.
The supervisor must not transfer its connected socket to another process.

A missing peer, failed observer registration, or EOF before the fresh challenge
proof is an unknown lifetime, not an already-stopped success. A PID from runtime
files is neither stop authority nor a substitute for the connected peer.
The endpoint is derived through `config::vm_socket_dir_at`, including the existing
private short-path namespace for deep homes; no request supplies its path.
Owned-child paths query SIGCHLD disposition without changing it and refuse
auto-reaping or non-default handlers. Exclusive reaping and stable disposition
remain a process-internal cooperation requirement, not a guarantee against
arbitrary concurrent reapers or host administration.

Stop acceptance and resident ownership transfer share one linearization gate.
Acceptance rechecks the current generation under that gate. Transfer rotates the
generation before acknowledging the child; a previously authenticated parent
command cannot commit after that rotation. Once stop commits, transfer is denied.
Transfer reserves its generation under a short lock, then releases that lock for
filesystem and capture work. While preparation is pending, control requests are
refused rather than waiting for owner I/O. Commit rechecks the reserved generation
and cancellation under the short lock. Finalization persistence likewise runs
outside the control lock. The control exchange has a two-second monotonic I/O
deadline; this does not claim a bound on underlying filesystem operations during
bootstrap, ownership preparation, root loading or terminal evidence persistence.

Each connection accepts at most one stop command and is then consumed, including
on refusal. A fresh connection has a fresh random connection nonce. Requests
issued in the future or more than 30 seconds ago are rejected; a bounded
monotonic connection deadline independently prevents wall-clock rollback from
extending a request. Repeated stop attempts use a new challenge and may observe
the same already-dispatched stop, but may not authorize another generation.

## Cleanup and failure boundary

Acknowledgment proves dispatch only. EOF, read failure, a terminal record, or
absence of a PID file does not independently prove process death. Cleanup
requires both actual exit of the authenticated connected process lifetime and
matching authenticated successful finalization evidence.

An owned launch handle can retain its child and kernel observer for natural
exit. A later detached client that never established a lifetime observation
cannot reconstruct that proof from a missing endpoint or PID file. It retains
state and reports the uncertainty. Legacy detached instances without this
control protocol fail closed rather than falling back to numeric signals.

Missing roots, authentication failures, deadlines, observer failures, capture
finalization failures and ambiguous status preserve runtime, control and session
evidence. Error cleanup and destructors have the same obligations as explicit
stop. Never-launched resources may be cleaned only when launch admission is
known not to have occurred.

Attestation publication has a distinct post-publication outcome. Guest quiescence
and durable capture, status and workload outcome are prerequisites to minting its
signature. A failure before the attestation is published cannot create successful
evidence. If its own directory sync fails after the signed record becomes visible,
the owner reports `PublishedDurabilityUnconfirmed`, not rollback or capture failure.
That already-visible valid attestation can still prove quiescence when combined
with the normal authentication, exact-generation and independently observed exit
checks. It is not a promise that the attestation itself survives a host crash.
The supervisor reports the durability error and does not delete runtime evidence.

## Hard expiry

Wall-clock and session expiry retain the existing hard self-exit behavior and
timeout exit code 124. They do not grant additional guest execution time for
capture or endpoint cleanup. The HVF expiry killer retains PID, control, helper
and session evidence and does not mint `finalized`. Consequently, expiry can
leave an already-dead instance whose automatic cleanup still refuses because
successful capture/compound finalization was not established. This is a deliberate
compatibility cost, not a reason to fall back to PID signals or state deletion.

The existing backend stop-timing field names remain compatible. For HVF,
`supervisor_signal` measures authenticated request dispatch, `pid_disappearance`
measures the kernel lifetime wait, and `force_kill_wait` is zero because the
supervisor path has no forced-signal fallback. The backend itself does not remove
state; higher-level cleanup must consume successful quiescence first.

## Delivery gate

The pre-activation checkpoints supply typed wire messages, signature/binding
validators, broker refusal, bounded endpoint/client libraries and a serialized
stop/transfer gate. Production boot and cleanup integration require independent
review; helper-only tests do not authorize native VM execution.
Activation requires bounded transport and replay tests,
concurrent stop/transfer tests, cleanup failure tests, and an owned native
quiescence/finalization witness. Startup timing is measured after those security
gates, not used to waive them.
