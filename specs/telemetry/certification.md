# Guest telemetry: backend and security certification

Backing: preview
Validation: `MVM_BDD_ONLY_TAG=telemetry_collection cargo test -p mvm-conformance --features bdd --test conformance`

The record for W6 of the
[host-mediated telemetry plan](../plans/2026-09-17-host-mediated-telemetry.md):
what has been run on real backends, what is witnessed by tests, the measured
cost, and what is not certified. A row says *live* only when a booted guest on
that backend produced the evidence.

## Backend matrix

| Backend | Status | Evidence |
|---|---|---|
| Firecracker (Linux KVM) | **live** | Reference host (AMD Ryzen 5 3600, Linux 6.1), 2026-10-12. Detached machines with no egress (collector-only) and with egress (collector embedded in the endpoint) each reached `collecting`, held a sealed records file, and their collector exited on `machine stop`. An idle session stays one session (two coverage announcements in 40 s). With collection on by default, a detached machine's workload `stdout`/`stderr` lines appeared in `mvmctl machine telemetry` (`stdio 6` for three lines on each stream). |
| HVF (macOS 26+, Apple Silicon) | **live** | Apple M4 Max, debug build, 2026-10-12. A detached machine reached `collecting` with a sealed records file; the collector exited on `machine stop`. |
| Firecracker warm claim | **live** | A transient `run` claimed from a standby parent booted with collection on reached `collecting` under the child's VM id, with the agent's records delivered, collected only after the claim succeeded. Unit witnesses: `telemetry_follows_the_boot_that_asserted_it`, `a_boot_without_an_endpoint_still_starts_its_telemetry_collector`. |
| HVF warm claim | unit-witnessed | The Mac's debug build did not meet the 300 ms warm ceiling with or without collection, so no claim completed there. |
| libkrun, QEMU, `apple-container` | not certified | Same dial paths (per-port socket) as HVF; never booted with collection. |
| Wasm | not applicable | No vsock; needs a separate host adapter (inventory row in `sources.toml`). |

## What a first live run found

Before the fixes recorded in the W4 section of the plan, no ordinary launch
collected anything: a VM with no endpoint had no collector, Firecracker had no
socket to dial, and every session failed authentication against a signer that
only broker services start. Mocks and in-process witnesses had passed
throughout; each of the three surfaced only on a booted guest. That is the
reason this record distinguishes *live* from *unit-witnessed*.

## Security properties and their witnesses

- **Authenticated, encrypted, typed transport; no other way out.** Wire
  refusals for wrong boot/VM/generation, replay, tamper, unknown versions,
  oversize and malformed input (`crates/mvm-core/tests/telemetry_contract.rs`
  and the transport tests); no plaintext on the wire and no raw or direct
  exporter fallback (`crates/mvm-agentd/tests/telemetry_routing.rs`,
  `check-guest-agent-runtime-free` forbids OpenTelemetry crates in the agent).
- **Identity.** A sibling VM's registered guest cannot feed this VM's
  collector (`a_sibling_vms_registered_guest_cannot_feed_this_vms_collector`);
  an unregistered key degrades the collector
  (`a_guest_with_an_unregistered_key_fails_authentication_and_degrades`).
- **Synthetic secrets never reach disk, a reader or the CLI.** Withheld whole
  or split across any number of stdio chunks, across hold expiry, session ends
  and stream crowding (the `telemetry_collector::sink` tests); through a real
  authenticated session into the sealed file
  (`the_embedded_collector_dials_authenticates_and_persists_what_it_receives`);
  and through the operator CLI (BDD below).
- **At rest.** Lines are sealed under a per-VM key wrapped by the host
  transcript KEK; a line under another key, a plaintext line, or a host without
  the KEK reads nothing (`a_sealed_line_opens_only_under_its_key_and_hides_the_record`,
  `records_need_the_hosts_key_and_a_line_under_another_key_is_not_served`).
- **Bounded and non-waiting.** Producer admission never waits and full queues
  shed with counted losses (outbox and capture-session tests, the
  [baselines](baselines.md) and the [overflow decision](overflow-evaluation.md));
  a stalled or trickling host fails the session within its deadline
  (`a_host_reading_one_byte_at_a_time_cannot_stretch_a_frame_past_its_deadline`);
  a stalled disk costs records, not the session
  (`a_stalled_writer_costs_counted_records_never_a_waiting_receive_loop`);
  one VM's stall does not slow another's collector
  (`a_stalled_vms_collector_does_not_slow_another_vms_collector`).

## Operator-visible behaviour (BDD)

`features/suites/s34_telemetry_capture/`, tag `@telemetry_collection`. Each
scenario runs the guest agent's own capture subscriber and capture session
against an authenticated host receiver and the collector's scrub and sealed
sink, writes where a VM's collector writes, and reads back through
`mvmctl machine telemetry`:

- an event emitted outside any span arrives as a standalone event;
- guest agent diagnostics and its coverage announcement arrive;
- one machine's telemetry is not shown for another;
- a guest that floods diagnostics with no host reading loses records
  visibly — every emission returns at once, and the loss summary arrives with
  the session;
- a record carrying a secret bound to the machine is withheld, counted, and
  absent from the output;
- a detached machine's workload stdout and stderr are readable without the
  guest.

## Cost

Cold named boots on the Firecracker reference host, 15 interleaved pairs:
median 860 ms with collection on, 872 ms off; the collector start runs beside
the boot and its own work measured about 4 ms.

Warm claims start no collector until the claim succeeds. On the same host,
from a fresh MVM home, eight warm launches with collection off and eight with
it on (alternating blocks of four): startup medians 165 ms and 166 ms,
`warm_claim` medians 76.6 ms and 75.8 ms — inside the 300 ms ceiling, and
level with the same measurement of `main` (about 190 ms and 78 ms). The same
build in a home that had served a day of test launches took about 270 ms to
claim, collection on or off: warm-claim cost grows with the state a home has
accumulated, independent of telemetry.

## Not certified

- Spans: the contract carries them, but no guest producer emits them yet.
- The interval before the guest agent starts (reported as unavailable).
- libkrun, QEMU and `apple-container` live runs; an HVF warm-claim witness.
