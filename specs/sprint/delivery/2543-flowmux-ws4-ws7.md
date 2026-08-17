# One transport, finished: WS4–WS7 and the gate that keeps it that way

Issue [#2543](https://github.com/tinylabscom/mvm/issues/2543), plan
`specs/plans/2026-08-15-flowmux-single-transport-cutover.md`. Completes WS4–WS7 and the
hermetic BDD scenarios.

## What was still broken

WS0–WS3 put every guest and its endpoint on one authenticated FlowMux session, and the endpoint
began serving it. Two verbs never moved: secret substitution still framed a `WireRequest`, and
`ping` still opened with a `MVM_ICMP/1` line. Both dialled the same port — `EGRESS_PORT` *is*
`NETWORK_FLOW_PORT` — so both had been talking to a host that no longer answered them.

## WS4 — substitution as a typed HTTP flow

`OpenHttp` → `HttpRequestHead` → `HttpRequestBody`*, answered by `HttpResponseHead` →
`HttpResponseBody`* → `HttpComplete`. The head declares `body_len`, because treating a
half-close as the end makes "finished sending" and "went away mid-body" the same event on the
host, and the host would forward a truncated request rather than refuse it.

Substitution itself did not move. The `Http` arm assembles frames into the `WireRequest`
`SubstitutionService::process` already takes and calls it, so placeholder resolution,
destination binding, the claim-10 gate and payload-free audit stay where they are. `process`
runs on the runtime, not the session's blocking read loop: it is async and tokio's `block_on`
panics inside `spawn_blocking`, and an inline forward would stall every other flow behind one
slow upstream.

Two hard gates: an `OpenHttp` on an endpoint with no substitution service is refused rather
than forwarded unsubstituted, and an endpoint carrying secrets with no substitution service
refuses to boot. Placeholders are minted and injected regardless of either, so without one the
guest sends `mvm-secret-<hex>` to a real upstream — a leak to a third party, not a local
failure.

## WS5 — ICMP as a one-shot flow

`IcmpEcho` → `IcmpReply` | `IcmpRefused`, shaped like a DNS lookup: the reply confirms the flow
and ends it. The decision is `icmp_handler::serve_request` — parse, bounds, admission, rate,
echo — unchanged and shared, so no transport can drift on what is allowed.
`emit_icmp_echo_blocking` lost its Linux gate; it was gated because the blocking vsock
transport was its only caller, and leaving it would have left an echo served on macOS
unaudited.

## The blocking client both needed

`forward_proxy` and `icmp_client` are in `mvm-guest-agent`, whose closure is deliberately
tokio-free. `flowmux_sync::SyncFlowMux` opens a connection, does one authenticated exchange and
closes. Nothing new was required to make it blocking: `Session::guest` already takes
`Read + Write` and the frame codec is `no_std`.

Several sessions is not several transports — one wire contract, one auth boundary, one gate.

## WS6 — the alternatives, and the gate

Gone: `EgressMode::Raw`, `serve_raw`, the whole guest-facing `raw_egress` dispatcher (~660
lines) and its 14 tests, `substitution_client::substitute`, and the `can_skip_substitution_assembly`
shortcut that only `raw` used. `resolve_hostname_ips_pure` stays — `dns_handler` and
`socks5_udp` pin names through it on the FlowMux path too.

**Deliberately kept: `EgressMode::Wire` and `substitution_client::relay`.** The plan listed
them for deletion, but their one remaining consumer is the wasm tier's `mvm:egress` host
import, which runs in the *host* process and connects to the endpoint's Unix socket. That is
host-internal IPC between two host processes, not a guest speaking to its host, so it is not on
the channel the one-transport rule governs. Moving the wasm tier onto FlowMux would mean giving
a host process a guest identity, which is a different change with a different argument.

`xtask check-one-guest-protocol` is the recurrence gate. Two checks: no retired line marker in
guest or host sources, and every guest file that opens the egress port constructs a FlowMux
client. The second is checked against the file's own text rather than an allowlist of paths —
an allowlist is silenced by adding a name to it, which is exactly the move someone makes while
introducing what the gate exists to catch. Both halves were confirmed red against a planted
regression and green after.

## WS7 — readiness fails closed

An endpoint binds and prints its handshake line before the guest boots, so "ready" never meant
a guest had reached it. The endpoint now records its first authenticated session to
`substitution.session` in the per-VM state dir, and
`refuse_launch_without_endpoint_session` fails the launch when it is absent, distinguishing
"the endpoint exited" from "the endpoint is up and no guest ever authenticated" — the second is
what a mismatched identity looks like.

Checked **after activation**, in `exec.rs` right after the agent becomes reachable. A pre-boot
wait would deadlock on an event the wait itself prevents. A boot with no endpoint at all — no
secrets, deny-egress — is admitted rather than refused; the pid file is the evidence one was
spawned.

## Tests

Hermetic throughout. The guest↔host substitution round-trip captures every frame the guest
emits and asserts the real credential appears in none of them — claim 13 on this transport,
checked on the bytes. Five new BDD scenarios in `one_transport.feature` state the rules the
gate enforces, and the secret-bearing one calls the real
`refuse_secrets_without_substitution` rather than a copy of it (which is why that function
moved from the endpoint binary into the library).

## It prints `4`

    $ mvmctl machine run --image python:3.12 -- python -c 'print(2 + 2)'
    4

Exit 0, macOS/libkrun, warm kernel cache. Zero resets, truncations, SOCKS
failures, credit exhaustion or supervisor refusals in the run — the datapath
that used to truncate every transfer at 48 KiB now carries a full nixpkgs
closure and a kernel build without a frame error.

The last blocker was outside this plan: the supervisor's wall-clock timer
decoded the admitted plan as a bare `ExecutionPlan` when every producer emits
the signed envelope, so it refused every plan-bearing boot on the macOS
backends. That is #2564 / #2555, already in main; #2579 was a parallel diagnosis
of the same bug, closed as superseded.

## Scope note

WS4 and WS5 are proven hermetically rather than by a dedicated live run — a
secret-bearing workload and a `ping` each have in-process round-trip coverage
instead. That was the scope decision taken when the work started; the live
`python:3.12` run above exercises the transport they ride on, not those two
verbs specifically.
