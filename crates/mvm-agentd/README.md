# mvm-agentd

`mvm-agentd` is the guest-side runtime library and binary collection embedded
in mvm images. It implements the host/guest vsock protocol, launches admitted
workloads, reports health and exit status, and supplies narrowly scoped guest
helpers for networking, mounts, egress, consoles, and host services.

## Who uses it

`mvm-build` compiles and injects the guest binaries into images. `mvm-runtime`,
`mvm-vmm`, and `mvm-backends` share its session and wire behavior on the host
side. `mvm-hostd` speaks the corresponding broker, audit, and supervisor
protocols. `mvm-sdk` and `mvm-host-services` use its in-guest adapters. The root
`mvmctl` crate re-exports selected protocol surfaces.

## How it works

The primary guest agent listens on an unprivileged vsock port. It authenticates
and decodes bounded requests, applies the admitted runtime profile and verb
grants, starts the workload, and multiplexes control, output, and exit events
back to the host. Framing is a length-prefixed typed protocol rather than an
SSH session.

Specialized binaries keep privilege and dependency boundaries small:

- `mvm-guest-agent` owns normal workload lifecycle and health.
- `mvm-runner` and `mvm-oci-entrypoint` prepare and exec the workload.
- `mvm-builder-agent` handles isolated builder sessions and file transfer.
- `mvm-guest-netinit` and `mvm-egress-client` configure or mediate network
  access.
- `mvm-addon-dns` and `mvm-addon-vsock-bridge` expose optional local addon
  services.
- `mvm-seccomp-apply` applies the final sandbox; `mvm-setpriv`, from the
  `mvm-setpriv` crate, applies the final identity.

The guest treats host replies as protocol input, while the host treats every
guest request as untrusted. Host sealing and destination signing material
remain host-side; an opt-in mailbox reader additionally holds its own per-boot
ACK signing key inside the guest agent, not in the workload.

## Guest mailbox reader

Only a signed plan granting this workload's own mailbox can enable Receive.
The agent binds `/run/mvm/mailbox/receive.sock` when its separate boot ACK key
was provisioned. Dev's ephemeral host helper refuses reader frames; a production
mailbox with signed retention uses a locally anchored journal and boot-bound
Receive authority. The local protocol
is versioned, length-prefixed, and bounded; use `ApplicationReaderRequest` and
`ReaderResponse` from `mvm_core::mailbox::reader_wire`. Once backed by that
local destination, `Receive` returns a signed lease,
content type, and payload. Process the payload **before** sending
`Ack { lease }` on a new connection. An empty inbox and a refusal are not
successful delivery; reading never automatically ACKs.

For a guest application example, build:

```sh
cargo build -p mvm-agentd --example mailbox_reader_client --target aarch64-unknown-linux-musl
```

Run it without arguments to read without acknowledging; pass `--ack` only when
writing and flushing its stdout counts as completed processing. The returned
`Acknowledged { ack }` echoes the exact guest-signed operation after the local
journal and anchor commit. This is a trusted-local confirmation, **not** a
destination-signed, exportable ACK receipt. A lost delivery or ACK response is
**unknown**, not success. Retry with the same lease and signed ACK identity
while this boot's agent remains active, or reconcile against the durable
journal; a different ACK for the same lease conflicts.

`mailbox_writer_client` is a separate guest example for staging a message in
the existing outbox. It reports **local staging only**, not signed destination
acceptance; use a host-side durable receipt or journal witness for that claim.

## Bounded entrypoint capture

Entrypoint stdout/stderr readers and the RPC handoff use eight-slot queues plus
per-stream retention rings. Offers never wait for queue capacity. A saturated
ring evicts old output and reports `mvm.stream.gap`, identifying `pipe_reader`
or `consumer_handoff` so their independent loss counts are not conflated.
Completion transfers ownership of the bounded tail instead of sending into a
full queue. Accepted fd3 control records retain their cumulative wire-byte cap
and are not evicted by stdout/stderr pressure.

The ring retains one newest frame even when its byte cap is smaller than a
frame; budget for that allowance, the fixed queue slots and record overhead.
Order is preserved within each pipe, not across pipes. Pending tails and gap
summaries may wait until another offer or EOF. Reader errors/panics produce
`mvm.stream.capture_incomplete` with an unknown tail, without error text or data.

This is invocation-scoped capture over the existing authenticated session, not
an always-on telemetry service or complete tracing coverage. It does not certify
allocation-free/wait-free internals or remove synchronous downstream sinks and
pipe-EOF/reaping waits. VM-lifetime collection remains separate work.

## Main areas

| Area | Representative modules |
|---|---|
| Session transport | `guest_vsock_session`, `flowmux`, `exec_stream` |
| Workload launch | `entrypoint`, `guest_bootstrap`, `runner`, `child_wait` |
| Builder guest | `builder_agent`, `builder_session`, `builder_transfer` |
| Host services | `broker_client`, `host_audit`, `host_time`, `host_cost`, `host_kv` |
| Networking | `guest_net`, `netinit`, `flowmux_egress`, `flowmux_sync` |
| Guest resources | `guest_mount`, `genid`, `lifecycle_hooks`, `console` |

## Features and platforms

`addons` enables the async FlowMux client, the DNS/vsock bridge binaries and
their async dependencies, and `schema` enables protocol schema generation. Linux-only helpers compile as stubs or are target-gated on
other development hosts.

## Developing

Run `cargo test -p mvm-agentd`. Wire changes require round trips through mock
I/O plus malformed, oversized, unauthorized, and replay cases. Linux syscall
and guest-image tests run in the project builder VM.
