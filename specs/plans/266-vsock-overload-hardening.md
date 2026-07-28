# Vsock overload hardening

Issue: #1827

Status: COMPLETE

## Goal

Keep guest-generated traffic from exhausting host sockets, connection state, or
the host-side network path when a workload is dead, unresponsive, or sending
more traffic than its approved egress path can deliver. Production workloads
remain NIC-less; the authenticated vsock seam is the primary enforcement point.

## Delivery checklist

- [x] Bound the per-device received-credit table to 256 connection identities,
      use a typed connection key, saturate credit accounting, and refuse new
      identities with `OP_RST` once the table is full.
- [x] Bound substitution, host-agent, and dev-console bridge connection sets
      to the same per-device ceiling; refuse before opening another host socket.
- [x] Add focused cap, slot-reuse, existing-stream, and bridge refusal tests.
- [x] Add idle timestamps and deterministic eviction for inactive bridge and
      credit-table entries, with `OP_RST` cleanup for the guest side. The fixed
      60-second window covers substitution, agent, console, and transport-credit
      state; host-side EOF and idle expiry both remove the credit identity before
      the reset is queued.
- [x] Add per-workload concurrent-stream and byte-rate budgets around raw,
      SOCKS5, DNS, and substitution egress, preserving kernel backpressure.
      The egress and broker vsock ports share a 128-stream ceiling, an 8 MiB
      burst, and a 4 MiB/s token refill; refusal closes the stream fail-closed.
- [x] Cancel active egress sessions as part of VM teardown and prove that a
      dead workload cannot retain host sockets after its stop path completes.
      `VirtioVsock::shutdown` now stops the host-I/O thread and explicitly closes
      agent, console, broker, and egress bridge state before guest RAM is freed.
- [x] Evaluate null-node routing for the optional packet gateway path; it is
      separate from the production NIC-less vsock path. No production route is
      added: the packet-forwarding gateway was removed, rejected vsock streams
      already reset at the authenticated seam, and a guest-wide default
      blackhole would also break the admitted loopback egress client.
- [x] Run the workspace check, tests, formatting, and Linux-builder clippy
      gates; the required GitHub CI gates passed on #1878. The one local full
      runtime-test failure was environment-only: the `mvm-substitution-endpoint`
      helper is not built in the source checkout.

## First slice

The first slice is intentionally transport-local. A guest controls its vsock
source port, so an unbounded map or bridge set turns that field into a host
resource-exhaustion primitive. The cap is fail-closed: a new identity gets an
`OP_RST`, an existing identity continues to make progress, and `OP_SHUTDOWN`
releases the slot. No raw packet forwarding or host NIC is introduced.

## Idle eviction slice

Each tracked stream records monotonic last activity. The host bridges expire
inactive Unix sockets before accepting more work and surface the closed
connection to the handler, which removes the matching receive-credit identity
and sends one `OP_RST` to the guest. The transport credit table runs the same
idle sweep at the end of host-I/O service, so guest-selected identities cannot
remain allocated after their bridge state disappears. Tests use injected
`Instant` values at the timeout boundary rather than wall-clock sleeps.

## Egress budget slice

The egress and broker relays share one budget per workload, so opening both
authenticated vsock paths cannot multiply the allowance. A stream reserves a
concurrency slot before the endpoint socket is opened and releases it on EOF,
reset, or idle expiry. Both relay directions consume the same monotonic token
bucket; a depleted bucket resets the stream instead of buffering an unbounded
host-side queue. The existing non-blocking socket relay remains the only writer,
so the budget limits admission while the kernel retains normal socket
backpressure.

## Teardown and null-node decision

`VirtioVsock::shutdown` first joins the host-I/O worker and then cancels every
bridge, releasing connection slots and dropping endpoint sockets. The transport
credit table and pending receive packets are cleared before the VMM returns;
the backend stop path separately reaps the per-workload endpoint process.

The requested null-node route belongs to the retired packet-forwarding gateway,
not to the current production path. Workloads are NIC-less and rejected traffic
is reset at the authenticated vsock seam; adding a default guest blackhole
would also blackhole the loopback proxy used by admitted egress. Keep this as a
future, explicitly admitted packet-gateway feature rather than widening the
production networking boundary.
