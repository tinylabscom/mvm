# Vsock overload hardening

Issue: #1827

Status: IN PROGRESS

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
- [ ] Add idle timestamps and deterministic eviction for inactive bridge and
      credit-table entries, with `OP_RST` cleanup for the guest side.
- [ ] Add per-workload concurrent-stream and byte-rate budgets around raw,
      SOCKS5, DNS, and substitution egress, preserving kernel backpressure.
- [ ] Cancel active egress sessions as part of VM teardown and prove that a
      dead workload cannot retain host sockets after its stop path completes.
- [ ] Evaluate null-node routing for the optional packet gateway path; it is
      separate from the production NIC-less vsock path.
- [ ] Run the workspace check, tests, formatting, and Linux-builder clippy
      gates; resolve any failures attributable to this plan.

## First slice

The first slice is intentionally transport-local. A guest controls its vsock
source port, so an unbounded map or bridge set turns that field into a host
resource-exhaustion primitive. The cap is fail-closed: a new identity gets an
`OP_RST`, an existing identity continues to make progress, and `OP_SHUTDOWN`
releases the slot. No raw packet forwarding or host NIC is introduced.

