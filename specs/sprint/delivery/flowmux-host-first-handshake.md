# The endpoint speaks first, so the relay has to dial first

`machine run --allow-host …` failed on HVF every time with "the network
endpoint is running but no guest authenticated within 5s — check that the
guest found its FlowMux identity drive". The guest had found its drive, and
had connected. The message named the one thing that was fine.

The FlowMux session handshake is host-first: `Session::guest` opens with a
read and waits for the endpoint's `SessionHello`. The in-house VMM's vsock
relay was guest-first — `SubstitutionBridge` dialed the per-VM endpoint UDS
lazily, on the first guest payload, which is the right shape for the
substitution protocol it was written for and the wrong one for this. So the
guest connected and blocked on a read, the endpoint had no accepted socket to
greet it on, and both halves waited until the launcher's five-second deadline
tore the VM down. A trace of the vsock device showed one packet on port 5253
for the whole run: `OP_REQUEST`, then nothing.

The relay now opens the endpoint connection on the guest's connect, and
answers `OP_RST` rather than `OP_RESPONSE` when it cannot — a guest with
nothing bound learns at connect instead of blocking until its own retry budget
runs out. Recording the connect header there is the other half of the same
bug: `drain` can only push endpoint bytes at a connection it holds a header
for, and the header was only recorded after a successful *guest→host* relay,
so even an eagerly opened connection had no way back to a guest that had not
spoken.

Firecracker and QEMU were never affected. Their transports accept on the
endpoint's own listener, so a guest connect and the host-side accept are the
same event; only the relayed-UDS path could defer one behind the other.

Two accounting details stayed put. The stream reservation is taken at connect
and released by `close_connection`, which the refusal arms already call, so
the budget stays balanced when a first payload is rate-limited on a
connection that is now already open. And the connection cap is checked before
the reservation, as before.

Witnesses: `egress_port_delivers_a_host_first_greeting_after_only_a_connect`
(an endpoint that writes on accept and never reads reaches a guest that has
only connected — red against the lazy dial),
`egress_port_resets_a_connect_without_endpoint`,
`open_connection_fails_closed_without_an_endpoint_and_returns_the_reservation`, and
`open_connection_is_active_before_any_guest_bytes`. Confirmed live: the
reported command boots, runs, and returns 0 on HVF, and the endpoint logs
`FlowMux handshake complete` followed by `FlowMux sending Opened`.
