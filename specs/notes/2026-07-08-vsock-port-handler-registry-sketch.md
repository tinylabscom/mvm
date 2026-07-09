# vsock port-handler registry sketch

**Date:** 2026-07-08
**Status:** Draft

## Goal

Refactor the host-side virtio-vsock device so port-bound protocols are modeled as
small trait implementations behind a registry, rather than as ad hoc branches in
`VsockShared::handle_packet` and the surrounding drain methods.

The immediate targets are the existing protocol families:

- host-initiated guest-agent bridge on `GUEST_AGENT_PORT`
- guest-initiated egress relay on `EGRESS_PORT`
- guest-initiated broker relay on `BROKER_PORT`
- host-initiated dev console relay on per-session console data ports
- transient workload-exit signal on `WORKLOAD_EXIT_PORT`

This is a static, in-process extension seam. It is not a runtime plugin system.

## Why this refactor is worth doing

The current vsock device already hosts multiple protocol shapes, but the dispatch
 lives in one large stateful type:

- port matching is embedded in `VsockShared::handle_packet`
- host-driven pumps are split across `drain_agent`, `drain_console`,
  `drain_substitution`, and `drain_broker`
- relay-specific header bookkeeping (`substitution_hdrs`, `broker_hdrs`) lives in
  `VsockShared` instead of next to the relay that owns it

That shape is serviceable for a handful of protocols, but it does not scale well
 once the repo adds more host services or more non-agent byte streams over vsock.
The problem is not “support third-party plugins”; it is “make the built-in
protocol seams explicit, testable, and locally owned.”

## Non-goals

- no dynamic loading
- no external plugin ABI
- no change to the wire format of existing protocols
- no broad rewrite of guest-agent request dispatch in the same slice
- no change to the broker `ServiceHandler` model; that remains the service-level
  extension seam on top of the broker port

## Design summary

Split the current monolithic `VsockShared` responsibilities into:

1. a transport core that understands virtio-vsock framing, credits, rx/tx queues,
   and host/guest packet delivery
2. a small registry of protocol handlers keyed by guest-facing port or by a
   host-opened stream classification
3. handler implementations that own their own relay state, header bookkeeping,
   and per-tick drain logic

The transport stays dumb: it parses headers, tracks per-stream credits, and asks
the appropriate handler what to do next.

## Proposed traits

Two separate traits keep the design honest:

### 1. Guest-listener handlers

These own protocols where the guest dials a well-known destination port on the
host, such as workload-exit, egress, and broker.

```rust
pub trait GuestPortHandler: Send {
    fn guest_port(&self) -> u32;

    fn on_request(&mut self, ctx: &mut VsockHandlerContext<'_>, hdr: &VsockHdr);

    fn on_rw(&mut self, ctx: &mut VsockHandlerContext<'_>, hdr: &VsockHdr, payload: &[u8]);

    fn on_credit_request(&mut self, ctx: &mut VsockHandlerContext<'_>, hdr: &VsockHdr) {
        ctx.queue_reply(hdr, OP_CREDIT_UPDATE, &[]);
    }

    fn on_shutdown(&mut self, ctx: &mut VsockHandlerContext<'_>, hdr: &VsockHdr);

    fn drain(&mut self, ctx: &mut VsockHandlerContext<'_>) -> Option<u32> {
        let _ = ctx;
        None
    }
}
```

### 2. Host-opened stream handlers

These own protocols where the host accepts a local socket, opens a guest stream,
and later routes guest replies back by the host-assigned connection id. Today
that is the agent bridge and the console bridge.

```rust
pub trait HostInitiatedHandler: Send {
    fn accepts_stream(&self, conn_id: u32) -> bool;

    fn on_response(&mut self, ctx: &mut VsockHandlerContext<'_>, conn_id: u32);

    fn on_rw(&mut self, ctx: &mut VsockHandlerContext<'_>, conn_id: u32, guest_port: u32, payload: &[u8]);

    fn on_shutdown(&mut self, ctx: &mut VsockHandlerContext<'_>, conn_id: u32, guest_port: u32);

    fn drain(&mut self, ctx: &mut VsockHandlerContext<'_>) -> Option<u32>;
}
```

### Shared transport context

Handlers should not poke `VsockShared` internals directly. Give them a narrow
capability object:

```rust
pub struct VsockHandlerContext<'a> {
    transport: &'a mut VsockTransportCore,
    lifecycle: &'a mut VsockLifecycleState,
}
```

It exposes only the operations handlers actually need:

- `queue_reply`
- `queue_host_packet`
- `add_recv`
- `remove_recv`
- `record_workload_exit`
- `flush_rx`

That keeps credit accounting and queue manipulation centralized.

## Concrete type split

Introduce these internal types under `crates/mvm-backend/src/vmm/`:

- `vsock_transport.rs`
  - `VsockHdr`
  - `VsockTransportCore`
  - virtqueue read/write helpers
  - `queue_reply`, `queue_host_packet`, `flush_rx`, `add_recv`, `fwd_cnt_for`
- `vsock_handlers/mod.rs`
  - trait definitions
  - `VsockHandlerContext`
  - registry types
- `vsock_handlers/workload_exit.rs`
  - `WorkloadExitHandler`
- `vsock_handlers/stream_relay.rs`
  - a reusable guest-port relay for egress and broker
- `vsock_handlers/agent_bridge.rs`
  - `AgentVsockHandler`
- `vsock_handlers/console_bridge.rs`
  - `ConsoleVsockHandler`

The existing `substitution_bridge::SubstitutionBridge` is already most of the way
to a reusable relay implementation. The refactor should wrap and reuse it, not
reimplement it.

## Registry shape

Keep the registry static and explicit:

```rust
pub struct VsockHandlerRegistry {
    guest_ports: std::collections::BTreeMap<u32, Box<dyn GuestPortHandler>>,
    host_initiated: Vec<Box<dyn HostInitiatedHandler>>,
}
```

`VsockShared::new` wires the known handlers up front:

- `WORKLOAD_EXIT_PORT` -> `WorkloadExitHandler`
- `EGRESS_PORT` -> `StreamRelayGuestPortHandler`
- `BROKER_PORT` -> `StreamRelayGuestPortHandler`
- host-initiated `AgentVsockHandler`
- host-initiated `ConsoleVsockHandler`

No runtime registration is required outside construction.

## How packet dispatch changes

Today `handle_packet` mixes three questions:

1. is this packet for a host-opened stream?
2. if not, which guest-listener port is it for?
3. what relay-specific side effects happen on each op?

After the refactor:

1. first ask the host-initiated handlers whether `hdr.dst_port` is one of their
   open connection ids
2. otherwise look up `hdr.dst_port` in the guest-port registry
3. fall back to the current generic behavior for unknown ports: accept request,
   record raw bytes, credit-update, and reset on shutdown as today

That keeps unknown-port behavior stable while allowing real protocols to move out
one by one.

## How the existing handlers map

### Workload exit

The workload-exit path should become the smallest handler:

- `OP_RW` with at least four bytes records the little-endian exit code
- any short write records `0`, preserving current behavior
- if `exit_stop` is armed, set it
- send `OP_CREDIT_UPDATE`

No drain path, no local sockets, no extra state.

### Egress and broker

These are the same protocol shape:

- guest dials a fixed port
- first frame opens or reuses a Unix-socket endpoint
- payload is relayed byte-for-byte
- replies are drained back into guest rx using the saved inbound header
- missing endpoint fails closed with `OP_RST`

The repo already has a reusable substrate in
`substitution_bridge::SubstitutionBridge`. Generalize the naming and move the
per-stream header map into the handler so `VsockShared` no longer carries
`substitution_hdrs` and `broker_hdrs`.

One generic handler should be parameterized by:

- guest-facing port
- endpoint source
- activity counter hookup

### Agent bridge

The agent bridge remains host-initiated:

- accepts host UDS connections
- assigns a host-side connection id
- opens `OP_REQUEST` to `GUEST_AGENT_PORT`
- relays host writes as `OP_RW`
- routes guest replies back by connection id
- emits `OP_RST` when the host side closes

This logic already exists in `AgentBridge`; the refactor mainly moves the packet
interpretation and drain loop into a dedicated handler wrapper.

### Console bridge

Console is the same host-initiated shape as the agent bridge, except the guest
port is dynamic per session. It should become a separate handler rather than
remaining special-cased in `VsockShared`.

## Recommended implementation order

Do this in four small slices so behavior stays reviewable:

### Slice 1: extract transport primitives

Move pure transport helpers out of `VsockShared` without changing behavior:

- header type
- rx/tx queue helpers
- credit accounting
- reply/host-packet framing

This should be mostly mechanical and test-preserving.

### Slice 2: introduce handler traits and port registry

Add the traits, registry, and context, then migrate:

- `WORKLOAD_EXIT_PORT`
- `EGRESS_PORT`
- `BROKER_PORT`

These are the easiest because they do not depend on host-opened stream-id
ownership.

### Slice 3: migrate host-initiated handlers

Wrap:

- `AgentBridge`
- `ConsoleBridge`

Then delete the host-stream branches from `handle_packet`, `drain_agent`, and
`drain_console`.

### Slice 4: shrink `VsockShared`

Once every built-in protocol sits behind handlers:

- remove relay-specific header maps from `VsockShared`
- collapse drain methods into one `service_handlers` tick
- leave `VsockShared` as transport core + wiring

## Testing plan

Keep the existing `crates/mvm-backend/src/vmm/vsock.rs` tests green, then add
focused handler tests for the new seams.

### Preserve existing transport behavior

Keep coverage for:

- `egress_port_relays_frame_to_endpoint_and_back`
- `broker_port_relays_frame_to_endpoint_and_back`
- reset-without-endpoint cases
- host agent connect / reply routing
- console connect / reply routing
- per-stream credit accounting
- workload-exit capture

### Add new unit tests

- registry routes `WORKLOAD_EXIT_PORT` to the exit handler
- relay handler retains the right inbound header per guest source port
- host-initiated handler classification wins before guest-port lookup
- unknown ports still follow the fallback behavior

### Keep integration boundary the same

Do not change the guest or host external behavior in this refactor. The acceptance
bar is structural improvement with identical wire semantics.

## Risks

### Over-generalizing too early

Do not invent a framework for arbitrary transport types. The registry needs to
support exactly the current protocol families plus the next obvious additions.

### Smearing transport ownership into handlers

Handlers should not own credit accounting or virtqueue writes directly. If they do,
the refactor will simply move complexity around rather than contain it.

### Conflating service-level and port-level extensibility

New host services should continue to land as broker `ServiceHandler`
implementations whenever they fit the broker model. A new vsock port should be
reserved only when the protocol shape is materially different from the broker or
guest-agent surfaces.

## Resulting extension model

After this refactor, the repo will have a clean two-level extensibility story:

- `ServiceHandler` for multiplexed host services on the broker surface
- `GuestPortHandler` / `HostInitiatedHandler` for distinct protocol families on
  the vsock transport

That gives the project a plugin-like development model without paying the cost of
runtime plugins.
