# Plan 287 — Userspace socket datapath

**Status: RETIRED AND DELETED — preserved as historical implementation and
performance record.** Plan 316 and ADR-042 replaced this production path with
FlowMux; the userspace L3 datapath and smoltcp dependency no longer ship.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `l3-vsock` work on hosts with no privileges — macOS always, Linux when TUN is unavailable — by terminating guest TCP/UDP in userspace and re-originating each admitted flow on a host socket.

**Architecture:** A new `UserspaceSocketDatapath` implements the existing `L3Datapath` trait below the policy seam, using smoltcp for guest-side TCP termination. Nothing above the seam changes. A prerequisite phase fixes two platform-neutral defects in the shipped `mvm-netd` drive loop that block the work and affect Linux today.

**Tech Stack:** Rust, smoltcp (new dependency), mio (existing workspace dependency, new `mvm-hostd` edge), `std::os::unix` sockets.

**ADR:** [037](../adrs/037-userspace-socket-datapath.md). Read it first — this plan is the sequencing.

## Global Constraints

Every task's requirements implicitly include this section.

- **No plan/PR/ADR references in code comments.** CI-gated by `xtask check-no-spec-refs`. Reword to describe the mechanism, not the document. This plan's own ADR references belong in specs only.
- **`#[allow(clippy::too_many_arguments)]` is banned outright.** When a function trips the lint, introduce a params struct with a builder and pass the built value.
- **Reuse first.** Search the workspace before writing anything. All `~/.mvm` paths go through `mvm-core::config` helpers — never `std::env::var("HOME")` inline.
- **Time stays a caller-supplied parameter.** `mvm_net::l3` deliberately takes `now_millis` rather than reading `Instant`, so expiry is a pure function of its inputs and tests assert behaviour instead of sleeping. Do not push clock reads down into the gateway or the flow table.
- **File size:** `MAX_PROD_LINES` is 1500, and `xtask check-file-size` counts **production lines only** — those before a file's first top-level `#[cfg(test)]`, per this repo's trailing-tests convention. `crates/mvm-hostd/src/netd/gateway.rs` is ~1466 lines total but its production body is **889**, so it has ample headroom. (Tasks 4 and 6-9 were briefed with the total-line count mistaken for the gated figure, and told gateway.rs could absorb nothing. No task was actually blocked by it, but the deferral of gateway.rs's unbounded `poll_inbound` drain rested on that false premise and is therefore un-deferred.)
- **New dependency gates:** adding smoltcp requires a `deny.toml` review **and** passing `xtask check-duplicate-majors`. Both, not either.
- **Formatting:** CI Lint runs **nightly** rustfmt. Run `cargo +nightly fmt --all` before pushing, not stable.
- **Scratch files go under `/tmp/`**, never anywhere in the repo working tree, including gitignored paths.
- **Sprint sync:** ticking a workstream here also ticks `specs/REFACTOR-STATUS.md` and `specs/SPRINT.md` in the same commit.

## Gate list (run before every push)

```sh
cargo +nightly fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo nextest run --workspace
cargo test --workspace --doc
cargo build --all-targets
cargo run -p xtask -- check-all      # the full xtask gate suite
just check-linux                      # cross-check the Linux target from macOS
```

## File structure

| File | Status | Responsibility |
|---|---|---|
| `crates/mvm-net/src/channel.rs` | Modify | `GuestConnection` gains `pollable_fd` |
| `crates/mvm-hostd/src/netd/uds_channel.rs` | Modify | UDS listener populates `pollable_fd` |
| `crates/mvm-hostd/src/netd/datapath.rs` | Modify | `DatapathHandle::readiness_fd` |
| `crates/mvm-hostd/src/netd/linux.rs` | Modify | Implement `readiness_fd` for the TUN handle |
| `crates/mvm-hostd/src/bin/mvm-netd.rs` | Modify | Real clock + mio poll loop |
| `crates/mvm-hostd/src/netd/userspace/mod.rs` | Create | `UserspaceSocketDatapath`, `UserspaceHandle`, fd budget |
| `crates/mvm-hostd/src/netd/userspace/limits.rs` | Create | Bounds and defaults |
| `crates/mvm-hostd/src/netd/userspace/device.rs` | Create | smoltcp `phy::Device` over the guest queues |
| `crates/mvm-hostd/src/netd/userspace/tcp.rs` | Create | Half-open table, deferred handshake, flow pumping |
| `crates/mvm-hostd/src/netd/userspace/udp.rs` | Create | Datagram association table |
| `crates/mvm-hostd/tests/userspace_datapath.rs` | Create | Unprivileged integration + hostile-guest suite |

---

# Phase A — WS0: the drive loop

Must land before Phase B. Independently valuable: it fixes two real defects on the shipped Linux path.

### Task 1: Carry a pollable descriptor out of the guest channel

`GuestStream` is `Read + Write + Send` with a blanket impl over every `T`, so it cannot gain a specialised fd accessor. `GuestConnection` is the seam instead: the UDS listener knows the concrete `UnixStream` and can record its descriptor at accept time, leaving the blanket impl and every test double untouched.

**Files:**
- Modify: `crates/mvm-net/src/channel.rs:171-185`
- Modify: `crates/mvm-hostd/src/netd/uds_channel.rs:181-195`

**Interfaces:**
- Produces: `GuestConnection::pollable_fd: Option<std::os::fd::RawFd>`, and `GuestConnection::with_pollable_fd(self, fd: RawFd) -> Self`.

- [x] **Step 1: Write the failing test**

In `crates/mvm-hostd/src/netd/uds_channel.rs`, in the existing `mod tests`:

```rust
#[test]
fn an_accepted_uds_connection_exposes_its_pollable_descriptor() {
    let (mut listener, path) = bound_listener_for_test();
    let _client = std::thread::spawn(move || UnixStream::connect(&path).expect("connect"));
    let conn = listener.accept().expect("accept");
    assert!(
        conn.pollable_fd.is_some(),
        "a UDS-backed guest connection must expose a descriptor the poll loop can register"
    );
}
```

- [~] **Step 2 (not observed): Run it and confirm it fails**

Not observed — implementation preceded the test run; the field's absence was
verified by inspection, not by a captured red (task-1-report.md:38-39).

Run: `cargo nextest run -p mvm-hostd an_accepted_uds_connection_exposes`
Expected: FAIL — no field `pollable_fd` on `GuestConnection`.

- [x] **Step 3: Add the field and builder**

In `crates/mvm-net/src/channel.rs`:

```rust
pub struct GuestConnection<S> {
    pub instance: VmInstanceIdentity,
    pub service: GuestService,
    pub stream: S,
    /// The descriptor a poll loop can register, when the transport has
    /// one. `None` for in-memory streams, which are only ever driven
    /// synchronously.
    pub pollable_fd: Option<std::os::fd::RawFd>,
}

impl<S> GuestConnection<S> {
    pub fn new(instance: VmInstanceIdentity, service: GuestService, stream: S) -> Self {
        Self { instance, service, stream, pollable_fd: None }
    }

    /// Record the descriptor this connection can be polled on.
    pub fn with_pollable_fd(mut self, fd: std::os::fd::RawFd) -> Self {
        self.pollable_fd = Some(fd);
        self
    }
}
```

- [x] **Step 4: Populate it in the UDS listener**

In `uds_channel.rs`'s `accept`, capture the descriptor before boxing the stream:

```rust
use std::os::fd::AsRawFd;

let fd = stream.as_raw_fd();
Ok(GuestConnection::new(
    self.instance.clone(),
    self.service,
    Box::new(stream) as Box<dyn GuestStream>,
)
.with_pollable_fd(fd))
```

- [x] **Step 5: Run tests and confirm they pass**

Run: `cargo nextest run -p mvm-hostd -p mvm-net`
Expected: PASS, including every pre-existing channel test.

- [x] **Step 6: Commit**

```sh
git add crates/mvm-net/src/channel.rs crates/mvm-hostd/src/netd/uds_channel.rs
git commit -m "feat(netd): carry a pollable descriptor out of the guest channel"
```

---

### Task 2: Give DatapathHandle a readiness descriptor

**Files:**
- Modify: `crates/mvm-hostd/src/netd/datapath.rs:191-211` (trait), `:303-340` (`LoopbackHandle`)
- Modify: `crates/mvm-hostd/src/netd/linux.rs` (the TUN handle)

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces: `DatapathHandle::readiness_fd(&self) -> Option<std::os::fd::RawFd>`, defaulting to `None`.

- [x] **Step 1: Write the failing test**

In `datapath.rs`'s `mod tests`:

```rust
#[test]
fn a_loopback_handle_has_no_readiness_descriptor() {
    let dp = LoopbackDatapath::sink();
    let handle = dp.open(&request()).expect("open");
    assert!(
        handle.readiness_fd().is_none(),
        "an in-memory datapath is driven synchronously and has nothing to poll"
    );
}
```

- [x] **Step 2: Run it and confirm it fails**

Run: `cargo nextest run -p mvm-hostd a_loopback_handle_has_no_readiness`
Expected: FAIL — no method `readiness_fd`.

- [x] **Step 3: Add the defaulted trait method**

In `datapath.rs`, inside `pub trait DatapathHandle`:

```rust
    /// A descriptor that becomes readable when this datapath has work.
    ///
    /// `None` means the datapath makes progress only when called, so the
    /// driver polls it on its timer tick rather than on readiness.
    fn readiness_fd(&self) -> Option<std::os::fd::RawFd> {
        None
    }
```

The default is deliberate: `LoopbackHandle` and the refusing handles inherit it unchanged, so only backends with something to poll implement it.

- [x] **Step 4: Implement it for the Linux TUN handle**

In `linux.rs`, on the handle struct holding the TUN descriptor:

```rust
    fn readiness_fd(&self) -> Option<std::os::fd::RawFd> {
        Some(self.tun.as_raw_fd())
    }
```

- [x] **Step 5: Run tests and confirm they pass**

Run: `cargo nextest run -p mvm-hostd` and `just check-linux`
Expected: PASS on both. `check-linux` matters because `linux.rs` does not compile on macOS.

- [x] **Step 6: Commit**

```sh
git add crates/mvm-hostd/src/netd/datapath.rs crates/mvm-hostd/src/netd/linux.rs
git commit -m "feat(netd): expose a readiness descriptor on datapath handles"
```

---

### Task 3: Replace the frame counter with a real monotonic clock

`mvm-netd` declares `let mut now: u64 = 0` and increments once per guest frame, then passes it to APIs declared `now_millis`. `expire_idle` compares against `DEFAULT_TCP_IDLE_MILLIS` (300_000), so a TCP flow currently needs 300,000 guest frames to expire rather than five minutes. The fix belongs in the caller only.

**Files:**
- Modify: `crates/mvm-hostd/src/bin/mvm-netd.rs:125-195`

**Interfaces:**
- Produces: `fn monotonic_millis(start: std::time::Instant) -> u64`, used by Task 4.

- [x] **Step 1: Write the failing test**

In `crates/mvm-hostd/tests/netd_bin.rs`:

```rust
/// A flow must expire on wall-clock time, not on how many frames the
/// guest happened to send. The counter this replaced made a 5-minute
/// idle timeout mean 300,000 frames.
#[test]
fn flows_expire_on_wall_clock_time_not_frame_count() {
    let mut tracker = mvm_net::l3::FlowTracker::new(mvm_net::l3::FlowLimits::default());
    let key = test_flow_key();
    tracker.observe_outbound(key, 100, 1_000);

    // Two frames later in counter terms, but five minutes later in real
    // time: the flow must be gone.
    let expired = tracker.expire_idle(1_000 + mvm_net::l3::DEFAULT_TCP_IDLE_MILLIS);
    assert_eq!(expired.len(), 1, "an idle TCP flow must expire on elapsed milliseconds");
}
```

- [x] **Step 2: Run it — it is expected to PASS, and that is the point**

Run: `cargo nextest run -p mvm-hostd flows_expire_on_wall_clock`
Expected: **PASS.**

This is deliberately not a red-green step, so do not "fix" it into failing. `FlowTracker` is already correct — expiry is a pure function of the `now_millis` it is handed. The defect is entirely in `mvm-netd`, which hands it a frame counter. This test pins the library contract that Step 3 makes the binary honour; the red-green proof for the actual defect is Task 4's `host_to_guest_data_flows_while_the_guest_is_silent` and the end-to-end check in Task 5.

- [x] **Step 3: Thread a real clock through `serve`**

In `mvm-netd.rs`, delete `let mut now: u64 = 0;` and every `now += 1;`. Add:

```rust
/// Milliseconds since the process's reference instant.
///
/// A monotonic source: it cannot jump backwards when the host's wall
/// clock is corrected, which would otherwise make an idle flow look
/// arbitrarily young and defer its expiry.
fn monotonic_millis(start: std::time::Instant) -> u64 {
    start.elapsed().as_millis() as u64
}
```

and in `serve`, take `let start = std::time::Instant::now();` once, then replace each `now` use with `monotonic_millis(start)`.

- [x] **Step 4: Run the suite**

Run: `cargo nextest run -p mvm-hostd`
Expected: PASS.

- [x] **Step 5: Commit**

```sh
git add crates/mvm-hostd/src/bin/mvm-netd.rs crates/mvm-hostd/tests/netd_bin.rs
git commit -m "fix(netd): drive expiry from a monotonic clock, not a frame counter"
```

---

### Task 4: Poll the guest channel and the datapath independently

The steady-state loop blocks on `data.read()` and polls the datapath only after a guest frame arrives, so host-to-guest traffic stalls whenever the guest is quiet.

**Files:**
- Modify: `crates/mvm-hostd/src/bin/mvm-netd.rs:162-195`
- Modify: `crates/mvm-hostd/Cargo.toml` (add `mio`)

**Interfaces:**
- Consumes: `GuestConnection::pollable_fd` (Task 1), `DatapathHandle::readiness_fd` (Task 2), `monotonic_millis` (Task 3).

- [x] **Step 1: Add the dependency**

In `crates/mvm-hostd/Cargo.toml` under `[dependencies]`:

```toml
mio = { workspace = true }
```

`mio` is already a workspace dependency, so this adds an edge rather than a new third-party crate. Confirm with `cargo tree -p mvm-hostd -e no-dev | grep mio`.

- [x] **Step 2: Write the failing test**

In `crates/mvm-hostd/tests/netd_bin.rs`:

```rust
/// The defect this pins: the old loop blocked on the guest data channel
/// and only drained the datapath afterwards, so a server pushing to a
/// silent guest stalled indefinitely. The guest sends nothing here.
#[test]
fn host_to_guest_data_flows_while_the_guest_is_silent() {
    let harness = NetdHarness::start_with_injecting_datapath();
    harness.inject_from_network(sample_inbound_packet());

    let frame = harness
        .read_guest_frame_within(std::time::Duration::from_secs(2))
        .expect("a frame must reach the guest without the guest sending first");
    assert!(!frame.is_empty());
}
```

- [x] **Step 3: Run it and confirm it fails**

Run: `cargo nextest run -p mvm-hostd host_to_guest_data_flows_while`
Expected: FAIL — times out, because nothing drains the datapath until the guest transmits.

- [x] **Step 4: Replace the blocking loop**

Register the guest data descriptor and the datapath readiness descriptor with one `mio::Poll`, and use a timer tick as the floor so a datapath reporting `None` still makes progress:

```rust
const TICK: std::time::Duration = std::time::Duration::from_millis(50);

const GUEST_DATA: mio::Token = mio::Token(0);
const DATAPATH: mio::Token = mio::Token(1);

let mut poll = mio::Poll::new().context("creating the netd poll loop")?;
let mut events = mio::Events::with_capacity(64);

if let Some(fd) = data_fd {
    poll.registry()
        .register(&mut mio::unix::SourceFd(&fd), GUEST_DATA, mio::Interest::READABLE)
        .context("registering the guest data channel")?;
}
if let Some(fd) = gateway.datapath_readiness_fd() {
    poll.registry()
        .register(&mut mio::unix::SourceFd(&fd), DATAPATH, mio::Interest::READABLE)
        .context("registering the datapath")?;
}

loop {
    poll.poll(&mut events, Some(TICK)).or_else(|e| {
        if e.kind() == std::io::ErrorKind::Interrupted { Ok(()) } else { Err(e) }
    })?;
    let now = monotonic_millis(start);

    for event in events.iter() {
        if event.token() == GUEST_DATA {
            match data.read(&mut buf) {
                Ok(0) => return Ok(()),
                Ok(n) => {
                    if let Err(err) = gateway.ingest_data_bytes(&buf[..n], now) {
                        eprintln!("mvm-netd: dropping the tunnel: {err}");
                        return Ok(());
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(err) => return Err(err).context("reading the data channel"),
            }
        }
    }

    // Unconditional, not gated on an event: a datapath with no readiness
    // descriptor makes progress only here, and smoltcp's retransmit
    // timers need servicing whether or not either side sent anything.
    for event in gateway.poll_inbound(now) {
        log_event(&event);
    }
    for frame in gateway.take_guest_frames() {
        data.write_all(&frame).context("writing to the guest")?;
    }
    data.flush().ok();
    gateway.tick(now);
}
```

Set the guest data descriptor non-blocking before the loop, since a readiness-driven read must not block.

- [~] **Step 5 (superseded): Expose the datapath descriptor through the gateway**

Superseded: `Gateway::datapath()` is already `pub` and returns `&dyn
DatapathHandle`, and `readiness_fd(&self)` takes `&self`, so
`gateway.datapath().readiness_fd()` already works — a wrapper method would
duplicate an existing path under a new name, and `mvm-netd.rs` calls the
existing path directly.

`Gateway` owns the handle, so add a thin accessor beside its existing ones. Keep it to the two lines the borrow allows — `gateway.rs` has 14 lines of headroom:

```rust
    /// The datapath's readiness descriptor, if it has one.
    pub fn datapath_readiness_fd(&self) -> Option<std::os::fd::RawFd> {
        self.datapath.readiness_fd()
    }
```

If this pushes `gateway.rs` past 1500 lines, stop and split the file first as its own commit, then return here.

- [x] **Step 6: Run the suite and the gates**

Run: `cargo nextest run -p mvm-hostd && cargo run -p xtask -- check-file-size`
Expected: PASS, and `gateway.rs` still under 1500 lines.

- [x] **Step 7: Commit**

```sh
git add crates/mvm-hostd/src/bin/mvm-netd.rs crates/mvm-hostd/src/netd/gateway.rs crates/mvm-hostd/Cargo.toml Cargo.lock
git commit -m "fix(netd): poll the guest channel and the datapath independently"
```

---

### Task 5: Close out Phase A

- [x] **Step 1: Run the full gate list**

Run every command in the Gate list section above.
Expected: all green.

- [x] **Step 2: Tick the ledgers**

Mark WS0 complete in `specs/plans/287-userspace-socket-datapath.md`, and update `specs/REFACTOR-STATUS.md` (bump its "Last updated" date) and `specs/SPRINT.md` in the same commit.

- [x] **Step 3: Commit**

```sh
git add specs/
git commit -m "docs(plan-287): record the drive-loop fix as landed"
```

---

# Phase B — WS1: the userspace socket datapath

### Task 6: Bounds, and the memory ceiling as an assertion

**Files:**
- Create: `crates/mvm-hostd/src/netd/userspace/limits.rs`
- Create: `crates/mvm-hostd/src/netd/userspace/mod.rs` (module declarations only)
- Modify: `crates/mvm-hostd/src/netd/mod.rs`, `crates/mvm-hostd/Cargo.toml`, `deny.toml`

**Interfaces:**
- Produces: `DEFAULT_MAX_HOST_SOCKETS: usize`, `FD_RESERVE: usize`, `DEFAULT_MAX_HALF_OPEN: usize`, `HALF_OPEN_TIMEOUT_MILLIS: u64`, `SOCKET_RX_BUFFER: usize`, `SOCKET_TX_BUFFER: usize`, `MEMORY_CEILING_BYTES: usize`.

- [x] **Step 1: Add smoltcp**

```sh
cargo add smoltcp -p mvm-hostd --no-default-features \
  --features medium-ip,proto-ipv4,socket-tcp,socket-udp
```

Then review `deny.toml` for the new licence and any duplicate-major it introduces, and run `cargo run -p xtask -- check-duplicate-majors`. Both gates, not either.

- [x] **Step 2: Write the failing test**

In `limits.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    /// The ceiling is a number the host must be able to afford at the
    /// cap. Asserting it here means changing a buffer size cannot
    /// silently multiply the worst-case footprint.
    #[test]
    fn the_per_machine_memory_ceiling_is_what_we_claim() {
        assert_eq!(SOCKET_RX_BUFFER + SOCKET_TX_BUFFER, 32 * 1024);
        // Superseded — see the note under Step 4. The landed figure is
        // 181_778_432, because the ceiling has to count the per-flow
        // device queues as well as the socket ring buffers.
        assert_eq!(MEMORY_CEILING_BYTES, 32 * 1024 * 1024);
        assert!(
            DEFAULT_MAX_HOST_SOCKETS < mvm_net::l3::DEFAULT_MAX_FLOWS,
            "the socket cap must sit below the flow cap: a descriptor costs more than a table entry"
        );
    }

    #[test]
    fn half_open_is_far_smaller_than_the_socket_cap() {
        assert!(DEFAULT_MAX_HALF_OPEN * 4 < DEFAULT_MAX_HOST_SOCKETS);
    }
}
```

- [x] **Step 3: Run it and confirm it fails**

Run: `cargo nextest run -p mvm-hostd the_per_machine_memory_ceiling`
Expected: FAIL — module does not exist.

- [x] **Step 4: Write the constants**

```rust
//! Bounds for the userspace socket datapath.
//!
//! Consts rather than negotiated values: a ceiling a hostile guest can
//! raise is not a ceiling. This datapath is the first whose per-flow cost
//! is a file descriptor, so its cap is derived from the process budget
//! rather than inherited from the flow table.

/// Ceiling on concurrent host sockets for one machine.
pub const DEFAULT_MAX_HOST_SOCKETS: usize = 1024;

/// Descriptors held back for the process itself: audit log, vsock,
/// control channel, logging, and slack.
pub const FD_RESERVE: usize = 64;

/// Concurrent half-open connections. Each parks a connecting descriptor,
/// so this is sized for a burst, not for a flood.
pub const DEFAULT_MAX_HALF_OPEN: usize = 128;

/// How long a half-open entry waits for its host connect.
pub const HALF_OPEN_TIMEOUT_MILLIS: u64 = 10_000;

pub const SOCKET_RX_BUFFER: usize = 16 * 1024;
pub const SOCKET_TX_BUFFER: usize = 16 * 1024;

/// Worst-case buffer footprint for one machine at the socket cap.
pub const MEMORY_CEILING_BYTES: usize =
    DEFAULT_MAX_HOST_SOCKETS * (SOCKET_RX_BUFFER + SOCKET_TX_BUFFER);
```

**Superseded during Task 11 (two rounds). The 32 MiB figure above was never the whole cost.**

Task 11 gave every flow its own `GuestDevice`, so the device queues multiply by `DEFAULT_MAX_HOST_SOCKETS` and belong in the ceiling; the constant above counts only the socket ring buffers. The landed form adds a derived per-flow queue depth and the handle's own machine-wide device:

```rust
pub const FLOW_RX_QUEUE_DEPTH: usize = SOCKET_RX_BUFFER.div_ceil(DEFAULT_SEGMENT_PAYLOAD);            // 31

const DATA_SEGMENTS_PER_PASS: usize =
    SOCKET_TX_BUFFER.div_ceil(DEFAULT_SEGMENT_PAYLOAD) + (POLLS_PER_PASS - 1);                        // 32

pub const FLOW_TX_QUEUE_DEPTH: usize =
    FLOW_RX_QUEUE_DEPTH + DATA_SEGMENTS_PER_PASS + POLLS_PER_PASS * CONTROL_SEGMENTS_PER_POLL;        // 65

pub const FLOW_BUFFER_BYTES: usize = SOCKET_RX_BUFFER + SOCKET_TX_BUFFER
    + (FLOW_RX_QUEUE_DEPTH + FLOW_TX_QUEUE_DEPTH) * MTU_V1 as usize;                                  // 176_768

pub const MEMORY_CEILING_BYTES: usize =
    DEFAULT_MAX_HOST_SOCKETS * FLOW_BUFFER_BYTES + 2 * DEFAULT_QUEUE_DEPTH * MTU_V1 as usize;         // 181_778_432
```

The depth went 256 (inherited machine-wide default) → 12 (a byte budget at full-size segments) → 33 (one symmetric depth) → 31 guest-facing and 65 guest-bound. Twelve was too small in two ways at once: a segment need not be full-size — a guest whose SYN carries no MSS option gets smoltcp's 536 byte default, turning a 16 KiB window into 31 segments — and a pass emits control segments beside its data.

Thirty-three then failed on the term that dominates. smoltcp answers an ingested segment with an **immediate ACK** whenever its reassembly hole is non-empty, once per segment inside one poll's ingress loop, and unlike its challenge ACK that reply is not rate-limited. One poll drains the whole guest→stack queue, so a poll can emit as many ACKs as that queue is deep — the ACK count is bounded by `FLOW_RX_QUEUE_DEPTH`, not by the number of polls, and 33 was a per-poll *egress* figure applied to an *ingress* count. The hole needs no attacker: this datapath models dropping a guest packet when the receive queue is full, and that drop is itself the hole. Behavioural witness: `a_queue_full_drop_does_not_cost_the_guest_the_passs_data`, which under the old depth reports "8 of the 41 segments this pass produced were discarded".

Data is also emitted in two rounds — whatever was unsent at the first poll, then whatever the host read in before the second — each rounding up independently, so the data term is 32 rather than 31. The two rounds share one send buffer's worth of bytes, since the second can only write into space the first left free.

The two directions are separate constants now, and `GuestDevice` takes a named `QueueDepths` rather than two bare `usize` arguments, because transposing them reads correctly at the call site. Overflow that no depth can absorb — a guest advertising a 64-byte MSS — is counted rather than silent: `GuestDevice::dropped_to_guest` feeds `GatewayMetrics::queue_drops_egress` from `pump`, so it reaches an operator and not only a debugger holding the flow.

`MTU_V1` in the formula is the configured MTU too, because `accept_mtu` refuses anything above it at both entry points (`open_handle` and `EstablishedFlow::from_half_open`). Failing closed rather than computing from the configured value keeps the ceiling a compile-time constant: `MTU_V1` is fixed and not negotiated by design, and a ceiling a configuration can raise is not a ceiling.

- [x] **Step 5: Run tests and confirm they pass**

Run: `cargo nextest run -p mvm-hostd -E 'test(memory_ceiling) or test(half_open_is_far)'`
Expected: PASS.

- [x] **Step 6: Commit**

```sh
git add crates/mvm-hostd/src/netd/userspace/ crates/mvm-hostd/src/netd/mod.rs crates/mvm-hostd/Cargo.toml Cargo.lock deny.toml
git commit -m "feat(netd): bound the userspace socket datapath"
```

---

### Task 7: The virtual smoltcp device

**Files:**
- Create: `crates/mvm-hostd/src/netd/userspace/device.rs`

**Interfaces:**
- Produces: `GuestQueues { rx: VecDeque<Vec<u8>>, tx: VecDeque<Vec<u8>> }` and `struct GuestDevice` implementing `smoltcp::phy::Device`. `GuestDevice::push_from_guest(&mut self, bytes: &[u8])`, `GuestDevice::pop_for_guest(&mut self) -> Option<Vec<u8>>`.

- [x] **Step 1: Write the failing test**

```rust
#[test]
fn a_packet_pushed_from_the_guest_is_visible_to_the_stack() {
    let mut dev = GuestDevice::new(1500, 64);
    dev.push_from_guest(&[0x45, 0x00, 0x00, 0x14]);
    assert_eq!(dev.pending_from_guest(), 1);
}

#[test]
fn the_queue_drops_rather_than_growing_without_bound() {
    let mut dev = GuestDevice::new(1500, 2);
    for _ in 0..10 {
        dev.push_from_guest(&[0x45, 0x00, 0x00, 0x14]);
    }
    assert_eq!(
        dev.pending_from_guest(), 2,
        "a guest that outruns the stack must hit the queue bound, not the host's memory"
    );
}
```

- [x] **Step 2: Run and confirm failure**

Run: `cargo nextest run -p mvm-hostd a_packet_pushed_from_the_guest`
Expected: FAIL — `GuestDevice` not defined.

- [x] **Step 3: Implement the device**

Implement `smoltcp::phy::Device` where `receive()` pops from the guest-to-stack queue and `transmit()` pushes onto the stack-to-guest queue. Both queues are bounded by the depth passed to `new`; `push_from_guest` drops on a full queue and reports it so the caller can count it.

- [x] **Step 4: Run tests and confirm they pass**

Run: `cargo nextest run -p mvm-hostd -E 'test(guest_device) or test(pushed_from_the_guest) or test(without_bound)'`
Expected: PASS.

- [x] **Step 5: Commit**

```sh
git add crates/mvm-hostd/src/netd/userspace/device.rs
git commit -m "feat(netd): add the guest-facing smoltcp device"
```

---

### Task 8: The datapath skeleton and the descriptor budget

**Files:**
- Modify: `crates/mvm-hostd/src/netd/userspace/mod.rs`

**Interfaces:**
- Consumes: `limits::*` (Task 6), `GuestDevice` (Task 7).
- Produces: `UserspaceSocketDatapath` implementing `L3Datapath`; `UserspaceHandle` implementing `DatapathHandle`; `fn socket_budget(rlimit_soft: u64, rlimit_hard: u64) -> usize`.
- Produces (driver entry point, used by Tasks 11–15): `UserspaceHandle::service(&mut self, now_millis: u64) -> Result<(), DatapathError>` — polls smoltcp, resolves completed connects, pumps established flows, and expires timed-out state. `mvm-netd` reaches it through `recv_from_network`; the tests call it directly.
- Produces (test-facing accessors, `pub(crate)`): `UserspaceHandle::open_socket_count(&self) -> usize`.

- [x] **Step 1: Write the failing test**

```rust
/// macOS ships a soft RLIMIT_NOFILE of 256. Inheriting the flow cap of
/// 4096 would exhaust the process's descriptors — which does not merely
/// break the tunnel, it breaks the supervisor's ability to open its
/// audit log.
#[test]
fn the_socket_budget_respects_a_small_descriptor_limit() {
    assert_eq!(socket_budget(256, 256), 256 - FD_RESERVE);
}

#[test]
fn the_socket_budget_never_exceeds_the_ceiling() {
    assert_eq!(socket_budget(1_048_576, 1_048_576), DEFAULT_MAX_HOST_SOCKETS);
}

#[test]
fn the_userspace_datapath_reports_socket_translation_capabilities() {
    let dp = UserspaceSocketDatapath::new();
    assert_eq!(dp.capabilities(), ForwardingCapabilities::USERSPACE_SOCKETS);
    assert!(dp.is_available().is_ok(), "it needs no privileges, so it is always available");
}
```

- [x] **Step 2: Run and confirm failure**

Run: `cargo nextest run -p mvm-hostd the_socket_budget_respects`
Expected: FAIL — not defined.

- [x] **Step 3: Implement**

```rust
/// Concurrent host sockets this process can afford.
///
/// The soft limit is raised toward the hard limit first, which an
/// unprivileged process is permitted to do, then a fixed reserve is held
/// back for the process's own descriptors.
pub fn socket_budget(rlimit_soft: u64, rlimit_hard: u64) -> usize {
    let usable = rlimit_soft.max(rlimit_hard) as usize;
    usable.saturating_sub(FD_RESERVE).min(DEFAULT_MAX_HOST_SOCKETS)
}
```

`UserspaceSocketDatapath::open` reads `RLIMIT_NOFILE`, raises the soft limit toward the hard limit, computes the budget, and builds a `UserspaceHandle` owning a `mio::Poll`, a `GuestDevice`, a smoltcp `Interface`, a `SocketSet`, and the tables from Tasks 9 and 13. `readiness_fd` returns the `mio::Poll` descriptor.

- [x] **Step 4: Run tests and confirm they pass**

Run: `cargo nextest run -p mvm-hostd -E 'test(socket_budget) or test(socket_translation_capabilities)'`
Expected: PASS.

- [x] **Step 5: Commit**

```sh
git add crates/mvm-hostd/src/netd/userspace/mod.rs
git commit -m "feat(netd): add the userspace datapath and its descriptor budget"
```

---

### Task 9: The deferred handshake

Given a listening socket, smoltcp answers a SYN itself. Interception before the stack is what makes deferral possible.

**Files:**
- Create: `crates/mvm-hostd/src/netd/userspace/tcp.rs`

**Interfaces:**
- Consumes: `FlowKey` from `mvm_net::l3::flow`, `DenyCode` from `mvm_net::l3::admit`.
- Produces: `struct HalfOpen { key: FlowKey, syn: Vec<u8>, socket: TcpStream, opened_at_millis: u64 }`; `struct HalfOpenTable`; `HalfOpenTable::on_syn(&mut self, key: FlowKey, syn_bytes: Vec<u8>, dst: SocketAddr, now_millis: u64) -> SynOutcome`; `HalfOpenTable::len(&self) -> usize`; `HalfOpenTable::replayable(&mut self) -> Vec<HalfOpen>`; `HalfOpenTable::expire(&mut self, now_millis: u64) -> Vec<HalfOpen>`; `enum SynOutcome { Started, Folded, Refused(DenyCode) }`.

`DenyCode` is the existing deny enum in `mvm_net::l3::admit` — reuse it rather than minting a parallel reason type.

- [x] **Step 1: Write the failing tests**

```rust
#[test]
fn a_syn_does_not_reach_the_stack_until_the_host_connect_succeeds() {
    let mut t = HalfOpenTable::new(DEFAULT_MAX_HALF_OPEN);
    let outcome = t.on_syn(key(), syn_bytes(), unreachable_dst(), 0);
    assert!(matches!(outcome, SynOutcome::Started));
    assert!(t.replayable().is_empty(), "nothing may be replayed into the stack before connect resolves");
}

#[test]
fn a_retransmitted_syn_folds_into_the_existing_entry() {
    let mut t = HalfOpenTable::new(DEFAULT_MAX_HALF_OPEN);
    t.on_syn(key(), syn_bytes(), some_dst(), 0);
    let again = t.on_syn(key(), syn_bytes(), some_dst(), 10);
    assert!(matches!(again, SynOutcome::Folded));
    assert_eq!(t.len(), 1, "a retransmit must not open a second host socket");
}

#[test]
fn a_syn_flood_is_bounded_by_the_half_open_cap() {
    let mut t = HalfOpenTable::new(4);
    for i in 0..64 {
        t.on_syn(key_with_port(i), syn_bytes(), some_dst(), 0);
    }
    assert_eq!(t.len(), 4, "the cap, not the descriptor limit, is what a SYN flood hits");
}

#[test]
fn a_half_open_entry_times_out() {
    let mut t = HalfOpenTable::new(DEFAULT_MAX_HALF_OPEN);
    t.on_syn(key(), syn_bytes(), some_dst(), 0);
    let dropped = t.expire(HALF_OPEN_TIMEOUT_MILLIS);
    assert_eq!(dropped.len(), 1);
}
```

- [x] **Step 2: Run and confirm failure**

Run: `cargo nextest run -p mvm-hostd a_syn_does_not_reach_the_stack`
Expected: FAIL — `HalfOpenTable` not defined.

- [x] **Step 3: Implement**

`on_syn` keys on the guest 4-tuple. An existing entry returns `Folded` without opening a second socket. A full table returns `Refused`, dropping the SYN rather than evicting a live entry. Otherwise it opens a non-blocking `TcpStream` toward the destination, stores the SYN bytes, and returns `Started`. `replayable()` yields only entries whose connect has completed successfully.

- [x] **Step 4: Run tests and confirm they pass**

Run: `cargo nextest run -p mvm-hostd -E 'test(syn)'`
Expected: PASS.

- [x] **Step 5: Commit**

```sh
git add crates/mvm-hostd/src/netd/userspace/tcp.rs
git commit -m "feat(netd): defer the guest handshake until the host connect resolves"
```

---

### Task 10: Destination integrity, and RST on connect failure

**Files:**
- Modify: `crates/mvm-hostd/src/netd/userspace/tcp.rs`
- Also modified: `crates/mvm-hostd/src/netd/test_packets.rs` (restore the TTL the helper lost when it moved out of `gateway.rs`), `crates/mvm-protocol/src/l3/ip.rs` (`tcp_sequence`, sharing one transport-offset walk with `tcp_flags`), `crates/mvm-hostd/Cargo.toml` (smoltcp `proto-ipv6`, for the wire types only)

**Interfaces:**
- Produces: `fn assert_peer_matches(socket: &TcpStream, admitted: IpAddr) -> Result<(), DatapathError>`; `fn synthesize_rst(key: &FlowKey, guest: IpAddr, acknowledging: u32) -> Option<Vec<u8>>` (signature changed — see Step 3).
- Also produces: `HalfOpen::reset_for_guest(&self, guest: IpAddr)`, `HalfOpenTable::guest()`, `Resolved::resets`. `HalfOpenTable::new` now takes the leased guest address and `resolve` now takes `&mut GatewayMetrics`; Task 11 consumes these shapes.

- [x] **Step 1: Write the failing tests**

```rust
/// With a host TUN the admitted packet's bytes are what goes on the wire,
/// so the checked destination is the reached one by construction. Socket
/// translation re-derives it, so the equality has to be asserted.
#[test]
fn a_socket_connected_elsewhere_is_refused() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let sock = std::net::TcpStream::connect(listener.local_addr().unwrap()).expect("connect");
    let wrong = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
    assert!(
        assert_peer_matches(&sock, wrong).is_err(),
        "a peer that is not the admitted destination must tear the flow down"
    );
}

#[test]
fn a_matching_peer_is_accepted() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let sock = std::net::TcpStream::connect(listener.local_addr().unwrap()).expect("connect");
    assert!(assert_peer_matches(&sock, IpAddr::V4(Ipv4Addr::LOCALHOST)).is_ok());
}

#[test]
fn a_failed_connect_synthesizes_a_reset_toward_the_guest() {
    let rst = synthesize_rst(&key());
    let parsed = mvm_net::l3::ip::parse(&rst).expect("the synthesized packet must parse");
    assert_eq!(parsed.protocol, mvm_protocol::l3::proto::TCP);
    assert!(tcp_flags(&rst).contains_rst());
}
```

- [x] **Step 2: Run and confirm failure**

Run: `cargo nextest run -p mvm-hostd a_socket_connected_elsewhere`
Observed: FAIL, 10 errors — `E0425: cannot find function 'assert_peer_matches'` / `'same_host'` / `'synthesize_rst'`, `E0599: no method named 'resets'`. Each behaviour was additionally mutation-checked after implementing, since "not defined" only proves the symbol was absent.

- [~] **Step 3 (implemented; `synthesize_rst` signature changed): Implement**

`assert_peer_matches` compares `socket.peer_addr()?.ip()` against the admitted destination and returns `DatapathError` on mismatch. Call it immediately after connect completion, before the SYN is replayed. `connect()` is only ever handed the `IpAddr` from the admitted packet — never a hostname, never a string through `ToSocketAddrs`, which would re-enter DNS resolution below the policy seam.

Deviation: `synthesize_rst(key: &FlowKey) -> Vec<u8>` cannot produce a reset a guest accepts. `FlowKey` deliberately omits the guest address (its own doc says so), and RFC 793 requires the reset to acknowledge the SYN's sequence plus one — a reset outside that window is discarded by the guest's stack. It takes the leased guest address and the sequence to acknowledge, and returns `Option` for the family-mismatch case that cannot arise. Comparison is on the canonical form, so `::ffff:x` and `x` are one host; admission refuses non-IPv4 destinations outright, so the mapped form is never admitted in the first place.

- [x] **Step 4: Run tests and confirm they pass**

Run: `cargo nextest run -p mvm-hostd -E 'binary_id(mvm-hostd) and test(/netd::userspace::tcp/)'`
Result: 28 passed. Plus `-p mvm-hostd` 1347 passed, `-p mvm-protocol` 465 passed, clippy `-D warnings` clean, nightly fmt clean, `check-file-size` clean, Linux zigbuild and wasm32 check clean.

- [~] **Step 5 (two commits, not one): Commit**

Review round 1 landed as a second commit: the destination-integrity violation now counts a `DenyCode::WrongDestination` deny, `synthesize_rst` grew a real `Ipv6Repr` arm, the reset is addressed from the lease rather than the guest-written SYN source, and `mvm_protocol::l3::ip::tcp_sequence` reads the sequence at its fixed offset so a crafted data-offset nibble cannot suppress a reset.

```sh
git add crates/mvm-hostd/src/netd/userspace/tcp.rs
git commit -m "feat(netd): assert the connected peer is the admitted destination"
```

---

### Task 11: Pumping, backpressure, and half-close

**Files:**
- Modify: `crates/mvm-hostd/src/netd/userspace/tcp.rs`
- Also modified: `crates/mvm-hostd/Cargo.toml` (smoltcp `alloc`), `crates/mvm-hostd/src/netd/userspace/mod.rs` (the shared `SocketSet`'s storage, and the comment about `alloc` that ceased to be true), `xtask/src/check_duplicate_majors.rs` (`defmt` — see Step 3)

**Interfaces:**
- Consumes: `HalfOpen` and `HalfOpenTable` (Task 9), `assert_peer_matches` and `synthesize_rst` (Task 10).
- Produces: `struct EstablishedFlow` with `from_half_open(entry, guest, mtu, now_millis)`, `pump(&mut self, now_millis: u64) -> PumpStats`, `on_guest_fin(&mut self)`, `take_guest_packets(&mut self) -> Vec<Vec<u8>>`, `deliver_from_guest(&mut self, &[u8]) -> PushOutcome`, `close_host(&mut self)`, `key()`, `guest()`, `is_active()`, `host_error()`; `struct PumpStats { to_host: usize, to_guest: usize, stalled: usize }`; `const fn max_bytes_per_pass() -> usize`. `on_host_error` stays Task 12's.
- Produces (test-facing accessors): `EstablishedFlow::bytes_buffered(&self) -> usize`, `host_write_shutdown(&self) -> bool`, `host_socket_closed(&self) -> bool`. Landed as `pub`, not `pub(crate)`: `netd::userspace::tcp` is public API of the crate, so `pub` is reachable and warning-free while a `pub(crate)` accessor used only from `#[cfg(test)]` code trips `dead_code` in the plain lib build, which `-D warnings` rejects.

- [x] **Step 1: Write the failing tests**

```rust
/// Backpressure is what makes the stated memory ceiling real. Without
/// it the buffers grow without bound and the ceiling is fiction.
#[test]
fn a_slow_host_socket_stops_us_accepting_from_the_stack() {
    let mut flow = established_flow_with_full_host_buffer();
    let stats = flow.pump(0);
    assert!(stats.stalled > 0);
    assert!(
        flow.bytes_buffered() <= SOCKET_TX_BUFFER,
        "buffering must stop at the per-socket bound, not grow to meet demand"
    );
}

/// Closing outright would discard the peer's remaining response and
/// break every half-duplex protocol.
#[test]
fn a_guest_fin_half_closes_the_host_socket() {
    let mut flow = established_flow();
    flow.on_guest_fin();
    assert!(flow.host_write_shutdown());
    assert!(!flow.host_socket_closed(), "the peer must still be able to send");
}
```

Landed as ten tests, driven by a hand-built guest TCP endpoint (`FakeGuest`) over a real loopback host socket. Beyond the four sketched: `backpressure_holds_while_the_guest_keeps_pushing` (the bound under sustained demand), `a_guest_fin_arriving_as_a_packet_half_closes_the_host_socket` (the production path, where the FIN is a packet rather than a call), `a_guest_fin_does_not_truncate_data_the_host_has_not_seen`, `a_pump_pass_on_an_idle_flow_moves_nothing`, and `closing_the_host_socket_is_observable` — which exists so that `assert!(!flow.host_socket_closed())` is not vacuously true.

Two of the sketched assertions were strengthened because the sketch would have passed under a real bug:

- `bytes_buffered() <= SOCKET_TX_BUFFER` is satisfied by a mutant that *discards* the guest's bytes on `WouldBlock`. The landed test asserts `bytes_buffered() == buffered_before` and `to_host == 0` as well, so a drop is caught.
- `!to_guest.is_empty()` after a guest FIN is satisfied by `Shutdown::Both`, which still puts a packet on the guest queue. The landed test asserts the packet carries the peer's payload.

Every fixture is bounded (`FILL_ATTEMPTS`, `SETTLED_BLOCKS`, `PUMP_ATTEMPTS`, an explicit peer read timeout), so no negative in this suite can hang instead of failing.

- [x] **Step 2: Run and confirm failure**

Run: `cargo nextest run -p mvm-hostd a_guest_fin_half_closes`
Observed: FAIL, 13 errors — `E0433/E0425: cannot find type 'EstablishedFlow'` (×9), `cannot find type 'PumpStats'`, `cannot find function 'max_bytes_per_pass'` (×2), `cannot find function 'emit_v4_segment'`.

- [~] **Step 3 (implemented; three deviations): Implement**

`pump` moves bytes both directions in one bounded pass. When the host socket returns `WouldBlock`, nothing is consumed from the smoltcp socket, so its receive window closes and the guest's own TCP stops sending; the host→guest direction mirrors it, refusing to read the host socket once the stack's send buffer is full. A guest FIN calls `shutdown(Shutdown::Write)` and leaves the read half open.

Deviations:

1. **Each flow carries its own smoltcp stack** — `Interface` + `GuestDevice` + a one-socket `SocketSet` — rather than being one socket in a set shared across flows. The guest addresses each flow at *its own* destination, and a shared interface can hold four addresses; the alternative is `set_any_ip`, which makes one interface answer for every address that exists. Per-flow also makes the buffer ceiling per-flow arithmetic instead of a shared pool one flow can monopolise, and it is what lets `pump(&mut self, ..)` and `take_guest_packets(&mut self)` have the shapes this task specifies. Consequence: `UserspaceHandle`'s own `SocketSet` stays empty; wiring the handle to own a flow table is Task 12's.

2. **Order of operations on a FIN.** `shutdown(Write)` cannot fire the moment the FIN is seen: the guest's last segment can still be in the stack's receive buffer, and shutting down first truncates the request into a short body with a clean close — indistinguishable, to the peer, from the guest having sent exactly that. The FIN is latched, the guest→host direction drained, and the shutdown forwarded only once `recv_queue()` is empty. `on_guest_fin` does that drain itself, so it still shuts down synchronously when nothing is buffered.

3. **smoltcp's `alloc` feature is now on**, because per-flow socket storage and ring buffers must be owned and smoltcp can otherwise only borrow them for the socket set's own lifetime. It compiles no new crate — it enables the owned arm of `managed`, already in the tree — but smoltcp's `alloc` names `defmt?/alloc`, and that weak reference alone resolves `defmt` 0.3 into `Cargo.lock` beside the 1.1 `jiff` declares. `cargo tree -e normal -i defmt@0.3.100` and `@1.1.0` both print nothing, so neither is built; `check-duplicate-majors` reads the resolved graph regardless, so `defmt` joins its ALLOWLIST with that evidence, alongside the existing `nom` entry made on the same grounds. `cargo deny check`: advisories/bans/licenses/sources all ok.

`max_bytes_per_pass()` is `SOCKET_RX_BUFFER.min(SOCKET_TX_BUFFER)` — no new number. Worth recording that within a single pass this bound is also *structural*: nothing frees buffer space mid-pass (the guest's ACKs only arrive on the next poll), so a pass cannot exceed it whether or not the budget is checked. The explicit budget keeps the bound stated if that ever stops being true.

Host-side errors are stored on the flow and exposed through `host_error()` rather than swallowed; turning one into a guest-facing RST is Task 12's.

- [x] **Step 4: Run tests and confirm they pass**

Run: `cargo nextest run -p mvm-hostd -E 'test(/netd::userspace::tcp/)'` → 38 passed.
Also: `-p mvm-hostd` 1357 passed / 2 skipped; clippy `-D warnings` clean; nightly fmt clean; `check-file-size`, `check-no-spec-refs-in-comments`, `check-no-network-literals`, `check-vsock-only-egress`, `check-duplicate-majors` clean; `cargo deny check` ok; `just check-linux` and `cargo zigbuild --target x86_64-unknown-linux-gnu -p mvm-hostd --all-targets` clean.

Mutation-checked, each red in under 0.05 s (never a hang):

| Mutation | Result |
|---|---|
| host `WouldBlock` consumes the bytes anyway | `a_slow_host_socket_stops_us_accepting_from_the_stack` fails — "a host socket that will not take a byte must register as a stall"; `backpressure_holds_while_the_guest_keeps_pushing` fails on `to_host` 16384 ≠ 0 |
| host→guest drains into a side buffer instead of stopping at the stack | `a_pump_pass_terminates_under_a_saturating_peer` fails — "one pass must be bounded so the drive loop keeps servicing other work" |
| `Shutdown::Write` → `Shutdown::Both` | `the_peer_can_still_send_after_a_guest_fin` fails — "and what reaches the guest must be the peer's bytes" |

**Two review rounds landed on top.**

Round 1 (`fix(netd): make the per-flow memory ceiling true again, and the FIN the stack's call`): the per-flow device queue was still inheriting `DEFAULT_QUEUE_DEPTH`, so the real footprint was ~800 MiB against an asserted 32 MiB — see the note under Task 6 Step 4. `bytes_buffered()` also grew its device term, and `on_guest_fin` stopped latching on the caller's word: it runs the same drain `pump` does and latches only on `RecvError::Finished`, so a forged out-of-window FIN cannot half-close the host socket.

Round 2 (`fix(netd): size the guest queue for what a pass emits, and stop dropping silently`): the round-1 depth of 12 was below what one pass emits, the guest-bound overflow was silent, and the ceiling read `MTU_V1` where the configured MTU was unvalidated. Depth went to 33 — superseded again by round 3 below — overflow is counted, and `accept_mtu` fails closed above `MTU_V1` at both entry points. The oversize check moved into `GuestDevice::push_from_guest`, so `EstablishedFlow::deliver_from_guest` is covered by the same guard as the handle's `send_to_network` rather than being a second unguarded way in. `a_flows_fixed_overhead_stays_small_beside_its_buffers` became `a_flows_inline_size_stays_pinned`, whose doc states what a `size_of` pin cannot see: everything behind `SocketSet`'s `Vec` is one pointer here, so a new heap-allocating field must be added to `FLOW_BUFFER_BYTES` by hand.

Worth recording about the device term's witnesses: `a_guest_that_floods_the_device_queue_stays_inside_the_flow_bound` is the only runtime test that reddens if `bytes_buffered()` stops counting the device queues. The two backpressure tests assert `bytes_buffered() <= FLOW_BUFFER_BYTES`, an upper bound that a smaller measure satisfies trivially. The constant-level term is separately pinned by `the_per_machine_memory_ceiling_is_what_we_claim`.

Round 3 (`fix(netd): bound the guest queue by the ACK burst a poll can emit`): round 2's `POLLS_PER_PASS = 2` did not bound the control segments a pass emits — see the note under Task 6 Step 4 for the ACK-burst derivation and the two-round data term. The depths are now asymmetric (31 guest-facing, 65 guest-bound), the ceiling is 181_778_432, and `pump` takes `&mut GatewayMetrics` so a guest-bound drop moves `queue_drops_egress`.

- [x] **Step 5: Commit**

```sh
git add crates/mvm-hostd/src/netd/userspace/ crates/mvm-hostd/Cargo.toml Cargo.lock xtask/src/check_duplicate_majors.rs
git commit -m "feat(netd): pump established flows with backpressure and half-close"
```

---

### Task 12: Host errors reach the guest; close is deterministic

**Files:**
- Modify: `crates/mvm-hostd/src/netd/userspace/tcp.rs`, `crates/mvm-hostd/src/netd/userspace/mod.rs`, `crates/mvm-hostd/src/netd/userspace/device.rs`, `crates/mvm-hostd/src/netd/userspace/limits.rs`, `crates/mvm-hostd/src/netd/metrics.rs`

**The largest part of this task was not the error handling.** A review found
`HalfOpenTable` and `EstablishedFlow` unreachable from production code:
`UserspaceHandle` held neither, so everything Tasks 9–11 built was exercised
only by unit tests. The wiring landed here.

- [x] **Step 1: Write the failing tests**

Landed as nineteen tests: eight on the flow (`tcp.rs`) and eleven on the
handle (`mod.rs`), plus one on the device's new host-originated push path.

Beyond the sketched four: `every_terminal_host_error_resets_the_guest`
(all six terminal kinds, not the two a fixture happens to use),
`a_second_host_error_does_not_produce_a_second_reset`,
`the_reset_a_host_error_produces_sits_inside_the_guests_window`, and
`a_failed_host_write_resets_the_guest_too`.

The window test is the one that matters: it asserts the emitted reset's
sequence equals the next byte the guest expects and its acknowledgement
equals everything the guest has sent. A reset outside that window is
discarded in silence by the guest's stack, which is the hang this task
exists to prevent — with a packet on the wire to make it look handled.

On the handle: `a_guest_syn_becomes_a_flow_over_a_real_host_socket`,
`the_stacks_reply_reaches_the_guest_through_recv`,
`guest_data_reaches_the_flow_that_owns_it`,
`the_budget_counts_half_open_and_established_together`,
`a_failed_connect_reaches_the_guest_as_a_reset`,
`udp_is_refused_rather_than_silently_dropped`,
`a_segment_for_no_flow_opens_nothing_and_is_counted`,
`a_retransmitted_syn_costs_no_second_socket`,
`close_shuts_every_host_socket_and_is_idempotent`,
`close_releases_connects_that_are_still_in_flight`,
`close_on_a_handle_that_never_opened_a_socket_is_a_no_op`, and
`a_closed_handle_refuses_to_open_new_flows`.

Every handle fixture drives real loopback connects through a bounded
service loop (`SERVICE_ATTEMPTS`), so a connect that never resolves fails an
assertion rather than hanging.

- [x] **Step 2: Run and confirm failure**

Run: `cargo nextest run -p mvm-hostd a_host_side_reset_reaches`
Observed: `error[E0599]: no method named `on_host_error` found for struct
`userspace::tcp::EstablishedFlow`` — 7 compile errors, `error: could not
compile `mvm-hostd` (lib test)`.

- [x] **Step 3: Implement**

Four decisions worth recording.

1. **The reset comes from the live socket's `abort()`, not from
   `synthesize_rst`.** That function answers a SYN whose sequence number is
   in the held SYN; an established flow has no held SYN, and its correct
   numbers live inside the stack where nothing outside can read them —
   smoltcp exposes no sequence accessor. `abort()` moves the socket to
   CLOSED and its dispatch emits `RST` at `remote_last_seq` acknowledging
   `remote_seq_no + rx_buffer.len()`, then forgets the endpoint, so one
   aborted connection is exactly one reset however many times it is called.
   `synthesize_rst` keeps the failed-*connect* path, where no stack exists.
   `on_host_error` polls at the flow's last-polled clock — held in a new
   `last_polled_millis` field — because the method's contract is that the
   packet is queued by the time it returns, and the signature carries no
   timestamp.

2. **Terminal is the default; the two transient kinds are named.** A kind
   missing from a terminal allow-list is a flow that hangs with nothing to
   say why; a kind wrongly called terminal is a connection that ends with an
   `ECONNRESET` the application sees immediately. Only the second failure is
   visible, so the default falls that way. `WouldBlock` and `Interrupted`
   are no-ops.

3. **One combined budget.** Half-open and established entries each park a
   real descriptor and compete for the same allowance, so
   `open_socket_count()` is their sum and `open_flow` refuses at
   `budget`. `HalfOpenTable`'s own capacity stays as a second, tighter cap
   on the half-open *class* (`DEFAULT_MAX_HALF_OPEN.min(budget)`), so a
   connect flood cannot crowd out established flows. Both drop the newcomer.

4. **The reset queue is the machine-wide device, not a new queue.**
   `GuestDevice::push_to_guest` puts a host-originated packet on the same
   bounded `to_guest` queue, under the same depth, the same
   drop-the-newcomer rule, and the same `dropped_to_guest` counter. The
   handle's device had become dead state once flows carried their own; this
   is what it is for. It also means the resets owed to failed connects need
   no term of their own in the ceiling.

`pump` now calls `on_host_error` when a direction latched one. That closes
the gap Task 11 §8.3 carried forward: a flow whose host write failed with
data still queued never reached `forward_guest_fin` (the `recv_queue() > 0`
guard), so it sat claiming to be open with nothing able to drain it. A
terminal host error is now what resolves it, in the same mechanism that
tells the guest.

`send_to_network` classifies on the admitted metadata: established flow →
`deliver_from_guest`; TCP SYN-without-ACK → `HalfOpenTable::on_syn` with the
destination taken from the admitted `FlowKey` (never a re-parse of guest
bytes, which would put a second parse below the policy seam); any other TCP
segment → dropped and counted under `GatewayMetrics::segments_without_flow`,
because the ordinary cause is a guest's last ACK arriving after its flow was
reaped and an error counter that climbs on every healthy close is useless;
non-TCP → refused with `DatapathError::Unsupported` and a `ProtocolDenied`
deny, so a UDP datagram fails loudly on the first packet rather than
vanishing. `ForwardingCapabilities::USERSPACE_SOCKETS` still advertises
`udp: true`, which is over-claiming until Task 13 lands — left alone
deliberately, since flipping it changes admission rather than the datapath.

**The ceiling moved.** The half-open table's held SYNs were a per-handle
allocation the formula did not model: `HALF_OPEN_BUFFER_BYTES =
DEFAULT_MAX_HALF_OPEN * MTU_V1` = 96,000 bytes.
`MEMORY_CEILING_BYTES` goes 46,020,608 → **46,116,608**, and
`the_per_machine_memory_ceiling_is_what_we_claim` pins the new term
separately. `EstablishedFlow` grew one inline `u64`, no heap, so
`FLOW_BUFFER_BYTES` is unchanged and `a_flows_inline_size_stays_pinned`
still holds.

- [x] **Step 4: Run tests and confirm they pass**

`cargo nextest run -p mvm-hostd` → 1405 passed / 2 skipped (after review round 2).
`-E 'test(userspace)'` → 106 passed. clippy `-D warnings` clean (`metrics()`
is `pub`, not `pub(crate)`, for the `dead_code` reason recorded under Task
11); nightly fmt clean; `check-file-size` clean; `cargo zigbuild --target
x86_64-unknown-linux-gnu -p mvm-hostd --all-targets` clean.

Mutation-checked. Each red is timed on an already-built tree — a first
measurement that counted the rebuild inside its budget reported a false
"hang", which is worth recording because a real hang and a slow rebuild look
identical from outside:

| Mutation | Result |
| --- | --- |
| `is_terminal_host_error` → always `false` | 7 red in 0.10 s, incl. `a_host_side_reset_reaches_the_guest_as_a_reset` |
| `is_terminal_host_error` → always `true` | `a_would_block_is_not_treated_as_a_host_error` red, 0.10 s |
| drop the `poll` from `on_host_error` | 5 red in 0.12 s — the abort alone queues nothing |
| drop the `on_host_error` call from `pump` | `a_failed_host_write_still_resolves_the_write_half` + `..._resets_the_guest_too` red, 0.09 s |
| `close()` no longer clears `flows` | `close_shuts_every_host_socket_and_is_idempotent` red, 0.10 s |
| `close()` no longer clears `half_open` | `close_releases_connects_that_are_still_in_flight` red, 0.09 s |
| budget counts only `flows.len()` | `the_budget_counts_half_open_and_established_together` red, 0.11 s |
| `resolve_connects` drops its resets | `a_failed_connect_reaches_the_guest_as_a_reset` red, 0.68 s |
| reaper drops the `pending_to_guest()` guard | **survived at first.** The guard's claim — a reset flow must outlive the pass that ended it — had no witness. `a_reset_flow_is_not_reaped_before_the_guest_has_its_reset` was added for it; the mutation now reddens in 0.14 s |

- [x] **Step 5: Commit**

```sh
git add crates/mvm-hostd/src/netd/ specs/plans/287-userspace-socket-datapath.md
git commit -m "feat(netd): surface host socket errors to the guest and close deterministically"
```

**Review round 1 landed on top** (`fix(netd): deliver before resetting, and
reclaim on a dead peer rather than a quiet one`).

1. **The reset was discarding data the peer had already sent.** `abort()` was
   called after `host_to_guest` had buffered the peer's bytes, and smoltcp's
   aborted-socket dispatch emits a **payload-less** RST — so a server that
   answered and then closed with `SO_LINGER 0` (`ECONNRESET`, the ordinary
   shape of a hard close) lost its whole response, and the guest's
   application saw a request that failed for no reason. Losing an answered
   request is worse than the hang the reset exists to prevent.

   `deliver_then_reset` now polls first and holds the reset back while
   `send_queue() > 0`, retrying on each later pump pass. It waits for the
   guest to *acknowledge* rather than merely for the bytes to be emitted: a
   reset arriving beside unacknowledged data is entitled to discard it, so
   emission is not delivery. Witnessed by
   `a_peers_buffered_response_reaches_the_guest_before_the_reset`, which
   asserts the payload arrives **and** that no reset accompanies it, then
   that the reset follows the acknowledgement.

2. **The idle-timeout instruction was withdrawn and is not implemented.** An
   idleness reaper would have killed Server-Sent Events and WebSocket
   streams, which are plain TCP, fully carried here, and idle *by design* —
   the failure would have looked like a connection dropped for no reason
   with nothing in any log. Idleness cannot distinguish a connection nobody
   is using from one nobody is answering.

   What landed instead: `SO_KEEPALIVE` on every flow's host socket
   (`KEEPALIVE_IDLE_SECS` 60, `KEEPALIVE_PROBE_INTERVAL_SECS` 10,
   `KEEPALIVE_PROBE_RETRIES` 3 — a vanished peer surfaces as a socket error
   within ~90 s instead of a platform default's two hours). No new reap path
   was needed: the probes failing make the socket error, and the host-error
   path already resets the guest and releases the descriptor.
   `a_quiet_flow_whose_peer_is_alive_is_never_reclaimed` is the streaming
   case made executable — it is the test that would have caught the
   withdrawn instruction — and `a_flow_whose_peer_is_gone_is_reclaimed`
   closes the resource hole with an abortive peer close.

   **Residual hole, stated rather than papered over:** a peer that stays
   alive indefinitely while the guest has forgotten the flow keeps its
   descriptor. Keepalive cannot see that, and no idle timer may be used to
   guess at it. The shape that would close it is a liveness probe *toward
   the guest* — this datapath terminates the guest's TCP, so it can ask the
   guest's stack directly — reaping only on no answer, which distinguishes
   "nobody wants this" from "nothing to send". Not implemented; the blast
   radius is one guest's own per-machine budget, and machine teardown
   reclaims everything.

3. **Throughput is counted.** `PumpStats` was discarded, so nothing recorded
   whether the datapath was carrying traffic at all. `fold_throughput` folds
   each pass's bytes in, and packets are counted where they cross the guest
   seam. Packets at the guest seam and bytes at the host seam are different
   quantities on a socket-translating datapath — a guest packet includes
   framing and may be a pure ACK — so they are documented as such rather
   than collapsed into one number that would be wrong for both.

The handle fixture now completes a real handshake
(`handle_with_an_established_conversation`), which is what makes
`the_traffic_it_carries_crosses_the_host_socket_and_is_counted` an
end-to-end witness: a guest packet in at the datapath's own entry point,
the same bytes read out of a host socket by a real peer.

Round-1 mutations, all observed on an already-built tree:

| Mutation | Result |
| --- | --- |
| `deliver_then_reset` aborts without delivering | `a_peers_buffered_response_reaches_the_guest_before_the_reset` + `the_reset_is_in_window_after_the_flow_has_carried_data` red, 0.12 s |
| the keepalive `setsockopt` removed | `a_flows_host_socket_asks_whether_its_peer_is_still_there` red, 0.11 s |
| `fold_throughput` not called | both throughput tests red, 0.64 s |
| `packets_ingress` not counted | `the_traffic_it_carries_crosses_the_host_socket_and_is_counted` red, 0.14 s |
| an idleness reaper re-introduced | `a_quiet_flow_whose_peer_is_alive_is_never_reclaimed` red, 0.10 s |

The ceiling did not move: the one field added is an inline `bool`, and
keepalive is a socket option, not memory. 1403 tests pass, and the full
crate suite was run five times to confirm the flake that came in with the
withdrawn idle measure left with it.

**Review round 2 landed on top** (`fix(netd): bound the deferred reset with
a deadline a guest cannot move`).

Round 1 introduced a coupling neither side saw: the deferred reset was
relying on the idleness reaper as its backstop, and round 1 removed that
reaper. The deferral was left with **no terminator**. A guest that stops
acknowledging — a crash, a zero window, or a hostile guest simply choosing
not to — kept `send_queue() > 0` forever, so `deliver_then_reset` returned
early on every pass, the socket was never aborted, it stayed `is_active()`,
and the retain kept it. The descriptor was released (that part was right),
but the flow entry, ~176 KB of buffers, and a slot in `open_socket_count`
were held for the machine's lifetime; 256 of those and no connect for that
machine can ever succeed again.

**The terminator: an absolute deadline on the flow, not smoltcp's
`set_timeout`.** `RESET_DELIVERY_TIMEOUT_MILLIS` (10 s, the same scale as
the half-open timeout and for the same reason — the guest is one in-memory
hop away) is taken once when the failure is latched and never refreshed.

`set_timeout` was examined first, since using the stack's own mechanism
would have been preferable, and rejected on two counts read out of
smoltcp 0.13.1's source rather than assumed:

- It measures the gap between packets **the remote sends**
  (`timed_out()` is `now >= remote_last_ts + timeout`, and `remote_last_ts`
  is refreshed on every ingress packet at `socket/tcp.rs:2001`). A guest
  that acknowledges without ever draining refreshes it for free — precisely
  the starvation the review asked about. A terminator a guest can postpone
  is not a terminator.
- `timed_out()` is evaluated **unconditionally** at the top of `dispatch`
  (`socket/tcp.rs:2389`), and `poll_at` schedules a wake for it, so a socket
  left carrying a timeout aborts a healthy quiet connection whose remote
  has simply had nothing to say. That is round 1's streaming case again,
  reached through a different door.

Two tests: `a_guest_that_stops_acknowledging_cannot_hold_the_flow_forever`
(the flow becomes reapable rather than staying `is_active()` forever) and
`a_guest_that_stops_acknowledging_does_not_pin_its_budget_slot` (the handle
gets its `open_socket_count` slot back). Both stay red under a deferral with
the deadline removed **and** under a deadline that is refreshed each pass —
the second mutation is the starvable shape, so the suite discriminates
between the two designs rather than merely covering the code.

Also in this round: the `pump_flows` doc line still said "or gone idle",
contradicting its own body — corrected. And `socket2`'s `all` feature, which
the keepalive knobs need, is now declared in `crates/mvm-hostd/Cargo.toml`
instead of being inherited by luck from `mvm-build → reqwest → hyper-util`;
`cargo metadata --no-deps` reports `mvm-hostd -> socket2 features = ['all']`.

Round-2 mutations, both observed:

| Mutation | Result |
| --- | --- |
| the deadline check removed (the bug as found) | both stops-acknowledging tests red, 0.12 s |
| the deadline refreshed on every pass (the starvable shape) | both stops-acknowledging tests red, 0.11 s |

The ceiling did not move: `reset_pending: bool` became
`reset_deadline: Option<u64>`, still inline. 1405 tests pass.

**Known gap, not this task's:** nothing in production calls
`UserspaceHandle::service`. `DatapathHandle` has no `service` method and the
gateway drives only `send_to_network` / `recv_from_network`, so connects
never resolve outside tests. `UserspaceSocketDatapath` is also not what
`host_datapath()` returns on macOS — that is still `MacosUserspaceGateway`,
which refuses. Both are wiring above this seam.

---

### Task 13: UDP associations

**Files:**
- Create: `crates/mvm-hostd/src/netd/userspace/udp.rs`

**Interfaces:**
- Produces: `struct UdpAssociations`; `UdpAssociations::send(&mut self, key: FlowKey, payload: &[u8], now_millis: u64) -> Result<(), DatapathError>`; `UdpAssociations::poll(&mut self, now_millis: u64) -> Vec<Vec<u8>>`; `UdpAssociations::expire(&mut self, now_millis: u64) -> usize`.

- [x] **Step 1: Write the failing tests**

```rust
#[test]
fn a_datagram_round_trips_through_a_host_socket() {
    let echo = bind_udp_echo_server();
    let mut a = UdpAssociations::new(64);
    a.send(key_to(echo.local_addr()), b"ping", 0).expect("send");
    let replies = poll_until_nonempty(&mut a, std::time::Duration::from_secs(2));
    assert!(!replies.is_empty());
}

#[test]
fn associations_expire_on_the_datagram_timeout() {
    let mut a = UdpAssociations::new(64);
    a.send(key(), b"x", 0).expect("send");
    assert_eq!(a.expire(mvm_net::l3::DEFAULT_DATAGRAM_IDLE_MILLIS), 1);
}

#[test]
fn the_association_table_drops_rather_than_evicting() {
    let mut a = UdpAssociations::new(2);
    for i in 0..8 { let _ = a.send(key_with_port(i), b"x", 0); }
    assert_eq!(a.len(), 2);
}
```

- [~] **Step 2 (not observed): Run and confirm failure**

Run: `cargo nextest run -p mvm-hostd a_datagram_round_trips`
Expected: FAIL.

The implementer was stopped before reporting, so whether the red state was
ever observed is unknown. Marked not-observed rather than done: the tests
and the implementation both exist and pass, but nobody recorded watching
them fail first, and a test never seen red is a test whose failure mode is
unproven.

- [x] **Step 3: Implement**

One host `UdpSocket` per association keyed on the guest 4-tuple. Replies are synthesized back as IP+UDP toward the guest. DNS never reaches here — it terminates above the seam.

- [x] **Step 4: Run tests and confirm they pass**

Run: `cargo nextest run -p mvm-hostd -E 'test(datagram) or test(association)'`
Expected: PASS.

- [x] **Step 5: Commit**

```sh
git add crates/mvm-hostd/src/netd/userspace/udp.rs
git commit -m "feat(netd): translate guest datagrams onto host sockets"
```

---

### Task 14: Selection and the honest fallback diagnostic

**Files:**
- Modify: `crates/mvm-hostd/src/netd/mod.rs:54-72` (selection) **and `:46`** (drop it from the `pub use` list)
- Delete: `MacosUserspaceGateway` from `crates/mvm-hostd/src/netd/datapath.rs:383-435`, **and its two test-module uses at `:527` and `:541`** — those tests assert the placeholder's refusal, so they are deleted with it rather than retargeted.

Every reference, so the deletion compiles: `datapath.rs:405,407,419,527,541` and `mod.rs:46,68`.

**Interfaces:**
- Consumes: `UserspaceSocketDatapath` (Task 8).

- [x] **Step 1: Write the failing tests**

```rust
#[cfg(not(target_os = "linux"))]
#[test]
fn macos_selects_the_userspace_datapath() {
    let dp = host_datapath();
    assert!(dp.is_available().is_ok());
    assert!(dp.capabilities().userspace_socket_translation);
}

/// An operator who lost CAP_NET_ADMIN would otherwise see a plan refused
/// for `missing: ["icmp"]` with nothing saying the fallback caused it.
#[test]
fn the_linux_fallback_explains_itself() {
    let reason =
        fallback_reason(TunProbe::Unavailable).expect("a fallback must state its reason");
    assert!(reason.contains("CAP_NET_ADMIN"), "{reason}");
    assert!(reason.contains("userspace socket translation"), "{reason}");
}
```

Two deviations from the sketch, both deliberate. The helper is
`fallback_reason`, not `fallback_reason_for_test`: a `_for_test` name on a
shipped function reads as a test-only back door, and this one is the
production path. And the first test is `cfg(not(target_os = "linux"))`,
because a Linux host that *passes* its TUN probe correctly reports
`userspace_socket_translation: false` — asserting otherwise there would
demand a lie. Three further tests cover what the sketch left open: the
`Available` arm explains nothing; the `Unsupported` arm does not tell a
platform to go and acquire a capability it cannot hold; and the selected
datapath's availability and its reason agree, so a fallback always carries a
reason and the packet-level path never does. Two more in `mvm-netd` pin the
message an operator actually reads:
`a_capability_refusal_arrives_with_the_substitution_that_caused_it` and
`a_host_on_its_own_datapath_is_told_no_story_about_a_fallback`.

- [x] **Step 2: Run and confirm failure**

Run: `cargo nextest run -p mvm-hostd -E 'test(macos_selects_the_userspace_datapath) or test(the_linux_fallback_explains_itself)'`

Both observed red, and for behavioural reasons rather than compile errors:

```
thread 'netd::tests::macos_selects_the_userspace_datapath' panicked at
  crates/mvm-hostd/src/netd/mod.rs:105:9:
  assertion failed: dp.is_available().is_ok()
thread 'netd::tests::the_linux_fallback_explains_itself' panicked at
  crates/mvm-hostd/src/netd/mod.rs:114:52:
  a fallback must state its reason
Summary [0.010s] 2 tests run: 0 passed, 2 failed, 1448 skipped
```

The first is the refusing gateway, exactly as predicted. The second needed
`TunProbe` and `fallback_reason` to exist at all before it could compile, so
they were introduced first with the body `None` — which is not a straw man
but literally the prior state: nothing anywhere carried a reason. The red is
the real absence, not a placeholder arranged to fail.

- [x] **Step 3: Implement**

`select_host_datapath()` returns a `DatapathSelection` — the datapath plus
the reason it is not the packet-level one. `LinuxDatapath` when its probe
passes; `UserspaceSocketDatapath` otherwise, on every platform including
Linux. `host_datapath()` survives as the thin accessor for the two callers
that only ask whether this host can serve one at all.
`MacosUserspaceGateway` is deleted outright, along with the two tests that
asserted its refusal. The reason reaches the operator in two places in
`mvm-netd`: logged at selection, before anything can refuse, and appended to
a `Gateway::open` failure, so a capability shortfall arrives next to the
substitution that caused it rather than as a bare `missing: ["icmp"]`.

- [x] **Step 4: Run tests and confirm they pass**

One mutation, to prove the diagnostic test earns its name. Dropping the
`fallback` argument from `explain_open_failure` turns it red with exactly the
message this task exists to prevent:

```
opening the gateway: selected forwarding backend cannot serve this plan:
  missing icmp
```

That is the whole of what the operator would have had — true, and no use to
anyone. Restored, and the suites below are the post-restore run.

```
cargo nextest run -p mvm-hostd
  Summary [7.135s] 1451 tests run: 1451 passed, 2 skipped
cargo clippy -p mvm-hostd --all-targets -- -D warnings   # clean
cargo zigbuild --target x86_64-unknown-linux-gnu -p mvm-hostd --all-targets
  Finished `dev` profile in 1m 01s
xtask check-vsock-only-egress / check-uniform-vsock-egress /
  check-claim-catalog / check-no-spec-refs-in-comments /
  check-no-overclaim / check-honesty                     # all clean
```

`--all-targets` on the Linux cross-build rather than `just check-linux`,
which is `--lib` only and would have compiled neither the `mvm-netd` bin nor
this task's tests. The flaky trio (`host_agent_restart`,
`per_tenant_isolation`, `broker_audit_round_trip`) passed in the full run.

**Blocker this task exposes, and does not close.** Selecting the datapath is
necessary but not sufficient: nothing in production calls
`UserspaceHandle::service`, and `DatapathHandle` has no `service` method for
`mvm-netd`'s pump loop to reach through its trait object. `service` is the
only thing that resolves connects, promotes them into flows, polls UDP
associations, and pumps established flows, so on a host that falls back
today a guest's `connect()` never completes. Task 12 recorded this as
"wiring above this seam" while the fallback was unreachable; selection is
what makes it load-bearing. It needs a `DatapathHandle::service(now_millis)`
defaulting to a no-op — the Linux TUN handle genuinely has nothing to do on
a tick — called from the same tick that already ages flows and DNS
bindings. Not folded in here because it changes a trait every backend
implements and belongs in its own red-green cycle, but nothing downstream of
this plan should treat the fallback as working until it lands.

**Blocker closed** — its own commit, as described above.
`DatapathHandle::service(now_millis)` exists with a no-op default, so the
Linux TUN handle and `LoopbackHandle` are untouched;
`UserspaceHandle`'s impl forwards to the inherent one; `Gateway::
service_datapath` forwards to the boxed handle without handing it out
mutably; and `mvm-netd`'s `drive` calls it once a pass with the loop's own
monotonic clock, before `poll_inbound` — that ordering is what makes a
connect the kernel decided readable on the same pass. A service failure is
fatal to the tunnel rather than counted: a datapath that cannot be serviced
cannot carry traffic, and continuing would restore the silent hang.

Two witnesses, both mutation-proved:

- `the_loop_services_the_datapath_it_owns` (`crates/mvm-hostd/src/bin/
  mvm-netd.rs`) drives the real `serve` loop against a datapath whose
  packets are unreadable until a service pass promotes them, and asserts the
  guest received the packet and that every service pass carried the loop's
  injected clock value. Removing the `service_datapath` call from `drive`
  turns it red: `WouldBlock` on the guest's read — the hang itself.
- `servicing_through_the_trait_object_resolves_a_pending_connect`
  (`crates/mvm-hostd/src/netd/userspace/mod.rs`) boxes a `UserspaceHandle`
  as `dyn DatapathHandle`, delivers a SYN toward a live loopback listener,
  and drives only the trait method until a SYN-ACK comes back. Deleting the
  `UserspaceHandle` impl so the no-op default stands turns it red, which the
  first witness cannot catch because it uses a test double.

A test that calls `service` itself catches neither mutation: it exercises
exactly the thing production was failing to do.

```
cargo nextest run -p mvm-hostd
  Summary [4.945s] 1454 tests run: 1454 passed, 2 skipped
cargo clippy -p mvm-hostd --all-targets -- -D warnings   # clean
cargo zigbuild --target x86_64-unknown-linux-gnu -p mvm-hostd --all-targets
  Finished `dev` profile in 22.73s
xtask check-vsock-only-egress / check-uniform-vsock-egress /
  check-claim-catalog / check-no-spec-refs-in-comments   # all clean
```

**Open over-claim, not this task's to fix.**
`ForwardingCapabilities::USERSPACE_SOCKETS` declares `declared_ingress:
true`, and nothing in the userspace datapath opens a listening socket, so
host-initiated inbound to a declared guest port cannot be served. It is not
merely cosmetic now that this backend is reachable: `GatewayConfig::new`
requires `declared_ingress`, so flipping the flag to the truth would make
every default gateway refuse on the fallback path and strand the whole
plan. The honest fix is a listener per declared mapping, which belongs with
the deferred "UDP ingress" item rather than here. **Resolved in WS2 for
datagrams** — a listener per declared UDP mapping now exists, so the flag
became true rather than false and the config requirement never had to move.
Stream ingress on this backend remains unserved and is recorded as such.

- [x] **Step 5: Commit**

```sh
git add crates/mvm-hostd/src/netd/ crates/mvm-hostd/src/bin/mvm-netd.rs
git commit -m "feat(netd): select the userspace datapath, with an honest fallback reason"
```

---

### Task 15: The unprivileged end-to-end suite

**Files:**
- Create: `crates/mvm-hostd/tests/userspace_datapath.rs`

- [x] **Step 1: Write the tests**

```rust
/// The decision this makes executable: the guest must not see
/// ESTABLISHED for a destination that has not accepted.
#[test]
fn no_syn_ack_reaches_the_guest_before_the_listener_accepts() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let mut h = open_userspace_handle();

    h.send_to_network(&admitted_syn_to(listener.local_addr().unwrap())).expect("send");
    h.service(0).expect("service");
    assert!(drain_guest(&mut h).is_empty(), "no SYN-ACK before the host side is real");

    let _accepted = listener.accept().expect("accept");
    h.service(50).expect("service");
    assert!(
        drain_guest(&mut h).iter().any(|p| tcp_flags(p).is_syn_ack()),
        "the SYN-ACK must follow acceptance, not precede it"
    );
}

#[test]
fn bytes_flow_in_both_directions_over_a_translated_flow() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().expect("accept");
        let mut got = [0u8; 4];
        s.read_exact(&mut got).expect("read");
        assert_eq!(&got, b"ping");
        s.write_all(b"pong").expect("write");
    });

    let mut h = open_userspace_handle();
    establish_flow(&mut h, addr);
    h.send_to_network(&admitted_payload_to(addr, b"ping")).expect("send");
    h.service(50).expect("service");

    let to_guest = drain_guest_until_payload(&mut h, b"pong", std::time::Duration::from_secs(2));
    assert!(to_guest, "the host's reply must be framed back to the guest");
    server.join().expect("server thread");
}

#[test]
fn a_malformed_tcp_segment_is_dropped_without_panicking() {
    let mut h = open_userspace_handle();
    // Truncated header, absurd data offset, and zero-length payload with
    // SYN+FIN both set — each has bitten real userspace stacks.
    for corpus in [
        &b"\x45\x00\x00\x14"[..],
        &b"\x45\x00\x00\x28\x00\x00\x00\x00\x40\x06\xff\xff\x0a\x00\x00\x02\x0a\x00\x00\x01\x00\x50\x00\x50\x00\x00\x00\x00\x00\x00\x00\x00\xf0\x03\x00\x00"[..],
    ] {
        let _ = h.send_to_network(&admitted_raw(corpus));
        h.service(0).expect("a malformed segment must not take the datapath down");
    }
}

#[test]
fn descriptor_exhaustion_degrades_to_drop_rather_than_panic() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap();
    let mut h = open_userspace_handle_with_budget(2);

    for port in 0..32u16 {
        let _ = h.send_to_network(&admitted_syn_from_port(port, addr));
        h.service(u64::from(port)).expect("exhaustion must not panic");
    }
    assert!(
        h.open_socket_count() <= 2,
        "the budget, not the process descriptor limit, is what a flow burst hits"
    );
}
```

Test helpers (`open_userspace_handle`, `open_userspace_handle_with_budget`,
`admitted_syn_to`, `admitted_raw`, `admitted_payload_to`,
`admitted_syn_from_port`, `establish_flow`, `drain_guest`,
`drain_guest_until_payload`, `tcp_flags`) live in this file's own
`mod helpers`. `admitted_*` construct `AdmittedPacket` through
`mvm_net::l3`'s admitter — the type cannot be built any other way, which
is the point of the seam.

**What was written instead, and why.** Three corrections to the sketch
above, all forced by what the code actually is:

- *No handle a test services alone.* Six of the nine witnesses drive the
  **`mvm-netd` process** — its pump loop, its trait object, its service
  pass — through the real guest agent over the real Unix sockets. A suite
  built only on `open_userspace_handle()` + `h.service(0)` would drive the
  exact thing production can fail to drive, and would have stayed green
  through the defect Task 14 fixed. Only the flow-lifetime bounds, whose
  deadlines are 10s and 60s, use a directly-serviced handle with an
  injected clock.
- *No loopback destination.* `L3Admitter` refuses loopback outright and an
  `AdmittedPacket` comes from nowhere else, so `127.0.0.1:0` cannot be a
  fixture destination at all. Every listener binds a **private
  non-loopback address the host owns**, discovered by `getifaddrs` at
  runtime. A host with no such interface skips with the reason printed.
- *"Before the listener accepts" is not observable.* A listening socket's
  backlog completes the handshake in the kernel with no `accept()`
  anywhere, so no host socket can distinguish the two. The deferred
  handshake is pinned on a destination that **refuses**: the guest gets a
  reset and never a SYN-ACK. Mutation-checked — promoting a failed
  connect into a flow turns that witness red.

Malformed-segment and descriptor-exhaustion coverage stayed where it
already is (Task 8's fuzz target; the in-crate budget tests), rather than
being restated here against a seam that cannot construct the inputs.

- [x] **Step 2: Run them**

Run: `cargo nextest run -p mvm-hostd --test userspace_datapath`
Expected: **PASS.** Tasks 6–14 all precede this one, so the datapath already exists — this task is the end-to-end suite over finished parts, not a red-green cycle. If any test here fails, the bug is in Tasks 6–14 and belongs in that task's fix loop, not patched here.

Observed: 9 passed, and the whole `mvm-hostd` suite at 1463 passed. No
failure indicated a defect in Tasks 6–14.

- [x] **Step 3: Commit**

```sh
git add crates/mvm-hostd/tests/userspace_datapath.rs
git commit -m "test(netd): cover the userspace datapath end to end, unprivileged"
```

---

### Task 16: Documentation and ledger close-out

**Files:**
- Modify: `public/src/content/docs/guides/l3-vsock-networking.md`, `specs/plans/285-l3-tun-over-vsock.md`, `specs/plans/287-userspace-socket-datapath.md`, `specs/REFACTOR-STATUS.md`, `specs/SPRINT.md`

- [x] **Step 1: Update the platform matrix**

The guide and ADR-036 both state macOS is unsupported. Correct both to describe what now ships, including that ICMP, raw IP protocols, and arbitrary IPv4 remain unavailable and are refused at admission.

Done, and widened past what the step asked for, because three things in the
existing prose were false rather than merely stale:

- The guide's matrix now distinguishes the two forwarding backends instead
  of the two platforms, since an unprivileged Linux host and a macOS host
  now get the same backend. ICMP, raw IP protocols and arbitrary
  IPv4/IPv6 are named as refused at admission, and named as **permanent**
  on macOS: ADR-039, which proposed the privileged helper that would have
  bought them, is Rejected.
- Three open defects are stated as limitations rather than omitted: the
  50 ms latency floor (the readiness descriptor is exposed and registered
  but has nothing behind it, so every host-driven step waits for the drive
  loop's tick), `declared_ingress: true` advertised with no listening
  socket serving it, and `poll_inbound`'s unbudgeted drain. They are in
  the guide as user-visible costs and in ADR-037 §"Known defects in what
  shipped" as engineering record.
- ADR-036 described `MacosUserspaceGateway` in the present tense. Every
  reference is corrected; the type is deleted.

**ADR-037's memory ceiling was wrong and is re-derived.** It claimed
`1024 × 32 KiB = 32 MiB`, wrong in three independent ways: the cap is 256,
a flow costs 176,768 bytes rather than its 32,768 bytes of ring buffers
(each flow owns its own smoltcp device and its two packet queues), and UDP
associations landed after the ADR and add a term the formula had no place
for. The real figure from `limits.rs` is 46,500,608 bytes — 44.35 MiB —
with the arithmetic shown term by term in the ADR. Surfaced rather than
smoothed over: the doc comment on `DEFAULT_MAX_HOST_SOCKETS` says the worst
case at a cap of 256 is "back under 44 MiB", which holds only for the
per-flow term (43.16 MiB) and omits the three machine-level terms
`MEMORY_CEILING_BYTES` itself sums. The bounds audit corrected that comment
and gave the machine-wide device term an assertion of its own, since losing
it and losing the UDP term each move the total by the same 384,000 bytes.

- [x] **Step 2: Tick plan 285's deferred item**

Mark "macOS userspace socket gateway" done in plan 285, pointing at this plan.

Ticked. Its sibling `utun` + PF entry is annotated as closed rather than
queued, and its IPv6 entry's "blocked on `CONFIG_IPV6`" framing is
corrected per ADR-038.

- [x] **Step 3: Run the full gate list**

Every command in the Gate list section. `xtask check-doc-claims` is the one most likely to object to new prose — it gates claim phrasing.

Run for this task: `check-doc-claims`, `check-no-overclaim`,
`check-claim-catalog`, `check-adr-coverage`, `check-deferrals`,
`check-no-spec-refs-in-comments`, `cargo nextest run -p mvm-hostd`, and
`cargo +nightly fmt --all -- --check`. All clean. Neither prose gate
objected, so no wording was softened to get past one.

- [x] **Step 4: Commit**

```sh
git add specs/ public/
git commit -m "docs(plan-287): record the userspace socket datapath as shipped"
```

---

# Phase E — WS4: what the datapath costs, and whether it needs multi-queue

**Status: COMPLETE — measured 2026-08-04. Multi-queue is NOT warranted; no
implementation code was written, which is the intended outcome when the
measurement does not support the work.**

The deliverable here is the measurement. Multi-queue was always contingent on
it, and the numbers do not support it.

### The benchmark

`crates/mvm-hostd/tests/userspace_datapath.rs`, six `#[ignore]`d tests at the
end of the file. They extend the suite that was already there rather than
standing up a second harness: `Translator` — the direct-handle driver the
flow-lifetime tests use — already establishes flows through the real
admission seam, so the benchmarks reuse it and add only the guest-side
sequence bookkeeping a sustained flow needs (`GuestFlow`) and one host peer
that plays source, sink or echo (`HostPeer`).

Driving the handle directly rather than the `mvm-netd` process is deliberate:
the process path folds the guest channel's framing and a UDS round trip into
every figure, which measures the tunnel rather than the datapath this
decides about.

`#[ignore]`d because they run for seconds and are timing-sensitive; a
benchmark that can go red under a loaded CI box trains people to ignore red.

```sh
cargo test --release -p mvm-hostd --test userspace_datapath \
    -- --ignored --nocapture --test-threads 1
```

### Conditions

Apple MacBook Pro, Darwin 25.5.0 arm64 (T6041), 16 cores, 128 GiB. Release
build, `--test-threads 1`. Host otherwise near-idle — load average 5–9, all
non-benchmark processes together under 160% of 1600% CPU. Eight runs of the
concurrency sweep, three of everything else. Ranges below are the observed
spread across those runs, not error bars.

One caveat stated up front: **the guest→host figure is bounded by the
benchmark's own 8 KiB send window**, half the datapath's 16 KiB receive
buffer, chosen because this fake guest has no retransmit and an overrun
would wedge the flow rather than cost it a round trip. That number is a
floor, not the datapath's capacity.

### Throughput, one flow

| Direction | Median | Runs |
|---|---|---|
| host→guest | **7.1 Gb/s** | 7042, 7272, 7134 Mb/s |
| guest→host | **2.0 Gb/s** (floor, see caveat) | 2025, 2107, 1988 Mb/s |

### Aggregate throughput against flow count

Fixed 16 MiB **aggregate** budget at every point, so each does identical
total work and the only variable is how many flows carry it.

| Flows | Median Gb/s | Range | B/pass | ns/pass |
|---|---|---|---|---|
| 1 | 6.6 | 5.1–7.3 | 15,828 | ~19,500 |
| 2 | 10.3 | 8.8–11.4 | 31,536 | ~24,500 |
| 4 | 14.5 | 13.5–16.4 | 62,602 | ~35,700 |
| 8 | 19.0 | 18.1–19.8 | 123,362 | ~52,000 |
| 16 | 20.9 | 18.4–22.0 | 239,675 | ~91,000 |

Aggregate throughput **rises 3.2×** from one flow to sixteen and flattens
around eight. It does not flatten at one, which is what a serial pass being
the ceiling would have looked like.

### Latency

| Measurement | p50 | p99 |
|---|---|---|
| connect→established | 78–130 µs | 92–200 µs |
| guest→host→guest round trip | 68–73 µs | 87–102 µs |

### Where the time goes

| Measurement | ns |
|---|---|
| bare readiness drain, nothing registered | 12,377–13,013 |
| idle service pass, 0 flows | 12,968–13,549 |
| idle service pass, 1 flow | 12,814–13,141 |
| idle service pass, 4 flows | 14,037–14,314 |
| idle service pass, 16 flows | 16,518–16,623 |

Which fits `pass_ns ≈ 14.6 µs + 4.9 µs × flows`. The marginal 4.9 µs moves
15.8 KB, so the datapath's real per-byte capacity is **≈26 Gb/s on one
core** — and the 14.6 µs intercept is **almost entirely one syscall**, the
readiness drain, at ~12.8 µs. On a single-flow pass that intercept is 74% of
the pass. Per established-but-quiet flow a pass costs only ~230 ns.

So the flow count does not buy parallelism. It amortizes a fixed per-pass
tax over more bytes, which is why the curve rises and then flattens onto the
per-byte asymptote.

### Re-measured 2026-08-04, after the drain stopped asking twice

The drain used to end on a poll that reported nothing, and on macOS that is
the expensive shape. It now stops on a *short* return instead — see the
closed defect below — which removes one empty `kevent` from every pass whose
set had anything on it. Same host, same session, medians across runs.

| Measurement | Before | After | |
|---|---|---|---|
| guest→host, one flow | 1.9 Gb/s | **5.5 Gb/s** | **2.9×** |
| guest→host, ns/pass | 35,156 | **12,275** | |
| host→guest, one flow | 7.0 Gb/s | **7.8 Gb/s** | 1.12× |
| host→guest, ns/pass | 17,865 | **15,968** | |
| host→guest, 16 flows | 20.9 Gb/s | 21.2 Gb/s | |
| guest→host→guest round trip, p50 | 68 µs | **53 µs** | |
| idle pass, 1 flow | 12,951 ns | 12,313 ns | unchanged |

The idle figures are unchanged **by construction**, and that is the shape of
the whole result: a pass whose set is empty makes one poll before and one
after, and it is that *first* poll which costs the 12 µs. What the change
removes is the second one, so the gain lands wherever the set actually had
something on it. Counted directly, by instrumenting the drain and running
each direction: ~96% of guest→host drains find events, against ~37% of
host→guest ones. Hence 2.9× one way and 1.12× the other.

That also retires the projection below, which said removing the drain tax
would put a single flow near 18–19 Gb/s. Half the tax is gone and host→guest
moved 12%. The other half is the empty first poll, and it is **not**
removable by asking less often — see the deferred item.

### Decision: multi-queue is not warranted

1. **A single queue already scales.** 3.2× from 1 to 16 flows. The serial
   service pass is not preventing concurrent flows from getting throughput,
   which is the premise multi-queue rests on.
2. **What limits one flow is a syscall, not serialization.** Half that tax
   has since been removed and single-flow guest→host went 2.9×, host→guest
   12% — see the re-measurement above. The projection this line originally
   carried (18–19 Gb/s) was wrong, but its argument held: the ceiling on one
   flow was never the serial pass.
3. **Multi-queue would multiply the tax rather than remove it.** Each queue
   is its own drive loop paying its own ~12.8 µs zero-return wait per pass.
4. **The asymptote is ~26 Gb/s on one core**, against a guest reachable only
   over vsock. No workload is near this, and none has asked.

Reopening this needs a workload demonstrating a per-VM demand a single queue
cannot meet — not a flow count, a measured shortfall.

---

## Deferred (explicitly not in this plan)

- [ ] **`utun` + PF full-packet datapath**, and the privileged helper it needs. Separate ADR, separate decision, gated on explicit sign-off of the helper API. **Resolved as a rejection:** ADR-039 is Rejected — mvm adds no root-capable component — so this is closed, not queued, and reopening it needs a workload with a demonstrated need.
- [x] **UDP ingress** — shipped as WS2, below. **IPv6**, **multi-queue**, **zero-copy**, **node-to-node transport**, **`mvmd` node-control API**, **WSL2 validation** remain — tracked in the deferred set of `specs/plans/285-l3-tun-over-vsock.md`.

### Open defects in what this plan shipped

Not scope reductions — things that are wrong, recorded so the close-out is
not read as "finished". Three were listed at close-out; two of those closed,
two more were found while closing them, and those two are now closed as well.
One remains. ADR-037 §"Known defects in what shipped" carries the original
three with the mechanism.

- [x] **Register host sockets on the datapath's poll set.** Done. Every
      host socket the datapath opens — half-open connect, established flow,
      datagram association — is registered on the set behind `readiness_fd`,
      so the drive loop wakes on the event rather than on its 50 ms tick.
      The registration lives with the socket (`readiness::Watched` owns both
      and drops them in that order), so it cannot go stale at any of the
      places a socket is dropped out of a table. Witnessed by
      `a_resolved_connect_reports_on_the_readiness_descriptor`, which asserts
      on readiness rather than on elapsed time, and by
      `a_dropped_registration_stops_reporting`, which drops the registration
      while the descriptor stays open — the only arrangement in which
      "it stopped reporting" means deregistration.
- [x] **`traffic_does_not_push_out_an_associations_deadline` aims at a dead
      port.** Done. The fixture opened an association toward `127.0.0.1:443`
      with nothing listening, so the first datagram drew an ICMP port
      unreachable and the connected socket reported `ECONNREFUSED` on the
      second `send` — which the table treats as terminal, correctly, and
      the fixture's `expect` panicked. It failed deterministically on Linux
      and intermittently on macOS (about one full-suite run in ten), which
      is why it read as a flake there. Fixed by giving it a destination that
      exists and discards (`bind_udp_sink`), never by tolerating the refusal:
      a refusal is a real signal this path is meant to surface, and no
      production error handling was touched. The subject is unchanged — the
      deadline is still taken once from the datagram that opened the
      association, and only the destination moved.
      `a_bound_destination_absorbs_a_second_datagram_rather_than_refusing_it`
      now pins the fixture property itself, waiting out the ICMP round trip
      so it is deterministic rather than a race; aimed back at a closed port
      it fails with `ConnectionRefused` on macOS (`code: 61`) as it did on
      Linux (`code: 111`). Pre-existing; found while closing the two defects
      above.
- [x] **Report a datapath backlog the way both drains now do.** Done. A
      flow's host-to-guest pump is bounded per pass (`max_bytes_per_pass`),
      and the service pass consumes the readiness edge before pumping —
      which is the right order, since an edge cleared afterwards is one for
      bytes nothing would go back for. The consequence was that a peer which
      sent more than one pass's budget and then went quiet left its tail
      waiting for the 50 ms tick rather than for an edge. `host_to_guest` now
      raises `PumpStats::backlogged` when the bound rather than the peer
      ended the pass, `pump_flows` folds every flow's report into one
      `InboundDrain` for the machine, `DatapathHandle::service` returns it,
      and `drive`'s existing `Backlog` carries it as a third flag — the
      mechanism the two drains already use, extended, not a second one.
      `InboundDrain` moved from `gateway` to `datapath` so the trait can name
      it; its public path is unchanged. A stall is deliberately *not* a
      backlog: what frees the stack's send buffer is the guest's ACK, and
      that arrives on the guest channel, which wakes the loop by itself.
      Witnessed at four levels, each mutation-proven:
      `a_pump_stopped_by_its_budget_says_so_and_the_tail_still_arrives` (red
      when the report is gutted),
      `a_flow_that_stopped_at_its_budget_makes_the_service_pass_say_so` (red
      when either the report or the fold is gutted),
      `a_backlogged_service_pass_reaches_the_caller_that_decides_to_wait`
      (red when the gateway swallows it), and
      `every_bounded_step_can_hold_the_pass_off_the_wait` (red when the flag
      is dropped from `Backlog::any`). Every one asserts on backlog state,
      none on elapsed time. Found while closing the two defects above.
- [x] **Serve declared ingress, or stop advertising it.** Served, for
      datagrams, as WS2 — and the half that is still not served is stated
      rather than rounded off. `DatapathRequest` now carries the
      declarations, `Gateway::open` copies them out of the same table
      admission will check against, and `DatagramIngress` binds one host
      listener per declared UDP mapping on **exactly** the address it
      named. Binding is not admitting: a synthesized packet leaves through
      the handle's read path and goes back through `admit_inbound`, so
      withdrawing a declaration stops delivery while the socket is still
      bound — witnessed by
      `an_inbound_datagram_reaches_the_guest_only_while_its_mapping_is_declared`,
      which delivers first and refuses second so neither half is vacuous.
      The guest port comes from the declaration and never from the
      datagram's own destination port, and a guest answer leaves a listener
      only toward a peer that has already written to that mapping —
      otherwise the unconnected listener socket would be an egress route
      around the admitted-destination check. The config requirement did not
      have to move, because the flag became true rather than false.
      **Still open: TCP.** A declared stream mapping is admitted and binds
      nothing on this backend; serving one needs a listener whose accepted
      connections are originated toward the guest. It is skipped at open
      rather than refused, opens no socket, and is recorded in ADR-037
      §"Known defects in what shipped" as the remaining over-claim.
- [x] **Give `Gateway::poll_inbound` a per-pass budget.** Done, mirroring
      the guest-facing drain rather than inventing a second mechanism:
      bounded by `MAX_INBOUND_PACKETS_PER_PASS`, reporting
      `InboundDrain::Backlogged` so the loop resumes instead of waiting on a
      spent readiness edge. Witnessed at the unit level by
      `the_inbound_drain_stops_at_its_budget_and_says_so` and at the loop
      level by `the_loop_alternates_rather_than_draining_one_side_to_exhaustion`,
      which records both sides' turns in one log and asserts no run of
      inbound turns exceeds the budget.

- [x] **Every service pass pays one ~12.8 us zero-return `kevent` on macOS.**
      Fixed, in the half that is sound. Found by WS4's measurement:
      `ReadinessSet::drain_for` only stopped when a poll returned zero
      events, so the drain's *last* call was always a zero-return one -- and
      on this platform that is the pathological case. Measured in pure C,
      with no Rust and none of this code in the picture: a zero-timeout
      `kevent` that returns an event costs 171-430 ns, one that returns
      nothing costs ~12,600 ns, and a trivial syscall (`close(-1)`) costs
      70 ns. So the cost is not the syscall, it is specifically the empty
      return.

      The drain now stops on a **short** return -- fewer events than the
      buffer offered room for. Both kqueue and epoll copy out ready events
      until the ready list runs out or the caller's buffer does, so a short
      return already *is* the "nothing left" report and the terminating call
      could only repeat it. It drops no edge, and strictly improves the
      set-left-dirty hazard: a short return means the set is empty, where
      before the loop could bail on its pass bound with events still on it.
      Witnessed by `a_drain_that_empties_the_set_stops_without_a_further_poll`,
      which asserts on **poll count** rather than elapsed time -- a latency
      fix witnessed by a stopwatch is a flake -- and paired with
      `a_drain_keeps_going_while_each_poll_fills_the_buffer` so the stop
      cannot be over-narrowed into "stop after the first poll". Both
      mutation-proven: restoring `if n == 0` reddens the first, an
      unconditional `break` reddens the second. Measured effect in the
      re-measurement above: **2.9x guest→host, 1.12x host→guest**.

      **Linux: measured, and there is no pathology there.** On 6.8.0
      x86_64, an `epoll_wait` returning zero events costs ~480 ns against
      ~610 ns for one returning an event -- the two shapes cost the same, so
      the fix saves one cheap syscall rather than one expensive one. Harmless
      either way; the gain is macOS-only.

- [ ] **The empty *first* poll of a drain still costs ~12 µs on macOS, and
      the obvious fix is unsound.** What is left after the fix above. A pass
      whose readiness set is empty still asks the kernel once, and on macOS
      that question costs ~12 µs however it is phrased. Roughly 63% of
      host→guest passes are in this state, which is why that direction moved
      only 12%.

      The tempting fix -- let the drive loop skip the drain on a pass it was
      not woken by readiness for -- **must not be taken as stated**. Measured
      with a nested-kqueue probe: an outer kqueue watching an inner one is
      edge-triggered on the inner set's transition into *non-empty*, and a
      set that is already non-empty never transitions again. Not even a
      further event on it re-reports. So the unconditional drain is not only
      how the edge is spent, it is the only thing that **repairs** a
      readiness descriptor left dirty by anything -- a poll error, the
      `DRAIN_PASSES` bound. Make the drain conditional on having been woken
      by readiness and a dirty set is stranded permanently: the drive loop
      stops waking on readiness for the rest of that machine's life and
      silently degrades to its 50 ms tick. Any future attempt needs a
      guaranteed repair pass and a witness for it, and it is worth ~12 µs on
      backlog-re-entry and tick passes only.

      A cheaper *emptiness check* was measured and rejected too: `poll(2)` on
      the kqueue descriptor costs ~6,600 ns when the set is empty. Half the
      price, still two orders of magnitude off the non-empty case, and it
      adds ~360 ns to every busy pass.

      The other lead this exposed is more promising and unexplored: those
      63% are passes where the flow socket still held data but had raised no
      new edge -- backlog re-entries under `max_bytes_per_pass`. Raising that
      budget would cut the number of passes rather than the cost of one.
- [x] **`l3_linux_privileged.rs` did not compile for Linux.** Fixed here. The
      IPv6 work gave `DatapathRequest` its `gateway_v6`/`guest_v6` fields and
      did not update this file, which is `#![cfg(target_os = "linux")]` and
      therefore never built by anything a macOS contributor runs. The gap is
      the gate, not the omission: `just check-linux` is `--lib`, so no
      routine command compiles Linux-gated *test* files. Catching the next
      one needs `cargo zigbuild --target x86_64-unknown-linux-gnu -p mvm-hostd
      --all-targets` in the lane.

> **Numbering note.** `285` is used twice on main — `285-l3-tun-over-vsock.md`
> and `285-hvf-virtio-rng.md` — and so is `284`. Always reference these by
> filename, never by bare number. `286` is claimed by an in-flight worktree,
> which is why this plan is `287`.
- [ ] **ICMP** — needs full packet forwarding; unavailable by construction here, and on macOS unavailable for good, since the helper that would carry it was rejected.
