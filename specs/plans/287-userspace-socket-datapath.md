# Plan 287 — Userspace socket datapath

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

- [ ] **Step 1: Add smoltcp**

```sh
cargo add smoltcp -p mvm-hostd --no-default-features \
  --features medium-ip,proto-ipv4,socket-tcp,socket-udp
```

Then review `deny.toml` for the new licence and any duplicate-major it introduces, and run `cargo run -p xtask -- check-duplicate-majors`. Both gates, not either.

- [ ] **Step 2: Write the failing test**

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
        // 135_698_432, because the ceiling has to count the per-flow
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

- [ ] **Step 3: Run it and confirm it fails**

Run: `cargo nextest run -p mvm-hostd the_per_machine_memory_ceiling`
Expected: FAIL — module does not exist.

- [ ] **Step 4: Write the constants**

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
pub const FLOW_QUEUE_DEPTH: usize = /* window.div_ceil(DEFAULT_SEGMENT_PAYLOAD) + POLLS_PER_PASS */;  // 33

pub const FLOW_BUFFER_BYTES: usize =
    SOCKET_RX_BUFFER + SOCKET_TX_BUFFER + 2 * FLOW_QUEUE_DEPTH * MTU_V1 as usize;                     // 131_768

pub const MEMORY_CEILING_BYTES: usize =
    DEFAULT_MAX_HOST_SOCKETS * FLOW_BUFFER_BYTES + 2 * DEFAULT_QUEUE_DEPTH * MTU_V1 as usize;         // 135_698_432
```

The depth went 256 (inherited machine-wide default) → 12 (a byte budget at full-size segments) → 33. Twelve was too small in two ways at once: a segment need not be full-size — a guest whose SYN carries no MSS option gets smoltcp's 536 byte default, turning a 16 KiB window into 31 segments — and a pass emits an ACK per poll beside its data. A depth below what one pass emits overflows on ordinary full-throughput traffic, and that overflow costs the guest a retransmission timeout, so the guest-bound queue now counts what it discards (`GuestDevice::dropped_to_guest`) instead of dropping silently. A hostile MSS can still outrun any depth; that becomes a visible number rather than a stall nobody can explain.

`MTU_V1` in the formula is the configured MTU too, because `accept_mtu` refuses anything above it at both entry points (`open_handle` and `EstablishedFlow::from_half_open`). Failing closed rather than computing from the configured value keeps the ceiling a compile-time constant: `MTU_V1` is fixed and not negotiated by design, and a ceiling a configuration can raise is not a ceiling.

- [ ] **Step 5: Run tests and confirm they pass**

Run: `cargo nextest run -p mvm-hostd -E 'test(memory_ceiling) or test(half_open_is_far)'`
Expected: PASS.

- [ ] **Step 6: Commit**

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

- [ ] **Step 1: Write the failing test**

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

- [ ] **Step 2: Run and confirm failure**

Run: `cargo nextest run -p mvm-hostd a_packet_pushed_from_the_guest`
Expected: FAIL — `GuestDevice` not defined.

- [ ] **Step 3: Implement the device**

Implement `smoltcp::phy::Device` where `receive()` pops from the guest-to-stack queue and `transmit()` pushes onto the stack-to-guest queue. Both queues are bounded by the depth passed to `new`; `push_from_guest` drops on a full queue and reports it so the caller can count it.

- [ ] **Step 4: Run tests and confirm they pass**

Run: `cargo nextest run -p mvm-hostd -E 'test(guest_device) or test(pushed_from_the_guest) or test(without_bound)'`
Expected: PASS.

- [ ] **Step 5: Commit**

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

- [ ] **Step 1: Write the failing test**

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

- [ ] **Step 2: Run and confirm failure**

Run: `cargo nextest run -p mvm-hostd the_socket_budget_respects`
Expected: FAIL — not defined.

- [ ] **Step 3: Implement**

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

- [ ] **Step 4: Run tests and confirm they pass**

Run: `cargo nextest run -p mvm-hostd -E 'test(socket_budget) or test(socket_translation_capabilities)'`
Expected: PASS.

- [ ] **Step 5: Commit**

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

- [ ] **Step 1: Write the failing tests**

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

- [ ] **Step 2: Run and confirm failure**

Run: `cargo nextest run -p mvm-hostd a_syn_does_not_reach_the_stack`
Expected: FAIL — `HalfOpenTable` not defined.

- [ ] **Step 3: Implement**

`on_syn` keys on the guest 4-tuple. An existing entry returns `Folded` without opening a second socket. A full table returns `Refused`, dropping the SYN rather than evicting a live entry. Otherwise it opens a non-blocking `TcpStream` toward the destination, stores the SYN bytes, and returns `Started`. `replayable()` yields only entries whose connect has completed successfully.

- [ ] **Step 4: Run tests and confirm they pass**

Run: `cargo nextest run -p mvm-hostd -E 'test(syn)'`
Expected: PASS.

- [ ] **Step 5: Commit**

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

Round 2 (`fix(netd): size the guest queue for what a pass emits, and stop dropping silently`): the round-1 depth of 12 was below what one pass emits, the guest-bound overflow was silent, and the ceiling read `MTU_V1` where the configured MTU was unvalidated. Depth is now 33, overflow is counted, and `accept_mtu` fails closed above `MTU_V1` at both entry points. The oversize check moved into `GuestDevice::push_from_guest`, so `EstablishedFlow::deliver_from_guest` is covered by the same guard as the handle's `send_to_network` rather than being a second unguarded way in. `a_flows_fixed_overhead_stays_small_beside_its_buffers` became `a_flows_inline_size_stays_pinned`, whose doc states what a `size_of` pin cannot see: everything behind `SocketSet`'s `Vec` is one pointer here, so a new heap-allocating field must be added to `FLOW_BUFFER_BYTES` by hand.

Worth recording about the device term's witnesses: `a_guest_that_floods_the_device_queue_stays_inside_the_flow_bound` is the only runtime test that reddens if `bytes_buffered()` stops counting the device queues. The two backpressure tests assert `bytes_buffered() <= FLOW_BUFFER_BYTES`, an upper bound that a smaller measure satisfies trivially. The constant-level term is separately pinned by `the_per_machine_memory_ceiling_is_what_we_claim`.

- [x] **Step 5: Commit**

```sh
git add crates/mvm-hostd/src/netd/userspace/ crates/mvm-hostd/Cargo.toml Cargo.lock xtask/src/check_duplicate_majors.rs
git commit -m "feat(netd): pump established flows with backpressure and half-close"
```

---

### Task 12: Host errors reach the guest; close is deterministic

**Files:**
- Modify: `crates/mvm-hostd/src/netd/userspace/tcp.rs`, `crates/mvm-hostd/src/netd/userspace/mod.rs`

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn a_host_side_reset_reaches_the_guest_as_a_reset() {
    let mut flow = established_flow();
    flow.on_host_error(std::io::ErrorKind::ConnectionReset);
    let out = flow.take_guest_packets();
    assert!(out.iter().any(|p| tcp_flags(p).contains_rst()),
        "the guest's stack must learn, rather than hang to its own timeout");
}

#[test]
fn close_shuts_every_host_socket_and_is_idempotent() {
    let mut handle = handle_with_open_flows(8);
    handle.close().expect("close");
    assert_eq!(handle.open_socket_count(), 0);
    handle.close().expect("close must be safe to call twice");
}
```

- [ ] **Step 2: Run and confirm failure**

Run: `cargo nextest run -p mvm-hostd a_host_side_reset_reaches`
Expected: FAIL.

- [ ] **Step 3: Implement**

Map `ConnectionReset` / `HostUnreachable` / `ConnectionAborted` on an established flow to a synthesized RST toward the guest. `close()` drains every table, closing each descriptor, and is safe on both the normal and failed-startup paths.

- [ ] **Step 4: Run tests and confirm they pass**

Run: `cargo nextest run -p mvm-hostd -E 'test(host_side_reset) or test(close_shuts_every)'`
Expected: PASS.

- [ ] **Step 5: Commit**

```sh
git add crates/mvm-hostd/src/netd/userspace/
git commit -m "feat(netd): surface host socket errors to the guest and close deterministically"
```

---

### Task 13: UDP associations

**Files:**
- Create: `crates/mvm-hostd/src/netd/userspace/udp.rs`

**Interfaces:**
- Produces: `struct UdpAssociations`; `UdpAssociations::send(&mut self, key: FlowKey, payload: &[u8], now_millis: u64) -> Result<(), DatapathError>`; `UdpAssociations::poll(&mut self, now_millis: u64) -> Vec<Vec<u8>>`; `UdpAssociations::expire(&mut self, now_millis: u64) -> usize`.

- [ ] **Step 1: Write the failing tests**

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

- [ ] **Step 2: Run and confirm failure**

Run: `cargo nextest run -p mvm-hostd a_datagram_round_trips`
Expected: FAIL.

- [ ] **Step 3: Implement**

One host `UdpSocket` per association keyed on the guest 4-tuple. Replies are synthesized back as IP+UDP toward the guest. DNS never reaches here — it terminates above the seam.

- [ ] **Step 4: Run tests and confirm they pass**

Run: `cargo nextest run -p mvm-hostd -E 'test(datagram) or test(association)'`
Expected: PASS.

- [ ] **Step 5: Commit**

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

- [ ] **Step 1: Write the failing tests**

```rust
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
    let reason = fallback_reason_for_test(TunProbe::Unavailable);
    assert!(reason.contains("CAP_NET_ADMIN"));
    assert!(reason.contains("userspace socket translation"));
}
```

- [ ] **Step 2: Run and confirm failure**

Run: `cargo nextest run -p mvm-hostd macos_selects_the_userspace`
Expected: FAIL — still returns the refusing gateway.

- [ ] **Step 3: Implement**

`host_datapath()` returns `LinuxDatapath` on Linux when its TUN probe succeeds, and `UserspaceSocketDatapath` otherwise — on every platform. Delete `MacosUserspaceGateway`: it was a placeholder whose entire behaviour was a refusal, and per this repo's no-back-compat posture it is removed rather than left as a shim. Carry the fallback reason into the diagnostic.

- [ ] **Step 4: Run tests and confirm they pass**

Run: `cargo nextest run -p mvm-hostd && just check-linux`
Expected: PASS on both.

- [ ] **Step 5: Commit**

```sh
git add crates/mvm-hostd/src/netd/
git commit -m "feat(netd): select the userspace datapath, with an honest fallback reason"
```

---

### Task 15: The unprivileged end-to-end suite

**Files:**
- Create: `crates/mvm-hostd/tests/userspace_datapath.rs`

- [ ] **Step 1: Write the tests**

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

- [ ] **Step 2: Run them**

Run: `cargo nextest run -p mvm-hostd --test userspace_datapath`
Expected: **PASS.** Tasks 6–14 all precede this one, so the datapath already exists — this task is the end-to-end suite over finished parts, not a red-green cycle. If any test here fails, the bug is in Tasks 6–14 and belongs in that task's fix loop, not patched here.

- [ ] **Step 3: Commit**

```sh
git add crates/mvm-hostd/tests/userspace_datapath.rs
git commit -m "test(netd): cover the userspace datapath end to end, unprivileged"
```

---

### Task 16: Documentation and ledger close-out

**Files:**
- Modify: `public/src/content/docs/guides/l3-vsock-networking.md`, `specs/plans/285-l3-tun-over-vsock.md`, `specs/plans/287-userspace-socket-datapath.md`, `specs/REFACTOR-STATUS.md`, `specs/SPRINT.md`

- [ ] **Step 1: Update the platform matrix**

The guide and ADR-036 both state macOS is unsupported. Correct both to describe what now ships, including that ICMP, raw IP protocols, and arbitrary IPv4 remain unavailable and are refused at admission.

- [ ] **Step 2: Tick plan 285's deferred item**

Mark "macOS userspace socket gateway" done in plan 285, pointing at this plan.

- [ ] **Step 3: Run the full gate list**

Every command in the Gate list section. `xtask check-doc-claims` is the one most likely to object to new prose — it gates claim phrasing.

- [ ] **Step 4: Commit**

```sh
git add specs/ public/
git commit -m "docs(plan-287): record the userspace socket datapath as shipped"
```

---

## Deferred (explicitly not in this plan)

- [ ] **`utun` + PF full-packet datapath**, and the privileged helper it needs. Separate ADR, separate decision, gated on explicit sign-off of the helper API.
- [ ] **UDP ingress**, **IPv6**, **multi-queue**, **zero-copy**, **node-to-node transport**, **`mvmd` node-control API**, **WSL2 validation** — tracked in the deferred set of `specs/plans/285-l3-tun-over-vsock.md`.

> **Numbering note.** `285` is used twice on main — `285-l3-tun-over-vsock.md`
> and `285-hvf-virtio-rng.md` — and so is `284`. Always reference these by
> filename, never by bare number. `286` is claimed by an in-flight worktree,
> which is why this plan is `287`.
- [ ] **ICMP** — needs full packet forwarding; unavailable by construction here.
