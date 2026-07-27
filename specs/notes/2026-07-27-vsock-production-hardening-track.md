# vsock production-hardening track

**Date:** 2026-07-27
**Scope:** transport/socket layer of the vsock stack. No wire-format, crypto,
policy, egress, or audit change. Four independent workstreams; each lands as its
own reviewable PR.

## Transport decision (recorded)

vsock stays. It is not merely acceptable — it is the load-bearing security
primitive, and the apparent alternatives are not real alternatives:

- **vsock *is* virtio.** The in-house VMM already implements it as a virtio
  device (`vmm/vsock.rs`, `vsock_handlers/`, `vsock_io.rs`) beside `virtio_fs.rs`.
  There is no "move to virtio" — we are on virtio.
- **virtio-net (guest NIC): forbidden.** `xtask check-vsock-only-egress` fails
  closed if any converged workload path grows a virtio-net device, tap, or
  userspace gateway. A guest NIC destroys the vsock-only auditable data plane
  (host mediation, egress-substitution, audit). Hard no.
- **smol: category error.** An async runtime, not a transport. A second runtime
  beside tokio regresses the runtime-free sealed-agent posture.
- **smoltcp: already deleted.** The userspace L3 stack that undercut vsock-only is
  gone; no Cargo/code refs remain. Do not resurrect it.

The only legitimate "more than vsock" is at the **device** layer, not the
channel: hardening the hand-rolled virtio-vsock device with audited rust-vmm
primitives (WS4). The multi-backend reality (Firecracker UDS, libkrun per-port
UDS, future Windows hvsocket) is "vsock semantics, different host plumbing"
behind the existing `VsockTransport` trait — not a second transport.

## Guest AF_VSOCK call sites (audited)

Four hand-rolled sites, three sync + one async. Each carries its own copy of the
`sockaddr_vm` layout / `AF_VSOCK` constants:

- `vsock/connection.rs::connect_host_vsock` — sync client dial, CID 2, retries;
  private `SockaddrVm`. → WS1
- `bin/mvm-exit-report.rs` — sync client dial, CID 2; `libc::sockaddr_vm`, wraps
  as `TcpStream`; dup `HOST_CID`. → WS1
- `bin/mvm-builder-agent.rs` — sync **server** bind/listen/accept, CID_ANY; own
  `extern "C"` socket/bind/listen/accept + private `SockAddrVm`. → WS1
- `guest_vsock_session.rs::connect_host_vsock_blocking` — **async** dial:
  `spawn_blocking(raw libc sockaddr_vm)` → `std::net::TcpStream` → tokio
  `TcpStream`. Already tokio, already `addons`-gated. → WS2

Separately, `connection.rs` performs the Firecracker UDS handshake and admits the
response with `starts_with("OK ")` — a permissive prefix check. → WS3

(`mvm-egress-client` delegates to `guest_vsock_session` — not a fifth site.)

## Workstreams

### WS1 — nix sync consolidation  *(hygiene; low risk)*

- [ ] `nix = { version = "0.29", features = ["socket"] }` in mvm-agentd's
      `[target.'cfg(target_os = "linux")'.dependencies]`. Reuse the **already
      vendored** 0.29 node — no bump, no new supply-chain entry, no closure delta.
- [ ] New leaf `src/vsock/sys.rs` (`cfg(target_os="linux")`, nix + std only, no
      serde/framing pull-in): `dial_host(port)`, `bind_listen(cid, port, backlog)`,
      `accept(fd)`, returning `OwnedFd` (RAII drops the manual `close`/`unsafe`).
- [ ] Rewire the three sync sites onto it; keep each caller's existing stream type
      via `from_raw_fd`, so the RPC/framing layer is untouched. Keep connection.rs's
      retry loop and `HOST_CID` as the single CID source.
- [ ] Unit tests: `VsockAddr` field mapping; dead-port dial surfaces the connect
      error unchanged.

### WS2 — tokio-vsock async dial  *(anti-pattern removal; low-med risk)*

- [ ] `tokio-vsock` as an `addons`-feature + `cfg(target_os="linux")` dep — never
      in the default/sealed closure.
- [ ] Replace `connect_host_vsock_blocking` + its `spawn_blocking`/fake-TcpStream
      with a native `VsockStream::connect(VsockAddr::new(HOST_CID, port))`. The
      session's `AsyncRead + AsyncWrite` generic seam and `copy_bidirectional`
      relay stay; `HostVsockSession<TcpStream>` becomes `HostVsockSession<VsockStream>`.
- [ ] Keep typed errors distinguishing unsupported-platform / refused / timeout /
      reset. Bounded retry only around connection establishment.
- [ ] Gate proof: `check-guest-agent-runtime-free` stays green (tokio-vsock is
      addons-gated, absent from the default no-dev closure).

### WS3 — strict Firecracker `OK <port>` parser  *(correctness; low risk, high ROI)*

- [ ] Replace `starts_with("OK ")` with a strict parser for the exact
      `OK <decimal>\n` grammar, extracted into a pure, unit-testable function.
      Verify against Firecracker's documented hybrid-vsock semantics whether the
      returned port must equal the requested port **before** enforcing equality —
      do not impose an equality rule the protocol does not guarantee.
- [ ] Reject: missing newline, empty/negative/overflowing/non-decimal port, extra
      token, embedded NUL/control chars, overlong line (keep `MAX_CONNECT_RESPONSE_LEN`),
      partial read, EOF-before-complete. Retry only transient connect failures;
      never replay after application bytes.
- [ ] Test table covering every row above (valid split across reads, one byte at a
      time, and each malformed case).

### WS4 — virtio-vsock device hardening  *(AUDIT ONLY this round; highest value/risk)*

Do **not** write device code or add rust-vmm deps yet. Audit the hand-rolled
device, then author a staged ADR-backed plan from the findings.

Target files: `vmm/vsock.rs`, `vmm/vsock_handlers/`, `vmm/vsock_io.rs`,
`vmm/vsock_transport.rs`, `vmm/virtio.rs`, `vmm/guest_mem.rs`.

Audit checklist (untrusted guest bytes → host memory):
- [ ] descriptor-chain loops / invalid `next` indices; queue index wraparound
- [ ] checked guest-memory bounds; header-len / payload-len validation
- [ ] integer overflow/truncation; unbounded alloc from guest-provided sizes
- [ ] credit-accounting correctness; half-close / reset / shutdown / reconnect
- [ ] panic paths reachable from guest bytes; O(n) hot-path ops
- [ ] snapshot/restore state; vCPU↔host-IO concurrency; IRQ delivery/wakeup races

Decision recorded for the follow-up plan: adopt audited rust-vmm primitives
(`virtio-queue` descriptor iteration, `vm-memory` checked access, `virtio-vsock`
typed packet/header parsing) **only** behavior-preserving, in bounded reviewable
slices, ADR-gated (supply-chain + closure-budget event), with no HVF
startup-latency / IRQ / snapshot / cross-platform regression. `arcbox-virtio-vsock`
is a reference/oracle, not a dependency, until audited. Extend existing fuzz
targets for malformed descriptors/headers/credit as the slices land.

## Sequencing

WS3 and the WS4 **audit** first (cheapest; the audit is where a live vuln would
be — a real finding reprioritizes everything). WS1 → WS2 trail as hygiene (WS1
first; WS2's tokio-vsock likely deletes the async dial so it won't need WS1's
leaf). WS3 is independent and may land in parallel.

## Shared security invariants (must hold across every WS)

Host-CID authorization before any frame is read; frame-length cap checked before
body alloc; no raw/legacy JSON path bypassing the authenticated session; port
allowlists explicit and fail-closed; no guest NIC / tap / SSH / unmediated egress;
sealed-production compile/profile gates intact; ephemeral key agreement, host-key
pinning, sequence/replay, nonce derivation, zeroization untouched; no logging of
secrets or plaintext payloads; timeouts/disconnects fail closed with no ambiguous
double-execution.

## Shared gates (before every push)

`cargo xtask check-guest-agent-runtime-free`, `check-closure-budget` (expect 266),
`check-vsock-only-egress`, `check-uniform-vsock-egress`; `just check-linux`
(zigbuild — touched guest code is Linux-only, the mac host can't build it
natively); `rustup run nightly cargo fmt --all`; `cargo clippy --workspace -D
warnings`; `cargo nextest run --workspace`; `cargo test --workspace --doc`. WS1/WS3
make no wire change (fuzz corpus untouched); WS4 extends fuzz.

## Non-goals

No host-side transport change; no Windows work (future `VsockTransport` impl —
hvsocket/named pipe); no wire/crypto/policy/egress/audit change; no rust-vmm code
or dep this round (WS4 is audit-only).
