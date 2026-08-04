# Plan 292 — The node-control API, and what is left of the L3 epic

**Status: In progress**
**ADRs: [041](../adrs/041-node-control-api.md) (this surface),
[040](../adrs/040-node-to-node-transport.md) (the transport it half-unblocks)**
**Issues: #2120 (this), #2111 (epic), #2153 (handoff)**

Read ADR-041 first. This plan is the sequencing, the state of what landed,
and — deliberately — the list of things a fresh session would otherwise
have to rediscover.

## Why this plan exists separately from plan 287

Plan 287 (the userspace socket datapath) is complete: all sixteen tasks,
plus five defects found and fixed after them. What remains of epic #2111
is not datapath work. It is a control surface, a transport that cannot be
built yet, a guest-kernel measurement, and an audit gap — four unrelated
things that happened to be filed under one epic because they were all
deferred by plan 285.

Keeping them in plan 287 would have made a finished document look
unfinished. They live here instead.

## WS8 — the node-control API (#2120)

### The question it had to answer first

ADR-040 established that cross-node traffic needs an issuer both nodes
trust, and named this workstream as where that might come from. The
answer, recorded in ADR-041: **the issuer is a fleet concept and belongs
to the control plane; the node's job is to verify what the issuer says.**

That means this workstream **half-unblocks** #2119 rather than unblocking
it. The verification seam is here; the issuer is not, and must not be
invented here — a key scoped to a node pair is still a second trust root,
just one with a smaller blast radius.

### What landed

- [x] `crates/mvm-hostd/src/nodectl/` — `wire`, `service`, `registry`,
      `server`, `caller`, `limits` (~1,310 lines)
- [x] Ownership is a uid comparison and nothing else. `CallerIdentity`
      comes from the connection's peer credential, never from a field in
      the message — a self-asserted identity is not an identity
- [x] A caller asking about a machine it does not own is refused; a
      listing carries only the caller's own machines
- [x] `#[serde(deny_unknown_fields)]` on the wire types, so an
      unexpected field fails closed
- [x] Bounded tables, dropping rather than evicting
- [x] No listener bound inside `nodectl` — the server takes an
      already-accepted stream, which is also why it does not trip the
      no-orchestration-server architecture gate

### Verified

- 2206 tests pass across `mvm-hostd`/`mvm-net`/`mvm-protocol` (up from
  2180; this workstream added 26)
- **Mutation-proved.** `CallerIdentity::owns` forced to `true` turns
  **five** tests red, including
  `a_caller_is_refused_a_machine_it_does_not_own`,
  `a_listing_carries_only_the_callers_own_machines`, and
  `a_request_over_a_socket_is_scoped_to_the_connections_own_credential`.
  Restored, all green. The ownership check is witnessed, not decorative

### Not built here, on purpose

- [ ] The cross-node issuer. Control-plane responsibility; see ADR-041
- [ ] Anything mvmd-side: tenants, pools, scheduling, admission

## The other three open items

These are independent of each other. None blocks the datapath work that
already shipped.

### Guest-side IPv6 (#2147, parent #2116)

- [ ] Measure the `CONFIG_IPV6` guest-kernel delta — image size and boot
      time — building both ways
- [ ] Then decide: land it unconditionally as a known accepted cost, or
      make IPv6 a guest-image variant if the delta is material

The host side shipped: admission, the address-class rules, and flow
translation, with all four embedded-v4 forms collapsed before the v4
rules judge them. **No guest can originate v6 until this lands.** That is
a gap in reach, not in safety — every refusal is enforced regardless.

ADR-038 requires this be measured rather than assumed, because guest
kernels are being cut to the virtual hardware floor in parallel and
enabling the option blind would quietly reverse part of that.

### The gateway emits no audit entries (#2151)

- [ ] Emit chain-signed entries for the gateway decisions ADR-036 §Audit
      already enumerates — the `LocalAuditKind` variants exist

There is no `AuditEmitter` anywhere under `crates/mvm-hostd/src/netd/`.
`log_event` turns five of twelve `GatewayEvent` variants into stderr and
drops the rest into counters. So the seam where default-deny is enforced
for `l3-vsock` writes nothing to the tamper-evident record.

Worth fixing on the local path regardless of cross-node work, and ADR-040
lists it as one of four blockers on #2119.

### WSL2 validation (#2121)

- [ ] Run it on a live host; no live Windows/WSL2 host exists yet

The test plan is pre-specified in the issue so this is a short session
rather than a fresh investigation. What is already established without a
host: the datapath carries no `target_os` gating at all, WSL2 is Linux,
and that Linux path is built by `zigbuild --all-targets` and has been run
on a real Linux/KVM host. What cannot be established: whether WSL2's TUN
probe fails there, vsock behaviour under its hypervisor, and end-to-end
traffic.

## Traps a fresh session will otherwise hit

Each of these cost time on this branch.

- **`just check-linux` is `--lib` only.** It compiles neither bins nor
  Linux-gated test files. A `#![cfg(target_os = "linux")]` test file sat
  broken for days because of this. Use
  `RUSTC=$HOME/.cargo/bin/rustc cargo zigbuild --target
  x86_64-unknown-linux-gnu -p mvm-hostd --all-targets`.
- **Homebrew's `rustc` shadows rustup's** on `PATH` and produces a
  misleading `can't find crate for core`. Pin `RUSTC=$HOME/.cargo/bin/rustc`.
  Use `~/.cargo/bin/cargo`, never Homebrew's.
- **Never run two cargo commands at once.** `crates/mvm-cli/build.rs`
  spawns `cargo zigbuild`, which blocks on the same target-directory lock
  an outer cargo holds. Both processes then sit at 0% CPU looking like a
  slow build; it is a deadlock and it cost an hour.
- **`check-no-spec-refs` is not a gate name.** It is
  `check-no-spec-refs-in-comments`; xtask rejects the short form as
  `Unknown xtask`, so a run of it silently checks nothing.
- **The closure budget now has zero headroom** (279 of 279). The next
  dependency into mvmctl's default binary trips it. That is intended.
- **A known flake, not a regression:** `host_agent_restart` (×4),
  `per_tenant_isolation`, and `broker_audit_round_trip` fail under
  full-suite parallel load and pass isolated at `-j 2`. They spawn
  daemons that must bind within 10s.
- **This Mac intermittently wedges its loader** — `syspolicyd` spins and
  every freshly built binary hangs at `_dyld_start`, so builds look fine
  and test children never start. Diagnose with a trivial C binary before
  blaming the code.

## Gate list

```sh
cargo nextest run -p mvm-hostd -p mvm-net -p mvm-protocol   # 2206 expected
cargo clippy -p mvm-hostd --all-targets -- -D warnings
RUSTC=$HOME/.cargo/bin/rustc cargo zigbuild \
  --target x86_64-unknown-linux-gnu -p mvm-hostd --all-targets
cargo +nightly fmt --all -- --check                         # CI Lint uses nightly
cargo run -q -p xtask check-vsock-only-egress
cargo run -q -p xtask check-uniform-vsock-egress
cargo run -q -p xtask check-claim-catalog
cargo run -q -p xtask check-no-spec-refs-in-comments
cargo run -q -p xtask check-doc-claims
cargo run -q -p xtask check-no-overclaim
cargo run -q -p xtask check-adr-coverage
cargo run -q -p xtask check-closure-budget
```
