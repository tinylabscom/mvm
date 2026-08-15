# 2519 — the blocking vsock leg of the raw-egress tunnel bound gets a witness

## What was missing

The per-workload cap on simultaneous raw TCP tunnels lives on two legs of
`crates/mvm-hostd/src/supervisor/raw_egress.rs`:

- async UDS — `handle_raw_conn_with_resolver`, witnessed by
  `an_exhausted_tunnel_pool_refuses_before_resolving_the_target`.
- blocking vsock — `handle_raw_conn_blocking`, `#[cfg(target_os = "linux")]`.
  Identical `rate_guard.try_admit_tunnel()` call, no test.

The vsock leg was compile-checked only. Deleting its admission left the whole
suite green on every host, Linux included.

## Why the obvious test does not work

A refused tunnel's only tell on the wire is a one-byte `ConnectAck::Fail`. So is
a policy `Deny`, so is a `Malformed` target, so is an admitted target whose
upstream connect fails. Four outcomes, one byte.

A test that writes a target and asserts `Fail` therefore passes whether or not
the bound exists — measured below, not assumed. The async leg's first witness
made exactly this mistake and was only caught by reverting the fix.

The assertion has to be behavioural. A refused tunnel is refused *before* the
target is resolved, so the observable is how many times the resolver was
reached: zero.

## What landed

`handle_raw_conn_blocking` becomes a pure delegator over
`handle_raw_conn_blocking_with_resolver<F: Fn(&str) -> io::Result<Vec<IpAddr>>>`
— the same split, with the same synchronous one-arg resolver bound, that the
async leg already has. `spawn_raw_egress_connection` and every production caller
are untouched. `dns_handler::serve_dns_blocking` is deliberately not the model:
it hardcodes `resolve_hostname_ips_pure` and offers no seam.

Two Linux-gated tests, reusing the `UnixStream::pair()` + `into_raw_fd()` idiom
from `raw_vsock_handlers_run_concurrently` and the existing `unrestricted_gate()`
fixture:

- `an_exhausted_tunnel_pool_refuses_before_resolving_on_the_vsock_leg` —
  `max_tunnels(0)`, asserts the injected resolver was reached **0** times.
- `an_available_tunnel_slot_reaches_the_resolver_on_the_vsock_leg` —
  `max_tunnels(1)`, asserts **1**. Without it the first assertion could hold
  because the fixture never resolves anything under any condition.

Neither test asserts anything load-bearing on the ack byte.

## Evidence

Both tests are `#[cfg(target_os = "linux")]`, so the red-proof was run on the
x86_64 Linux box, not the macOS dev host. Green first — `cargo nextest run -p
mvm-hostd raw_egress`:

```
        PASS [   0.011s] ( 1/16) mvm-hostd supervisor::raw_egress::tests::an_exhausted_tunnel_pool_refuses_before_resolving_on_the_vsock_leg
        PASS [   0.011s] ( 2/16) mvm-hostd supervisor::raw_egress::tests::an_exhausted_tunnel_pool_refuses_before_resolving_the_target
        PASS [   0.011s] ( 5/16) mvm-hostd supervisor::raw_egress::tests::an_available_tunnel_slot_reaches_the_resolver_on_the_vsock_leg
        PASS [   0.011s] ( 6/16) mvm-hostd supervisor::raw_egress::tests::an_available_tunnel_slot_reaches_the_resolver
     Summary [   3.019s] 16 tests run: 16 passed, 1920 skipped
```

Then the `rate_guard.try_admit_tunnel()` block deleted from
`handle_raw_conn_blocking_with_resolver`, nothing else changed:

```
        FAIL [   0.010s] ( 5/16) mvm-hostd supervisor::raw_egress::tests::an_exhausted_tunnel_pool_refuses_before_resolving_on_the_vsock_leg

  stderr ───
    raw-egress: refusing target blocked.test:80: blocked.test is not admitted; no hosts are admitted

    thread 'supervisor::raw_egress::tests::an_exhausted_tunnel_pool_refuses_before_resolving_on_the_vsock_leg' (2775281) panicked at crates/mvm-hostd/src/supervisor/raw_egress.rs:1417:9:
    assertion `left == right` failed: a full tunnel pool must refuse before the host does any DNS work
      left: 1
     right: 0

     Summary [   3.018s] 16 tests run: 15 passed, 1 failed, 1920 skipped
```

That stderr line is the trap made visible. With the bound gone the guest still
received its `Fail` byte — the gate produced it a few lines further down, off the
resolved-but-unadmitted address — and the test sailed past its `assert_eq!(ack[0],
Fail)` before dying on the resolver count. An ack-byte assertion would have stayed
green.

The companion test passing in the red run is the correct result; it is not the
witness. Restored, both green again. Full `cargo nextest run -p mvm-hostd`: 1926 passed
on Linux, 1891 passed on macOS with the Linux-gated pair skipped.
