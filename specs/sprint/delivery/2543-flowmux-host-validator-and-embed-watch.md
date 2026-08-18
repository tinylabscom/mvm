# The host validator sees its own sends, and the embed watch sees the guest's source

Issue [#2543](https://github.com/tinylabscom/mvm/issues/2543), plan
`specs/plans/2026-08-15-flowmux-single-transport-cutover.md`. Follows
[#2572](https://github.com/tinylabscom/mvm/pull/2572), which fixed the flow-control halves and
characterised one remaining defect it deliberately left "for the owner of this branch". This is
that defect, plus a build-side one found while proving it.

## The host validator never saw the host's own outbound `Data`

The per-stream relay runs on its own thread and writes through `write_frame_to`, which does not
hold the validator. So the session validator's host-side credit counter was credited by every
guest `WindowUpdate` it admitted and debited by nothing. It climbed until a legitimate grant
pushed it past `MAX_STREAM_CREDIT` and the session was torn down:

    stream 1 credit grant of 16384 exceeds the 4194304-byte window

Only a transfer past the 4 MiB cap reaches it — below that the counter simply climbs unnoticed,
which is why every smaller test passed. `a_download_past_the_credit_cap_is_not_torn_down` drives
4.5 MB through the real session and was confirmed red on this exact error before the fix.

The validator is now `Arc<Mutex<SessionValidator>>`, shared with the relay threads, and the relay
admits the `Data` it sends. That is the structural change #2572 named. `run_tcp_relay`'s
arguments moved into a `TcpRelayParams` struct to stay under the argument limit —
`#[allow(clippy::too_many_arguments)]` is banned, and `UdpRelayParams` beside it is the same
pattern.

## `mvm-cli/build.rs` embedded stale guest binaries

The embedded-binary watch listed `crates/mvm-build/src`. But `mvm-egress-client` — the guest's
entire egress path — belongs to `mvm-agentd`, and reaches `mvm-core` and `mvm-contract` beneath
it. An edit to any of them rebuilt `mvmctl` while embedding the *previous* guest binary. The
guest then ran code the contributor did not write, and nothing said so.

This cost two live runs during this work: a fix was made, the run reproduced the old failure
exactly, and the reasonable conclusion — "the fix was wrong" — was the wrong one. The watch now
covers every workspace crate's `src`, walked from the tree rather than listed, because a list
cannot be kept correct against a dependency graph.

## Verification

- `cargo nextest run` for `mvm-hostd` + `mvm-agentd` + `mvm-contract` + `mvm-build`
- `cargo clippy --workspace --all-targets -- -D warnings` — clean
- `cargo +nightly fmt --all` — clean
- `check-uniform-vsock-egress`, `check-vsock-only-egress`, `check-no-spec-refs-in-comments`,
  `check-build-egress-callers`, `check-l3-expansion-freeze` — all pass
- Live: `machine run --image python:3.12` pulls the whole nixpkgs closure and builds the workload
  kernel over the FlowMux datapath with no resets, truncations or teardowns

## Still not printing `4`

The run now fails past egress entirely, in the per-VM supervisor:

    refusing to boot a bounded workload it cannot audit:
    decoding the admitted plan for the wall-clock timer

`crates/mvm-hostd/src/supervisor/wall_clock.rs:214` — the `Preview` claim 18 fail-closed path.
Nothing in this change or in #2572 touches `ExecutionPlan` or its serde; the stage was simply
unreachable until egress worked. It needs its own diagnosis.

## Remaining plan workstreams

WS4 (fold substitution onto `OpenHttp`), WS5 (ICMP dispatch), WS6 (delete `EgressMode` /
`serve_wire` / `serve_raw`, add the one-protocol gate), WS7 (readiness fails closed), the BDD
scenarios, and excluding the resolved `MVM_HOME` from the Stage 0 work-tree copy rather than a
name list.

Note for WS4/WS5: `forward_proxy` and `icmp_client` sit in the sealed agent's tokio-free closure
while `flowmux` is behind the `addons` feature, so they need a **synchronous** one-shot FlowMux
client, not the existing tokio one. `mvm_core::net::session::Session::guest` is already sync and
the frame codec is `no_std`, so it is buildable without putting tokio in the sealed closure.
Both currently dial `EGRESS_PORT`, which is the same 5253 the endpoint now serves FlowMux on —
so substitution and `ping` are broken on this branch until they land.
