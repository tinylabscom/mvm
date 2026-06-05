# Plan 124 Phase A — the lean guest-agent dep cut (measured)

Measured 2026-06-05 on branch `feat/plan-124a-lean-agent`. Method matches
[`dep-baseline.md`](dep-baseline.md) (unique packages, not tree lines):

```sh
cargo tree -p mvm-guest -e no-dev --prefix none --target <triple> \
  | sed 's/ v[0-9].*//' | sort -u | wc -l
```

The async stack mvm-guest carried was `cfg(target_os = "linux")`-gated
(netinit's rtnetlink), so it is **invisible on a macOS host tree** — every
real number here is on the guest's actual target, `aarch64-unknown-linux-gnu`.

## The cut

| `mvm-guest` no-dev closure (unique crates) | Before (A1, `1cb2c9dc`) | After (A3) | Δ |
|---|---|---|---|
| Linux target (`aarch64-unknown-linux-gnu`) | **126** | **99** | **−27** |
| Host target (`aarch64-apple-darwin`) | 203¹ | 199 | −4 |

¹ host baseline recorded in A1; on the host the only removed crate is
`async-trait` (+ its proc-macro deps) — the heavy async stack was never on
the host target.

**Added: 0.** A3 replaced the `rtnetlink` crate with a hand-rolled
`RTM_NEWROUTE` message over a synchronous `AF_NETLINK` socket using `libc`
(already a dep) — the brief's proposed `linux-raw-sys` was unnecessary
(constants are frozen kernel UAPI, inlined and pinned to `libc` by the
`constants_match_libc` CI test).

The 27 removed crates — the entire `tokio` + `futures` + `netlink`
ecosystems that `rtnetlink` (async) dragged in:

```
async-trait byteorder bytes errno futures futures-channel futures-core
futures-executor futures-io futures-macro futures-sink futures-task
futures-util mio netlink-packet-core netlink-packet-route
netlink-packet-utils netlink-proto netlink-sys nix paste rtnetlink
signal-hook-registry slab socket2 tokio tokio-macros
```

(The raw `cargo tree | wc -l` the plan literally names drops 285 → 198
*tree lines* on the Linux target, but that counts a crate once per position
in the graph — `futures-core` alone appears many times. The 27 figure above
is unique crates, the meaningful number, and is what `dep-baseline.md`'s
method reports.)

## Where the cut came from

All of it is A3 (`rtnetlink` → raw netlink). **A1** added only the
`check-guest-agent-runtime-free` gate (no dep change). **A2** (`serde_json`
→ hand-rolled vsock codec) was found **not viable** and deferred:
`serde_json` enters `mvm-guest` transitively via `mvm-core`
(`serde_json → mvm-core → mvm-guest`) and is load-bearing in 7 guest
modules + 3 bins, so hand-rolling the vsock codec removes **0 crates** for
a large, risky rewrite — see plan 124 Task A2 for the full reasoning.

## Invariants

- **Claim 4 (`prod-agent-no-exec`):** untouched. A3 did not modify
  `src/bin/mvm-guest-agent.rs` or `do_exec` (`git diff 1cb2c9dc..HEAD --
  src/bin/mvm-guest-agent.rs` is empty); the CI witness is unaffected.
- **Claim 5 (vsock framing fuzzed):** untouched. A2 deferred → the vsock
  codec and its two fuzz targets are unchanged.
- **Claim 10 (`NetworkMandatoryDeny`):** preserved. `RawNetlinkInstaller`
  installs the same blackhole routes and emits the same `REPORT_MARKER`
  console-audit line; the `RouteInstaller` trait + install-loop + report
  shape are behaviourally identical (covered by the same tests, now sync).

## Verification (local, this branch)

- macOS: 236 `mvm-guest` tests pass, clippy `-D warnings` clean, nightly fmt clean.
- Linux target (`aarch64-unknown-linux-gnu`, rustc 1.96): `cargo check`
  **and** `cargo clippy -D warnings` clean for `mvm-guest --all-targets`,
  compiling the `cfg(linux)` `RawNetlinkInstaller` + `constants_match_libc`.
- Runtime behaviour of the AF_NETLINK install (kernel accepts the message)
  is exercised by Linux CI / a real KVM host — not runnable on a macOS dev host.
