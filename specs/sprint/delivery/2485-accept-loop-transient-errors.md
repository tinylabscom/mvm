# 2485 — production egress accept loops survive transient accept errors

## What was wrong

Every guest-facing listener treated any `accept(2)` error as fatal: log a
`warn!`, `return` out of the loop. Six sites, all the same shape — raw egress
(UDS + vsock), the substitution endpoint (UDS + vsock, plus the accept-task
panic arm), and the transparent terminator.

`accept(2)` reports two unrelated things through one channel. `EBADF`,
`EINVAL` and `ENOTSOCK` mean the listener is dead. `EINTR`, `ECONNABORTED`,
`ECONNRESET`, `EMFILE`, `ENFILE`, `ENOBUFS` and `ENOMEM` are about the pending
connection or about transient host pressure, and the listener is still good.

There is no restart wrapper — `bin/mvm-network-endpoint.rs` awaits the primary
loop directly — so the second class ended egress for that VM for the rest of
its life. Fd exhaustion is usually host-wide, so the VM that died was typically
not the one that caused it, and it did not recover when the host did.

The terminator case was worse because it is a spawned task the primary loop
does not join: it could die while the VM kept running, leaving the redirect
path silently gone.

Fail-closed throughout, so no claim was violated. Availability and
observability defect, not a security one.

## What landed

`crates/mvm-hostd/src/supervisor/accept_loop.rs` — a pure classifier
(`classify_accept_error`) returning `Retry(Duration)` or `Fatal`, one delay
policy (first four retries free, then 1 ms doubling to a 1 s cap), and
`record_listener_stopped`, which emits `host.listener_stopped` through the
chain signer so a VM losing egress is visible in the audit log rather than only
on the endpoint's stderr.

Unrecognised errno values classify as `Fatal`. A listener failing in a way
nobody characterised should surface loudly rather than spin forever on
something that will not clear.

All six sites now share it. The accept-task panic arm stays fatal — a panic is
a bug in this process, not pressure that clears — but is now audited.

## Verification

`cargo nextest run --workspace` 11,609 passed. Clippy clean. `cargo +nightly
fmt --all -- --check`, doctests, and `check-no-spec-refs-in-comments`,
`check-honesty`, `check-doc-claims`, `check-no-overclaim`,
`check-uniform-vsock-egress`, `check-vsock-only-egress` all pass.
`just check-linux` passes — the two vsock sites are `cfg(target_os = "linux")`
and a macOS-only check would not have compiled them.

## Not addressed here

The audit that found this also confirmed a hard 16 MiB ceiling
(`MAX_FRAME_BYTES`) on any request or response through the substitution path.
It is enforced cleanly rather than truncating or hanging, but it is not stated
in user-facing docs. Left open on the issue.
