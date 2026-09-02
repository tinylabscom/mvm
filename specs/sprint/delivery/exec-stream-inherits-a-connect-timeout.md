# A large egress transfer died because the exec stream inherited a connect timeout

`mvmctl machine run --image python:3.12 --allow-host pypi.org:443 -- pip
install pandas` finished the 11 MB pandas wheel, went quiet while the 16.7 MB
numpy wheel was fetched, and died:

```
Error: control frame read failed
  0: session i/o error: Resource temporarily unavailable (os error 11)
```

Reproduced on the Hetzner x86_64 KVM box against current main, so this was
neither environment nor collateral from the runner shutdown that ended the same
nightly run.

## Root cause

`connect_vsock_uds` arms `set_read_timeout` to bound the agent handshake and
never disarms it. Every later read on that stream therefore inherits a
*connect* budget, and a quiet gap longer than it — routine between two
multi-megabyte wheels on one `pip install` — arrives as `EAGAIN` on a frame
boundary. `read_exec_stream_with_session` had no timeout handling, so a
transfer that was working was aborted as a transport failure.

The backtrace named it exactly:

```
5: read_exec_stream_with_session   crates/mvm-agentd/src/vsock/rpc.rs:658
6: send_exec_streaming             crates/mvm-agentd/src/vsock/rpc.rs:583
7: run_in_guest                    crates/mvm-cli/src/exec/guest_run.rs:92
```

## Why the earlier fix did not cover it

This is the same symptom as a previously closed issue, whose fix preserved the
typed I/O source so a caller could recognise `EAGAIN`, and taught the
*entrypoint* stream to retry against a liveness probe. Both halves were
correct. Neither reached the exec stream, which is quiet for exactly the same
reasons and consulted neither: it inherited the connect timeout and treated it
as fatal.

So the classifier was never wrong. What was missing is that only one of the two
streaming paths ever called it.

## The change

`read_exec_stream_with_session` now does what the entrypoint stream already
did: install its own poll, restore whatever it found on the way out, and treat
a timeout as "quiet" rather than "broken". The frame loop moved into
`read_exec_stream_frames` so the timeout is restored on every exit path, and
`ENTRYPOINT_LIVENESS_POLL` became `STREAM_LIVENESS_POLL` now that two streams
share it.

Retrying cannot spin on a dead peer: a guest that is actually gone fails the
read with a hangup, not a timeout, and the command's own `timeout_secs` bounds
it inside the guest.

## Tests, and one that was wrong

Two, because the fix has two halves and they are not both exercised by the same
gap:

- `a_quiet_gap_between_exec_frames_does_not_end_the_stream` — the **override**.
  A 400 ms gap beats the inherited 50 ms budget but never reaches the retry,
  because the poll replaced it. This is the half that fixes the reported
  failure.
- `a_gap_longer_than_the_liveness_poll_is_retried_not_failed` — the **retry**.
  Drives the frame loop directly with a short timeout so every gap times out
  underneath, and only the retry can carry the stream to its terminal frame.

The first test was written alone and claimed to cover EAGAIN handling. It does
not: deleting the retry leaves it green, which a mutation run showed. The
second test exists because of that, is mutation-verified, and the first one's
doc comment now says plainly what it does not cover. Worth recording, because
a single test here would have looked like proof and been none.

## Live verification

Same command, same host, with the fix applied and rebuilt:

```
Downloading numpy-2.5.2 (16.7 MB)  ━━━━ 16.7/16.7 MB 1.5 MB/s
Successfully installed numpy-2.5.2 pandas-3.0.5 python-dateutil-2.9.0 six-1.17.0
EXIT=0
```

## Not in scope

The other live failure in that nightly is untouched: guest activation dies on
`open /dev/mapper/control: No such file or directory`. It is inside the guest,
not on the host, and appears in both recent nightly runs, so it is persistent
and separate.

## Validation

67 gates clean · `cargo nextest run --workspace` 12981 passed · doctests clean ·
`clippy --all-targets -D warnings` clean · `fmt --all --check` clean ·
`check-gated` clean with `RUSTFLAGS=-D warnings` · live witness above.
