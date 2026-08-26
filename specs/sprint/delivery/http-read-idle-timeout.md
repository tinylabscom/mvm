# A silent peer could park an mvm request forever

Backing: shipped-source
Validation: cargo nextest run -p mvm-http

`DEFAULT_CONNECT_TIMEOUT` bounds *reaching* a peer. Nothing bounded what happened
after the handshake. A peer that accepts and then stops sending left the read
parked in `epoll` indefinitely, because the only other deadline is the
whole-request `timeout`, which is `Option<Duration>` defaulting to `None` — and
`mvm-fs`'s OCI registry client builds its client with `mvm_http::Client::new()`,
so it never set one.

Every OCI request — token, manifest, blob — was therefore unbounded after connect.

## Observed

On the KVM box, host load 0.04 (so not contention):

```
mvmctl machine run --name bdd-guest-hostname --image alpine --timeout 120 -- /bin/hostname
PID 1461588  STAT Sl  WCHAN ep_poll  ELAPSED 29:21  %CPU 0.1
threads: ep_poll, pipe_read     children: none     locks: none
```

29 minutes against `--timeout 120`. And `mvmctl image pull alpine:latest`, warm
home, idle box: 5 minutes wall, **0.187s of CPU** — blocked, not working.

This is very likely what the README pip-over-egress runs were doing when they
exited 124 at a 900s and then a 1500s cap having produced no output. Those were
read as "the example is slow".

## Why the bound is on idle time, not total duration

The obvious fix — default the whole-request `timeout` — is wrong, and wrong in a
way that would not show up until it mattered. `deadline` wraps `send_once`, which
covers the response body, so a total deadline would cap a multi-hundred-megabyte
blob pull. Fixing a hang by breaking large image pulls is a worse trade, and one
that only appears on big images.

So `Stream` carries an idle budget: armed on the first `Pending`, cleared
whenever bytes arrive. A slow transfer that keeps delivering re-arms on every
read and is unaffected; only genuine silence trips it. Default 60s, deliberately
generous, overridable with `Client::builder().read_idle_timeout(..)`.

## Both directions are tested, and both tests are load-bearing

- `a_peer_that_accepts_then_goes_silent_does_not_hang_forever` — a real listener
  that accepts and writes nothing. Before the fix it parked the full 20s the test
  allows; after, it fails in 0.5s naming the timeout.
- `a_slow_but_progressing_transfer_is_not_cut_off` — a drip-fed body whose total
  duration exceeds the budget while no single gap does. This is the counter-test
  for the wrong fix.

Mutation-verified: removing the disarm-on-progress line turns the idle bound into
a total deadline, and the counter-test goes red while the hang test stays green.
That is the distinction the pair exists to hold.

A real listener is used rather than a reserved address because the property is
"accepted then silent", which a black-holed address cannot express — that case
fails at connect, which was already bounded.

## Error text

The read failure says `read timed out: no bytes from peer for {duration}`. The
first draft said only "no bytes from peer", which is accurate but does not tell
an operator what kind of failure they are looking at.
