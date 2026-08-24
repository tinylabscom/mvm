# `ping` works again: a loopback ICMP mediator in the process that holds the identity

Issue [#2821](https://github.com/tinylabscom/mvm/issues/2821).

## What was broken

```
$ mvmctl machine run --image alpine --allow-host github.com -- sh -c "ping github.com"
mvm-ping: open a FlowMux session for the echo: reading the guest signing key from
          /run/mvm/flowmux-guest-signing-key: Permission denied (os error 13)
mvm-ping: a host must be admitted to be pinged — pass `--allow-host github.com` to the run
```

`mvm-ping` is bind-mounted over the image's `/bin/ping` and runs as the workload, uid 901. The
identity drive's signing key lands in `/run/mvm` root-owned at mode 0400, and the workload's
capability bounding set is `CAP_KILL|CAP_SYS_TIME` — no `CAP_DAC_OVERRIDE`. So the read cannot
succeed, and `SyncFlowMux::connect` does that read first.

Before the one-transport cutover, `icmp_client` dialled the egress port directly and needed no
key at all; the cutover put it on an authenticated session without noticing that its one caller
runs as the one uid that cannot authenticate. `ping` has been dead in every guest since.

## The key being unreadable is not the bug

It is the point. The whole reason the identity rides a drive rather than the kernel cmdline is
that the cmdline is readable by uid 901, and the drive copy's mode is what keeps the property
after the copy. A workload that can read the key can authenticate as its own guest. So the fix
is not to widen the mode — it is for `ping` to stop trying, the way every other outbound thing a
workload does already works: through a loopback service in the process that legitimately holds
the identity.

`mvm-egress-client` runs as root and is already that process for two of them — the SOCKS/HTTP
proxy on `127.0.0.1:1080` and the DNS stub on `127.0.0.1:53`. ICMP is now the third, on
`127.0.0.1:1081`.

## What the mediator is

`mvm_agentd::icmp_mediator`. Per connection: open one blocking FlowMux session, announce it,
then answer echo requests until the client hangs up. The request and reply lines are the same
`IcmpEchoRequest` / `IcmpEchoReply` the `IcmpEcho` flow already carries, so nothing new was
invented and the host side is untouched — `icmp_handler::serve_request` still makes every
decision.

Nothing new crosses the guest→host boundary either. This is the guest's own loopback;
`check-one-guest-protocol` still sees one dialer per file and one protocol on the wire.

The connection opens with a `MediatorHello` for one reason: the round trip `ping` prints has to
be the echo and not the handshake. The mediator establishes its session and says so, and the
client starts timing after that — the same property the old code had by opening its own session
before starting the timer, kept rather than quietly lost.

A session that cannot be opened comes back as `Unavailable { message }` rather than a closed
socket, because the workload cannot see the host endpoint, the identity drive, or the egress
client's stderr, and `EOF` would be all it had to go on.

## The second line of that output

The `--allow-host` hint was printed for every error, including this one — advising the reader to
pass a flag they had just passed. A refusal is now typed (`icmp_client::Refused`) and the hint is
printed only for one, which is the only case where it is true.

## Tests

- `an_echo_crosses_the_loopback_and_comes_back_off_the_session` — an unprivileged line-speaking
  client, the mediator holding the only key, and a host running the real sealed session on the
  other side.
- `an_out_of_bounds_request_is_refused_without_reaching_the_host` — the host asserts the
  negative, because "refused" and "refused by the host" print the same to the workload. Confirmed
  red with the bounds check removed: the frame reaches the host.
- `a_client_that_cannot_open_a_session_is_told_why_rather_than_dropped`.
- `a_refusal_is_distinguishable_from_a_transport_failure` — confirmed red with the refusal
  untyped back to a bare `bail!`.
- `each_wire_request_carries_a_single_echo` — still one request per echo, now asserted against
  what the mediator actually received rather than against a locally rebuilt copy of it.

## Not fixed here: the same defect in the forward proxy

[#2822](https://github.com/tinylabscom/mvm/issues/2822). `mvm-guest-agent` also runs as uid 901
and also relays through `SyncFlowMux::connect`, so every request to its forward proxy on 18080
fails the same read and returns a `502` with nothing logged — the egress-substitution path is
dead for the same reason. The fix is the same shape, but it has two decisions this one did not
(the egress client is started only under `mvm.vsock_egress=1`, and the container tier reaches the
endpoint over a bind-mounted socket), so it is filed rather than folded in.
