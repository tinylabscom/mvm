# Egress substitution works: the forward proxy moves to a process that can authenticate

Issue [#2822](https://github.com/tinylabscom/mvm/issues/2822), the sibling of
[#2821](https://github.com/tinylabscom/mvm/issues/2821).

## What was broken

Every request through the guest's forward proxy answered `502`, in every guest, since the
one-transport cutover. Live, before:

```
$ printf 'GET http://example.com/ HTTP/1.1\r\nhost: example.com\r\n\r\n' | nc 127.0.0.1 18080
HTTP/1.1 502 Bad Gateway

substitution refused: reading the guest signing key from /run/mvm/flowmux-guest-signing-key
```

`mvm-guest-agent` started the proxy on its own thread and relayed each request with
`SyncFlowMux::connect`, which reads the guest signing key. The agent runs as uid 901 — the
workload's own uid, because it serves the verbs that run workload code — and the key is
root-owned at mode 0400 so that a workload cannot authenticate as its own guest. The read
could never succeed.

That is the whole of a secret-bearing workload's egress. `effective_vsock_egress` is
deliberately false when the admitted plan carries bound secrets, so that launch starts no
vsock egress client at all and the host substitution endpoint owns the port. Egress
substitution has therefore been dead, not degraded.

## Why the fix is not the one #2821 used

`ping`'s fix was to route the workload through a loopback service inside `mvm-egress-client`,
which is root and already holds the identity. That does not transfer: for exactly the launches
that need the forward proxy, the egress client is not running.

So the proxy becomes its own privileged process. `mvm-forward-proxy` is spawned by
`guest_bootstrap::provision_guest_environment` — the choke point both Rust inits reach while
still root, before the agent is handed the workload identity — and by `mk-guest.nix`'s `/init`
for the Nix-built tier. It is the one helper there started as root rather than under
`setpriv`, which is the point: the process that must read the key cannot be the one that
shares the workload's uid.

Unconditional, not gated on `mvm.vsock_egress=1`. That token is off precisely when this
listener is needed. A workload with no placeholders has no `HTTP_PROXY` pointed at it and it
sees no connections.

The binary is deliberately outside the `addons` feature: the whole proxy is `std` and
blocking, and a tokio runtime in a process that moves one request at a time would be pure
closure.

## The silence

`serve` folded the relay error into the `502` body with `e.to_string()` and logged nothing.
Two consequences, both of which kept this hidden: the body carried only the outermost
`anyhow` context — the message above stops at `flowmux-guest-signing-key` and never says
`Permission denied` — and a client that prints "Bad Gateway" without the body made a broken
relay indistinguishable from a refused destination. Relay failures now log the full chain in
the trusted guest log. The untrusted workload gets the stable `forward proxy relay failed`
class without privileged filesystem or endpoint details.

## Overlay

`/forward-proxy` joins `REQUIRED_OVERLAY_GUEST_PATHS`. An overlay without it strands a
secret-bearing workload as completely as one without the agent, so it is refused at resolve
time rather than at the workload's first request.

The overlay fixture in `mvm-fs` now derives its payload from that list instead of repeating
it, and the three-bool `valid_overlay_ext4_bytes(true, true, false)` becomes
`overlay_ext4_bytes_without(&["/exit-report"])`. Adding a required path used to leave a stale
fixture that failed every unrelated test at once and named none of them the cause.

`resolve_forward_proxy` shares one rule with `resolve_egress_client` rather than repeating the
ladder: a required-overlay boot is a statement about where all of the runtime came from, and a
helper quietly falling back to a baked copy would be the one binary the declaration did not
cover.

## Verification

Live, macOS/HVF, the same command as above:

```
HTTP/1.1 502 Bad Gateway

substitution refused: egress destination not admitted by network policy (claim-10)
```

The request now reaches the host, authenticates, and is answered by the claim-10 gate — a
policy decision instead of a local file-permission failure. (`--allow-host example.com`
admits `:443`; that request was plain `:80`.) And the admitted case, which had never worked:

```
$ printf 'GET https://example.com/ HTTP/1.1\r\nhost: example.com\r\n\r\n' | nc 127.0.0.1 18080
HTTP/1.1 200 OK
content-type: text/html
server: cloudflare
content-length: 559
```

Tests: `a_relay_failure_is_reported_without_exposing_its_cause`, the
`resolve_forward_proxy_for_*` pair, `the_egress_client_and_the_forward_proxy_resolve_by_the_same_rule`,
and `resolve_rejects_overlay_payload_missing_forward_proxy`.

## Noticed, not fixed

`mk-guest.nix` launches `mvm-egress-client` under `setpriv --reuid=<agentUid>`, and that
client mounts the identity drive itself — which needs `CAP_SYS_ADMIN`, and the launch grants
only `net_bind_service`. If that reads the way it looks, the Nix-built tier's egress client
cannot provision its own identity either. Not touched here: it is a different failure in a
different tier, and this change gives that tier a working forward proxy regardless.
