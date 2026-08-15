# 2482 — upstream proxy support on the host egress leg

## What was missing

On a host that force-tunnels all outbound traffic, every workload's egress
failed and there was no knob. The forward leg already built its trust store
from `rustls-native-certs`, so a host with a locally-trusted interception CA
worked; what did not exist was any way to reach an *upstream proxy*.
`mvm-http`'s own module docs said so plainly: "no proxy support".

## What landed

`crates/mvm-http/src/proxy.rs` — `Proxy` / `ProxyConfig` / `NoProxy`, parsing
`http`, `https`, `socks5` and `socks5h` endpoints, scheme-specific selection
with `ALL_PROXY` fallback, and lowercase-wins-over-uppercase precedence.
Credentials never reach `Debug`, `endpoint()` or `summary()`.

`crates/mvm-http/src/client.rs` — the transport. `CONNECT` tunnelling for TLS
destinations (bounded by the same head limit the response parser uses),
absolute-URI request lines for plaintext through an HTTP proxy, and SOCKS5
CONNECT sending the destination as a domain name so the proxy resolves it.

Host wiring: `EndpointConfig` carries the proxy as strings, resolved by
`spawn_network_endpoint` from the host environment **once for every backend**
rather than at each call site — a backend that forgot would be an egress outage
on a force-tunnelled host, and the forgetting would be invisible.
`HardenedForwarder::with_proxy` applies it to the forward leg. `mvmctl doctor`
grew an `egress proxy` line.

A malformed proxy value is an error at every layer, never a silent direct dial.
On a host whose only route out is the proxy, downgrading a typo to a direct
dial converts a fixable misconfiguration into an unexplained total outage.

## The security trade-off, stated rather than discovered

The client's `Resolve` seam is the SSRF chokepoint: the client dials only what
the resolver returned, which is what closes the DNS-rebinding window. **When a
request is proxied, the proxy performs the destination's final resolution**, so
`SsrfFilteringResolver` no longer constrains the destination address. That is
inherent to proxying. It is acceptable only because the proxy comes from
operator configuration on the host and is never guest-supplied.

For the same reason the proxy's own address is resolved *outside* the guard: a
corporate proxy is almost always on RFC1918, which the guard exists to reject.

What does not change: whether a destination is permitted at all is decided by
the egress gate before a request reaches this client. Proxy selection is a
transport choice made afterwards, and `NoProxy` only picks how an
already-permitted destination is reached — it is not a second allow-list.

## Verification

`cargo nextest run --workspace` 11,634 passed. Clippy clean, nightly fmt clean,
doctests clean. `check-no-spec-refs-in-comments`, `check-honesty`,
`check-doc-claims`, `check-no-overclaim`, `check-uniform-vsock-egress`,
`check-vsock-only-egress`, `check-forbidden-deps`, `check-duplicate-majors` all
pass. `just check-linux` passes.

Wire behaviour is covered by fake proxies on loopback
(`crates/mvm-http/tests/proxy.rs`): absolute-URI form, `CONNECT` naming the
destination authority and carrying credentials, SOCKS5 domain-name CONNECT,
`NO_PROXY` falling back to a direct origin-form dial, and both refusal paths.

## Not done here

- **Per-flow audit attribution.** The endpoint logs the resolved proxy at
  startup and `doctor` reports it, but the chain-signed log carries no
  per-connection proxy label, so a single flow entry does not say whether it was
  proxied or bypassed by `NO_PROXY`. That checkbox on the issue stays open.
- **Only the per-VM workload egress forward leg is proxied.** Other host HTTP —
  the search/fetch tool clients in `supervisor/tools/`, and the OCI
  registry/manifest/layer fetches in `mvm-fs` — still dial directly and will
  still fail on a force-tunnelled host.
