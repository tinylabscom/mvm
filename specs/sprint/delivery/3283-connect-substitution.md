# 3283 — a CONNECT tunnel to a bound host is terminated, not refused

Credential substitution shipped, worked, and could not be used by any client
anyone would actually run. The in-guest proxy that substitutes accepts
absolute-form requests only, and every HTTPS client that honours a proxy
environment variable — curl, Python `requests`, most Node agents — tunnels with
`CONNECT` instead. That got a 502. On the host side the refusal was correct:
relaying an opaque flow to a host carrying a bound secret would put a
placeholder on the wire and skip substitution entirely. So the feature was
reachable only by a client written specifically for it.

The host now terminates such a flow rather than refusing it.

## Why the terminator was sitting there unwired

Not a decision. The TLS terminator was built against a topology with a guest NIC
and an nftables redirect, and its live glue recovers the original destination
from `SO_ORIGINAL_DST` or a proxy preamble. The vsock-only cutover deleted the
NIC and the redirect, so the listener that fed it has been disabled at every call
site since — `terminator_listen: None`, everywhere, for months.

The TLS half survived that intact: it is generic over `Read + Write`, so it does
not care what carries the bytes. The flow half did not, and is not reused here.
It is a parallel pipeline that never consults the egress gate, never meters the
AI budget, never runs reversible replacement, and buffers whole responses — four
controls the main path has. A terminated flow is driven through
`SubstitutionService::process_body_stream` instead, which is where those controls
already live.

## What holds the boundary

The forward leg's destination is the gate-admitted value, never bytes from the
guest. A request whose `Host` disagrees with the tunnel authority is refused with
421 and a chain-signed entry — and so is a request with no `Host` at all,
because defaulting to the authority would make the absence of the check
indistinguishable from it passing.

Only an `Egress` route can be terminated. For a peer route the gate's admitted
address *is* the translation, so terminating one would re-originate by name
through the ordinary resolver with the real credential attached. The guard is an
allowlist match on the route, so a future third variant is not terminable by
default.

Bytes arriving past the declared `Content-Length` are refused rather than folded
into a credentialed body that never passed header substitution. A transfer-coded
body is refused rather than silently mangled into the request.

Exhausting the per-VM terminated-flow ceiling refuses. It never degrades to an
opaque relay — that degradation would have been the one path where this feature
could have become a bypass.

## The certificate

The per-VM CA is self-signed rather than an intermediate under a long-lived host
root. An intermediate handed to a guest as its trust anchor needs partial-chain
verification, which rustls supports and older OpenSSL-backed clients do not —
and the entire premise is that an unmodified client works. Name constraints bound
it to exactly the destinations the plan's secrets are bound to, and a review
measured that both verifiers that matter enforce them from a self-signed anchor.

Deleting the host root lost nothing: the guest only ever trusted the
intermediate directly, there was no revocation to lose, per-boot minting is
stronger rotation than a root provides, and it removed the only long-lived
unconstrained signing key on the host.

The guest receives the certificate on the per-boot identity drive and nothing
else; the writer refuses a slot containing private key material outright. A
warm-claimed child inherits its parent's CA, because it restores the parent's
`/run/mvm` and therefore already trusts the parent's certificate.

## A module the compiler never saw

`flowmux/session.rs` held 1,188 lines that no `mod` declared: a byte-identical
copy of the live `handle_open_tcp`, which a later change then edited, fixing
nothing. `check-single-network-path` named it as one of two callers that must
route a guest target through the egress gate, and as a flow-audit site — so a
gate was asserting a property of a file the compiler does not compile. That
reads as coverage, which is worse than no check at all. Deleted, and both lists
now name only the live path.

## Found on the way, filed rather than folded in

Documenting the substitution path against source produced #3284 through #3288:
secrets thread through one invocation only, a kept-alive entrypoint machine
ignores `--name`, the substitution audit entry is written on response completion
rather than when the credential is sent, the agent network preset and the token
budget are unreachable from the CLI, and the guest has two egress proxies with
different capabilities.

The security review produced #3297 and #3300: the whole host-side scan layer has
no callers while its own prose says "always-on", leaving a placeholder in a
request body ungated; and a claim-10 gate refusal writes nothing to the chain.

Reviewing the endpoint itself produced #3301 and #3302: the egress gate is
optional on `SubstitutionService`, so an endpoint that enforces nothing is a
well-typed value; and the 5,281-line file that owns the whole decision surface is
why parallel pipelines keep appearing inside it.
