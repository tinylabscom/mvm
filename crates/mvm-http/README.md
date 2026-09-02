# mvm-http

`mvm-http` is mvm's small HTTP/1.1 client over rustls. It serves the registry,
artifact-fetch, update, SDK deployment, and host egress paths without bringing
the general-purpose hyper/tower stack into shipped binaries.

## Who uses it

`mvm-fs` uses it for OCI distribution, `mvm-build` for artifact acquisition,
`mvm-cli` for user-facing fetches, `mvm-hostd` for admitted host networking,
and `mvm-sdk` for optional remote deployment. `mvm-core` uses it only for the
feature-gated remote client transport.

## How it works

1. `ClientBuilder` configures TLS bounds, resolution, proxy behavior, limits,
   and timeouts.
2. URL and header types are validated by established parsing crates.
3. A resolver returns permitted socket addresses; `PinnedResolver` can bind
   resolution to an already-authorized address set.
4. `conn` establishes TCP and rustls sessions and writes one HTTP/1.1 request.
5. `parse` reads a bounded response head and chooses exactly one body framing
   mode.
6. `response` exposes the status, headers, and bounded body to the caller.

The framing parser fails closed on conflicting content lengths, ambiguous
transfer encodings, malformed chunks, oversized heads, and premature EOF. The
crate deliberately does not implement HTTP/2, redirects, decompression, or a
connection pool. Callers own redirect policy and application-level retries.

## Main modules

| Module | Responsibility |
|---|---|
| `client` | Async client and request builder |
| `blocking` | Blocking facade for synchronous callers |
| `resolve` | System and pinned DNS resolution |
| `proxy` | Explicit proxy and no-proxy configuration |
| `conn` | TCP/TLS connection and request I/O |
| `parse` | Bounded response-head and chunked-body parsing |
| `response` | Response representation and body access |
| `error` | Typed transport and protocol failures |

## Security boundaries

This crate supplies safe parsing and resolution primitives, but callers remain
responsible for deciding which schemes, hosts, ports, redirects, and resolved
addresses are authorized. New parser behavior should include hostile-server
tests and, where applicable, fuzz coverage.

## Developing

Run `cargo test -p mvm-http`. Exercise both async and blocking paths when their
behavior changes. Parser changes must cover valid framing, malformed input,
size caps, and request-smuggling ambiguities.
