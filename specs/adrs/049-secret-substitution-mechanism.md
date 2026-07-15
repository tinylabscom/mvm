# ADR 049: TLS substitution mechanism for guest secret placeholders

- **Status: SUPERSEDED 2026-05-28 by [ADR-059](059-host-services-broker.md).** Runtime secret substitution is no longer an mvm responsibility in v1. The vsock-substitution-vs-TLS-proxy comparison below is kept as historical context; the design itself is not being implemented. `host.secrets.v1` and `mvm-secrets-dispatcher` are dropped from Plan 104.
- Date: 2026-05-14 (superseded 2026-05-28)
- Owner: MVM Project
- Related: ADR-002 (microVM security posture), ADR-004 (egress policy), ADR-041 (signed audited execution plans), ADR-048 (claim-safe sandbox parity), [ADR-059 (rescope — drop secrets)](059-host-services-broker.md), Plan 74 W2 + W3, Plan 74 §Risks R9

## Context

Plan 74 W3 makes the secret-non-leakage claim defensible: workloads
receive an opaque `mvm-secret://<grant-id>` placeholder instead of
the real secret value, and the host swaps the placeholder for the
real value at egress time, only when destination policy passes.

ADR-048 §"Secret non-leakage" gates the claim on
"substitution is bound to destination policy and transport
identity." Plan 74 W3 says "integrate substitution with the L7
egress proxy after destination policy passes." Both are consistent
with three architectural shapes, with very different trust
footprints. Shipping W3 without picking turns the substitution
code into ad-hoc PR-review architecture and risks one shape
landing "temporarily" and never being revisited. This ADR picks.

The three candidates:

**(a) Proxy-with-CA.** Install an mvm-issued CA in the guest's
trust store. The supervisor-owned L7 proxy terminates TLS,
substitutes the placeholder in plaintext request bytes,
re-encrypts to upstream with a fresh TLS session.

**(b) Vsock side-channel.** The guest's SDK runtime library hooks
the HTTP client's credential-loading step. At egress the hook
calls a host-side substitution service over vsock, requesting a
signed credential for the placeholder; the host validates
destination policy and returns the credential; the hook injects
it into the actual request. The guest's TLS stack is untouched;
the proxy stays SNI-only.

**(c) Host-side request reconstruction.** The guest issues
plaintext HTTP through the proxy; the proxy substitutes in
plaintext on the host and does the TLS handshake to upstream.

## Decision

**The default substitution mechanism is (b) vsock side-channel.**
**(a) proxy-with-CA lands later as an explicit opt-in feature
flag** for legacy workloads that cannot be modified. **(c) is
rejected** as architecturally inadequate.

### Substitution flow (b — default)

1. Plan admission mints a `SecretPlaceholder` per grant: opaque
   token, grant id, allowed destinations (host + path patterns),
   expiry, signed under the host signer.
2. The placeholder is delivered to the guest as env or argv —
   `OPENAI_API_KEY=mvm-secret://01H9Q…XYZ`. The token is a ULID,
   not a UUID, so it sorts and is cryptographically distinguishable
   from any plausible plaintext secret.
3. The guest's `mvm-sdk-runtime` library (one per Python, TS,
   Rust) hooks the HTTP client's outbound request. At hook time it:
   - Resolves the placeholder via `$MVM_SECRET_VSOCK_PORT`
     (host-injected at boot).
   - Sends a substitution request over vsock:
     `(grant_id, target_url, method, scheme)`.
   - Receives `Authorization: Bearer …` (or arbitrary
     header/body fragment, per the placeholder's substitution
     descriptor) signed by the supervisor.
   - Injects into the outbound request and lets the guest's
     normal TLS stack send it.
4. The supervisor's substitution service, on each call:
   - Verifies the grant id against the active-grants registry.
   - Verifies the target URL matches the placeholder's allowed
     destinations.
   - Emits `secret.substitute.allow` or
     `secret.substitute.deny` to the audit chain.
   - Returns the materialized credential (or a structured
     denial). The real secret value never leaves the supervisor.

### Coverage matrix (b)

| Language    | Library                | Hook point                                    |
| ----------- | ---------------------- | --------------------------------------------- |
| Python      | `requests`             | `Session.send` middleware                     |
| Python      | `httpx`                | `Client.send` + `AsyncClient.send`            |
| Python      | `aiohttp`              | `ClientSession._request`                      |
| Python      | `urllib3` (direct)     | Pool manager `urlopen` wrapper                |
| TypeScript  | global `fetch`         | Polyfill via `mvm-sdk-runtime` install hook   |
| TypeScript  | `axios`                | `interceptors.request`                        |
| TypeScript  | `node:http(s)`         | `request` patch in install hook               |
| Rust        | `reqwest`              | `reqwest_middleware::Middleware`              |
| Rust        | `hyper`                | `tower::Layer`                                |
| Rust        | `tonic` (gRPC)         | `Interceptor`                                 |

SDK-bundled clients (OpenAI Python, Anthropic JS, etc.) inherit
their underlying HTTP-library hook. The `mvm-sdk-runtime` package
exposes a `register_substitution_handler(name, fn)` for SDKs that
inject credentials in non-standard places (e.g. AWS SigV4, which
signs the request body — the handler intercepts at signature time,
not at header injection).

### Credential-loading substitution handlers

`register_substitution_handler(name, fn)` is the extension point
for protocols whose authentication material is signed before the
HTTP request middleware sees the final request. The handler receives
the placeholder and returns materialized credential bytes through
the same vsock-backed substitution service as the HTTP hooks. The
language adapter must call the handler while the cloud SDK is
loading credentials, before the SDK signs headers, query strings,
or request bodies.

Built-in AWS adapters resolve access key id, secret access key, and
optional session token through the `aws` handler namespace, then
hand the resolved values back to the native credential provider:

- Python: `botocore.credentials.Credentials`.
- TypeScript: `@aws-sdk/credential-providers` provider result.
- Rust: `aws_config::SdkConfig` credential provider.

SigV4 then runs unchanged with real credentials, so the guest does
not need host-side signing and the upstream service receives a
valid signature. Missing handlers fail closed before any outbound
request is signed.

### Non-HTTP egress

Out of scope for v1 substitution. SSH, raw TCP, DB protocols
(PostgreSQL/MySQL wire), mTLS APIs see no substitution by default.
Two paths offered:

- **L4 deny.** Plan 74 W2's deny-by-default policy keeps non-HTTP
  egress closed. Workloads that need DB or SSH egress declare a
  destination policy explicitly; secrets for those destinations
  flow via in-image config bound by `unsafe_guest_secret_materialization`
  (ADR-048 documents this as "not a non-leakage claim").
- **Future ADR.** Non-HTTP substitution can land later via a
  per-protocol hook contract; the vsock service is protocol-agnostic.

### Legacy opt-in (a — proxy-with-CA, behind feature flag)

For workloads that cannot be modified (vendored binaries, third-party
agents, customer-provided rootfs), provide an opt-in feature flag
`unsafe_guest_tls_inspection`:

- Per-workload CA issued at admission; CA private key never leaves
  the supervisor.
- CA cert installed in guest's trust store at boot via the existing
  `/etc/ssl/certs/` overlay path.
- The L7 proxy terminates TLS, runs the substitution, re-encrypts.
- CA cert is revoked at workload stop; subsequent workloads get a
  fresh CA.

The flag's name is deliberately load-bearing: it expands the trust
boundary, and the docs page for the status row carries the
expansion as an explicit caveat. The `cargo xtask check-doc-claims`
lint W0 builds will not allow "secrets cannot leak" on any page
that enables this flag without also marking it Preview, not
Shipped, for that workload class.

### Rejected: (c) host-side reconstruction

Breaks the modal egress destination — every SaaS API mvm users
care about (OpenAI, Anthropic, Stripe, AWS, GitHub) requires
HTTPS. Plaintext-through-proxy is only viable for internal CIDR
egress, which is rarely secret-bearing in practice. The complexity
of running both (c) for plaintext + (b) for HTTPS would exceed the
complexity of just shipping (b) for everything.

## Consequences

### Positive

- No expansion of the host trust boundary. The supervisor's
  responsibilities grow (substitution service, grant registry) but
  the **guest's** trust store is unchanged. ADR-002's threat model
  holds without revision.
- Protocol-agnostic. HTTP/1.1, HTTP/2, HTTP/3, gRPC, mTLS — the
  guest emits a request shape the proxy already supports; the
  substitution happens before TLS, not inside it.
- Auditable. Every substitution is an explicit vsock RPC; every
  call emits an audit-chain entry naming the grant, destination,
  and outcome.
- Cold-start friendly. One vsock round-trip + Ed25519-sign per
  egress; well under the boot budget being negotiated in W5.
- Tractable hostile-guest tests. The threat model is "guest
  attempts to extract the real secret value." Vsock substitution
  never returns the raw value, only a signed credential bound to
  a destination — the guest cannot replay it elsewhere.

### Negative

- **Library coverage burden.** Each HTTP-library hook is small
  (~30-100 LoC), but the matrix is broad. SaaS SDKs that bake
  custom auth (AWS SigV4, GCP IAP) need explicit handlers.
- **Opt-out by raw socket.** A guest can ignore `mvm-sdk-runtime`
  and call socket(2) directly. Acceptable: the user's SDK choice
  is their own attack surface. The host still enforces L4
  destination policy (W2) and audits the connection.
- **Two paths to maintain.** (b) default plus (a) feature flag is
  more code than (a) alone. Mitigated by the flag being explicit
  and the (a) path being a thin alternative — both share the
  destination-policy enforcer and the audit emitter.

## Non-goals

- Replacing the guest's HTTP stack. The library hooks are
  cooperative; the guest opts in by importing `mvm-sdk-runtime`
  (which the SDK installs by default in built images).
- Substitution into binary protocols (gRPC body fields, mTLS
  client auth, custom binary wire) in v1. Future ADR.
- Generic TLS interception for non-secret purposes (e.g. DLP,
  content scanning). The substitution service is bound to grant
  semantics; broader inspection requires (a) and a separate ADR.
- Claiming non-leakage for the legacy `unsafe_guest_secret_materialization`
  env/file flow. ADR-048 §"Non-goals" already forbids this.

## Open questions

- **Resolved — AWS SigV4-shaped auth.** SigV4 signs the request
  body after building it, so substitution happens through the
  credential-loading handler contract above rather than at
  request-send. The W3.4 SDK layer ships the `aws` handler
  namespace in Python, TypeScript, and Rust and verifies S3
  `ListBuckets`-shaped SigV4 signing sees resolved credentials
  before the signature is computed. Tracked by
  [mvm#224](https://github.com/tinylabscom/mvm/issues/224).
- **WebSocket auth.** Most use a connect-time `Authorization`
  header that fits cleanly into the substitution model. Some use
  post-connect token messages; those need protocol-specific
  hooks.
- **Long-running connections that outlive grants.** A grant with
  a 1h expiry on a 24h workload: the guest re-requests
  substitution at re-connect time and gets a fresh credential.
  The placeholder-token-to-grant mapping is many-to-one across
  the workload lifetime.

## Implementation Plan

Tracked in [`specs/plans/74-claim-safe-sandbox-parity.md`](../plans/74-claim-safe-sandbox-parity.md)
§W3. Plan 74 §Risks R9 closes when this ADR ships and W3 task
list adopts the vsock substitution mechanism.

W3 task additions on top of plan 74 as-written:

- Vsock substitution service in `crates/mvm-supervisor/src/secrets/substitute.rs`.
- `mvm-sdk-runtime` Python package with hooks for `requests`,
  `httpx`, `aiohttp`.
- `mvm-sdk-runtime` TypeScript package with `fetch` polyfill +
  `axios` interceptor.
- `mvm-sdk-runtime` Rust crate with `reqwest::Middleware` + `hyper::Service` shim.
- Credential-loading substitution handlers:
  `register_substitution_handler(name, fn)` in Python,
  TypeScript, and Rust; built-in `aws` credential adapters for
  SigV4-shaped auth; deterministic S3 `ListBuckets`-shaped
  signing tests proving placeholders are resolved before signing.
- Hostile-guest tests:
  - Raw socket bypass attempt → L4 policy denies + audits.
  - Substitution replay attempt (re-use signed credential on a
    different destination) → upstream rejects + audits.
  - Library bypass attempt (`socket.send` directly with the
    placeholder string) → string egresses unchanged but does not
    authenticate anywhere.
- W3 status row on the public sandbox-parity page flips to
  Preview when the Rust core ships, Shipped when the three SDK
  bindings + hostile-guest tests run in CI.

The legacy `unsafe_guest_tls_inspection` opt-in (a) is a
separate, later workstream — not part of W3 v1.
