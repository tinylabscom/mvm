# ADR-067 — Secrets subsystem: egress substitution, never in the guest

**Status:** Accepted (2026-05-31). Supersedes ADR-049 (in-guest resolve-over-vsock). Fills the gap ADR-059 left when it dropped `host.secrets.v1` from the broker. Implemented by plan 129; the `SecretsNotImplemented` gate in `mvm-ir/src/validate.rs` lifts when 129 lands. Backs claims 12 + 13.

## Context

The guest is the untrusted workload. A raw secret reaching it can be exfiltrated, logged, or baked into a snapshot. The requirement: **a raw secret value never enters guest RAM.** The workload still needs secrets to reach external services (an API key, a SigV4 signature, a webhook HMAC).

The model already half-exists. `mvm-ir` carries `EnvValue::SecretRef` — a secret-store *key* plus a mount shape, never bytes ("No secret bytes ever live in this struct"). `mvm-sdk/src/runtime_substitution.rs` (ADR-049) resolved placeholders over vsock so the *guest* SDK could sign — but that brings the credential into the guest, which we now reject. ADR-059 dropped the broker's `host.secrets.v1` handler without a replacement, so the subsystem is gated (`SecretsNotImplemented`).

Constraints that shaped the decision:

- **Same story with or without `mvmd`.** mvm runs standalone (local dev) and under `mvmd` (production, multi-tenant). The secret API, the workload's view, and the substitution flow must be identical; only the value's *source* differs.
- **No hardware requirement.** Requiring a Secure Enclave/TPM to run the demo is an unacceptable DX. Hardware sealing must be a transparent upgrade, never a gate.
- **Don't trust-the-host-with-everything more than necessary.** ADR-002 trusts the host, but the blast radius of a host bug should be one small audited component, not "every secret in plaintext in a general proxy." (This is where the adjacent MITM-everything designs are weakest: one proxy terminates all guest TLS and sees every secret.)

## Decision

A secret is a reference. The host substitutes the real value into outbound traffic at the egress boundary; the guest holds only a placeholder. Four parts.

### 1. Mechanism — proxy-native transparent substitution (SDK optional)

> **Update (plan 129 Stage 2 — proxy-native is the primary path).** The
> original framing below made SDK-cooperative routing primary and the non-SDK
> path a "coverage boundary." That is now inverted. The **transparent host-side
> terminator** is the primary mechanism: an nft `nat` REDIRECT steers the
> guest's outbound `:80`/`:443` to a per-VM terminator that recovers the
> original destination (`SO_ORIGINAL_DST`), substitutes on bound hosts, and —
> for `https` — terminates TLS under a **per-VM name-constrained intermediate**
> the guest trusts (ADR-004), splicing unbound hosts through untouched. A
> generic `curl https://<bound-host> -H "Authorization: Bearer $PLACEHOLDER"`
> with **no SDK** now gets the real credential substituted host-side. The SDK
> forward-proxy (`HTTP_PROXY` + placeholder env) remains supported as an
> alternative, but is no longer required. The claim-12 allow-list and claim-13
> "no value to the guest / metadata-only audit" invariants are identical on both
> paths. The §"Coverage caveat" below is superseded for **bound** hosts (they
> substitute SDK-or-not); an unbound destination still gets the placeholder
> dropped, which remains the correct failure.

The workload's HTTP client routes a secret-bearing request to a **host substitution endpoint** (configured by the SDK / proxy env), carrying a placeholder token where the secret goes. That hop is host-local (vsock / UDS), so its plaintext is fine — the host is in the TCB and the channel has no third-party observer. The host endpoint:

1. checks the destination is allow-listed for that secret (binding-gated — claim 12),
2. substitutes — injects the value (bearer) or delegates to the signer (signing-based, §3),
3. makes the **real TLS** to the destination and streams the response back.

The workload never makes its own TLS to the destination for a secret-bearing request and never holds the value. We do **not** MITM the guest's other TLS — only requests the workload explicitly routes for substitution are seen host-side.

The egress proxy (claim-10 default-deny, ADR-004 `NetworkProvider`) is the catch-all underneath: **all** egress traverses it. Secret-bearing requests are routed for substitution; everything else is policy-checked and **leak-scanned** — a placeholder or a known secret value appearing in non-substitution egress is dropped and audited. This is the "detect" backstop for the case a workload tries to smuggle a placeholder out a side channel; it cannot smuggle a *value* because it never had one.

Coverage caveat, stated honestly: a workload that bypasses the SDK and emits a placeholder via a raw `curl` to an arbitrary host gets the placeholder dropped (the proxy never substitutes for an unbound destination), not a secret. That is the correct failure — you only get substitution on the bound path.

### 2. Resolver — pluggable, identical story with or without `mvmd`

A `SecretResolver` trait resolves a `SecretRef` (name + auth-type + allowed-hosts) to material at substitution time. Two backends, same trait:

- **Local** — the OS keyring / encrypted file. This is the existing `KeyProvider` in `mvm-core` (`keystore.rs`: Keyring/File/Env), so it largely exists. Define with `mvmctl secret set <NAME> --host <allowed-host> --type sigv4|bearer|hmac`. No `mvmd`.
- **mvmd** — the same trait, backed by the tenant control plane (a separate mvmd plan).

The `Sandbox` API, the placeholder, the egress flow, and the audit are identical on top. The resolver is an implementation detail the workload never sees. Dev (Local) → prod (mvmd) is one continuous story, not two systems.

### 3. Keyholder — software-first, hardware-optional, split by auth-type

How the secret is *used*, independent of where its value came from:

- **Signing-based (SigV4, HMAC webhooks, JWT/OAuth client-assertion):** a jailed **signer** receives the canonical request and returns a signature. The key never goes on the wire. If a Secure Enclave / TPM is present the key is sealed there and signing is a hardware op — **the host never sees the plaintext key.** If not, a confined software signer decrypts-signs-zeroizes (key encrypted at rest via 122's DEK/KEK). Same flow; the property strengthens with hardware. This reuses the `mvm-hostd` separate-signer-process model and the keyless `core::subprocess` scaffold.
- **Bearer / basic (the value is transmitted):** the raw value must hit the wire, so a host component must see it — there is no way around that, and we will not overclaim otherwise. We confine it: decrypted only inside a minimal jailed **injector** that terminates TLS to the bound destination, injects, and zeroizes; encrypted at rest; never written to disk in plaintext; never to the guest. Blast radius is one audited component scoped to that secret's destinations. The design steers integrations toward signing schemes (most cloud APIs offer HMAC/assertion) so the hardware-sealed path covers as much as possible and bearer is the fallback.

**No hardware is required.** The default is pure software: encrypted at rest with a software-managed key, and the OS keyring (software-backed by default; on macOS it can ride the Secure Enclave for free with no setup). Hardware sealing changes nothing about the DX or the demo.

Honest framing for the docs and tests: *software default = encrypted at rest, decrypted only in a minimal jailed keyholder; hardware = never seen.* Same code path.

### 4. IR contract, placeholder, audit

- **`SecretRef`** gains `auth_type` (`sigv4 | hmac | bearer | basic`, extensible) and `allowed_hosts` (wildcards like `*.internal.corp`) alongside the existing name + mount shape. Still no bytes. The validator's `SecretsNotImplemented` gate is replaced by real resolution.
- **Placeholder** is an opaque, per-session, single-use token (not the secret name) so a leaked placeholder reveals nothing and can't be replayed for a different session or destination.
- **Audit** (chain-signed, claim-13 lineage): every substitution emits a `secret.substituted` entry (name, destination, auth-type — never the value); every dropped leak emits `secret.placeholder_dropped`. `mvm_supervisor::verify_audit_chain` covers it; `mvmctl audit verify` surfaces drift.

## Consequences

- Stronger than a general MITM proxy: signing keys can be hardware-sealed and never seen; the host sees only the requests the workload routes for substitution, not all its TLS; bearer values are confined to one audited component.
- The demo runs with no hardware and no `mvmd`: `mvmctl secret set` + run.
- The SDK-cooperative path requires the workload to use the mvm SDK (or proxy env) for secret-bearing calls. The proxy's default-deny + leak-detector make the non-cooperative path fail safe (placeholder dropped), so this is a coverage boundary, not a hole.
- Claims 12 (binding-gated dispatch) and 13 (no raw secret to the guest) are restored, with a CI leak-gate built in plan 128 asserting (a) no raw secret crosses to the guest, (b) substitution only fires for bound destinations, (c) the audit chain carries no secret bytes.

## Alternatives considered

- **TLS MITM of *all* guest egress** (the adjacent-SDK approach). Rejected: the host terminates every TLS session and sees all plaintext, the guest's end-to-end TLS is broken, and it requires the guest to trust a long-lived blanket-trust host CA. Maximum host visibility for a platform whose pitch is minimal blast radius. **Note (plan 129 Stage 2):** the scoped terminator we *did* build is not this — it terminates **only bound hosts** (the host already sees their plaintext via substitution → zero added visibility), splices everything else untouched, and trusts a **per-VM name-constrained** intermediate that cannot vouch for any host outside the plan's allow-list (ADR-004), not a blanket CA.
- **Pure SDK-cooperative with no proxy detection.** Rejected: no backstop for a placeholder leaking via a non-cooperative side channel. The default-deny proxy + leak-scan is cheap and closes it.
- **Hardware-sealed required.** Rejected: unacceptable DX; hardware is a transparent upgrade, not a gate.
- **Resolve into the guest for signing** (ADR-049). Rejected and superseded: it brings the credential into guest RAM, which is the thing we are eliminating. Signing moves to the host keyholder.

## Claim — Egress substitution keeps a raw secret off the guest (consolidated from specs/claims/claim-egress-no-secret-to-guest.md)

---
claim: egress-no-secret-to-guest
status: Preview
gated_phrases:
  - "egress secret substitution"
  - "raw secret never reaches the guest"
  - "no secret value reaches the guest"
exempt_paths:
  - "specs/**"
  - "CHANGELOG.md"
  - ".github/**"
  - "memory/**"
  - "crates/mvm-core/src/egress_substitution.rs"
  - "crates/mvm-core/src/lib.rs"
  - "crates/mvm-hostd/**"
  - "public/src/content/docs/contributing/adr/**"
---

# Egress substitution — a raw secret never reaches the guest

## Assertion

The egress substitution model (ADR-067) keeps raw secret values off the
untrusted guest. The guest receives an opaque placeholder
(`mvm-secret-<hex>`) where its credential would go; the host substitution
endpoint holds the real value and substitutes it on the outbound forward
leg, after binding-checking the request's destination. Three invariants
back this:

- **(a) No secret value reaches a guest-facing artifact.** The
  `(var, placeholder)` pairs handed to the guest, and the guest
  environment derived from them, carry only opaque placeholders — never
  the value.
- **(b) Substitution fires only for bound destinations (claim 12).** A
  placeholder bound to host A and routed to host B is refused before the
  forward leg runs; the real credential is never substituted toward an
  unbound destination.
- **(c) The audit chain carries no secret bytes (claim 13).** A
  successful substitution records a `secret.substituted` metadata event —
  name, destination, auth-type — but never the secret value.

`mvmctl audit verify` continues to detect drift on the audit chain;
tampering with any field of a `secret.substituted` entry breaks the chain
signature.

## Threat

The guest is the untrusted workload. A raw secret reaching guest RAM can
be exfiltrated, logged, baked into a snapshot, or sent to an
attacker-controlled host. A future refactor of the substitution path
could silently regress any of the three invariants — handing the value
into the guest env, substituting toward an unbound host, or writing the
value into the audit chain — with no test noticing. This leak-gate is the
standing backstop: a distinctive canary value
(`CANARY-SECRET-VALUE-MUST-NOT-LEAK`) is driven through the path, and the
assertions name exactly which surface leaked if it ever appears where it
must not.

## CI gate that ratifies the claim

The canary leak-gate runs on every PR via the normal Test lane
(`crates/mvm-hostd/tests/egress_secret_leak_gate.rs`), with three
witnesses:

- `fn:handed_placeholders_never_contain_the_secret_value` — puts the
  canary in a `FileSecretStore`, binds it to a host, calls
  `SubstitutionService::from_plan`, and asserts every handed placeholder
  is `mvm-secret-`-prefixed and carries the canary in none of them; also
  that `secret_placeholder_env` (the guest env) contains the canary in no
  value. (invariant a)
- `fn:substitution_endpoint_refuses_unbound_destination` — a placeholder
  bound to host A, a request routed to host B, asserting the endpoint
  refuses and the forwarder never saw the request. (invariant b /
  claim 12)
- `fn:audit_chain_carries_no_secret_value` — drives a successful
  substitution with a recorder + the canary secret, reads the chain file,
  and asserts it contains `secret.substituted` but never the canary value.
  (invariant c / claim 13)

`xtask check-claim-catalog` resolves these three `fn:` witnesses against
the tree on every PR, so renaming or deleting one trips the gate.

## Status

- **2026-06-11**: leak-gate filed at status `Preview`. The egress
  substitution model is delivered (plan 129) and these invariants are
  enforced; the claim's guarded phrases stay blocked in user-facing
  surface until a maintainer promotes it.

Promotion to a numbered claim in the ADR-002 source-of-truth table is the
maintainer's call — exactly like the OCI image provenance claim
(`claim-10-oci-image-provenance.md`), which is tracked via its own doc
and only later folded into the numbered set. This doc + the catalog row
register the witnesses for machine-checking without asserting the claim
in ADR-002's prose.

## Cross-refs

- ADR-067 §"Decision" — egress substitution, never in the guest; the
  per-VM name-constrained terminator and the placeholder model.
- ADR-002 §"Security model" — claims 12 + 13, which these invariants
  reinforce on the egress (vs. broker) delivery.
- `specs/claims/catalog.md` — the witness ledger row for this leak-gate.
- `specs/claims/claim-10-oci-image-provenance.md` — the precedent for a
  not-yet-numbered claim tracked via its own doc.


## Consolidated from ADR-049 — TLS substitution mechanism for guest secret placeholders

- **Status: SUPERSEDED 2026-05-28 by [ADR-059](059-host-services-broker.md).** Runtime secret substitution is no longer an mvm responsibility in v1. The vsock-substitution-vs-TLS-proxy comparison below is kept as historical context; the design itself is not being implemented. `host.secrets.v1` and `mvm-secrets-dispatcher` are dropped from Plan 104.
- Date: 2026-05-14 (superseded 2026-05-28)
- Owner: MVM Project
- Related: ADR-002 (microVM security posture), ADR-004 (egress policy), ADR-041 (signed audited execution plans), ADR-041 (claim-safe sandbox parity), [ADR-059 (rescope — drop secrets)](059-host-services-broker.md), Plan 74 W2 + W3, Plan 74 §Risks R9

## Context

Plan 74 W3 makes the secret-non-leakage claim defensible: workloads
receive an opaque `mvm-secret://<grant-id>` placeholder instead of
the real secret value, and the host swaps the placeholder for the
real value at egress time, only when destination policy passes.

ADR-041 §"Secret non-leakage" gates the claim on
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
  (ADR-041 documents this as "not a non-leakage claim").
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
  env/file flow. ADR-041 §"Non-goals" already forbids this.

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
