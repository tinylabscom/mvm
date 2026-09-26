# ADR-023: Secrets subsystem — egress substitution, never in the guest

## Status

Accepted

## Context

The guest is the untrusted workload. A raw secret value that reaches
guest RAM can be exfiltrated, logged, or baked into a snapshot. The
workload still needs secrets to reach external services — an API key, a
SigV4 signature, a webhook HMAC — so the requirement is narrower than
"never touch secrets": a raw secret value must never enter the guest, and
the same story must hold whether mvm runs standalone (local dev) or under
a fleet control plane (only the value's source differs). No hardware
requirement (Secure Enclave/TPM) may gate the demo path — hardware
sealing must be a transparent upgrade, never a prerequisite.

## Decision

A secret is a reference. The host substitutes the real value into
outbound traffic at the egress boundary; the guest holds only an **opaque
placeholder the host mints** — `mvm-secret-` and 48 random hex characters,
one per plan binding — never the value. Each placeholder is valid only for
the destinations its own binding names.

### Mechanism — host-side termination of a flow to a bound host, no SDK required

The guest has no network interface. Every outbound connection leaves over
the vsock `NetworkFlow` channel to the per-VM `mvm-network-endpoint`,
which admits it against the egress policy before anything is dialled. A
client that honours the guest's proxy environment reaches the endpoint
either as a typed HTTP request or as a `CONNECT` tunnel. When an admitted
TCP flow names a host that a secret is bound to, the endpoint terminates
it instead of relaying it: on `:443` under a leaf minted by a per-VM
name-constrained CA the guest trusts, on `:80` in cleartext. Each request
is then read and put through the same substitution pipeline as a typed
request, so the destination bind check, redaction and metering apply in
one place. A flow to any other host is relayed opaquely and never
decrypted. A bound host the endpoint cannot terminate — another port, or
no per-VM CA — is refused rather than relayed, since relaying it would put
the placeholder on the wire. A plain `curl https://<bound-host> -H
"Authorization: Bearer $PLACEHOLDER"` using the proxy environment, with no
SDK cooperation, gets the real credential substituted host-side.

The workload never makes its own TLS handshake to the destination for a
secret-bearing request and never holds the value. The endpoint originates
the upstream TLS connection itself and verifies the destination's
certificate the ordinary way; a destination that fails verification gets
nothing, and the guest gets a `502`. There is no fallback to relaying the
guest's own bytes for a bound destination — not on a TLS error, not on an
exhausted termination budget. The host does not MITM the guest's other TLS
sessions — only flows to a bound destination are opened host-side, and only
for that destination.

Within a terminated flow, substitution happens only in request headers, and
only for a placeholder whose binding admits the flow's destination. A
placeholder presented to a destination its binding does not name is refused
before the forward leg runs and recorded as `secret.placeholder_dropped`; one
in the request URL or body is refused and recorded as `secret.flow_refused`.
The typed HTTP path applies the same checks. A tunnel to a destination no
secret is bound to is relayed opaquely, so a placeholder sent down one leaves
the VM as the meaningless token it is — the endpoint does not see inside it,
and there is no value in it to leak.

### Where the destinations come from

`mvmctl secret set` records a secret's destination allow-list and auth type in
the host binding store. A run binds a stored secret with `--secret
NAME[:HOST,...]` on `mvmctl run` / `mvmctl machine run`, or through a
Workload IR declaration. The binding the signed `ExecutionPlan` carries names
the guest variable, the keystore address and, optionally, a destination list.
At assembly the endpoint reads the stored allow-list and narrows it to the
plan's destinations; a plan destination the stored allow-list does not admit
fails the launch rather than widening the binding. The per-VM CA's name
constraints and the substitution registry are computed from the same narrowed
set, so the certificate and the enforcement cannot disagree. Unknown secrets,
secrets with no binding, and out-of-allow-list destinations are refused before
the VM boots.

### Resolver — pluggable, identical story with or without a fleet control plane

A `SecretResolver` trait resolves a secret reference (name + auth-type +
allowed-hosts) to material at substitution time. The local backend is the
OS keyring or an encrypted file (`KeyProvider` in `mvm-core::crypto`:
`KeyringProvider` layered over a file fallback), configured with `mvmctl
secret set <NAME> --host <allowed-host> --type sigv4|hmac|bearer|basic`.
A fleet-backed resolver implements the same trait against a tenant
control plane. The placeholder, the egress flow, and the audit trail are
identical on top; the resolver is an implementation detail the workload
never sees.

### Keyholder — software-first, hardware-optional, split by auth-type

How a secret is *used* is independent of where its value came from:

- **Signing-based** (`Sigv4`, `Hmac`): a jailed signer receives the
  canonical request and returns a signature. The key never goes on the
  wire. Sealed in a Secure Enclave/TPM when present — the host never sees
  plaintext key material; otherwise a confined software signer
  decrypts-signs-zeroizes. Same flow either way; the property only
  strengthens with hardware.
- **Injected** (`Bearer`, `Basic`): the raw value must hit the wire, so a
  host component necessarily sees it. It is confined to the per-VM
  network endpoint, which terminates the guest's flow, injects, originates
  verified TLS to the bound destination, and zeroizes — never written to disk in plaintext, never to
  the guest. Blast radius is one audited component scoped to that
  secret's destinations.

No hardware is required: the default is encrypted-at-rest with a
software-managed key, decrypted only inside the minimal jailed keyholder.
Hardware sealing changes nothing about the code path, only what the host
process ever sees.

### IR contract, placeholder, audit

- A workload's secret reference (`mvm_contract::ir::Workload`) carries
  `auth_type` (`Sigv4 | Hmac | Bearer | Basic`) and `allowed_hosts`
  (exact host or `*.suffix` wildcard) alongside its name and mount shape
  — never bytes. IR validation refuses a secret reference with no
  `allowed_hosts`: an unbound secret is a build-time error, not a
  runtime surprise.
- The placeholder handed to the guest is an **opaque token the host
  mints** at boot from the OS random source, one per plan binding, under the
  guest variable the binding names. Substitution fires only when the token
  was minted in this VM's session **and** the request is bound for a
  destination that binding admits; a token the session never minted is
  refused. A leaked placeholder reveals nothing about the value and cannot
  be substituted for a destination outside its binding — the security is the
  destination binding and host-side-only injection, not the token's opacity.
- Every substitution emits a `secret.substituted` audit entry (name,
  destination, auth-type — never the value) when the request is handed to the
  forward leg, before any response, so a forward that fails after sending
  still records that the credential went out. A separate
  `secret.forward_outcome` entry records how the forward ended. Every dropped
  leak emits a drop entry. The chain-signed audit verifier covers both; `mvmctl trust
  audit verify` surfaces drift.

## Consequences

- Stronger than a general MITM proxy: signing keys can be hardware-sealed
  and never seen by the host process; the host sees only the requests a
  workload routes to a bound destination, not all of its TLS; injected
  values are confined to one audited component.
- The demo path runs with no hardware and no fleet control plane:
  `mvmctl secret set` plus a run.
- A workload that emits a placeholder to a host its binding does not name
  fails safe: refused on a terminated or typed flow, carried as an inert
  token through an opaque one — never substituted. That is a coverage
  boundary (substitution only fires on the bound path), not a hole.
- A compromised workload can still use the credential through the
  placeholder against a bound destination. Substitution keeps the value
  from being copied out of the VM; it does not limit what the key is used
  for at that destination.

## Alternatives considered

- **TLS MITM of all guest egress.** Rejected: the host would terminate
  every TLS session and see all plaintext, breaking the guest's
  end-to-end TLS for non-secret traffic and requiring a blanket-trust
  host CA. The terminator this ADR ships is narrower by construction — it
  only ever sees plaintext for hosts it already substitutes into, via a
  per-VM name-constrained certificate that cannot vouch for any host
  outside the plan's allow-list.
- **Pure SDK-cooperative substitution with no proxy-side detection.**
  Rejected: no backstop for a placeholder leaking through a
  non-cooperative side channel. The default-deny proxy plus leak-scan is
  cheap and closes it.
- **Hardware-sealed keys required.** Rejected: unacceptable DX; hardware
  is a transparent upgrade, not a gate.
- **Resolve the credential into the guest for in-guest signing.**
  Rejected: it brings the credential into guest RAM, which is exactly the
  exposure this design eliminates. Signing happens host-side, in the
  keyholder.

## Claim — egress substitution keeps a raw secret off the guest

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
  - "crates/mvm-core/src/lib.rs"
  - "crates/mvm-hostd/**"
  - "public/src/content/docs/contributing/adr/**"
---

### Assertion

The guest receives an opaque host-minted placeholder where its
credential would go; the host substitution endpoint holds the real value
and substitutes it on the outbound forward leg, after binding-checking
the request's destination. Three invariants back this:

- **No secret value reaches a guest-facing artifact.** The env/argv pairs
  handed to the guest carry only opaque placeholders — never the value.
- **Substitution fires only for bound destinations.** A placeholder bound
  to host A and routed to host B is refused before the forward leg runs.
- **The audit chain carries no secret bytes.** A successful substitution
  records name, destination, and auth-type — never the value.

### CI gate that ratifies the claim

`crates/mvm-hostd/tests/egress_secret_leak_gate.rs` drives a distinctive
canary secret through the path on every PR, with three witnesses:
`fn:handed_placeholders_never_contain_the_secret_value`,
`fn:substitution_endpoint_refuses_unbound_destination`, and
`fn:audit_chain_carries_no_secret_value`. `xtask check-claim-catalog`
resolves these against the tree on every PR.

### Status

Filed at `Preview`: the mechanism above is delivered and these invariants
are enforced, but the gated phrases stay blocked from user-facing surface
until a maintainer promotes the claim to the numbered ledger.
