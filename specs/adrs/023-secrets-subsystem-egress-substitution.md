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
outbound traffic at the egress boundary; the guest holds only an opaque
placeholder.

### Mechanism — a host-side transparent terminator, no SDK required

An nftables `nat` REDIRECT steers the guest's outbound `:80`/`:443` to a
per-VM terminator that recovers the original destination
(`SO_ORIGINAL_DST`), substitutes the bound secret into the request, and —
for `https` — terminates TLS under a per-VM name-constrained intermediate
certificate the guest trusts, splicing every unbound host through
untouched. A plain `curl https://<bound-host> -H "Authorization: Bearer
$PLACEHOLDER"` with no SDK cooperation gets the real credential
substituted host-side. An SDK/proxy-env path remains available as an
alternative entry point, but nothing about substitution depends on it.

The workload never makes its own TLS handshake to the destination for a
secret-bearing request and never holds the value. The host does not MITM
the guest's other TLS sessions — only requests routed to a bound
destination are seen host-side, and only for that destination.

The default-deny egress proxy is the catch-all underneath: every egress
packet traverses it. Secret-bearing requests to a bound destination are
substituted; everything else is policy-checked and leak-scanned — a
placeholder or a known secret value appearing outside the substitution
path is dropped and audited. A workload that emits a placeholder toward
an *unbound* destination gets the placeholder dropped, never a secret —
substitution only ever fires for a destination the placeholder is bound
to.

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
  host component necessarily sees it. It is confined to a minimal jailed
  injector that terminates TLS to the bound destination, injects,
  responds, and zeroizes — never written to disk in plaintext, never to
  the guest. Blast radius is one audited component scoped to that
  secret's destinations.

No hardware is required: the default is encrypted-at-rest with a
software-managed key, decrypted only inside the minimal jailed keyholder.
Hardware sealing changes nothing about the code path, only what the host
process ever sees.

### IR contract, placeholder, audit

- A workload's secret reference (`mvm-sdk::ir::workload`) carries
  `auth_type` (`Sigv4 | Hmac | Bearer | Basic`) and `allowed_hosts`
  (exact host or `*.suffix` wildcard) alongside its name and mount shape
  — never bytes. IR validation refuses a secret reference with no
  `allowed_hosts`: an unbound secret is a build-time error, not a
  runtime surprise.
- The placeholder handed to the guest is an opaque, `mvm-secret-`-prefixed
  token, not the secret's name — a leaked placeholder reveals nothing and
  cannot be replayed against a different destination.
- Every substitution emits a `secret.substituted` audit entry (name,
  destination, auth-type — never the value); every dropped leak emits a
  drop entry. The chain-signed audit verifier covers both; `mvmctl trust
  audit verify` surfaces drift.

## Consequences

- Stronger than a general MITM proxy: signing keys can be hardware-sealed
  and never seen by the host process; the host sees only the requests a
  workload routes to a bound destination, not all of its TLS; injected
  values are confined to one audited component.
- The demo path runs with no hardware and no fleet control plane:
  `mvmctl secret set` plus a run.
- A workload that bypasses cooperative routing and emits a placeholder to
  an arbitrary host fails safe — placeholder dropped, not substituted.
  That is a coverage boundary (substitution only fires on the bound
  path), not a hole.

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
  - "crates/mvm-core/src/egress_substitution.rs"
  - "crates/mvm-core/src/lib.rs"
  - "crates/mvm-hostd/**"
  - "public/src/content/docs/contributing/adr/**"
---

### Assertion

The guest receives an opaque placeholder (`mvm-secret-<hex>`) where its
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
