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
