# ADR-044: Named service bindings

Backing: shipped-source
Validation: `provider_resolves_to_its_catalog_hosts_and_auth_type`,
`unknown_provider_refuses_rather_than_falling_through`,
`provider_and_explicit_host_are_mutually_exclusive`,
`binding_records_resolved_hosts_not_the_provider_name`,
`a_sigv4_provider_supplies_the_scope_service_but_not_the_account`,
`catalog_entry_rejects_mismatched_auth_scope`

## Status

Accepted. Refines ADR-023 (secrets subsystem — egress substitution); does not
supersede it. Claims 12 and 13 are unchanged in substance: this narrows how a
binding is *authored*, not what it guarantees once written.

## Context

`mvmctl secret set` records two things about a credential: where it may go
(`allowed_hosts`) and how it authenticates (`AuthType`, plus a SigV4 scope where
that applies). Until now both were typed by hand:

```
mvmctl secret set aws --host s3.amazonaws.com --host '*.s3.amazonaws.com' \
  --type sigv4 --aws-access-key-id AKIA… --region us-east-1 --service s3
```

`--host` is the most dangerous hand-written field in the secrets path, and it
does not fail in the direction that would make a mistake obvious. A typo
*withholds* the credential, which surfaces as an unrelated upstream auth error.
A wrong-but-plausible host does something worse: it sends a live credential to a
destination the operator never intended. Nothing downstream can distinguish the
host that was typed from the host that was meant — `host_is_bound` faithfully
enforces whatever was recorded.

The auth shape has the same problem in milder form. `--type` and the three SigV4
flags are properties of the *provider*, not of the operator's intent, so asking
an operator to restate them is asking them to reproduce a fact they do not own.

## Decision

**A provider is a named catalog entry.** `ServiceProvider { name, description,
hosts, auth, sigv4_service, tags }` and `ServiceCatalog` live in `mvm-contract`
(`no_std` + alloc, so the wasm/verifier tier can read them), modelled on the
existing `Catalog`/`CatalogEntry` pair in `mvm-core/src/catalog.rs` rather than
inventing a second catalog idiom.

There is deliberately no `header` field. The header a credential travels in is
implied by `AuthType`, and `SecretBindingMeta` has nowhere to put one, so
carrying it here would be a field with no sink.

**`--provider` is the ordinary path; `--host`/`--type` remain.** The two forms
are mutually exclusive at the clap layer. Keeping the explicit form is not a
concession: a catalog that cannot express your destination must not become a
wall, and an operator forced to work around a catalog will work around it badly.

**A provider is expanded once, at `set` time, and the literal hosts are stored.**
This is the load-bearing decision. `SecretBindingMeta` gains
`provider: Option<String>`, but enforcement continues to read `allowed_hosts`.
The catalog is never consulted on the forward path. Three consequences follow,
and all three are the point:

- the egress hot path takes on no catalog lookup and no new failure mode;
- the enforcement input stays auditable as literal hosts, so `mvmctl secret ls`
  and the audit chain show what is actually enforced;
- a later edit to a catalog entry cannot silently widen a binding that already
  exists. A binding means what it meant the day it was written.

**An unrecognised provider refuses.** It does not fall through to the explicit
form and does not resolve to a default. A typo'd `--provider` that quietly
became "no restriction" would reintroduce, in a new place, exactly the failure
this ADR removes. The refusal names the known providers and points at
`--host`/`--type`.

**The catalog ships in the binary.** It is code: versioned with the release,
reviewed like code, no file to parse and no fetch to fail. A remote catalog
would put a network dependency on the authoring path for a security-critical
field, trading a typo for an outage.

## Consequences

For every catalogued provider the most dangerous field in the secrets path is no
longer hand-written. `mvmctl secret providers` makes the safe set discoverable,
and `mvmctl secret ls` names the entry a binding came from without changing what
is enforced.

The cost is maintenance. The catalog is a curated list someone has to keep
correct, and a stale entry — a provider that adds an API host — presents as a
withheld credential, which is the same confusing symptom as a typo. This is
mitigated by keeping the catalog short and by the explicit form remaining
available, but it is a real cost and not a rounding error.

`SecretBindingMeta` gains a field. Existing records deserialize unchanged
(`#[serde(default)]`), and a binding authored before this change reports no
provider, which is accurate.

## Alternatives considered

**Validate `--host` against a deny-list of known-bad patterns.** Rejected:
enumerating badness never converges, and it does nothing about a plausible typo,
which is the actual failure mode.

**Make the catalog a forward-path lookup.** Rejected: it puts I/O on the egress
path and makes a binding's meaning mutable after admission. A binding that can
change meaning without anyone editing it is not auditable.

**Infer the region for SigV4 providers.** Rejected: the region is a property of
the operator's account, not the provider. Guessing it would silently bind a
credential to a scope nobody chose.

**Unify with `WebFetchTool`'s allow-list.** Out of scope. That surface is a
per-tenant fetch allow-list over exact hosts — a different policy with different
semantics — and folding it in would silently change its behaviour. See the
exemption in `xtask check-single-host-predicate`.
