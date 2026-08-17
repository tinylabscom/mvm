# Named service bindings (`--provider`)

Delivered 2026-08-16. Follows the single-host-predicate cleanup (#2573), which
removed the dead second binding model this builds on top of.

## Why

`mvmctl secret set --host …` made the operator hand-type the destination a
credential may reach. That field does not fail loudly when it is wrong: a typo
withholds the credential and surfaces as an unrelated upstream auth error, while
a wrong-but-plausible host sends a live credential somewhere unintended.
`host_is_bound` faithfully enforces whatever was recorded, so nothing downstream
can tell the host that was typed from the host that was meant.

## What shipped

`mvm_contract::service_catalog` — `ServiceProvider` / `ServiceCatalog`, `no_std`
+ alloc (builds on `wasm32-unknown-unknown`), modelled on the existing
`Catalog`/`CatalogEntry` in `mvm-core/src/catalog.rs`. Five curated entries.

`mvmctl secret set --provider <name>` resolves hosts + auth type + SigV4 scope
service from the entry; mutually exclusive with `--host`/`--type`, which remain
for uncatalogued destinations. `mvmctl secret providers [--search]` lists the
set. `mvmctl secret ls` names the authoring provider.

`SecretBindingMeta.provider: Option<String>` (`#[serde(default)]`, so existing
records read unchanged).

## The load-bearing choice

A provider is expanded **once, at `set` time**, and the literal hosts are stored.
Enforcement still reads `allowed_hosts`; the catalog is never consulted on the
forward path. That keeps the egress path free of catalog I/O, keeps the enforced
set auditable as literal hosts, and — most importantly — means a later catalog
edit cannot silently widen a binding that already exists.

An unrecognised provider **refuses**, naming the known set and the
`--host`/`--type` escape hatch. It does not fall through to the explicit form and
does not resolve to a default.

## Witnesses

All in `crates/mvm-cli/src/commands/ops/secret.rs`, each mutation-checked (the
mutation was applied, the test confirmed red, then reverted):

| witness | mutation that must turn it red |
|---|---|
| `provider_resolves_to_its_catalog_hosts_and_auth_type` | resolution ignores the entry's auth type |
| `unknown_provider_refuses_rather_than_falling_through` | unknown name falls through to the explicit form |
| `provider_and_explicit_host_are_mutually_exclusive` | `--provider` stops conflicting with `--host` |
| `binding_records_resolved_hosts_not_the_provider_name` | the provider name is stored as a host |
| `a_sigv4_provider_supplies_the_scope_service_but_not_the_account` | a region is invented instead of demanded |

Plus `catalog_entry_rejects_mismatched_auth_scope` and ten unit tests on the
catalog type itself.

## Scope note

No claim row changed. This narrows how a binding is *authored*; what claims 12
and 13 guarantee once a binding exists is untouched. ADR-044 records the
decision.

## Deliberately not done

`WebFetchTool`'s per-tenant allow-list still uses exact `contains` where the
secret path uses case-insensitive wildcard matching. Different policy surface;
unifying them would silently change its documented semantics. It remains an
explicit, reasoned exemption in `xtask check-single-host-predicate`.

Workload identity federation — short-lived plan-bound tokens exchanged at the
provider, so no long-lived secret sits in `secret_store` at all — is the
destination this unblocks: you cannot federate "to a provider" while a provider
is a free-text host string. It needs a stable issuer a customer configures once,
so it belongs in mvmd, not here.
