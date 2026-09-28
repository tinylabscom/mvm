# Composable policy: groups, authored profiles, the resolved manifest

What a workload may do was spread across `mvm.toml`, `--grants-file`, workload
IR and flags, and the one resolved artifact — the signed `ExecutionPlan` — could
be neither printed nor supplied. `mvm_client::policy_profiles` adds three layers,
library-first, so the CLI and the host library share one implementation.

**Groups** are named TOML fragments covering network (allow, deny, block,
endpoint routes), secrets (names and destinations), shares, env (allow, deny,
and the `readmit` escape hatch), a `[tools]` stub, and resource ceilings. A
group can be `required`. **Profiles** add `extends` (one or many), `groups`
include/exclude, `[[when]]` os/arch/backend blocks and `[overrides]`.
`deny_unknown_fields` throughout; every error names the file, the layer and the
key.

**Merge rules**, each with positive and negative tests: allows union; denies
union and beat allows; once blocked the network stays blocked and `block =
false` below is an error; a required group cannot be excluded; a secret's
destinations only narrow, and the launch still checks them against the
allow-list stored with `mvmctl secret set`; a share is writable only if every
layer says so; resource bounds are ceilings, smallest wins; `env.readmit` is
honoured only in user-authored layers (`LayerOrigin::Pack` exists for signed
packs). Cycles are named, and `extends` is capped at ten levels.

**Discovery**: `--plan FILE`, then `--policy NAME|PATH`, then the project's
`mvm.toml` `[policy]` table (new), then nothing. Names resolve in
`$MVM_HOME/config/policy/{profiles,groups}` (new `mvm-core::config` helpers),
then among embedded built-ins: groups `registries`, `github`, `llm-apis`,
`offline` (drift-tested against the network presets) and profiles `default`,
`dev-network`, `agent-apis`, `offline`. `ns/name[@ver]` pack references parse
and are refused. The flag is `--policy`, not `--profile`: `--profile` already
selects the run's security tier (restrictive/standard/dev/permissive).

**Resolved manifest = the signed plan.** A resolved policy is folded into the
launch's own flags (`--allow-host`, routes, `--secret`, `--mount`,
`--allow-env`, `--cpu-limit`, `--timeout`), with the flags as the last layer —
they add to allows and cannot reach denies, blocks or ceilings — and from there
takes the one road every launch takes: grant resolution, synthesis, signing,
admission. A test admits a profile and the equivalent flags through the real
admission path and compares the plans. `mvmctl policy resolve` writes the
manifest; `run --plan FILE` reads it back, re-validates it, refuses a plan or
signature inside it, and is exclusive with every policy flag.

**One resolution for every verb.** The project's `[network] allow_hosts`
used to reach only `machine create --manifest`; `run` and `machine run` never
read it. It is now a project layer of the resolved policy, applied the same way
by `run`, `machine run`, `machine create` and `machine start --manifest` —
unioned with profiles and flags, under their blocks and denies. A test resolves
one project through all three verbs and compares the allow lists. `machine
create` records the network and resource result in its spec and refuses a
policy carrying secrets, shares, re-admitted variables or routes rather than
dropping them on restart. A `--allow-host` alongside a manifest's hosts now
unions with them on `machine create` instead of replacing them.

**CLI**: `mvmctl policy resolve|show [--format toml|json|plan]|validate
[--strict]|diff|groups`; `--policy`/`--plan` on `run` and `machine run`.
`policy` is now a top-level verb: it covers only a workload's own authored
policy; tenant policy bundles stay in mvmd, and the test that pinned that now
pins the tenant verbs instead.

**Schema**: `schema/policy-profiles-v0.json` and
`reference/policy-schema.md`, both drift-tested under `--features schema`, run
by a new `lint-features` step.

**Not yet**: `[tools]` is not enforced (PS-13); packs are refused (PS-06);
policy routes are refused on a persistent machine, like `--allow-endpoint`; the
host library has no `policy.*` method yet — the library is ready for one.
