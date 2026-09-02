# A residency nobody configured stops failing launches

`machine run --hypervisor libkrun` could not boot on a macOS 26 host:

```
Error: claiming configured warm standby
Caused by:
    0: requested standby-pool recovery
    1: libkrun: standby pool is not supported by this backend
```

Nothing was configured. On the HVF default tier `resolve_residency` returns
`always_warm` on its own, so `effective_warm_pool_size(None)` hands every
transient run a warm target of 1 — including runs that name a backend with no
standby pool. Three capability gates then turned that inherited default into a
hard error. The message said "configured", and the code comment beside it said
only an explicitly configured pool should refuse; the path that produced it
had no explicit configuration anywhere, because `MachineRunMode::warm_pool_size`
is called with `None` and nothing else reaches `try_warm_claim` outside tests.

The three gates now ask where the target came from.
`unsupported_standby_pool_is_fatal` is pure over `ResidencySource`: an
`EnvOverride` is an operator asking for warm by name and still refuses, so
choosing a backend that cannot serve it is not hidden; an `AutoDetect` default
yields and the launch cold-boots.

`MVM_HVF_WARM_REQUIRE_CLAIM=1` is unaffected — `claim_with_mode` answers that
with its existing `BackendUnsupported` refusal before this decision is reached.

Left alone deliberately: `machine/runtime.rs` still zeroes the warm target for
`--hypervisor wasm` by name. That carve-out is the same bug fixed for one
backend by string comparison, and it is now redundant, but removing it changes
what `warm_pool_size` is on the wasm path for every downstream reader of the
value — worth doing on its own, not folded into this.

Witnesses: `try_warm_claim_cold_boots_a_host_default_pool_on_an_unsupported_backend`,
`try_warm_claim_refuses_an_operator_configured_pool_on_an_unsupported_backend`,
`a_host_default_warm_target_yields_to_a_backend_with_no_pool`, and
`an_operator_set_residency_still_refuses_a_backend_with_no_pool`. Confirmed
live: `machine run --hypervisor libkrun --allow-host example.com:80` boots,
authenticates FlowMux and fetches the page with no `MVM_RESIDENCY` set, and the
HVF default path is unchanged.
