# One host-binding predicate

Delivered 2026-08-15.

## What was wrong

Two different public types were both named `SecretBinding`, and only one of
them was live:

| | live | dead |
|---|---|---|
| type | `mvm_contract::plan::types::SecretBinding { name, source }` (re-exported as `mvm_core::plan::SecretBinding`) | `mvm_contract::policy::secret_binding::SecretBinding { env_var, target_host, header, value }` |
| predicate | `host_is_bound` / `host_matches` — wildcard `*.suffix`, case-insensitive, apex-excluded | `decide_substitution` — exact `==`, case-sensitive, single host |
| callers | the keyholder admission + forward path | none; its own tests only |

`host_is_bound`'s doc comment already warned that a second copy of the
quantifier would "only be discovered to disagree by a destination reaching a
secret it should not have". `decide_substitution` was that second copy, and it
already disagreed: `API.Example.com` withholds on the dead path where the live
path substitutes.

Nothing was exploitable, because nothing called it. The cost was legibility —
`rg SecretBinding` returned hits across two unrelated types with no way to tell
them apart, and the dead module's docs presented it as the enforcement point.

## What changed

Deleted, as one self-contained cluster (workspace `--all-targets` was clean
immediately afterward, which is the evidence it really was dead):

- `crates/mvm-core/src/egress_substitution.rs`
- `crates/mvm-contract/src/policy/secret_binding.rs`
- `crates/mvm-core/src/policy/secret_binding.rs`

With them went the `mvm-managed:` placeholder prefix, and the
`the_two_reserved_prefixes_do_not_collide` test in
`crates/mvm-contract/src/substitution.rs` that existed only to keep it distinct
from the live `mvm-secret-` token. That file's "three prefixes" doc table is now
two.

Added `xtask check-single-host-predicate`, registered in the CI Lint job: outside
`crates/mvm-contract/src/ir/workload.rs`, no production source may iterate or
search an `allowed_hosts` set itself. Two files carry a same-named field that is
a different concept and are exempt **by name with a stated reason**, each checked
to still exist so an exemption cannot go stale unnoticed:

- `crates/mvm-client/src/secret.rs` — validates an allow-list's shape at
  `secret set` time; decides nothing about a destination.
- `crates/mvm-hostd/src/supervisor/tools/web_fetch.rs` — `WebFetchTool`'s own
  per-tenant fetch allow-list, a separate policy surface over exact hosts.

## Scope note

This narrows how a destination binding is *decided*, not what claims 12/13
guarantee. No claim row changed. ADR-023's prose was already accurate; only its
`exempt_paths` list named the deleted file.

## Not done here

`web_fetch`'s allow-list uses exact `contains` where the secret path uses
case-insensitive wildcard matching. That is a real inconsistency between two host
allow-lists, but they are different policy surfaces and unifying them would
silently change `web_fetch`'s documented semantics. Left alone deliberately.
