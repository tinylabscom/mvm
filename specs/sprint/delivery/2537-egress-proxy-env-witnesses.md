# 2537 — witnesses for the upstream-proxy egress config

## Found by the lane, not by reading

The first nightly after #2540 and #2565 landed reported `mvm-vmm` red with
**four survivors nobody had seen before**, all in
`EgressProxySpawnConfig::from_host_env`
(`crates/mvm-vmm/src/host/network_endpoint_spawn.rs`):

- `from_host_env -> None`
- `from_host_env -> Some(Default::default())`
- `delete !` in the `.filter(|v| !v.is_empty())` that drops empty values
- `||` → `&&` in `(cfg.https.is_some() || cfg.http.is_some())`

The function arrived with #2502, which routes the workload egress forward leg
through an upstream proxy. It landed on a file already on the claim-10 mutation
surface, so the surface pin did not change and nothing flagged it — the file was
already covered, the new function inside it was not.

## Why they matter

Each one silently disables or corrupts proxy configuration on the egress path:

- `-> None` — a configured host dials direct. Every proxied environment
  silently stops using its proxy.
- `-> Some(Default::default())` — looks configured, forwards nothing.
- the `!` deletion — inverts empty-filtering, so a real proxy value is
  discarded and an empty one is kept.
- `||` → `&&` — a host with only one leg set reads as unconfigured, which is
  the shape most http-only and https-only environments actually have.

None was detectable by any existing test: the function had no direct coverage.

## What shipped

Six tests in the file's own `mod tests`, using `mvm_core::util::test_env::TestEnv`
rather than a new helper. Each clears all eight proxy names first, so a
contributor whose shell exports one does not get a different answer from CI.

Coverage is behavioural rather than mutant-shaped — unconfigured stays
distinguishable from configured-with-nothing, either leg alone counts,
empty and whitespace read as unset, `no_proxy` alone configures nothing, and
`all_proxy` fills both legs without overriding a specific one.

## Evidence

Each of the four mutants was hand-applied and the suite re-run:

| mutant | result |
|---|---|
| `-> None` | 3 failed |
| `-> Some(Default::default())` | 6 failed |
| `delete !` | 4 failed |
| `\|\|` → `&&` | 2 failed |

Restored: 538 passed, 0 failed in `mvm-vmm`. `fmt`, `clippy -D warnings`,
`check-mutation-witnesses`, `check-test-home-isolation`,
`check-no-network-literals` and `check-no-spec-refs-in-comments` all clean.

## Note

The failure detail came out of the artifact #2565 added, not the logs — the run
was still in progress and GitHub withholds job logs until a run completes. That
upload existed for the shard that dies without saying why; it turned out to be
just as useful for the shard that fails while its siblings are still going.
