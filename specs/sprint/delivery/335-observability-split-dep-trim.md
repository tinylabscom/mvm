# 335 — Split subscriber assembly out of `mvm-core`; gate the guest agent's

Installing a global tracing subscriber is a *binary* concern. `mvm-core` — the
crate every consumer links, including the sealed guest agent and the embedded
musl host binaries — owned it, and so carried `tracing-subscriber` (~32 crates)
for 248 of its 2562 observability lines.

New `mvm-observability` crate takes `logging.rs` and the span-timing `Layer`.
Everything else stays in `mvm-core`: `metrics`, `instance_metrics`, and the
span-timing registry/histogram/Prometheus rendering, because `MetricsSnapshot`
is part of the **agent wire protocol** (`AgentResponse::Metrics`) and the guest
agent reads it.

`mvm-agentd` had the identical bug: `tracing-subscriber` declared
non-optionally, but used only in `src/bin/` by the three `addons`-gated helper
bins. The sealed agent never installs a subscriber. Now gated behind `addons`,
exactly as `tokio` and `hickory-proto` already were.

## Measured

| Closure | Before | After |
|---|---|---|
| `mvm-core` | 110 | **101** |
| `mvm-agentd` (sealed guest agent) | 111 | **102** |
| `mvm-build` (embedded musl bins) | `tracing-subscriber` present | **absent** |
| `mvmctl` (shipped) | 243 | **244** |

The shipped binary gains one crate: `mvm-observability` itself. It carries no
new third-party code — `tracing-subscriber` was already there via `mvm-core`.
`CLOSURE_BUDGET` bumped 243 -> 244 with that justification.

## Long-tail deps: measured, mostly kept

Cutting on call-site count would have been wrong. Measured footprint instead:

- **`ipnet`** — sole use is inside `#[cfg(test)]`; moved to `[dev-dependencies]`.
  Hygiene only: `mvm-contract` pulls it legitimately, so **zero** closure change.
- **`unicode-normalization`** (3 crates) — Unicode NFC. Kept; hand-rolling
  normalization tables is not a defensible trade.
- **`x25519-dalek`** — crypto, shares curve25519 with `ed25519-dalek`. Kept.
- **`aho-corasick`** (2) — backs secret scanning and the command gate. Kept.
- **`keyring`** (2), **`bs58`** (1, no transitive deps) — nothing to gain. Kept.

## Duplicate majors

Only four reach the shipped binary: `bitflags`, `getrandom`, `rand`,
`rand_core`. `bitflags 1.3` comes from third-party `smoltcp`. The other three
collapse into one fix — the workspace pins `rand = "0.8"` while `hickory-proto`
needs `0.10`.

**Deferred to its own PR.** The 14 `rand` call sites in `mvm-agentd` alone
include `SigningKey::from_bytes(&rand::random::<[u8; 32]>())` and X25519
ephemeral secrets. Cryptographic seed generation across a breaking API change
(`thread_rng` -> `rng`, `gen` -> `random`) deserves isolated review.

## Note on build time

This changes build time by roughly nothing, and was never expected to.
Dependencies are cached and do not recompile on an inner-loop edit; that was
measured separately (see `specs/plans/334-build-critical-path.md`). The
justification here is **security surface**: what the sealed guest agent and the
embedded musl binaries link.
