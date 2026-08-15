# Unify duplicate `rand` major: workspace pin 0.8 → 0.10

**Branch:** `feat/rand-unification`

The workspace shipped two copies of `rand` (`0.8` and `0.10`) because
first-party code pinned `0.8` while `hickory-proto` required `0.10`. That
also duplicated `rand_core` and `rand_chacha`, adding three crates to the
`mvmctl` closure.

This change bumps the workspace pin to `0.10`, migrates every first-party
call site, and ratchets the closure budgets.

## What changed

- `Cargo.toml`: `rand = "0.8"` → `rand = "0.10"`.
- `crates/mvm-build/Cargo.toml`: switched the test-only `rand` dependency
  from a direct `"0.8"` pin to `rand.workspace = true` so it stays unified.
- Migrated ~181 call sites across 9 crates plus integration tests:
  - `rand::thread_rng()` → `rand::rng()`
  - `.gen()` / `.gen_range()` → `.random()` / `.random_range()`
  - `StdRng::from_entropy()` → `StdRng::try_from_rng(&mut rand::rngs::SysRng)`
  - `RngCore` / `OsRng` paths → `Rng` / `SysRng` / `TryRng` paths
  - `rng.r#gen::<u8>()` → `rng.random::<u8>()`
- Updated `Cargo.lock` so every first-party crate resolves `rand 0.10.2`.
- Ratcheted budgets:
  - `CLOSURE_BUDGET` 243 → 238
  - `FEATURE_CLOSURE_BUDGET` 476 → 474

## Security-critical call sites

These sites generate key material and were reviewed explicitly rather than
blindly replaced:

- `crates/mvm-agentd/src/bin/mvm-guest-agent.rs`: guest Ed25519 signing key
  now filled from `rand::rngs::SysRng.try_fill_bytes(...)`.
- `crates/mvm-agentd/src/vsock/framing.rs`: handshake challenge, host X25519
  ephemeral secret, and guest X25519 ephemeral secret now filled from
  `rand::rngs::SysRng.try_fill_bytes(...)`.
- `crates/mvm-core/src/crypto/`: `key_rotation`, `secret_store`, `aead`,
  `snapshot_hmac`, `snapshot_sign`, `attestation/{identity,header}`, and
  `vmgenid` continue to fill keys/nonces from a CSPRNG (`rand::rng()`).
- `crates/mvm-core/src/net/session.rs`: X25519 `StaticSecret`s and shared
  secrets continue to come from a CSPRNG (`rand::rng()` / `rand::random()`).

No site was converted to a seeded or deterministic RNG. `rand::rng()` is the
thread-local CSPRNG in `rand 0.10`, seeded from and periodically reseeded by
`SysRng`. The explicit `SysRng` fills are used where the original code called
`OsRng` directly.

## Verification

- `cargo +nightly fmt --all -- --check` — clean.
- `cargo clippy --workspace --all-targets -- -D warnings` — clean.
- `cargo test --workspace --doc` — clean.
- `cargo nextest run --workspace` — 11614 passed, 26 skipped, 2 unrelated
  flaky failures in `mvm-agentd::entrypoint_execute` that pass when run
  individually.
- `cargo run -p xtask -- check-duplicate-majors` — clean.
- `cargo run -p xtask -- check-closure-budget` — 238 crates (at budget 238).
- `cargo run -p xtask -- check-core-runtime-free` — clean.
- `cargo run -p xtask -- check-guest-agent-runtime-free` — clean.
- `cargo tree -p mvmctl -e no-dev` shows a single `rand 0.10.2` and single
  `rand_core 0.10.1` in the first-party closure. `getrandom 0.2.17` remains
  only as a transitive dependency of `ring` and is outside the scope of this
  unification.
