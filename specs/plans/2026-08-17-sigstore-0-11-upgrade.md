# Upgrade sigstore-verify stack 0.9 → 0.11

Backing: shipped-source
Validation: none

**Status:** COMPLETE

## Background

`mvm-core`'s `manifest-verify` feature (opt-in cosign-keyless image verification)
pinned the modular sigstore-verify stack at 0.9.x. That version pulled
sha2 0.10.9 and digest 0.10.7 as transitive orphan lockfile entries — packages
not reachable from any default feature, but visible in `Cargo.lock` as dead
weight. It also brought in rustls 0.22 (vs the workspace's rustls 0.23), creating
a silent second copy of the TLS stack behind the optional feature flag.

Version 0.11 of the stack converges on the workspace's rustls 0.23, drops the
sha2 0.10.x orphan, and removes a dead `VerificationResult.success` boolean
field from its public API (verification errors are `Err(...)` now, not
`success == false`).

## What changed

- `crates/mvm-core/Cargo.toml`: sigstore-verify / sigstore-trust-root /
  sigstore-types bumped from `"0.9"` to `"0.11"`. Added `features = ["rustls"]`
  to sigstore-verify to select the ring-backed rustls TLS path rather than the
  aws-lc-rs backend.

- `crates/mvm-core/src/crypto/image_verify.rs`: removed the dead
  `result.success` check. In 0.11 the `verify()` call returns `Result<()>`;
  an unsuccessful verification is already an `Err`, so the `if !result.success`
  branch was unreachable and the `let result =` binding was dead. Removed both.

- `xtask/src/check_duplicate_majors.rs` ALLOWLIST: removed the stale `rand` and
  `rand_core` entries. The workspace unified on rand 0.10 (delivered in a prior
  change); the ALLOWLIST entries covering the old 0.8 ↔ 0.10 split were never
  ratcheted down. Confirmed by `cargo metadata --locked` showing only
  `rand 0.10.2` and `rand_core 0.10.1`.

- `deny.toml` skip list: removed the stale `rand` / `rand_core` entries with
  their now-false "rand 0.8 vs rand 0.10" comment for the same reason.

## Verification

- `cargo fmt --all -- --check` — clean.
- `cargo clippy -p mvm-core -p xtask -- -D warnings` — clean.
- `cargo test -p mvm-core` — 1829 passed, 0 failed.
- `cargo run -p xtask -- check-duplicate-majors` — clean (9 allowlisted).
- `cargo run -p xtask -- check-no-spec-refs-in-comments` — clean.
- `cargo tree -i aws-lc-rs` — not found (default closure is aws-lc-rs-free).
