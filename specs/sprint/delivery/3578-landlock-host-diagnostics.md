# Landlock failure is now a host diagnostic

Issue: #3578

The secret-holding network endpoint still refuses every partially confined or
unconfined start. The change adds a read-only kernel ABI query to the jailer and
surfaces it as a `landlock` security line in `mvmctl doctor`. Linux hosts now
distinguish an ABI older than v2, a kernel built without Landlock, Landlock
disabled in the active LSM list, and an unexpected probe failure. Every failing
state names the remediation: enable `CONFIG_SECURITY_LANDLOCK=y`, include
Landlock in the active LSM list, and run Linux 5.19 or newer.

Endpoint startup shares that language. A ruleset reported as `NotEnforced`
becomes an actionable kernel-capability error, and the existing spawn handshake
quotes the endpoint's stderr into the host error. Builder endpoints are spawned
before their guest boots, so this failure no longer needs a guest timeout or
kernel panic to become visible.

The undocumented `MVM_ENDPOINT_NO_CONFINE` branch is deleted. There is no
operator switch that can run the endpoint—which parses untrusted guest bytes
and holds decrypted credentials—without both Landlock and seccomp on Linux.

## Validation

- `cargo test -p mvm-hostd --lib jailer::tests` — 11 passed.
- `cargo test -p mvm-hostd --bin mvm-network-endpoint
  endpoint_source_has_no_unconfined_escape_hatch` — 1 passed.
- `cargo test -p mvm-cli doctor::security_checks::tests --lib` — 36 passed.
- `cargo test --workspace -- --test-threads=1` — passed, including every
  Rustdoc target. An initial run's final `mvm-build` Rustdoc invocation hit a
  transient missing-crate compiler error; both its isolated rerun and the full
  warm workspace rerun passed.
- `just check-gated` — Linux x86_64 all-target and BDD feature-gated checks
  passed.
- `cargo clippy --workspace --all-targets -- -D warnings` — passed.
- `cargo fmt --all -- --check` — passed.
- `cargo run -p xtask -- check-all` — passed.
