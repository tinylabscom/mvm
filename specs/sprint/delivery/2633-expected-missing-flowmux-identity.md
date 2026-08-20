# Issue 2633 — healthy secretless boots produce no authentication failures

The two healthy-boot messages had different causes and are now classified at
their actual boundaries.

PR #2707 made an abandoned readiness connection a transport probe outcome,
not a failed authenticated control handshake. This change closes the remaining
identity-drive half: unconditional guest setup treats
`IdentityDriveError::NotAttached` as the expected shape for a boot whose policy
admits no egress, so it emits no failure line. A drive that was attached but
cannot be mounted or read remains loud.

`IdentityDriveError::boot_warning` makes the distinction explicit and testable.
The positive and negative tests prove expected absence is silent while an
unreadable attached drive retains its actionable diagnostic. The Linux-gated
guest setup consumes that classifier directly.

## Verification

- `cargo fmt --all -- --check`
- `just check-gated`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace -- --test-threads=1`
- `cargo test -p mvm-cli --doc -- --test-threads=1`
- `cargo test -p mvm-hostd --test host_agent_restart daemon_crash_mid_flight_loses_at_most_one_call_and_preserves_chain -- --test-threads=1`

The workspace run passed every executable test before a transient doctest
compile-state failure; the doctest passed when repeated in isolation. A second
workspace run reached the unrelated host-agent restart suite and timed out once
waiting for its socket; that exact test passed on immediate isolated retry.
