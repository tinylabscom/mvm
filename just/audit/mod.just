set working-directory := "../.."

# Security audit (cargo-audit — RUSTSEC advisories against Cargo.lock)
audit:
    cargo audit

# Supply chain check (cargo-deny — advisories + licenses + bans + sources)
deny:
    cargo deny check

# Combined supply-chain gate (ADR-001 claim 7)
supply-chain: audit deny

# Verify production guest agent has no dev-only Exec symbols (ADR-001 claim 4)
prod-agent:
    ./scripts/check-prod-agent-no-exec.sh

# Run the GuestRequest deserializer fuzzer (ADR-001 claim 5). Default 5min.

# Override with: just audit::fuzz-guest-request 3600
fuzz-guest-request SECONDS="300":
    cd crates/mvm-agentd && cargo +nightly fuzz run fuzz_guest_request -- -max_total_time={{ SECONDS }}

# Run the AuthenticatedFrame envelope fuzzer (ADR-001 claim 5). Default 5min.
fuzz-authenticated-frame SECONDS="300":
    cd crates/mvm-agentd && cargo +nightly fuzz run fuzz_authenticated_frame -- -max_total_time={{ SECONDS }}
