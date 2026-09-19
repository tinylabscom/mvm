# Boot admission moves from the CLI into mvm-client

Issue #3261, the first step of task 5. WS2 of
`specs/plans/2026-09-15-agent-sandbox-drive-plane.md`.

Task 5 set out to give the host library launch parity with the CLI. Tracing it
showed the two did not share an admission path. Every CLI boot (transient runs,
entrypoints, sessions, checkpoint forks, persistent starts) admits through
`admit_plan_for_boot`, which lived in `mvm-cli`. `mvm_client::launch` admits
through `mvm_hostd::run::admit_and_boot_local`, which synthesizes a different
plan: no ingress, no agent-verb restriction, no network policy, no caller
commitment, and no profile wiring. A library that called `mvm_client::launch`
would have admitted SDK machines under a different plan than the CLI gives the
same request.

This change is the pure-move half of the fix. The CLI's admission now lives in
`mvm-client`, where the library can reach it:

| was (`crates/mvm-cli/src/commands/`) | now (`crates/mvm-client/src/admission/`) |
| --- | --- |
| `vm/up/admission.rs` | `mod.rs` |
| `vm/up/audit.rs`, `vm/up/policy.rs` | `audit.rs`, `policy.rs` |
| `vm/policy_resolver.rs`, `vm/entrypoint_resolve.rs`, `vm/agent_verbs.rs` | same names |
| `shared/grants.rs` | `run_grants.rs` |
| the egress and peer half of `shared/resolve.rs` | `run_network.rs` |

The moves are `git mv` renames, and tests travel with their code. The CLI calls
`mvm_client::admission::…` directly. `admitted_shares_for_boot` is still named
at its real call site rather than re-exported, because `check-dormant-controls`
counts a `use` line as a caller.

One piece is new, and it is there for correctness. The CLI kept its open
command signer in a private global, so that launch admission would reuse it
rather than open a second `FileAuditSigner` on the same chain and fork it. The
admission code can no longer see a CLI global, so the registry moves beside
`FileAuditSigner` as `mvm_hostd::audit::active_signer`. It is the same single
weak slot, now cleared by a guard. The CLI registers its command signer through
it, and admission reads it wherever it runs.

The second half, making `mvm_client::launch` admit through this path so the
library can launch with a CLI-parity plan, is the next change.

## Gate bookkeeping

- `xtask/dormant-controls.toml` and `xtask/mutation-witness-baseline.json`
  follow the moved files.
- Claim 10's witness `run_net_default_is_deny_all` moved into `run_network.rs`,
  which puts `mvm-client` on the mutation surface (claims 10 and 17).
  `.github/workflows/security.yml` gains an `mvm-client` shard, because
  `check-mutation-witnesses` refuses a surface package that nothing mutates.
  The CLI's `resolve.rs` drops off the surface, and the four accepted misses
  recorded against it, which were for functions that stayed behind, go with it.

## Validation

- `cargo nextest run --no-fail-fast -p mvm-hostd -p mvm-client -p mvm-cli`:
  4400 run, 4399 passed. The one failure,
  `daemon_crash_mid_flight_loses_at_most_one_call_and_preserves_chain`, is a
  timing test that passed twice when run alone (2 s, against 9 s in the loaded
  full run).
- `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D
  warnings`, `just check-gated`, `cargo nextest run -p xtask` (766) and
  `xtask check-all`: pass.
