# #3717 follow-up: runtime approval across secret injection modes

Backing: shipped-source
Validation: check-sprint-append

## Problem

PS-07 runtime approval originally inspected plain request-header values for a
secret placeholder. PS-02 later added `query_param`, `url_path`, and
`basic_auth` injection modes. The endpoint's older preflight still rejects URL
placeholders before the position-aware substitution code runs, while a Basic
credential hides its placeholder inside base64. A binding marked
`approve = "ask"` therefore is not presented to the approval supervisor for
those three modes.

## Solution

Use `mvm_contract::substitution::locate_placeholders` as the endpoint's single
inventory of placeholders in URL, header, and decoded Basic-auth positions.
Only a placeholder whose discovered position matches its signed binding is an
approval candidate; malformed or out-of-position requests remain the
substitution engine's fail-closed responsibility. Request bodies remain an
unsupported injection position and are refused before forwarding.

## Scope

- Fix secret-use approval discovery for header, Basic-auth, query-value, and
  URL-path injection modes.
- Keep one prompt per secret name per request.
- Preserve destination binding checks and the no-body-substitution invariant.
- Reuse the same placeholder inventory for substitution audit metadata.

Out of scope: new injection modes, filesystem approvals, persistent approval
profiles, and the PS-13 live tool-policy caller.

## Context references

- `crates/mvm-contract/src/substitution/position.rs` — canonical parser for
  placeholder positions, including decoded Basic credentials.
- `crates/mvm-contract/src/substitution.rs` — validates a located position
  against `SecretRef.inject` and performs the substitution.
- `crates/mvm-hostd/src/supervisor/network_endpoint_proxy/prepare.rs` — runtime
  secret approval and request preparation.
- `crates/mvm-hostd/src/supervisor/terminator/flow/tests/endpoint_routes.rs` —
  terminated-flow approval tests over the real registry and forwarder seam.

## Tasks

- [x] Add regressions proving a denied `approve = "ask"` binding prompts and
      never forwards in `query_param`, `url_path`, and `basic_auth` modes.
      Validate: `cargo test -p mvm-hostd secret_approval_covers_every_injection_mode`
- [x] Replace header-only approval discovery and metadata collection with the
      contract's position-aware placeholder inventory; remove the stale blanket
      URL refusal while retaining the body refusal.
      Validate: `cargo test -p mvm-hostd secret_approval_covers_every_injection_mode`
- [x] Update the PS-07 delivery note, sprint state, and refactor rollup to
      record the regression fix and the already-landed PS-02 injection modes.
      Validate: `cargo run -p xtask -- check-sprint-append`
- [x] Run formatting, focused tests, workspace tests, clippy, workspace check,
      and gated-target compilation.

## Acceptance criteria

- [x] Every supported secret injection mode reaches the approval supervisor
      before substitution when its binding requires approval.
- [x] A denial forwards neither the placeholder nor the resolved secret.
- [x] An out-of-position or body placeholder remains fail-closed.
- [x] No raw secret is added to approval prompts, logs, or audit labels.
- [ ] Repository validation is green.

## Validation status

- `cargo test -p mvm-hostd`: passed, including 1,978 unit tests and all hostd
  integration and documentation tests.
- `cargo clippy --workspace -- -D warnings`, `cargo check --workspace`,
  `cargo fmt --all -- --check`, and `cargo run -p xtask -- check-sprint-append`:
  passed.
- `cargo test --workspace`: reached `mvm-agentd` with 840 tests passed, then the
  pre-existing flaky `stream_pump::tests::a_slow_sink_receives_every_byte_exactly_once`
  observed 165,888 of 524,288 bytes.
- `cargo run -p xtask -- check-all`: all 75 gates passed after restoring the
  installed `uvx` and `npx` directories to the non-login shell's `PATH`.
- `just check::gated`: passed both Linux cross-target and BDD-required-feature
  compilation after restoring the installed Rust and Zig tools to `PATH`.
- A focused retry confirms the workspace failure is the unrelated bounded
  slow-sink expectation being corrected by auto-merge PR #3835; this plan does
  not duplicate that change.

## Open questions / assumptions

No open product questions. The signed `SecretRef.inject` value is authoritative,
and the existing contract parser and substitution semantics are inherited.
