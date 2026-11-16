# P2 implementation report: neutral signer-helper client

Backing: historical
Validation: none

This records local implementation validation for [#5510](https://github.com/tinylabscom/mvm/issues/5510)
against `8f3803b5c81240641c169d956a172d8dc474db72` plus the P2 working-tree changes.
The [plan](signer-helper-prerequisite-plan.md) received scoped design review
before the relocation. Publication and landing were not authorized.

## Outcome

The client and its four existing tests moved from hostd to
`crates/mvm-core/src/signer_helper.rs`, gated by Unix and `hostd-transport`.
Hostd retains its old module path through a Unix-gated re-export.
Manifest executable content, defaults, dependency versions and lockfile are
unchanged. Existing consumers retain their imports.

Source review confirmed that executable source and relocated tests are
unchanged after accounting for self-crate paths and import ordering. The
module documentation now states Unix availability. No server, process, key,
configuration, authority, timeout or wire behavior moved or changed.

A new compatibility fixture proves bidirectional type identity, successful
helper exchange and caller-selected cap rejection. A new telemetry fixture
explicitly aborts an in-flight request and observes socket EOF, complementing
the existing deadline and signature/correlation refusal tests.

## Validation

Passed:

- `cargo fmt --all -- --check`
- `cargo check -p mvm-core --no-default-features --lib`
- `cargo check -p mvm-core --no-default-features --features hostd-transport --lib`
- `just tests::scoped mvm-core signer_helper::tests --lib --no-default-features --features hostd-transport`
- `just tests::scoped mvm-hostd '' --test signer_helper_compat`
- `just tests::scoped mvm-hostd '' --test telemetry_signer`
- Hostd scoped library filters `host_signer` and `broker`.
- Core runtime-free, guest runtime-free and SDK transport-free closure gates.
- `cargo check --workspace`
- `cargo test --workspace`, including doctests, on the serial rerun.
- `cargo clippy --workspace -- -D warnings`
- `just check::gated`
- `cargo run -p xtask -- check-all`: 86 gates clean.

Commands used the isolated worktree target directory, cached Cargo home,
offline Cargo resolution and invocation-local `TMPDIR=/tmp`.
The aggregate gate used a temporary Git index representing the relocation and
new files, leaving the real index unchanged.

## Failed attempts and evidence limits

The intended pre-move baseline was not valid: edits overlapped its compilation,
so hostd saw the new export while core's compiled artifact lacked the module.
It failed with an unresolved import. No successful pre-move run is claimed.
Post-move selected tests and full workspace validation passed.

The first workspace test run reached CLI doctests and failed to locate compiled
dependencies while aggregate checks were running against the same target
directory. A subsequent serial clippy, gated-check and exact workspace-test
run passed without source changes. Artifact interference is a plausible cause,
not a separately reproduced root-cause proof.

The fresh implementation review found no production regression. Its low-priority
test-hardening suggestion was addressed afterward: fixture accept/read/write
exchanges have five-second deadlines, and the synchronous compatibility client
returns its result through a channel with a five-second receive timeout.
The abort fixture bounds setup as well as its EOF assertion. Production
deadlines remain unchanged.

After this test-only hardening, formatting, both affected integration targets
(one compatibility test and eight telemetry tests), and
`cargo clippy -p mvm-hostd --test signer_helper_compat --test telemetry_signer -- -D warnings`
passed. The full workspace and aggregate gates above preceded this test-only
change and were not repeated afterward.

No live microVM, Linux runtime, hardware, density or latency witness was run.
No later prerequisite, combined helper composition or host-role extraction is
implemented by this change. At this report's completion, changes are uncommitted,
unpublished and unlanded.
