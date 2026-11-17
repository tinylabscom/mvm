# Audit directory ownership correction

Backing: preview
Validation: none

## Combined recovery validation

The recovered candidate based on `d7727419166b6ba7cfd47f603d523624f637318a`
passed the following checks after integrating the relocation, directory
correction, emitter review fix and test-only mailbox prototype:

| Command | Result |
| --- | --- |
| `cargo fmt --all -- --check` | Passed |
| `cargo test -p mvm-hostd --test audit_directory_policy --test audit_chain_compat --test audit_chain_frozen_bytes --test mailbox_audit_handshake` | Passed: 8 directory, 2 compatibility, 6 frozen-byte and 11 prototype tests |
| `cargo check --workspace` | Passed |
| `cargo clippy --workspace -- -D warnings` | Passed |
| `just check::gated` | Passed: Linux all-targets and feature-gated conformance compilation |
| `cargo run -p xtask -- check-all` | Passed: 88 gates, with `UV_OFFLINE=true` and `npm_config_offline=true` |
| `cargo test --workspace` | Passed with `RUST_TEST_THREADS=1`: 21,526 passed, zero failed, 63 ignored |

Build shells sourced `scripts/dev-env.sh`, used `TMPDIR=/tmp`, and retained
worktree-isolated Cargo state. The final complete batch used
`CARGO_BUILD_JOBS=1`. The default concurrent workspace run failed the unchanged
HVF same-name launch-lock reacquisition test; that test subsequently passed
alone, and the full serialized run passed without weakening its assertion.
Concurrency-related descriptor inheritance is a hypothesis, not a proven
root cause. Earlier interrupted runs with missing exit status are not passes.

Fresh independent source review found the emitter bypass described below;
the corrected combined candidate received a follow-up review with no remaining
concrete findings. Both emitter regressions passed in the combined run.
Review covered the candidate source, not just the historical transcript.

No live-backend, power-loss or hostile concurrent namespace-replacement
witness was run. Ignored tests were not enabled. Gated Linux compilation is
not Linux execution evidence. Production mailbox audit publication remains
outside this fixture-only checkpoint. Issue #5671 owns PR and CI status.

## Recovery provenance

Recovered for #5671 from the archived successful edit inputs in
`/tmp/mvm-audit-recovery-transcript.json`. The original report below, including
its validation and review results, describes the archived run, not validation
of the recovered checkout.

The successful scoped patches were replayed in order against the attached
source, including the two authorized audit-file relocations and canonical
audit imports. Intermediate and final Rust formatting was reproduced with
`rustfmt --edition 2024`. All nine recovered files matched the reconstructed
archive result byte-for-byte before this provenance section was added.
No implementation adaptation or production mailbox change was needed.
Module declarations and the remaining relocation belong to the combined
recovery, outside this directory-policy slice.

The recovery's eight Rust files passed
`rustfmt --edition 2024 --check --config skip_children=true` with the explicit
scoped file list. Current scoped test results are recorded separately below;
the archived full/scoped results must not be treated as fresh evidence.

### Post-recovery review correction

Review of the recovered source found that `AuditEmitter::with_dir` and its
shared-signer initialization still used the legacy lexical private-directory
helper. For a path such as `MVM_HOME/../audit`, those calls could chmod an
external ancestor before the signer's resolved policy ran. Both now use
`create_private_dir_resolved`. This is a new correction, not an archived edit.

Two new integration regressions exercise `with_dir` and
`with_primary_signer`, each with parent escape and symlink-then-`..` paths,
requiring private audit targets and unchanged external ancestor modes.
They were added before the production correction, but a pre-fix executable
witness was not run in the isolated slice: the canonical audit module
declarations are being recovered separately. Combined validation must cover
these tests before treating the review finding as verified.

## Original archived report

This is a separately approved behavior correction after the audit-chain
relocation, not part of its byte-equivalent source result. The initial basis
is `62603aeffe78be79728ef347204872ae0344fb79` plus the local relocation.
The owner explicitly approved expanding scope to a narrow core path-policy
helper. No mailbox, handshake-prototype, signing, wire or publication changes
are included.

## Caller classification

`FileAuditSigner::open` owns a dedicated primary audit directory. Production
callers include CLI command/secret recording at the default audit directory,
endpoint recording at `mvm_audit_dir`, audit pruning, and `AuditEmitter`.
The emitter already called `create_private_dir` for explicitly supplied
dedicated audit roots, including relocated roots outside MVM home.

`FileAuditSigner::open_file` is used by emitter policy `file://` destinations:
the parent can be an ordinary caller-owned output directory. Applying the
existing private helper unconditionally would chmod that external leaf.
Inside MVM home, however, a caller-selected path still belongs to the private
namespace. Constructors and append-time parent recreation must agree.

Checkpoint persistence is always below `mvm_cache_dir`; it uses the private
helper and retains its best-effort cache error behavior.

## Core policy and algorithm

Two policy-specific APIs, `config::create_output_parent` and
`config::create_private_dir_resolved`, share one private walker and policy
implementation; neither exposes a general path resolver. The old
`create_private_dir` delegates its existing loop to a private
`create_private_dir_under(home, dir)` with identical arguments/semantics.
The new policies reuse that loop with resolved paths.

Before creation, the helper walks both configured MVM home and output-parent
paths component by component:

1. Make a relative spelling absolute without lexically removing `..`.
2. For an existing component, canonicalize it and require a directory.
   Existing directory symlinks therefore affect the meaning of later `..`.
3. For a missing normal component, retain an ordered creation step. Processing
   a later `..` changes the eventual location but does not discard this step.
   Thus `missing/x/../leaf` creates `x`, while `file/../leaf` fails.
4. Dangling links, nondirectories, permission errors and unresolvable
   configured home paths return errors. No classification failure selects
   an external fallback.

Ownership uses component-aware `Path::starts_with` on resolved paths, not
string prefixes. When the walk touches the resolved home, necessary missing
components of the home's own spelling are created privately. Each owned
destination step uses the shared private home-to-target loop. Missing
external steps use ordinary directory creation; existing external modes are
untouched. Paths outside home do not initialize an unrelated absent home.
After creation, `metadata` of the original spelling must identify a directory,
then canonicalization must resolve to the planned target. This verifies traversal through components
before `..`, including DAC-denied intermediates, rather than merely checking
that a lexically equivalent final leaf exists. It is not a containment proof
against concurrent replacement.

Both `open_file` and each fixed-file append call the output-parent policy.
Primary `open` and primary append call the dedicated resolved policy:
the target itself is private even outside home; missing external traversal
directories are created private, but existing external ancestors are not
chmodded. The choice is derived from the existing `fixed_file` field, not a
new mutable flag.

The dedicated policy is necessary for safe wiring of the public signer API.
Simply substituting the legacy private helper for raw mkdir would introduce
an unintended chmod of the parent for `MVM_HOME/../external`. The new policy
retains that path's meaning without claiming the escaped ancestor. The legacy
owner helper's existing contract remains unchanged.

### Trust and failure limits

The underlying private-directory helper follows directory symlinks. This
change preserves that behavior and explicitly makes no symlink-containment
guarantee against hostile concurrent namespace replacement. Preflight and
creation are not one descriptor-relative transaction; the host namespace
and configured home remain trusted, as before.

Permission changes may be partially applied if a later creation or chmod
fails; the operation returns failure rather than silently proceeding.
The helper changes directory policy only, not output-file modes. The
permission-denial regression checks real DAC refusal when the process lacks
traversal authority; a privileged process that bypasses DAC cannot witness
that refusal and prints that limitation.

## Gate treatment

No audit implementation file is exempted. The gate reuses
`strip_cfg_test_items` after comment/string blanking so nested fixture bodies,
including the frozen-corpus regeneration code, are excluded without hiding
production code following those modules. Test fixture filesystem behavior
and frozen fixtures remain unchanged.

The existing atomic sidecar writer exception is tightened from a suffix match
to its exact full relative path. No new exception is added. The gate recognizes
the policy-specific core helper and still rejects a raw creation call on the
same line as an approved helper.

New tests cover nested test-module stripping, rejection of production after
tests, same-line raw-call rejection, and rejection of a misleading filename
suffix. The original gate failure is historical evidence of why this separate
correction was needed, not a result to erase from the relocation report.

## Regression witnesses

Nine core tests cover:

- Empty filename parents resolving to the current directory without mutation.
- Existing 0755 home repaired and missing owned chains created privately.
- External parent modes retained, including similarly prefixed siblings.
- Relative paths, `..` escape and missing-before-`..` creation.
- Aliases into/out of home and an aliased configured MVM home.
- Missing components in the configured home's own spelling.
- Dedicated-root parent escapes and symlink/`..` traversal without external ancestor chmod.
- File/dangling symlink and nondirectory failures without external fallback.
- Permission-denied paths where real DAC denial is available.

Six hostd integration tests cover primary root repair and append recreation,
dedicated external roots versus their caller-owned ancestors, fixed-file
inside/outside ownership at open/append/recreation, checkpoint cache modes,
and bare-relative-file open/append in a subprocess with a 0755 temporary cwd.
The subprocess also exercises a relative dedicated root; a separate integration
witness checks primary parent-escape and symlink/`..` open and append recreation.
Frozen signing-byte and old/new path compatibility tests are retained.

Parent review caught the empty-parent case before final validation:
`Path::parent("audit.jsonl")` yields an empty path, but `Path::absolute("")`
refuses it. The policy now treats an empty parent as `.`. This was a genuine
intermediate compatibility defect, not a pre-existing failure; the subprocess
witness avoids changing the test process's cwd or touching ambient directories.

The first scoped core run had six passes and one test failure: the relative
path test assumed a temporary root started at 0700, while this host created
it at 0755. The assertion now captures the original mode and proves it remains
unchanged; no production change was needed for that failure.

The next core run passed seven tests and exposed a real platform detail in the
new DAC/`..` witness: on this macOS host `canonicalize` alone accepted a spelling
through an unsearchable intermediate. The final check now first performs
`metadata` on the original spelling (kernel traversal), requires a directory,
then compares canonical resolution. A final canonical path alone is not used
as proof that the original spelling is traversable.

Independent source review reported no additional concrete defect beyond the
empty-parent case. That review was of the pre-fix snapshot; the parent reviewed
the incremental empty-parent fix, subprocess witness, original-spelling final
recheck and corrected temporary-root mode assertion.

Fresh independent follow-up review of the final dedicated-resolved policy and
metadata-before-canonicalize snapshot found no blocking issues. It checked
private creation without a permissive-creation gap, preservation of external
ancestors, the unchanged legacy helper contract, original traversal,
constructor/append consistency and gate exact-path/same-line enforcement.
This was source-only review; the reviewer did not independently run tests.

## Validation

Build shells source `scripts/dev-env.sh`, use `TMPDIR=/tmp`, keep the isolated
target directory and reuse the existing Cargo registry with
`CARGO_NET_OFFLINE=true`. No npm/uv tool execution or dependency installation
is authorized for this correction.

Final scoped test batch on the reviewed implementation:

| Exact command | Observed result |
| --- | --- |
| `cargo test -p mvm-core --lib config::output_parent` | Passed: 9 tests |
| `cargo test -p mvm-core --lib config::tests::create_private_dir` | Passed: 2 legacy-contract tests |
| `cargo test -p xtask --bin xtask check_private_mvm_dirs` | Passed, including the real workspace gate and new negative scanner witnesses |
| `cargo test -p mvm-hostd --test audit_directory_policy --test audit_chain_frozen_bytes --test audit_chain_compat` | Passed: directory-policy target, unchanged frozen-byte target and cross-path compatibility target |
| `cargo test -p mvm-hostd --lib audit::` | Passed: 441 tests, zero failed/ignored |
| `cargo clippy -p mvm-core -p mvm-hostd -p xtask --all-targets -- -D warnings` | Passed on rerun after correcting test-only `Permissions::from_mode(0)` to equivalent `0o000`. |
| `cargo fmt --all -- --check` | Passed after clippy in the same fail-fast job |

The octal correction changes only literal spelling, not the tested permission
value; no production edits followed the successful test batch.

## Archive checkpoint and outstanding work

The user requested a bounded archive checkpoint rather than starting further
long workspace jobs. This is **not full-task completion**:

- No full `cargo check --workspace`, `cargo test --workspace`,
  `cargo clippy --workspace -- -D warnings` or `just check::gated` has been
  run on this later directory-policy correction.
- Earlier workspace check/clippy/gated passes belong to the prior relocation
  snapshot, not this expanded core behavior change.
- The original relocation's private-directory failure is historical; the
  current targeted workspace gate test now passes.
- `cargo run -p xtask -- check-all` remains unvalidated. Its prior invocation
  entered installer-capable uv/npm schema generation. No documented
  no-install invocation was established, so it was not invoked again.
- No live backend, power-loss, hostile concurrent path-replacement or Linux
  syscall execution witness was run. These tests exercised the macOS host;
  directory symlinks retain the stated trusted-host behavior.
- No commit, push, PR, merge, publication or issue update was performed.

The scoped clippy/formatting tail exited successfully. The final terminal
inventory contains **no active background terminals**: all jobs exited or,
for the earlier installer-capable check-all run, were stopped.
The real Git index remains unchanged and HEAD remains the source-basis commit.
Production mailbox publication remains separately scoped/reviewed work,
not implemented here.
