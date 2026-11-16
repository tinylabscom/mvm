# ADR-061 prerequisite P1: lower bounded host framing

Backing: preview
Validation: none

This is an immutable planning attachment for [#5510, section G](https://github.com/tinylabscom/mvm/issues/5510),
based on source revision `052276763f889960b0fd16cb7d58583e6cce4ec5`.
It inherits [accepted ADR-061](../../../../specs/adrs/061-crate-layout-by-where-code-runs.md)
and the [owner decision](https://github.com/tinylabscom/mvm/issues/5510#issuecomment-6903558088).
Execution status belongs on the issue, not in this attachment.
Planning is authorized; implementation, commits, publication and landing are not.

## Objective and scope

As a maintainer extracting host roles, I want their shared framing implementation
below those roles, so none needs a supervisor dependency just to exchange a frame.

Move the existing asynchronous JSON framing implementation from hostd into core,
behind core's existing off-default `hostd-transport` feature. Preserve the public
hostd module path with a downward module re-export. Do not rewrite every caller.
This is a prerequisite ownership/dependency change, not a role-crate extraction.

**Complexity:** low implementation complexity, security-sensitive compatibility.
**Dependencies:** existing Tokio, serde, serde_json and thiserror only; no new
package, version change, lockfile update, process, service or wire protocol.
**First-pass confidence:** 9/10, contingent on a clean current-source preflight.

ADR-061 settles the destination, feature boundary and preservation rules. There
are no additional owner design questions for this bounded prerequisite.
External library research is unnecessary: the existing implementations and
dependency versions remain unchanged.

### Non-goals

- No signer-helper client/config/composition move, key-custody change or process split.
- No guest protocol, synchronous libkrun framing or core control-protocol rewrite.
- No authentication/encryption retrofit, peer-identity change or new retry/timeout.
- No sender cap, automatic flush, JSON/schema/version change or error translation.
- No new role crate, directory regroup, generic transport abstraction or gate waiver.
- No default-feature expansion, cache-key bypass or unrelated comment cleanup.

## Source context

The immutable links below survive the later directory moves.

| Read before implementing | Why |
| --- | --- |
| [hostd framing, lines 1–182](https://github.com/tinylabscom/mvm/blob/052276763f889960b0fd16cb7d58583e6cce4ec5/crates/mvm-hostd/src/framing.rs#L1-L182) | Entire implementation, five public items, four existing tests; exact current wire/error behavior. |
| [hostd public module, lines 48–52](https://github.com/tinylabscom/mvm/blob/052276763f889960b0fd16cb7d58583e6cce4ec5/crates/mvm-hostd/src/lib.rs#L48-L52) | Replace the declaration with the compatibility re-export. |
| [hostd dependencies, lines 93–100](https://github.com/tinylabscom/mvm/blob/052276763f889960b0fd16cb7d58583e6cce4ec5/crates/mvm-hostd/Cargo.toml#L93-L100) | Explicitly enable core's transport feature on the existing normal dependency. |
| [core features, lines 125–177](https://github.com/tinylabscom/mvm/blob/052276763f889960b0fd16cb7d58583e6cce4ec5/crates/mvm-core/Cargo.toml#L125-L177) | Empty defaults and existing optional Tokio feature; do not change defaults. |
| [core dev dependencies, lines 275–279](https://github.com/tinylabscom/mvm/blob/052276763f889960b0fd16cb7d58583e6cce4ec5/crates/mvm-core/Cargo.toml#L275-L279) | Existing Tokio test support suffices; no production test runtime. |
| [supervisor frame adapter, lines 1–74](https://github.com/tinylabscom/mvm/blob/052276763f889960b0fd16cb7d58583e6cce4ec5/crates/mvm-hostd/src/supervisor/services/frame.rs#L1-L74) | Preserve caller-owned path/error mapping and UDS connection behavior. |
| [core control protocol, lines 1–11](https://github.com/tinylabscom/mvm/blob/052276763f889960b0fd16cb7d58583e6cce4ec5/crates/mvm-core/src/protocol/protocol.rs#L1-L11) | Separate 1 MiB control-channel cap; sharing a feature does not make these protocols interchangeable. |
| [runtime-free gate](https://github.com/tinylabscom/mvm/blob/052276763f889960b0fd16cb7d58583e6cce4ec5/xtask/src/check_core_runtime_free.rs#L19-L61) and [guest gate](https://github.com/tinylabscom/mvm/blob/052276763f889960b0fd16cb7d58583e6cce4ec5/xtask/src/check_guest_agent_runtime_free.rs#L94-L175) | Selected-package default closures, not whole-workspace feature union, are the regression boundary. |

### Direct consumer inventory

All paths here are relative to `crates/mvm-hostd/`. Preserve these call sites
through the facade; they do not need mechanical import edits in P1.

| Surface | Source files |
| --- | --- |
| Audit signing and combined helper | `src/audit_signer/{server,helper,helper_client}.rs` |
| Host signing | `src/host_signer/server.rs`, including its helper fixture |
| Broker transport | `src/broker/{server,controller_proxy,service_proxy}.rs` |
| Endpoint transport | `src/supervisor/endpoint/network_endpoint_connector.rs`, `src/supervisor/endpoint/network_endpoint_proxy/listen.rs` |
| Supervisor error adapter | `src/supervisor/services/frame.rs` |
| Endpoint fixtures | `src/supervisor/endpoint/network_endpoint_proxy/{audit,listen,prepare,redaction}.rs` |
| External facade consumers | `tests/telemetry_signer.rs`, `tests/egress_secret_leak_gate.rs` |

Refresh this inventory before execution with Trail's exhaustive search, or
`rg -n '(crate|mvm_hostd|super)::framing' crates` when the index is unavailable.
Follow any newly introduced alias/re-export rather than treating this snapshot
as a permanent allowlist. Synchronous `libkrun_sys::framing` and signed guest
session framing are different implementations, not duplicates to consolidate.

## Compatibility contract

1. Keep `FRAME_LEN_BYTES = 4`, `DEFAULT_MAX_FRAME_BYTES = 65_536`, and four-byte
   big-endian length followed by exactly `serde_json::to_vec` output.
2. Keep all `FrameError` variants, fields, error text, source chaining and
   generic bounds. The hostd and core paths name the same type, not wrappers.
3. Read the full prefix, reject `len > max_frame_bytes` before allocating or
   reading the body, accept equality, then read exactly that body and decode.
   A zero-length body currently reaches JSON decoding; do not invent a new error.
4. Preserve write ordering: serialize, check u32 representability, write prefix,
   write body. There is no caller-size cap or flush in this writer today.
   Do not add either while moving it.
5. Keep cap selection, connection/session ownership, cancellation, error mapping
   and retries at callers. Preserve `read_exact`/`write_all` completion of short
   transfers. Propagate terminal I/O failures, including failures after partial
   progress; framing provides no frame-level retry or rollback.
6. This framing provides no authentication. Same-UID channel checks remain with
   their current owners; guest authenticated/session framing is untouched.
7. Core default and selected default guest closures remain runtime-free.
   Hostd explicitly opts into transport; it already depends on Tokio.
8. Source relocation may change content fingerprints. Preserve correct hashing
   of the new source location; do not exclude files to retain an old cache key.
   Unchanged resolved guest dependencies do not imply unchanged source hashes.

## Implementation tasks

These tasks are for a future authorized implementation. They are ordered;
do not mix this prerequisite with a role extraction or adjacent cleanup.

### 1. Preflight and pin the existing behavior

- Check the current branch/source against this pin and refresh the consumer list.
  If framing signatures, caps, errors or protocol ownership changed, revise the
  implementation review before editing; do not apply stale line-based moves.
- Run the existing hostd framing tests before moving them.
- Add focused tests alongside the implementation for exact prefix/body bytes,
  equality at a small cap, truncated prefix, zero-length/malformed body,
  serialization failure before any bytes, and propagation of write I/O failure.
- Use a small recording `AsyncWrite` to verify the existing writer does not
  flush, completes successful short writes, and propagates a failure after
  partial progress. Cover successful short reads too. Do not allocate a
  multi-gigabyte value to exercise `LengthOverflow`.
- Retain the existing `u32::MAX` prefix refusal, truncated-body and roundtrip
  tests. In-memory streams are sufficient; do not boot a VM or contact a service.
- **Validate:** `just tests::scoped mvm-hostd framing::tests --lib`.
- **Satisfies:** AC1–AC3 below; establishes before/after fixtures.

### 2. Move once and expose a gated core module

- Move `crates/mvm-hostd/src/framing.rs` to the new
  `crates/mvm-core/src/framing.rs`, including its tests.
- In `crates/mvm-core/src/lib.rs`, expose `framing` only under
  `#[cfg(feature = "hostd-transport")]`.
- Keep the implementation generic over async I/O. Do not introduce Unix imports
  into it or couple it to a protocol/request type.
- Adjust the moved module's ownership documentation: default core is still
  runtime-free, peer authentication is external, and this is not guest framing.
  Remove the stale future `AuthStage`/`NoAuth` roadmap prose rather than treating
  it as an implemented API. Do not add ADR/issue citations in code comments.
- Core's existing optional dependencies and dev Tokio dependency suffice.
  No change to `mvm-core/default`, `host-state` or the control-protocol module.
- **Validate:** the two core checks and gated framing test command below.
- **Satisfies:** AC1–AC4.

### 3. Keep the hostd facade and prove cross-crate compatibility

- Add `hostd-transport` to the existing normal `mvm-core` dependency's feature
  list in `crates/mvm-hostd/Cargo.toml`.
- Replace hostd's `pub mod framing;` with `pub use mvm_core::framing;`.
  Update its module comment; there must be no second implementation file.
- Leave production imports and `supervisor/services/frame.rs` error conversion
  unchanged. Update only stale ownership documentation there and in
  `crates/deps/libkrun-sys/src/framing.rs`.
- Add `crates/mvm-hostd/tests/framing_compat.rs`: use both public paths to
  exchange a fixed small JSON frame and demonstrate `FrameError` type identity.
  Pin expected wire bytes independently of either encoder. Exercise caller-
  supplied limits through the facade, not only the default constant.
- Do not rename helper executables, change manifest-required features, or move
  the neutral signer-helper client yet.
- **Validate:** facade test, existing caller suites and closure gates below.
- **Satisfies:** AC1, AC3–AC6.

### 4. Review the cut and hand off

- Confirm one framing implementation in core, hostd's downward re-export, no
  core import of hostd, and no new normal dependency in selected guest closures.
- Compare default/no-default and explicit transport selections independently.
  `--workspace` or `--all-features` feature unification is not a lean-guest test.
- Run final repository gates, record exact results on #5510/the eventual PR,
  and retain any pre-existing failures as explicit blockers—not waived checks.
- The PR is partial work: use `Refs #5510`, not an issue-closing keyword.
  Do not mark role extraction, density, or the whole restructure complete.
- **Satisfies:** AC4–AC7.

## Validation commands for the eventual change

Run Cargo from its worktree, sourcing `scripts/dev-env.sh` once per shell.
Git operations remain centralized as required by `AGENTS.md`.

```sh
# Before relocation; the four original tests plus new compatibility cases.
just tests::scoped mvm-hostd framing::tests --lib

# After relocation.
cargo fmt --all -- --check
cargo check -p mvm-core --no-default-features --lib
cargo check -p mvm-core --no-default-features --features hostd-transport --lib
just tests::scoped mvm-core framing::tests --lib --no-default-features --features hostd-transport
just tests::scoped mvm-hostd '' --test framing_compat
just tests::scoped mvm-hostd audit_signer --lib
just tests::scoped mvm-hostd host_signer --lib
just tests::scoped mvm-hostd broker --lib
just tests::scoped mvm-hostd supervisor::services --lib
just tests::scoped mvm-hostd '' --test telemetry_signer
just tests::scoped mvm-hostd '' --test egress_secret_leak_gate
cargo run -p xtask -- check-core-runtime-free
cargo run -p xtask -- check-guest-agent-runtime-free
cargo run -p xtask -- check-sdk-transport-free

# Before publishing an implementation PR; not replaced by the scoped tests.
cargo check --workspace
cargo test --workspace
cargo clippy --workspace -- -D warnings
just check::gated
cargo run -p xtask -- check-all
```

The generic framing tests run on the ordinary host. Exercise the existing Unix
callers on macOS and Linux; Linux-specific execution belongs in the builder/CI
boundary. No live VM witness is supplied by these in-memory/UDS fixtures.
No implementation validation command above was run as part of writing this plan.

## Acceptance criteria

- [ ] **AC1:** One implementation, unchanged wire bytes/constants/generic bounds.
- [ ] **AC2:** Prefix/cap/decode/I/O ordering and failure semantics covered before
      and after the move; writer remains uncapped apart from u32 representation
      and does not flush.
- [ ] **AC3:** Existing and new focused tests pass, including the public facade
      and type-identity check; no large-allocation fixture is introduced.
- [ ] **AC4:** Default core and selected guest closure gates pass without
      `hostd-transport`/Tokio leaking into defaults; explicit transport builds pass.
- [ ] **AC5:** Existing signer, broker, supervisor and endpoint caller behavior
      remains unchanged; no process/key/authority or guest-protocol changes.
- [ ] **AC6:** No new dependency/version or Cargo.lock change; documentation and
      source fingerprint inputs refer to the actual owner.
- [ ] **AC7:** Required repository validation and focused review complete; issue
      records partial completion accurately. Separate landing approval obtained.

## Subsequent prerequisite planning slices

These are dependency groups to plan individually, not pre-authorized PRs.

| Slice | Dependency / purpose |
| --- | --- |
| Neutral signer-helper client | After P1; lower the existing client under the same optional transport feature, preserving its wire/config and error behavior. |
| Audit substrate and vocabulary | Reown chain/recorder/mirror, audit client, refusal vocabulary and shared capture layout; do not pull producer orchestration into audit. |
| Combined signer composition | After neutral client and audit seams; rehome the existing single helper under admission composition, without splitting processes/key lifetime. |
| Admission and broker composition | Split checked admission/caller capabilities from start/rollback; rehome assurance registry items as accepted. Preserve transaction order. |
| Egress and shared host support | Use lower audit/framing; group endpoint/keyholder/redaction/collector ownership and split policy from bootstrap/confinement helpers. |
| VMM preparation boundaries | Plan helper preparation, prepared spec/policy inputs and FC stop-wrapper cuts separately; retain low descriptor/process mechanisms. |

Once the relevant prerequisites pass review and validation, follow ADR-061's
accepted extraction order. This attachment does not schedule those extractions
or claim that P1 alone removes the hostd source cycles.

## Open questions and assumptions

No unresolved owner contract choice for P1. The source must still match the
snapshot at execution time, and baseline test failures require diagnosis.
The compatibility facade intentionally remains until its consumers migrate in
later authorized extractions; removing it is not part of this prerequisite.
