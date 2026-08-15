# Plan 331 — Unblocked closeout batch

**Status:** IN PROGRESS — opened 2026-08-14
**Tracks:** #2256 (#2107 closed by PR #2475)
**Parent:** `specs/plans/300-open-issue-closeout.md` Phases 2 and 5
**Design source for the WS items:** `specs/plans/306-declared-backing-and-tier-honesty.md`

## Why this plan exists

Plan 300's second reconciliation left 23 open issues. Eleven of them are blocked
on something this repository does not control — a Linux host with `/dev/kvm`
**and** NVMe for #2299/#2280, live KVM and Apple Silicon validation for the
warm-pool chain, `mvm-studio#18` for #2083, and a live egress witness for
#2371/#2372 now that FlowMux turns out not to be on the production path.

This plan is the batch that needs none of that. It exists so the hardware
decision and the code work stop blocking each other: everything here can land
while a machine is being provisioned, and none of it depends on one.

Scope is deliberately narrow. #2211 is excluded because it needs a scope
decision before it needs code, and #2169 is excluded because it is a large
contract surface that deserves its own plan rather than a slot in a batch.

## Ordering

WS1 and WS4 first. WS1 closes a defect this repository has already been bitten
by — the fabricated witness names that lived in `specs/` and `CLAUDE.md` for
months precisely because `check-doc-claims` does not scan them. WS4 is a
paragraph that the later workstreams reason against. WS5, WS6, WS7 and #2107
are mutually independent after that.

WS2 and WS3 from Plan 306 are **not** in this batch: WS2 depends on #2248's
`capabilities()` shape and WS3's fail-closed probe wants a live backend to
probe, which puts it with the hardware-gated set.

## Workstreams

### A — #2107: mirror chain-signed audit appends into tracing — **LANDED ELSEWHERE**

Delivered by **PR #2475** (`b26496f2b`) in a concurrent session; #2107 is closed.
`supervisor::audit_mirror::emit_mirror_event` emits one event at target
`mvm::audit`, omits `labels` wholesale, and wraps the emit in `catch_unwind` so
a panicking subscriber cannot unwind into the appender. Both call sites
(`audit_recorder::record_plan_bound`, `audit::emitter`) `?` on `sign_and_emit`
before mirroring, so a failed append correctly emits nothing.

I implemented this independently before noticing #2475 and threw that work away
rather than contest a merged, working implementation. Two of the issue's stated
acceptance criteria are nevertheless **not witnessed** by what merged, and those
tests are additive rather than duplicative:

- [x] *"Chain bytes are byte-identical with the mirror enabled vs disabled."*
      True by construction — the mirror runs after the write and touches
      nothing — but untested. Use a fixed key and fixed timestamp so the two
      runs are comparable; a fresh key changes every signature and makes the
      comparison vacuous. Assert the subscriber observed something, so the test
      cannot pass by mirroring nothing at all.
- [x] A failed append emits **no** mirrored event. Correct today because both
      call sites `?` first, but nothing pins that ordering — a future
      refactor that hoists the mirror above the `?` would go unnoticed.

Deliberately **not** pursued, recorded so it is a decision rather than an
oversight:

- The issue asked for a `sequence` field and the merged mirror has none. In a
  hash chain, position is the tip hash; adding one means threading the chain
  tip out of the signer to the recorder, which is a wider change than the gap
  justifies. Raise it separately if an operator actually needs to order
  mirrored events without reading the chain.
- The merged mirror is called from two sites rather than from the single append
  path, so an emitter could add a third and forget. Not worth churning a merged
  implementation over; noted for whoever touches that surface next.

### B — Plan 306 WS1: declared backing on claim-bearing contributor prose

- [ ] Add a `Backing:` / `Validation:` header to every file under
      `specs/adrs/`, `specs/plans/`, plus `CLAUDE.md` and `AGENTS.md`.
- [ ] `Backing` enum: `shipped-source | checked-example | generated | preview |
      historical`. `Validation`: an xtask gate, test, or CI job name, or `none`.
- [ ] `xtask check-declared-backing` enforces: the block is present and both
      values are in the enum; a `Validation` naming a gate or job resolves —
      reusing `check-witness-citations`' resolver rather than writing a second
      one; a `shipped-source` file may not cite a `preview` file as evidence
      (the one-way citation rule that stops a preview claim laundering itself
      into a shipped one); and a `preview` file may not use the assertive
      vocabulary `check-honesty` already enumerates.
- [ ] Ship `--self-test`: copy the tree, seed one violation of each rule, assert
      a nonzero exit. A gate nobody has watched fail is a gate nobody knows
      works.
- [ ] Register in xtask help, the available-commands list, and CI.

### C — Plan 306 WS4: state the check-time law in ADR-001

- [ ] Write the law: *an effect may be checked no later than its last undo
      point.* A reversible effect can be checked at commit; an irreversible one
      — network egress, a published artifact, a released secret — must be
      checked before it happens.
- [ ] Add a column classifying each governed effect as checked-before or
      checked-at-commit. The value is prospective: it turns "where does this new
      effect's gate go?" into a lookup, and it explains why `EgressGate` sits
      before the connection while the audit chain records after.

### D — Plan 306 WS5: pin the egress predicate algebra

- [ ] Audit the current network-policy resolution against the intended order,
      then state it in one place with tests: within a grant, negation scopes
      only that grant's positives (deny-wins); across grants, union; absent any
      admitting grant, default-deny.
- [ ] An unrecognised predicate operator **raises** rather than falling through
      to allow. Test the unknown-operator path explicitly.
- [ ] Replace the boolean escape hatch `MVM_ACK_UNRESTRICTED_NETWORK` with an
      enumerated third verdict that is **deny-loud** until an approval path
      exists. The vocabulary should admit the case the product will need without
      shipping an env var that turns enforcement off.

### E — Plan 306 WS6: freeze JCS replay vectors for the audit chain

- [ ] Add frozen vectors for `CanonicalEntry`'s JCS bytes — the thing a third
      party verifies, and the one thing `address_vectors.rs` does not cover.
- [ ] Cover the three cases where independent implementations actually diverge
      and which the current vectors do not exercise at all: a non-ASCII string,
      an integer above 2^53, and a float, which must be **refused** rather than
      rounded.
- [ ] Decide on a version-tag byte prefix on the signed bytes so a future
      profile change cannot collide with already-published digests. Wire-
      breaking, so it lands as a hard change under the no-back-compat rule or
      not at all — record the decision either way.

### F — Plan 306 WS7: double-key the stale-name relief valves

- [ ] Convert `check-no-vz` and the oblique-naming exemptions to require **two**
      keys for the same relief: a page-level marker **and** enumeration in an
      allowlist file whose comment names the owning reason. The marker alone
      must fail.
- [ ] The allowlist header states the intended end state, so the list is
      self-documenting and visibly shrinking.

## Definition of done

- [ ] Every checkbox above is complete with its tests green.
- [ ] `cargo fmt --all -- --check`, `cargo nextest run --workspace`,
      `cargo test --workspace --doc`, and
      `cargo clippy --workspace --all-targets -- -D warnings` pass.
- [ ] Linux-gated code cross-checks with `cargo zigbuild --target
      x86_64-unknown-linux-gnu --all-targets`.
- [ ] Every new gate is registered in xtask help and CI, and has watched itself
      fail at least once via `--self-test`.
- [ ] Plan 306's WS1/WS4/WS5/WS6/WS7 boxes are ticked in the same change that
      makes each true, and Plan 300, `specs/SPRINT.md`, and
      `specs/REFACTOR-STATUS.md` agree.
- [ ] #2107 closes. #2256 closes only when WS2 and WS3 also land — they are not
      in this batch, so this plan does **not** close it.

## Deliberately out of scope

- **Plan 306 WS2** — depends on #2248's `capabilities()` shape.
- **Plan 306 WS3** — its fail-closed probe wants a live backend to probe, which
  puts it with the hardware-gated set.
- **#2211** — needs a scope decision (narrow to the landed spike, or complete
  the byte/latency tuple) before it needs code.
- **#2169** — a large contract surface that deserves its own plan.
- Anything requiring a live VM, a KVM host, or Apple Silicon validation. That is
  the whole point of this batch.
