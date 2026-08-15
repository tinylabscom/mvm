# Plan 306 — Declared backing, tier honesty, and the check-time law

**Status: OPEN — no workstream started**

Tracking: #2256

## Why

An external agent-supervision substrate (reviewed 2026-08-08; a Python
runtime that records agent runs as reversible traces and confines them with
Seatbelt/Landlock rather than a VMM) solves several problems one layer above
ours, and solves four of them better than we do. This plan takes those four
and nothing else.

The reason its answers transfer despite the different isolation tier: it
treats *"can this claim be trusted?"* as a machine-checkable property of the
artifact making the claim, rather than a review discipline. That is the same
disease we have documented in our own tree — `check-witness-citations` exists
because `CLAUDE.md` cited a witness that never existed and was believed for
months.

What we already have, and therefore what this plan does **not** redo:

- `check-witness-citations` — a cited identifier must denote something.
- `check-doc-claims` / `check-no-overclaim` — gated phrases require a
  `Shipped` claim, with per-claim `exempt_paths` relief valves.
- `check-honesty` — no assertive verbs attached to an `open` claim.
- `check-claim-witness-freshness` — a `ci:` witness whose lane stopped
  running is stale, not green.
- `VmBackend::negotiate` + `CapabilityAlternative::None` (#2248) — a typed
  refusal that names a substitute or names why there isn't one.
- `crates/mvm-contract/tests/address_vectors.rs` — frozen replay vectors for
  `ir_hash` and the Merkle surface.

## Workstreams

- [ ] **WS1 — Declared backing on claim-bearing contributor prose.**
      `check-doc-claims` deliberately scans only `public/` and the root
      `README.md`: "`specs/`, `CLAUDE.md`, `AGENTS.md`, and crate-level
      `*.md` are contributor-facing, not user-facing. We don't lint them."
      That exclusion is the hole the fabricated witness names lived in for
      months. The fix is not to point the phrase lint at contributor prose —
      it is to make each claim-bearing file declare *what backs it*.

      Add a header block to every file under `specs/adrs/`, `specs/plans/`,
      `CLAUDE.md`, and `AGENTS.md`:

      ```
      Backing: shipped-source | checked-example | generated | preview | historical
      Validation: <xtask gate / test / CI job name, or `none`>
      ```

      `xtask check-declared-backing` then enforces four things: the block is
      present and both values are in the enum; a `Validation` naming a gate
      or job resolves (reuse `check-witness-citations`' resolver rather than
      writing a second one); a file declaring `shipped-source` may not cite a
      `preview` file as its evidence (the one-way citation rule — this is
      what stops a preview claim laundering itself into a shipped one); and a
      file whose `Backing` is `preview` may not use the assertive vocabulary
      `check-honesty` already enumerates.

      Ship the gate with a `--self-test` that copies the tree, seeds one
      violation, and asserts a nonzero exit. A gate nobody has watched fail
      is a gate nobody knows works.

- [ ] **WS2 — Derive the ADR-001 per-backend tier matrix from code.** The
      matrix is prose asserted *about* the backends. #2248 gives every
      backend a uniform `capabilities()` / `negotiate()` surface, which makes
      the matrix computable. Add a test that renders the matrix from the
      backend set and compares it to the ADR-001 table, failing on either
      direction of drift. The ledger stays authoritative; it stops being
      hand-maintained.

      Reference model: the external substrate carries `name` and
      `enforcement_tier` as fields on the containment backend itself, so
      "which tier is this?" is a value read off the object rather than a row
      someone remembered to update.

- [ ] **WS3 — Refuse what we cannot enforce exactly.** Their rule:
      *a confinement spec with no faithful lowering on this host refuses to
      run rather than running under a weaker profile.* We have two live sites
      that do the opposite and silently degrade:

      - transient-lifecycle egress resolves to `AllowAll` on libkrun and HVF
        (only Firecracker enforces);
      - `mvmctl up --network-allow` on libkrun enforces nothing.

      Convert both to typed refusals through `negotiate`, so the caller gets
      either enforcement or an error naming the tier that can serve it.
      `CapabilityAlternative::None` is already the right shape for the case
      with no substitute.

      Second half: a fail-closed **probe before the body runs**. Theirs
      checks both jail liveness *and* conformance to the requested surface,
      and refuses to proceed unconfined. Ours asserts the gate is wired by
      construction (`check-uniform-vsock-egress`) but never asks the running
      host whether it took. Add the probe to the shared spawn seam so one
      site covers all three workload backends.

- [x] **WS4 — Write the check-time law into ADR-001.** One sentence, which we
      obey in two places without ever having stated it: *an effect may be
      checked no later than its last undo point.* A reversible effect can be
      checked at commit; an irreversible one — network egress, a published
      artifact, a released secret — must be checked before it happens.

      Add the law plus a column classifying each governed effect as
      checked-before or checked-at-commit. The value is prospective: it turns
      "where does this new effect's gate go?" from a judgement call into a
      lookup, and it explains why `EgressGate` sits before the connection
      while the audit chain records after.

- [ ] **WS5 — Pin the egress predicate algebra and enumerate escalation.**
      Audit our network-policy resolution against their pinned order, then
      state ours in one place with tests: within a grant, negation scopes
      only that grant's positives (deny-wins); across grants, union; absent
      any admitting grant, default-deny. An unrecognised predicate operator
      must raise, never fall through to allow.

      Then replace the boolean escape hatch (`MVM_ACK_UNRESTRICTED_NETWORK`)
      with an enumerated third verdict that is **deny-loud** until the
      approval path exists. Their `ESCALATE` is enumerated but denies today;
      the point is that the vocabulary admits the case the product will need
      without shipping an env var that turns enforcement off.

- [x] **WS6 — Replay vectors for the audit chain's signed bytes.**
      `address_vectors.rs` covers `ir_hash` and Merkle; the audit chain's
      `CanonicalEntry` JCS bytes — the thing a third party verifies — has no
      frozen vector. Add them, including the three cases where independent
      implementations actually diverge and which our current vectors do not
      exercise at all: a non-ASCII string, an integer above 2^53, and a
      float (which must be refused, not rounded). This matters because
      `mvm-contract` is meant to reach the browser, i.e. a second verifier
      implementation is coming.

      Also consider a version-tag byte prefix on the signed bytes (theirs
      prefixes `commons.canonical.v1\n`), so a future profile change cannot
      collide with digests already published. Wire-breaking, so it lands as a
      hard change under the no-back-compat rule or not at all.

      **Landed** as `crates/mvm-contract/tests/audit_canonical_vectors.rs`.
      Non-ASCII round-trips byte for byte and is asserted to emit raw UTF-8
      rather than `\u` escapes; an integer past 2^53 is refused rather than
      rounded; a float is refused in an integer field **including `1.0`**,
      because accepting it would decide that two distinct byte sequences are
      the same entry. Label ordering is pinned too — a verifier re-serializing
      from a hash map emits a different order per run.

      One honest gap recorded in the test: `plan_version` is a `u32`, so the
      2^53 case is refused for a narrower reason than precision, and **a future
      `u64`/`i64` field in the signed entry would not inherit that protection**
      and needs its own vector. The version-tag prefix is **not** taken — it is
      wire-breaking and no second verifier exists yet to collide with.

- [ ] **WS7 — Double-key the stale-name relief valves.** `check-no-vz` and
      the oblique-naming rule are binary: a path is exempt or it is not.
      Theirs requires *two* keys for the same relief — a page-level marker
      **and** enumeration in an allowlist file whose comment names the owning
      reason — so the marker alone fails, and the file header states the
      intended end state ("forward entries gone"). Convert our exemptions to
      that shape so the list is self-documenting and visibly shrinking.

## Not in scope

- **Signature-as-permission-surface.** Their strongest single idea — the
  permission grant rides the function parameter, so "there is no second
  policy file the code merely approximates" — does not transfer. We need the
  grant *detached* from the workload so it can be signed, transported, and
  verified by a supervisor that never sees the source. The derived rule we
  can take is narrower and belongs to the IR work, not here: a workload's
  ceiling should be *derived from* its declared grants rather than declared
  twice.
- **The carrier axis.** Their Device = Containment × Carrier split is right,
  but the reversibility half is already moving in #2250's snapshot-seam
  extraction. WS2 takes the containment half only.
- **Their docs pipeline machinery** — numbered shell scripts, a promote step,
  a page-mode taxonomy, a generated public-symbol snapshot. WS1 takes the
  header and the admission rule; the machinery is theirs to maintain.
- **Their source-comment convention.** Their modules cite spike ids, decision
  records, and design-doc sections inline. We gate against exactly that
  (`check-no-spec-refs-in-comments`) and our rule is the better one.
