# Signed caller commitment

Backing: shipped-source
Validation: check-sprint-append

**Status: IMPLEMENTED AND VALIDATED — MERGE DELIVERY REMAINS**

Issue #3070 asks whether an external settlement or escrow verifier can bind a
pre-agreed task-spec digest to the exact execution MVM admits. `audit_labels`
are signed today, but they are free-form operational metadata, are not bounded,
and can be overwritten by event-specific audit extras. A financial verifier
should not depend on those incidental properties.

This change adds one optional, opaque 32-byte caller commitment to the typed
execution contract. MVM validates and preserves the bytes but assigns them no
meaning. The commitment is covered by the plan content address and host
signature, copied into every chain-signed plan audit entry as a typed field,
and accepted by the user-facing launch commands.

## Contract

- [x] Add a canonical lowercase-hex `CallerCommitment` newtype with strict
      32-byte parsing, serde round trips, and negative tests.
- [x] Add an optional skip-serialized commitment to `ExecutionPlan` and
      `PlanAuditEntry`; prove absence preserves frozen bytes and presence is
      covered by the plan and audit signatures.
- [x] Thread the value through `SynthesisInput` and its builder.

## Surfaces

- [x] Add `--caller-commitment HEX` to `run` and `machine run`, whose shared
      admission seam replaces the retired public `up` surface, with CLI
      parsing/help regressions.
- [x] Thread it through plan-mode, transient/local, and persistent admission
      without exposing a generic audit-label flag.
- [x] Copy the typed plan field into all plan-derived audit entries without
      using or colliding with the free-form labels map.

## Validation and delivery

- [x] Add focused unit, integration, and BDD coverage for the user-visible
      commitment-to-audit workflow.
- [x] Run workspace tests/check, gated-target checks, formatting, and
      zero-warning workspace Clippy.
- [x] Update the sprint delivery record and refactor rollup.
- [ ] Merge through the queue and close #3070 from landed evidence.
