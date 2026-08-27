# SDK surface contract repairs

Backing: shipped-source
Validation: check-sprint-append

## Status

In progress. Implementation and local verification are complete; merge-queue
delivery remains.

## Scope

Two documented recovery paths had drifted from their executable surfaces:

- the README's Python decorator used `source=mvm.local_path(".")`, but the
  static compiler rejected that exported SDK helper before lowering; and
- the builder-pack download refusal recommended the removed root Cargo feature
  `manifest-verify`, so following the error could not compile.

The repair keeps the public SDK and compiler aligned. `mvm.local_path` is now a
strictly lowered source helper with typed path, include, and exclude handling;
malformed inputs fail at the decorator boundary. The download refusal names the
existing root feature aggregation, `user,release-artifact-bootstrap`.

## Tasks

- [x] Reproduce the documented decorator failure with the exact helper shape.
- [x] Add `mvm.local_path` to the shared allowlist and lower its source fields.
- [x] Add negative coverage for a missing path and malformed include entries.
- [x] Correct the builder-pack remediation and pin it with a unit test.
- [x] Pass the full `mvm-sdk` suite, focused `mvm-cli` test, formatting, and
      package Clippy with warnings denied.
- [ ] Merge the repair PR and verify issues #2902 and #2906 close through the
      merge commit.

