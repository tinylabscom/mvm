# Issue #2940 — audit root-history classification

`mvmctl doctor` used to classify every otherwise-unreserved `.jsonl` file in
the audit directory as a lifecycle chain. The signed Merkle-root history uses
the same extension but a distinct envelope, so healthy hosts were reported as
tampered.

The audit filename contract now names the root-history suffix centrally. Both
the writer and lifecycle classifier use it, and the lifecycle base parser also
refuses the distinct format. Tests cover the exact filename written by the
emitter while retaining retired lifecycle segments in the verification set.
