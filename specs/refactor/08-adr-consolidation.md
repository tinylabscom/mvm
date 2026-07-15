# ADR Consolidation

How `specs/adrs/` went from a sprawling, duplicate-numbered legacy set to a clean, contiguous plan-of-record.

## As landed

The 92 legacy ADRs were consolidated into **30 contiguous ADRs** (`specs/adrs/001..030`), each rewritten as an absolute decision record (stating the decision as it stands today, not as a chronological narrative of how the team got there). The claims ledger is fenced as machine-checked data in **ADR-001**; the trust gradient is fenced as machine-checked data in **ADR-020**. Both are parsed by CI gates (`check-claim-catalog`, and the trust-gradient check bundled with ADR-020's coverage), so the ADR text and the enforced reality can't silently drift apart the way the old prose-only ADRs could.

This is a materially different outcome than the original WS0.2 target of "~92 → ~15" (see [06-execution-plan.md](06-execution-plan.md) WS0.2) — the consolidation ran further than first scoped, landing at 30 rather than ~15, because the cluster-merge work surfaced more genuinely distinct decisions than the original estimate assumed. The count itself isn't load-bearing; what matters is that it's contiguous, absolute-form, and machine-checked.

## Historical consolidation map

The cluster table below is the map used to do the merge — which legacy ADR numbers fed into which theme. It's retained here as the historical record of the consolidation, not as a live index (use `specs/adrs/001..030` directly for that).

| Canonical ADR (theme) | Merge these |
|---|---|
| Security posture & trust boundary (SoT) | 002, 032, 063, 070, 083, 088, 104, 108, 109, 111 + claims + compliance + threat-models |
| Networking / egress / vsock | 004, 006, 055, 064, 067, 078, 082, 085, 100, 101, 110 |
| Backends / hypervisor abstraction | 014, 046, 056, 072, 076, 093, 094, 095, 098, 099, 102 |
| Builder VM / Stage 0 / seed | 005, 013, 054, 057, 065, 068, 071, 096, 106, 107 |
| Host services broker / daemon | 059, 061, 062, 084, 089, 090 |
| Signed/audited execution + claims substrate | 041, 044, 047, 048, 058, 079, 103 |
| OCI / image / registry / verity | 050, 052, 074, 097 |
| Secrets substitution | 049, 067 |
| Machine / CLI surface | 077, 091, 092, 105 |
| Function entrypoints / factories | 007, 008, 010, 011, 039 |
| Encryption | 027, 042 |
| WASM path | 069, 080, 081 |

Note: the legacy numbers in this table refer to the pre-consolidation ADR numbering, not the current `001..030` set — they're historical references, not links into the current tree.

See [07-progress-and-decisions.md](07-progress-and-decisions.md) for the commit-level record of when this landed, and [04-security.md](04-security.md) for how the resulting security model (claims, verified boot, secrets) is described in this document set.
