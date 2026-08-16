# Published launch budgets

mvm's differentiator is launch latency, and the number appeared nowhere a user
could read it. The bench harness under `crates/mvm-cli/src/bench/` already
encoded a full publication contract — per-lane dispatch-window budgets, a
20-sample/2-warm-up floor, a report-level gate that refuses a contaminated or
under-sampled lane — and none of it was published. `public/src/content/docs/`
had no performance page at all; `reference/limits.md` is a limits table, not a
measurement or a budget.

Plan 299 named this outstanding: "the real-host backend matrix and canonical
budget table remain". This is the canonical budget table half. The real-host
matrix still needs a seeded lane report and is not in this change.

## One source for a budget

`validate_matrix_report` matched on the lane and inlined each constant at the
call site. A published table built the same way would have been a second copy
of the budget list, free to drift from the gate silently — which is the failure
this page exists to avoid.

`LaunchLane::budgets()` is now the single accessor. It returns `LaneBudgets`
with an `Option<f64>` per percentile, where `None` means "this lane publishes no
budget here" and can never be confused with zero. `validate_matrix_report` zips
it against `SpanStats::by_percentile()` — both sides expose the same
`[(label, Option<f64>); 3]` shape, so neither names a percentile as a bare
string. Behaviour is unchanged: the existing 92 bench tests pass untouched.

The acquisition lanes (`mount_miss`, `artifact_miss`) return all-`None`. Their
cost is dominated by a registry and a disk, and gating on that would measure
someone else's network.

## The page and its gate

`bench/doc_table.rs` renders the budget section from that accessor, bounded by
`<!-- generated:launch-budgets:begin -->` / `:end` markers. Prose outside the
markers is hand-written and untouched by the generator.

`tests/perf_doc_sync.rs` pins the committed page to the render. Both directions
were confirmed red before being fixed: hand-editing a budget cell in the page
fails it, and changing `PREPARED_COLD_P50_BUDGET_MS` without regenerating the
page fails it. The failure message prints the correct section to paste.

## What the page deliberately does not say

It publishes budgets, labelled as ceilings CI enforces, not as percentiles
anyone observed — with a test asserting the page keeps saying so. A ceiling in
the same column as an observation gets read as an observation, and mvm has no
seeded matrix report to publish observations from yet.

It also states that a number measured on rotational storage is not a runtime
number, because a large fixed fraction of such a launch is `fsync` cost that
disappears on NVMe.
