// Launch numbers shown on the homepage, mirrored from the published
// performance page. `scripts/check-perf-provenance.mjs` re-parses that page
// and fails if any value here drifts, so this file is a cache of the source
// of truth rather than a second copy of it.
//
// The budget/measurement split is the whole point and must survive any edit
// here: a budget is a ceiling CI enforces, a measurement is something a
// named host actually did. The performance page keeps them in separate
// tables precisely so a ceiling is never read as a result — this section
// keeps them in separate *roles*, ceiling as the arc's full sweep and
// measurement as the fill, which is the same distinction drawn visually.

/** Page the provenance gate parses. Repo-root-relative. */
export const PERF_SOURCE = "public/src/content/docs/reference/performance.md";

/** The lane both tables on that page describe. */
export const PERF_LANE = "prepared_cold";

export type Percentile = {
  /** Column heading in both source tables. */
  label: "p50" | "p95" | "p99";
  /** Ceiling from the generated budget table. */
  budgetMs: number;
  /** Observation from the seeded measurements table. */
  measuredMs: number;
};

export const PERCENTILES: Percentile[] = [
  { label: "p50", budgetMs: 200, measuredMs: 171.5 },
  { label: "p95", budgetMs: 250, measuredMs: 176.0 },
  { label: "p99", budgetMs: 300, measuredMs: 178.0 },
];

/** The seeded row's provenance columns, verbatim from the page. */
export const MEASUREMENT = {
  date: "2026-08-19",
  host: "Linux 6.8.0-137 x86_64, Intel i7-7700",
  backend: "Firecracker v1.14.1",
  storage: "rotational md-RAID (ROTA=1)",
  samples: "20 (+2 warm-ups)",
} as const;
