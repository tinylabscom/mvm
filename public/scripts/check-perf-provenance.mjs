// Every launch number on the homepage must still be the number the published
// performance page states. A landing page that quotes a stale percentile is
// worse than one that quotes none: the perf page's whole contract is that a
// number travels with the host that produced it, and a drifted copy breaks
// that silently while still looking authoritative.
//
// This parses the two tables on that page separately and on purpose. The
// budget table is generated from the Rust accessor CI gates against; the
// seeded table is an observation with a fingerprint. Conflating them is the
// specific failure the page is built to prevent, so the gate that guards the
// homepage copy refuses to conflate them either.
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";

const repoRoot = resolve(import.meta.dirname, "..", "..");
const perfPath = join(import.meta.dirname, "..", "src/components/landing/perf.ts");
const { PERCENTILES, MEASUREMENT, PERF_SOURCE, PERF_LANE } = await import(perfPath);

const failures = [];
const fail = (m) => failures.push(m);

let page;
try {
  page = readFileSync(join(repoRoot, PERF_SOURCE), "utf8");
} catch {
  console.error(`Perf provenance failures:\n  source not found: ${PERF_SOURCE}`);
  process.exit(1);
}

// Backticks are markdown, not data: the page writes `prepared_cold` and
// (`ROTA=1`) as code spans, and the homepage renders them as plain text.
const cells = (row) => row.split("|").slice(1, -1).map((c) => c.replaceAll("`", "").trim());
const rows = page.split("\n").filter((l) => l.trimStart().startsWith("|"));
const ms = (cell) => {
  const m = /^([0-9]+(?:\.[0-9]+)?) ms$/.exec(cell);
  return m ? Number(m[1]) : null;
};

// --- Budget table: the ceilings CI enforces -------------------------------
// Read only from inside the generated region, so a hand-written example
// table elsewhere on the page can never be mistaken for the contract.
const genStart = page.indexOf("<!-- generated:launch-budgets:begin -->");
const genEnd = page.indexOf("<!-- generated:launch-budgets:end -->");
if (genStart === -1 || genEnd === -1 || genEnd < genStart) {
  fail("generated launch-budget markers not found on the performance page");
}
const generated = genStart === -1 ? "" : page.slice(genStart, genEnd);
const budgetRow = generated
  .split("\n")
  .filter((l) => l.trimStart().startsWith("|"))
  .map(cells)
  .find((c) => c[0] === PERF_LANE);

if (!budgetRow) {
  fail(`no generated budget row for lane \`${PERF_LANE}\``);
} else {
  // Columns: lane | what it measures | p50 | p95 | p99 | every boot
  const budgets = { p50: ms(budgetRow[2]), p95: ms(budgetRow[3]), p99: ms(budgetRow[4]) };
  for (const p of PERCENTILES) {
    const want = budgets[p.label];
    if (want === null || want === undefined) {
      fail(`budget table has no parseable ${p.label} for \`${PERF_LANE}\``);
    } else if (want !== p.budgetMs) {
      fail(`${p.label} budget drifted: perf.ts says ${p.budgetMs} ms, page says ${want} ms`);
    }
  }
}

// --- Seeded table: one observation, with its fingerprint ------------------
// Columns: date | lane | host | backend | storage | samples | p50 | p95 | p99
const seededRow = rows
  .map(cells)
  .find((c) => c.length === 9 && c[1] === PERF_LANE && c[0] === MEASUREMENT.date);

if (!seededRow) {
  fail(
    `no seeded measurement row for lane \`${PERF_LANE}\` dated ${MEASUREMENT.date} ` +
      `— if the seeded row was replaced, update perf.ts to the new row rather than keeping the old numbers`,
  );
} else {
  const provenance = [
    ["host", MEASUREMENT.host, seededRow[2]],
    ["backend", MEASUREMENT.backend, seededRow[3]],
    ["storage", MEASUREMENT.storage, seededRow[4]],
    ["samples", MEASUREMENT.samples, seededRow[5]],
  ];
  for (const [field, ours, theirs] of provenance) {
    if (ours !== theirs) {
      fail(`${field} drifted: perf.ts says "${ours}", page says "${theirs}"`);
    }
  }

  const measured = { p50: ms(seededRow[6]), p95: ms(seededRow[7]), p99: ms(seededRow[8]) };
  for (const p of PERCENTILES) {
    const want = measured[p.label];
    if (want === null || want === undefined) {
      fail(`seeded table has no parseable ${p.label} measurement`);
    } else if (want !== p.measuredMs) {
      fail(`${p.label} measurement drifted: perf.ts says ${p.measuredMs} ms, page says ${want} ms`);
    }
  }
}

// --- The gauge's own precondition -----------------------------------------
// The arc spans zero to the budget, so a measurement above its ceiling would
// render as a full sweep and read as "exactly at budget" — the one way this
// section could show a passing picture of a failing number.
for (const p of PERCENTILES) {
  if (p.measuredMs > p.budgetMs) {
    fail(
      `${p.label} measurement ${p.measuredMs} ms exceeds its ${p.budgetMs} ms ceiling; ` +
        `the gauge cannot render this honestly and the homepage must not claim it`,
    );
  }
}

if (PERCENTILES.length === 0) {
  fail("PERCENTILES is empty — the homepage section would render no readings");
}

if (failures.length) {
  console.error("Perf provenance failures:\n  " + failures.join("\n  "));
  process.exit(1);
}
console.log(`perf provenance OK (${PERCENTILES.length} percentiles against ${PERF_SOURCE})`);
