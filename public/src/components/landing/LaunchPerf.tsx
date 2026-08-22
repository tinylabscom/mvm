import { Eyebrow } from "./primitives/Eyebrow";
import { Reveal } from "./primitives/Reveal";
import { Section } from "./primitives/Section";
import { MEASUREMENT, PERCENTILES, PERF_LANE, type Percentile } from "./perf";

// The arc spans zero to the *budget*, so a full sweep is the ceiling and the
// fill is how much of it the measured launch actually spent. That mapping is
// chosen so the picture cannot make the claim the performance page warns
// about: there is no scale on which a measurement can be mistaken for the
// ceiling, because the ceiling is the arc itself.
//
// `pathLength={100}` renormalizes the arc so stroke-dasharray is read in
// percent — no arc-length arithmetic to drift when the radius changes.
const ARC = "M 8 60 A 52 52 0 0 1 112 60";

function Gauge({ p }: { p: Percentile }) {
  // Rounded before it reaches the attribute: an unrounded ratio serializes
  // as 70.39999999999999 in the markup, which reads as spurious precision
  // on a page whose argument is that its numbers are exact.
  const pct = Math.round((p.measuredMs / p.budgetMs) * 1000) / 10;
  // A reading this close to its ceiling is a warning, not a pass. The
  // threshold is deliberately blunt: the point is that the colour is
  // derived from the numbers, so it cannot flatter a regression.
  const nearCeiling = pct >= 90;

  return (
    <div className="h-full rounded-xl border border-glass-border/60 bg-raised p-5">
      <div className="flex items-baseline justify-between gap-2">
        <p className="font-mono text-[11px] font-semibold tracking-[0.14em] uppercase text-label">
          {p.label}
        </p>
        <span className="shrink-0 font-mono text-[10px] uppercase tracking-widest text-label">
          {Math.round(pct)}% of ceiling
        </span>
      </div>

      <svg
        viewBox="0 0 120 68"
        className="mt-4 w-full"
        role="img"
        aria-label={`${p.label} dispatch ${p.measuredMs} milliseconds, against a ${p.budgetMs} millisecond ceiling`}
      >
        <path
          d={ARC}
          fill="none"
          stroke="var(--color-edge)"
          strokeWidth="8"
          strokeLinecap="round"
        />
        <path
          d={ARC}
          fill="none"
          stroke={nearCeiling ? "var(--color-amber)" : "var(--color-accent)"}
          strokeWidth="8"
          strokeLinecap="round"
          pathLength={100}
          strokeDasharray={`${pct} 100`}
        />
      </svg>

      <p className="-mt-4 text-center font-display text-3xl font-bold leading-none text-title">
        {p.measuredMs.toFixed(1)}
        <span className="ml-1 text-base font-normal text-label">ms</span>
      </p>
      <p className="mt-2 text-center font-mono text-[11px] text-label">
        ceiling {p.budgetMs} ms
      </p>
    </div>
  );
}

export function LaunchPerf() {
  const rawBase = import.meta.env.BASE_URL;
  const base = rawBase.endsWith("/") ? rawBase : `${rawBase}/`;

  return (
    <Section id="launch-performance" rule>
      <Reveal>
        <Eyebrow>Performance</Eyebrow>
        <h2 className="lowercase font-display text-2xl font-bold leading-tight text-title sm:text-3xl">
          measured, not asserted.
        </h2>
        <p
          className="max-w-2xl text-sm leading-relaxed text-body"
          style={{ marginTop: "1rem" }}
        >
          The dispatch window — an admitted execution plan to the guest command
          running. The arc is the budget CI enforces on every launch; the fill
          is what one named host actually did, revalidated sample by sample
          before it was allowed onto the page.
        </p>
      </Reveal>

      <div
        className="grid gap-3 sm:grid-cols-3"
        style={{ marginTop: "3rem" }}
      >
        {PERCENTILES.map((p, i) => (
          <Reveal key={p.label} delay={i * 80}>
            <Gauge p={p} />
          </Reveal>
        ))}
      </div>

      {/* Provenance is not a footnote here. The performance page refuses a
          number whose host fingerprint it does not know, so reprinting the
          number without the fingerprint would launder exactly the context
          that makes it checkable.

          Inline margin, not mt-*: Starlight's unlayered stylesheet beats
          layered utilities on this page (see Positioning.tsx) — a margin
          utility here collapses to zero and runs this list into the cards. */}
      <dl
        className="grid gap-x-6 gap-y-2 font-mono text-xs leading-relaxed text-label sm:grid-cols-2"
        style={{ marginTop: "2rem" }}
      >
        <div>
          <dt className="inline text-dim">lane </dt>
          <dd className="inline">{PERF_LANE}</dd>
        </div>
        <div>
          <dt className="inline text-dim">backend </dt>
          <dd className="inline">{MEASUREMENT.backend}</dd>
        </div>
        <div>
          <dt className="inline text-dim">host </dt>
          <dd className="inline">{MEASUREMENT.host}</dd>
        </div>
        <div>
          <dt className="inline text-dim">storage </dt>
          <dd className="inline">{MEASUREMENT.storage}</dd>
        </div>
        <div>
          <dt className="inline text-dim">samples </dt>
          <dd className="inline">{MEASUREMENT.samples}</dd>
        </div>
        <div>
          <dt className="inline text-dim">date </dt>
          <dd className="inline">{MEASUREMENT.date}</dd>
        </div>
      </dl>

      <p
        className="max-w-2xl font-mono text-xs leading-relaxed text-label"
        style={{ marginTop: "1.75rem" }}
      >
        Measured on spinning media, where a large fixed fraction of the window
        is <code>fsync</code> cost that disappears on NVMe — so this is a
        pessimistic reading, not a favourable one. Budgets, disqualification
        rules, and the raw report digest are on the{" "}
        <a
          href={`${base}reference/performance/`}
          className="text-accent underline underline-offset-2 hover:text-accent/80"
        >
          launch performance
        </a>{" "}
        page.
      </p>
    </Section>
  );
}
