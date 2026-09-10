import { Section } from "./primitives/Section";
import { Eyebrow } from "./primitives/Eyebrow";
import { Reveal } from "./primitives/Reveal";

// The pitch script's timing argument, second half. WhyNow (near the top of
// the page) carries the builder side — AI proliferation and the fear of
// going hands-off. This section carries the regulator side, which the page
// previously omitted on purpose (WhyNow's old "no regulator names" note):
// the pitch leans on it as the reason the Execution Contract matters
// *now*, so it gets its own beat. Facts here stay at the level the pitch
// states them — named acts, no invented dates, fines, or clause numbers.
const SIDES = [
  {
    label: "the builders",
    body: "An explosion of AI startups is shipping agents into production — and not all of them are building securely.",
  },
  {
    label: "the regulators",
    body: "The EU AI Act and emerging state legislation push for more logging, more auditing, more visibility, and more control over what agents do — and what they're allowed to do.",
  },
];

export function RegulatorsNow() {
  return (
    // Canvas background: RiskControl above is raised, so this stays on the
    // canvas to preserve the alternation.
    <Section id="regulation" rule>
      <Reveal>
        <Eyebrow>Why now</Eyebrow>
        {/* Inline margins, not margin utilities: Starlight's unlayered
            stylesheet beats layered utilities on this page (see
            Positioning.tsx). */}
        <h2
          className="lowercase font-display tracking-tight text-2xl font-semibold leading-tight text-title sm:text-3xl"
          style={{ marginBottom: "1.5rem" }}
        >
          regulators want proof.{" "}
          <span className="text-accent-2">the contract is proof.</span>
        </h2>
        <p className="max-w-2xl text-base leading-relaxed text-body">
          The squeeze is coming from both sides &mdash; and companies
          deploying AI, especially in regulated industries, are going to
          have to get a lot more disciplined about it.
        </p>
      </Reveal>

      <div
        className="grid gap-4 sm:grid-cols-2"
        style={{ marginTop: "2.5rem" }}
      >
        {SIDES.map((side, i) => (
          <Reveal key={side.label} delay={i * 80}>
            <div className="h-full rounded-xl border border-glass-border/60 bg-raised p-5">
              <p className="mb-2 font-mono text-[11px] font-semibold tracking-[0.14em] uppercase text-accent">
                {side.label}
              </p>
              <p className="text-sm leading-relaxed text-body">{side.body}</p>
            </div>
          </Reveal>
        ))}
      </div>

      <Reveal delay={160}>
        <p
          className="max-w-2xl font-display tracking-tight text-lg font-semibold leading-snug text-title sm:text-2xl"
          style={{ marginTop: "2.5rem" }}
        >
          Proof of what your agents did, and what they were allowed to do
          &mdash;{" "}
          <span className="text-accent-2">
            that&rsquo;s what an Execution Contract is.
          </span>
        </p>
      </Reveal>
    </Section>
  );
}
