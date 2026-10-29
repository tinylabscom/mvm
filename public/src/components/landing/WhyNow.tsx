import { Reveal } from "./primitives/Reveal";
import { Section } from "./primitives/Section";

// Explain the workload boundary before introducing execution plans.
const SHIFTS = [
  {
    label: "AI agents",
    body: "Agents write code and call tools. Run that code in a microVM rather than directly on your host.",
  },
  {
    label: "Customer code",
    body: "Give each customer's workload its own kernel instead of sharing the host kernel across tenants.",
  },
  {
    label: "Build jobs",
    body: "Run build tools and dependencies in a microVM without giving them direct access to your host.",
  },
];

export function WhyNow() {
  const rawBase = import.meta.env.BASE_URL;
  const base = rawBase.endsWith("/") ? rawBase : `${rawBase}/`;

  return (
    <Section id="why-now" rule className="bg-raised">
      <Reveal>
        <h2 className="lowercase font-display tracking-tight text-2xl font-semibold leading-tight text-title sm:text-3xl">
          Run code you didn&rsquo;t write{" "}
          <span className="text-accent-2">without sharing your kernel.</span>
        </h2>
      </Reveal>

      {/* Inline margins, not mt-* utilities: Starlight's unlayered
          stylesheet beats layered utilities on this page (see
          Positioning.tsx), and these gaps keep the headline, the cards,
          and the closer from sitting on top of each other. */}
      <div
        className="grid gap-4 sm:grid-cols-3"
        style={{ marginTop: "2.5rem" }}
      >
        {SHIFTS.map((shift, i) => (
          <Reveal key={shift.label} delay={i * 80}>
            <div className="h-full rounded-xl border border-glass-border/60 bg-canvas p-5">
              <p className="mb-2 font-mono text-[11px] font-semibold tracking-[0.14em] uppercase text-accent">
                {shift.label}
              </p>
              <p className="text-sm leading-relaxed text-body">{shift.body}</p>
            </div>
          </Reveal>
        ))}
      </div>

      <Reveal delay={160}>
        <div
          className="flex flex-wrap gap-x-6 gap-y-2"
          style={{ marginTop: "2.5rem" }}
        >
          <a
            href={`${base}security/threat-model/`}
            className="text-sm text-accent underline underline-offset-2 hover:text-accent/80"
          >
            Read the threat model
          </a>
          <a
            href={`${base}security/claim-ledger/`}
            className="text-sm text-accent underline underline-offset-2 hover:text-accent/80"
          >
            See the security claims
          </a>
        </div>
      </Reveal>
    </Section>
  );
}
