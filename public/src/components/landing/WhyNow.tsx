import { Reveal } from "./primitives/Reveal";
import { Section } from "./primitives/Section";

// The "why now" narrative: AI writes and runs more of the code in
// production, review doesn't scale with it, so the runtime has to assume
// the code is hostile. This is the emotional core of the page — the
// sections around it supply the mechanism (demo, boundary, claims).
const SHIFTS = [
  {
    label: "generated",
    body: "Agents ship code faster than any review cycle.",
  },
  {
    label: "unreviewed",
    body: "Hallucinated packages and unvetted deps ride along.",
  },
  {
    label: "exploitable",
    body: "A prompt-injected agent with network access is an exfiltration path.",
  },
];

export function WhyNow() {
  const rawBase = import.meta.env.BASE_URL;
  const base = rawBase.endsWith("/") ? rawBase : `${rawBase}/`;

  return (
    <Section id="why-now" rule className="bg-raised">
      <Reveal>
        <h2 className="lowercase font-display tracking-tight text-2xl font-semibold leading-tight text-title sm:text-3xl">
          code is getting cheaper to write.{" "}
          <span className="text-accent-2">so are exploits.</span>
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
        {/* No max-width cap: the first line needs the section's full
            column to stay on one line at desktop sizes. */}
        <p
          className="font-display tracking-tight text-lg font-semibold leading-snug text-title sm:text-2xl"
          style={{ marginTop: "2.5rem" }}
        >
          With MVM{" "}
          <span className="text-accent-2">
            Security first isn&rsquo;t a tier, it&rsquo;s the default.
          </span>
        </p>
        <div
          className="flex flex-wrap gap-x-6 gap-y-2"
          style={{ marginTop: "1.5rem" }}
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
