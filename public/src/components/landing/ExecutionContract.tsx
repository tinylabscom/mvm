import { Section } from "./primitives/Section";
import { Eyebrow } from "./primitives/Eyebrow";
import { Reveal } from "./primitives/Reveal";

// The composition argument: isolation alone is table stakes (every
// serious runtime has a microVM now), so this section makes the case that
// what a security team actually approves is the contract around the box —
// told the way the pitch script tells it, as three moves in order:
// declare → sign → prove. This collapsed from six parallel layer cards
// (pitch-script reshape): each step absorbs two or three of the old
// layers, and the CI-enforced claim(s) backing each step are noted in a
// comment per step, not rendered (/security/ci-claims/ mirrors the
// machine-checked ADR-001 ledger and is linked below the grid). Do not
// add a step here without a shipped claim to cite.
const LAYERS: Array<{
  num: string;
  title: string;
  body: string;
}> = [
  // claims 10, 12, 13 (granted authority) + claim 10 (no bypass path)
  {
    num: "01",
    title: "Declare",
    body: "Say what's allowed before anything runs — what's in the box, what it can reach, what it can do. Everything else is blocked by default.",
  },
  // claims 8, 9, 14 (signed admission, pinned artifact) + 3, 15 (sealed)
  {
    num: "02",
    title: "Sign",
    body: "Your declaration is signed and the code is locked to it. What runs is exactly what you approved — proof, not hope.",
  },
  // claims 8, 14 (verifiable record)
  {
    num: "03",
    title: "Prove",
    body: "Every run leaves a signed record of what happened and what was allowed — tamper with it and it shows. Evidence you can hand to an auditor.",
  },
];

export function ExecutionContract() {
  const rawBase = import.meta.env.BASE_URL;
  const base = rawBase.endsWith("/") ? rawBase : `${rawBase}/`;

  return (
    // No bg-raised: this section sits directly below WhyNow, which is
    // raised — keeping this one on the canvas preserves the alternation.
    <Section id="execution-contract" rule>
      <Reveal>
        <Eyebrow>The contract</Eyebrow>
        {/* Inline margins, not margin utilities: Starlight's unlayered
            stylesheet beats layered utilities on this page (see
            Positioning.tsx). */}
        <h2
          className="lowercase font-display tracking-tight text-2xl font-semibold leading-tight text-title sm:text-3xl"
          style={{ marginBottom: "1.5rem" }}
        >
          the box is table stakes.{" "}
          <span className="text-accent-2">the contract is the product.</span>
        </h2>
        <p className="max-w-2xl text-base leading-relaxed text-body">
          Before anything runs, you declare what&rsquo;s allowed &mdash;
          what&rsquo;s in the box, what it can reach, what it can do &mdash;
          and sign it. What runs is what you approved: proof, not hope. Three
          moves, enforced and witnessed.
        </p>
      </Reveal>

      {/* One row of three: the steps read left-to-right as a sequence.
          Inline margin, not mt-*: Starlight's unlayered stylesheet beats
          layered utilities on this page (see Positioning.tsx). */}
      <div
        className="grid gap-x-6 gap-y-6 sm:grid-cols-3"
        style={{ marginTop: "3rem" }}
      >
        {LAYERS.map((layer, i) => (
          <Reveal key={layer.num} delay={i * 60}>
            <div className="flex h-full gap-4 rounded-xl border border-glass-border/60 bg-raised p-5">
              <p className="font-mono text-lg font-semibold leading-none text-accent">
                {layer.num}
              </p>
              <div className="min-w-0">
                <h3 className="mb-1.5 text-base font-semibold leading-snug text-title">
                  {layer.title}
                </h3>
                <p className="text-sm leading-relaxed text-body">{layer.body}</p>
              </div>
            </div>
          </Reveal>
        ))}
      </div>

      <Reveal delay={400}>
        <div
          className="flex flex-wrap gap-x-6 gap-y-2"
          style={{ marginTop: "2rem" }}
        >
          <a
            href={`${base}how-it-works/`}
            className="text-sm text-accent underline underline-offset-2 hover:text-accent/80"
          >
            Under the hood: microVMs, performance, backends
          </a>
          <a
            href={`${base}security/ci-claims/`}
            className="text-sm text-accent underline underline-offset-2 hover:text-accent/80"
          >
            The numbered claims, with witnesses
          </a>
        </div>
      </Reveal>
    </Section>
  );
}
