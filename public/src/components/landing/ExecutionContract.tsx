import { Section } from "./primitives/Section";
import { Eyebrow } from "./primitives/Eyebrow";
import { Reveal } from "./primitives/Reveal";

// Keep the plan, admission, and audit steps distinct. Each step links
// back to the enforced security claims listed below.
const LAYERS: Array<{
  num: string;
  title: string;
  body: string;
}> = [
  // claims 10, 12, 13 (granted authority) + claim 10 (no bypass path)
  {
    num: "01",
    title: "Declare",
    body: "List the files, tools, secrets, and outbound connections the workload can use. Access is denied unless the plan allows it.",
  },
  // claims 8, 9, 14 (signed admission, pinned artifact) + 3, 15 (sealed)
  {
    num: "02",
    title: "Sign",
    body: "Sign the plan and pin the workload artifacts. Admission checks the signature before the workload starts.",
  },
  // claims 8, 14 (verifiable record)
  {
    num: "03",
    title: "Verify",
    body: "Review the signed execution record after a run. Verify its integrity rather than relying on an unsigned log.",
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
        <Eyebrow>Execution plans</Eyebrow>
        {/* Inline margins, not margin utilities: Starlight's unlayered
            stylesheet beats layered utilities on this page (see
            Positioning.tsx). */}
        <h2
          className="lowercase font-display tracking-tight text-2xl font-semibold leading-tight text-title sm:text-3xl"
          style={{ marginBottom: "1.5rem" }}
        >
          Set the rules{" "}
          <span className="text-accent-2">before the workload starts.</span>
        </h2>
        <p className="max-w-2xl text-base leading-relaxed text-body">
          Isolation is one part of running untrusted code. A signed execution
          plan also defines what the workload can access, and a signed record
          lets you review the execution afterward.
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
          {/* The how-it-works link is hidden with its page — see
              pages/_how-it-works.astro.
          <a
            href={`${base}how-it-works/`}
            className="text-sm text-accent underline underline-offset-2 hover:text-accent/80"
          >
            Under the hood: microVMs, performance, backends
          </a>
          */}
          <a
            href={`${base}security/ci-claims/`}
            className="text-sm text-accent underline underline-offset-2 hover:text-accent/80"
          >
            Read the enforced security claims
          </a>
        </div>
      </Reveal>
    </Section>
  );
}
