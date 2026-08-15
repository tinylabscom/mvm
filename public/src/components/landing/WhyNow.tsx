import { Eyebrow } from "./primitives/Eyebrow";
import { Reveal } from "./primitives/Reveal";
import { Section } from "./primitives/Section";

// The "why now" narrative: AI writes and runs more of the code in
// production, review doesn't scale with it, so the runtime has to assume
// the code is hostile. This is the emotional core of the page — the
// sections around it supply the mechanism (demo, boundary, claims).
const SHIFTS = [
  {
    label: "generated",
    body: "Assistants and agents author a growing share of new code — and ship it faster than any human review cycle can keep up with.",
  },
  {
    label: "unreviewed",
    body: "Hallucinated packages, unvetted transitive deps, and copy-pasted configs ride along with every generated feature.",
  },
  {
    label: "exploitable",
    body: "A prompt-injected agent with network access and ambient credentials isn't a bug — it's an exfiltration path.",
  },
];

export function WhyNow() {
  const rawBase = import.meta.env.BASE_URL;
  const base = rawBase.endsWith("/") ? rawBase : `${rawBase}/`;

  return (
    <Section id="why-now" rule className="bg-raised">
      <Reveal>
        <Eyebrow>Why now</Eyebrow>
        <h2 className="mb-4 max-w-2xl lowercase font-display text-2xl font-bold leading-tight text-title sm:text-3xl">
          code is getting cheaper to write.{" "}
          <span className="text-accent-2">so are exploits.</span>
        </h2>
        <p className="max-w-2xl text-base leading-relaxed text-body">
          AI writes more of the code you run every day — and agents don&rsquo;t
          just write it, they execute it: installing dependencies, calling
          tools, touching real data. Most of it is fine. Some of it is slop. A
          little of it is hostile. At that volume you can&rsquo;t review your
          way to safety — the runtime has to assume the worst.
        </p>
      </Reveal>

      <div className="mt-10 grid gap-4 sm:grid-cols-3">
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
        <p className="mt-10 max-w-2xl text-base leading-relaxed text-body">
          That&rsquo;s the assumption mvm is built on. Every workload is
          untrusted by default: it boots its own kernel under a real
          hypervisor, gets no network device, and reaches out only through one
          policy-governed channel — with every decision signed into a
          tamper-evident audit chain. As simple to run as a container, with a
          hardware boundary where a container has a shared kernel.{" "}
          <span className="text-emphasis">
            Security first isn&rsquo;t a tier — it&rsquo;s the default,
            enforced by 15+ CI-gated claims.
          </span>
        </p>
        <div className="mt-6 flex flex-wrap gap-x-6 gap-y-2">
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
