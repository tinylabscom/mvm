import { Section } from "./primitives/Section";
import { Eyebrow } from "./primitives/Eyebrow";
import { Reveal } from "./primitives/Reveal";

// The wedge story: agent products don't stall on features — they stall in
// the customer's security review. Four of the questions those reviews ask,
// each answered by a mechanism with a numbered CI-enforced claim behind it.
// The full ten-question version lives at /security/security-review/ — keep
// this teaser's answers consistent with that page, and its claim refs
// consistent with /security/ci-claims/.
const QA: Array<{ q: string; a: string; claims: string }> = [
  {
    q: "What exactly will execute?",
    a: "A signed plan naming a content-addressed, digest-pinned artifact. The answer is a hash, not a tag.",
    claims: "claims 8, 9, 14",
  },
  {
    q: "What happens after prompt injection?",
    a: "Containment that doesn't depend on the model behaving: no network device, deny-all egress, sealed rootfs.",
    claims: "claims 10, 15",
  },
  {
    q: "Can it steal credentials?",
    a: "It never holds them. The guest sees placeholders; real values are substituted only into connections the host admits.",
    claims: "claim 13",
  },
  {
    q: "Can we prove what happened?",
    a: "A chain-signed record of admission, policy decisions, and provenance — verifiable after the fact.",
    claims: "claims 8, 14",
  },
];

export function SecurityReviewTeaser() {
  const rawBase = import.meta.env.BASE_URL;
  const base = rawBase.endsWith("/") ? rawBase : `${rawBase}/`;

  return (
    <Section id="security-review" rule className="bg-raised">
      <Reveal>
        <Eyebrow>The security review</Eyebrow>
        {/* Inline margins, not margin utilities: Starlight's unlayered
            stylesheet beats layered utilities on this page (see
            Positioning.tsx). */}
        <h2
          className="lowercase font-display text-2xl font-bold leading-tight text-title sm:text-3xl"
          style={{ marginBottom: "1.5rem" }}
        >
          built for the review{" "}
          <span className="text-accent-2">that blocks the deal.</span>
        </h2>
        <p className="max-w-2xl text-base leading-relaxed text-body">
          Agent products don&rsquo;t stall on features — they stall in the
          customer&rsquo;s security review. Those reviews ask the same
          questions everywhere. mvm is the runtime shaped like the answers.
        </p>
      </Reveal>

      <div
        className="grid gap-x-8 gap-y-6 sm:grid-cols-2"
        style={{ marginTop: "3rem" }}
      >
        {QA.map((item, i) => (
          <Reveal key={item.q} delay={i * 60}>
            <div className="h-full rounded-xl border border-glass-border/60 bg-canvas p-5">
              <h3 className="mb-1.5 text-base font-semibold leading-snug text-title">
                &ldquo;{item.q}&rdquo;
              </h3>
              <p className="text-sm leading-relaxed text-body">{item.a}</p>
              <p className="mt-2 font-mono text-[11px] text-label/70">
                {item.claims}
              </p>
            </div>
          </Reveal>
        ))}
      </div>

      <Reveal delay={300}>
        <div style={{ marginTop: "2rem" }}>
          <a
            href={`${base}security/security-review/`}
            className="text-sm text-accent underline underline-offset-2 hover:text-accent/80"
          >
            All ten questions, answered
          </a>
        </div>
      </Reveal>
    </Section>
  );
}
