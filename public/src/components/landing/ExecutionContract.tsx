import { Section } from "./primitives/Section";
import { Eyebrow } from "./primitives/Eyebrow";
import { Reveal } from "./primitives/Reveal";

// The composition argument: isolation alone is table stakes (every serious
// runtime has a microVM now), so this section makes the case that what a
// security team actually approves is the six-layer contract around the
// box. Each layer cites the numbered CI-enforced claim(s) that back it —
// the claim refs must track /security/ci-claims/, which mirrors the
// machine-checked ADR-001 ledger. Do not add a layer here without a
// shipped claim to cite.
const LAYERS: Array<{
  num: string;
  title: string;
  body: string;
  claims: string;
}> = [
  {
    num: "01",
    title: "Signed admission",
    body: "Nothing boots without a signed, audited ExecutionPlan — validity window, nonce, chain-signed lifecycle.",
    claims: "claim 8",
  },
  {
    num: "02",
    title: "Pinned artifact",
    body: "Artifacts are content-addressed and digest-pinned, re-verified at fetch and again at admit.",
    claims: "claims 9, 14",
  },
  {
    num: "03",
    title: "Granted authority",
    body: "Network, services, and credentials are grants in the plan — deny-all by default, raw secrets never in the guest.",
    claims: "claims 10, 12, 13",
  },
  {
    num: "04",
    title: "No bypass path",
    body: "The guest has no network device. Every byte exits over one vsock channel the host can refuse.",
    claims: "claim 10",
  },
  {
    num: "05",
    title: "Sealed, immutable production behavior",
    body: "A dm-verity-sealed rootfs with no shell, no PTY, no dev verbs — the admitted program can't be swapped.",
    claims: "claims 3, 15",
  },
  {
    num: "06",
    title: "Verifiable record",
    body: "Every admission and policy decision lands in a chain-signed audit log. Tampering breaks the chain.",
    claims: "claims 8, 14",
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
          Anyone can put an agent in a microVM. A security team approves the
          contract: what may execute, with what authority, and what proves it.
          Six layers, enforced and witnessed — not asserted.
        </p>
      </Reveal>

      {/* Two columns of three: the layers read top-to-bottom as a chain,
          left column first. Inline margin, not mt-*: Starlight's unlayered
          stylesheet beats layered utilities on this page (see
          Positioning.tsx). */}
      <div
        className="grid gap-x-8 gap-y-6 sm:grid-cols-2"
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
                <p className="mt-2 font-mono text-[11px] text-label/70">
                  {layer.claims}
                </p>
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
            href={`${base}security/security-review/`}
            className="text-sm text-accent underline underline-offset-2 hover:text-accent/80"
          >
            How this answers a security review
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
