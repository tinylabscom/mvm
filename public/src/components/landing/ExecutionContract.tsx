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
    body: "Every workload runs from a signed, audited ExecutionPlan — validity window, nonce replay protection, chain-signed lifecycle events. Nothing boots without one.",
    claims: "claim 8",
  },
  {
    num: "02",
    title: "Pinned artifact",
    body: "Bundles are content-addressed and key-pinned, re-verified at fetch and again at admit. OCI images admit by resolved digest, with provenance recorded.",
    claims: "claims 9, 14",
  },
  {
    num: "03",
    title: "Granted authority",
    body: "Network, host services, and credentials are grants in the plan, not ambient capabilities. Egress defaults to deny-all, and raw secret bytes never enter the guest.",
    claims: "claims 10, 12, 13",
  },
  {
    num: "04",
    title: "No bypass path",
    body: "The workload VM has no network device — on any backend. Every byte leaves over one vsock channel to a host-side gate that originates, and can refuse, the real connection. A CI gate fails the build if a network path reappears.",
    claims: "claim 10",
  },
  {
    num: "05",
    title: "Sealed production behavior",
    body: "A production rootfs is dm-verity sealed and boots with no shell, no PTY, and no dev-only verbs — the admitted program can't be swapped for another one.",
    claims: "claims 3, 15",
  },
  {
    num: "06",
    title: "Verifiable record",
    body: "Admission, launch, policy decisions, and provenance land in a chain-signed audit log. Tampering breaks the chain, and verification exits nonzero.",
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
        <h2 className="mb-4 lowercase font-display text-2xl font-bold leading-tight text-title sm:text-3xl">
          the box is table stakes.{" "}
          <span className="text-accent-2">the contract is the product.</span>
        </h2>
        <p className="mb-2 max-w-2xl text-base leading-relaxed text-body">
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
        style={{ marginTop: "2.5rem" }}
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
