import { Eyebrow } from "./primitives/Eyebrow";
import { Reveal } from "./primitives/Reveal";
import { Section } from "./primitives/Section";

// Status labels are load-bearing: only tier 01 ships today. Hosted is
// design-partner gated (the request-access form is the way in), and tiers
// 03/04 are roadmap — hardware attestation is explicitly out of scope of
// the current runtime, so nothing here may imply attestation-gated key
// release exists.
const TIERS: Array<{
  label: string;
  name: string;
  body: string;
  status?: string;
  confidential?: boolean;
}> = [
  {
    label: "01 / Local",
    name: "Local Development",
    body: "libkrun/HVF-backed VMs on your macOS or Linux machine. Same workload contract.",
  },
  {
    label: "02 / Hosted",
    name: "Hosted Standard",
    body: "Firecracker on Linux/KVM fleet infrastructure. High-density, short-lived workloads.",
    status: "Design partners",
  },
  {
    label: "03 / Edge",
    name: "Edge & Private",
    body: "Your VPC or your metal. The same signed contract, forward-deployed into your infrastructure.",
    status: "Roadmap",
  },
  {
    label: "04 / Confidential",
    name: "Hosted Confidential",
    body: "AMD SEV-SNP and Intel TDX. Hardware attestation is out of scope of today's shipped runtime.",
    status: "Roadmap",
    confidential: true,
  },
];

export function DeploymentTiers() {
  const rawBase = import.meta.env.BASE_URL;
  const base = rawBase.endsWith("/") ? rawBase : `${rawBase}/`;

  return (
    <Section id="deployment" rule>
      <Reveal>
        <Eyebrow>Deployment</Eyebrow>
        <h2 className="lowercase font-display tracking-tight text-2xl font-semibold leading-tight text-title sm:text-3xl">
          one contract. four places to run it.
        </h2>
      </Reveal>
      {/* Inline margin, not mt-*: Starlight's unlayered stylesheet beats
          layered utilities on this page (see Positioning.tsx). */}
      <div
        className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4"
        style={{ marginTop: "3rem" }}
      >
        {TIERS.map((tier, i) => (
          <Reveal key={tier.label} delay={i * 80}>
            <div
              className={
                tier.confidential
                  ? "h-full rounded-xl border border-accent-3/50 bg-accent-3/5 p-5 transition-colors hover:border-accent-3"
                  : "h-full rounded-xl border border-glass-border/60 bg-raised p-5 transition-colors hover:border-accent/50"
              }
            >
              <div className="mb-3 flex items-baseline justify-between gap-2">
                <p
                  className={
                    tier.confidential
                      ? "font-mono text-[11px] font-semibold tracking-[0.14em] uppercase text-accent-3"
                      : "font-mono text-[11px] font-semibold tracking-[0.14em] uppercase text-label"
                  }
                >
                  {tier.label}
                </p>
                {tier.status && (
                  <span className="shrink-0 rounded border border-edge/50 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-widest text-label">
                    {tier.status}
                  </span>
                )}
              </div>
              <h3 className="text-base font-semibold text-title">{tier.name}</h3>
              <p className="mt-2 text-sm leading-relaxed text-body">{tier.body}</p>
            </div>
          </Reveal>
        ))}
      </div>
      <p className="mt-5 font-mono text-xs leading-relaxed text-label">
        Local runs today with the open-source CLI. Tier status is tracked on
        the{" "}
        <a
          href={`${base}security/capability-status/`}
          className="text-accent underline underline-offset-2 hover:text-accent/80"
        >
          capability status
        </a>{" "}
        page; what&rsquo;s enforced right now — with named test witnesses — is
        in the{" "}
        <a
          href={`${base}security/ci-claims/`}
          className="text-accent underline underline-offset-2 hover:text-accent/80"
        >
          CI-enforced claims
        </a>
        .
      </p>
    </Section>
  );
}
