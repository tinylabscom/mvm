import { Eyebrow } from "./primitives/Eyebrow";
import { Reveal } from "./primitives/Reveal";
import { Section } from "./primitives/Section";

const TIERS = [
  {
    label: "01 / Local",
    name: "Local Development",
    body: "libkrun/HVF-backed VMs on your macOS or Linux machine. Same workload contract.",
  },
  {
    label: "02 / Hosted",
    name: "Hosted Standard",
    body: "Firecracker on our Linux/KVM fleet. High-density, short-lived workloads.",
  },
  {
    label: "03 / Edge",
    name: "Edge & Private",
    body: "Your VPC or your metal, via Incus or containerd. TPM, Secure Enclave, AVF.",
  },
  {
    label: "04 / Confidential",
    name: "Hosted Confidential",
    body: "SEV-SNP and TDX. Hardware-rooted memory confidentiality gates key release.",
    confidential: true,
  },
];

export function DeploymentTiers() {
  return (
    <Section id="deployment" rule>
      <Reveal>
        <Eyebrow>Deployment</Eyebrow>
        <h2 className="mb-8 lowercase font-display text-2xl font-bold leading-tight text-title sm:text-3xl">
          one contract. four places to run it.
        </h2>
      </Reveal>
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        {TIERS.map((tier, i) => (
          <Reveal key={tier.label} delay={i * 80}>
            <div
              className={
                tier.confidential
                  ? "h-full rounded-xl border border-accent-3/50 bg-accent-3/5 p-5 transition-colors hover:border-accent-3"
                  : "h-full rounded-xl border border-glass-border/60 bg-raised p-5 transition-colors hover:border-accent/50"
              }
            >
              <p
                className={
                  tier.confidential
                    ? "mb-3 font-mono text-[11px] font-semibold tracking-[0.14em] uppercase text-accent-3"
                    : "mb-3 font-mono text-[11px] font-semibold tracking-[0.14em] uppercase text-label"
                }
              >
                {tier.label}
              </p>
              <h3 className="text-base font-semibold text-title">{tier.name}</h3>
              <p className="mt-2 text-sm leading-relaxed text-body">{tier.body}</p>
            </div>
          </Reveal>
        ))}
      </div>
      <p className="mt-5 font-mono text-xs leading-relaxed text-label">
        Trust tier is recorded on every release. Sensitive key release is gated
        on the tier you require.
      </p>
    </Section>
  );
}
