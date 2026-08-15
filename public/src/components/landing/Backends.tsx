import { Eyebrow } from "./primitives/Eyebrow";
import { Reveal } from "./primitives/Reveal";
import { Section } from "./primitives/Section";

const BACKENDS = [
  { tag: "Primary", name: "Firecracker", primary: true },
  { tag: "Backend", name: "libkrun" },
  { tag: "Backend", name: "Incus" },
  { tag: "Backend", name: "containerd" },
  { tag: "Attestation", name: "AMD SEV-SNP" },
  { tag: "Attestation", name: "Intel TDX" },
];

export function Backends() {
  return (
    <Section id="backends" rule>
      <Reveal>
        <Eyebrow>Backends</Eyebrow>
        <h2 className="mb-4 lowercase font-display text-2xl font-bold leading-tight text-title sm:text-3xl">
          the backend is an implementation detail.
        </h2>
        <p className="mb-8 max-w-3xl text-base leading-relaxed text-body">
          The same signed image, decorated execution plan, policy bundle, and
          audit chain runs across every backend MVM supports.
        </p>
      </Reveal>
      <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-3 lg:grid-cols-6">
        {BACKENDS.map((backend, i) => (
          <Reveal key={backend.name} delay={i * 60}>
            <div className="h-full rounded-xl border border-glass-border/60 bg-raised px-4 py-3.5 transition-colors hover:border-accent/50">
              <p
                className={
                  backend.primary
                    ? "font-mono text-[10px] font-semibold tracking-[0.1em] uppercase text-accent"
                    : "font-mono text-[10px] font-semibold tracking-[0.1em] uppercase text-label"
                }
              >
                {backend.tag}
              </p>
              <p className="mt-2 font-display text-sm text-title">
                {backend.name}
              </p>
            </div>
          </Reveal>
        ))}
      </div>
    </Section>
  );
}
