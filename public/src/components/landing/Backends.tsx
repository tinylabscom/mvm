import { Eyebrow } from "./primitives/Eyebrow";
import { Reveal } from "./primitives/Reveal";
import { Section } from "./primitives/Section";

// Shipped backends only — this list must track what the CLI actually
// selects, not the roadmap. Confidential-compute attestation (SEV-SNP/TDX)
// is explicitly out of scope of the current runtime and must not appear
// here until it ships.
const BACKENDS = [
  { tag: "Linux / KVM", name: "Firecracker", primary: true },
  { tag: "macOS 13–25", name: "libkrun" },
  { tag: "macOS 26+", name: "HVF" },
  { tag: "Dev / test", name: "QEMU" },
];

export function Backends() {
  const rawBase = import.meta.env.BASE_URL;
  const base = rawBase.endsWith("/") ? rawBase : `${rawBase}/`;

  return (
    <Section id="backends" rule>
      <Reveal>
        <Eyebrow>Backends</Eyebrow>
        {/* Inline margins, not margin utilities: Starlight's unlayered
            stylesheet beats layered utilities on this page (see
            Positioning.tsx). */}
        <h2
          className="lowercase font-display tracking-tight text-2xl font-semibold leading-tight text-title sm:text-3xl"
          style={{ marginBottom: "1.5rem" }}
        >
          the backend is an implementation detail.
        </h2>
        <p className="max-w-3xl text-base leading-relaxed text-body">
          The same signed image, decorated execution plan, policy bundle, and
          audit chain runs across every backend MVM supports.
        </p>
      </Reveal>
      <div
        className="grid grid-cols-2 gap-2.5 lg:grid-cols-4"
        style={{ marginTop: "3rem" }}
      >
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
      <p className="mt-5 font-mono text-xs leading-relaxed text-label">
        Shipped, preview, and roadmap capabilities are tracked on the{" "}
        <a
          href={`${base}security/capability-status/`}
          className="text-accent underline underline-offset-2 hover:text-accent/80"
        >
          capability status
        </a>{" "}
        page.
      </p>
    </Section>
  );
}
