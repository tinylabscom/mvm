import { GlowCard } from "./primitives/GlowCard";
import { Eyebrow } from "./primitives/Eyebrow";
import { Reveal } from "./primitives/Reveal";
import { Bloom } from "./primitives/Bloom";

const features: Array<{
  icon: string;
  title: string;
  description: string;
  accent: 1 | 2 | 3;
}> = [
  {
    icon: "layers",
    title: "Multi-Backend",
    description:
      "Auto-detects your platform. HVF on macOS 26+ Apple Silicon, libkrun on macOS 13–25, Firecracker on Linux KVM. No shared-kernel fallback.",
    accent: 1,
  },
  {
    icon: "package",
    title: "Nix-Based Builds",
    description:
      "Reproducible microVM images from Nix flakes — the same flake always produces the same image. Builds persist to a slot keyed by the manifest path, so unchanged manifests skip the rebuild.",
    accent: 2,
  },
  {
    icon: "blocks",
    title: "Signed & Audited",
    description:
      "Every run admits a signed ExecutionPlan and appends a chain-signed entry to the audit log. mvmctl trust audit verify catches tampering; mvmctl doctor reports the live security posture.",
    accent: 3,
  },
  {
    icon: "lock",
    title: "No SSH. Ever.",
    description:
      "Host-brokered control uses typed vsock or the backend equivalent. Guests do not need SSH, inbound ports, or a host daemon you operate.",
    accent: 1,
  },
  {
    icon: "zap",
    title: "Snapshots & Manifests",
    description:
      "Restore a running VM from snapshot in 1–2 seconds. mvmctl manifest info inspects the current revision, slot path, and provenance for any project.",
    accent: 2,
  },
  {
    icon: "terminal",
    title: "Developer-First",
    description:
      "Scaffold presets for minimal, http, postgres, worker, and python projects. Actionable error hints. System diagnostics via doctor.",
    accent: 3,
  },
];

const icons: Record<string, JSX.Element> = {
  layers: (
    <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M6.429 9.75 2.25 12l4.179 2.25m0-4.5 5.571 3 5.571-3m-11.142 0L2.25 7.5 12 2.25l9.75 5.25-4.179 2.25m0 0L12 12.75 6.429 9.75m11.142 0 4.179 2.25L12 17.25 2.25 12l4.179-2.25m11.142 0 4.179 2.25L12 22.5l-9.75-5.25 4.179-2.25" />
    </svg>
  ),
  package: (
    <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="m21 7.5-9-5.25L3 7.5m18 0-9 5.25m9-5.25v9l-9 5.25M3 7.5l9 5.25M3 7.5v9l9 5.25m0-9v9" />
    </svg>
  ),
  blocks: (
    <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 6A2.25 2.25 0 0 1 6 3.75h2.25A2.25 2.25 0 0 1 10.5 6v2.25a2.25 2.25 0 0 1-2.25 2.25H6a2.25 2.25 0 0 1-2.25-2.25V6ZM3.75 15.75A2.25 2.25 0 0 1 6 13.5h2.25a2.25 2.25 0 0 1 2.25 2.25V18a2.25 2.25 0 0 1-2.25 2.25H6A2.25 2.25 0 0 1 3.75 18v-2.25ZM13.5 6a2.25 2.25 0 0 1 2.25-2.25H18A2.25 2.25 0 0 1 20.25 6v2.25A2.25 2.25 0 0 1 18 10.5h-2.25a2.25 2.25 0 0 1-2.25-2.25V6ZM13.5 15.75a2.25 2.25 0 0 1 2.25-2.25H18a2.25 2.25 0 0 1 2.25 2.25V18A2.25 2.25 0 0 1 18 20.25h-2.25a2.25 2.25 0 0 1-2.25-2.25v-2.25Z" />
    </svg>
  ),
  lock: (
    <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M16.5 10.5V6.75a4.5 4.5 0 1 0-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 0 0 2.25-2.25v-6.75a2.25 2.25 0 0 0-2.25-2.25H6.75a2.25 2.25 0 0 0-2.25 2.25v6.75a2.25 2.25 0 0 0 2.25 2.25Z" />
    </svg>
  ),
  zap: (
    <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="m3.75 13.5 10.5-11.25L12 10.5h8.25L9.75 21.75 12 13.5H3.75Z" />
    </svg>
  ),
  terminal: (
    <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="m6.75 7.5 3 2.25-3 2.25m4.5 0h3m-9 8.25h13.5A2.25 2.25 0 0 0 21 18V6a2.25 2.25 0 0 0-2.25-2.25H5.25A2.25 2.25 0 0 0 3 6v12a2.25 2.25 0 0 0 2.25 2.25Z" />
    </svg>
  ),
};

export function Features() {
  return (
    <section className="relative w-full overflow-hidden px-6 py-28 sm:px-8 lg:py-36">
      <Bloom accents={[2, 3]} />

      <div className="relative mx-auto max-w-6xl">
        <div className="mb-16 text-center lg:mb-20">
          <Eyebrow n="02" className="text-center">
            Capabilities
          </Eyebrow>
          <h2 className="text-3xl font-bold text-title sm:text-4xl">
            Everything you need to run microVMs
          </h2>
        </div>

        <div className="grid gap-5 sm:grid-cols-2 lg:grid-cols-3">
          {features.map((f, i) => (
            <Reveal key={f.title} delay={i * 80}>
              <GlowCard accent={f.accent} className="group">
                <div className="mb-3 flex h-10 w-10 items-center justify-center rounded-lg border border-edge/60 bg-canvas text-accent transition-colors group-hover:border-accent/40 group-hover:bg-accent/10">
                  {icons[f.icon]}
                </div>
                <h3 className="mb-2 text-lg font-semibold leading-none tracking-tight text-title">
                  {f.title}
                </h3>
                <p className="text-sm leading-relaxed text-body">{f.description}</p>
              </GlowCard>
            </Reveal>
          ))}
        </div>
      </div>
    </section>
  );
}
