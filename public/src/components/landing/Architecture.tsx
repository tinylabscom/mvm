import { Section } from "./primitives/Section";
import { Eyebrow } from "./primitives/Eyebrow";
import { Bloom } from "./primitives/Bloom";
import { GlowCard } from "./primitives/GlowCard";
import { Reveal } from "./primitives/Reveal";

// Class names below are written out in full (not built from a template
// literal) because Tailwind's build-time scanner matches literal substrings
// in the source text — an interpolated `border-${x}/30` never appears as a
// real token and silently drops out of the generated CSS.
const BACKENDS = [
  {
    name: "Firecracker",
    badge: "default",
    accent: 2 as const,
    cardClass: "border-rust/30 bg-rust/6",
    iconWrapClass: "bg-rust/20 text-rust",
    nameClass: "text-rust",
    badgeClass: "bg-rust/10 text-rust/70",
    tagClass: "bg-rust/10 text-rust/80",
    desc: "Production-grade microVMs. Snapshots, pause/resume, vsock-only egress — no guest NIC.",
    tags: ["snapshots", "vsock", "pause"],
    tier: "Linux + KVM — native",
  },
  {
    name: "HVF",
    badge: undefined,
    accent: 1 as const,
    cardClass: "border-green/30 bg-green/6",
    iconWrapClass: "bg-green/20 text-green",
    nameClass: "text-green",
    badgeClass: "bg-green/10 text-green/70",
    tagClass: "bg-green/10 text-green/80",
    desc: "In-house Hypervisor.framework VMM. Vsock-only device model, no Homebrew dependencies.",
    tags: ["vsock"],
    tier: "macOS 26+ Apple Silicon — default",
  },
  {
    name: "libkrun",
    badge: undefined,
    accent: 3 as const,
    cardClass: "border-nix/30 bg-nix/6",
    iconWrapClass: "bg-nix/20 text-nix",
    nameClass: "text-nix",
    badgeClass: "bg-nix/10 text-nix/70",
    tagClass: "bg-nix/10 text-nix/80",
    desc: "Third-party in-process VMM via Homebrew (slp/krun/libkrun). Vsock-only egress.",
    tags: ["vsock"],
    tier: "macOS 13–25 — default",
  },
  {
    name: "microvm.nix",
    badge: "dev/test",
    accent: 2 as const,
    cardClass: "border-edge/50 bg-canvas/80",
    iconWrapClass: "bg-edge/30 text-label",
    nameClass: "text-emphasis",
    badgeClass: "bg-edge/30 text-label",
    tagClass: "bg-edge/20 text-label",
    desc: "NixOS-native VM runner with QEMU. Dev/test only — never used for multi-tenant workloads.",
    tags: ["vsock"],
    tier: "Linux — opt-in",
  },
];

export function Architecture() {
  return (
    <Section rule className="border-y border-edge/30 bg-raised/50">
      <div className="relative overflow-hidden">
        <Bloom accents={[2]} />

        <div className="relative mb-16 text-center lg:mb-20">
          <Eyebrow n="05" className="justify-center text-center">
            Architecture
          </Eyebrow>
          <h2 className="font-display text-3xl font-bold text-title sm:text-4xl lg:text-5xl">
            One CLI, four backends
          </h2>
          <p className="mx-auto mt-6 max-w-xl text-lg leading-relaxed text-body">
            mvm detects your OS, chip, and macOS version, then picks a workload
            backend automatically. You can also choose one explicitly.
          </p>
        </div>

        <div className="relative mx-auto max-w-4xl space-y-6">
          {/* Host layer */}
          <Reveal>
            <div className="rounded-xl border border-accent/30 bg-accent/6 p-6 sm:p-8">
              <div className="flex items-center gap-3">
                <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-accent/20 text-accent">
                  <svg
                    className="h-4 w-4"
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                    strokeWidth={2}
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      d="M9 17.25v1.007a3 3 0 0 1-.879 2.122L7.5 21h9l-.621-.621A3 3 0 0 1 15 18.257V17.25m6-12V15a2.25 2.25 0 0 1-2.25 2.25H5.25A2.25 2.25 0 0 1 3 15V5.25m18 0A2.25 2.25 0 0 0 18.75 3H5.25A2.25 2.25 0 0 0 3 5.25m18 0V12a2.25 2.25 0 0 1-2.25 2.25H5.25A2.25 2.25 0 0 1 3 12V5.25"
                    />
                  </svg>
                </div>
                <div>
                  <span className="text-sm font-semibold text-accent">
                    Your Host
                  </span>
                  <span className="ml-2 text-xs text-label">macOS / Linux</span>
                </div>
              </div>
              <p className="mt-2 ml-11 text-xs text-label">
                mvmctl picks HVF on macOS 26+ Apple Silicon, libkrun on macOS
                13–25, and Firecracker on Linux + KVM.
              </p>

              {/* Auto-detect arrow */}
              <div className="my-5 flex items-center gap-3 ml-11">
                <div className="h-px flex-1 bg-linear-to-r from-accent/30 to-transparent" />
                <span className="rounded border border-accent/20 bg-accent/10 px-2.5 py-1 text-[10px] font-medium uppercase tracking-wider text-accent">
                  auto-select
                </span>
                <div className="h-px flex-1 bg-linear-to-l from-accent/30 to-transparent" />
              </div>

              {/* Backend cards grid */}
              <div className="grid gap-4 sm:grid-cols-2">
                {BACKENDS.map((b) => (
                  <GlowCard
                    key={b.name}
                    accent={b.accent}
                    className={`${b.cardClass} p-5`}
                  >
                    <div className="flex items-center gap-3">
                      <div
                        className={`flex h-7 w-7 shrink-0 items-center justify-center rounded-md ${b.iconWrapClass}`}
                      >
                        <svg
                          className="h-3.5 w-3.5"
                          fill="none"
                          viewBox="0 0 24 24"
                          stroke="currentColor"
                          strokeWidth={2}
                        >
                          <path
                            strokeLinecap="round"
                            strokeLinejoin="round"
                            d="m3.75 13.5 10.5-11.25L12 10.5h8.25L9.75 21.75 12 13.5H3.75Z"
                          />
                        </svg>
                      </div>
                      <div>
                        <span
                          className={`text-sm font-semibold ${b.nameClass}`}
                        >
                          {b.name}
                        </span>
                        {b.badge && (
                          <span
                            className={`ml-1.5 rounded px-1.5 py-0.5 text-[10px] ${b.badgeClass}`}
                          >
                            {b.badge}
                          </span>
                        )}
                      </div>
                    </div>
                    <p className="mt-2 text-xs text-label leading-relaxed">
                      {b.desc}
                    </p>
                    <div className="mt-3 flex flex-wrap gap-1.5">
                      {b.tags.map((c) => (
                        <span
                          key={c}
                          className={`rounded px-1.5 py-0.5 text-[10px] ${b.tagClass}`}
                        >
                          {c}
                        </span>
                      ))}
                    </div>
                    <div className="mt-3 text-[10px] text-label">
                      <strong className="text-emphasis">{b.tier}</strong>
                    </div>
                  </GlowCard>
                ))}
              </div>
            </div>
          </Reveal>

          <Reveal delay={80}>
            <div className="space-y-6">
              {/* Drive model strip */}
              <div className="rounded-lg border border-edge/30 bg-canvas px-6 py-4">
                <p className="mb-3 text-center text-[10px] font-medium uppercase tracking-wider text-label">
                  Guest Drive Model
                </p>
                <div className="flex flex-wrap items-center justify-center gap-3">
                  {[
                    {
                      dev: "vda",
                      label: "rootfs",
                      cls: "text-accent border-accent/20 bg-accent/5",
                    },
                    {
                      dev: "vdb",
                      label: "rootfs hash-tree",
                      cls: "text-green border-green/20 bg-green/5",
                    },
                    {
                      dev: "vdc",
                      label: "runtime overlay",
                      cls: "text-amber border-amber/20 bg-amber/5",
                    },
                    {
                      dev: "vdd",
                      label: "overlay hash-tree",
                      cls: "text-label border-edge/40 bg-canvas/50",
                    },
                  ].map((d) => (
                    <span
                      key={d.dev}
                      className={`rounded-md border px-2.5 py-1 font-mono text-[11px] ${d.cls}`}
                    >
                      {d.dev} {d.label}
                    </span>
                  ))}
                </div>
              </div>

              {/* Network strip */}
              <div className="flex flex-wrap items-center justify-center gap-4 rounded-lg border border-edge/30 bg-canvas px-6 py-4 text-xs">
                <span className="text-emphasis">guest</span>
                <span className="text-label">no NIC</span>
                <svg
                  className="h-3 w-3 text-label"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                  strokeWidth={2}
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    d="M13.5 4.5 21 12m0 0-7.5 7.5M21 12H3"
                  />
                </svg>
                <span className="font-mono text-emphasis">vsock</span>
                <svg
                  className="h-3 w-3 text-label"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                  strokeWidth={2}
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    d="M13.5 4.5 21 12m0 0-7.5 7.5M21 12H3"
                  />
                </svg>
                <span className="text-emphasis">
                  host substitution endpoint
                </span>
                <span className="text-label">default-deny</span>
                <svg
                  className="h-3 w-3 text-label"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                  strokeWidth={2}
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    d="M13.5 4.5 21 12m0 0-7.5 7.5M21 12H3"
                  />
                </svg>
                <span className="text-emphasis">internet</span>
              </div>
            </div>
          </Reveal>
        </div>
      </div>
    </Section>
  );
}
