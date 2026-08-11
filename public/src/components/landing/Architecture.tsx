import { Section } from "./primitives/Section";
import { Reveal } from "./primitives/Reveal";

// Class names below are written out in full (not built from a template
// literal) because Tailwind's build-time scanner matches literal substrings
// in the source text — an interpolated `border-${x}/30` never appears as a
// real token and silently drops out of the generated CSS.
const BACKENDS = [
  {
    name: "Firecracker",
    badge: "default",
    desc: "Production-grade microVMs. Snapshots, pause/resume, vsock-only egress — no guest NIC.",
    tier: "Linux + KVM — native",
  },
  {
    name: "HVF",
    badge: undefined,
    desc: "In-house Hypervisor.framework VMM. Vsock-only device model, no Homebrew dependencies.",
    tier: "macOS 26+ Apple Silicon — default",
  },
  {
    name: "libkrun",
    badge: undefined,
    desc: "Third-party in-process VMM via Homebrew (slp/krun/libkrun). Vsock-only egress.",
    tier: "macOS 13–25 — default. Also opt-in on Linux.",
  },
  {
    name: "microvm.nix",
    badge: "dev/test",
    desc: "NixOS-native VM runner with QEMU. Dev/test only — never used for multi-tenant workloads.",
    tier: "Linux — opt-in",
  },
];

export function Architecture() {
  return (
    <Section space="tight" className="border-y border-edge/30 bg-raised/50">
      <h2 className="lowercase font-display text-2xl font-bold leading-tight text-title sm:text-3xl">
        One CLI. The backend picked for you.
      </h2>
      <p className="mt-4 max-w-2xl text-base leading-relaxed text-body">
        mvmctl reads your OS, chip, and macOS version and picks a backend:
        HVF on macOS 26+ Apple Silicon, libkrun on macOS 13–25, Firecracker
        on Linux with KVM. Every one of them boots the guest over vsock with
        no NIC — no SSH path in, no host daemon to run.
      </p>

      <div className="mt-8 max-w-3xl space-y-6">
        {/* Host layer */}
        <Reveal>
          <div className="rounded-xl border border-edge/40 p-6 sm:p-8">
            <div className="flex items-center gap-3">
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-accent/10 text-accent">
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
                <span className="text-sm font-semibold text-emphasis">
                  Your Host
                </span>
                <span className="ml-2 text-xs text-label">macOS / Linux</span>
              </div>
            </div>

            {/* Auto-detect divider */}
            <div className="my-5 flex items-center gap-3 ml-11">
              <div className="h-px flex-1 bg-edge/40" />
              <span className="text-[10px] font-medium uppercase tracking-wider text-label">
                auto-select
              </span>
              <div className="h-px flex-1 bg-edge/40" />
            </div>

            {/* Backend list — quiet rows, no cards */}
            <ul className="space-y-4">
              {BACKENDS.map((b) => (
                <li key={b.name} className="border-t border-edge/30 pt-4 first:border-t-0 first:pt-0">
                  <div className="flex flex-wrap items-baseline gap-2">
                    <span className="text-sm font-semibold text-emphasis">{b.name}</span>
                    {b.badge && (
                      <span className="rounded px-1.5 py-0.5 text-[10px] text-label bg-canvas/60">
                        {b.badge}
                      </span>
                    )}
                    <span className="text-[11px] text-label">{b.tier}</span>
                  </div>
                  <p className="mt-1 text-xs leading-relaxed text-label">{b.desc}</p>
                </li>
              ))}
            </ul>
          </div>
        </Reveal>

        <Reveal delay={80}>
          <div className="space-y-6">
            {/* Drive model strip */}
            <div className="rounded-lg border border-edge/30 bg-canvas px-6 py-4">
              <p className="mb-3 text-[10px] font-medium uppercase tracking-wider text-label">
                Sealed-Boot Guest Drive Model
              </p>
              <div className="flex flex-wrap items-center gap-3">
                {[
                  { dev: "vda", label: "rootfs" },
                  { dev: "vdb", label: "rootfs hash-tree" },
                  { dev: "vdc", label: "runtime overlay" },
                  { dev: "vdd", label: "overlay hash-tree" },
                ].map((d) => (
                  <span
                    key={d.dev}
                    className="rounded-md border border-edge/40 bg-canvas/50 px-2.5 py-1 font-mono text-[11px] text-label"
                  >
                    {d.dev} {d.label}
                  </span>
                ))}
              </div>
              <p className="mt-3 text-[10px] text-label">
                dm-verity rootfs + runtime overlay — the production boot
                shape. Dev and volume-mount boots assign these devices
                differently.
              </p>
            </div>

            {/* Network strip */}
            <div className="flex flex-wrap items-center gap-4 rounded-lg border border-edge/30 bg-canvas px-6 py-4 text-xs">
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
    </Section>
  );
}
