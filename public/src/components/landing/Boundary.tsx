import { Section } from "./primitives/Section";
import { Reveal } from "./primitives/Reveal";

// Split feature panel: one bordered card, cut in half. Left half makes the
// argument (the guarantee is backend-agnostic); right half carries the one
// figure that proves it — a workload always gets its own kernel, whichever
// VMM mvmctl resolved to. Chips replace the old per-backend detail table
// (drive model, network strip) this section used to carry — that detail
// lives in the docs now, not on the homepage.
const BACKENDS = ["Firecracker", "HVF", "libkrun", "microvm.nix (dev/test)"];

export function Boundary() {
  const rawBase = import.meta.env.BASE_URL;
  const base = rawBase.endsWith("/") ? rawBase : `${rawBase}/`;

  return (
    <Section rule space="tight">
      <Reveal>
        <div className="grid overflow-hidden rounded-2xl border border-edge/50 lg:grid-cols-2">
          {/* Left half: the argument. */}
          <div className="p-8 sm:p-10 lg:p-12">
            <h2 className="mb-4 lowercase font-display tracking-tight text-2xl font-semibold leading-tight text-title sm:text-3xl">
              one boundary, three backends
            </h2>
            <p className="mb-6 max-w-md text-base leading-relaxed text-body">
              mvmctl reads your OS, chip, and macOS version and resolves one
              of three VMMs. Which one runs underneath isn&rsquo;t the point
              &mdash; the guarantee doesn&rsquo;t change when the VMM does.
              Every one of them boots the guest with its own kernel, no NIC,
              and vsock as the only way out.
            </p>
            <ul className="flex flex-wrap gap-2" aria-label="Supported backends">
              {BACKENDS.map((b) => (
                <li
                  key={b}
                  className="rounded-full border border-edge/60 px-3 py-1 font-mono text-xs lowercase text-label"
                >
                  {b}
                </li>
              ))}
            </ul>
          </div>

          {/* Right half: the figure. */}
          <div className="flex flex-col justify-center bg-accent-low p-8 sm:p-10 lg:p-12">
            <p className="font-display tracking-tight text-5xl font-semibold text-title sm:text-6xl">1</p>
            {/* text-emphasis, not text-body: body measured 4.26:1 on the accent-low
                fill, just under the 4.5 AA floor for this size. */}
            <p className="mt-2 max-w-xs text-sm leading-relaxed text-emphasis">
              kernel per workload &mdash; no NIC, no shared namespace, vsock
              as the only way out.
            </p>
            <a
              href={`${base}reference/architecture/`}
              className="mt-6 inline-block text-sm text-accent underline underline-offset-2 hover:text-accent/80"
            >
              How backends map to VMMs
            </a>
          </div>
        </div>
      </Reveal>
    </Section>
  );
}
