import { Reveal } from "./primitives/Reveal";

// Answers "is this real?" in one glance, directly under the hero — the
// reference site's slot for a customer-logo band. We have no adopters we
// can name, so this carries only what's independently verifiable: the
// licence (LICENSE, Cargo.toml), the platforms (README.md), and the repo
// itself (Cargo.toml `repository`). No stars, no downloads, no logos.
const FACTS = [
  { label: "license", value: "Apache-2.0" },
  { label: "platforms", value: "macOS + Linux" },
];

export function CredibilityStrip() {
  return (
    <div className="w-full border-y border-edge/30 bg-raised/40">
      <div className="mx-auto max-w-6xl border-x border-edge/15 px-6 sm:px-8">
        <Reveal>
          <div className="flex flex-col gap-4 py-6 sm:flex-row sm:items-center sm:justify-between">
            {/* Short label, left. */}
            <p className="font-mono text-xs tracking-[0.2em] uppercase text-label">
              Verified, not asserted
            </p>

            {/* Verified items, right. */}
            <ul className="flex flex-wrap items-center gap-x-8 gap-y-2 sm:justify-end">
              {FACTS.map((f) => (
                <li
                  key={f.label}
                  className="flex items-baseline gap-2 font-mono text-xs lowercase"
                >
                  <span className="text-dim">{f.label}</span>
                  <span className="text-emphasis">{f.value}</span>
                </li>
              ))}
              <li>
                <a
                  href="https://github.com/tinylabscom/mvm"
                  target="_blank"
                  rel="noopener"
                  className="font-mono text-xs lowercase text-label hover:text-accent"
                >
                  github.com/tinylabscom/mvm
                </a>
              </li>
            </ul>
          </div>
        </Reveal>
      </div>
    </div>
  );
}
