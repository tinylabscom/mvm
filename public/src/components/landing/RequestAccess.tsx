import { Eyebrow } from "./primitives/Eyebrow";
import { Reveal } from "./primitives/Reveal";
import { Section } from "./primitives/Section";

const WORKLOAD_CLASSES = [
  "AI agents · tool use",
  "Code interpreter",
  "Multi-tenant platform",
  "Workflow runtime",
  "Other",
];

export function RequestAccess() {
  return (
    <Section id="request-access" rule>
      <div className="grid gap-10 lg:grid-cols-[1.1fr_0.9fr] lg:items-start lg:gap-14">
        <Reveal>
          <Eyebrow>Request access</Eyebrow>
          {/* Inline margin, not mb-*: Starlight's unlayered stylesheet beats
              layered utilities on this page (see Positioning.tsx). */}
          <h2
            className="lowercase font-display tracking-tight text-2xl font-semibold leading-tight text-title sm:text-3xl"
            style={{ marginBottom: "1.5rem" }}
          >
            run the workload. isolate the tenant. enforce the policy. audit the
            execution.
          </h2>
          <p className="max-w-xl text-base leading-relaxed text-body">
            Working with a small group of design partners building agent
            platforms, code interpreters, secure workflow runners, multi-tenant
            SaaS, and edge AI workloads.
          </p>
        </Reveal>

        <Reveal delay={80}>
          <form
            className="rounded-xl border border-glass-border/60 bg-raised p-6"
            action="https://formspree.io/f/xwvyllrp"
            method="POST"
          >
            <p className="mb-5 font-mono text-[11px] font-semibold tracking-[0.14em] uppercase text-label">
              Form.access
            </p>
            <label
              className="mb-2 block text-sm font-medium text-emphasis"
              htmlFor="request-access-email"
            >
              Email
            </label>
            <input
              id="request-access-email"
              type="email"
              name="email"
              required
              placeholder="you@yourcompany.com"
              className="w-full rounded-lg border border-edge bg-canvas px-4 py-2.5 font-mono text-sm text-emphasis placeholder:text-dim focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/20"
            />
            <p className="mt-5 mb-2 text-sm font-medium text-emphasis">
              Workload class
            </p>
            <div className="flex flex-wrap gap-2">
              {WORKLOAD_CLASSES.map((wc, i) => (
                <label
                  key={wc}
                  className="cursor-pointer rounded-full border border-edge bg-canvas px-3.5 py-1.5 font-mono text-xs text-body transition-colors hover:border-accent/50 has-checked:border-accent has-checked:text-accent"
                >
                  <input
                    type="radio"
                    name="class"
                    value={wc}
                    defaultChecked={i === 0}
                    className="sr-only"
                  />
                  <span>{wc}</span>
                </label>
              ))}
            </div>
            <div className="mt-6 flex flex-wrap items-center gap-4">
              <button
                type="submit"
                className="inline-flex h-10 items-center justify-center rounded-lg bg-action px-5 text-sm font-medium text-canvas transition-colors hover:bg-action-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-2"
              >
                Request access &rarr;
              </button>
              <span className="font-mono text-xs text-label">
                Response within 48h
              </span>
            </div>
          </form>
        </Reveal>
      </div>
    </Section>
  );
}
