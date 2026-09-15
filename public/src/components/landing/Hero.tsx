import { Button } from "../ui/button";
import { Bloom } from "./primitives/Bloom";
import { Reveal } from "./primitives/Reveal";
import { HeroStackDiagram } from "./HeroStackDiagram";

// The install affordance (one-liner + platform tabs) moved to
// InstallTabs.tsx, rendered inside Quickstart — the hero keeps the
// claim and the diagram, and the story runs before the install
// command (pitch-script reshape).
export function Hero() {
  const rawBase = import.meta.env.BASE_URL;
  const base = rawBase.endsWith("/") ? rawBase : `${rawBase}/`;

  return (
    // Padding lives on the section itself (not a wrapper div) so the
    // `mx-auto max-w-6xl` div below is a *direct* child of `main section` —
    // same shape as Section.tsx. That direct-child relationship matters:
    // `[data-has-hero] main section > div { margin-inline: auto }` in
    // custom.css is what actually centers these divs (Tailwind's `mx-auto`
    // utility loses to Starlight's unlayered CSS otherwise, see that rule's
    // comment) — one extra nesting level here previously put the centering
    // div out of that selector's reach and silently dropped the gutter to
    // padding-only, 74px short of every other section's at 1440px.
    // Bloom's `inset-0` still spans edge-to-edge: an absolutely positioned
    // descendant's containing block is the *padding* box of this element,
    // so this section's own padding doesn't inset it.
    <section className="relative w-full overflow-hidden px-6 pt-24 pb-12 sm:px-8 sm:pt-20 lg:pt-24 lg:pb-16">
      {/* Background glow */}
      <Bloom accents={[1, 2]} />

      <div className="relative mx-auto max-w-6xl border-x border-edge/15">
        <div className="grid grid-cols-1 gap-12 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)] lg:items-center lg:gap-14">
          <div className="flex min-w-0 max-w-xl flex-col gap-6">
            {/* Credibility badge row — verified facts only, checked against
                LICENSE, Cargo.toml, and README.md. No stars/downloads/adopters. */}
            <Reveal delay={0}>
              <p className="flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-xs lowercase text-label">
                <span>apache 2.0</span>
                <span className="text-dim" aria-hidden="true">
                  /
                </span>
                <span>macos + linux</span>
                <span className="text-dim" aria-hidden="true">
                  /
                </span>
                <a
                  href="https://github.com/tinylabscom/mvm"
                  target="_blank"
                  rel="noopener"
                  className="hover:text-accent"
                >
                  github.com/tinylabscom/mvm
                </a>
              </p>
            </Reveal>

            <Reveal delay={80}>
              {/* Sized for Inter, not for the mono face this used to set in:
                  Inter runs ~20% narrower at the same point size, so the
                  ceiling goes up and the max-widths come down to hold the
                  same two-line break. Tracking is -0.03em rather than the
                  -0.01em mono wanted — a sans this large needs the pull, and
                  it is most of what keeps the headline from reading generic. */}
              <h1
                className="max-w-[16rem] sm:max-w-[26rem] lg:max-w-xl lowercase font-display font-semibold leading-[1.05] tracking-[-0.03em] text-title"
                style={{ fontSize: "clamp(2.5rem, 4.8vw, 3.9rem)" }}
              >
                Run code you can&rsquo;t fully{" "}
                <span className="text-accent-2">trust</span>.
              </h1>
            </Reveal>

            <Reveal delay={120}>
              <p className="font-display text-xl font-semibold leading-snug text-title sm:text-2xl">
                A secure execution layer, built security-first for AI agents.
              </p>
              {/* The what-MVM-does callout — this sentence is the pitch, so
                  it gets an accent rule and emphasized key phrases instead
                  of reading as body copy. */}
              <p
                className="text-base leading-relaxed text-body"
                style={{ marginTop: "1rem" }}
              >
                mvm puts the agent in a box: any workload &mdash; an agent, a
                customer&rsquo;s code, a build job &mdash; runs inside a
                sealed, immutable, hardware-isolated microVM.
              </p>
              {/* Runs-anywhere facts as badge chips, in the same mono idiom
                  as the credibility row above. */}
              <div className="mt-4 flex flex-wrap gap-2 font-mono text-[11px] lowercase">
                {["sub-150 ms boot", "on a laptop", "in the cloud", "in a browser"].map(
                  (chip) => (
                    <span
                      key={chip}
                      className="rounded border border-edge/50 bg-raised/60 px-2.5 py-1 text-label"
                    >
                      {chip}
                    </span>
                  ),
                )}
              </div>
            </Reveal>

            <Reveal delay={320} className="flex flex-wrap items-center gap-4">
              <a href={`${base}getting-started/quickstart/`}>
                <Button size="lg">Get Started</Button>
              </a>
              <a href="#request-access">
                <Button size="lg" variant="outline">
                  Request access &rarr;
                </Button>
              </a>
            </Reveal>

          </div>

          {/* The boundary diagram — the hero's visual anchor. This is the
              page's actual differentiator (own kernel, no NIC, one vsock
              channel to a deny-all-by-default endpoint), not a generic
              product shot, so it carries the argument as much as the
              headline does. */}
          <Reveal delay={360} className="relative">
            <div className="pointer-events-none absolute -inset-4 rounded-2xl bg-linear-to-br from-glow-1 via-transparent to-glow-3 blur-xl" />
            <div className="mx-auto w-full max-w-[18rem] sm:max-w-[22rem] lg:max-w-none">
              <HeroStackDiagram />
            </div>
          </Reveal>
        </div>
      </div>
    </section>
  );
}
