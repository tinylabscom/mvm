import { Button } from "../ui/button";
import { Section } from "./primitives/Section";
import { Bloom } from "./primitives/Bloom";
import { Reveal } from "./primitives/Reveal";

export function CTABanner() {
  const rawBase = import.meta.env.BASE_URL;
  const base = rawBase.endsWith("/") ? rawBase : `${rawBase}/`;
  return (
    <Section>
      <div className="relative overflow-hidden">
        <Bloom accents={[1, 3]} />

        <div className="relative mx-auto flex max-w-2xl flex-col items-center gap-8 text-center">
          <Reveal>
            <p className="text-sm font-medium uppercase tracking-widest text-accent">
              Get started
            </p>
            <h2 className="mt-2 font-display text-3xl font-bold text-title sm:text-4xl">
              Ready to ship your first microVM?
            </h2>
          </Reveal>
          <Reveal delay={80}>
            <p className="max-w-lg text-lg leading-relaxed text-body">
              From zero to a running microVM in minutes. mvm handles
              bootstrapping, Nix builds, and lifecycle management.
            </p>
          </Reveal>
          <Reveal delay={160}>
            <div className="flex flex-wrap justify-center gap-4">
              <a href={`${base}getting-started/quickstart/`}>
                <Button size="lg">Quick Start Guide</Button>
              </a>
              <a
                href="https://github.com/tinylabscom/mvm"
                target="_blank"
                rel="noopener"
              >
                <Button variant="outline" size="lg">
                  View on GitHub
                </Button>
              </a>
            </div>
          </Reveal>
        </div>
      </div>
    </Section>
  );
}
