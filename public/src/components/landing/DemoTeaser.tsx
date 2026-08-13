import { Button } from "@/components/ui/button";
import { Eyebrow } from "./primitives/Eyebrow";
import { GlowCard } from "./primitives/GlowCard";
import { Reveal } from "./primitives/Reveal";
import { Section } from "./primitives/Section";

export function DemoTeaser() {
  const rawBase = import.meta.env.BASE_URL;
  const base = rawBase.endsWith("/") ? rawBase.slice(0, -1) : rawBase;

  return (
    <Section id="demo-teaser" rule space="tight">
      <div className="grid gap-10 lg:grid-cols-2 lg:items-center lg:gap-14">
        <Reveal>
          <Eyebrow n="04">Try it in your browser</Eyebrow>
          <h2 className="mb-4 lowercase font-display text-2xl font-bold leading-tight text-title sm:text-3xl">
            run the sandbox demo.
          </h2>
          <p className="mb-6 max-w-md text-base leading-relaxed text-body">
            See policy, placeholder substitution, and chain-signed audit
            verification run from the same wasm core the host uses — no install
            required.
          </p>
          <a href={`${base}/demo/`}>
            <Button>Open the demo</Button>
          </a>
        </Reveal>

        <Reveal delay={80}>
          <GlowCard accent={2} className="p-6 sm:p-8">
            <div className="space-y-3 font-mono text-xs text-label">
              <p>module holds: Bearer mvm-secret-...</p>
              <p>destination receives: Bearer sk-real-openai-key</p>
              <p>audit chain: signed, tamper-evident</p>
            </div>
          </GlowCard>
        </Reveal>
      </div>
    </Section>
  );
}
