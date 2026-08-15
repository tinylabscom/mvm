import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Eyebrow } from "./primitives/Eyebrow";
import { GlowCard } from "./primitives/GlowCard";
import { Reveal } from "./primitives/Reveal";
import { Section } from "./primitives/Section";

export function DemoTeaser() {
  const rawBase = import.meta.env.BASE_URL;
  const base = rawBase.endsWith("/") ? rawBase.slice(0, -1) : rawBase;
  // The iframe is only mounted after the click so landing-page visitors
  // don't pay for the wasm worker unless they ask for it. Embed mode
  // (?embed=1) hides the demo's config pane and auto-launches, leaving
  // just the console and the audit chain.
  const [open, setOpen] = useState(false);

  return (
    <Section id="demo-teaser" rule space="tight">
      <div className="grid gap-10 lg:grid-cols-2 lg:items-center lg:gap-14">
        <Reveal>
          <Eyebrow n="02">Try it in your browser</Eyebrow>
          <h2 className="mb-4 lowercase font-display text-2xl font-bold leading-tight text-title sm:text-3xl">
            run the sandbox demo.
          </h2>
          <p className="mb-6 max-w-md text-base leading-relaxed text-body">
            See policy, placeholder substitution, and chain-signed audit
            verification run from the same wasm core the host uses — no install
            required.
          </p>
          <Button onClick={() => setOpen((v) => !v)}>
            {open ? "Close the demo" : "Run demo"}
          </Button>
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

      {open && (
        <div className="mt-8 overflow-hidden rounded-xl border border-code-border bg-code-canvas shadow-2xl shadow-black/30">
          <iframe
            src={`${base}/demo/?embed=1`}
            title="mvm browser-tier microVM demo"
            className="block h-176 w-full border-0"
          />
        </div>
      )}
    </Section>
  );
}
