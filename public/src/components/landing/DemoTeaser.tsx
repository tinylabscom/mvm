import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { Eyebrow } from "./primitives/Eyebrow";
import { GlowCard } from "./primitives/GlowCard";
import { Reveal } from "./primitives/Reveal";
import { Section } from "./primitives/Section";

export function DemoTeaser() {
  const rawBase = import.meta.env.BASE_URL;
  const base = rawBase.endsWith("/") ? rawBase.slice(0, -1) : rawBase;
  // The dialog (and its iframe) is only mounted after the click so
  // landing-page visitors don't pay for the wasm worker unless they ask
  // for it. Autorun (?autorun=1) starts the WebLinux engine as soon as
  // the iframe loads.
  const [open, setOpen] = useState(false);

  useEffect(() => {
    if (!open) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("keydown", onKeyDown);
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      document.body.style.overflow = prevOverflow;
    };
  }, [open]);

  return (
    <Section id="demo-teaser" rule space="tight">
      <div className="grid gap-10 lg:grid-cols-2 lg:items-center lg:gap-14">
        <Reveal>
          <Eyebrow n="02">Try it in your browser</Eyebrow>
          {/* Inline margins, not margin utilities: Starlight's unlayered
              stylesheet beats layered utilities on this page (see
              Positioning.tsx). */}
          <h2
            className="lowercase font-display text-2xl font-bold leading-tight text-title sm:text-3xl"
            style={{ marginBottom: "1.5rem" }}
          >
            run a linux vm in your browser.
          </h2>
          <p className="max-w-md text-base leading-relaxed text-body">
            See a real x86_64 Linux guest boot inside the browser under
            the QEMU-Wasm engine — no install
            required.
          </p>
          <div style={{ marginTop: "2rem" }}>
            <Button onClick={() => setOpen(true)}>Run demo</Button>
          </div>
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
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm sm:p-8"
          role="dialog"
          aria-modal="true"
          aria-label="mvm WebLinux demo"
          onClick={(e) => {
            if (e.target === e.currentTarget) setOpen(false);
          }}
        >
          <div className="relative w-full max-w-6xl overflow-hidden rounded-xl border border-code-border bg-code-canvas shadow-2xl shadow-black/50">
            <div className="flex items-center justify-between border-b border-code-border px-4 py-2.5">
              <p className="font-mono text-xs tracking-[0.14em] uppercase text-label">
                mvm · WebLinux demo
              </p>
              <button
                type="button"
                onClick={() => setOpen(false)}
                aria-label="Close demo"
                className="rounded px-2 py-0.5 font-mono text-sm text-label transition-colors hover:text-emphasis focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
              >
                [ × ]
              </button>
            </div>
            <iframe
              src={`${base}/demo/weblinux/?autorun=1`}
              title="mvm WebLinux demo"
              className="block h-128 w-full border-0"
            />
          </div>
        </div>
      )}
    </Section>
  );
}
