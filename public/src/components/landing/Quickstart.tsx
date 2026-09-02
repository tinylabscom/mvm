import { useEffect, useState } from "react";
import { Section } from "./primitives/Section";
import { Eyebrow } from "./primitives/Eyebrow";
import { Reveal } from "./primitives/Reveal";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "../ui/tabs";
import { CodeBlock } from "../ui/code-block";
import { SAMPLES } from "./samples";

// The run leg of the Define/Build/Run walk — same flake the Build tab
// compiles (examples/python/hello-env/, see walk-* in samples.ts), so the
// printed output follows from the code on the Define tab.
const TERMINAL_LINES = [
  { text: "$ mvmctl machine run --flake /tmp/hello-env --entrypoint", delay: 0 },
  { text: "  Preparing a private root from the compiled flake...", delay: 900, dim: true },
  { text: "  Booted. Own kernel. Network: deny-all.", delay: 2200, accent: true },
  { text: "  hello danny", delay: 3100 },
];

// Folded down from the old scroll-synced walkthrough (four steps stacked at
// 26vh each — a lot of scroll for four short facts) into one tabbed panel,
// which fits the quickstart block's compact right-hand slot and reads in
// one screen instead of four scroll stops.
function TerminalAnimation() {
  const [visibleLines, setVisibleLines] = useState(0);

  useEffect(() => {
    const timers = TERMINAL_LINES.map((line, i) =>
      setTimeout(() => setVisibleLines(i + 1), line.delay),
    );
    return () => timers.forEach(clearTimeout);
  }, []);

  return (
    <div className="w-full overflow-hidden rounded-xl border border-code-border bg-code-canvas shadow-lg shadow-black/20">
      <div className="flex items-center gap-2 border-b border-code-border bg-code-header px-4 py-3">
        <span className="h-3 w-3 rounded-full bg-dot-close/80" />
        <span className="h-3 w-3 rounded-full bg-dot-minimize/80" />
        <span className="h-3 w-3 rounded-full bg-dot-expand/80" />
        <span className="ml-3 text-xs text-code-text/55">terminal</span>
      </div>
      <div className="p-5 font-mono text-[13px] leading-relaxed sm:p-6">
        {TERMINAL_LINES.slice(0, visibleLines).map((line, i) => (
          <div
            key={i}
            className={
              line.accent ? "text-code-success" : line.dim ? "text-code-text/55" : "text-code-text"
            }
          >
            {line.text}
          </div>
        ))}
        <span
          className="site-terminal-cursor inline-block h-4 w-2 animate-pulse bg-accent/70"
          aria-hidden="true"
        />
      </div>
    </div>
  );
}

const STEPS = [
  { tab: "define", trigger: "Define", sampleId: "walk-define" },
  { tab: "build", trigger: "Build", sampleId: "walk-build" },
  { tab: "run", trigger: "Run", sampleId: "walk-run" },
] as const;

export function Quickstart() {
  const rawBase = import.meta.env.BASE_URL;
  const base = rawBase.endsWith("/") ? rawBase : `${rawBase}/`;
  const sample = (id: string) => SAMPLES.find((s) => s.id === id);

  return (
    <Section rule space="tight">
      <div className="grid gap-10 lg:grid-cols-[minmax(0,0.85fr)_minmax(0,1.15fr)] lg:items-start lg:gap-16">
        <div className="lg:sticky lg:top-32">
          <Reveal>
            <Eyebrow>Quickstart</Eyebrow>
            <h2 className="max-w-sm lowercase font-display tracking-tight text-2xl font-semibold leading-tight text-title sm:text-3xl">
              file in.
              <br />
              running microVM out.
            </h2>
            {/* Inline margins, not mt-*: Starlight's unlayered stylesheet
                beats layered utilities on this page (see Positioning.tsx). */}
            <p
              className="max-w-sm text-base leading-relaxed text-body"
              style={{ marginTop: "1.5rem" }}
            >
              mvmctl reads the decorator statically, builds a rootfs inside a
              builder VM, and boots the workload in its own kernel &mdash;
              nothing you run here ever executes on your host.
            </p>
            <a
              href={`${base}getting-started/quickstart/`}
              className="inline-block text-sm text-accent underline underline-offset-2 hover:text-accent/80"
              style={{ marginTop: "2rem" }}
            >
              Read the full quickstart guide
            </a>
          </Reveal>
        </div>

        <Reveal delay={80}>
          <Tabs defaultValue="define" className="max-w-xl">
            <TabsList>
              {STEPS.map((s) => (
                <TabsTrigger key={s.tab} value={s.tab}>
                  {s.trigger}
                </TabsTrigger>
              ))}
            </TabsList>
            {STEPS.map((s) => {
              const stepSample = sample(s.sampleId);
              return (
                <TabsContent key={s.tab} value={s.tab}>
                  {s.tab === "run" ? (
                    <TerminalAnimation />
                  ) : (
                    stepSample && (
                      <CodeBlock code={stepSample.code} language={stepSample.language} />
                    )
                  )}
                </TabsContent>
              );
            })}
          </Tabs>
        </Reveal>
      </div>
    </Section>
  );
}
