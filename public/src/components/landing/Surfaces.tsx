import { Section } from "./primitives/Section";
import { Eyebrow } from "./primitives/Eyebrow";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "../ui/tabs";
import { CodeBlock } from "../ui/code-block";
import { SAMPLES } from "./samples";

type LangPane = { tab: string; trigger: string; sampleId: string };

type Surface = {
  tab: string;
  trigger: string;
  blurb: string;
  /** Surfaces with one voice (CLI) render a build/run pair; others offer a language pane. */
  langs?: LangPane[];
};

// CLI does both authoring and running from a shell: compile builds the
// image, run boots it. No language axis — there's one mvmctl.
const CLI_STEPS = [
  { sampleId: "walk-build", label: "Build" },
  { sampleId: "walk-run", label: "Run" },
] as const;

const SURFACES: Surface[] = [
  {
    tab: "cli",
    trigger: "CLI",
    blurb: "mvmctl builds and runs from a shell — the same signed, audited path every other surface goes through.",
  },
  {
    tab: "declare",
    trigger: "Declare",
    blurb:
      "Declare a workload in source. mvmctl reads it statically and emits a Nix flake — your code never runs on the host.",
    langs: [
      { tab: "python", trigger: "Python", sampleId: "python-hello" },
      { tab: "typescript", trigger: "TypeScript", sampleId: "declare-typescript" },
    ],
  },
  {
    tab: "runtime",
    trigger: "Runtime",
    blurb: "Boot and run a machine imperatively, from a script or another process.",
    langs: [
      { tab: "python", trigger: "Python", sampleId: "sdk-python" },
      { tab: "node", trigger: "Node.js", sampleId: "sdk-node" },
      { tab: "rust", trigger: "Rust", sampleId: "sdk-rust" },
    ],
  },
];

export function Surfaces() {
  const rawBase = import.meta.env.BASE_URL;
  const base = rawBase.endsWith("/") ? rawBase : `${rawBase}/`;
  // Returns undefined on a typo'd/missing id rather than throwing, so a
  // bad sample id degrades to a missing pane instead of taking the whole
  // island down.
  const sample = (id: string) => SAMPLES.find((s) => s.id === id);

  return (
    <Section rule space="roomy" className="bg-raised">
      <Eyebrow>SDKs and CLI</Eyebrow>
      <h2 className="mb-4 font-display text-3xl font-bold text-title sm:text-4xl">
        Three surfaces, one execution path
      </h2>
      <p className="mb-12 max-w-2xl text-lg leading-relaxed text-body">
        A shell, a declarative SDK, or an imperative runtime SDK — pick the
        one that fits, they all admit through the same signed{" "}
        <code className="font-mono text-emphasis/90">mvmctl</code> path.
        Language support differs by surface; see below.
      </p>

      <Tabs defaultValue="cli" className="max-w-3xl">
        <TabsList>
          {SURFACES.map((s) => (
            <TabsTrigger key={s.tab} value={s.tab}>
              {s.trigger}
            </TabsTrigger>
          ))}
        </TabsList>

        {SURFACES.map((s) => (
          <TabsContent key={s.tab} value={s.tab}>
            <p className="mb-4 max-w-xl text-sm leading-relaxed text-body">{s.blurb}</p>

            {!s.langs && (
              <div className="flex flex-col gap-4">
                {CLI_STEPS.map((step) => {
                  const cliSample = sample(step.sampleId);
                  return (
                    cliSample && (
                      <div key={step.sampleId} className="min-w-0">
                        <p className="mb-1.5 font-mono text-xs tracking-[0.2em] uppercase text-accent">
                          {step.label}
                        </p>
                        <CodeBlock code={cliSample.code} language={cliSample.language} />
                      </div>
                    )
                  );
                })}
              </div>
            )}

            {s.langs && (
              <Tabs defaultValue={s.langs[0].tab}>
                <TabsList>
                  {s.langs.map((l) => (
                    <TabsTrigger key={l.tab} value={l.tab}>
                      {l.trigger}
                    </TabsTrigger>
                  ))}
                </TabsList>
                {s.langs.map((l) => {
                  const langSample = sample(l.sampleId);
                  return (
                    <TabsContent key={l.tab} value={l.tab}>
                      {langSample && (
                        <CodeBlock code={langSample.code} language={langSample.language} />
                      )}
                    </TabsContent>
                  );
                })}
              </Tabs>
            )}
          </TabsContent>
        ))}
      </Tabs>

      <nav className="mt-8 flex flex-wrap gap-x-8 gap-y-3" aria-label="SDK and CLI documentation">
        <a
          href={`${base}reference/cli-commands/`}
          className="text-sm text-accent underline underline-offset-2 hover:text-accent/80"
        >
          CLI docs
        </a>
        <a
          href={`${base}sdk/python/`}
          className="text-sm text-accent underline underline-offset-2 hover:text-accent/80"
        >
          Python docs
        </a>
        <a
          href={`${base}sdk/nodejs/`}
          className="text-sm text-accent underline underline-offset-2 hover:text-accent/80"
        >
          Node.js docs
        </a>
        <a
          href={`${base}sdk/rust/`}
          className="text-sm text-accent underline underline-offset-2 hover:text-accent/80"
        >
          Rust docs
        </a>
      </nav>
    </Section>
  );
}
