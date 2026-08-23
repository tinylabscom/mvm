import { Section } from "./primitives/Section";
import { Reveal } from "./primitives/Reveal";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "../ui/tabs";
import { CodeBlock } from "../ui/code-block";
import { SAMPLES } from "./samples";

type LangPane = { tab: string; trigger: string; sampleId: string };

type Row = {
  label: string;
  heading: string;
  body: string;
  linkLabel: string;
  linkHref: string;
  /** Single sample, or a language-tabbed set for surfaces with more than one voice. */
  sampleId?: string;
  langs?: LangPane[];
};

const ROWS: Row[] = [
  {
    label: "Shell",
    heading: "CLI",
    body: "mvmctl builds and runs from a shell — the same signed, audited path every other surface goes through. It's the fastest way to try a workload before wiring it into a script or a pipeline.",
    linkLabel: "CLI reference",
    linkHref: "reference/cli-commands/",
    sampleId: "cli-run",
  },
  {
    label: "Source",
    heading: "Declare",
    body: "Declare a workload with a decorator. mvmctl reads it statically and emits a Nix flake — the function body never executes on your host. Available for Python and TypeScript today; Rust has no declarative surface yet.",
    linkLabel: "Python SDK docs",
    linkHref: "sdk/python/",
    langs: [
      { tab: "python", trigger: "Python", sampleId: "python-hello" },
      { tab: "typescript", trigger: "TypeScript", sampleId: "declare-typescript" },
    ],
  },
  {
    label: "Process",
    heading: "Runtime",
    body: "Boot and run a machine imperatively, called from a script or another process. Python and Node.js ship a runtime client today; a Rust lifecycle client is planned, not shipped.",
    linkLabel: "Node.js SDK docs",
    linkHref: "sdk/nodejs/",
    langs: [
      { tab: "python", trigger: "Python", sampleId: "sdk-python" },
      { tab: "node", trigger: "Node.js", sampleId: "sdk-node" },
      { tab: "rust", trigger: "Rust", sampleId: "sdk-rust" },
    ],
  },
];

function RowPanel({ row }: { row: Row }) {
  const sample = (id: string) => SAMPLES.find((s) => s.id === id);

  if (row.langs) {
    return (
      <Tabs defaultValue={row.langs[0].tab}>
        <TabsList>
          {row.langs.map((l) => (
            <TabsTrigger key={l.tab} value={l.tab}>
              {l.trigger}
            </TabsTrigger>
          ))}
        </TabsList>
        {row.langs.map((l) => {
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
    );
  }

  const s = row.sampleId ? sample(row.sampleId) : undefined;
  return s ? <CodeBlock code={s.code} language={s.language} /> : null;
}

export function Positioning() {
  const rawBase = import.meta.env.BASE_URL;
  const base = rawBase.endsWith("/") ? rawBase : `${rawBase}/`;

  return (
    <Section rule space="roomy" className="bg-raised">
      <Reveal>
        <h2 className="mb-6 max-w-xl lowercase font-display tracking-tight text-3xl font-semibold leading-tight text-title sm:text-4xl">
          one project.
          <br />
          <span className="inline-block bg-accent-2 px-2 py-0.5 text-canvas">
            three ways to drive it.
          </span>
        </h2>
      </Reveal>

      {/* Three panels side by side across the section, each with its text
          directly underneath. Collapses to a single column on small
          screens. */}
      {/* Inline margin, not a Tailwind mt-* utility: Starlight's unlayered
          stylesheet beats layered utilities on this page (see Hero.tsx's
          centering comment), and this gap is load-bearing for the section's
          rhythm. */}
      <div
        className="grid gap-12 lg:grid-cols-3 lg:gap-8"
        style={{ marginTop: "5rem" }}
      >
        {ROWS.map((row, i) => (
          <Reveal key={row.heading} delay={i * 80}>
            {/* Text on top, panel anchored to the card's bottom edge: the
                cards stretch to equal height, so the panels' bottoms sit on
                one shared line even though the text blocks and code samples
                differ in length. */}
            <div className="flex h-full flex-col">
              <p className="mb-1.5 font-mono text-xs tracking-[0.2em] uppercase text-accent">
                {row.label}
              </p>
              <h3 className="mb-2 lowercase font-display tracking-tight text-lg font-semibold text-title">
                {row.heading}
              </h3>
              <p className="text-sm leading-relaxed text-body">{row.body}</p>
              <a
                href={`${base}${row.linkHref}`}
                className="mt-3 self-start text-sm text-accent underline underline-offset-2 hover:text-accent/80"
              >
                {row.linkLabel}
              </a>
              <div className="mt-auto min-w-0 pt-5">
                <RowPanel row={row} />
              </div>
            </div>
          </Reveal>
        ))}
      </div>
    </Section>
  );
}
