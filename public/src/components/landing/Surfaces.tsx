import { Section } from "./primitives/Section";
import { Eyebrow } from "./primitives/Eyebrow";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "../ui/tabs";
import { CodeBlock } from "../ui/code-block";
import { SAMPLES } from "./samples";

const SURFACES = [
  { tab: "python", trigger: "Python", sampleId: "sdk-python", docHref: "sdk/python/" },
  { tab: "node", trigger: "Node.js", sampleId: "sdk-node", docHref: "sdk/nodejs/" },
  { tab: "rust", trigger: "Rust", sampleId: "sdk-rust", docHref: "sdk/rust/" },
  { tab: "cli", trigger: "CLI", sampleId: "cli-run", docHref: "reference/cli-commands/" },
] as const;

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
        One call, four surfaces
      </h2>
      <p className="mb-12 max-w-2xl text-lg leading-relaxed text-body">
        Boot an image, allow a host, run a command. Same operation, same
        result, whether it's the Python SDK, the Node.js SDK, the Rust SDK, or{" "}
        <code className="font-mono text-emphasis/90">mvmctl</code> directly.
      </p>

      <Tabs defaultValue="python" className="max-w-3xl">
        <TabsList>
          {SURFACES.map((s) => (
            <TabsTrigger key={s.tab} value={s.tab}>
              {s.trigger}
            </TabsTrigger>
          ))}
        </TabsList>

        {SURFACES.map((s) => {
          const surfaceSample = sample(s.sampleId);
          return (
            <TabsContent key={s.tab} value={s.tab}>
              {surfaceSample && (
                <CodeBlock code={surfaceSample.code} language={surfaceSample.language} />
              )}
            </TabsContent>
          );
        })}
      </Tabs>

      <nav className="mt-8 flex flex-wrap gap-x-8 gap-y-3" aria-label="SDK and CLI documentation">
        {SURFACES.map((s) => (
          <a
            key={s.tab}
            href={`${base}${s.docHref}`}
            className="text-sm text-accent underline underline-offset-2 hover:text-accent/80"
          >
            {s.trigger} docs
          </a>
        ))}
      </nav>
    </Section>
  );
}
