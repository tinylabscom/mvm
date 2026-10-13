import { Section } from "./primitives/Section";
import { Eyebrow } from "./primitives/Eyebrow";
import { Reveal } from "./primitives/Reveal";
import { InstallTabs } from "./InstallTabs";

const TERMINAL_LINES = [
  { text: "$ mvmctl machine run --image alpine -- uname -a", dim: false, accent: false },
  { text: "  Preparing a private root from alpine...", dim: true, accent: false },
  { text: "  Booted. Own kernel. Network: deny-all.", dim: false, accent: true },
  { text: "  Linux mvm 6.12.0 #1 SMP aarch64 GNU/Linux", dim: false, accent: false },
];

function TerminalExample() {
  return (
    <div className="w-full overflow-hidden rounded-xl border border-code-border bg-code-canvas shadow-lg shadow-black/20">
      <div className="flex items-center gap-2 border-b border-code-border bg-code-header px-4 py-3">
        <span className="h-3 w-3 rounded-full bg-dot-close/80" />
        <span className="h-3 w-3 rounded-full bg-dot-minimize/80" />
        <span className="h-3 w-3 rounded-full bg-dot-expand/80" />
        <span className="ml-3 text-xs text-code-text/55">terminal</span>
      </div>
      <div className="p-5 font-mono text-[13px] leading-relaxed sm:p-6">
        {TERMINAL_LINES.map((line, i) => (
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

export function Quickstart() {
  const rawBase = import.meta.env.BASE_URL;
  const base = rawBase.endsWith("/") ? rawBase : `${rawBase}/`;

  return (
    <Section rule space="tight">
      <div className="grid gap-10 lg:grid-cols-[minmax(0,0.85fr)_minmax(0,1.15fr)] lg:items-start lg:gap-16">
        <div className="lg:sticky lg:top-32">
          <Reveal>
            <Eyebrow>Quickstart</Eyebrow>
            <h2 className="max-w-sm lowercase font-display tracking-tight text-2xl font-semibold leading-tight text-title sm:text-3xl">
              one command.
              <br />
              one private kernel.
            </h2>
            {/* Inline margins, not mt-*: Starlight's unlayered stylesheet
                beats layered utilities on this page (see Positioning.tsx). */}
            <p
              className="max-w-sm text-base leading-relaxed text-body"
              style={{ marginTop: "1.5rem" }}
            >
              Install mvm, then run an OCI image in a transient microVM.
              Networking is denied by default, and the machine is removed when
              the command exits.
            </p>
            <a
              href={`${base}getting-started/quickstart/`}
              className="inline-block text-sm text-accent underline underline-offset-2 hover:text-accent/80"
              style={{ marginTop: "2rem" }}
            >
              Read the full quickstart guide
            </a>
            <div style={{ marginTop: "2.5rem" }}>
              {/* Keep install beside the first runnable command: the homepage
                  should not require a docs detour before a developer can try it. */}
              <InstallTabs />
            </div>
          </Reveal>
        </div>

        <Reveal delay={80} className="max-w-xl">
          <TerminalExample />
          <div className="mt-5 flex flex-wrap gap-x-5 gap-y-2 text-sm">
            <a className="text-accent underline underline-offset-2" href={`${base}getting-started/python-quickstart/`}>
              Python SDK
            </a>
            <a className="text-accent underline underline-offset-2" href={`${base}getting-started/nodejs-quickstart/`}>
              TypeScript SDK
            </a>
            <a className="text-accent underline underline-offset-2" href={`${base}guides/ai-agent-integration/`}>
              Run an AI agent
            </a>
          </div>
        </Reveal>
      </div>
    </Section>
  );
}
