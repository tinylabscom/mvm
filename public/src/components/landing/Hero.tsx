import { useState } from "react";
import { Button } from "../ui/button";
import { Bloom } from "./primitives/Bloom";
import { Reveal } from "./primitives/Reveal";
import { BoundaryDiagram } from "./BoundaryDiagram";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "../ui/tabs";

const ONE_LINER =
  "curl -fsSL https://raw.githubusercontent.com/tinylabscom/mvm/main/install.sh | sh";

function InstallRow({ command }: { command: string }) {
  const [copied, setCopied] = useState(false);

  function copy() {
    navigator.clipboard.writeText(command);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <button
      type="button"
      className="group flex w-full items-center gap-3 rounded-lg border border-edge/50 bg-raised/80 px-5 py-3.5 text-left backdrop-blur transition-all hover:border-accent/30 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-2 focus-visible:ring-offset-page"
      onClick={copy}
      aria-label="Copy install command"
    >
      <span className="text-accent/60 text-sm">$</span>
      <code className="flex-1 text-left font-mono text-sm text-emphasis/90 overflow-x-auto">
        {command}
      </code>
      <span className="shrink-0 rounded border border-edge/50 px-2 py-0.5 text-[11px] text-label transition-colors group-hover:border-accent/30 group-hover:text-accent">
        {copied ? "Copied!" : "Copy"}
      </span>
    </button>
  );
}

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
    <section className="relative w-full overflow-hidden px-6 pt-20 pb-16 sm:px-8 lg:pt-24 lg:pb-20">
      {/* Background glow */}
      <Bloom accents={[1, 2]} />

      <div className="relative mx-auto max-w-6xl">
        <div className="grid grid-cols-1 gap-12 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)] lg:items-center lg:gap-14">
          <div className="flex min-w-0 max-w-xl flex-col gap-6">
            <Reveal delay={80}>
              <h1
                className="max-w-[19rem] sm:max-w-[28rem] lg:max-w-xl font-display font-bold leading-[1.05] tracking-[-0.03em] text-title"
                style={{ fontSize: "clamp(2.5rem, 4.5vw, 4rem)" }}
              >
                Run code you don&rsquo;t trust.
              </h1>
            </Reveal>

            <Reveal delay={160}>
              <p className="max-w-[46ch] text-lg leading-relaxed text-body">
                One command boots it in a microVM with its own kernel. No
                daemon, no SSH, and no network until policy admits it.
              </p>
            </Reveal>

            {/* Platform-specific install — the single install affordance in
                the hero. */}
            <Reveal delay={240}>
              <Tabs defaultValue="macos" className="max-w-lg">
                <TabsList>
                  <TabsTrigger value="macos">macOS</TabsTrigger>
                  <TabsTrigger value="linux">Linux</TabsTrigger>
                  <TabsTrigger value="windows">Windows (WSL2)</TabsTrigger>
                </TabsList>

                <TabsContent value="macos">
                  <p className="mb-4 text-sm leading-relaxed text-body">
                    Apple Silicon only. Runs the HVF backend on macOS 26+, libkrun on
                    macOS 13&ndash;25.
                  </p>
                  <InstallRow command={ONE_LINER} />
                </TabsContent>

                <TabsContent value="linux">
                  <p className="mb-4 text-sm leading-relaxed text-body">
                    Tier 1 target. Needs a kernel with KVM enabled at{" "}
                    <code className="font-mono text-emphasis/90">/dev/kvm</code>.
                  </p>
                  <InstallRow command={ONE_LINER} />
                </TabsContent>

                <TabsContent value="windows">
                  <p className="mb-4 text-sm leading-relaxed text-body">
                    Native Windows isn&apos;t a supported microVM host. Run mvm inside
                    a WSL2 distro with nested KVM and libkrun &mdash; then follow the{" "}
                    <a
                      href={`${base}install/windows/`}
                      className="text-accent underline underline-offset-2 hover:text-accent/80"
                    >
                      WSL2 install guide
                    </a>
                    .
                  </p>
                </TabsContent>
              </Tabs>
            </Reveal>

            <Reveal delay={320} className="flex flex-wrap items-center gap-5">
              <a href={`${base}getting-started/installation/`}>
                <Button size="lg">Get Started</Button>
              </a>
              <a
                href="https://github.com/tinylabscom/mvm"
                target="_blank"
                rel="noopener"
                className="text-sm text-label underline underline-offset-4 hover:text-accent"
              >
                View on GitHub
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
            <BoundaryDiagram />
          </Reveal>
        </div>
      </div>
    </section>
  );
}
