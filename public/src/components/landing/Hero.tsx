import { useState } from "react";
import { Button } from "../ui/button";
import { Bloom } from "./primitives/Bloom";
import { Reveal } from "./primitives/Reveal";
import { HeroStackDiagram } from "./HeroStackDiagram";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "../ui/tabs";

const ONE_LINER =
  "curl -fsSL https://raw.githubusercontent.com/tinylabscom/mvm/main/install.sh | sh";

// Splits on "/" and inserts a <wbr> right after each one, so the browser's
// only wrap opportunities inside the URL are slash boundaries — never mid
// path-segment. Default (unmodified) overflow-wrap only breaks at existing
// break characters, so once the wrap points are placed deliberately, no
// segment ever splits mid-token the way the un-broken command used to
// under the mono face (which sets ~20% wider than the sans it was tuned
// for). Space stays a break point via normal browser behaviour.
function withSlashBreaks(command: string) {
  const parts = command.split("/");
  return parts.map((part, i) => (
    <span key={i}>
      {part}
      {i < parts.length - 1 && (
        <>
          /<wbr />
        </>
      )}
    </span>
  ));
}

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
      className="group flex w-full flex-wrap items-center gap-x-3 gap-y-2 rounded-lg border border-edge/50 bg-raised/80 px-5 py-3.5 text-left backdrop-blur transition-all hover:border-accent/30 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-2 focus-visible:ring-offset-page"
      onClick={copy}
      aria-label="Copy install command"
    >
      <span className="text-accent/60 text-sm">$</span>
      {/* The command shares the line with the $ at every width; long
          commands wrap inside the code element (at slash boundaries) rather
          than dropping to their own row. */}
      <code className="min-w-0 flex-1 text-sm leading-relaxed break-normal font-mono text-emphasis/90">
        {withSlashBreaks(command)}
      </code>
      <span className="ml-auto shrink-0 self-center rounded border border-edge/50 px-2 py-0.5 text-[11px] text-label transition-colors group-hover:border-accent/30 group-hover:text-accent">
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
    <section className="relative w-full overflow-hidden px-6 pt-24 pb-12 sm:px-8 sm:pt-20 lg:pt-24 lg:pb-16">
      {/* Background glow */}
      <Bloom accents={[1, 2]} />

      <div className="relative mx-auto max-w-6xl border-x border-edge/15">
        <div className="grid grid-cols-1 gap-12 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)] lg:items-center lg:gap-14">
          <div className="flex min-w-0 max-w-xl flex-col gap-6">
            {/* Credibility badge row — verified facts only, checked against
                LICENSE, Cargo.toml, and README.md. No stars/downloads/adopters. */}
            <Reveal delay={0}>
              <p className="flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-xs lowercase text-label">
                <span>apache 2.0</span>
                <span className="text-dim" aria-hidden="true">
                  /
                </span>
                <span>macos + linux</span>
                <span className="text-dim" aria-hidden="true">
                  /
                </span>
                <a
                  href="https://github.com/tinylabscom/mvm"
                  target="_blank"
                  rel="noopener"
                  className="hover:text-accent"
                >
                  github.com/tinylabscom/mvm
                </a>
              </p>
            </Reveal>

            <Reveal delay={80}>
              {/* Sized for Inter, not for the mono face this used to set in:
                  Inter runs ~20% narrower at the same point size, so the
                  ceiling goes up and the max-widths come down to hold the
                  same two-line break. Tracking is -0.03em rather than the
                  -0.01em mono wanted — a sans this large needs the pull, and
                  it is most of what keeps the headline from reading generic. */}
              <h1
                className="max-w-[16rem] sm:max-w-[26rem] lg:max-w-xl lowercase font-display font-semibold leading-[1.05] tracking-[-0.03em] text-title"
                style={{ fontSize: "clamp(2.5rem, 4.8vw, 3.9rem)" }}
              >
                Run code you don&rsquo;t <span className="text-accent-2">trust</span>.
              </h1>
            </Reveal>

            <Reveal delay={120}>
              <p className="font-display text-xl font-semibold leading-snug text-title sm:text-2xl">
                Agent execution a security team can approve.
              </p>
              <p className="mt-2 max-w-[46ch] text-base leading-relaxed text-body">
                Hardened microVMs under a signed execution contract.
                Sub-150&nbsp;ms boot. Configurable to the kernel.
              </p>
            </Reveal>

            {/* Platform-specific install — the single install affordance in
                the hero. */}
            <Reveal delay={240}>
              <Tabs defaultValue="unix" className="max-w-lg">
                <TabsList>
                  <TabsTrigger value="unix">macOS / Linux</TabsTrigger>
                  <TabsTrigger value="windows">Windows (WSL2)</TabsTrigger>
                </TabsList>

                <TabsContent value="unix">
                  <p className="mb-4 text-sm leading-relaxed text-body">
                    macOS 13+ (libkrun on 13&ndash;25, HVF on 26+) or Linux with{" "}
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

            <Reveal delay={320} className="flex flex-wrap items-center gap-4">
              <a href={`${base}getting-started/quickstart/`}>
                <Button size="lg">Get Started</Button>
              </a>
              <a href="#request-access">
                <Button size="lg" variant="outline">
                  Request access &rarr;
                </Button>
              </a>
            </Reveal>

            {/* Tertiary text link — the third action the reference reserves
                for a lower-commitment path than the button pair. Ours
                points at the CLI reference rather than anything invented. */}
            <Reveal delay={360}>
              <a
                href={`${base}reference/cli-commands/`}
                className="inline-flex items-center gap-1.5 text-sm text-label underline underline-offset-4 hover:text-accent"
              >
                Browse the CLI reference
                <span aria-hidden="true">&rarr;</span>
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
            <div className="mx-auto w-full max-w-[18rem] sm:max-w-[22rem] lg:max-w-none">
              <HeroStackDiagram />
            </div>
          </Reveal>
        </div>
      </div>
    </section>
  );
}
