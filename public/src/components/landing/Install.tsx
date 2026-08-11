import { useState } from "react";
import { Section } from "./primitives/Section";
import { Eyebrow } from "./primitives/Eyebrow";
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

export function Install() {
  const rawBase = import.meta.env.BASE_URL;
  const base = rawBase.endsWith("/") ? rawBase : `${rawBase}/`;

  return (
    <Section rule>
      <Eyebrow n="01">Install</Eyebrow>
      <h2 className="mb-8 text-3xl font-bold text-title sm:text-4xl">
        Pick your platform
      </h2>

      <Tabs defaultValue="macos" className="max-w-2xl">
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
    </Section>
  );
}
