import { useState } from "react";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "../ui/tabs";

// The platform-specific install affordance — the one-liner plus the WSL2
// tab. This lived in the hero (as its single install affordance) until the
// pitch-script reshape; it now renders inside Quickstart so the landing
// page's story runs before the install command does.
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

export function InstallTabs() {
  const rawBase = import.meta.env.BASE_URL;
  const base = rawBase.endsWith("/") ? rawBase : `${rawBase}/`;

  return (
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
  );
}
