import { useState } from "react";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";

export function Hero() {
  const base = import.meta.env.BASE_URL;
  const [copied, setCopied] = useState(false);
  const installCmd = "curl -fsSL https://raw.githubusercontent.com/auser/mvm/main/install.sh | sh";

  function copyInstall() {
    navigator.clipboard.writeText(installCmd);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <section className="mx-auto flex max-w-4xl flex-col items-center gap-10 px-6 py-28 text-center sm:px-8 lg:py-36">
      <div className="flex flex-wrap justify-center gap-3">
        <Badge>
          <span className="inline-block h-2 w-2 rounded-full bg-rust" />
          Rust
        </Badge>
        <Badge>
          <span className="inline-block h-2 w-2 rounded-full bg-nix" />
          Nix Flakes
        </Badge>
        <Badge>
          <span className="inline-block h-2 w-2 rounded-full bg-green" />
          Apache 2.0
        </Badge>
      </div>

      <h1 className="max-w-3xl text-4xl font-bold leading-tight tracking-tight text-heading sm:text-5xl lg:text-6xl">
        MicroVMs,{" "}
        <span className="text-accent">Made Simple</span>
      </h1>

      <p className="max-w-2xl text-lg leading-relaxed text-muted sm:text-xl">
        Build and run microVMs on macOS and Linux with reproducible
        Nix flakes. Sub-5s boot. No SSH. No containers.
      </p>

      <div
        className="flex w-full max-w-xl cursor-pointer items-center gap-3 rounded-lg border border-border bg-surface px-5 py-3.5"
        onClick={copyInstall}
        title="Click to copy"
      >
        <code className="flex-1 text-left font-mono text-sm text-green overflow-x-auto">
          {installCmd}
        </code>
        <span className="shrink-0 text-xs text-muted">
          {copied ? "Copied!" : "Copy"}
        </span>
      </div>

      <div className="flex flex-wrap justify-center gap-4">
        <a href={`${base}/getting-started/installation/`}>
          <Button size="lg">Get Started</Button>
        </a>
        <a href="https://github.com/auser/mvm" target="_blank" rel="noopener">
          <Button variant="outline" size="lg">
            GitHub
          </Button>
        </a>
      </div>
    </section>
  );
}
