import { useState, useEffect } from "react";
import { Button } from "../ui/button";

const lines = [
  { text: "$ mvmctl dev", delay: 0 },
  { text: "  Detecting platform... macOS (Apple Silicon)", delay: 800, dim: true },
  { text: "  Backend: firecracker (via Lima)", delay: 1400, dim: true },
  { text: "  Ready.", delay: 2000, accent: true },
  { text: "", delay: 2400 },
  { text: "$ mvmctl build --flake .", delay: 2800 },
  { text: "  Building rootfs via Nix...", delay: 3400, dim: true },
  { text: "  rootfs: 48.2 MB (squashfs)", delay: 4000, accent: true },
  { text: "", delay: 4400 },
  { text: "$ mvmctl up --flake . --cpus 2", delay: 4800 },
  { text: "  Booted in 1.2s. Health: OK", delay: 5400, accent: true },
];

function TerminalAnimation() {
  const [visibleLines, setVisibleLines] = useState(0);

  useEffect(() => {
    const timers = lines.map((line, i) =>
      setTimeout(() => setVisibleLines(i + 1), line.delay)
    );
    return () => timers.forEach(clearTimeout);
  }, []);

  return (
    <div className="w-full overflow-hidden rounded-xl border border-edge/60 bg-[#0a0e14] shadow-2xl shadow-black/40">
      <div className="flex items-center gap-2 border-b border-edge/40 px-4 py-3">
        <span className="h-3 w-3 rounded-full bg-[#ff5f57]/80" />
        <span className="h-3 w-3 rounded-full bg-[#febc2e]/80" />
        <span className="h-3 w-3 rounded-full bg-[#28c840]/80" />
        <span className="ml-3 text-xs text-label/60">terminal</span>
      </div>
      <div className="p-5 font-mono text-[13px] leading-relaxed sm:p-6">
        {lines.slice(0, visibleLines).map((line, i) => (
          <div
            key={i}
            className={`${
              line.accent
                ? "text-green"
                : line.dim
                  ? "text-label/60"
                  : "text-heading"
            } ${line.text === "" ? "h-3" : ""}`}
          >
            {line.text}
          </div>
        ))}
        {visibleLines < lines.length && (
          <span className="inline-block h-4 w-2 animate-pulse bg-accent/70" />
        )}
      </div>
    </div>
  );
}

const stats = [
  { value: "<2s", label: "snapshot boot" },
  { value: "~50MB", label: "rootfs images" },
  { value: "0", label: "SSH required" },
];

export function Hero() {
  const rawBase = import.meta.env.BASE_URL;
  const base = rawBase.endsWith("/") ? rawBase : `${rawBase}/`;
  const [copied, setCopied] = useState(false);
  const installCmd =
    "curl -fsSL https://raw.githubusercontent.com/auser/mvm/main/install.sh | sh";

  function copyInstall() {
    navigator.clipboard.writeText(installCmd);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <section className="relative overflow-hidden">
      {/* Background glow */}
      <div className="pointer-events-none absolute inset-0">
        <div className="absolute left-1/2 top-0 h-[600px] w-[900px] -translate-x-1/2 -translate-y-1/4 rounded-full bg-accent/7 blur-[120px]" />
        <div className="absolute right-0 top-1/3 h-[400px] w-[400px] rounded-full bg-nix/5 blur-[100px]" />
      </div>

      <div className="relative mx-auto max-w-7xl px-6 pt-28 pb-24 sm:px-8 lg:pt-40 lg:pb-32">
        <div className="grid items-center gap-16 lg:grid-cols-2 lg:gap-20">
          {/* Left — copy */}
          <div className="flex flex-col gap-8">
            <div className="flex items-center gap-2">
              <span className="inline-block h-2 w-2 rounded-full bg-green animate-pulse" />
              <span className="text-sm font-medium text-green">v0.7 — Multi-backend VM support</span>
            </div>

            <h1 className="text-4xl font-bold leading-[1.1] tracking-tight text-title sm:text-5xl xl:text-6xl">
              Firecracker microVMs,
              <br />
              <span className="bg-linear-to-r from-accent via-nix to-accent bg-clip-text text-transparent">
                without the toil.
              </span>
            </h1>

            <p className="max-w-lg text-lg leading-relaxed text-body">
              Build reproducible VM images with Nix. Boot them in under 2 seconds
              on macOS or Linux. No SSH. No containers. Just workloads.
            </p>

            {/* Install command */}
            <div
              className="group flex w-full max-w-lg cursor-pointer items-center gap-3 rounded-lg border border-edge/50 bg-raised/80 px-5 py-3.5 backdrop-blur transition-all hover:border-accent/30"
              onClick={copyInstall}
              title="Click to copy"
            >
              <span className="text-accent/60 text-sm">$</span>
              <code className="flex-1 text-left font-mono text-sm text-emphasis/90 overflow-x-auto">
                {installCmd}
              </code>
              <span className="shrink-0 rounded border border-edge/50 px-2 py-0.5 text-[11px] text-label transition-colors group-hover:border-accent/30 group-hover:text-accent">
                {copied ? "Copied!" : "Copy"}
              </span>
            </div>

            <div className="flex flex-wrap gap-3">
              <a href={`${base}getting-started/installation/`}>
                <Button size="lg">Get Started</Button>
              </a>
              <a
                href="https://github.com/auser/mvm"
                target="_blank"
                rel="noopener"
              >
                <Button variant="outline" size="lg">
                  GitHub
                </Button>
              </a>
            </div>

            {/* Stats row */}
            <div className="flex flex-wrap gap-8 border-t border-edge/40 pt-6">
              {stats.map((s) => (
                <div key={s.label} className="flex flex-col">
                  <span className="text-2xl font-bold text-title">{s.value}</span>
                  <span className="text-xs text-label">{s.label}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Right — terminal */}
          <div className="relative">
            <div className="pointer-events-none absolute -inset-4 rounded-2xl bg-linear-to-br from-accent/10 via-transparent to-nix/10 blur-xl" />
            <TerminalAnimation />
          </div>
        </div>
      </div>
    </section>
  );
}
