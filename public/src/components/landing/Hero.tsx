import { useState, useEffect } from "react";
import { Button } from "../ui/button";
import { Bloom } from "./primitives/Bloom";
import { Reveal } from "./primitives/Reveal";

const lines = [
  { text: '$ mvmctl machine run --image python:3.12 -- \\', delay: 0 },
  { text: '  python -c "print(2 + 2)"', delay: 500 },
  { text: "  Pulling image and preparing a private root...", delay: 1200, dim: true },
  { text: "  Booted. Own kernel. Network: deny-all.", delay: 2500, accent: true },
  { text: "  Warm microVM start: milliseconds.", delay: 3100, accent: true },
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
    <div className="w-full overflow-hidden rounded-xl border border-code-border bg-code-canvas shadow-2xl shadow-black/30">
      <div className="flex items-center gap-2 border-b border-code-border bg-code-header px-4 py-3">
        <span className="h-3 w-3 rounded-full bg-dot-close/80" />
        <span className="h-3 w-3 rounded-full bg-dot-minimize/80" />
        <span className="h-3 w-3 rounded-full bg-dot-expand/80" />
        <span className="ml-3 text-xs text-code-text/55">terminal</span>
      </div>
      <div className="p-5 font-mono text-[13px] leading-relaxed sm:p-6">
        {lines.slice(0, visibleLines).map((line, i) => (
          <div
            key={i}
            className={`${
              line.accent
                ? "text-code-success"
                : line.dim
                  ? "text-code-text/55"
                  : "text-code-text"
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
  { value: "ms", label: "warm microVM starts" },
  { value: "1", label: "kernel per workload" },
  { value: "0", label: "SSH or daemon" },
];

export function Hero() {
  const rawBase = import.meta.env.BASE_URL;
  const base = rawBase.endsWith("/") ? rawBase : `${rawBase}/`;
  const [copied, setCopied] = useState(false);
  const installCmd =
    "curl -fsSL https://raw.githubusercontent.com/tinylabscom/mvm/main/install.sh | sh";

  function copyInstall() {
    navigator.clipboard.writeText(installCmd);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <section className="relative overflow-hidden">
      {/* Background glow */}
      <Bloom accents={[1, 2]} />

      <div className="relative mx-auto max-w-7xl px-6 pt-28 pb-24 sm:px-8 lg:pt-40 lg:pb-32">
        <div className="grid items-center gap-16 lg:grid-cols-2 lg:gap-20">
          {/* Left — copy */}
          <div className="flex flex-col gap-8">
            <div className="flex items-center gap-2">
              <span className="inline-block h-2 w-2 rounded-full bg-green animate-pulse" />
              <span className="text-sm font-medium text-green">v0.7 — Multi-backend VM support</span>
            </div>

            <Reveal delay={0}>
              <h1 className="font-display text-5xl font-bold leading-[1.1] tracking-tight text-title sm:text-6xl xl:text-7xl">
                Local. A real microVM
                <br />
                <span className="bg-linear-to-r from-accent via-accent-2 to-accent-3 bg-clip-text text-transparent">
                  in milliseconds.
                </span>
              </h1>
            </Reveal>

            <Reveal delay={80}>
              <p className="max-w-lg text-lg leading-relaxed text-body">
                Run untrusted code behind a real hypervisor with one command. The
                first run prepares the image and kernel; warm runs start in
                milliseconds. No SSH. No daemon. No container fallback.
              </p>
            </Reveal>

            {/* Install command */}
            <Reveal delay={160}>
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
            </Reveal>

            <Reveal delay={240} className="flex flex-wrap gap-3">
              <a href={`${base}getting-started/installation/`}>
                <Button size="lg">Get Started</Button>
              </a>
              <a
                href="https://github.com/tinylabscom/mvm"
                target="_blank"
                rel="noopener"
              >
                <Button variant="outline" size="lg">
                  GitHub
                </Button>
              </a>
            </Reveal>

            {/* Stats row */}
            <Reveal delay={320} className="flex flex-wrap gap-8 border-t border-edge/40 pt-6">
              {stats.map((s) => (
                <div key={s.label} className="flex flex-col">
                  <span className="text-2xl font-bold text-title">{s.value}</span>
                  <span className="text-xs text-label">{s.label}</span>
                </div>
              ))}
            </Reveal>
          </div>

          {/* Right — terminal */}
          <div className="relative">
            <div className="pointer-events-none absolute -inset-4 rounded-2xl bg-linear-to-br from-glow-1 via-transparent to-glow-3 blur-xl" />
            <TerminalAnimation />
          </div>
        </div>
      </div>
    </section>
  );
}
