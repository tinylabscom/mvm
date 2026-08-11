import { useEffect, useRef, useState } from "react";
import { Section } from "./primitives/Section";
import { CodeBlock } from "../ui/code-block";
import { SAMPLES } from "./samples";

const TERMINAL_LINES = [
  { text: '$ mvmctl machine run --image python:3.12 -- \\', delay: 0 },
  { text: '  python -c "print(2 + 2)"', delay: 500 },
  { text: "  Pulling image and preparing a private root...", delay: 1200, dim: true },
  { text: "  Booted. Own kernel. Network: deny-all.", delay: 2500, accent: true },
  { text: "  Warm microVM start: milliseconds.", delay: 3100, accent: true },
  { text: "  4", delay: 4200 },
];

// Relocated from the hero (Plan: the boundary diagram took the identity
// slot there) into the "Run it" step, where the command it plays out
// actually belongs narratively.
function TerminalAnimation() {
  const [visibleLines, setVisibleLines] = useState(0);

  useEffect(() => {
    const timers = TERMINAL_LINES.map((line, i) =>
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
        {TERMINAL_LINES.slice(0, visibleLines).map((line, i) => (
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
        {visibleLines < TERMINAL_LINES.length ? (
          <span
            className="site-terminal-cursor inline-block h-4 w-2 animate-pulse bg-accent/70"
            aria-hidden="true"
          />
        ) : (
          <div className="flex items-center gap-2 text-code-text">
            <span className="text-accent">$</span>
            <span
              className="site-terminal-cursor inline-block h-4 w-2 animate-pulse bg-accent/70"
              aria-hidden="true"
            />
          </div>
        )}
      </div>
    </div>
  );
}

const STEPS = [
  {
    id: "walk-define",
    title: "Define the workload",
    body: "A decorator marks the entrypoint. mvmctl parses the file statically — none of it executes on your host.",
  },
  {
    id: "walk-build",
    title: "Build the image",
    body: "mvmctl build compile turns the file into a Nix flake. The build itself runs inside the builder VM, not on your host.",
  },
  {
    id: "walk-run",
    title: "Run it",
    body: "mvmctl machine run --entrypoint boots the flake and calls the function directly.",
  },
  {
    id: "walk-result",
    title: "Read the result",
    body: "The function's return value is the command's output.",
  },
];

export function Walkthrough() {
  const [active, setActive] = useState(0);
  const refs = useRef<Array<HTMLDivElement | null>>([]);

  useEffect(() => {
    // Reduced motion gets the stacked fallback rendered below instead, so
    // there is no observer to run at all.
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    const io = new IntersectionObserver(
      (entries) => {
        for (const e of entries) {
          if (e.isIntersecting) setActive(Number((e.target as HTMLElement).dataset.i));
        }
      },
      { rootMargin: "-45% 0px -45% 0px" },
    );
    refs.current.forEach((el) => el && io.observe(el));
    return () => io.disconnect();
  }, []);

  // Returns undefined on a typo'd/missing id rather than throwing, so a
  // bad sample id degrades to "no code block for this step" instead of
  // taking the whole island down.
  const sample = (id: string) => SAMPLES.find((s) => s.id === id);
  const activeSample = sample(STEPS[active].id);

  return (
    <Section rule space="tight">
      <h2 className="mb-12 lowercase font-display text-2xl font-bold leading-tight text-title sm:text-3xl">
        From file to running microVM
      </h2>

      {/* Scroll-synced layout, hidden when motion is reduced. */}
      <div className="site-walk grid gap-12 lg:grid-cols-2">
        <div className="flex max-w-[52ch] flex-col gap-[26vh]">
          {STEPS.map((s, i) => (
            <div
              key={s.id}
              data-i={i}
              ref={(el) => {
                refs.current[i] = el;
              }}
              className={`transition-opacity duration-500 ${active === i ? "opacity-100" : "opacity-65"}`}
            >
              <h3 className="mb-3 font-mono text-xs tracking-[0.2em] uppercase text-accent">
                Step {i + 1}
              </h3>
              <p className="mb-1 text-lg font-semibold text-title">{s.title}</p>
              <p className="text-lg leading-relaxed text-body">{s.body}</p>
            </div>
          ))}
        </div>
        <div className="hidden lg:block">
          <div className="sticky top-32">
            {STEPS[active].id === "walk-run" ? (
              <TerminalAnimation />
            ) : (
              activeSample && (
                <CodeBlock code={activeSample.code} language={activeSample.language} />
              )
            )}
          </div>
        </div>
      </div>

      {/* Stacked fallback: reduced motion, and every viewport below lg. */}
      <div className="site-walk-static flex flex-col gap-12 lg:hidden">
        {STEPS.map((s, i) => {
          const stepSample = sample(s.id);
          return (
            <div key={s.id}>
              <h3 className="mb-3 font-mono text-xs tracking-[0.2em] uppercase text-accent">
                Step {i + 1}
              </h3>
              <p className="mb-1 text-lg font-semibold text-title">{s.title}</p>
              <p className="mb-4 max-w-md text-lg leading-relaxed text-body">{s.body}</p>
              {s.id === "walk-run" ? (
                <TerminalAnimation />
              ) : (
                stepSample && (
                  <CodeBlock code={stepSample.code} language={stepSample.language} />
                )
              )}
            </div>
          );
        })}
      </div>
    </Section>
  );
}
