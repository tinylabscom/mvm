import { useEffect, useRef, useState } from "react";
import { Section } from "./primitives/Section";
import { Eyebrow } from "./primitives/Eyebrow";
import { CodeBlock } from "../ui/code-block";
import { SAMPLES } from "./samples";

const STEPS = [
  {
    id: "walk-define",
    title: "Define the workload",
    body: "A decorator marks the entrypoint. Nothing runs on your host — the file is parsed statically.",
  },
  {
    id: "walk-build",
    title: "Build the image",
    body: "mvmctl build compile walks the file's AST and emits a Nix flake; the actual build then runs inside the builder VM.",
  },
  {
    id: "walk-run",
    title: "Run it",
    body: "The compiled flake boots as a real microVM with its own kernel, and the entrypoint is dispatched over vsock.",
  },
  {
    id: "walk-result",
    title: "Read the result",
    body: "The entrypoint's return value comes back as the command's output.",
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

  const sample = (id: string) => SAMPLES.find((s) => s.id === id)!;

  return (
    <Section rule>
      <Eyebrow n="03">How it works</Eyebrow>
      <h2 className="mb-16 font-display text-3xl font-bold text-title sm:text-4xl">
        From a file to a running microVM
      </h2>

      {/* Scroll-synced layout, hidden when motion is reduced. */}
      <div className="site-walk grid gap-12 lg:grid-cols-2">
        <div className="flex flex-col gap-[40vh]">
          {STEPS.map((s, i) => (
            <div
              key={s.id}
              data-i={i}
              ref={(el) => {
                refs.current[i] = el;
              }}
              className={`transition-opacity duration-500 ${active === i ? "opacity-100" : "opacity-40"}`}
            >
              <Eyebrow n={String(i + 1).padStart(2, "0")}>{s.title}</Eyebrow>
              <p className="max-w-md text-lg leading-relaxed text-body">{s.body}</p>
            </div>
          ))}
        </div>
        <div className="hidden lg:block">
          <div className="sticky top-32">
            <CodeBlock code={sample(STEPS[active].id).code} language={sample(STEPS[active].id).language} />
          </div>
        </div>
      </div>

      {/* Stacked fallback: reduced motion, and every viewport below lg. */}
      <div className="site-walk-static flex flex-col gap-12 lg:hidden">
        {STEPS.map((s, i) => (
          <div key={s.id}>
            <Eyebrow n={String(i + 1).padStart(2, "0")}>{s.title}</Eyebrow>
            <p className="mb-4 max-w-md text-lg leading-relaxed text-body">{s.body}</p>
            <CodeBlock code={sample(s.id).code} language={sample(s.id).language} />
          </div>
        ))}
      </div>
    </Section>
  );
}
