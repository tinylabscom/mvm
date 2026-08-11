import { useRef } from "react";
import { cn } from "@/lib/utils";

// Do not nest a GlowCard inside another interactive element (link/button):
// the pointer handler and hover styling assume it owns its own hit area.
// It sets a `--glow` custom property on its root — consumers must not
// override that property on the same element.
export function GlowCard({
  accent = 1,
  className,
  children,
}: {
  accent?: 1 | 2 | 3;
  className?: string;
  children: React.ReactNode;
}) {
  const ref = useRef<HTMLDivElement>(null);

  // Cursor tracking is pure decoration, so it is skipped entirely rather
  // than merely shortened when the user asks for reduced motion.
  function onPointerMove(e: React.PointerEvent<HTMLDivElement>) {
    const el = ref.current;
    if (!el) return;
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    const r = el.getBoundingClientRect();
    el.style.setProperty("--mx", `${e.clientX - r.left}px`);
    el.style.setProperty("--my", `${e.clientY - r.top}px`);
  }

  return (
    <div
      ref={ref}
      onPointerMove={onPointerMove}
      className={cn(
        "site-glow-card group relative overflow-hidden rounded-xl border border-glass-border/60 bg-raised p-6 transition-colors",
        className,
      )}
      style={{ "--glow": `var(--color-glow-${accent})` } as React.CSSProperties}
    >
      <div
        className="site-glow-card__sheen pointer-events-none absolute inset-0 opacity-0 transition-opacity group-hover:opacity-100"
        aria-hidden="true"
      />
      <div className="relative">{children}</div>
    </div>
  );
}
