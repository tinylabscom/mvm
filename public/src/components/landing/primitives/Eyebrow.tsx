import { cn } from "@/lib/utils";

export function Eyebrow({
  n,
  className,
  children,
}: {
  n?: string;
  className?: string;
  children: React.ReactNode;
}) {
  return (
    <p className={cn("mb-3 font-mono text-xs tracking-[0.2em] uppercase text-label", className)}>
      {n && <span className="text-accent">{n}</span>}
      {n && <span className="mx-2 text-dim">—</span>}
      {children}
    </p>
  );
}
