import { cn } from "@/lib/utils";

// Named vertical-rhythm values, not an open scale — a page where every
// section picks its own padding drifts back to the uniform-`py-24` tell
// this replaces. "normal" is the old uniform default; "tight" is for
// narrow editorial sections that shouldn't compete with the hero; "roomy"
// is reserved for the one full-bleed band that should read as more
// spacious than its neighbours.
const SPACE = {
  tight: "py-16 lg:py-20",
  normal: "py-24 lg:py-32",
  roomy: "py-28 lg:py-40",
} as const;

export function Section({
  id,
  rule = false,
  space = "normal",
  className,
  children,
}: {
  id?: string;
  rule?: boolean;
  space?: keyof typeof SPACE;
  className?: string;
  children: React.ReactNode;
}) {
  return (
    <section
      id={id}
      className={cn(
        "relative w-full px-6 sm:px-8",
        SPACE[space],
        rule && "border-t border-edge/60",
        className,
      )}
    >
      <div className="relative mx-auto max-w-6xl">{children}</div>
    </section>
  );
}
