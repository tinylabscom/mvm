import { cn } from "@/lib/utils";

export function Bloom({
  accents = [1, 2],
  className,
}: {
  accents?: Array<1 | 2 | 3>;
  className?: string;
}) {
  return (
    <div className={cn("pointer-events-none absolute inset-0 overflow-hidden", className)} aria-hidden="true">
      {accents.map((a, i) => (
        <div
          key={a}
          className={cn(
            "site-bloom absolute rounded-full blur-[120px]",
            // Centring uses left+margin, not a translate utility: the drift
            // animation owns `transform` and would otherwise cancel it.
            i === 0 ? "left-1/2 top-0 ml-[-26rem] mt-[-9rem] h-[36rem] w-[52rem]" : "right-0 top-1/3 h-[26rem] w-[26rem]",
          )}
          style={{ background: `var(--color-glow-${a})`, animationDelay: `${i * -8}s` }}
        />
      ))}
    </div>
  );
}
