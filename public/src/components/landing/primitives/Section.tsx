import { cn } from "@/lib/utils";

export function Section({
  id,
  rule = false,
  className,
  children,
}: {
  id?: string;
  rule?: boolean;
  className?: string;
  children: React.ReactNode;
}) {
  return (
    <section
      id={id}
      className={cn(
        "relative w-full px-6 py-24 sm:px-8 lg:py-32",
        rule && "border-t border-edge/60",
        className,
      )}
    >
      <div className="relative mx-auto max-w-6xl">{children}</div>
    </section>
  );
}
