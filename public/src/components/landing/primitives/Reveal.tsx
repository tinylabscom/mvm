interface RevealProps {
  delay?: number;
  className?: string;
  children: React.ReactNode;
}

export function Reveal({ className, children }: RevealProps) {
  return <div className={className}>{children}</div>;
}
