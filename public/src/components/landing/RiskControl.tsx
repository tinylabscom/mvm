import { Section } from "./primitives/Section";
import { Eyebrow } from "./primitives/Eyebrow";
import { Reveal } from "./primitives/Reveal";

// Operator controls: machine start/stop and the chain-signed audit log
// verified via `mvmctl trust audit verify`.
const CONTROLS = [
  {
    label: "Lifecycle",
    title: "Stop a running workload",
    body: "Start a workload when you need it. Stop it when you're done or need to cut a run short.",
  },
  {
    label: "Audit log",
    title: "Review execution records",
    body: "Look back through a run's recorded activity to investigate what happened.",
  },
  {
    label: "Verification",
    title: "Check for tampering",
    body: "Verify the record's digital signatures to check whether it has been changed.",
  },
];

export function RiskControl() {
  const rawBase = import.meta.env.BASE_URL;
  const base = rawBase.endsWith("/") ? rawBase : `${rawBase}/`;

  return (
    <Section id="risk-control" rule className="bg-raised">
      <Reveal>
        <Eyebrow>Operations</Eyebrow>
        {/* Inline margins, not margin utilities: Starlight's unlayered
            stylesheet beats layered utilities on this page (see
            Positioning.tsx). */}
        <h2
          className="lowercase font-display text-2xl font-bold leading-tight text-title sm:text-3xl"
          style={{ marginBottom: "1.5rem" }}
        >
          Stop workloads.{" "}
          <span className="text-accent-2">Review what ran.</span>
        </h2>
        <p className="max-w-2xl text-base leading-relaxed text-body">
          Control when workloads run and review their recorded activity
          afterward.
        </p>
      </Reveal>

      <div
        className="grid gap-4 sm:grid-cols-3"
        style={{ marginTop: "2.5rem" }}
      >
        {CONTROLS.map((item, i) => (
          <Reveal key={item.label} delay={i * 80}>
            <div className="h-full rounded-xl border border-glass-border/60 bg-canvas p-5">
              <p className="mb-2 font-mono text-[11px] font-semibold tracking-[0.14em] uppercase text-accent">
                {item.label}
              </p>
              <h3 className="mb-1.5 text-base font-semibold leading-snug text-title">
                {item.title}
              </h3>
              <p className="text-sm leading-relaxed text-body">{item.body}</p>
            </div>
          </Reveal>
        ))}
      </div>

      <Reveal delay={240}>
        <div
          className="flex flex-wrap gap-x-6 gap-y-2"
          style={{ marginTop: "2rem" }}
        >
          <a
            href={`${base}working/sandbox-management/`}
            className="text-sm text-accent underline underline-offset-2 hover:text-accent/80"
          >
            Managing running workloads
          </a>
          <a
            href={`${base}security/claim-ledger/`}
            className="text-sm text-accent underline underline-offset-2 hover:text-accent/80"
          >
            What the audit chain records
          </a>
        </div>
      </Reveal>
    </Section>
  );
}
