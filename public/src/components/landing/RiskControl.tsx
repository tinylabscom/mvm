import { Section } from "./primitives/Section";
import { Eyebrow } from "./primitives/Eyebrow";
import { Reveal } from "./primitives/Reveal";

// Control for the people who own the risk: the one-pager's operator
// section. Builders get the contract; admins and security teams get the
// levers — start/stop, kill on violation, and the audit trail underneath.
// Everything named here is shipped surface: machine start/stop, and the
// chain-signed audit log verified via `mvmctl trust audit verify`.
const CONTROLS = [
  {
    label: "turn it off",
    title: "Workloads run at your pleasure",
    body: "Start and stop workloads on command. If something violates the contract, kill the box — it's gone.",
  },
  {
    label: "everything on the record",
    title: "Logging and traceability underneath it all",
    body: "Admission, launch, and every policy decision land in a chain-signed audit log. Tampering breaks the chain.",
  },
  {
    label: "proof on demand",
    title: "Evidence you can hand to compliance",
    body: "What ran, and what it was allowed to do — a verifiable record, not a claim. Check it with mvmctl trust audit verify.",
  },
];

export function RiskControl() {
  const rawBase = import.meta.env.BASE_URL;
  const base = rawBase.endsWith("/") ? rawBase : `${rawBase}/`;

  return (
    <Section id="risk-control" rule className="bg-raised">
      <Reveal>
        <Eyebrow>The operators</Eyebrow>
        {/* Inline margins, not margin utilities: Starlight's unlayered
            stylesheet beats layered utilities on this page (see
            Positioning.tsx). */}
        <h2
          className="lowercase font-display text-2xl font-bold leading-tight text-title sm:text-3xl"
          style={{ marginBottom: "1.5rem" }}
        >
          control for the people who{" "}
          <span className="text-accent-2">own the risk.</span>
        </h2>
        <p className="max-w-2xl text-base leading-relaxed text-body">
          Visibility and control aren&rsquo;t just for builders. The contract
          gives admins and security teams the levers &mdash; and the evidence
          trail underneath them.
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
            The audit chain, claim by claim
          </a>
        </div>
      </Reveal>
    </Section>
  );
}
