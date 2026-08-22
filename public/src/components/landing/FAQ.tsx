import { Section } from "./primitives/Section";
import { Eyebrow } from "./primitives/Eyebrow";
import { Reveal } from "./primitives/Reveal";

// Every answer here is traceable to a doc or to code — noted inline as a
// comment, not shown on the page. An FAQ is where confident-sounding
// invention is easiest and most damaging, so nothing here is written from
// memory of what a product "probably" does.
const FAQ_ITEMS: Array<{ q: string; a: string }> = [
  {
    q: "Why not just use a container?",
    // Source: README.md, "Every machine boots its own Linux kernel under a
    // real hypervisor... no guest network device at all — on any workload
    // backend."
    a: "A container is namespaces and cgroups around processes that still call straight into the host kernel — one kernel, shared by everything on the box. Every mvm workload boots its own Linux kernel under a real hypervisor, with no guest network device on any backend. The isolation is hardware-assisted, not namespace-assisted.",
  },
  {
    q: "Which languages are supported?",
    // Source: public/src/content/docs/sdk/index.md ("Runtime SDK" /
    // "Decorator SDK" table) and README.md Highlights ("SDKs for Python,
    // TypeScript, and Rust").
    a: "The CLI (mvmctl) drives any workload from a shell. The decorator SDK, for declaring workloads in source, is available for Python and TypeScript. The runtime SDK, for driving a sandbox imperatively, is partial in Python and TypeScript today; a Rust lifecycle client is planned, not shipped.",
  },
  {
    q: "Is it open source?",
    // Source: LICENSE (Apache License 2.0) and Cargo.toml
    // (`license = "Apache-2.0"`, `repository = "https://github.com/tinylabscom/mvm"`).
    a: "Yes — Apache-2.0, source at github.com/tinylabscom/mvm.",
  },
  {
    q: "What does it run on?",
    // Source: README.md backend table.
    a: "macOS 13–25 on libkrun, macOS 26+ Apple Silicon on the in-house HVF backend, and Linux with /dev/kvm on Firecracker. mvmctl reads your OS, chip, and macOS version and picks one for you.",
  },
  {
    q: "What is the security posture?",
    // Source: README.md ("Security claims, CI-enforced — 15+ numbered
    // claims...") and public/src/content/docs/security/threat-model.md
    // (protected assets, trusted computing base, non-goals).
    a: "Fifteen-plus numbered claims, each backed by a named test or CI job — not adjectives in a doc. The host itself is trusted; a malicious host, mutually distrusting guests in one VM, and hardware key attestation are explicitly out of scope.",
  },
];

export function FAQ() {
  return (
    <Section rule space="tight">
      <div className="grid gap-8 lg:grid-cols-[minmax(0,0.6fr)_minmax(0,1.4fr)] lg:gap-16">
        {/* Left: small label + the word. */}
        <div className="lg:sticky lg:top-32 lg:self-start">
          <Reveal>
            <Eyebrow>Questions worth asking</Eyebrow>
            <h2 className="lowercase font-display tracking-tight text-3xl font-semibold leading-tight text-title sm:text-4xl">
              faq
            </h2>
          </Reveal>
        </div>

        {/* Right: the accordion. */}
        <div className="divide-y divide-edge/30 border-t border-edge/30">
          {FAQ_ITEMS.map((item, i) => (
            <Reveal key={item.q} delay={i * 40}>
              {/* First row open by default so the section doesn't close the
                  page on a stack of unanswered questions — and the first
                  question is the one most readers actually arrive with. */}
              <details className="group py-5" open={i === 0}>
                <summary className="flex cursor-pointer list-none items-start justify-between gap-4 text-base font-semibold leading-snug text-title marker:content-none">
                  {item.q}
                  <span
                    className="mt-0.5 shrink-0 font-mono text-label transition-transform group-open:rotate-45"
                    aria-hidden="true"
                  >
                    +
                  </span>
                </summary>
                <p className="mt-3 max-w-xl text-sm leading-relaxed text-body">{item.a}</p>
              </details>
            </Reveal>
          ))}
        </div>
      </div>
    </Section>
  );
}
