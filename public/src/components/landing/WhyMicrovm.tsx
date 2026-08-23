import { Section } from "./primitives/Section";
import { Eyebrow } from "./primitives/Eyebrow";
import { Reveal } from "./primitives/Reveal";
import { ContainmentDiagram } from "./ContainmentDiagram";

// The positive case for the boundary, made once instead of twice: state
// what a microVM gives you and let the containment figure carry the
// "layered, not shared" idea rather than spelling out what it isn't. No
// side-by-side, no "them vs us" comparison panel.
const GIVES_YOU = [
  { label: "its own Linux kernel", detail: "booted fresh, under a real hypervisor" },
  { label: "its own root filesystem", detail: "not a view onto the host's" },
  { label: "no network device", detail: "on any backend — HVF, libkrun, Firecracker" },
  { label: "one channel out", detail: "vsock, deny-all until policy admits it" },
];

export function WhyMicrovm() {
  return (
    <Section rule space="tight">
      <div className="grid gap-10 lg:grid-cols-2 lg:items-center lg:gap-14">
        <div>
          <Eyebrow>The boundary</Eyebrow>
          {/* Inline margins, not margin utilities: Starlight's unlayered
              stylesheet beats layered utilities on this page (see
              Positioning.tsx). */}
          <h2
            className="lowercase font-display tracking-tight text-2xl font-semibold leading-tight text-title sm:text-3xl"
            style={{ marginBottom: "1.5rem" }}
          >
            Why A MicroVM
          </h2>
          <p className="max-w-md text-base leading-relaxed text-body">
            Every mvm workload boots its own guest kernel under a real
            hypervisor, on its own root filesystem &mdash; a hardware-assisted
            boundary, not a shared one.
          </p>
          <ul className="space-y-3" style={{ marginTop: "2.5rem" }}>
            {GIVES_YOU.map((item) => (
              <li key={item.label} className="flex gap-3 text-sm leading-relaxed text-body">
                <span className="mt-2 h-1.5 w-1.5 shrink-0 rounded-full bg-accent-3" aria-hidden="true" />
                <span>
                  <span className="font-mono font-semibold text-emphasis">{item.label}</span>
                  {" — "}
                  {item.detail}
                </span>
              </li>
            ))}
          </ul>
        </div>

        <Reveal className="mx-auto w-full max-w-[18rem] sm:max-w-[22rem] lg:max-w-none">
          <ContainmentDiagram />
        </Reveal>
      </div>
    </Section>
  );
}
