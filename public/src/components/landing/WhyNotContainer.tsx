import { Section } from "./primitives/Section";
import { Eyebrow } from "./primitives/Eyebrow";
import { Reveal } from "./primitives/Reveal";
import { KernelCompareDiagram } from "./KernelCompareDiagram";

// The argument the page has never made. Kept short and technical, and
// deliberately not comparative-in-tone: a container shares the host
// kernel, this doesn't, state that and let the reader draw the
// conclusion rather than telling them containers are unsafe.
export function WhyNotContainer() {
  return (
    <Section rule space="tight">
      <Eyebrow>The boundary</Eyebrow>
      <h2 className="mb-3 lowercase font-display text-2xl font-bold leading-tight text-title sm:text-3xl">
        Why Not A Container
      </h2>
      <p className="mb-4 max-w-2xl text-base leading-relaxed text-body">
        A container is namespaces and cgroups around a process — the
        syscalls still land on the host kernel, and every container on the
        box shares that same kernel.
      </p>
      <p className="mb-10 max-w-2xl text-base leading-relaxed text-body">
        An mvm workload boots its own guest kernel under a real hypervisor,
        on its own root filesystem, with no guest network device on any
        backend. Same hardware, same host kernel underneath &mdash; one
        extra layer, and a hardware-assisted boundary instead of a shared
        one.
      </p>

      <Reveal>
        <KernelCompareDiagram />
      </Reveal>
    </Section>
  );
}
