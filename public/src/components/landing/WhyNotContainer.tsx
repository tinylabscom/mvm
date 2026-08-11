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
        A container is a set of Linux namespaces and cgroups around
        processes that still make syscalls straight into the host kernel.
        That kernel is one thing every container on the box shares — a
        kernel bug or a namespace escape reaches the host.
      </p>
      <p className="mb-10 max-w-2xl text-base leading-relaxed text-body">
        A microVM doesn&rsquo;t share it. Every workload mvm runs boots its
        own Linux kernel under a real hypervisor, with its own root
        filesystem and, on every backend, no guest network device at all
        &mdash; the isolation is hardware-assisted, not namespace-assisted.
      </p>

      <Reveal>
        <KernelCompareDiagram />
      </Reveal>
    </Section>
  );
}
