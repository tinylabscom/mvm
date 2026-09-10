import { Backends } from "./Backends";
import { DeploymentTiers } from "./DeploymentTiers";
import { Eyebrow } from "./primitives/Eyebrow";
import { FAQ } from "./FAQ";
import { Footer } from "./Footer";
import { LaunchPerf } from "./LaunchPerf";
import { Reveal } from "./primitives/Reveal";
import { WhyMicrovm } from "./WhyMicrovm";

// The evidence page. The landing page (Landing.tsx) tells the pitch story
// — one beat per section — and links here from the contract section and
// the header nav. This page holds the mechanism sections for the visitor
// who is already interested and is now evaluating: why a microVM and not
// a container, what booting one costs, where the same contract runs, and
// the backends underneath. These sections lived on the landing page until
// the pitch-script reshape; they moved here unchanged, so their internal
// comments (and check-perf-provenance.mjs's gating of LaunchPerf's
// numbers) still apply.
export function HowItWorks() {
  return (
    <div className="min-h-screen w-full bg-canvas">
      {/* Compact intro — an h1 (the Starlight page skips PageTitle via
          `hero: {}`, so this is the page's only h1) and one framing
          paragraph; the moved sections carry the content. */}
      <section className="relative w-full px-6 pt-24 pb-12 sm:px-8 sm:pt-20 lg:pt-24">
        <div className="relative mx-auto max-w-6xl border-x border-edge/15">
          <Reveal>
            <Eyebrow>Under the hood</Eyebrow>
            <h1
              className="max-w-2xl lowercase font-display font-semibold leading-[1.05] tracking-[-0.03em] text-title"
              style={{ fontSize: "clamp(2.2rem, 4vw, 3.2rem)" }}
            >
              how it works
            </h1>
          </Reveal>
        </div>
      </section>

      <WhyMicrovm />
      <LaunchPerf />
      <DeploymentTiers />
      <Backends />
      <FAQ />
      <Footer />
    </div>
  );
}
