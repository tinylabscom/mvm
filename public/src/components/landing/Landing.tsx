import { useEffect } from "react";
import { Backends } from "./Backends";
import { ExecutionContract } from "./ExecutionContract";
import { Hero } from "./Hero";
import { LaunchPerf } from "./LaunchPerf";
import { Quickstart } from "./Quickstart";
import { DemoTeaser } from "./DemoTeaser";
import { DeploymentTiers } from "./DeploymentTiers";
// Positioning is hidden for now — restore its import alongside the
// commented-out <Positioning /> below.
// import { Positioning } from "./Positioning";
import { RequestAccess } from "./RequestAccess";
import { WhyNow } from "./WhyNow";
import { WhyMicrovm } from "./WhyMicrovm";
import { FAQ } from "./FAQ";
import { CTABanner } from "./CTABanner";
import { Footer } from "./Footer";

// Section order is the argument, not a menu:
//   1. Hero            — the claim, and the diagram that backs it.
//   2. Demo teaser      — browser sandbox, straight after the claim so a
//                         visitor can see governance behavior immediately,
//                         before installing anything.
//   2b. Why now          — the vibecoding-era narrative: AI writes and runs
//                         more of the code, review doesn't scale, so the
//                         runtime must assume the code is hostile. The
//                         emotional core; placed after the demo so the
//                         reader has just *seen* the governance the story
//                         argues for.
//   2c. Execution contract — the composition argument: isolation is table
//                         stakes, the six-layer contract around the box is
//                         the differentiator. Directly after the why-now
//                         story so the claim lands while the problem is
//                         fresh, before any how-to content.
//   3. Quickstart       — the shortest path from install to a running microVM.
//   5. Positioning      — "one project, three ways to drive it": CLI,
//                         Declare, Runtime, each given its own row.
//                         HIDDEN for now (commented out below), not removed.
//   6. Why a microVM      — the positive case for the boundary, made once.
//                         Placed right after Positioning: the reader has
//                         just seen how you *use* mvm, so this is where
//                         "here's what you're actually getting" lands
//                         hardest.
//   6a. Launch performance — the objection Why-a-microVM provokes, answered
//                         where it forms: a reader who has just been told
//                         every workload boots its own kernel under a real
//                         hypervisor is at that moment thinking "that must
//                         be slow". Budget-vs-measurement is drawn, not
//                         narrated — the arc is the ceiling CI enforces and
//                         the fill is what one fingerprinted host did.
//                         Numbers live in perf.ts and are gated against the
//                         performance page by check-perf-provenance.mjs.
//   6b. Deployment tiers — "one contract, four places to run it": the
//                         product-site tier grid (local / hosted / edge /
//                         confidential), after the case for the boundary
//                         is made.
//   6c. Backends          — "the backend is an implementation detail": the
//                         product-site backend/attestation grid, standing in
//                         where the Boundary panel used to make the
//                         backend-agnostic point.
//   9. FAQ              — leads with the container question a second time,
//                         for the reader who skimmed straight to the bottom.
//   9b. Request access   — the product-site design-partner form (#request-access,
//                         the hero's "Request access" button anchors here).
//   10. Close + footer   — one quiet ask, one quiet line.
// Do not reorder without re-reading reshape-brief.md and
// layout-match-report.md.
export function Landing() {
  // Marks that the client:load island actually mounted, so the CSS
  // failsafe (custom.css) can tell a live page apart from a hydration
  // failure instead of guessing off elapsed time.
  useEffect(() => {
    document.documentElement.classList.add("hydrated");
  }, []);

  return (
    <div className="min-h-screen w-full bg-canvas">
      <Hero />
      <DemoTeaser />
      <WhyNow />
      <ExecutionContract />
      <Quickstart />
      {/* Positioning ("one project. three ways to drive it.") is hidden for
          now, not deleted — restore by uncommenting here and re-adding its
          entry to the section-order comment above. */}
      {/* <Positioning /> */}
      <WhyMicrovm />
      <LaunchPerf />
      <DeploymentTiers />
      <Backends />
      <FAQ />
      <RequestAccess />
      <CTABanner />
      <Footer />
    </div>
  );
}
