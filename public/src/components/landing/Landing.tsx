import { useEffect } from "react";
import { Backends } from "./Backends";
import { ExecutionContract } from "./ExecutionContract";
import { Hero } from "./Hero";
import { Quickstart } from "./Quickstart";
import { DemoTeaser } from "./DemoTeaser";
import { DeploymentTiers } from "./DeploymentTiers";
import { Positioning } from "./Positioning";
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
//   3. Quickstart       — the shortest path from install to a running microVM.
//   4b. Execution contract — the composition argument: isolation is table
//                         stakes, the six-layer contract around the box is
//                         the differentiator. Placed before Positioning so
//                         the reader knows what they're buying before the
//                         tour of how to drive it.
//   5. Positioning      — "one project, three ways to drive it": CLI,
//                         Declare, Runtime, each given its own row.
//   6. Why a microVM      — the positive case for the boundary, made once.
//                         Placed right after Positioning: the reader has
//                         just seen how you *use* mvm, so this is where
//                         "here's what you're actually getting" lands
//                         hardest.
//   6a. Deployment tiers — "one contract, four places to run it": the
//                         product-site tier grid (local / hosted / edge /
//                         confidential), after the case for the boundary
//                         is made.
//   6b. Backends          — "the backend is an implementation detail": the
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
      <Quickstart />
      <ExecutionContract />
      <Positioning />
      <WhyMicrovm />
      <DeploymentTiers />
      <Backends />
      <FAQ />
      <RequestAccess />
      <CTABanner />
      <Footer />
    </div>
  );
}
