import { useEffect } from "react";
import { Hero } from "./Hero";
import { CredibilityStrip } from "./CredibilityStrip";
import { Quickstart } from "./Quickstart";
import { Positioning } from "./Positioning";
import { WhyNotContainer } from "./WhyNotContainer";
import { Boundary } from "./Boundary";
import { Security } from "./Security";
import { FAQ } from "./FAQ";
import { CTABanner } from "./CTABanner";
import { Footer } from "./Footer";

// Section order is the argument, not a menu:
//   1. Hero            — the claim, and the diagram that backs it.
//   2. Credibility      — "is this real?" answered in one glance.
//   3. Quickstart       — the shortest path from install to a running microVM.
//   4. Positioning      — "one project, three ways to drive it": CLI,
//                         Declare, Runtime, each given its own row.
//   5. Why not a container — the objection the page used to skip. Placed
//                         right after Positioning, before the boundary is
//                         quantified: the reader has just seen how you
//                         *use* mvm, so this is where "and here's what
//                         you're actually getting instead of a container"
//                         lands hardest — right before the boundary panel
//                         backs it with a figure.
//   6. Boundary panel   — the figure: one kernel per workload, regardless
//                         of which of the three backends resolved.
//   7. Trust            — named tests and CI jobs, not adjectives.
//   8. FAQ              — leads with the container question a second time,
//                         for the reader who skimmed straight to the bottom.
//   9. Close + footer   — one quiet ask, one quiet line.
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
      <CredibilityStrip />
      <Quickstart />
      <Positioning />
      <WhyNotContainer />
      <Boundary />
      <Security />
      <FAQ />
      <CTABanner />
      <Footer />
    </div>
  );
}
