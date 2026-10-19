// CTABanner is hidden for now — restore its import alongside the
// commented-out <CTABanner /> below.
// import { CTABanner } from "./CTABanner";
import { ExecutionContract } from "./ExecutionContract";
import { Footer } from "./Footer";
import { Hero } from "./Hero";
import { Quickstart } from "./Quickstart";
import { RequestAccess } from "./RequestAccess";
import { RiskControl } from "./RiskControl";
import { WhyNow } from "./WhyNow";
// DemoTeaser is hidden for now — restore its import alongside the
// commented-out <DemoTeaser /> below.
// import { DemoTeaser } from "./DemoTeaser";
// Positioning is hidden for now — restore its import alongside the
// commented-out <Positioning /> below.
// import { Positioning } from "./Positioning";

// Start with a runnable example, then explain workloads, execution plans,
// and operator controls. Keep the contact form after the product details.
export function Landing() {
  return (
    <div className="min-h-screen w-full bg-canvas">
      <Hero />
      <Quickstart />
      {/* The demo teaser (browser sandbox) is hidden for now, not
          deleted — restore by uncommenting here and its import above. */}
      {/* <DemoTeaser /> */}
      <WhyNow />
      <ExecutionContract />
      <RiskControl />
      {/* Positioning ("one project. three ways to drive it.") is hidden for
          now, not deleted — restore by uncommenting here and re-adding its
          entry to the section-order comment above. */}
      {/* <Positioning /> */}
      <RequestAccess />
      {/* The closing band ("ai may never be fully predictable" + the
          vision paragraph) is hidden for now, not deleted — restore
          by uncommenting here and its import above. */}
      {/* <CTABanner /> */}
      <Footer />
    </div>
  );
}
