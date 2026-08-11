import { useEffect } from "react";
import { Hero } from "./Hero";
import { CredibilityStrip } from "./CredibilityStrip";
import { Walkthrough } from "./Walkthrough";
import { Architecture } from "./Architecture";
import { Surfaces } from "./Surfaces";
import { WhyNotContainer } from "./WhyNotContainer";
import { Security } from "./Security";
import { FAQ } from "./FAQ";
import { CTABanner } from "./CTABanner";
import { Footer } from "./Footer";

// Section order is the argument, not a menu: credibility right after the
// hero answers "is this real?", the walkthrough proves the boundary works,
// "one boundary, three backends" generalises it, "three ways in" hands the
// reader the tools only once they've seen why the boundary matters, "why
// not a container" answers the objection the page used to skip, the
// security claims back it with named tests, and the FAQ mops up what's
// left. Do not reorder without re-reading reshape-brief.md.
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
      <Walkthrough />
      <Architecture />
      <Surfaces />
      <WhyNotContainer />
      <Security />
      <FAQ />
      <CTABanner />
      <Footer />
    </div>
  );
}
