import { useEffect } from "react";
import { Hero } from "./Hero";
import { Install } from "./Install";
import { Features } from "./Features";
import { Walkthrough } from "./Walkthrough";
import { Surfaces } from "./Surfaces";
import { Architecture } from "./Architecture";
import { Security } from "./Security";
import { CTABanner } from "./CTABanner";
import { Footer } from "./Footer";

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
      <Install />
      <Features />
      <Walkthrough />
      <Surfaces />
      <Architecture />
      <Security />
      <CTABanner />
      <Footer />
    </div>
  );
}
