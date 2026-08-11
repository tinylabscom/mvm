import { Hero } from "./Hero";
import { Install } from "./Install";
import { Features } from "./Features";
import { Architecture } from "./Architecture";
import { CodeExample } from "./CodeExample";
import { CTABanner } from "./CTABanner";
import { Footer } from "./Footer";

export function Landing() {
  return (
    <div className="min-h-screen w-full bg-canvas">
      <Hero />
      <Install />
      <Features />
      <Architecture />
      <CodeExample />
      <CTABanner />
      <Footer />
    </div>
  );
}
