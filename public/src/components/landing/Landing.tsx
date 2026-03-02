import { Hero } from "./Hero";
import { Features } from "./Features";
import { Architecture } from "./Architecture";
import { CodeExample } from "./CodeExample";
import { CTABanner } from "./CTABanner";

export function Landing() {
  return (
    <div className="min-h-screen bg-page">
      <Hero />
      <Features />
      <Architecture />
      <CodeExample />
      <CTABanner />
    </div>
  );
}
