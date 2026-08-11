import { Reveal } from "./primitives/Reveal";
import { Button } from "../ui/button";

// Full-bleed closing band: edge to edge, a distinct background from the
// page canvas, with one centred card. This is the page's one deliberately
// "loud" moment — everywhere else backgrounds are quiet, so the contrast
// here signals "this is the ask."
export function CTABanner() {
  const rawBase = import.meta.env.BASE_URL;
  const base = rawBase.endsWith("/") ? rawBase : `${rawBase}/`;

  return (
    <div className="w-full border-y border-edge/40 bg-raised py-20 lg:py-28">
      <div className="mx-auto max-w-3xl px-6 sm:px-8">
        <Reveal>
          <div className="rounded-2xl border border-edge/50 bg-canvas px-8 py-12 text-center sm:px-12 sm:py-16">
            <h2 className="mx-auto max-w-md lowercase font-display text-2xl font-bold leading-tight text-title sm:text-3xl">
              run something you don&rsquo;t trust.
            </h2>
            <p className="mx-auto mt-4 max-w-sm text-base leading-relaxed text-body">
              One install command. No daemon, no SSH, and no network until
              policy admits it.
            </p>
            <div className="mt-8 flex flex-wrap items-center justify-center gap-4">
              <a href={`${base}getting-started/installation/`}>
                <Button size="lg">Get Started</Button>
              </a>
              <a href="https://github.com/tinylabscom/mvm" target="_blank" rel="noopener">
                <Button size="lg" variant="outline">
                  View on GitHub
                </Button>
              </a>
              <a
                href={`${base}getting-started/quickstart/`}
                className="text-sm text-accent underline underline-offset-2 hover:text-accent/80"
              >
                Read the quickstart
              </a>
            </div>
          </div>
        </Reveal>
      </div>
    </div>
  );
}
