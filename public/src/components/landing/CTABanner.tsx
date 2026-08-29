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
    // A <section>, not a <div>: `mx-auto` on the wrapper below loses the
    // cascade to Starlight's unlayered CSS, and the rule that compensates
    // (`[data-has-hero] main section > div { margin-inline: auto }`) only
    // matches a direct child of a section. As a plain div this band's
    // wrapper computed margin 0 and the card sat flush left.
    <section className="w-full border-y border-edge/40 bg-raised pt-10 pb-20 lg:pt-14 lg:pb-28">
      <div className="mx-auto max-w-3xl px-6 sm:px-8">
        <Reveal>
          <div className="rounded-2xl border border-edge/50 bg-canvas px-8 py-12 text-center sm:px-12 sm:py-16">
            {/* `text-balance` rather than `mx-auto` + a max-width: it evens the
                two lines without constraining the box, so this doesn't depend
                on the `main section > div { margin-inline: auto }` rule that
                rescues Tailwind's mx-auto here — that rule only matches divs,
                so on an h2 the box stayed left of centre while its text
                appeared centred. */}
            <h2 className="text-balance lowercase font-display tracking-tight text-2xl font-semibold leading-tight text-title sm:text-3xl">
              ai may never be fully predictable.{" "}
              <span className="text-accent-2">its boundaries should be.</span>
            </h2>
            {/* No max-width cap: the sentence should sit on one line at
                desktop sizes; it still wraps naturally on narrow screens.
                Inline margins, not mt-*: Starlight's unlayered stylesheet
                beats layered utilities on this page (see Positioning.tsx). */}
            <p
              className="text-base leading-relaxed text-body"
              style={{ marginTop: "1.5rem" }}
            >
              That&rsquo;s mvm. One install command. No daemon, no SSH, and no
              network until policy admits it.
            </p>
            <div
              className="flex flex-wrap items-center justify-center gap-4"
              style={{ marginTop: "3rem" }}
            >
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
    </section>
  );
}
