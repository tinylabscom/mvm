import { Section } from "./primitives/Section";
import { Reveal } from "./primitives/Reveal";

// Deliberately one line: the hero already carries the install command and
// the primary "Get Started" CTA. A second headline-plus-button-pair here
// would just restate it — the tell the maintainer flags as machine-built.
export function CTABanner() {
  const rawBase = import.meta.env.BASE_URL;
  const base = rawBase.endsWith("/") ? rawBase : `${rawBase}/`;
  return (
    <Section space="tight">
      <Reveal>
        <p className="max-w-lg text-lg leading-relaxed text-body">
          Installed already? Start with the{" "}
          <a
            href={`${base}getting-started/quickstart/`}
            className="text-accent underline underline-offset-2 hover:text-accent/80"
          >
            quickstart
          </a>{" "}
          or read the source on{" "}
          <a
            href="https://github.com/tinylabscom/mvm"
            target="_blank"
            rel="noopener"
            className="text-accent underline underline-offset-2 hover:text-accent/80"
          >
            GitHub
          </a>
          .
        </p>
      </Reveal>
    </Section>
  );
}
