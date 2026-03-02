import { Button } from "../ui/button";

export function CTABanner() {
  return (
    <section className="px-6 py-28 sm:px-8">
      <div className="mx-auto flex max-w-2xl flex-col items-center gap-8 text-center">
        <h2 className="text-2xl font-semibold text-heading sm:text-3xl">
          Ready to build your first microVM?
        </h2>
        <p className="max-w-lg text-lg leading-relaxed text-muted">
          mvm handles bootstrapping, Nix builds, Firecracker lifecycle, and
          template management — so you can focus on your workload.
        </p>
        <div className="flex flex-wrap justify-center gap-4">
          <a href="/getting-started/quickstart/">
            <Button size="lg">Quick Start Guide</Button>
          </a>
          <a href="https://github.com/auser/mvm" target="_blank" rel="noopener">
            <Button variant="outline" size="lg">
              View on GitHub
            </Button>
          </a>
        </div>
      </div>
    </section>
  );
}
