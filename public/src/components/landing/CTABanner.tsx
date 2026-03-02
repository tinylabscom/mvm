import { Button } from "../ui/button";

export function CTABanner() {
  const base = import.meta.env.BASE_URL;
  return (
    <section className="w-full px-6 py-28 sm:px-8 lg:py-36">
      <div className="mx-auto flex max-w-2xl flex-col items-center gap-10 text-center">
        <h2 className="text-2xl font-semibold text-title sm:text-3xl">
          Ready to build your first microVM?
        </h2>
        <p className="max-w-lg text-lg leading-relaxed text-body">
          mvm handles bootstrapping, Nix builds, Firecracker lifecycle, and
          template management — so you can focus on your workload.
        </p>
        <div className="flex flex-wrap justify-center gap-4">
          <a href={`${base}/getting-started/quickstart/`}>
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
