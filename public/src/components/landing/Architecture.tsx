export function Architecture() {
  const drives = [
    { dev: "/dev/vda", label: "rootfs", cls: "text-accent" },
    { dev: "/dev/vdb", label: "config (ro)", cls: "text-green" },
    { dev: "/dev/vdc", label: "secrets (ro)", cls: "text-amber" },
    { dev: "/dev/vdd", label: "data (rw)", cls: "text-muted" },
  ];

  return (
    <section className="px-6 py-24 sm:px-8">
      <div className="mx-auto max-w-4xl">
        <h2 className="mb-12 text-center text-2xl font-semibold text-heading sm:text-3xl">
          Architecture
        </h2>
        <div className="overflow-x-auto rounded-xl border border-border bg-surface p-8 font-mono text-sm sm:p-10">
          {/* Stack layers */}
          <div className="flex flex-col items-center gap-4">
            <div className="flex flex-wrap items-center justify-center gap-4">
              <div className="rounded-lg border border-accent px-5 py-3 text-accent">
                macOS / Linux Host
              </div>
              <span className="text-muted">&rarr;</span>
              <div className="rounded-lg border border-border px-5 py-3 text-heading">
                Lima VM (Ubuntu + Nix)
              </div>
              <span className="text-muted">&rarr;</span>
              <div className="rounded-lg border border-border px-5 py-3 text-heading">
                Firecracker microVM
              </div>
            </div>

            {/* Drive model */}
            <div className="mt-8 w-full border-t border-border pt-8">
              <p className="mb-5 text-center text-xs text-muted">
                Guest Drive Model
              </p>
              <div className="flex flex-wrap justify-center gap-4">
                {drives.map((d) => (
                  <div
                    key={d.dev}
                    className="flex flex-col items-center gap-1.5 rounded-lg border border-border bg-page px-5 py-3"
                  >
                    <span className={`text-xs font-semibold ${d.cls}`}>
                      {d.dev}
                    </span>
                    <span className="text-xs text-muted">{d.label}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Network */}
            <div className="mt-8 w-full border-t border-border pt-8 text-center">
              <p className="mb-3 text-xs text-muted">Network</p>
              <div className="flex flex-col items-center gap-1.5 text-xs">
                <span className="text-heading">MicroVM (172.16.0.2, eth0)</span>
                <span className="text-muted">| TAP + vsock:52</span>
                <span className="text-heading">Lima VM (172.16.0.1, tap0) — NAT — internet</span>
                <span className="text-muted">| Lima</span>
                <span className="text-heading">Host</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
