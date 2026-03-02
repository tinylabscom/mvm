export function Architecture() {
  const drives = [
    { dev: "/dev/vda", label: "rootfs", cls: "text-accent" },
    { dev: "/dev/vdb", label: "config (ro)", cls: "text-green" },
    { dev: "/dev/vdc", label: "secrets (ro)", cls: "text-amber" },
    { dev: "/dev/vdd", label: "data (rw)", cls: "text-label" },
  ];

  return (
    <section className="w-full px-6 py-28 sm:px-8 lg:py-36">
      <div className="mx-auto max-w-5xl">
        <h2 className="mb-16 text-center text-2xl font-semibold text-title sm:text-3xl lg:mb-20">
          Architecture
        </h2>
        <div className="overflow-x-auto rounded-xl border border-edge bg-raised p-8 font-mono text-sm shadow-lg shadow-black/10 sm:p-12 lg:p-14">
          {/* Stack layers */}
          <div className="flex flex-col items-center gap-4">
            <div className="flex flex-wrap items-center justify-center gap-4">
              <div className="rounded-lg border border-action px-5 py-3 text-link">
                macOS / Linux Host
              </div>
              <span className="text-label">&rarr;</span>
              <div className="rounded-lg border border-edge px-5 py-3 text-emphasis">
                Lima VM (Ubuntu + Nix)
              </div>
              <span className="text-label">&rarr;</span>
              <div className="rounded-lg border border-edge px-5 py-3 text-emphasis">
                Firecracker microVM
              </div>
            </div>

            {/* Drive model */}
            <div className="mt-8 w-full border-t border-edge pt-8">
              <p className="mb-5 text-center text-xs text-label">
                Guest Drive Model
              </p>
              <div className="flex flex-wrap justify-center gap-4">
                {drives.map((d) => (
                  <div
                    key={d.dev}
                    className="flex flex-col items-center gap-1.5 rounded-lg border border-edge bg-canvas px-5 py-3"
                  >
                    <span className={`text-xs font-semibold ${d.cls}`}>
                      {d.dev}
                    </span>
                    <span className="text-xs text-label">{d.label}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Network */}
            <div className="mt-8 w-full border-t border-edge pt-8 text-center">
              <p className="mb-3 text-xs text-label">Network</p>
              <div className="flex flex-col items-center gap-1.5 text-xs">
                <span className="text-emphasis">MicroVM (172.16.0.2, eth0)</span>
                <span className="text-label">| TAP + vsock:52</span>
                <span className="text-emphasis">Lima VM (172.16.0.1, tap0) — NAT — internet</span>
                <span className="text-label">| Lima</span>
                <span className="text-emphasis">Host</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
