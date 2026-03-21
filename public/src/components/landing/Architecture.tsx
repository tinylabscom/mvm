export function Architecture() {
  return (
    <section className="relative w-full border-y border-edge/30 bg-raised/50 px-6 py-28 sm:px-8 lg:py-36">
      <div className="mx-auto max-w-5xl">
        <div className="mb-16 text-center lg:mb-20">
          <p className="mb-4 text-sm font-medium uppercase tracking-widest text-accent">
            Architecture
          </p>
          <h2 className="text-3xl font-bold text-title sm:text-4xl lg:text-5xl">
            One CLI, four backends
          </h2>
          <p className="mx-auto mt-6 max-w-xl text-lg leading-relaxed text-body">
            mvm auto-detects your platform and picks the fastest path to a
            running VM. You can also choose a backend explicitly.
          </p>
        </div>

        <div className="mx-auto max-w-4xl space-y-6">
          {/* Host layer */}
          <div className="rounded-xl border border-accent/30 bg-accent/6 p-6 sm:p-8">
            <div className="flex items-center gap-3">
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-accent/20 text-accent">
                <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M9 17.25v1.007a3 3 0 0 1-.879 2.122L7.5 21h9l-.621-.621A3 3 0 0 1 15 18.257V17.25m6-12V15a2.25 2.25 0 0 1-2.25 2.25H5.25A2.25 2.25 0 0 1 3 15V5.25m18 0A2.25 2.25 0 0 0 18.75 3H5.25A2.25 2.25 0 0 0 3 5.25m18 0V12a2.25 2.25 0 0 1-2.25 2.25H5.25A2.25 2.25 0 0 1 3 12V5.25" />
                </svg>
              </div>
              <div>
                <span className="text-sm font-semibold text-accent">Your Host</span>
                <span className="ml-2 text-xs text-label">macOS / Linux / WSL2</span>
              </div>
            </div>
            <p className="mt-2 ml-11 text-xs text-label">
              mvmctl detects /dev/kvm, Apple Virtualization, and Docker — then
              selects the best backend automatically.
            </p>

            {/* Auto-detect arrow */}
            <div className="my-5 flex items-center gap-3 ml-11">
              <div className="h-px flex-1 bg-linear-to-r from-accent/30 to-transparent" />
              <span className="rounded border border-accent/20 bg-accent/10 px-2.5 py-1 text-[10px] font-medium uppercase tracking-wider text-accent">
                auto-select
              </span>
              <div className="h-px flex-1 bg-linear-to-l from-accent/30 to-transparent" />
            </div>

            {/* Backend cards grid */}
            <div className="grid gap-4 sm:grid-cols-2">
              {/* Firecracker */}
              <div className="rounded-xl border border-rust/30 bg-rust/6 p-5">
                <div className="flex items-center gap-3">
                  <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md bg-rust/20 text-rust">
                    <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="m3.75 13.5 10.5-11.25L12 10.5h8.25L9.75 21.75 12 13.5H3.75Z" />
                    </svg>
                  </div>
                  <div>
                    <span className="text-sm font-semibold text-rust">Firecracker</span>
                    <span className="ml-1.5 rounded bg-rust/10 px-1.5 py-0.5 text-[10px] text-rust/70">
                      default
                    </span>
                  </div>
                </div>
                <p className="mt-2 text-xs text-label leading-relaxed">
                  Production-grade microVMs. Snapshots, pause/resume, vsock, TAP
                  networking.
                </p>
                <div className="mt-3 flex flex-wrap gap-1.5">
                  {["snapshots", "vsock", "TAP", "pause"].map((c) => (
                    <span key={c} className="rounded bg-rust/10 px-1.5 py-0.5 text-[10px] text-rust/80">
                      {c}
                    </span>
                  ))}
                </div>
                <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1 text-[10px] text-label">
                  <span><strong className="text-emphasis">Linux + KVM</strong> — native</span>
                  <span><strong className="text-emphasis">macOS</strong> — via Lima VM</span>
                </div>
              </div>

              {/* Apple Virtualization */}
              <div className="rounded-xl border border-green/30 bg-green/6 p-5">
                <div className="flex items-center gap-3">
                  <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md bg-green/20 text-green">
                    <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M10.5 1.5H8.25A2.25 2.25 0 0 0 6 3.75v16.5a2.25 2.25 0 0 0 2.25 2.25h7.5A2.25 2.25 0 0 0 18 20.25V3.75a2.25 2.25 0 0 0-2.25-2.25H13.5m-3 0V3h3V1.5m-3 0h3m-3 18.75h3" />
                    </svg>
                  </div>
                  <div>
                    <span className="text-sm font-semibold text-green">Apple Virtualization</span>
                  </div>
                </div>
                <p className="mt-2 text-xs text-label leading-relaxed">
                  Native macOS 26+ on Apple Silicon. Sub-second startup, no Lima
                  needed.
                </p>
                <div className="mt-3 flex flex-wrap gap-1.5">
                  {["vsock", "fast boot"].map((c) => (
                    <span key={c} className="rounded bg-green/10 px-1.5 py-0.5 text-[10px] text-green/80">
                      {c}
                    </span>
                  ))}
                </div>
                <div className="mt-3 text-[10px] text-label">
                  <strong className="text-emphasis">macOS 26+</strong> — Apple Silicon only
                </div>
              </div>

              {/* microvm.nix */}
              <div className="rounded-xl border border-nix/30 bg-nix/6 p-5">
                <div className="flex items-center gap-3">
                  <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md bg-nix/20 text-nix">
                    <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="m21 7.5-9-5.25L3 7.5m18 0-9 5.25m9-5.25v9l-9 5.25M3 7.5l9 5.25M3 7.5v9l9 5.25m0-9v9" />
                    </svg>
                  </div>
                  <div>
                    <span className="text-sm font-semibold text-nix">microvm.nix</span>
                  </div>
                </div>
                <p className="mt-2 text-xs text-label leading-relaxed">
                  NixOS-native VM runner with QEMU. Vsock and TAP networking
                  support.
                </p>
                <div className="mt-3 flex flex-wrap gap-1.5">
                  {["vsock", "TAP"].map((c) => (
                    <span key={c} className="rounded bg-nix/10 px-1.5 py-0.5 text-[10px] text-nix/80">
                      {c}
                    </span>
                  ))}
                </div>
                <div className="mt-3 text-[10px] text-label">
                  <strong className="text-emphasis">Linux</strong> — native or via Lima
                </div>
              </div>

              {/* Docker */}
              <div className="rounded-xl border border-edge/50 bg-canvas/80 p-5">
                <div className="flex items-center gap-3">
                  <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md bg-edge/30 text-label">
                    <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M5.25 14.25h13.5m-13.5 0a3 3 0 0 1-3-3m3 3a3 3 0 1 0 0 6h13.5a3 3 0 1 0 0-6m-16.5-3a3 3 0 0 1 3-3h13.5a3 3 0 0 1 3 3m-19.5 0a4.5 4.5 0 0 1 .9-2.7L5.737 5.1a3.375 3.375 0 0 1 2.7-1.35h7.126c1.062 0 2.062.5 2.7 1.35l2.587 3.45a4.5 4.5 0 0 1 .9 2.7m0 0a3 3 0 0 1-3 3m0 3h.008v.008h-.008v-.008Zm0-6h.008v.008h-.008v-.008ZM6.75 14.25h.008v.008H6.75v-.008Z" />
                    </svg>
                  </div>
                  <div>
                    <span className="text-sm font-semibold text-emphasis">Docker</span>
                    <span className="ml-1.5 rounded bg-edge/30 px-1.5 py-0.5 text-[10px] text-label">
                      fallback
                    </span>
                  </div>
                </div>
                <p className="mt-2 text-xs text-label leading-relaxed">
                  Universal fallback. Runs anywhere Docker does. Pause/resume via
                  container lifecycle.
                </p>
                <div className="mt-3 flex flex-wrap gap-1.5">
                  {["pause", "unix socket"].map((c) => (
                    <span key={c} className="rounded bg-edge/20 px-1.5 py-0.5 text-[10px] text-label">
                      {c}
                    </span>
                  ))}
                </div>
                <div className="mt-3 text-[10px] text-label">
                  <strong className="text-emphasis">Everywhere</strong> — macOS, Linux, WSL2
                </div>
              </div>
            </div>
          </div>

          {/* Drive model strip */}
          <div className="rounded-lg border border-edge/30 bg-canvas px-6 py-4">
            <p className="mb-3 text-center text-[10px] font-medium uppercase tracking-wider text-label">
              Guest Drive Model
            </p>
            <div className="flex flex-wrap items-center justify-center gap-3">
              {[
                { dev: "vda", label: "rootfs", cls: "text-accent border-accent/20 bg-accent/5" },
                { dev: "vdb", label: "config (ro)", cls: "text-green border-green/20 bg-green/5" },
                { dev: "vdc", label: "secrets (ro)", cls: "text-amber border-amber/20 bg-amber/5" },
                { dev: "vdd", label: "data (rw)", cls: "text-label border-edge/40 bg-canvas/50" },
              ].map((d) => (
                <span
                  key={d.dev}
                  className={`rounded-md border px-2.5 py-1 font-mono text-[11px] ${d.cls}`}
                >
                  {d.dev} {d.label}
                </span>
              ))}
            </div>
          </div>

          {/* Network strip */}
          <div className="flex items-center justify-center gap-4 rounded-lg border border-edge/30 bg-canvas px-6 py-4 text-xs">
            <span className="font-mono text-emphasis">172.16.0.2</span>
            <span className="text-label">TAP + vsock:52</span>
            <svg className="h-3 w-3 text-label" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M7.5 21 3 16.5m0 0L7.5 12M3 16.5h13.5m0-13.5L21 7.5m0 0L16.5 12M21 7.5H7.5" />
            </svg>
            <span className="font-mono text-emphasis">172.16.0.1</span>
            <span className="text-label">NAT</span>
            <svg className="h-3 w-3 text-label" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 4.5 21 12m0 0-7.5 7.5M21 12H3" />
            </svg>
            <span className="text-emphasis">internet</span>
          </div>
        </div>
      </div>
    </section>
  );
}
