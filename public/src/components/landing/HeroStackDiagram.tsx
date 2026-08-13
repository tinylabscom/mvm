// Clean 3-Step Execution Pipeline Hero Diagram for mvm.
//
// Visually conveys mvm's core job:
// 1. Input: Untrusted Code (mvm.invoke / Sandbox API)
// 2. MicroVM Sandbox: Own Linux Kernel, Nix RootFS, Hardware Isolated, NO NIC
// 3. Safe Output: Returned over VSOCK (the only crossing)
//
// Scheme-invariant CSS variables only; zero hardcoded hex.

const RADIUS = 12;

const DESCRIPTION =
  "Flow diagram of mvm execution: Untrusted code enters a hardware-isolated microVM running its own Linux kernel with no raw network interface, returning safe results back over a single vsock channel.";

function LockIcon({ x, y }: { x: number; y: number }) {
  return (
    <g transform={`translate(${x} ${y})`} className="text-accent-2" aria-hidden="true">
      <path d="M-3 -1 v-2.2 a3 3 0 0 1 6 0 v2.2" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" />
      <rect x={-5} y={-1} width={10} height={8} rx={1.5} fill="none" stroke="currentColor" strokeWidth={2} />
    </g>
  );
}

function ArrowDown({ x, y, label }: { x: number; y: number; label?: string }) {
  return (
    <g transform={`translate(${x} ${y})`} aria-hidden="true">
      <line x1={0} y1={0} x2={0} y2={24} stroke="var(--color-accent-2)" strokeWidth={2} strokeDasharray="4 4" className="site-boundary-pulse" />
      <polygon points="-4,20 0,27 4,20" fill="var(--color-accent-2)" />
      {label && (
        <text x={12} y={15} fill="var(--color-label)" fontSize={11} className="font-mono">
          {label}
        </text>
      )}
    </g>
  );
}

function DesktopFlow() {
  const width = 480;
  const x = 20;

  return (
    <svg viewBox="0 0 520 400" className="hidden w-full lg:block" role="presentation" aria-hidden="true">
      {/* ── STEP 1: UNTRUSTED CODE INPUT ── */}
      <g>
        <rect
          x={x}
          y={16}
          width={width}
          height={64}
          rx={RADIUS}
          fill="var(--color-raised)"
          stroke="var(--color-edge)"
          strokeWidth={1.5}
        />
        {/* Terminal window dots */}
        <circle cx={x + 20} cy={34} r={4} fill="var(--color-dot-close)" />
        <circle cx={x + 32} cy={34} r={4} fill="var(--color-dot-minimize)" />
        <circle cx={x + 44} cy={34} r={4} fill="var(--color-dot-expand)" />
        <text x={x + 60} y={38} fill="var(--color-label)" fontSize={11} className="font-mono">
          untrusted-code.py
        </text>

        {/* Code invocation */}
        <text x={x + 20} y={60} fill="var(--color-title)" fontSize={13} className="font-mono font-medium">
          mvm.invoke(<tspan fill="var(--color-accent)">"run_agent"</tspan>, input=...)
        </text>
        <rect x={x + width - 90} y={28} width={70} height={20} rx={4} fill="var(--color-accent-low)" />
        <text x={x + width - 55} y={42} fill="var(--color-accent)" fontSize={10} textAnchor="middle" className="font-mono font-semibold">
          UNTRUSTED
        </text>
      </g>

      {/* Connection arrow */}
      <ArrowDown x={x + width / 2} y={80} />

      {/* ── STEP 2: ISOLATED MICROVM SANDBOX ── */}
      <g>
        {/* Container box */}
        <rect
          x={x}
          y={114}
          width={width}
          height={164}
          rx={RADIUS}
          fill="var(--color-raised-2)"
          stroke="var(--color-accent-2)"
          strokeWidth={2}
        />

        {/* Container header */}
        <rect x={x} y={114} width={width} height={36} rx={RADIUS} fill="var(--color-canvas)" opacity={0.6} />
        <line x1={x} y1={150} x2={x + width} y2={150} stroke="var(--color-edge)" strokeWidth={1} />

        <LockIcon x={x + 22} y={132} />
        <text x={x + 36} y={136} fill="var(--color-title)" fontSize={14} className="font-mono font-bold">
          mvm MicroVM Sandbox
        </text>

        <rect x={x + width - 110} y={122} width={90} height={20} rx={4} fill="var(--color-canvas)" stroke="var(--color-accent-2)" strokeWidth={1} />
        <text x={x + width - 65} y={136} fill="var(--color-accent-2)" fontSize={10} textAnchor="middle" className="font-mono font-bold">
          OWN KERNEL
        </text>

        {/* Execution environment inner panel */}
        <rect
          x={x + 20}
          y={166}
          width={width - 40}
          height={92}
          rx={8}
          fill="var(--color-canvas)"
          stroke="var(--color-glass-border)"
          strokeWidth={1}
        />

        <text x={x + 36} y={190} fill="var(--color-title)" fontSize={13} className="font-mono font-semibold">
          Guest Kernel &amp; DM-Verity RootFS
        </text>
        <text x={x + 36} y={210} fill="var(--color-body)" fontSize={11} className="font-mono">
          Hardware isolated · Zero shared memory with host
        </text>

        {/* Feature Pills */}
        <g transform={`translate(${x + 36}, 224)`}>
          <rect x={0} y={0} width={72} height={20} rx={4} fill="var(--color-raised-2)" stroke="var(--color-edge)" strokeWidth={1} />
          <text x={36} y={14} fill="var(--color-accent-3)" fontSize={10} textAnchor="middle" className="font-mono font-semibold">
            NO NIC
          </text>

          <rect x={80} y={0} width={130} height={20} rx={4} fill="var(--color-raised-2)" stroke="var(--color-edge)" strokeWidth={1} />
          <text x={145} y={14} fill="var(--color-label)" fontSize={10} textAnchor="middle" className="font-mono">
            Secret Substitution
          </text>

          <rect x={218} y={0} width={110} height={20} rx={4} fill="var(--color-raised-2)" stroke="var(--color-edge)" strokeWidth={1} />
          <text x={273} y={14} fill="var(--color-label)" fontSize={10} textAnchor="middle" className="font-mono">
            Signed Audit Log
          </text>
        </g>
      </g>

      {/* VSOCK Connection arrow */}
      <ArrowDown x={x + width / 2} y={278} label="VSOCK (only crossing)" />

      {/* ── STEP 3: SAFE TYPED RESULT ── */}
      <g>
        <rect
          x={x}
          y={312}
          width={width}
          height={60}
          rx={RADIUS}
          fill="var(--color-raised)"
          stroke="var(--color-green)"
          strokeWidth={1.5}
        />
        <circle cx={x + 28} cy={342} r={10} fill="var(--color-green)" opacity={0.2} />
        <path d={`M${x + 23} 342 l3.5 3.5 l7 -7`} stroke="var(--color-green)" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" fill="none" />

        <text x={x + 48} y={338} fill="var(--color-title)" fontSize={13} className="font-mono font-semibold">
          Safe Typed Output Returned
        </text>
        <text x={x + 48} y={354} fill="var(--color-body)" fontSize={11} className="font-mono">
          {"{ status: 200, result: { ... } }"}
        </text>
      </g>
    </svg>
  );
}

function MobileFlow() {
  const width = 310;
  const x = 15;

  return (
    <svg viewBox="0 0 340 410" className="block w-full lg:hidden" role="presentation" aria-hidden="true">
      {/* Step 1 */}
      <g>
        <rect x={x} y={15} width={width} height={60} rx={RADIUS} fill="var(--color-raised)" stroke="var(--color-edge)" strokeWidth={1.5} />
        <circle cx={x + 16} cy={30} r={3} fill="var(--color-dot-close)" />
        <circle cx={x + 25} cy={30} r={3} fill="var(--color-dot-minimize)" />
        <circle cx={x + 34} cy={30} r={3} fill="var(--color-dot-expand)" />
        <text x={x + 16} y={54} fill="var(--color-title)" fontSize={11} className="font-mono font-medium">
          mvm.invoke("run_code")
        </text>
      </g>

      <ArrowDown x={x + width / 2} y={75} />

      {/* Step 2 */}
      <g>
        <rect x={x} y={105} width={width} height={170} rx={RADIUS} fill="var(--color-raised-2)" stroke="var(--color-accent-2)" strokeWidth={2} />
        <LockIcon x={x + 18} y={125} />
        <text x={x + 30} y={130} fill="var(--color-title)" fontSize={13} className="font-mono font-bold">
          mvm MicroVM Sandbox
        </text>

        <rect x={x + 14} y={145} width={width - 28} height={114} rx={8} fill="var(--color-canvas)" stroke="var(--color-glass-border)" strokeWidth={1} />
        <text x={x + 26} y={170} fill="var(--color-title)" fontSize={12} className="font-mono font-semibold">
          Own Guest Kernel
        </text>
        <text x={x + 26} y={188} fill="var(--color-body)" fontSize={10} className="font-mono">
          Nix rootfs · Hardware isolated
        </text>

        <rect x={x + 26} y={205} width={64} height={18} rx={4} fill="var(--color-raised-2)" stroke="var(--color-edge)" strokeWidth={1} />
        <text x={x + 58} y={218} fill="var(--color-accent-3)" fontSize={9} textAnchor="middle" className="font-mono font-semibold">
          NO NIC
        </text>

        <rect x={x + 98} y={205} width={100} height={18} rx={4} fill="var(--color-raised-2)" stroke="var(--color-edge)" strokeWidth={1} />
        <text x={x + 148} y={218} fill="var(--color-label)" fontSize={9} textAnchor="middle" className="font-mono">
          Secret Substituted
        </text>
      </g>

      <ArrowDown x={x + width / 2} y={275} label="VSOCK" />

      {/* Step 3 */}
      <g>
        <rect x={x} y={305} width={width} height={56} rx={RADIUS} fill="var(--color-raised)" stroke="var(--color-green)" strokeWidth={1.5} />
        <circle cx={x + 24} cy={333} r={8} fill="var(--color-green)" opacity={0.2} />
        <path d={`M${x + 20} 333 l2.5 2.5 l5 -5`} stroke="var(--color-green)" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" fill="none" />
        <text x={x + 40} y={337} fill="var(--color-title)" fontSize={12} className="font-mono font-semibold">
          Typed Safe Result
        </text>
      </g>
    </svg>
  );
}

export function HeroStackDiagram() {
  return (
    <figure className="w-full" role="img" aria-label={DESCRIPTION}>
      <DesktopFlow />
      <MobileFlow />
    </figure>
  );
}
