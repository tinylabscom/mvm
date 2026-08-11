// The hero's visual anchor. This is not decoration bolted onto the pitch —
// it IS the pitch: a container shares the host kernel, mvm does not. The
// diagram draws exactly what Architecture.tsx and Security.tsx already
// claim (own kernel, own rootfs, no guest NIC, vsock-only, default-deny
// substitution endpoint) and nothing else. If a fact here ever drifts from
// those sections, the diagram is wrong, not them.
//
// Two <svg> trees, not one reflowed by CSS: the desktop layout reads
// left-to-right (host -> boundary -> guest) and the mobile layout reads
// top-to-bottom, which is a different label/line topology, not just a
// resize. Swapped via `hidden lg:block` / `lg:hidden` so exactly one is in
// the accessibility tree's layout at a time; both are `aria-hidden` because
// the figure's `aria-label` is the real text alternative.

const HOST_LABEL = "YOUR HOST";
const HOST_SUB = "mvmctl · no daemon";
const GUEST_LABEL = "GUEST — microVM";
const KERNEL_LABEL = "own kernel";
const ROOTFS_LABEL = "own root filesystem";
const NIC_LABEL = "no network interface";
const VSOCK_LABEL = "vsock";
const ENDPOINT_LABEL = "substitution endpoint";
const ENDPOINT_SUB = "deny-all by default";
const INTERNET_LABEL = "internet";
const INTERNET_SUB = "only if policy admits";

const DESCRIPTION =
  "Diagram of the mvm isolation boundary. On one side, your host runs mvmctl " +
  "directly — no daemon, no host agent. A hard boundary separates it from " +
  "the guest: a microVM with its own kernel and its own root filesystem, not " +
  "a shared kernel like a container. The guest has no network interface at " +
  "all. The only channel that crosses the boundary is vsock, and it leads to " +
  "one thing: a host-side substitution endpoint that is deny-all by default. " +
  "Traffic reaches the internet only if policy explicitly admits it.";

/** No-NIC glyph: a network dish with a strike through it. */
function NoNicGlyph({ x, y, size = 14 }: { x: number; y: number; size?: number }) {
  const s = size / 14;
  return (
    <g transform={`translate(${x} ${y}) scale(${s})`} className="text-label" aria-hidden="true">
      <circle cx={7} cy={7} r={6} fill="none" stroke="currentColor" strokeWidth={1.4} />
      <path d="M4 9.5 7 5l3 4.5" fill="none" stroke="currentColor" strokeWidth={1.4} strokeLinecap="round" strokeLinejoin="round" />
      <line x1={1.5} y1={1.5} x2={12.5} y2={12.5} stroke="currentColor" strokeWidth={1.6} strokeLinecap="round" />
    </g>
  );
}

function DesktopDiagram() {
  return (
    <svg
      viewBox="0 0 640 380"
      className="hidden w-full lg:block"
      role="presentation"
      aria-hidden="true"
    >
      {/* Internet, off the host's open edge — label sits above the arrow
          row so the two never collide. */}
      <g className="text-label">
        <text fill="currentColor" x="18" y="150" fontSize="10" letterSpacing="0.08em" className="font-mono">
          {INTERNET_LABEL.toUpperCase()}
        </text>
        <text fill="currentColor" x="18" y="163" fontSize="8.5" opacity="0.7" className="font-mono">
          {INTERNET_SUB}
        </text>
      </g>
      <line
        x1="18"
        y1="182"
        x2="64"
        y2="182"
        stroke="currentColor"
        className="text-label"
        strokeWidth="1.5"
        strokeDasharray="3 4"
        markerEnd="url(#boundary-arrow)"
      />

      {/* Host zone */}
      <rect x="66" y="70" width="216" height="220" rx="14" fill="none" stroke="currentColor" className="text-edge" strokeWidth="1.5" />
      <text fill="currentColor" x="86" y="98" fontSize="11" letterSpacing="0.12em" className="font-mono text-label">
        {HOST_LABEL}
      </text>
      <text fill="currentColor" x="86" y="114" fontSize="9.5" className="font-mono text-label" opacity="0.7">
        {HOST_SUB}
      </text>

      {/* Substitution endpoint — the one guarded door in the wall */}
      <rect x="248" y="164" width="40" height="36" rx="6" className="text-canvas" fill="currentColor" stroke="var(--color-accent)" strokeWidth="1.75" />
      <g className="text-accent">
        <circle cx="268" cy="180" r="3.4" fill="none" stroke="currentColor" strokeWidth="1.4" />
        <path d="M268 183.4v3.6M265.6 191h4.8" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
      </g>
      <text fill="currentColor" x="268" y="220" textAnchor="middle" fontSize="9.5" className="font-mono text-label">
        {ENDPOINT_LABEL}
      </text>
      <text fill="currentColor" x="268" y="232" textAnchor="middle" fontSize="8.5" className="font-mono text-label" opacity="0.7">
        {ENDPOINT_SUB}
      </text>

      {/* The boundary — dominant, deliberately the thickest line here, and
          extended past the room edges so it reads as a wall, not a divider
          between two cards. */}
      <line x1="320" y1="48" x2="320" y2="312" stroke="var(--color-accent)" strokeWidth="10" strokeLinecap="round" opacity="0.14" />
      <line x1="320" y1="48" x2="320" y2="312" stroke="var(--color-accent)" strokeWidth="3" strokeLinecap="round" />

      {/* vsock — the single channel through the wall */}
      <line
        x1="288"
        y1="182"
        x2="358"
        y2="182"
        stroke="var(--color-accent-2)"
        strokeWidth="2.25"
        strokeDasharray="7 6"
        strokeLinecap="round"
        className="site-boundary-pulse"
      />
      <text fill="currentColor" x="323" y="168" textAnchor="middle" fontSize="10" letterSpacing="0.08em" className="font-mono text-accent-2">
        {VSOCK_LABEL.toUpperCase()}
      </text>

      {/* Guest zone */}
      <rect x="358" y="70" width="216" height="220" rx="14" fill="none" stroke="currentColor" className="text-edge" strokeWidth="1.5" />
      <text fill="currentColor" x="378" y="98" fontSize="11" letterSpacing="0.1em" className="font-mono text-label">
        {GUEST_LABEL}
      </text>

      <rect x="378" y="118" width="176" height="46" rx="7" fill="var(--color-raised-2)" stroke="currentColor" className="text-edge" strokeWidth="1.25" />
      <text fill="currentColor" x="466" y="145" textAnchor="middle" fontSize="11.5" className="font-mono text-emphasis">
        {KERNEL_LABEL}
      </text>

      <rect x="378" y="172" width="176" height="46" rx="7" fill="var(--color-raised-2)" stroke="currentColor" className="text-edge" strokeWidth="1.25" />
      <text fill="currentColor" x="466" y="199" textAnchor="middle" fontSize="11.5" className="font-mono text-emphasis">
        {ROOTFS_LABEL}
      </text>

      <NoNicGlyph x="386" y="232" />
      <text fill="currentColor" x="410" y="243" fontSize="10" className="font-mono text-label">
        {NIC_LABEL}
      </text>

      <defs>
        <marker id="boundary-arrow" markerWidth="7" markerHeight="7" refX="5" refY="3.5" orient="auto">
          <path d="M0 0 L7 3.5 L0 7 Z" className="text-label" fill="currentColor" />
        </marker>
      </defs>
    </svg>
  );
}

function MobileDiagram() {
  return (
    <svg
      viewBox="0 0 340 520"
      className="block w-full lg:hidden"
      role="presentation"
      aria-hidden="true"
    >
      {/* Internet, above the host's open edge */}
      <g className="text-label">
        <text fill="currentColor" x="170" y="20" textAnchor="middle" fontSize="10" letterSpacing="0.08em" className="font-mono">
          {INTERNET_LABEL.toUpperCase()}
        </text>
        <text fill="currentColor" x="170" y="33" textAnchor="middle" fontSize="8.5" opacity="0.7" className="font-mono">
          {INTERNET_SUB}
        </text>
      </g>
      <line
        x1="170"
        y1="40"
        x2="170"
        y2="60"
        stroke="currentColor"
        className="text-label"
        strokeWidth="1.5"
        strokeDasharray="3 4"
        markerEnd="url(#boundary-arrow-m)"
      />

      {/* Host zone */}
      <rect x="30" y="60" width="280" height="150" rx="14" fill="none" stroke="currentColor" className="text-edge" strokeWidth="1.5" />
      <text fill="currentColor" x="50" y="86" fontSize="11" letterSpacing="0.12em" className="font-mono text-label">
        {HOST_LABEL}
      </text>
      <text fill="currentColor" x="50" y="102" fontSize="9.5" className="font-mono text-label" opacity="0.7">
        {HOST_SUB}
      </text>

      {/* Substitution endpoint sits on the host side, right at the wall */}
      <rect x="150" y="192" width="40" height="36" rx="6" className="text-canvas" fill="currentColor" stroke="var(--color-accent)" strokeWidth="1.75" />
      <g className="text-accent">
        <circle cx="170" cy="204" r="3.4" fill="none" stroke="currentColor" strokeWidth="1.4" />
        <path d="M170 207.4v3.6M167.6 215h4.8" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
      </g>
      <text fill="currentColor" x="204" y="200" fontSize="9.5" className="font-mono text-label">
        {ENDPOINT_LABEL}
      </text>
      <text fill="currentColor" x="204" y="212" fontSize="8.5" className="font-mono text-label" opacity="0.7">
        {ENDPOINT_SUB}
      </text>

      {/* The boundary — horizontal, dominant */}
      <line x1="16" y1="248" x2="324" y2="248" stroke="var(--color-accent)" strokeWidth="10" strokeLinecap="round" opacity="0.14" />
      <line x1="16" y1="248" x2="324" y2="248" stroke="var(--color-accent)" strokeWidth="3" strokeLinecap="round" />

      {/* vsock — the single channel through the wall */}
      <line
        x1="170"
        y1="210"
        x2="170"
        y2="284"
        stroke="var(--color-accent-2)"
        strokeWidth="2.25"
        strokeDasharray="7 6"
        strokeLinecap="round"
        className="site-boundary-pulse"
      />
      <text fill="currentColor" x="186" y="266" fontSize="10" letterSpacing="0.08em" className="font-mono text-accent-2">
        {VSOCK_LABEL.toUpperCase()}
      </text>

      {/* Guest zone */}
      <rect x="30" y="284" width="280" height="196" rx="14" fill="none" stroke="currentColor" className="text-edge" strokeWidth="1.5" />
      <text fill="currentColor" x="50" y="310" fontSize="11" letterSpacing="0.1em" className="font-mono text-label">
        {GUEST_LABEL}
      </text>

      <rect x="50" y="326" width="240" height="46" rx="7" fill="var(--color-raised-2)" stroke="currentColor" className="text-edge" strokeWidth="1.25" />
      <text fill="currentColor" x="170" y="353" textAnchor="middle" fontSize="11.5" className="font-mono text-emphasis">
        {KERNEL_LABEL}
      </text>

      <rect x="50" y="380" width="240" height="46" rx="7" fill="var(--color-raised-2)" stroke="currentColor" className="text-edge" strokeWidth="1.25" />
      <text fill="currentColor" x="170" y="407" textAnchor="middle" fontSize="11.5" className="font-mono text-emphasis">
        {ROOTFS_LABEL}
      </text>

      <NoNicGlyph x="58" y="440" />
      <text fill="currentColor" x="82" y="451" fontSize="10" className="font-mono text-label">
        {NIC_LABEL}
      </text>

      <defs>
        <marker id="boundary-arrow-m" markerWidth="7" markerHeight="7" refX="3.5" refY="5" orient="auto">
          <path d="M0 0 L7 0 L3.5 7 Z" className="text-label" fill="currentColor" />
        </marker>
      </defs>
    </svg>
  );
}

export function BoundaryDiagram() {
  return (
    <figure
      className="w-full overflow-hidden rounded-xl border border-edge/50 bg-raised/40 p-6 shadow-2xl shadow-black/20 backdrop-blur sm:p-8"
      role="img"
      aria-label={DESCRIPTION}
    >
      <DesktopDiagram />
      <MobileDiagram />
    </figure>
  );
}
