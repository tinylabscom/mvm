// The hero's visual anchor. This is not decoration bolted onto the pitch —
// it IS the pitch: a container shares the host kernel, mvm does not. The
// diagram draws exactly what Architecture.tsx and Security.tsx already
// claim (own kernel, own rootfs, no guest NIC, vsock-only, default-deny
// substitution endpoint) and nothing else. If a fact here ever drifts from
// those sections, the diagram is wrong, not them.
//
// Design intent (round 2 — the first pass was too quiet): the wall has to
// win the one-second glance before any label is read. It is drawn as a
// solid filled band, not a stroked line, sized to dominate the frame, with
// one gap cut into it — the substitution endpoint — so it reads as "a
// guarded door in a wall," not "two boxes with a divider." Everything else
// (host label, guest label, the kernel/rootfs stack) is secondary to that.
// The internet/policy-admits sub-flow from round 1 is cut entirely — it
// was the least load-bearing claim visually and it was competing with the
// wall for attention it couldn't win.
//
// Two <svg> trees, not one reflowed by CSS: the desktop layout reads
// left-to-right (host -> wall -> guest) and the mobile layout reads
// top-to-bottom (a horizontal wall), a different topology, not just a
// resize. Swapped via `hidden lg:block` / `lg:hidden` so exactly one is in
// the accessibility tree's layout at a time; both are `aria-hidden` because
// the figure's `aria-label` is the real text alternative.

const HOST_LABEL = "YOUR HOST";
const HOST_SUB = "mvmctl · no daemon";
const GUEST_LABEL = "GUEST";
const GUEST_SUB = "microVM";
const KERNEL_LABEL = "own kernel";
const ROOTFS_LABEL = "own root filesystem";
const NIC_LABEL = "no network interface";
const VSOCK_LABEL = "vsock";
const ENDPOINT_LABEL = "SUBSTITUTION ENDPOINT";
const ENDPOINT_SUB = "deny-all by default";

const DESCRIPTION =
  "Diagram of the mvm isolation boundary. On one side, your host runs mvmctl " +
  "directly — no daemon, no host agent. A thick, solid wall separates it " +
  "from the guest: a microVM with its own kernel and its own root " +
  "filesystem, not a shared kernel like a container. The guest has no " +
  "network interface at all. The wall has exactly one gap in it: a " +
  "host-side substitution endpoint, deny-all by default, and the only " +
  "channel that reaches it — from either side — is vsock.";

/** No-NIC glyph: a network dish with a strike through it. */
function NoNicGlyph({ x, y, size = 18 }: { x: number; y: number; size?: number }) {
  const s = size / 14;
  return (
    <g transform={`translate(${x} ${y}) scale(${s})`} className="text-label" aria-hidden="true">
      <circle cx={7} cy={7} r={6} fill="none" stroke="currentColor" strokeWidth={1.4} />
      <path d="M4 9.5 7 5l3 4.5" fill="none" stroke="currentColor" strokeWidth={1.4} strokeLinecap="round" strokeLinejoin="round" />
      <line x1={1.5} y1={1.5} x2={12.5} y2={12.5} stroke="currentColor" strokeWidth={1.6} strokeLinecap="round" />
    </g>
  );
}

/** Padlock glyph marking the one gap in the wall. */
function LockGlyph({ x, y }: { x: number; y: number }) {
  return (
    <g transform={`translate(${x} ${y})`} className="text-accent" aria-hidden="true">
      <circle cx={0} cy={-3.5} r={7.5} fill="none" stroke="currentColor" strokeWidth={2.75} />
      <path d="M0 4v7.5M-5 11.5h10" stroke="currentColor" strokeWidth={2.75} strokeLinecap="round" />
    </g>
  );
}

function DesktopDiagram() {
  return (
    <svg
      viewBox="0 0 600 400"
      className="hidden w-full lg:block"
      role="presentation"
      aria-hidden="true"
    >
      <defs>
        <filter id="wall-glow" x="-60%" y="-20%" width="220%" height="140%">
          <feGaussianBlur stdDeviation="16" />
        </filter>
      </defs>

      {/* Wall glow — soft light spilling off the wall, not a hairline. */}
      <rect x="234" y="30" width="132" height="340" className="text-accent" fill="currentColor" opacity="0.22" filter="url(#wall-glow)" />

      {/* The wall itself: two solid, hard-edged segments with one gap —
          the endpoint — cut into it. This is the diagram's dominant
          element by design: thickest shape, highest-contrast fill, first
          thing the eye should land on. */}
      <rect x="264" y="30" width="72" height="120" className="text-accent" fill="currentColor" />
      <rect x="264" y="250" width="72" height="120" className="text-accent" fill="currentColor" />

      {/* The gap — the one guarded door in the wall */}
      <rect x="264" y="150" width="72" height="100" rx="10" fill="var(--color-canvas)" stroke="var(--color-accent)" strokeWidth="3.5" />
      <LockGlyph x="300" y="203" />

      {/* Endpoint label — attached to the host side, reading toward the gap */}
      <text fill="currentColor" x="250" y="192" textAnchor="end" fontSize="13" letterSpacing="0.08em" className="font-mono text-label" fontWeight="600">
        {ENDPOINT_LABEL}
      </text>
      <text fill="currentColor" x="250" y="210" textAnchor="end" fontSize="12.5" className="font-mono text-label" opacity="0.75">
        {ENDPOINT_SUB}
      </text>

      {/* Host zone — label only; no bounding card, the wall does the
          separating. */}
      <text fill="currentColor" x="40" y="66" fontSize="27" letterSpacing="-0.01em" className="font-display text-title" fontWeight="700">
        {HOST_LABEL}
      </text>
      <text fill="currentColor" x="40" y="90" fontSize="14.5" className="font-mono text-label">
        {HOST_SUB}
      </text>

      {/* vsock — the single channel through the wall, drawn heavier and
          brighter than any other line here since it is the only crossing. */}
      <line
        x1="336"
        y1="200"
        x2="378"
        y2="200"
        stroke="var(--color-accent-2)"
        strokeWidth="4"
        strokeDasharray="9 7"
        strokeLinecap="round"
        className="site-boundary-pulse"
      />
      <text fill="currentColor" x="386" y="205" fontSize="16" letterSpacing="0.06em" className="font-mono text-accent-2" fontWeight="700">
        {VSOCK_LABEL.toUpperCase()}
      </text>

      {/* Guest zone */}
      <text fill="currentColor" x="376" y="66" fontSize="27" letterSpacing="-0.01em" className="font-display text-title" fontWeight="700">
        {GUEST_LABEL}
      </text>
      <text fill="currentColor" x="376" y="88" fontSize="14.5" className="font-mono text-label">
        {GUEST_SUB}
      </text>

      <rect x="376" y="108" width="212" height="66" rx="10" fill="var(--color-raised-2)" stroke="currentColor" className="text-edge" strokeWidth="1.5" />
      <text fill="currentColor" x="482" y="147" textAnchor="middle" fontSize="16.5" className="font-mono text-emphasis" fontWeight="600">
        {KERNEL_LABEL}
      </text>

      <rect x="376" y="188" width="212" height="66" rx="10" fill="var(--color-raised-2)" stroke="currentColor" className="text-edge" strokeWidth="1.5" />
      <text fill="currentColor" x="482" y="227" textAnchor="middle" fontSize="14.5" className="font-mono text-emphasis" fontWeight="600">
        {ROOTFS_LABEL}
      </text>

      <NoNicGlyph x="376" y="278" />
      <text fill="currentColor" x="402" y="292" fontSize="14" className="font-mono text-label">
        {NIC_LABEL}
      </text>
    </svg>
  );
}

function MobileDiagram() {
  return (
    <svg
      viewBox="0 0 360 580"
      className="block w-full lg:hidden"
      role="presentation"
      aria-hidden="true"
    >
      <defs>
        <filter id="wall-glow-m" x="-20%" y="-60%" width="140%" height="220%">
          <feGaussianBlur stdDeviation="16" />
        </filter>
      </defs>

      {/* Host zone */}
      <text fill="currentColor" x="24" y="52" fontSize="25" letterSpacing="-0.01em" className="font-display text-title" fontWeight="700">
        {HOST_LABEL}
      </text>
      <text fill="currentColor" x="24" y="76" fontSize="14" className="font-mono text-label">
        {HOST_SUB}
      </text>

      <text fill="currentColor" x="180" y="172" textAnchor="middle" fontSize="12.5" letterSpacing="0.07em" className="font-mono text-label" fontWeight="600">
        {ENDPOINT_LABEL}
      </text>
      <text fill="currentColor" x="180" y="188" textAnchor="middle" fontSize="12" className="font-mono text-label" opacity="0.75">
        {ENDPOINT_SUB}
      </text>

      {/* Wall glow */}
      <rect x="20" y="196" width="320" height="108" className="text-accent" fill="currentColor" opacity="0.22" filter="url(#wall-glow-m)" />

      {/* The wall: two solid segments with one gap */}
      <rect x="24" y="216" width="126" height="70" className="text-accent" fill="currentColor" />
      <rect x="210" y="216" width="126" height="70" className="text-accent" fill="currentColor" />
      <rect x="150" y="216" width="60" height="70" rx="10" fill="var(--color-canvas)" stroke="var(--color-accent)" strokeWidth="3.5" />
      <LockGlyph x="180" y="255" />

      {/* vsock */}
      <line
        x1="180"
        y1="286"
        x2="180"
        y2="330"
        stroke="var(--color-accent-2)"
        strokeWidth="4"
        strokeDasharray="9 7"
        strokeLinecap="round"
        className="site-boundary-pulse"
      />
      <text fill="currentColor" x="196" y="312" fontSize="15" letterSpacing="0.05em" className="font-mono text-accent-2" fontWeight="700">
        {VSOCK_LABEL.toUpperCase()}
      </text>

      {/* Guest zone */}
      <text fill="currentColor" x="24" y="368" fontSize="25" letterSpacing="-0.01em" className="font-display text-title" fontWeight="700">
        {GUEST_LABEL}
      </text>
      <text fill="currentColor" x="24" y="390" fontSize="14" className="font-mono text-label">
        {GUEST_SUB}
      </text>

      <rect x="24" y="408" width="312" height="66" rx="10" fill="var(--color-raised-2)" stroke="currentColor" className="text-edge" strokeWidth="1.5" />
      <text fill="currentColor" x="180" y="447" textAnchor="middle" fontSize="16.5" className="font-mono text-emphasis" fontWeight="600">
        {KERNEL_LABEL}
      </text>

      <rect x="24" y="488" width="312" height="66" rx="10" fill="var(--color-raised-2)" stroke="currentColor" className="text-edge" strokeWidth="1.5" />
      <text fill="currentColor" x="180" y="527" textAnchor="middle" fontSize="16.5" className="font-mono text-emphasis" fontWeight="600">
        {ROOTFS_LABEL}
      </text>

      <NoNicGlyph x="24" y="562" />
      <text fill="currentColor" x="50" y="576" fontSize="14" className="font-mono text-label">
        {NIC_LABEL}
      </text>
    </svg>
  );
}

export function BoundaryDiagram() {
  return (
    <figure className="w-full" role="img" aria-label={DESCRIPTION}>
      <DesktopDiagram />
      <MobileDiagram />
    </figure>
  );
}
