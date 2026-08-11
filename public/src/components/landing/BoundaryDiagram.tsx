// The hero's visual anchor. This is not decoration bolted onto the pitch —
// it IS the pitch: a container shares the host kernel, mvm does not. The
// diagram draws exactly what Architecture.tsx and Security.tsx already
// claim (own kernel, own rootfs, no guest NIC, vsock-only, default-deny
// substitution endpoint) and nothing else. If a fact here ever drifts from
// those sections, the diagram is wrong, not them.
//
// Design intent (round 3 — crispness pass): three colors, each owned by one
// thing, never two. The wall/gate/lock are `--color-accent-3` — the hero's
// primary CTA button is `--color-accent`, so the diagram no longer ties
// with "Get Started" for brightest-object-on-screen; the boundary gets its
// own identity color instead of the button stepping back (it's still the
// conversion action). vsock stays `--color-accent-2`, distinct from both.
//
// Stroke weights are a closed set of three, used consistently everywhere:
// 1.5 (hairline: box borders, small icons, the endpoint leader), 3 (feature:
// the gate border, the lock glyph), 4 (channel: vsock, deliberately the
// thickest line in the figure since it's the only crossing). Corner radii
// are a single value (10) on every rounded rect. The vsock line is drawn
// full-length *behind* the gate rect so the opaque gate visually interrupts
// it — it reads as one channel entering the gate from the host side and
// exiting toward the guest, not a stub that starts at the gate.
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
  "channel that crosses through it, from either side, is vsock.";

const HAIRLINE = 1.5;
const FEATURE = 3;
const CHANNEL = 4;
const RADIUS = 10;

/** No-NIC glyph: a network dish with a strike through it. */
function NoNicGlyph({ x, y, size = 18 }: { x: number; y: number; size?: number }) {
  const s = size / 14;
  return (
    <g transform={`translate(${x} ${y}) scale(${s})`} className="text-label" aria-hidden="true">
      <circle cx={7} cy={7} r={6} fill="none" stroke="currentColor" strokeWidth={HAIRLINE} />
      <path d="M4 9.5 7 5l3 4.5" fill="none" stroke="currentColor" strokeWidth={HAIRLINE} strokeLinecap="round" strokeLinejoin="round" />
      <line x1={1.5} y1={1.5} x2={12.5} y2={12.5} stroke="currentColor" strokeWidth={HAIRLINE} strokeLinecap="round" />
    </g>
  );
}

/** Padlock glyph marking the one gap in the wall. */
function LockGlyph({ x, y }: { x: number; y: number }) {
  return (
    <g transform={`translate(${x} ${y})`} className="text-accent-3" aria-hidden="true">
      <circle cx={0} cy={-3.5} r={7.5} fill="none" stroke="currentColor" strokeWidth={FEATURE} />
      <path d="M0 4v7.5M-5 11.5h10" stroke="currentColor" strokeWidth={FEATURE} strokeLinecap="round" />
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
      <rect x="234" y="30" width="132" height="340" className="text-accent-3" fill="currentColor" opacity="0.22" filter="url(#wall-glow)" />

      {/* The wall itself: two solid, hard-edged segments with one gap —
          the endpoint — cut into it. This is the diagram's dominant
          element by design: thickest shape, highest-contrast fill, first
          thing the eye should land on. Owns `accent-3`, distinct from the
          hero's CTA button (`accent`) and vsock (`accent-2`). */}
      <rect x="264" y="30" width="72" height="120" className="text-accent-3" fill="currentColor" />
      <rect x="264" y="250" width="72" height="120" className="text-accent-3" fill="currentColor" />

      {/* vsock — drawn full-length behind the gate, so the gate visually
          interrupts it: the line enters from the host side, disappears
          under the gate, and continues on the guest side, reading as one
          channel passing *through* the endpoint rather than a stub that
          starts at it. */}
      <line
        x1="230"
        y1="200"
        x2="376"
        y2="200"
        stroke="var(--color-accent-2)"
        strokeWidth={CHANNEL}
        strokeDasharray="9 7"
        strokeLinecap="round"
        className="site-boundary-pulse"
      />

      {/* The gap — the one guarded door in the wall — painted over the
          vsock line's midsection. VSOCK's own label lives inside the gate,
          right above the lock, so the channel's name sits on the exact
          node it passes through instead of floating beside the line. */}
      <rect x="264" y="150" width="72" height="100" rx={RADIUS} fill="var(--color-canvas)" stroke="var(--color-accent-3)" strokeWidth={FEATURE} />
      <text fill="currentColor" x="300" y="176" textAnchor="middle" fontSize="14" letterSpacing="0.05em" className="font-mono text-accent-2" fontWeight="700">
        {VSOCK_LABEL.toUpperCase()}
      </text>
      <LockGlyph x="300" y="212" />

      {/* Endpoint label — tight to the gate, with a leader that ties it to
          the gate's left edge instead of floating near it. */}
      <text fill="currentColor" x="246" y="177" textAnchor="end" fontSize="13" letterSpacing="0.07em" className="font-mono text-emphasis" fontWeight="600">
        {ENDPOINT_LABEL}
      </text>
      <text fill="currentColor" x="246" y="193" textAnchor="end" fontSize="12.5" className="font-mono text-label">
        {ENDPOINT_SUB}
      </text>
      <line x1="250" y1="183" x2="264" y2="183" stroke="var(--color-accent-3)" strokeWidth={HAIRLINE} />
      <circle cx="264" cy="183" r="2.5" fill="var(--color-accent-3)" />

      {/* Host zone — label only; no bounding card, the wall does the
          separating. */}
      <text fill="currentColor" x="40" y="66" fontSize="27" letterSpacing="-0.01em" className="font-display text-title" fontWeight="700">
        {HOST_LABEL}
      </text>
      <text fill="currentColor" x="40" y="90" fontSize="14.5" className="font-mono text-label">
        {HOST_SUB}
      </text>

      {/* Guest zone */}
      <text fill="currentColor" x="376" y="66" fontSize="27" letterSpacing="-0.01em" className="font-display text-title" fontWeight="700">
        {GUEST_LABEL}
      </text>
      <text fill="currentColor" x="376" y="88" fontSize="14.5" className="font-mono text-label">
        {GUEST_SUB}
      </text>

      <rect x="376" y="108" width="212" height="66" rx={RADIUS} fill="var(--color-raised-2)" stroke="currentColor" className="text-edge" strokeWidth={HAIRLINE} />
      <text fill="currentColor" x="482" y="147" textAnchor="middle" fontSize="16.5" className="font-mono text-emphasis" fontWeight="600">
        {KERNEL_LABEL}
      </text>

      <rect x="376" y="188" width="212" height="66" rx={RADIUS} fill="var(--color-raised-2)" stroke="currentColor" className="text-edge" strokeWidth={HAIRLINE} />
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
      viewBox="0 0 360 600"
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

      {/* Endpoint label — centered above the gate, with a short leader
          dropping straight to the gate's top edge. */}
      <text fill="currentColor" x="180" y="160" textAnchor="middle" fontSize="12.5" letterSpacing="0.06em" className="font-mono text-emphasis" fontWeight="600">
        {ENDPOINT_LABEL}
      </text>
      <text fill="currentColor" x="180" y="176" textAnchor="middle" fontSize="12" className="font-mono text-label">
        {ENDPOINT_SUB}
      </text>
      <line x1="180" y1="182" x2="180" y2="196" stroke="var(--color-accent-3)" strokeWidth={HAIRLINE} />
      <circle cx="180" cy="196" r="2.5" fill="var(--color-accent-3)" />

      {/* Wall glow */}
      <rect x="20" y="196" width="320" height="108" className="text-accent-3" fill="currentColor" opacity="0.22" filter="url(#wall-glow-m)" />

      {/* The wall: two solid segments with one gap */}
      <rect x="24" y="216" width="126" height="70" className="text-accent-3" fill="currentColor" />
      <rect x="210" y="216" width="126" height="70" className="text-accent-3" fill="currentColor" />

      {/* vsock — emerges from the gate straight down to the guest zone;
          longer and heavier than the gap it crosses, so it reads as the
          deliberate channel rather than a connector stub. */}
      <line
        x1="180"
        y1="216"
        x2="180"
        y2="350"
        stroke="var(--color-accent-2)"
        strokeWidth={CHANNEL}
        strokeDasharray="9 7"
        strokeLinecap="round"
        className="site-boundary-pulse"
      />
      <text fill="currentColor" x="196" y="326" fontSize="15" letterSpacing="0.05em" className="font-mono text-accent-2" fontWeight="700">
        {VSOCK_LABEL.toUpperCase()}
      </text>

      <rect x="150" y="216" width="60" height="70" rx={RADIUS} fill="var(--color-canvas)" stroke="var(--color-accent-3)" strokeWidth={FEATURE} />
      <LockGlyph x="180" y="255" />

      {/* Guest zone */}
      <text fill="currentColor" x="24" y="388" fontSize="25" letterSpacing="-0.01em" className="font-display text-title" fontWeight="700">
        {GUEST_LABEL}
      </text>
      <text fill="currentColor" x="24" y="410" fontSize="14" className="font-mono text-label">
        {GUEST_SUB}
      </text>

      <rect x="24" y="428" width="312" height="66" rx={RADIUS} fill="var(--color-raised-2)" stroke="currentColor" className="text-edge" strokeWidth={HAIRLINE} />
      <text fill="currentColor" x="180" y="467" textAnchor="middle" fontSize="16.5" className="font-mono text-emphasis" fontWeight="600">
        {KERNEL_LABEL}
      </text>

      <rect x="24" y="508" width="312" height="66" rx={RADIUS} fill="var(--color-raised-2)" stroke="currentColor" className="text-edge" strokeWidth={HAIRLINE} />
      <text fill="currentColor" x="180" y="547" textAnchor="middle" fontSize="16.5" className="font-mono text-emphasis" fontWeight="600">
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
