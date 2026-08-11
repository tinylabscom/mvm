// Concept B — the matryoshka containment model (see
// content/docs/security/matryoshka.md): your machine contains the
// hypervisor, which contains the microVM, which contains its own kernel,
// which contains your workload. vsock is drawn as the single channel that
// pierces every ring on its way in — the same "exactly one crossing" fact
// HeroStackDiagram makes positionally, made here as a single perforation.
//
// Deliberately not bullseye circles: each frame is a rounded rect, nested
// with asymmetric insets (more room top-left than bottom-right) so the
// stack reads as offset, layered cards rather than a dartboard, and every
// label sits on a tab overlapping its own ring's border — like a folder
// tab — instead of floating centered in empty space.

const HAIRLINE = 1.5;
const FEATURE = 3;
const RADIUS_STEP = 3; // each inner ring's corner radius shrinks a touch

type Ring = {
  key: string;
  label: string;
  sub?: string;
};

const RINGS: Ring[] = [
  { key: "machine", label: "your machine", sub: "macOS · Linux" },
  { key: "hypervisor", label: "hypervisor", sub: "HVF · libkrun · Firecracker" },
  { key: "microvm", label: "microVM", sub: "no NIC" },
  { key: "kernel", label: "its own kernel", sub: "own rootfs" },
];

const DESCRIPTION =
  "The matryoshka containment model. Your machine contains the hypervisor, " +
  "which contains a microVM, which contains its own guest kernel, which " +
  "contains your untrusted workload — four nested boundaries. A single " +
  "vsock channel pierces all four rings from the outside straight through " +
  "to the workload; it is the only way in or out, ending at a deny-all " +
  "substitution endpoint. The guest has no network interface of its own.";

function LockGlyph({ x, y, scale = 1 }: { x: number; y: number; scale?: number }) {
  return (
    <g transform={`translate(${x} ${y}) scale(${scale})`} className="text-accent-3" aria-hidden="true">
      <path d="M-3.6 -1 v-2.4 a3.6 3.6 0 0 1 7.2 0 v2.4" fill="none" stroke="currentColor" strokeWidth={FEATURE} strokeLinecap="round" />
      <rect x={-5.5} y={-1} width={11} height={8.5} rx={1.8} fill="none" stroke="currentColor" strokeWidth={FEATURE} />
    </g>
  );
}

/** A folder-tab label anchored to a ring's top-left corner, sitting half
 *  on / half off the border so it reads as attached to that specific
 *  ring rather than floating in the frame's empty interior. */
function RingTab({
  x,
  y,
  label,
  sub,
  labelSize,
  subSize,
  emphasis,
}: {
  x: number;
  y: number;
  label: string;
  sub?: string;
  labelSize: number;
  subSize: number;
  emphasis?: boolean;
}) {
  return (
    <g>
      <text
        fill="currentColor"
        x={x}
        y={y}
        fontSize={labelSize}
        letterSpacing="0.01em"
        className={emphasis ? "font-display text-title" : "font-mono text-emphasis"}
        fontWeight={emphasis ? 700 : 600}
      >
        {label}
      </text>
      {sub && (
        <text fill="currentColor" x={x} y={y + subSize + 4} fontSize={subSize} className="font-mono text-label">
          {sub}
        </text>
      )}
    </g>
  );
}

type RingRect = { x: number; y: number; w: number; h: number; rx: number };

/** Nested, asymmetrically-inset rects: more room is taken from the
 *  top-left on each step in than the bottom-right, so the stack drifts
 *  toward the bottom-right corner rather than staying perfectly centered —
 *  the "offset nesting" that keeps this from reading as a bullseye. */
function nestedRects(outer: RingRect, count: number, insetTL: number, insetBR: number): RingRect[] {
  const rects: RingRect[] = [outer];
  let cur = outer;
  for (let i = 1; i < count; i++) {
    cur = {
      x: cur.x + insetTL,
      y: cur.y + insetTL,
      w: cur.w - insetTL - insetBR,
      h: cur.h - insetTL - insetBR,
      rx: Math.max(4, cur.rx - RADIUS_STEP),
    };
    rects.push(cur);
  }
  return rects;
}

function NestDiagram({
  viewBox,
  outer,
  insetTL,
  insetBR,
  workload,
  vsockStartY,
  labelSize,
  subSize,
  workloadLabelSize,
  tabInset,
  className,
}: {
  viewBox: string;
  outer: RingRect;
  insetTL: number;
  insetBR: number;
  workload: { w: number; h: number };
  vsockStartY: number;
  labelSize: number;
  subSize: number;
  workloadLabelSize: number;
  tabInset: number;
  className: string;
}) {
  const rects = nestedRects(outer, RINGS.length, insetTL, insetBR);
  const kernelRect = rects[rects.length - 1];
  // Workload sits inside the innermost (kernel) ring, anchored below that
  // ring's own tab (so it never collides with the label) and biased toward
  // the bottom-right — the same drift direction as the rings around it,
  // not centered.
  const kernelLabelBlockH = tabInset + labelSize * 0.7 + subSize + 22;
  const workloadRect: RingRect = {
    x: kernelRect.x + kernelRect.w - workload.w - 14,
    y: kernelRect.y + kernelLabelBlockH,
    w: workload.w,
    h: workload.h,
    rx: Math.max(4, kernelRect.rx - RADIUS_STEP),
  };

  // vsock: one straight line from a point above the outer ring down to the
  // workload's top edge, crossing every ring's top border on the way. The
  // crossing points are computed by linearly interpolating along the same
  // line so the marker dots land exactly on it.
  const start = { x: outer.x + outer.w * 0.72, y: vsockStartY };
  const end = { x: workloadRect.x + workloadRect.w / 2, y: workloadRect.y };
  const crossings = rects.map((r) => {
    const t = (r.y - start.y) / (end.y - start.y);
    return { x: start.x + (end.x - start.x) * t, y: r.y };
  });

  const glowId = `nest-glow-${viewBox.replace(/\s+/g, "")}`;

  return (
    <svg viewBox={viewBox} className={className} role="presentation" aria-hidden="true">
      <defs>
        <filter id={glowId} x="-40%" y="-40%" width="180%" height="180%">
          <feGaussianBlur stdDeviation="12" />
        </filter>
      </defs>

      {/* Rings, outermost first so inner rings paint over/beside it. */}
      {rects.map((r, i) => (
        <rect
          key={RINGS[i].key}
          x={r.x}
          y={r.y}
          width={r.w}
          height={r.h}
          rx={r.rx}
          fill="var(--color-raised-2)"
          fillOpacity={0.05 + i * 0.11}
          stroke="currentColor"
          className="text-edge"
          strokeWidth={HAIRLINE}
        />
      ))}

      {/* vsock glow behind the workload — it's the thing being reached. */}
      <rect
        x={workloadRect.x - 14}
        y={workloadRect.y - 14}
        width={workloadRect.w + 28}
        height={workloadRect.h + 28}
        className="text-accent-3"
        fill="currentColor"
        opacity="0.18"
        filter={`url(#${glowId})`}
      />

      {/* vsock line, drawn behind the workload box so it visibly runs INTO
          it rather than stopping short. */}
      <line
        x1={start.x}
        y1={start.y}
        x2={end.x}
        y2={workloadRect.y + workloadRect.h / 2}
        stroke="var(--color-accent-2)"
        strokeWidth={FEATURE + 1}
        strokeDasharray="8 6"
        strokeLinecap="round"
        className="site-boundary-pulse"
      />
      {crossings.slice(1).map((c, i) => (
        <circle key={i} cx={c.x} cy={c.y} r={3.5} fill="var(--color-canvas)" stroke="var(--color-accent-2)" strokeWidth={HAIRLINE} />
      ))}

      {/* Workload — the innermost, genuinely-enclosed element. Distinct
          fill so it reads as the thing everything else exists to contain. */}
      <rect
        x={workloadRect.x}
        y={workloadRect.y}
        width={workloadRect.w}
        height={workloadRect.h}
        rx={workloadRect.rx}
        fill="var(--color-canvas)"
        stroke="var(--color-accent-3)"
        strokeWidth={FEATURE}
      />
      <text
        fill="currentColor"
        x={workloadRect.x + workloadRect.w / 2}
        y={workloadRect.y + workloadRect.h / 2 - 3}
        textAnchor="middle"
        fontSize={workloadLabelSize}
        className="font-mono text-emphasis"
        fontWeight="700"
      >
        your workload
      </text>
      <text
        fill="currentColor"
        x={workloadRect.x + workloadRect.w / 2}
        y={workloadRect.y + workloadRect.h / 2 + subSize + 3}
        textAnchor="middle"
        fontSize={Math.max(12, subSize - 0.5)}
        className="font-mono text-label"
      >
        untrusted code
      </text>

      {/* vsock label, directly above where the line originates — the
          margin above `outer.y` is reserved for exactly this. Sits above
          the start point rather than below it so the dashed line never
          runs through the letterforms. */}
      <text
        fill="currentColor"
        x={start.x}
        y={start.y - 5}
        textAnchor="middle"
        fontSize={labelSize - 1}
        letterSpacing="0.05em"
        className="font-mono text-accent-2"
        fontWeight="700"
      >
        VSOCK
      </text>
      <circle cx={start.x} cy={start.y} r={2.5} fill="var(--color-accent-2)" />
      {/* Lock — sits right at the workload box's top edge, where the line
          meets it; the same "one guarded door" motif as the stack
          diagram's gate. `kernelLabelBlockH` already reserves clearance
          between the ring's tab and this point, so it never crowds the
          "own rootfs" subtitle above it. */}
      <LockGlyph x={end.x} y={workloadRect.y} scale={0.85} />

      {/* Ring tabs — each on its own ring's top-left corner. */}
      {rects.map((r, i) => (
        <RingTab
          key={RINGS[i].key}
          x={r.x + tabInset}
          y={r.y + tabInset + labelSize * 0.7}
          label={RINGS[i].label}
          sub={RINGS[i].sub}
          labelSize={i === 0 ? labelSize + 2 : labelSize}
          subSize={subSize}
          emphasis={i === 0}
        />
      ))}
    </svg>
  );
}

function DesktopNest() {
  return (
    <NestDiagram
      viewBox="0 0 560 460"
      outer={{ x: 16, y: 42, w: 528, h: 402, rx: 20 }}
      insetTL={34}
      insetBR={54}
      workload={{ w: 168, h: 74 }}
      vsockStartY={18}
      labelSize={15}
      subSize={12}
      workloadLabelSize={15}
      tabInset={16}
      className="hidden w-full lg:block"
    />
  );
}

function MobileNest() {
  return (
    <NestDiagram
      viewBox="0 0 340 460"
      outer={{ x: 10, y: 42, w: 320, h: 402, rx: 18 }}
      insetTL={26}
      insetBR={38}
      workload={{ w: 100, h: 62 }}
      vsockStartY={18}
      labelSize={13}
      subSize={12}
      workloadLabelSize={13.5}
      tabInset={12}
      className="block w-full lg:hidden"
    />
  );
}

export function HeroNestDiagram() {
  return (
    <figure className="w-full" role="img" aria-label={DESCRIPTION}>
      <DesktopNest />
      <MobileNest />
    </figure>
  );
}
