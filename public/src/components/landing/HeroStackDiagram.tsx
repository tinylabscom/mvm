// Concept A — a vertical cross-section of the real execution stack, read
// bottom to top: your hardware -> host kernel -> hypervisor -> [the seam] ->
// guest kernel -> guest userspace -> your workload. This is the product's
// core claim shown positionally instead of asserted in prose: the workload
// sits above its OWN kernel, not the host's, and there is exactly one
// crossing point in the whole stack.
//
// Same three-color discipline as BoundaryDiagram: the seam owns
// `--color-accent-3` (its own identity, distinct from the hero CTA's
// `--color-accent`), vsock owns `--color-accent-2`. Everything else is
// `--color-raised-2` at a fill-opacity that climbs from top (workload,
// lightest) to bottom (hardware, densest) — the "elevation" cue asked for
// in the brief, done with one fill and one opacity ramp rather than a
// second palette. Hardware additionally gets a diagonal hatch overlay: the
// only band dense enough to earn actual texture, not just weight.
//
// Two <svg> trees (desktop / mobile), same convention as BoundaryDiagram,
// sharing one JS layout table so the two can't drift out of sync with each
// other the way two hand-duplicated coordinate sets would.

const HAIRLINE = 1.5;
const FEATURE = 3;
const RADIUS = 10;

type Band = {
  key: string;
  label: string;
  sub: string;
  fillOpacity: number;
  strokeOpacity: number;
  strokeWidth: number;
};

// Bottom to top in the real stack; drawn top to bottom in SVG y, so this
// array is reversed at render time. fillOpacity/strokeOpacity/strokeWidth
// all climb together toward the bottom — three cues for one idea (density),
// not three unrelated ones, so the eye reads "heavier" without needing a
// legend.
const BANDS: Band[] = [
  { key: "hardware", label: "your hardware", sub: "CPU · KVM / HVF", fillOpacity: 1, strokeOpacity: 1, strokeWidth: FEATURE },
  { key: "host-kernel", label: "host kernel", sub: "shared by every guest above", fillOpacity: 0.8, strokeOpacity: 0.9, strokeWidth: 2.5 },
  { key: "hypervisor", label: "hypervisor", sub: "HVF · libkrun · Firecracker", fillOpacity: 0.62, strokeOpacity: 0.78, strokeWidth: 2 },
  { key: "guest-kernel", label: "guest kernel", sub: "own kernel · own rootfs · no NIC", fillOpacity: 0.4, strokeOpacity: 0.62, strokeWidth: HAIRLINE },
  { key: "guest-userspace", label: "guest userspace", sub: "your process, fully isolated", fillOpacity: 0.24, strokeOpacity: 0.48, strokeWidth: HAIRLINE },
  { key: "workload", label: "your workload", sub: "untrusted code", fillOpacity: 0.1, strokeOpacity: 0.36, strokeWidth: HAIRLINE },
];

const DESCRIPTION =
  "Cross-section of the mvm execution stack, read bottom to top: your " +
  "hardware, host kernel, and hypervisor sit below a single boundary; the " +
  "guest kernel, guest userspace, and your workload sit above it, on a " +
  "kernel of their own rather than the host's. The one gap in the boundary " +
  "is a vsock channel into a deny-all-by-default substitution endpoint; " +
  "the guest has no network interface.";

/** Diagonal hatch texture — reserved for the densest (hardware) band. */
function Hatch({ id }: { id: string }) {
  return (
    <pattern id={id} width="9" height="9" patternTransform="rotate(45)" patternUnits="userSpaceOnUse">
      <line x1="0" y1="0" x2="0" y2="9" stroke="currentColor" strokeWidth={HAIRLINE} />
    </pattern>
  );
}

/** No-NIC glyph, matching BoundaryDiagram's mark so the two figures read as one visual family. */
function NoNicGlyph({ x, y, size = 15 }: { x: number; y: number; size?: number }) {
  const s = size / 14;
  return (
    <g transform={`translate(${x} ${y}) scale(${s})`} aria-hidden="true">
      <circle cx={7} cy={7} r={6} fill="none" stroke="currentColor" strokeWidth={HAIRLINE} />
      <path d="M4 9.5 7 5l3 4.5" fill="none" stroke="currentColor" strokeWidth={HAIRLINE} strokeLinecap="round" strokeLinejoin="round" />
      <line x1={1.5} y1={1.5} x2={12.5} y2={12.5} stroke="currentColor" strokeWidth={HAIRLINE} strokeLinecap="round" />
    </g>
  );
}

function LockGlyph({ x, y }: { x: number; y: number }) {
  return (
    <g transform={`translate(${x} ${y})`} className="text-accent-3" aria-hidden="true">
      <path d="M-3.6 -1 v-2.4 a3.6 3.6 0 0 1 7.2 0 v2.4" fill="none" stroke="currentColor" strokeWidth={FEATURE} strokeLinecap="round" />
      <rect x={-5.5} y={-1} width={11} height={8.5} rx={1.8} fill="none" stroke="currentColor" strokeWidth={FEATURE} />
    </g>
  );
}

/** Shared layout — one table, two renderers. `bandH`/`gap`/`seamH` are in
 *  local SVG units; each renderer supplies its own so desktop can run
 *  wider/roomier and mobile narrower without touching the band content. */
function layout(bandH: number, gap: number, seamH: number, seamGap: number, topMargin: number) {
  const order = [...BANDS].reverse(); // workload first (top) -> hardware last (bottom)
  const rows: { band: Band; y: number; h: number }[] = [];
  let y = topMargin;
  for (let i = 0; i < order.length; i++) {
    const band = order[i];
    const isHardware = band.key === "hardware";
    const h = isHardware ? bandH + 12 : bandH;
    rows.push({ band, y, h });
    y += h + gap;
    if (i === 2) {
      // The seam gets its own reserved slot between guest-kernel (i===2)
      // and hypervisor (i===3), with extra breathing room on both sides.
      y += seamGap;
    }
  }
  const seamY = rows[2].y + rows[2].h + gap + seamGap / 2 - seamH / 2;
  return { rows, seamY };
}

function StackBand({
  x,
  width,
  row,
  labelSize,
  subSize,
  hatchId,
}: {
  x: number;
  width: number;
  row: { band: Band; y: number; h: number };
  labelSize: number;
  subSize: number;
  hatchId: string;
}) {
  const { band, y, h } = row;
  const cy = y + h / 2;
  return (
    <g>
      <rect
        x={x}
        y={y}
        width={width}
        height={h}
        rx={RADIUS}
        fill="var(--color-raised-2)"
        fillOpacity={band.fillOpacity}
        stroke="currentColor"
        className="text-edge"
        strokeWidth={row.band.strokeWidth}
        strokeOpacity={band.strokeOpacity}
      />
      {band.key === "hardware" && (
        <rect x={x} y={y} width={width} height={h} rx={RADIUS} fill={`url(#${hatchId})`} opacity={0.5} className="text-edge" />
      )}
      <text
        fill="currentColor"
        x={x + width / 2}
        y={cy - (band.sub ? 4 : -5)}
        textAnchor="middle"
        fontSize={labelSize}
        letterSpacing="0.01em"
        className="font-mono text-emphasis"
        fontWeight="600"
      >
        {band.label}
      </text>
      {band.sub && (
        <text
          fill="currentColor"
          x={x + width / 2}
          y={cy + subSize + 3}
          textAnchor="middle"
          fontSize={subSize}
          className="font-mono text-label"
        >
          {band.sub}
        </text>
      )}
    </g>
  );
}

function Seam({
  x,
  width,
  y,
  h,
  gateWidth,
  glowId,
  desktop,
}: {
  x: number;
  width: number;
  y: number;
  h: number;
  gateWidth: number;
  glowId: string;
  desktop: boolean;
}) {
  const midX = x + width / 2;
  const gateX = midX - gateWidth / 2;
  // vsock line runs a bit past the seam into the bands on either side.
  const vTop = y - 10;
  const vBottom = y + h + 10;

  return (
    <g>
      {/* Glow — the seam is the diagram's focal point, so it gets the same
          soft light-spill treatment BoundaryDiagram gives its wall. */}
      <rect x={x - 10} y={y - 14} width={width + 20} height={h + 28} className="text-accent-3" fill="currentColor" opacity="0.2" filter={`url(#${glowId})`} />

      {/* vsock — full length, drawn behind the gate so the gate visually
          interrupts it (enters from the hypervisor side, exits into the
          guest-kernel side). */}
      <line
        x1={midX}
        y1={vTop}
        x2={midX}
        y2={vBottom}
        stroke="var(--color-accent-2)"
        strokeWidth={FEATURE + 1}
        strokeDasharray="8 6"
        strokeLinecap="round"
        className="site-boundary-pulse"
      />

      {/* Two solid seam segments, gap for the gate. */}
      <rect x={x} y={y} width={gateX - x} height={h} rx={RADIUS} className="text-accent-3" fill="currentColor" />
      <rect x={gateX + gateWidth} y={y} width={x + width - (gateX + gateWidth)} height={h} rx={RADIUS} className="text-accent-3" fill="currentColor" />

      {/* Gate — canvas background so text stays legible over the seam's
          solid fill, exactly BoundaryDiagram's contrast solution. */}
      <rect x={gateX} y={y} width={gateWidth} height={h} rx={RADIUS} fill="var(--color-canvas)" stroke="var(--color-accent-3)" strokeWidth={FEATURE} />
      <text
        fill="currentColor"
        x={midX}
        y={y + h / 2 - (desktop ? 10 : 8)}
        textAnchor="middle"
        fontSize={desktop ? 14 : 12.5}
        letterSpacing="0.05em"
        className="font-mono text-accent-2"
        fontWeight="700"
      >
        VSOCK
      </text>
      <text
        fill="currentColor"
        x={midX}
        y={y + h / 2 + (desktop ? 8 : 7)}
        textAnchor="middle"
        fontSize={12}
        className="font-mono text-label"
      >
        the only crossing
      </text>
      <LockGlyph x={midX} y={y + h / 2 + (desktop ? 24 : 21)} />
    </g>
  );
}

function DesktopStack() {
  const bandH = 58;
  const gap = 10;
  const seamH = 78;
  const seamGap = 84;
  const topMargin = 20;
  const x = 20;
  const width = 520;
  const { rows, seamY } = layout(bandH, gap, seamH, seamGap, topMargin);
  const bottom = rows[rows.length - 1].y + rows[rows.length - 1].h;
  const viewH = bottom + 20;

  return (
    <svg viewBox={`0 0 560 ${viewH}`} className="hidden w-full lg:block" role="presentation" aria-hidden="true">
      <defs>
        <filter id="stack-wall-glow" x="-60%" y="-40%" width="220%" height="180%">
          <feGaussianBlur stdDeviation="14" />
        </filter>
        <Hatch id="stack-hatch" />
      </defs>
      {rows.map((row, i) =>
        i === 3 ? (
          <g key={row.band.key}>
            <Seam x={x} width={width} y={seamY} h={seamH} gateWidth={148} glowId="stack-wall-glow" desktop />
            <StackBand x={x} width={width} row={row} labelSize={16} subSize={12.5} hatchId="stack-hatch" />
          </g>
        ) : (
          <StackBand key={row.band.key} x={x} width={width} row={row} labelSize={16} subSize={12.5} hatchId="stack-hatch" />
        ),
      )}
      <NoNicGlyph x={x + width - 26} y={rows[2].y + 12} />
    </svg>
  );
}

function MobileStack() {
  const bandH = 56;
  const gap = 10;
  const seamH = 74;
  const seamGap = 80;
  const topMargin = 18;
  const x = 18;
  const width = 304;
  const { rows, seamY } = layout(bandH, gap, seamH, seamGap, topMargin);
  const bottom = rows[rows.length - 1].y + rows[rows.length - 1].h;
  const viewH = bottom + 18;

  return (
    <svg viewBox={`0 0 340 ${viewH}`} className="block w-full lg:hidden" role="presentation" aria-hidden="true">
      <defs>
        <filter id="stack-wall-glow-m" x="-40%" y="-40%" width="180%" height="180%">
          <feGaussianBlur stdDeviation="12" />
        </filter>
        <Hatch id="stack-hatch-m" />
      </defs>
      {rows.map((row, i) =>
        i === 3 ? (
          <g key={row.band.key}>
            <Seam x={x} width={width} y={seamY} h={seamH} gateWidth={128} glowId="stack-wall-glow-m" desktop={false} />
            <StackBand x={x} width={width} row={row} labelSize={14} subSize={12} hatchId="stack-hatch-m" />
          </g>
        ) : (
          <StackBand key={row.band.key} x={x} width={width} row={row} labelSize={14} subSize={12} hatchId="stack-hatch-m" />
        ),
      )}
      <NoNicGlyph x={x + width - 24} y={rows[2].y + 12} size={13} />
    </svg>
  );
}

export function HeroStackDiagram() {
  return (
    <figure className="w-full" role="img" aria-label={DESCRIPTION}>
      <DesktopStack />
      <MobileStack />
    </figure>
  );
}
