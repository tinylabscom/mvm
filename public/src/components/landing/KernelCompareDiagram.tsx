// The visual half of "why not a container". Same visual language as
// HeroStackDiagram: two vertical stacks, bottom-to-top, identical band
// geometry (radius, stroke weights, opacity ramp), so a reader who has
// already seen the hero recognises this as the same system rather than a
// second, unrelated diagram.
//
// The two stacks share their bottom two bands exactly — hardware, host
// kernel — drawn at identical y-coordinates in both <svg> trees (bottom-up
// layout against a shared viewBox height) so the eye can register "these
// two rows are the same" without reading a label. Above that shared base
// they diverge at exactly one point:
//   - container: a permeable dashed line, then namespaces + cgroups — a
//     kernel *feature*, not a second kernel. The host kernel band is
//     already labelled "(shared)"; the dashed line makes that share
//     visible instead of asserted.
//   - mvm: a full hypervisor band, then the seam — the same solid
//     `--color-accent-3` wall as the hero's seam, so "seam" reads as one
//     colour-coded idea across the whole page — then a guest kernel band
//     that doesn't exist on the container side at all.
// mvm ends up taller by one band + the seam. That's deliberate: the extra
// layer is the thing being sold, not a rendering accident.

const HAIRLINE = 1.5;
const FEATURE = 3;
const RADIUS = 10;

type MiniBand = {
  key: string;
  label: string;
  sub?: string;
  fillOpacity: number;
  strokeOpacity: number;
  strokeWidth: number;
};

// Same density ramp as HeroStackDiagram's BANDS table: opacity + stroke
// weight climb together toward the bottom of the stack.
const HARDWARE: MiniBand = { key: "hardware", label: "hardware", sub: "CPU · memory · disk", fillOpacity: 1, strokeOpacity: 1, strokeWidth: FEATURE };
const HOST_KERNEL_SHARED: MiniBand = { key: "host-kernel-shared", label: "host kernel", sub: "shared by every container on the box", fillOpacity: 0.8, strokeOpacity: 0.9, strokeWidth: 2.5 };
const HOST_KERNEL_OWN: MiniBand = { key: "host-kernel", label: "host kernel", sub: "never shared with a guest", fillOpacity: 0.8, strokeOpacity: 0.9, strokeWidth: 2.5 };
const HYPERVISOR: MiniBand = { key: "hypervisor", label: "hypervisor", sub: "HVF · libkrun · Firecracker", fillOpacity: 0.62, strokeOpacity: 0.78, strokeWidth: 2 };
const NAMESPACES: MiniBand = { key: "namespaces", label: "namespaces + cgroups", sub: "a feature of the host kernel, not a second one", fillOpacity: 0.4, strokeOpacity: 0.62, strokeWidth: HAIRLINE };
const GUEST_KERNEL: MiniBand = { key: "guest-kernel", label: "guest kernel", sub: "its own — not the host's", fillOpacity: 0.4, strokeOpacity: 0.62, strokeWidth: HAIRLINE };
const APP: MiniBand = { key: "app", label: "your app", fillOpacity: 0.1, strokeOpacity: 0.36, strokeWidth: HAIRLINE };

type Row = { kind: "band"; band: MiniBand } | { kind: "seam" } | { kind: "divider" };

// Bottom to top — matches how the reader is told to read the stack.
const CONTAINER_ROWS: Row[] = [
  { kind: "band", band: HARDWARE },
  { kind: "band", band: HOST_KERNEL_SHARED },
  { kind: "divider" },
  { kind: "band", band: NAMESPACES },
  { kind: "band", band: APP },
];

const MVM_ROWS: Row[] = [
  { kind: "band", band: HARDWARE },
  { kind: "band", band: HOST_KERNEL_OWN },
  { kind: "band", band: HYPERVISOR },
  { kind: "seam" },
  { kind: "band", band: GUEST_KERNEL },
  { kind: "band", band: APP },
];

const DESCRIPTION =
  "Comparison of two stacks, read bottom to top. Both share the same " +
  "hardware and host kernel. A container stops there: namespaces and " +
  "cgroups are a permeable feature of that same shared kernel, and your " +
  "app sits directly on top. An mvm microVM adds a hypervisor and a solid " +
  "seam above the host kernel, then boots its own guest kernel above the " +
  "seam before your app runs — one more layer, and a hardware-assisted " +
  "boundary instead of a shared kernel.";

function rowHeight(row: Row, bandH: number, seamH: number, dividerH: number) {
  if (row.kind === "band") return row.band.key === "hardware" ? bandH + 10 : bandH;
  if (row.kind === "seam") return seamH;
  return dividerH;
}

/** Bottom-up layout so the shared base (hardware, host kernel) lands at the
 *  same y in both stacks regardless of how many rows sit above it. */
function layoutStack(rows: Row[], bandH: number, gap: number, seamH: number, dividerH: number, viewH: number, bottomMargin: number) {
  let y = viewH - bottomMargin;
  const laidOut: { row: Row; y: number; h: number }[] = [];
  for (const row of rows) {
    const h = rowHeight(row, bandH, seamH, dividerH);
    y -= h;
    laidOut.push({ row, y, h });
    y -= gap;
  }
  return laidOut;
}

function naturalHeight(rows: Row[], bandH: number, gap: number, seamH: number, dividerH: number) {
  let h = 0;
  for (const row of rows) h += rowHeight(row, bandH, seamH, dividerH) + gap;
  return h - gap;
}

function MiniBandRect({
  x,
  width,
  row,
  labelSize,
  subSize,
  hatchId,
}: {
  x: number;
  width: number;
  row: { row: Row; y: number; h: number };
  labelSize: number;
  subSize: number;
  hatchId: string;
}) {
  if (row.row.kind !== "band") return null;
  const { band } = row.row;
  const { y, h } = row;
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
        strokeWidth={band.strokeWidth}
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
        <text fill="currentColor" x={x + width / 2} y={cy + subSize + 3} textAnchor="middle" fontSize={subSize} className="font-mono text-label">
          {band.sub}
        </text>
      )}
    </g>
  );
}

/** The divergence marker on the container side: a dashed hairline the
 *  workload sits on top of — nothing actually separates it from the
 *  shared kernel below. Deliberately unstyled next to the seam so the
 *  contrast itself is the point. */
function Divider({ x, width, y, h }: { x: number; width: number; y: number; h: number }) {
  const midY = y + h / 2;
  return (
    <g>
      <line x1={x + 6} y1={midY} x2={x + width - 6} y2={midY} stroke="currentColor" className="text-edge" strokeWidth={HAIRLINE} strokeDasharray="4 4" />
      <text fill="currentColor" x={x + width / 2} y={midY - 6} textAnchor="middle" fontSize={10.5} letterSpacing="0.04em" className="font-mono text-dim">
        no boundary here
      </text>
    </g>
  );
}

/** The divergence marker on the mvm side: the same solid accent-3 seam as
 *  HeroStackDiagram, so "seam" reads as one colour-coded idea site-wide. */
function Seam({ x, width, y, h, glowId, labelSize }: { x: number; width: number; y: number; h: number; glowId: string; labelSize: number }) {
  const midX = x + width / 2;
  return (
    <g>
      <rect x={x - 8} y={y - 10} width={width + 16} height={h + 20} className="text-accent-3" fill="currentColor" opacity="0.2" filter={`url(#${glowId})`} />
      <rect x={x} y={y} width={width} height={h} rx={RADIUS} className="text-accent-3" fill="currentColor" />
      <text fill="currentColor" x={midX} y={y + h / 2 - 4} textAnchor="middle" fontSize={labelSize} letterSpacing="0.05em" className="font-mono text-canvas" fontWeight="700">
        SEAM
      </text>
      <text fill="currentColor" x={midX} y={y + h / 2 + 12} textAnchor="middle" fontSize={10.5} className="font-mono text-canvas" opacity={0.85}>
        hardware-assisted boundary
      </text>
    </g>
  );
}

function Stack({
  rows,
  x,
  width,
  bandH,
  gap,
  seamH,
  dividerH,
  viewH,
  bottomMargin,
  labelSize,
  subSize,
  hatchId,
  glowId,
}: {
  rows: Row[];
  x: number;
  width: number;
  bandH: number;
  gap: number;
  seamH: number;
  dividerH: number;
  viewH: number;
  bottomMargin: number;
  labelSize: number;
  subSize: number;
  hatchId: string;
  glowId: string;
}) {
  const laidOut = layoutStack(rows, bandH, gap, seamH, dividerH, viewH, bottomMargin);
  return (
    <>
      {laidOut.map((r) => {
        if (r.row.kind === "band") {
          return <MiniBandRect key={r.row.band.key} x={x} width={width} row={r} labelSize={labelSize} subSize={subSize} hatchId={hatchId} />;
        }
        if (r.row.kind === "seam") {
          return <Seam key="seam" x={x} width={width} y={r.y} h={r.h} glowId={glowId} labelSize={labelSize} />;
        }
        return <Divider key="divider" x={x} width={width} y={r.y} h={r.h} />;
      })}
    </>
  );
}

const BAND_H = 46;
const GAP = 8;
const SEAM_H = 52;
const DIVIDER_H = 30;
const BOTTOM_MARGIN = 8;
const TOP_MARGIN = 24;

// Shared viewBox height so both stacks' hardware/host-kernel bands land at
// the same y — the mvm stack is simply taller above that shared base.
const CONTAINER_H = naturalHeight(CONTAINER_ROWS, BAND_H, GAP, SEAM_H, DIVIDER_H);
const MVM_H = naturalHeight(MVM_ROWS, BAND_H, GAP, SEAM_H, DIVIDER_H);
const VIEW_H = Math.max(CONTAINER_H, MVM_H) + BOTTOM_MARGIN + TOP_MARGIN;

// The gap left above the container stack's shorter pile (it has no
// hypervisor, no seam, no guest kernel) reads as dead space unless it's
// doing something — so it carries the two layers container doesn't have,
// struck through, instead of sitting empty.
function AbsentLayers({ x, width, top, bottom }: { x: number; width: number; top: number; bottom: number }) {
  if (bottom - top < 40) return null;
  const midY = (top + bottom) / 2;
  const midX = x + width / 2;
  return (
    <g className="text-dim">
      <text fill="currentColor" x={midX} y={midY - 8} textAnchor="middle" fontSize={11} className="font-mono">
        no seam
      </text>
      <text fill="currentColor" x={midX} y={midY + 10} textAnchor="middle" fontSize={11} className="font-mono">
        no guest kernel
      </text>
    </g>
  );
}

function ContainerPanel() {
  const width = 232;
  const laidOut = layoutStack(CONTAINER_ROWS, BAND_H, GAP, SEAM_H, DIVIDER_H, VIEW_H, BOTTOM_MARGIN);
  const topOfStack = laidOut[laidOut.length - 1].y;
  return (
    <svg viewBox={`0 0 260 ${VIEW_H}`} className="w-full" role="presentation" aria-hidden="true">
      <defs>
        <Hatch id="cmp-hatch-container" />
      </defs>
      <text fill="currentColor" x="14" y="20" fontSize="13" letterSpacing="0.04em" className="font-mono text-label" fontWeight="600">
        container
      </text>
      <AbsentLayers x={14} width={width} top={34} bottom={topOfStack - 6} />
      <Stack
        rows={CONTAINER_ROWS}
        x={14}
        width={width}
        bandH={BAND_H}
        gap={GAP}
        seamH={SEAM_H}
        dividerH={DIVIDER_H}
        viewH={VIEW_H}
        bottomMargin={BOTTOM_MARGIN}
        labelSize={13}
        subSize={9.5}
        hatchId="cmp-hatch-container"
        glowId="cmp-glow-container"
      />
    </svg>
  );
}

function MvmPanel() {
  const width = 232;
  return (
    <svg viewBox={`0 0 260 ${VIEW_H}`} className="w-full" role="presentation" aria-hidden="true">
      <defs>
        <filter id="cmp-glow-mvm" x="-60%" y="-60%" width="220%" height="220%">
          <feGaussianBlur stdDeviation="10" />
        </filter>
        <Hatch id="cmp-hatch-mvm" />
      </defs>
      <text fill="currentColor" x="14" y="20" fontSize="13" letterSpacing="0.04em" className="font-mono text-label" fontWeight="600">
        mvm microVM
      </text>
      <Stack
        rows={MVM_ROWS}
        x={14}
        width={width}
        bandH={BAND_H}
        gap={GAP}
        seamH={SEAM_H}
        dividerH={DIVIDER_H}
        viewH={VIEW_H}
        bottomMargin={BOTTOM_MARGIN}
        labelSize={13}
        subSize={9.5}
        hatchId="cmp-hatch-mvm"
        glowId="cmp-glow-mvm"
      />
    </svg>
  );
}

/** Diagonal hatch texture — reserved for the densest (hardware) band, same
 *  treatment as HeroStackDiagram. */
function Hatch({ id }: { id: string }) {
  return (
    <pattern id={id} width="9" height="9" patternTransform="rotate(45)" patternUnits="userSpaceOnUse">
      <line x1="0" y1="0" x2="0" y2="9" stroke="currentColor" strokeWidth={HAIRLINE} />
    </pattern>
  );
}

export function KernelCompareDiagram() {
  return (
    <figure className="w-full" role="img" aria-label={DESCRIPTION}>
      <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 sm:gap-4">
        <div className="flex items-end rounded-xl border border-edge/40 p-4">
          <ContainerPanel />
        </div>
        <div className="flex items-end rounded-xl border border-edge/40 p-4">
          <MvmPanel />
        </div>
      </div>
    </figure>
  );
}
