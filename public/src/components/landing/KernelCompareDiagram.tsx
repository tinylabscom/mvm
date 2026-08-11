// The visual half of "why not a container": two small panels, same scale,
// same stroke vocabulary as BoundaryDiagram (hairline 1.5 / feature 3),
// so the reader recognises the wall from the hero without re-reading a
// legend. The container panel has no wall at all — three workloads sit
// directly on one shared kernel box, separated only by hairlines, because
// that boundary is a namespace, not a hypervisor. The microVM panel is a
// condensed re-statement of BoundaryDiagram's guest zone: its own kernel
// box, sealed behind the same solid accent-3 wall.
//
// Two <svg> trees side by side (stacked on mobile via the wrapping flex
// container, not a second reflow), each `role="presentation" aria-hidden`,
// with one real text alternative on the wrapping <figure>.

const HAIRLINE = 1.5;
const FEATURE = 3;
const RADIUS = 8;

const DESCRIPTION =
  "Comparison diagram. Left: a container — three workloads sit directly on " +
  "one shared host kernel box, separated only by thin process boundaries. " +
  "Right: an mvm microVM — a solid wall separates the host from a guest " +
  "that has its own kernel, not a shared one.";

function ContainerPanel() {
  return (
    <svg viewBox="0 0 260 200" className="w-full" role="presentation" aria-hidden="true">
      <text fill="currentColor" x="8" y="22" fontSize="13" letterSpacing="0.04em" className="font-mono text-label" fontWeight="600">
        container
      </text>

      {/* Three workloads, each just a hairline box — no wall between them
          and the kernel, because there isn't one. */}
      {[8, 96, 184].map((x) => (
        <rect
          key={x}
          x={x}
          y={40}
          width={68}
          height={40}
          rx={RADIUS}
          fill="none"
          stroke="currentColor"
          className="text-edge"
          strokeWidth={HAIRLINE}
        />
      ))}
      <text fill="currentColor" x="42" y="64" textAnchor="middle" fontSize="11" className="font-mono text-label">
        app
      </text>
      <text fill="currentColor" x="130" y="64" textAnchor="middle" fontSize="11" className="font-mono text-label">
        app
      </text>
      <text fill="currentColor" x="218" y="64" textAnchor="middle" fontSize="11" className="font-mono text-label">
        app
      </text>

      {/* Dashed hairline drops — a namespace boundary, not a hypervisor. */}
      {[42, 130, 218].map((x) => (
        <line
          key={x}
          x1={x}
          y1={80}
          x2={x}
          y2={106}
          stroke="currentColor"
          className="text-edge"
          strokeWidth={HAIRLINE}
          strokeDasharray="3 3"
        />
      ))}

      <rect
        x="8"
        y="106"
        width="244"
        height="54"
        rx={RADIUS}
        fill="var(--color-raised-2)"
        stroke="currentColor"
        className="text-edge"
        strokeWidth={HAIRLINE}
      />
      <text fill="currentColor" x="130" y="138" textAnchor="middle" fontSize="13" className="font-mono text-emphasis" fontWeight="600">
        host kernel (shared)
      </text>
    </svg>
  );
}

function MicroVmPanel() {
  return (
    <svg viewBox="0 0 260 200" className="w-full" role="presentation" aria-hidden="true">
      <text fill="currentColor" x="8" y="22" fontSize="13" letterSpacing="0.04em" className="font-mono text-label" fontWeight="600">
        mvm microVM
      </text>

      <text fill="currentColor" x="8" y="60" fontSize="12" className="font-mono text-label">
        host
      </text>

      {/* The wall — same accent-3, same solid fill, as BoundaryDiagram's
          hero figure. Deliberately unbroken here: this panel isn't about
          the substitution endpoint, it's about the kernel boundary. */}
      <rect x="76" y="30" width="26" height="140" className="text-accent-3" fill="currentColor" />

      <rect
        x="118"
        y="40"
        width="134"
        height="54"
        rx={RADIUS}
        fill="var(--color-raised-2)"
        stroke="currentColor"
        className="text-edge"
        strokeWidth={HAIRLINE}
      />
      <text fill="currentColor" x="185" y="72" textAnchor="middle" fontSize="13" className="font-mono text-emphasis" fontWeight="600">
        own kernel
      </text>

      <rect
        x="118"
        y="106"
        width="134"
        height="54"
        rx={RADIUS}
        fill="var(--color-raised-2)"
        stroke="currentColor"
        className="text-edge"
        strokeWidth={HAIRLINE}
      />
      <text fill="currentColor" x="185" y="138" textAnchor="middle" fontSize="12.5" className="font-mono text-emphasis" fontWeight="600">
        own rootfs
      </text>

      <text fill="currentColor" x="8" y="182" fontSize="12" className="font-mono text-label">
        guest
      </text>
    </svg>
  );
}

export function KernelCompareDiagram() {
  return (
    <figure className="w-full" role="img" aria-label={DESCRIPTION}>
      <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 sm:gap-4">
        <div className="rounded-xl border border-edge/40 p-4">
          <ContainerPanel />
        </div>
        <div className="rounded-xl border border-edge/40 p-4">
          <MicroVmPanel />
        </div>
      </div>
    </figure>
  );
}
