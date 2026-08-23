# One tracker now owns the rest of the FlowMux cutover

PR #2741 removed the relayed-vsock host-first handshake deadlock. It did not
finish the broader single-path architecture: limits are still instantiated as
per-session defaults, typed HTTP still crosses a whole-message compatibility
seam, declared ingress is contract-only, and the frozen L3 implementation and
its rejected public configuration remain in the source tree.

Issue #2751 and `specs/plans/2026-08-19-flowmux-single-path-closeout.md` now own
that remainder in dependency order. The old Plan 316 phase issues remain closed
historical records; they are not evidence that Phases 4–8 landed. The closeout
order is shared per-VM limits, performance baselines, streaming transformations
and endpoint-owned connectors, declared ingress, public raw-mode removal, L3
deletion, permanent invariant gates, then the cross-backend evidence matrix.

This entry changes tracking only. It does not claim that any of those runtime
workstreams is complete.

W3 verification keeps its host-side performance probe on the narrow
`mvm-agentd/flowmux-client` feature. The probe therefore exercises the same
FlowMux client without pulling the guest addon bundle's vsock transport into
the host dependency graph; the duplicate-major invariant remains clean.

W1 through W7 have since landed on the closeout stack: shared limits, bounded
typed transformations, endpoint-owned connectors, declared ingress, public
raw-mode removal, L3 deletion, and permanent single-path gates are complete.
W8 remains in progress. Its first post-deletion macOS arm64 performance report
passes 12 of 32 comparisons and retains all 20 misses rather than weakening a
threshold. No owner exception has been approved. The host workspace suite and
all doctests pass on the integrated W8 tree; cross-backend live evidence and
the final repository matrix remain the closeout conditions.
