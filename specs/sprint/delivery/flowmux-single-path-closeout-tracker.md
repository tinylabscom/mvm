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
