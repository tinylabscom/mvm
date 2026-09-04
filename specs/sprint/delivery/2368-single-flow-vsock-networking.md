# Single flow-aware vsock networking path

Plan 316 / ADR-042 defines one external networking path for every untrusted
workload: guest loopback adapter → authenticated FlowMux session on
`GuestService::NetworkFlow` (vsock 5253) → one per-VM `mvm-network-endpoint` →
canonical policy, DNS, substitution/redaction, rate and audit pipeline →
host-originated socket or host-owned ingress listener. It is flow-aware at L4
with selective L7: opaque TCP/UDP is relayed unparsed, and transformation runs
only for a typed flow whose signed plan requires it. A plan requiring
transformation refuses an opaque shape rather than downgrading.

Phase 0 is complete: ADR-042 ratifies the invariant, supersedes ADR-036 and
ADR-052 for production workload networking, corrects the networking refactor
record, and freezes expansion of the retired L3 path. The temporary
`check-l3-expansion-freeze` ratchet fails on new production references outside
its shrinking allowlist. Synthesis, supervisor admission, and CLI preflight all
refuse the retired transport with one shared error; running VMs are unaffected.

Remaining phases are tracked by issues #2370–#2377 and the owning plan.
