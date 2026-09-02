# JSON-safe phase timing

`MVM_PHASE_TIMING=1 mvmctl machine run --json ...` now emits one JSON document
on stdout without phase-timing records on stderr. The structured timing report
is nested under `phase_timing`, including coarse phases, sub-phases, backend
phases, and degradation notes.

Non-JSON runs render timing as a readable table. The existing line and detail
records remain available for non-JSON log consumers, and regression tests cover
the JSON round trip and table rendering.
