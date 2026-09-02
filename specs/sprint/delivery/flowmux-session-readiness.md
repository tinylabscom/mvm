# FlowMux authentication is a launch event

`machine run --allow-host …` no longer races guest-agent readiness against the
first FlowMux authentication. The endpoint now binds a per-VM Unix readiness
socket before announcing process readiness. Once a guest authenticates, it
writes the existing durable session marker and then signals that socket. The
launcher waits for the event and verifies the marker before admitting the
workload as ready.

On Linux, the endpoint's Landlock ruleset opts into bounded write access to the
configured marker's per-VM parent directory. Endpoints without session
readiness retain the narrower default confinement policy.

This is an event-driven wait, not a fixed delay. A healthy launch pays only for
the authentication and local event delivery, preserving the sub-200 ms warm
launch target. A guest that never authenticates fails closed at the bounded
five-second deadline with the existing actionable identity-drive diagnosis.
Endpoint exit, malformed notification, and missing durable evidence also fail
closed.

The change is covered by delayed-authentication, already-ready, endpoint-exit,
and timeout unit tests; a real endpoint subprocess authentication test; and a
hermetic BDD scenario for the formerly racy ordering. The full workspace test
suite, workspace check, host all-target Clippy, and gated Linux/BDD compilation
pass.
