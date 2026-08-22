# FlowMux is the only public workload-networking surface

The rejected `raw_ip_stack` declaration and `NetworkMode::L3Vsock` selector are
gone from the public Rust IR and execution-plan domain types, Python and
TypeScript SDKs, generated schema, CLI preflight, fixtures, examples, BDD
surface, and public guide. Supported workloads use the guest-loopback HTTP
proxy, SOCKS5h and SOCKS5 UDP adapters, controlled DNS, mediated ping, or typed
connectors; each terminates in the authenticated per-VM FlowMux endpoint.

Stale serialized input does not silently acquire different authority. The
outer IR compatibility decoder recognizes `raw_ip_stack` and returns a
migration error even when its value is false. The plan decoder similarly
recognizes `l3_vsock` and refuses it before constructing a `NetworkMode`.
Unknown values remain distinct malformed-input errors. The admitted domain
types therefore cannot represent the retired path.

The public networking guide now states the security boundary directly: a
program that ignores the supported loopback adapters has no routable guest NIC
and its direct socket fails closed. Plan 278's seccomp interception proposal is
closed as rejected; mvm does not set `DUMPABLE=1`, grant `CAP_SYS_PTRACE`, read
workload memory, or add a seccomp user-notification compatibility route.

Verification passed with schema/stub and Rust/SDK parity checks, focused stale-
input positive and negative tests, workspace all-target Clippy with warnings
denied, workspace check, gated-target compilation, the complete serial
workspace test and doctest suite, and the public Astro build (136 pages,
including `/guides/flowmux-networking/`). The complete BDD suite passed 56
features and 194 scenarios: 193 passed, one capability-gated scenario skipped;
801 of 802 steps passed with the same single skip. Permanent transport and
conformance gates also passed: one guest protocol, vsock-only egress, the
shrunk 12-entry L3 freeze allowlist, schema parity, and the 18-claim model.

A subsequent aarch64 workspace run exposed that the already-added ingress UDP
test depended on a fix carried only by a later stack branch. The fix is now in
this independently mergeable slice: an observed ingress peer may receive the
guest reply without being rechecked as a guest-introduced outbound
destination, while a forged unseen peer remains refused by the bounded relay
table. The focused regression passes five consecutive runs.
