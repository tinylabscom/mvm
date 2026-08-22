# The superseded L3 workload-networking path is gone

The raw-packet contract and policy modules, network control/data services and
leases, guest TUN agent, host gateway and userspace smoltcp datapath, VMM
spawn/reap hooks, binaries, privileged scenarios, fuzz targets, and dormant
node-control surface have been deleted. Nix packaging, release assembly,
kernel TUN configuration, runtime-overlay staging, CI path filters, and the
dependencies that existed only for that path are gone with them.

The retired public names survive only at the outer stale-input compatibility
boundary and in historical process records. An admitted workload therefore has
no raw-packet mode, no guest NIC or TUN, and no second ingress or egress socket
owner. Supported TCP, UDP, DNS, mediated ICMP, typed connector, and declared
ingress traffic continues through the authenticated per-VM FlowMux endpoint.

Dependency validation reports no unused crates. Advisory, license, source,
ban, duplicate-major, and closure-budget checks pass; the all-feature closure
is 468 crates and default Linux/macOS closures are 235/226. Host all-target
Clippy, all-feature gated compilation, formatting, the complete workspace test
and doctest suite, and all 56 BDD features pass (194 scenarios: 193 passed and
one capability-gated skip).

The standalone `mvm-agentd` fuzz lock pins `blake3` 1.8.6 so the
workspace-reviewed vendored `arrayref` patch remains active; its locked
all-target check passes.

Claim 5 now names the permanent FlowMux frame-decoder and session-state fuzz
targets instead of the deleted raw-packet datapath harness. The claim catalog
therefore fails if either replacement witness disappears.
