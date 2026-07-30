# ADR-034: An opt-in, prod-refused Docker dev-tier backend

## Status

Accepted — boundary ratified; scoped as the **shared-kernel container dev
tier** (opt-in, never auto-selected, refused by production admission,
honest capabilities, none of the hardware-isolation claims). Implemented
by `DockerBackend` (`mvm_runtime::docker_backend`), selectable only via
`--hypervisor docker` / `MVM_BACKEND=docker`.

This ADR deliberately narrows two older statements: ADR-007's "no Docker
backend anywhere on the execution path" and the security posture doc's "no
container fallback". Both stand for the **production and default** paths;
what changes is that a clearly-labeled, explicitly-selected container tier
now exists for development, demo, and CI-sandbox use. The production rule
is unchanged: a host with no microVM substrate still fails closed on every
path it did not explicitly opt out of.

## Context

mvm's backends provide hardware-isolated microVMs: Firecracker on Linux
`/dev/kvm`, libkrun and HVF on macOS, QEMU as a Linux dev/test substrate.
Hosts with none of these — a Linux CI runner without KVM, a developer
machine where only a container runtime is installed — currently have no
way to exercise an mvm workload at all: auto-detection fails closed and
the security model has no Tier 3. The recurring ask is a way to develop
and smoke-test workloads on such hosts without pretending the boundary is
something it is not.

A shared-kernel container is not a microVM. Its isolation is the host
kernel's namespace and cgroup machinery, which the workload shares with
the host and every other container; the container-escape CVE record (Leaky
Vessels, runc races, masked-path) applies to it and to nothing behind a
hardware boundary. A Docker-backed tier therefore cannot honestly carry
any of the hardware-isolation claims, and must never be reachable by
accident.

ADR-024 already established the discipline for a tier like this: opt-in
only, never auto-selected, honest capabilities, claim-free, failing closed
on anything it cannot do. This ADR applies the same discipline to a
container substrate and adds the guest-side compatibility story: the same
`mvm-guest-agent`, the same activation contract, the same operational RPC
surface — over a Unix socket, because a container has no vsock.

## Decision

**A Docker backend may exist, bound by five constraints, decided now so
they cannot be relitigated case by case later:**

1. **It is opt-in only and never auto-selected.** Backend auto-detection
   (the platform ladder) and capability-driven selection never resolve to
   it; a caller must name it explicitly with `--hypervisor docker` or
   `MVM_BACKEND=docker`. It is never a fallback: a host with no microVM
   substrate still fails closed unless the operator explicitly chose the
   container tier.
2. **Production admission refuses it, structurally.** The backend does not
   implement the workload-backend surface the admitted launch funnel
   requires (`as_workload_backend` → `None`, the same carve-out as QEMU
   and Wasm), its catalog descriptor marks it non-workload and Tier 3, and
   `doctor`/launch surfaces label it a shared-kernel container wherever
   the tier is shown. An untrusted production workload cannot be routed to
   it by config drift, by default, or by accident.
3. **It reports its capabilities and claims honestly.** Shared kernel ⇒
   the host-filesystem-isolation, no-uid-0-escape, and verified-boot
   claims do not hold; there is no dm-verity block boot, no guest kernel,
   no hardware boundary, and image references are tag-based and not
   hash-verified by mvm. The claims that are substrate-independent and
   still true — the production agent carries no `do_exec`, the RPC framing
   is fuzzed, dependencies are audited — are reported as holding, exactly
   as they are for the microVM backends. The tier string and doctor output
   say "shared-kernel container, dev tier" plainly.
4. **The guest-visible contract is the same, not a fork.** The container
   runs the identical `mvm-guest-agent` binary as PID 1 (bind-mounted
   read-only as `/init`), receives the identical `ActivateEnvironment`
   message — over an AF_UNIX listener instead of vsock, the only
   guest-side change — applies the identical uid-901 privilege drop, keeps
   the identical `NotActivated` fail-closed gate, and serves the identical
   operational RPC surface. The runtime overlay and declared volumes are
   host bind mounts (read-only honored); there is no NIC (`--network
   none`), so egress — when the launch policy allows it — rides the same
   per-VM substitution endpoint over a bind-mounted socket. Anything the
   tier cannot do (kernel/initrd boot, dm-verity, block volumes,
   snapshots, pause/resume, warm start, standby pool) fails closed with a
   typed error naming the limitation.
5. **It never dilutes the microVM tiers.** No documentation, doctor
   output, or marketing may present the container tier as an isolation
   tier, and no microVM-tier claim may cite a container-tier run as
   evidence. The security posture doc's "no container fallback" section is
   amended to carve out this opt-in tier explicitly rather than silently
   contradicted.

**If this tier is ever asked to execute untrusted production workloads,
the answer is no at the admission layer, not a better container.** The
promotion path for such a workload is a real microVM backend; hardening
containers into an isolation boundary is out of scope permanently.

## Alternatives considered

- **Keep "no container fallback" absolute.** Rejected: it leaves
  KVM-less/dev-container-only hosts with no workflow at all, which in
  practice pushes users to run the real thing with `--privileged` hacks or
  to fork the tooling — both worse than an honest, fenced-off dev tier.
- **A container tier that shares the microVM boot contract literally**
  (initramfs, dm-verity inside the container). Rejected: privileged
  containers or CAP_SYS_ADMIN would be required, which is a *worse*
  security posture than the honest shared-kernel label and still not
  hardware isolation.
- **Silent capability degradation** — accept kernel/verity/block-volume
  requests and ignore them. Rejected: violates the standing rule that a
  backend never silently drops a security-relevant requirement.
- **Rootless/privileged-hardened container runtime as an isolation
  boundary.** Rejected: it is still the host kernel's namespaces; the CVE
  record above applies, and the honest label stays "shared kernel".

## Consequences

- The execution path now contains a Tier 3 by construction, fenced by the
  admission type-bar rather than by convention: the prod funnel cannot
  name it, auto-detect cannot pick it, and the caller must type `docker`
  to get it.
- The guest agent gains exactly one transport variant (AF_UNIX listener,
  selected by environment) with the peer-CID authorization check replaced
  by the host-owned 0700 socket-directory boundary — documented as the
  weaker boundary it is.
- Dev, demo, and CI-sandbox workflows on KVM-less hosts can exercise the
  real agent, the real activation contract, and the real RPC surface, so
  most workload bugs are found against the same code production runs.
- The "no container fallback" posture doc and ADR-007 are superseded
  *only* for this opt-in tier; every default and production path keeps
  failing closed on hosts with no microVM substrate.
