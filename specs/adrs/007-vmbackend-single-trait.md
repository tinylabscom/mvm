# ADR-007: `VmBackend` — one trait abstracts every VMM

## Status

Accepted

## Context

mvm launches untrusted workloads inside real microVMs, never containers —
there is no Docker or other container fallback anywhere on the execution
path. Hypervisor availability differs sharply by host: Linux exposes
`/dev/kvm`; macOS never does, and instead offers a raw hypervisor interface
with its own device model; a constrained or CI host may have neither.

A production workload, a local dev/test run, and the Nix builder that
assembles a workload's rootfs are three different trust tiers that must
never share an abstraction, because a role's abstraction is where its
security invariants are enforced — or, for a lower-trust role, deliberately
not enforced.

Several independent callers — CLI commands, the fleet orchestrator's
lifecycle dispatch, `doctor` diagnostics, and the test suite — need to
start, stop, inspect, and list a VM without hardcoding which hypervisor is
under it, and without re-implementing egress enforcement, signed-plan
admission, or audit emission once per VMM.

## Decision

**One trait, `VmBackend`, is the sole VM-lifecycle abstraction for workload
execution.** It lives in the dependency-light core crate so it carries no
runtime baggage, and every backend is a plain type that implements it
directly — never a second trait bridged into `VmBackend`, never a wrapper
hierarchy.

**The current backend matrix:**

- **Firecracker** — Linux `/dev/kvm`. The production, Tier-1 workload
  runtime; selected automatically whenever native KVM is available, on both
  dev and production hosts.
- **libkrun** — an in-process VMM; the default on macOS 13–25, and
  available on Linux.
- **HVF** — the in-house Hypervisor.framework VMM; the default on macOS
  26+ Apple Silicon, and the destination macOS backend. Its egress,
  admission, and substitution guarantees are enforced through a single
  per-VM vsock gating endpoint — there is no guest network interface and no
  separate userspace gateway sidecar.
- **QEMU** — a Linux dev/test substrate (KVM-accelerated where available,
  software-emulated fallback otherwise). Opt-in only, never auto-selected,
  never reachable from the fleet orchestrator, and outside the
  security-claim boundary: it carries no untrusted multi-tenant workload.
- **Mock** — an in-memory, test-only backend. Records lifecycle calls and
  touches no host state; selected only by explicit request, never by
  auto-detection.

There is no Docker backend, no Cloud Hypervisor backend, and no
Apple-framework-based backend on this list — a workload runs on a real,
directly-driven hypervisor or it does not run.

**Selection is registry/enum-driven, never string-matched ad hoc.** A
backend-kind catalog entry backs a dispatch enum; resolving a backend by
name goes through that catalog, not a scattered `match` on strings.
Priority:

1. An explicit `--hypervisor <name>` flag or `MVM_BACKEND` environment
   variable always wins.
2. Otherwise, auto-detection walks a fixed platform ladder: native Linux
   KVM → Firecracker; macOS 26+ Apple Silicon → HVF; libkrun installed →
   libkrun; otherwise Firecracker, whose own start-up then fails closed
   with a clear "not available" error rather than silently substituting a
   weaker backend the caller never asked for.
3. A separate capability-aware path picks the most-preferred backend whose
   advertised capabilities satisfy a run's declared requirements, and fails
   closed with the specific missing capability per candidate when none
   qualify — it never silently downgrades to a backend that can't actually
   do what was asked. The mock backend is excluded from this candidate
   list; it is never chosen for real work.

**The trait is `dyn`-safe and is used both ways.** The dispatch enum gives
static, monomorphized dispatch for the common case; callers that need
trait-object polymorphism obtain a shared or borrowed `dyn VmBackend` from
the same wrapper. Neither path is a fiction bolted on for testing — both
are load-bearing in production code.

**A `VmBackend` implementation may be built two ways, and both coexist
behind the same trait boundary.** The common shape is a concrete type
written directly against one VMM's native API. A newer shape factors a
backend into a low-level driver (pure VMM mechanics: boot, wait, kill,
snapshot) plus a single generic runner that implements the role policy —
admission, the egress gating endpoint, audit — once, and is instantiated
over any driver. Both shapes produce an ordinary `VmBackend` impl; no
caller needs to know or care which one a given backend uses.

**The builder role is a deliberately separate trait, `BuilderVm`, never
unified with `VmBackend`.** The builder is the Linux guest that runs a Nix
build to produce a workload's rootfs. The two roles have irreconcilably
different shapes and risk profiles: a workload backend does a single-shot
`start` that returns a running VM's identity and later stops it; a builder
does a foreground spawn that blocks until the guest exits and returns a
build result. More importantly, the workload role must enforce admission
of a signed plan and default-deny egress, and the builder role must not
(it runs an intentionally broader-access Nix build). Folding them into one
trait would either bloat the interface with role-only methods or create a
dangerous symmetry where a future edit could wire enforcement into the
wrong role or drop it from the right one.

The builder selects among the same VMM family — HVF, libkrun, and QEMU,
all implementing `BuilderVm` and producing byte-identical build artifacts
regardless of which one ran — through its own `--builder` flag /
`MVM_BUILDER_BACKEND` environment variable, with its own platform-ordered
auto-detect (macOS 26+ Apple Silicon → HVF; native Linux → QEMU;
everywhere else → libkrun) and its own narrow auto-fallback: an
auto-detected HVF builder that fails to *create its VM* (a VMM-level
failure, never a genuine Nix build failure, which always surfaces
unchanged) retries once on libkrun. An explicit backend choice disables
that fallback outright. QEMU is never itself a silent fallback target for
a failed HVF or libkrun attempt — its networking model isn't an equivalent
stand-in for the production path, so it is reached only by explicit
request or by its own auto-detect slot.

**Build orchestration is a third, orthogonal abstraction and is not
`VmBackend`.** A separate trait pair governs how a build is *driven* —
shell execution, network/tap setup, loading a workload's declared
configuration — independent of which hypervisor eventually runs the
result. `VmBackend` and `BuilderVm` answer "which VMM"; that pair answers
"how is the build session conducted." None of the three subsumes another.

## Consequences

Adding a backend is "write one `impl VmBackend`" (or one driver, if it uses
the generic-runner shape) and register it in the catalog — no other caller
changes, because every caller already depends on the trait, not a concrete
type. The registry/enum-driven selection with a capability-aware fallback
ladder means a host without a requested capability gets a clear,
fail-closed error instead of a silently weaker backend: there is no code
path that degrades a security-relevant guarantee without the caller
knowing.

Keeping the workload and builder roles on two separate traits costs real
duplication — each VMM that serves both roles is written, or driven,
twice, once per role — but it buys a structural guarantee: the
security-enforcing role and the intentionally-permissive role cannot
accidentally converge through a shared interface. Selection knowledge for
the workload role is split across the catalog, the dispatch enum, and the
capability-selection module; keeping those three in sync is a standing
cost.

Two backend-construction shapes — direct impl, and driver-plus-generic-
runner — coexisting is an intentional migration surface, not drift: it
lets a backend move to the shared-role-policy shape independently of the
others, with the trait boundary, and every caller, unchanged throughout.
