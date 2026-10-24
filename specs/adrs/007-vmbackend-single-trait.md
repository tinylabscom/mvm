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
- **QEMU** — a dev/test substrate (KVM-accelerated where available,
  software-emulated fallback otherwise). It is the automatic local choice only
  when the host has no production hardware tier, is never reachable from the
  fleet orchestrator, and remains outside the
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
   KVM → Firecracker; macOS 26+ Apple Silicon → HVF; macOS 13–25 with the
   release component installed → libkrun; otherwise QEMU for local dev/test.
   Production admission still refuses QEMU, so absence of the production tier
   never silently weakens a production launch.
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
auto-detect (macOS 26+ Apple Silicon → HVF; native Linux with KVM →
Firecracker; macOS 13–25 with the release component installed → libkrun;
otherwise → QEMU). Backend creation and genuine Nix-build failures surface
unchanged; auto-detection does not retry a failed backend as another VMM. An
explicit backend choice likewise names exactly one attempt.

**Build orchestration is a third, orthogonal abstraction and is not
`VmBackend`.** A separate trait pair governs how a build is *driven* —
shell execution, network/tap setup, loading a workload's declared
configuration — independent of which hypervisor eventually runs the
result. `VmBackend` and `BuilderVm` answer "which VMM"; that pair answers
"how is the build session conducted." None of the three subsumes another.

## Backend distribution and installation

Backend selection and backend distribution are two views of one catalog, not
independent lists. The canonical backend-component table lives beside
`PER_VM_HOST_BINARIES`, and every row contains:

- the `BackendKind` and its CLI spelling;
- whether the backend is usable for workload execution, builder execution, or
  both;
- its supported host OS, architecture, minimum OS version, and required host
  capability (for example `/dev/kvm`);
- its release class (`core`, `platform`, or `optional`);
- every archive path it owns, including executable mode and file digest; and
- the licence texts and exact-source offer that must accompany those paths.

The table includes every production `VmBackend` registration. `Mock` is marked
test-only, and browser-only `WebLinux` is marked non-installable, so neither can
silently become a host choice. A repository gate compares the table with the
`BackendKind` registry, `VmBackend` implementations, `PER_VM_HOST_BINARIES`, the
release workflow, and the licence/source-offer inventory. Adding a backend or a
component therefore fails validation until every projection agrees. The
release packager, release verifier, installer selection helper,
`mvmctl backend`, and `mvmctl doctor` consume generated projections of this
table; none carries a second hand-written backend list.

### Signed component manifest

Each platform release archive contains `components-v1.json`. It names the
release tag and target triple, then groups the archive-relative paths owned by
each backend. Every file entry carries its SHA-256 digest, byte length, Unix
mode, component class, licence identifier, and source-offer identifier.
Archive paths are normalized relative paths: absolute paths, `..`, links that
escape the archive root, duplicate paths, and paths owned by two backend rows
are rejected.

`components-v1.json` is inside the release archive, so the existing Sigstore
bundle authenticates the manifest and its enclosing archive under the same
release identity. Installation verifies the archive signature, target, tag,
and whole-archive checksum before reading the component manifest, then verifies
each selected file against its manifest entry while extracting it. A missing,
extra, malformed, or digest-mismatched selected file refuses the operation.
Component installation never accepts a manifest, file, checksum, or signature
bundle from another tag, target, issuer, or signing identity.

Optional components still ship in the single platform archive. A normal
install downloads and verifies that one archive, retains only the selected
tier, and removes the temporary archive. `backend add` later downloads that
same release archive again; it does not introduce a second asset, package
manager, update channel, or trust root.

The libkrun tier's kernel source of truth is the explicit kernel version and
digest in `scripts/release/build-libkrun-tier.sh`, combined with the immutable
`libkrunfw` commit's patches and configuration. Both appear in the release's
`SOURCE-PINS`, and the repository's kernel freshness gate watches this pin. It
is deliberately not the kernel in an `mvm-images` image set: the tier is a host
release component built and signed with `mvmctl`, while `mvm-images` owns Linux
image layers. Changing the kernel, libkrunfw, or libkrun pin requires updating
the source offer and passing the packaged tier's relocation, signing, and
launch witnesses again.

### Installer selection

`install.sh` accepts `--backend NAME`; the equivalent non-interactive setting
is `MVM_INSTALL_BACKEND=NAME`. Supplying both with different values is an
error. `MVM_BACKEND` remains a runtime override and does not mutate the
installed component set.

After authenticating and unpacking the release, the installer asks that
release's verified `mvmctl` for the recommendation derived from
`auto_detect_default_for`; the shell script does not reproduce the platform
ladder. It prints the selected backend and the exact command for adding another
one. An explicit unsupported backend is refused with the failing host
requirement before the live installation is changed.

With no explicit selection, the automatic choice is accepted immediately when
fewer than two backends are viable. When two or more are viable and `/dev/tty`
can be opened for both input and output, the installer shows only those viable
choices, highlights the automatic choice, and accepts an empty response as that
choice. It reads the response from `/dev/tty`, never standard input. With no
usable terminal—including `curl | sh`, redirected execution, and unattended
CI—it does not prompt and uses the automatic choice. EOF, an interrupted read,
or a terminal disappearing before a valid choice also uses the automatic
choice and reports that fallback.

### `mvmctl backend`

`mvmctl backend list` reports every host-installable backend in catalog order
with its support state, installation state, automatic-choice marker, component
class, and missing host requirement. `--json` emits the same typed records and
is the stable automation surface. Listing is read-only and performs no network
access or repair.

`mvmctl backend add NAME` first refuses an unsupported host, a source build
whose release identity cannot be established, or an install directory it
cannot safely manage. It then downloads the current binary's exact release
archive, applies the existing checksum and Sigstore verification, validates the
component manifest and selected files, stages them on the same filesystem, and
atomically promotes the complete set. Re-adding an identical verified set is a
successful no-op. It never upgrades the CLI or chooses a different release.

`mvmctl backend remove NAME` applies only to optional or platform component
sets. It refuses removal while that backend owns a running VM or is the only
installed viable automatic backend. Promotion/removal is serialized with
install and update. Removal deletes the selected backend's owned files and
links only; it leaves `mvmctl`, shared host services, guest runtime assets,
other backends, caches, trust roots, signing keys, VM state, audit records, and
user configuration untouched. Core backends have no removable component set
and return a precise no-op explanation.

`mvmctl doctor` reads the same table. For the automatic backend and every
explicitly installed backend it reports platform viability, component
integrity, licence/source-offer presence, and the first unmet host capability.
An uninstalled optional backend is informational, not a failed health check.

### Required evidence

The catalog ships with exhaustive unit tests over every `BackendKind`,
platform/architecture/OS-floor table tests, and negative component-manifest
tests for traversal, duplicate ownership, cross-release substitution,
wrong-target content, malformed modes, missing licences, and file tampering.
CLI integration tests cover help, JSON, idempotent add, unsupported add,
same-release enforcement, safe removal, and removal refusals. The installer
harness mocks host detection and `/dev/tty` to cover explicit selection,
conflicting controls, Enter-to-accept, no-terminal fallback, EOF, and exactly
one viable backend. Release gates extract each published target and compare its
files, signatures, Mach-O/ELF dependencies, licences, and source offers with
the table.

Support is claimed only after packaged-release witnesses pass on macOS 13–25
with libkrun, macOS 26+ Apple Silicon with HVF, Linux with KVM using
Firecracker, and Linux without KVM using QEMU. Each witness starts from a clean
install, exercises list/add/remove where an optional component exists, launches
through the selected backend, and proves teardown. Source-built binaries and
an extracted-but-uninstalled component do not count as release evidence.

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
accidentally converge through a shared interface. Selection still has multiple
code projections—the catalog, dispatch enum, and capability-selection
module—but the canonical component table and repository gate make their
agreement a checked invariant rather than a standing manual cost.

Two backend-construction shapes — direct impl, and driver-plus-generic-
runner — coexisting is an intentional migration surface, not drift: it
lets a backend move to the shared-role-policy shape independently of the
others, with the trait boundary, and every caller, unchanged throughout.
