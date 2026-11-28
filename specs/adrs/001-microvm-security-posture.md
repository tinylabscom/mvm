# ADR-001: microVM security posture — guarantees and threat model

Backing: shipped-source
Validation: check-claim-catalog

## Status

Accepted.

## Amendment

*2026-08-24.* The project now ships an opt-in TPM2 attestation provider
(`mvm-core/attestation-tpm2`) that can quote PCR values from a host TPM
or a software TPM. This reverses the earlier "hardware-backed key
attestation is out of scope" wording, but only to the extent that the
provider is a supported measurement source. It does **not** reverse the
trusted-host boundary: a malicious host remains out of scope, because the
host still owns the TPM, the TCTI connection, and the launch material.
The "Explicit out of scope" and "Non-goals" sections below are updated
to reflect this narrower in-scope change.

## Context

mvm runs untrusted-shaped Linux workloads inside real microVMs. The
product promise — a developer can run third-party or AI-generated code in
a microVM and trust the isolation — only holds if every layer between the
workload and the host is hardened, verifiable, and stated explicitly. A
single strong claim ("vsock-only, no SSH") is not a security posture if
everything underneath it — the guest's privilege model, the rootfs's
integrity, the host-side proxy socket, the supply chain, the deserializer
parsing every host-to-guest message — is soft.

### Adversaries, in priority order

1. **A malicious guest workload.** Code running inside a microVM must not
   read the host filesystem beyond explicit shares, reach the host
   network without an admitted policy, escape the hypervisor, read
   another guest service's secrets, or tamper with the rootfs's baked
   closure.
2. **A same-host hostile process.** Another local user, or another
   process running as the host user, must not be able to talk to a
   guest's agent, read its console log, write to its rootfs cache, or
   tamper with its lifecycle state.
3. **A compromised supply chain.** A malicious nixpkgs commit, a
   compromised artifact-hosting account, or a typo-squatted Cargo
   dependency must not silently land code in a microVM without producing
   a verifiable signature failure.

A **malicious host** — the machine running `mvmctl` itself — is out of
scope. mvmctl trusts the host with the hypervisor, the GC roots, the
user's secrets, and the private signing keys. **Multi-tenant guests** are
out of scope: one guest is one workload. **Hardware-backed key
attestation against a malicious host** remains out of scope: a real TPM2
source is now supported as an opt-in, host-measured attestation input,
but it does not move the trusted-host boundary because the host still
controls the TPM, the TCTI, and the launch material (see "Explicit out
of scope" and "Amendment" above).

### Hardware boundary, not a userspace syscall sandbox

mvm isolates a workload behind a hardware boundary — a VMM over KVM or
Hypervisor.framework — rather than a userspace application-kernel sandbox
that intercepts guest syscalls in a host-side process and re-implements a
kernel ABI on seccomp plus namespaces. The isolation is enforced by the
CPU (rings, EPT, IOMMU), not by the correctness of a syscall-emulation
layer; there is no host-side syscall-compatibility surface to keep in
lockstep with the guest kernel; and a bug in the boundary is a rare,
hardware-assisted VM escape rather than an in-process logic error in an
emulated `openat`/`mount`/`ptrace`. The *in-guest* hardening layers (L4/L5
below) borrow syscall-discipline ideas from that class of sandbox — an
`openat2(RESOLVE_IN_ROOT | RESOLVE_NO_SYMLINKS)`-confined OCI-layer
unpacker, an ioctl-syscall denylist on the guest agent — without adopting
it as the primary isolation boundary.

## Decision

### Trust layers

Defense-in-depth is five nested trust layers. Each layer trusts only the
layer directly below it; an attacker must break every boundary above to
reach the host, and a failure in one layer is bounded by the layer
beneath it.

```
┌───────────────────────────────────────────────────────────────┐
│ L5 — Workload (untrusted code, AI-generated, user scripts)    │
│      enforced by: per-service uid, bounding-set drop,         │
│                    admitted seccomp tier on every process      │
├───────────────────────────────────────────────────────────────┤
│ L4 — Guest agent (parses host messages, launches services)    │
│      enforced by: uid 901 setpriv, no_new_privs,               │
│                    runtime profile + signed VerbGrant,         │
│                    fuzzed deserialization + deny_unknown_fields│
├───────────────────────────────────────────────────────────────┤
│ L3 — Guest kernel (Linux from Nix, ephemeral, isolated)        │
│      enforced by: dm-verity rootfs + roothash via vsock        │
│                    activation + the universal initramfs agent  │
├───────────────────────────────────────────────────────────────┤
│ L2 — VMM (userspace, Rust, seccomp-jailed, unprivileged)       │
│      enforced by: minimal device set, seccomp default-on,      │
│                    host-side proxy socket mode 0700,           │
│                    vsock port allowlist                        │
├───────────────────────────────────────────────────────────────┤
│ L1 — Host + hypervisor (KVM on Linux; Hypervisor.framework on  │
│                          macOS, via the in-house HVF VMM or    │
│                          libkrun)                               │
│      enforced by: hardware (CPU rings, EPT, IOMMU); host       │
│                    hardening is the operator's responsibility  │
└───────────────────────────────────────────────────────────────┘
```

L1 carries no numbered claim of its own — the host is trusted by
definition — but it *enables* claim 3: verified boot needs a hypervisor
that respects the kernel cmdline it is given. If the host is compromised,
every layer above it falls; that is the accepted, named out-of-scope
case.

The guest agent starts as uid 901 through `mvm-setpriv --no-new-privs` and
narrows its Linux capability bounding set through `PR_CAPBSET_DROP`; the
host-side vsock proxy socket is mode 0700; the proxy's port allowlist admits
only the agent port and the declared forward range; console and daemon logs
are mode 0600; and `~/.mvm` and `~/.cache/mvm` are mode 0700.

### The claims ledger

Every guarantee below is backed by a named test or CI lane, recorded in
the machine-checked ledger later in this document (between the
`claims-catalog` markers). `xtask check-claim-catalog` parses that table
on every PR and fails when a claim's witness no longer exists in the
tree — the claim list cannot silently drift from what the code actually
does. The narrative in this section states what each claim *means*; the
ledger is the checked source of truth for *what proves it*.

### The claims

Twenty-one claims: eighteen numbered guarantees (1-15 and 19-21) plus three
preview claims (16-18) not yet promoted to the numbered set. L1 (the host) has no claim of its own
per the threat model above.

| # | Claim | Layer | Enforcement |
|---|---|---|---|
| 1 | No host-fs access from a guest beyond explicit shares | L2/L5 | Per-service uid; the admitted seccomp tier (`standard`; `vsock` when a GPU grant is the launch's only socket need; `network` when the launch needs sockets) installed with `no_new_privs` in every workload process the agent starts; `mvm-setpriv --no-new-privs` plus agent-side `PR_CAPBSET_DROP`; user-volume allow-list with a read-only default; admission-enforced share matching |
| 2 | No guest binary can elevate to uid 0 | L2/L4 | `mvm-setpriv --no-new-privs`; the rootfs is mounted read-only (dm-verity sealed), so a compromised service cannot rewrite `/etc/{passwd,group,nsswitch.conf}` to mint a uid-0 entry |
| 3 | A tampered rootfs ext4 fails to boot, on the block+ext4 backends | L3 | dm-verity sidecar + 64-hex roothash delivered over vsock in `ActivateEnvironment` + the universal initramfs agent that sets up the verified devices before pivoting; a flipped data block fails verification when read. The runtime overlay's verity tree and roothash are computed on the host when `mvmctl` assembles the overlay from a guest-runtime archive — a source checkout's own build, or on a release binary the signed archive its own release ships (`assemble_release_runtime_pieces`) — and the roothash reaches the guest in `ActivateEnvironment` unchanged. No build takes the overlay or its roothash from the image set: a launch attaches only the overlay this CLI assembled, and a miss names `mvmctl bootstrap` |
| 4 | A production-safe run cannot invoke DevOnly guest-agent verbs | L4 | The universal agent classifies requests and requires both the runtime profile and a signed `VerbGrant`; the runtime-boundary CI lane and grant unit test cover the complete DevOnly set |
| 5 | Vsock framing, supervisor-config JSON, and FlowMux's guest-facing decoder and session state are fuzzed | L2/L4 | `cargo-fuzz` targets cover `GuestRequest`, the sealed control envelope `SealedFrame` parsed off the wire, the host-side `SupervisorConfig` parser, FlowMux frame decoding, and valid-frame sequences against the shared session ceilings, stream-id retirement, credit accounting, and refusal-without-state-change invariants; every host↔guest type is `#[serde(deny_unknown_fields)]` |
| 6 | The pre-built dev image is hash-verified | supply chain | The pinned image-set root is digest- and signature-verified before parsing; each fetched member is size- and SHA-256-checked, and a mismatch is removed. The image set carries the kernels, the base root filesystems, the builder image and the Stage 0 seeds. It also still publishes runtime-overlay, SDK-sidecar and initramfs members, which `mvmctl` parses as retired roles and never attaches. The guest runtime is not an image-set member: it is a CLI release asset, authenticated under claim 20 |
| 7 | Cargo dependencies are checked on dependency-changing PRs, nightly, and before release signing | supply chain | `ci.yml` calls `supply-chain.yml` for dependency, vendored-source, policy, and workflow changes; its `Test` aggregate refuses failed or unexpectedly skipped required checks. `release.yml` requires the same reusable gate before candidate signing and publication. `security.yml` retains nightly, tag, and manual checks using the same pinned checker action. Merge blocking relies on repository protection requiring `Test`; workflow definitions alone do not establish that external setting. A reproducibility double-build checks for non-determinism; neither advisory checks nor reproducibility prove the absence of malicious code |
| 8 | Every workload runs from a signed, audited `ExecutionPlan` | cross-cutting | An Ed25519 host-signer keypair signs a typed plan; a validity window and a nonce replay-store gate admission; every admission emits chain-signed `plan.admitted` / `plan.launched` / `plan.failed` audit entries |
| 9 | Every published bundle is content-addressed, key_id-pinned, and re-verified at fetch and at admit time | supply chain | A rejection ladder covers unknown key, tampered manifest, key_id mismatch, tampered or missing artifact, unsafe path, schema bump, and pin-archive/pin-signature drift |
| 10 | No untrusted workload reaches the network unless explicitly admitted by policy | data containment | `NetworkPolicy` defaults to deny-all; no workload guest has a NIC, so every claim-bearing backend's egress leaves over vsock to one per-VM network endpoint, where `EgressGate` decides every connect, datagram, and DNS answer against the admitted policy's canonical projection, refusing the mandatory-deny ranges and TCP/22 under every policy, and private ranges under any policy that does not name them |
| 11 | Every application-dependency volume is CVE-scanned and SBOM-enumerated when sealed, then hash-locked, attestation-checked, and bound to the workload's audit chain | supply chain (app layer) | A sealed volume carries `content/`, `sbom.cdx.json`, `fetch.log`, `cve.json`, and a hash-chained `meta.json`; the seal is re-verified when the build cache reuses a volume and by `mvmctl deps inspect` / `deps audit`. No launch path attaches a dependency volume or verifies one at admission (issue #5962). The severity gate is exercised by the seal-time security lane but has no production launch caller. |
| 12 | Every host-side broker service is bound to a signed `ExecutionPlan.services` binding, enforced before handler dispatch, and audited | cross-cutting | Binding-gated dispatch with a rejection ladder for unbound and out-of-profile calls; the handler registry is linted for policy-schema and composition coverage |
| 13 | The managed substitution path hands the guest placeholders, never raw secret values | data containment | The host-side substitution endpoint mints the placeholder environment delivered to the guest and resolves a credential only while preparing an admitted outbound request; no secret-returning broker handler exists |
| 14 | Every OCI image admission records provenance in the chain-signed audit log | supply chain | A `plan.oci_provenance` entry carries the registry host, repo, supplied reference, resolved manifest digest, layer digest list, trust policy, and cosign verdict; a production pull or run refuses a mutable reference before any network fetch |
| 15 | A sealed production microVM has no shell, no DevOnly guest-agent verbs, and no PTY | L4 | Only a dev image is served a console; the sealed rootfs is dm-verity protected; the backend captures the guest console write-only, with no host input; the host accessible-gate refuses `console` on a sealed image; the universal agent's console and DevOnly handlers require the runtime profile and signed grant |
| 16 | *(Preview)* Egress substitution keeps a raw secret off the guest, bound-only, with no value in the audit log | data containment | Preview status; the limits are stated on this claim's row in the ledger below and are not restated here |
| 17 | *(Preview)* Workload stdin is grant-gated, single-writer, secret-scanned across frames, and every refusal audited | data containment | Preview status; the scan is a length-and-hash fingerprint match, not an identity, and the ledger row states what that does and does not catch |
| 18 | *(Preview)* A workload's resource consumption is bounded at admission, and bound at spawn where the host has a mechanism | cross-cutting | Preview status; admission bounding holds everywhere, spawn-time CPU control is partial and backend-dependent, spawn-time memory and task ceilings hold only on a Linux host with a systemd user session, and the ledger row enumerates which backends are covered |
| 19 | Every dataset, model, prompt, agent, policy, and compute environment named by a workload carries a content-derived identity in the signed plan, and a pinned host share that drifts after admission fails closed | cross-cutting | `--asset KIND:PATH` hashes the asset through the canonical `hash_source` tree walk into `AssetIdentity` records inside the signed `ExecutionPlan`; admission also pins each directory share's content digest, re-verified at mount enforcement, so a post-admission edit of the host directory is refused; synthesis auto-derives the compute-environment identity from the measured image/kernel/verity state; a `plan.asset_identities` chain-signed entry carries kind, locator, and digest labels; `mvmctl trust audit asset id <path>` recomputes the same digest offline for comparison |
| 20 | Every published release artifact is authenticated under the release workflow's identity, directly or through a signed checksum manifest, and the build, fetch, install, and self-update paths refuse an artifact whose required signature is missing or invalid | supply chain | `release.yml` signs archives and checksum manifests keyless through GitHub OIDC, publishing bundles that carry the Fulcio certificate and Rekor inclusion proof; raw kernels, root filesystems, and metadata are covered by the signed manifests rather than individual bundles; the `verify-release` job re-downloads the published set, verifies the signatures against an identity regexp pinned to this workflow at a tag, and checks the covered blobs against their authenticated digests; the build gate refuses a missing or malformed bundle, and production image-set acquisition refuses an unsigned pinned root before parsing it, with the hash-skip hatch explicitly not waiving the signature. `mvmctl env update` verifies the checksum manifest's bundle in-process under its exact tag before reading a digest from it, and each archive's own bundle under the same tag. The guest runtime (`mvm-guest-bins-v<version>.tar.gz`) is one of the signed archives: `release.yml` refuses to publish without exactly one, named for the tag, and signs it and its `.sha256` sidecar; `verify-release-assets.sh` checks both signatures, the sidecar against the bytes, and the archive's manifest; `acquire_release_guest_runtime` holds a download to that digest and then to the signature at exactly this version before parsing it; and `install.sh` verifies it against the signed checksum manifest and its own bundle before staging it beside `mvmctl` |
| 21 | OCI base images are OS-package- and kernel-inventoried, CVE-scanned against OSV, and SBOM-enumerated at pull time, and production admission refuses a missing scan, a sidecar bound to another digest, or any high/critical finding | supply chain | The pull pipeline inventories the unpacked rootfs and queries OSV, writing a CVE and SBOM sidecar bound to the image digest; `--prod` runs refuse a missing scan, a digest mismatch, or a high/critical finding. The ledger row below carries the limits (host-controlled sidecar, best-effort severity, registry-pulled images only) |

**Claim 15 changed shape, and shrank.** It used to read "no interactive
access to a sealed production microVM", and it held by *absence*: a
sealed VM had no host→guest byte path at all, so "nobody can drive it"
needed no policy. The workload input plane built one. What survives is
the part that still holds by absence — no shell, no `do_exec`, no PTY —
and that is all this row now claims, because that is all its three
witnesses check.

The input plane's own properties are *not* folded in here, and they are
not all of one kind. Bytes that reach a running workload's stdin cannot
select a program, alter argv or environment, or spawn anything — that
holds by *construction*, because the entrypoint is fixed at admission
and the plane writes to a pipe rather than to a launcher, so there is no
mechanism to subvert rather than a rule against subverting it. What is a
*policy* decision made by host code is narrower: whether a workload
receives stdin at all, which is refused outright without a grant in the
signed plan.

Neither is claimed here, for different reasons. The construction half is
excluded because this row's three witnesses do not check it. The policy
half is excluded because promoting it is a separate maintainer decision,
mirroring rows 14 and 16. Both are stated and witnessed as Preview 17,
with their limits, rather than asserted as part of a shipped claim.

**Preview 17 — workload stdin is grant-gated, single-writer, secret-scanned
and audited.** The host→guest input plane refuses every write unless the
workload's signed `ExecutionPlan` carries the input grant; it arbitrates
concurrent writers with a per-VM lease so two consumers cannot interleave
into one byte stream; it scans across frame boundaries and withholds the
tail it must still be able to see rather than shipping it and refusing
afterwards; it emits a chain-signed, payload-free entry for
every refusal and every grant, and declines the decision entirely when it
cannot record it; and under a sealed production posture it refuses the
grant outright for a shell-shaped entrypoint, since streaming stdin to a
shell is interactive access wearing a different hat.

This is a preview, not a shipped claim. Every leg now has a production
caller: the channel has an operator surface (`mvmctl machine run
--entrypoint --stdin -`), the shell-entrypoint refusal reads the entrypoint
out of the image's own build-time record and fails closed when it cannot,
and the secret scan is populated — `StreamPlane::open_input` installs the
fingerprints the per-VM substitution endpoint computed for the secrets it
resolved. What keeps the row at `Preview` is no longer dormancy but what the
enforcement *is*: a fingerprint match is a length-and-hash match rather than
an identity, and encoding, derivation and a window-straddling split defeat
the scan permanently. Promotion is therefore a maintainer decision about
whether a numbered claim's prose can carry those qualifications — the same
posture rows 14 and 16 sit in. The five limits are stated in the ledger's
"Preview 17 limits" note below, marked as closed or open individually, and
are load-bearing.

**Preview 16 — egress substitution keeps a raw secret off the guest.** A
tokenized-replacement mechanism on the host-owned substitution proxy
boundary reinforces claims 12 and 13 on the egress delivery path: a
handed placeholder never contains the secret value, the substitution
endpoint refuses an unbound destination, and the audit chain carries no
secret value. This claim is registered in the ledger for
witness-checking but stays a preview — promotion to the numbered set
above is a separate decision.

**Preview 18 — a workload's resource consumption is bounded at admission,
and bound at spawn where the host has a mechanism.** Three controls, with
sharply different strengths, and the row exists to keep them from being read
as one thing.

*Admission* is the strong half and holds on every host. An operator-configured
ceiling bounds what one workload may be granted, and an operator-configured
host-wide budget bounds the sum: a boot whose memory, added to every live
machine's admitted charge, would exceed the headroom is refused before the
keystore is touched. Both are read from host config and never from the plan,
for the reason the ceiling already documents — a plan's author also authors
its grants. Two properties of the budget are load-bearing and are witnessed
individually. It counts only machines whose state directory carries a pid
marker pointing at a live process, using the same probe the fork path trusts,
so a VM that crashed without cleanup cannot turn the safety check into a
permanent refusal of every later boot. And it counts each machine's
*configured maximum*, not its current commitment, because the balloon
controller moves the latter at runtime and a budget summed from it would
re-admit memory the host has already promised.

*CPU* is the partial half. On Linux a granted share wraps the VMM spawn in a
systemd transient scope before the payload execs — born-bounded rather than
adopted — and the achieved tier is read back off the scope's `cpu.max`. On
the in-house HVF VMM on macOS there is no host quota primitive, so the run
loop enforces the share in-process: it measures every vCPU thread's consumed
CPU time via Mach `thread_info`, sums them, predicts allowance exhaustion, and
holds all of them out of `step()` until the period rolls over. The sum is what
makes the bound a bound on the machine — a controller reading one thread of a
four-CPU guest sees a quarter of what it is consuming and never throttles. The
achieved tier is read back from the scheduler's own measured record. In both
cases the receipt records what was measured rather than what was asked for.
libkrun has no in-process vCPU control and stays declared-only.

*Memory and tasks* are bounded at spawn on the same mechanism, for every VMM
spawn rather than only a granted one. On a Linux host with a systemd user
session, the scope every VMM process is born into carries `MemoryMax=` (guest
RAM plus a fixed overhead margin), `MemorySwapMax=0`, `TasksMax=` and
`OOMPolicy=stop`, whether or not the plan granted a CPU share. These are not
grants — nothing in a plan asks for them — and they exist to stop a VMM whose
device emulation leaks or whose helper threads run away from exhausting the
host, which the admission budget, being bookkeeping, cannot do. `memory.max` and
`pids.max` are read back off the live scope, with their values, into the same
`plan.grants_enforced` entry the CPU tier is written to, and a scope the OOM
killer ended is recorded as `plan.memory_limit_exceeded` when the run's exit is
reported. Scope creation is bounded: a service manager that never creates the
scope fails the launch after a fixed deadline instead of hanging it. Limit 6
below states where none of this holds.

*Wall clock* is enforced on the tiers with a per-VM supervisor process of
ours — libkrun, HVF, and the AppleContainer tier that runs the same driver and
supervisor. The supervisor arms a timer from the admitted plan and kills the
workload at its deadline with exit `124` and a chain-signed entry, so an
enforced timeout stays distinguishable from a crash. It is claimed by nothing
on Firecracker and QEMU, whose VMM is a bare child of an `mvmctl` that has
already exited; limit 2 below states what that leaves open.

This is a preview and not a numbered claim for the ordinary reason plus one
specific one: the CPU control's only *measured* witness — the live
1.5-core-against-a-1.5-core-grant run — is an `#[ignore]`d test that needs a
Linux host with a systemd user session, so PR CI witnesses the spawn wrapping
and the read-back, not the throttling. The limits below are load-bearing; do
not paraphrase this row without them.

**Preview 18 limits — what the resource bound does and does not enforce.**

1. **CPU is enforced on Linux and on the in-house HVF VMM; it is
   declared-only for libkrun. (OPEN for libkrun, permanent.)** Linux uses a
   cgroup v2 `cpu.max` on a systemd transient scope. macOS has no host-level
   quota primitive, so HVF enforces the share in-process in the run loop and
   reads the achieved tier back from the scheduler's measured record; libkrun
   has no in-process vCPU control and stays declared-only. A Linux host
   without `systemd-run` or without a user session bus gets the same
   treatment as a missing mechanism through a second, host-level probe, so a
   sealed run cannot be admitted on a host that merely looks capable by
   backend kind. Witnessed by
   `fn:the_libkrun_tier_cannot_bound_cpu_off_linux`,
   `fn:prod_refuses_a_cpu_grant_on_a_backend_that_cannot_bound_cpu`,
   `fn:host_cpu_mechanism_gap_honors_hvf_quota_range`,
   `fn:relay_config_threads_cpu_share_to_quota_scheduler`,
   `fn:apply_grants_reads_quota_record_from_state_dir`,
   `fn:a_share_grant_binds_the_spawn_when_the_mechanism_is_present` and
   `fn:a_vm_with_no_recorded_scope_reads_back_as_declared_not_as_an_error`.
   Note the qualifier: macOS has no *host-level* quota primitive, but HVF is
   an in-house VMM, so bounding a guest by time-slicing its own vCPU threads
   is implementable — substantial work, not a closed door. Recorded so the
   distinction between "nobody has built it" and "cannot be built" does not
   quietly harden into the latter.
2. **Wall clock is enforced only where a supervisor process holds the plan.
   (PARTIAL.)** The mechanism is a supervisor-side timer that audits the
   expiry to the chain-signed log *before* killing, so an enforced timeout is
   distinguishable from a crash; it is armed in `mvm-libkrun-supervisor` and
   `mvm-hvf-supervisor`. The dividing line is structural rather than
   incidental: those are the VMM tiers with a process of ours that outlives
   the workload *and* is handed the admitted plan to read a bound from. A
   restore never inherits its parent's plan, because auditing a child's kill
   under the parent's identity would write a wrong entry rather than a
   missing one. An HVF `vm_full` fork child carries its OWN admitted plan to
   its supervisor, which verifies the signature under the host key, the
   validity window and that the plan names this child (no nonce is re-spent;
   admission spent it), then arms the wall clock from the restore, audited
   under the child's identity. Firecracker restores are not covered.
   `ResourceControls::for_backend` answers `WallClockControl::None` for
   Firecracker, QEMU and Mock, so a wall-clock grant on those tiers is refused
   under `--prod` and warned under dev rather than admitted against nothing.
   Witnessed by
   `fn:an_expired_workload_is_killed_and_the_kill_is_audited` and
   `fn:a_wall_clock_bound_needs_a_clock_that_can_stop_the_workload`.
3. **wasm fuel, epoch and store limits are wired. (CLOSED.)** The wasm tier
   overrides `apply_grants` and reports `WasmFuel`/`WasmEpoch` from a
   read-back rather than from a setter's return, because wasmtime exposes no
   getter for either. Fuel and epoch are *jointly* required — a module blocked
   inside a host call consumes no fuel, so a fuel-only grant is refused rather
   than accepted as partial enforcement. Witnessed by
   `fn:a_fuel_grant_halts_a_runaway_module`.
4. **A forked child is spawn-bounded; a warm-claimed child is
   admission-bounded everywhere and spawn-bounded on one of its three claim
   paths. (PARTIALLY OPEN.)** A `vm_full` fork boots a fresh VMM under the
   child's own admitted plan and carries that plan's CPU grant into the spawn —
   Firecracker through the bounded snapshot-load launch line, HVF through the
   wrapped supervisor `Command`
   (`fn:a_firecracker_restored_child_is_cpu_bounded_by_its_admitted_grant` and
   `fn:an_hvf_restored_child_is_cpu_bounded_by_its_admitted_grant`). A
   same-identity `restore` binds nothing, deliberately rather than
   as a gap: it admits no plan of its own, so there is no grant to bind, and
   inventing one from the checkpoint record would be a bound nobody signed for
   that run.

   A warm-claimed child is bounded at admission on every path, by the host's
   own `GrantCeiling`. The standby parent is deliberately spawned with no
   grant — one parent serves every later claim, so sealing a provisioning
   workload's grant onto it would bind unrelated claims to a stranger's
   number — which leaves the parent-subset comparison nothing to bind against,
   so the ceiling is what refuses instead
   (`fn:a_claimed_child_over_the_host_ceiling_is_refused`,
   `fn:a_claimed_child_within_the_ceiling_is_admitted`). Read that for exactly
   what it is: a host-wide maximum every cold boot on this host already clears,
   not a pool-specific grant, and so the weakest of the bounds considered —
   strictly stronger than the unbounded claim it replaces and no stronger than
   that. It is checked after the pool has matched rather than folded into the
   compatibility key, because keying on a grant would fragment one pool into a
   pool per distinct share and cost the warm hit rate the pool exists for; the
   price is that a claim can match a parent and then be refused, so the refusal
   names both numbers (`fn:the_refusal_names_the_ceiling_and_the_request`,
   `fn:pool_matching_is_unchanged_by_the_bound`).

   The spawn half is closed only where a claim spawns something. The
   Firecracker saved-state fork goes through the same bounded restore a
   `vm_full` fork does. The other two claim paths spawn no process to wrap:
   Firecracker's preloaded child was started before the claim arrived, and the
   HVF resident handoff resumes the parent's own supervisor by signal — a
   process born grant-less as shared pool capacity, which binding now would
   bind the pool rather than the claim. `bind_spawn` wraps a `Command` and
   this tree has no post-spawn attach, so on those two paths a claimed child's
   CPU bound is a ledger entry and not a `cpu.max`. Wall clock is re-armed on an HVF
   forked child from its own plan, per limit 2; it is not on a Firecracker
   restore. A claimed child is different: it
   has an admitted plan of its own, and on HVF the resident handoff carries
   that plan, bound into the handoff signature, to the supervisor the child
   inherits. That supervisor arms the plan's wall-clock bound and session idle
   watcher as a cold boot would, and stops the child rather than run it
   unbounded if the bound cannot be audited
   (`fn:a_claimed_child_with_a_bound_gets_the_timer_a_cold_boot_would`).
   Firecracker's claim paths have no supervisor to arm one, per limit 2.
5. **The budget is not a precise cliff. (OPEN, by choice.)** Two admissions
   racing each other can both read the same total and both be admitted,
   overshooting by one boot; closing that needs a host-wide lock held across
   measure-and-start. Its CPU arm sums only *granted* shares, so an ungranted
   workload is uncapped and contributes nothing. No unreadable record, marker or
   stray file under `vms/` turns into an accounting error that refuses
   unrelated boots. A machine held in the configured-budget ledger counts once
   through its hold. Any other machine counts at its charge record, or at the
   charge its persisted admitted plan implies when that record is missing or
   unreadable. With neither readable it is invisible rather than refusing every
   boot on the host, and a file that exists but will not read is warned about
   once per process (`fn:an_unreadable_charge_record_is_skipped_rather_than_fatal`,
   `fn:an_unreadable_charge_record_with_no_plan_hides_only_that_machine`). The
   two sums differ in their liveness test:
   - The ledger counts a machine while any pid marker leaves it possibly
     running. A marker that cannot be read keeps it counted until its
     directory is removed, unless one of its markers is a link.
   - The advisory live-machine sum (default sizing, standby room) counts only a
     marker that names a live process.
   - Both judge a dir holding a link (a live-handoff child's marker, linked to
     its standby parent's) by whether some marker names a live process. So a
     dangling link, or a malformed marker beside a link, counts nothing. In
     the ledger, a link whose target is not a small regular file still keeps
     the machine counted. Every marker read is non-blocking and bounded, so no
     marker can stall an admission.

   A charge too large to add saturates. It reads as the whole host, which the
   headroom check then refuses. An idle standby carries no record or plan, so
   admission does not count it, by design; the standby budget bounds it
   instead. Each of these is a deliberate choice of the undercount failure over
   the lockout failure, which is the same judgement limit 4's counting rule
   makes.

   A `vm_full` fork child is admitted at the memory its restore maps: the
   saved RAM's authenticated length, which Firecracker sizes the guest from
   and which the HVF restore refuses to be shorter than the RAM its captured
   config maps, so the charge is never below the mapped RAM.
   Copy-on-write sharing with the parent is not credited. Its hold is reserved
   at admission, re-checked against the budget immediately before the restore
   can start a VMM, and recorded once the child runs; the charge record is
   written with or without a budget, as a cold launch writes it
   (`fn:a_vm_full_fork_that_fits_is_charged_and_counted_by_the_next_admission`,
   `fn:a_vm_full_fork_past_the_budget_at_dispatch_is_refused_before_restore`,
   `fn:a_fork_is_admitted_at_the_memory_its_restore_maps_not_the_host_default`).
   A fork that fails is settled by the ledger's liveness rule above: its hold
   is released when no marker leaves the child possibly running, and kept
   charged otherwise. Three gaps remain open. A launcher killed between
   spending a hold and settling it leaves the hold `Dispatching` permanently:
   nothing retires that phase, so it overcounts after the machine dies and
   blocks the name under a budget. That holds for every launch kind, and
   fs_quick forks reach the same state on every launch because they never
   record their charge (#6015). Only `vm_full` forks settle a failed launch:
   a cold transient that fails after spending its hold also leaves it
   `Dispatching` (#6015). And on Firecracker, a scope or socket wait
   that times out while the detached launcher is still pending can later exec
   an idle Firecracker that carried no marker when the hold was released, so
   it is not counted; before this change the fork's hold was dropped in that
   case too.
6. **Memory and task ceilings at spawn hold only on a Linux host with a systemd
   user session. (PARTIAL, by host.)** Where they hold, every VMM spawn —
   Firecracker cold boots and every Firecracker snapshot load (fork, pool
   preload, same-identity warm restore), QEMU, and the libkrun and HVF
   supervisors, cold or restored — is born inside a scope carrying
   `MemoryMax=` of guest RAM plus `VMM_MEMORY_OVERHEAD_MIB`, `MemorySwapMax=0`,
   `TasksMax=VMM_TASKS_MAX` and `OOMPolicy=stop`
   (`fn:a_spawn_with_no_grant_still_gets_memory_and_task_ceilings`). The
   overhead margin is 256 MiB against a measured charge beyond guest RAM of
   about 2 MiB for Firecracker and 34 MiB (38 MiB at peak) for QEMU with its RAM
   preallocated, on a 512 MiB, 2-vCPU guest; the libkrun supervisor was not
   measured. The ceilings are read back off `memory.max` and `pids.max` with
   their values
   (`fn:a_scope_with_a_resolvable_cgroup_reads_back_its_enforcement`) and
   audited beside the CPU tier. A live run measured the kill: a payload growing
   past its ceiling was OOM-killed and its unit reported "oom-kill" at the
   ceiling read back
   (`fn:a_spawn_past_its_memory_ceiling_is_killed_and_the_kill_is_recorded`,
   `#[ignore]`d for the same reason as the CPU witness). What stays open:
   - **No mechanism, no ceiling.** macOS (HVF and libkrun), and a Linux host
     without `systemd-run` or a user session bus, record both dimensions as
     `declared`. This is **not** an admission requirement, under `--prod` or
     otherwise: the ceilings are host protection that nobody asked for, and
     refusing every sealed run on such a host is a different decision from the
     CPU path's refusal of a share the plan did ask for. A sealed run there
     boots, and its `plan.grants_enforced` entry says `declared`.
   - **A present but unresponsive manager fails the launch.** Measured: a
     stopped user manager held `systemd-run` for 90 s before it gave up. A
     spawn now kills its launcher and fails after `SCOPE_CREATION_TIMEOUT`
     (`fn:an_unresponsive_manager_fails_the_launch_instead_of_hanging_it`), in
     dev and prod alike.
   - **The kill is audited only where an exit is reported.**
     `plan.memory_limit_exceeded` is written by the waited exit report of a
     launch that admitted a plan. A persistent machine nobody waits on is
     killed just the same, and the only record is its unit's "oom-kill"
     result.
   - **The budget does not count the margin.** Limit 5's budget charges each
     machine its configured guest memory, so the sum of the enforced ceilings
     can exceed the budget by the overhead margin per live machine.
   - **Two spawns are not scoped.** The unbounded Firecracker entry used only
     by a live snapshot harness that admits no plan, and the macOS-only HVF
     rootfs-inject helper VM, spawn without a scope.
   - **Wasm has no VMM process to scope** and reports both dimensions as
     `declared`; its store limits are not reported here.

### Explicit out of scope

- **A malicious host.** mvmctl trusts the host with the hypervisor, the
  GC roots, and the private signing keys. Nothing in this ADR defends
  against a compromised host.
- **Multi-tenant guests.** One guest is one workload. Fleet-level
  multi-tenancy is a distinct, separately-scoped trust boundary owned by
  the sibling fleet-orchestration product, not by this ADR.
- **Hardware-backed key attestation against a malicious host.** Every
  trust anchor a guest verifies today — the kernel cmdline, the per-launch
  config drive, even the dm-verity roothash — remains provisioned by the
  same trusted launcher that provisions the material it protects. A real
  TPM2 source is now supported as an opt-in, host-measured attestation
  input, but it does not move the trusted-host boundary: the host still
  owns the TPM, the TCTI connection, and the launch material, so a
  compromised host remains out of scope. Real separation against a
  malicious host still requires a trust root the host cannot forge —
  confidential-computing hardware (SEV-SNP/TDX) with CPU-signed
  attestation — and a future claim binding a grant's verifying key to an
  attested launch measurement is possible only after a dedicated
  confidential-computing workload backend exists and after this ADR's
  threat model is revised to bring a malicious host partly in scope.

### Post-quantum status

Today, mvm uses Ed25519 for execution-plan and audit signing. Our proposed
post-quantum roadmap prioritizes long-lived audit evidence: versioned,
algorithm-explicit formats first, then dual Ed25519/ML-DSA signatures,
followed by execution plans. Algorithm identifiers alone do not provide
post-quantum protection. For cross-host traffic, we plan to evaluate hybrid
X25519/ML-KEM key establishment within our existing networking architecture.
These post-quantum extensions are not implemented today.

Nothing in that paragraph is a claim in the ledger below: the roadmap is
proposed, and no part of it is implemented, demonstrated or witnessed.
`xtask check-pq-claims` holds its last sentence to the lockfile. The gate fails
when `Cargo.lock` gains a post-quantum implementation crate (ML-KEM, ML-DSA,
SLH-DSA, liboqs, pqcrypto and their pre-standard names) while the sentence still
stands, and fails when the sentence is removed with no such crate behind it. So
when the work lands, the build tells whoever lands it to rewrite this section:
say what shipped and what witnesses it, and leave only what is still ahead as
proposed. It is a signal, not a proof: a vendored or renamed implementation
would pass unnoticed.

The roadmap has two tracks, and they are not ranked against each other.
Authenticity comes first for what mvm itself produces: audit and epoch seals,
then execution plans, because audit evidence has to stay verifiable for years.
Confidentiality is evaluated in parallel wherever the host carries traffic:
hybrid X25519 + ML-KEM key establishment for the connections the host
originates and for cross-host transport, because recorded traffic can be
decrypted later and that exposure exists from the day the traffic is sent. That
applies on a single host as much as across a fleet; the guest has no network
device, but the host still makes outbound connections on a workload's behalf.
ADR-062 section 7 states the same two tracks.

The roadmap is written so that a FIPS-qualified deployment stays reachable
later. That is a constraint on every cryptographic operation the host performs,
signing and verification as well as the connections it originates, and on the
modules that perform them, not only on the algorithm names. CNSA 2.0 alignment
is likewise a requirements-led direction, not a current compliance claim. The
algorithms, cryptographic modules, deployment configuration and supporting
evidence would be scoped against a deployment's requirements. No qualified FIPS
deployment is claimed.

### Design principles

- **Defaults are safe.** Every option whose value affects security
  defaults to the safer choice; a user opts *out*, never in, and the
  opt-out is documented.
- **Defense in depth, not a single chokepoint.** The vsock-only claim is
  one enforced layer among many; a failure in any single layer is not
  catastrophic.
- **Verified boot is mandatory for production microVMs**, on the
  block+ext4 backends. A dev VM's writable overlay upper layer cannot
  compose with dm-verity, so the dev tier is named as an explicit
  exemption rather than left ambiguous.
- **The guest agent does not run as root in production**, without
  exception.
- **CI gates every claim.** A claim that stops being backed by a passing
  test or CI lane is a broken build, not a stale sentence in a document.
- **The threat model is lived with, not aspired to.** A malicious host,
  multi-tenant guests, and hardware attestation are named out of scope so
  the project never accidentally commits to defending against them by
  omission.

### PS-21 Firecracker authority boundary

**Approved source-design direction, not shipped enforcement or a live witness.**
The owner approved [option A for #4414](https://github.com/tinylabscom/mvm/issues/4414#issuecomment-6481580558):
direct current-user launches with operator-provisioned access and predelegated
resources. This refines the [existing-role contract](https://github.com/tinylabscom/mvm/issues/4414#issuecomment-6224073768).
The [owner-approved process-boundary refinement](https://github.com/tinylabscom/mvm/issues/4414#issuecomment-6587589521)
supersedes the earlier blanket utility/`systemd-run` prohibition. These decisions
do not promote a claim, change the tier matrix, or establish that the current
shell/scope launch paths satisfy this boundary.

- **Provisioning precedes launch.** The operator supplies KVM/device access and
  delegated resource authority separately. Hosts relying on the old implicit
  privileged route are unsupported by the replacement until provisioned. Missing
  rights or mechanisms refuse before process creation; there is no privilege-
  escalation fallback through passwords, `sudo`, `doas` or `pkexec`, and no
  unbounded-launch fallback. No root password, `sudo -C`, sudoers edit or
  `visudo` setup may become a user requirement.
- **Containment exists at birth.** Before creating the selected VMM process, the
  backend validates finite CPU, memory, swap, task, FD and time limits against
  the admitted plan and operator policy. Linux resource-group placement must be
  atomic with process creation, not a later move into a cgroup. `systemd-run` is
  permitted for these born-bounded resource scopes (claim 18). A mechanism that
  cannot enforce a required limit cannot launch. Numeric role profiles and their
  enforcement need review and evidence; this decision invents no default budget.
- **Production helpers are bounded by invariants, not executable names.** Fixed
  programs with fixed, code-constructed argv, including `find`, `stat`, `kill`,
  `mkfs`, `nft` and `systemd-run`, are permitted when signed admission, secret
  custody, containment and typed lifecycle ownership hold. Shell command strings
  built from untrusted input, every workload launch outside signed admission
  (claims 8 and 10), and secrets in argv or the process environment (claim 13)
  are forbidden. Prefer typed/in-process replacements on hot paths for
  performance and simpler lifecycle ownership, not as a blanket security
  prohibition on utility names. Development, build, test and operator tooling
  are outside this production-runtime restriction.
- **Authority is closed and prepared.** The original admitted typed plan
  authorizes every workload launch, and only the selected verified VMM binary
  may serve as that workload's VMM. Final effective
  configuration, environment, generation and retained descriptors stay bound
  to that admission. Caller-provided program paths, argv, PIDs or callbacks are
  not execution authority; no arbitrary public program/argv API is exposed, and
  deferred build, probing or signing is not a launch step.
- **Original ownership survives failure.** The original process/generation
  observer, runtime/file leases, required role owners and capture writer remain
  held through activation, dispatch, flush and confirmed stop. Uncertain stop or
  writer state remains nonterminal: no destructive cleanup, partial publication
  or terminal audit seal. PID disappearance alone is not terminal proof.
- **Existing security boundaries remain.** Keep the VMM supervisor, FlowMux
  endpoint, broker/signer key-holder, host-agent and conditional GPU roles
  separate and use only those required by the selected backend. Parser/signer
  process isolation must not collapse merely to reduce process count. This
  authorizes no additional service or generic helper. Signed grants,
  chain-signed audit, the NIC-less guest and authenticated vsock path remain
  binding; keys and raw
  credentials do not move into the parser, VMM or guest.

The alternative of a new privileged launch service was not approved: it would
add privileged IPC, installation and lifecycle authority beyond this contract.
Implementation must remove the old escalation route and every utility path that
violates these invariants, and demonstrate pre-birth refusal, bounded readiness,
confirmed stop, retained recovery ownership and cleanup before runtime parity is
claimed. Installation, activation, native
or privileged witnesses, billable runs, signing and release actions still need
their applicable authorization. This decision alone satisfies none of those
execution or acceptance gates.

### Per-backend tier matrix

mvm ships four workload-capable VM backends plus a test-only mock and an
explicitly claims-free browser preview backend. A given run carries the
tier of its *active* backend, not the strongest tier the project
supports; `mvmctl doctor` renders this matrix per host with the active
backend highlighted, and the CLI surfaces a loud banner when the active
backend falls below Tier 1.

<!-- tier-matrix:begin -->
| Backend | L1 | L2 | L3 | L4 | L5 | Notes |
|---|---|---|---|---|---|---|
| Firecracker (Linux + KVM) | ✅ | ✅ | ✅ | ✅ | ✅ | **Tier 1** — the production workload runtime, selected automatically whenever native KVM is available. Every numbered claim holds. |
| HVF / Hypervisor.framework (macOS 26+ Apple Silicon) | ✅ | ✅ | ⚠️ block+ext4 verified boot only | ✅ | ✅ | Tier 2 — the in-house Hypervisor.framework VMM. Egress, admission, and substitution are enforced through a single per-VM vsock gating endpoint: there is no guest network interface and no separate userspace gateway sidecar. The macOS 26+ Apple Silicon default. |
| libkrun (Linux KVM, macOS Hypervisor.framework) | ✅ | ✅ | ⚠️ block+ext4 verified boot only | ✅ | ✅ | Tier 2 — comparable VMM TCB to Firecracker. An explicit opt-in for source builds on macOS 26+ and Linux (`--hypervisor libkrun` / `--builder libkrun`); no release install stages it. macOS below 26 is unsupported: `install.sh` and `mvmctl` refuse there. |
| QEMU (Linux KVM/TCG) | ✅ KVM where available | ⚠️ larger device-model TCB | ⚠️ partial verified boot | ✅ | ✅ | Tier 2 — a `mvm`-only Linux dev/test substrate, opt-in only, never reachable from the fleet orchestrator. It carries no untrusted multi-tenant workload, so claim-10 egress enforcement is deliberately not wired into its start path. This carve-out is type-enforced: a `WorkloadBackend` marker trait gates the admitted workload-launch path, and QEMU does not implement it, so it cannot reach that path regardless of prose. The test-only mock backend does implement the marker — it is a hermetic lifecycle test double that carries no real workload, so permitting it costs nothing. |
| `wasm-sandbox` (browser / WASI preview) | ❌ | ❌ | ❌ | ❌ | ❌ | **Off the isolation scale.** No KVM, no real kernel, no TAP/virtio/vsock. Asserts none of the numbered claims and declares its own non-virtualization honestly; fails closed on any kernel/TAP/vsock request. Opt-in only; auto-detection never selects it. It is safe *because* it is single-principal — a developer's own code in their own browser sandbox, where the "malicious guest" adversary class does not apply — not because it holds any isolation claim. Promotion to a real, claim-bearing microVM re-materializes the workload from recorded intent through the audited build and admission pipeline; nothing produced in this claims-free tier carries authority into a claim-bearing one. |
<!-- tier-matrix:end -->

The `check-tier-matrix` gate derives the L1–L5 symbols in this table
from each backend's `security_profile()`; the Notes column is prose and
is deliberately outside derivation scope — the gate asserts nothing
about it.

**Matrix scope — networking.** Every claim-bearing workload backend is
NIC-less. The former `l3-vsock` compatibility mode and its guest TUN, packet
protocol, host forwarders, and public selector have been deleted. QEMU's
explicit dev/test user-mode networking remains outside the production
workload claim boundary described by this matrix.

**Tier discipline.** Tier 1 is the production default and the only tier
that carries every numbered claim. Tier 2 backends hold every claim
except claim 3, which is scoped to the block+ext4 backends. There is no
Tier 3: a shared-kernel container runtime holds none of the L1–L3
isolation claims, so mvm ships no container-based backend at any tier.

**Claim-10 coverage.** Claim 10's default-deny egress is enforced at **one**
seam for every backend that runs an untrusted workload: the authenticated
FlowMux session on `GuestService::NetworkFlow` terminates in one per-VM
`mvm-network-endpoint`. One projection of the admitted signed plan supplies
the endpoint's policy gate, resource budget, VM identity, declared ingress,
typed connector, and payload-free audit sink. The endpoint is the only owner
of workload outbound sockets and admitted ingress listeners.

There is no packet-filter chokepoint because the guest has no routable network
interface: Firecracker omits `/network-interfaces`, libkrun uses its direct
vsock mode, and the HVF device model has no net device. TCP, UDP, controlled
DNS, typed HTTP, and declared ingress are framed operations on the authenticated
session; the host opens an external socket only after the shared gate admits
the operation.

Two permanent gates keep that true. `xtask check-single-network-path` pins all
claim-bearing runners to the shared endpoint spawner, requires the one
`NetworkFlow` channel, rejects retired L3/NIC symbols, and inventories every
production workload `connect` and listener bind. `xtask
check-one-guest-protocol` rejects a guest caller of the network-flow port that
does not construct a FlowMux client. Synthetic negative fixtures prove a
second path or socket owner fails CI, while a projection test proves all flow
classes share the same admitted object graph.

**The retired `l3-vsock` path.** Two earlier ADRs historically supplied an
opt-in raw-packet compatibility mode. ADR-003 retired them, and the public
mode, guest TUN and agent, packet protocol, policy branch, host forwarders,
VMM hooks, dependencies, packaging, and temporary migration ratchets are now
deleted. Stale serialized declarations fail at the outer compatibility
boundary with guidance toward loopback adapters and typed connectors; the
rejected mode is not representable in admitted domain types.

*Corrected 2026-08-02.* This section previously described enforcement as
"Firecracker via nftables default-deny on the TAP, and libkrun via the
gateway-bridge `PlanFlowPolicy`". That predates the vsock-egress convergence
and had stopped being true: a workload has no TAP to put nftables on. The
mechanism was sound throughout — the description of it was not, which matters
because this document is what a reviewer reads to decide whether to trust the
posture.

**Deny-all posture.** A plan without a network grant has no `NetworkFlow`
capability, and the NIC-less guest has no route around that absence. A plan
with a narrow grant still begins from the same default-deny gate; only an
admitted typed flow can cause the host endpoint to resolve a name, connect a
socket, or bind an ingress listener.

**Retired packet-path scans.** A host-side scan chain used to sit on the
guest-NIC packet path: mandatory-deny egress, an L4 policy scan, a DNS
sink-hole, a placeholder-leak scan, and an inbound SSH banner classifier. It
lost its last caller when the guest NIC went away and has been deleted. What
each asserted, and where it holds now:

- *Link-local, cloud metadata, CGNAT, loopback* (`169.254.169.254`,
  `169.254.0.0/16`, `100.64.0.0/10`, `127.0.0.0/8`, `::1`, `fe80::/10`):
  `CanonicalEgress::permits` refuses these before consulting any rule, under an
  unrestricted policy too, and `EgressGate` applies it to every address it
  admits — a numeric target, each pinned address of a named host, and each
  address a live lookup returns.
- *TCP/22*: refused by the same predicate, under every policy.
- *The L4 allow-list*: `EgressGate` over the canonical projection of the
  admitted policy.
- *DNS names*: `EgressGate::dns_verdict` answers only pinned names under an
  allow-list, and strips private, loopback, link-local, and unique-local
  answers from a live lookup under an unrestricted policy. That gates questions
  asked through the host resolver, which is the only way a guest under an
  allow-list resolves a name. A bare `NetworkPolicy` allow-list projects TCP
  rules for its pinned hosts and no UDP rule at all, port 53 included, so it
  cannot be used to reach a resolver of the guest's choosing, public or on the
  host's own network. The endpoint refuses a UDP association outright when the
  admitted policy admits no datagram, and records the refusal as a chain-signed
  `host.flow.denied` entry with `class=udp` and `reason=policy_denied`. Only an
  unrestricted policy admits datagrams, and those carry no qname check.
- *A placeholder outside the substituted headers*: no equivalent. The typed
  HTTP path substitutes and checks headers only, so a placeholder in a URL or
  body is forwarded as-is (#3297). The placeholder is not the secret, so this
  is a failure of the substitution contract rather than a disclosure.
- *The inbound SSH banner classifier*: dropped, not ported. Guests ship no SSH
  server, TCP/22 is refused at the gate, and a banner match is blinded by
  wrapping the protocol in TLS, so it detected a service that cannot exist by
  a signature any adversary can hide.

**Verified-boot scoping (claim 3).** dm-verity is block-device-specific:
it covers the block+ext4 backends — Firecracker and the in-process
materialize path. A virtiofs root serves a host directory, not a block
device, so it cannot be dm-verity-sealed; it is a dev/local-tier boot
mechanism with an explicitly weaker contract (unpack-time per-layer
SHA-256 verification, then read-only serving from the trusted host, with
no guest-enforced re-verification) and does not witness claim 3.
Production, sealed, and every Firecracker tier stay on the block+ext4
path, where claim 3 holds unchanged.

### Framework references

Each claim named in adversary-technique and defensive-technique
vocabulary, for cross-reference only — the CI gate above, not the
framework mapping, is the source of truth.

| # | Adversary technique denied | Defensive technique instantiated |
|---|---|---|
| 1 | T1611 (Escape to Host) | Process segmentation, mandatory access control; privilege restriction, segmentation |
| 2 | T1548 (Abuse Elevation Control), T1068 (Exploitation for Privilege Escalation) | Local file permissions, system call permissions; privilege restriction |
| 3 | T1542.003 (Bootkit), T1601 (Modify System Image) | System boot verification; substantiated integrity |
| 4 | T1059 (Command and Scripting Interpreter — surface eliminated, not detected) | Scope reduction by build-time exclusion |
| 5 | T1190-class (exploit of the host↔guest interface) | Substantiated integrity via fuzzing and `deny_unknown_fields` |
| 6 | T1195.002 (Compromise Software Supply Chain) | Executable integrity via hash and signature verification |
| 7 | T1195.001 (Compromise Software Dependencies and Development Tools) | Software composition analysis; substantiated integrity |
| 8 | T1565 (Data Manipulation), T1574 (Hijack Execution Flow — policy substitution variant) | Authentication, authorization; every launch traces back to a signed, validity-windowed plan |
| 9 | T1195.002 (image variant), T1565.001 (Stored Data Manipulation) | Authentication, executable integrity; manifest-signed and key_id-pinned trust establishment |
| 10 | T1071 (Application Layer Protocol — exfiltration channel), T1041 (Exfiltration Over C2 Channel) | Network traffic filtering; deny-all default, egress as explicit opt-in |
| 11 | T1195.001 (app-layer variant), T1565.001 (deps-volume variant) | Software composition analysis, executable integrity; hash-locked, SBOM- and CVE-scanned, attested sealed volume |
| 12 | T1574 (capability-granting variant), T1078 (Valid Accounts — unauthorized service invocation) | Authorization; signed binding gate, enforced dispatch, chain-signed audit |
| 13 | T1078 (unauthorized audit attribution), T1565 (audit-chain variant) | Authentication, authorization; workload-emitted entries chain-signed under a distinct audit category |
| 15 | T1021 (Remote Services — interactive session into a sealed workload), T1059 (interactive console surface eliminated, not detected) | Scope reduction by build-time exclusion, same family as claim 4 |
| 17 | T1059 (driving a running interpreter through its stdin), T1078 (Valid Accounts — unauthorized write into a workload's input) | Authorization, execution isolation; signed grant gate, single-writer lease, chain-signed refusal audit |

### Cold-state guarantee

A workload's runtime state does not survive its own teardown, and the
next boot on the same host is fresh. This is a structural property of
the runtime today rather than a single CI-gated claim; promotion to a
witnessed, numbered claim is pending a machine-checked test. Scope is
strictly per-workload — one guest is one workload — and this is not a
claim about hypervisor or DRAM scrubbing, which stays out of scope under
the trusted-host model.

### Boundary language: Rust by default at the guest control surface

Every binary in the guest's blast radius — init, netinit, the agent, and
in-boot addons — and every host-side binary that participates in the
audit chain or signs material is Rust by default, and that default is
not negotiable case by case.

Before any non-Rust language is considered for boundary code, the lean-Rust
discipline must be evaluated first: replacing `tokio` with a small
hand-rolled executor where async ergonomics are not load-bearing,
replacing `serde_json` with hand-rolled per-variant parsers on a small
stable wire surface, and replacing broad netlink crates with narrow
manual netlink for one-shot usage.

A non-Rust language may be proposed for boundary code only when all of
the following hold: the binary has a narrow, stable ABI surface (a
netlink-route installer or a vsock diagnostics probe qualify; broad
protocol stacks like OCI, PGP, or an async runtime do not); the binary
does not drive the audit chain, which stays single-language by
construction; and the native language measurably reduces supply-chain
surface or boundary footprint, evidenced rather than asserted. Any
adopted non-Rust boundary binary ships side by side with the Rust
implementation, opt-in by default, until proven across a full release
cycle before its default flips — and the Rust implementation is removed
only in a later, separate change after that. There is no non-Rust code at
the guest control boundary today.

### Browser-reachable surface: verification, not virtualization

mvm virtualizes on real hardware — Firecracker and libkrun over KVM, HVF
over Hypervisor.framework. It does not run a CPU emulator, so it does not
pursue "run microVMs in the browser": that capability is incompatible
with hardware virtualization, and a wasm/emulator backend is the wrong
shape for the workload-backend trait (kernel path, ext4 rootfs, TAP,
pause/resume, vsock are nearly all not applicable).

What mvm does grow is a serverless, in-browser *verification* surface for
its signed artifacts: a dependency-light, wasm-clean leaf crate
re-implements the audit-chain verifier against an in-memory string and an
Ed25519 public key, with byte-exact parity to the native verifier pinned
by a cross-crate test. An operator can verify a downloaded audit log and
a host signer's public key in a browser tab with nothing leaving the
page — no host, no backend. Verification cores must be wasm-clean leaf
crates: no async runtime, no libc, no heavy dependency graph in the
compiled artifact. A browser-reachable interactive *console* against a
live microVM remains out of scope for this repository; it is
fleet-orchestration territory that must keep the console byte-stream and
its protocol cleanly bridgeable, nothing more.

### Dev-VM mutation boundary

A dev microVM is a mutable work surface only. Its rootfs mutations, ad
hoc package installs, and dev-lifecycle side effects never implicitly
flow into a production or sealed build or runtime. A production build may
depend only on declared inputs: host workspace files and committed
source, declared config and lockfiles, explicitly mounted host
directories that are part of the build-input model, and explicitly
exported or promoted artifacts that re-enter the system through a
declared input path. "It existed in the dev VM" is never itself a
promotion mechanism; a dev-produced change that should matter to
production must cross the boundary as a host workspace edit, an explicit
export, or a signed artifact re-admitted through a declared input path.

"No SSH in microVMs, ever" is absolute, with no dev-tier carve-out:
private key files, `~/.ssh/`, known-hosts material, SSH clients, SSH
servers, SSH config, and any form of host ssh-agent forwarding are never
copied, mounted, installed, or bridged into any guest template, on any
tier or run posture. A host ssh-agent socket in particular is never
forwarded — doing so would hand a guest every key the agent holds,
bypassing the bound-destination, claim-13/16 secret-substitution model
this ADR otherwise requires. The sole interactive path into a microVM is
the console PTY-over-vsock transport on a dev-tier machine (claim 15
gates it out of sealed production); nothing SSH-shaped exists anywhere in
this repository. `scripts/check-no-ssh.sh` (CI: `no-ssh-forwarding`) greps
source for SSH-capability identifiers as a regression backstop, and the
`sealed-prod-no-ssh` lane scans the assembled runtime overlay; both are claim 15
ledger witnesses, so the scheduled-freshness gate watches them.
Every dev-tier hook — writable registered directory snapshots,
dev-lifecycle side effects — stays visible in dry-run, admission and audit
output, and receipts; it is never hidden behind a convenience default. No
profile grants a live writable host directory: a transient run's directory
share is a read-only snapshot, and a persistent machine refuses a directory
volume at spec time under every profile. A writable disk-image volume
(`HOST.img:/GUEST:SIZE:rw`) is not a dev-tier hook: the guest writes into its
own ext4 image file, never into the host filesystem, so every profile that
accepts volumes accepts it, the default and `--prod` included. It is still
declared in the signed plan's shares and recorded in the same outputs, and the
guest mount allow-list still decides where it may mount.

### Cloud control-plane trust boundary

**Status: proposed, not yet accepted.** A future hosted, multi-tenant
control plane inverts two of this ADR's own scoping decisions: it owns
the host (so a malicious host partly re-enters scope from the tenant's
perspective) and it hosts many tenants on shared infrastructure (so
multi-tenant guests re-enter scope). The intended shape, recorded here
for continuity rather than as an accepted decision, is that the cloud
tier is a strict superset of this ADR's fifteen claims plus a named set
of multi-tenant claims — cross-tenant isolation with a database-level
fail-closed backstop, admission under fleet authority, control-plane
replay resistance, and per-tenant resource bounds — each with its own
CI-witnessed gate, owned by the sibling fleet-orchestration product's own
claim catalog. A control that exists but is not on the enforced request
path with a passing witness counts as absent, not as done. Any client
surface that can reach both a local, host-authoritative path and a
remote, fleet-authoritative path must keep the acting authority
observable and must never let a locally-signed artifact be honored by
the remote authority, or vice versa.

### Reversible replacement on owned cleartext paths

**Status: proposed, not yet accepted.** Where the runtime owns both sides
of a cleartext request/response flow, a request-scoped mechanism may
detect secret- and PII-shaped spans on the outbound leg, replace them
with opaque tokens, and restore only exact token echoes on the inbound
leg — never a semantic or paraphrase-aware recovery. This composes with,
and runs before, the existing one-way redaction and host-side declared-secret
substitution; its policy travels inside the signed `ExecutionPlan`, and
every replace/reinject event is recorded as plaintext-free proof metadata
(flow id, sensitive class, surface, offsets, token id, and keyed digests
of the original and rewritten bytes) rather than the value itself. This
reinforces claims 12 and 13 on the egress-delivery path; it does not
replace either.

## The check-time law

*An effect may be checked no later than its last undo point.*

We have obeyed this in two places without ever having stated it, which made it
a judgement call each time instead of a lookup. A reversible effect can be
checked at commit, because there is still something to undo. An irreversible
one — a packet on the wire, a published artifact, a released secret — must be
checked before it happens, because after it happens there is no state to
restore.

This is why `EgressGate` sits before the connection is opened rather than after
the first byte, and why the audit chain records after the fact: the connection
cannot be un-opened, and the record is not the effect.

The value is prospective. When a new governed effect appears, "where does its
gate go?" stops being a design discussion and becomes a question about whether
the effect has an undo point.

| Governed effect | Checked | Why |
| --- | --- | --- |
| Outbound connection (claim 10) | before | A packet on the wire cannot be recalled. |
| Secret substitution (claims 12, 13) | before | A credential that reached the guest is disclosed, whatever happens next. |
| Workload admission (claim 8) | before | Admission authorizes a boot; the boot is the effect. |
| Rootfs integrity (claim 3) | before | A tampered image that executes has already run. |
| Capability/`no_new_privs` drop | before | Both are one-way and inherited across exec; after exec there is nothing to drop. |
| Ingress listener bind (Plan 316 phase 5) | before | A bound port is reachable from the moment it binds. |
| Audit chain append (claim 8) | at commit | The record is evidence of an effect, not the effect. |
| Execution receipt | at commit | A record, not a control — a failed emit is logged and does not block admission. |
| Resource-usage accounting (preview 18) | at commit | Charges an effect that already occurred; the ceiling is the before-check. |

A row that says *before* and a mechanism that runs after is a defect, not a
tuning decision.

## Consequences

### Positive

- The project's security story is eighteen enumerated, CI-enforced claims
  plus three preview claims, each with a named witness, rather than a single
  vsock-only assertion resting on unstated layers beneath it.
- A new contributor gets one document that states what mvm protects
  against, what it explicitly does not, and how each protection is
  enforced in the tree today.
- The per-backend tier matrix makes "which guarantees does *my* run
  carry" a lookup, not a guess.

### Negative / accepted costs

- The production guest closure carries the dedicated static `mvm-setpriv`
  helper for the per-service privilege drop.
- dm-verity adds a second block device per VM and a small first-boot
  cost.
- `cargo-deny` and `cargo-audit` occasionally block a merge on an
  upstream advisory; that friction is the point, and is accepted.
- Reversing the per-service uid model would require every guest flake to
  be re-audited for cross-service file-sharing assumptions built on the
  old shared group.
- Reversing verified boot means dropping a numbered claim outright, which
  itself warrants a superseding decision record rather than a quiet
  rollback.
- Guest telemetry is scrubbed on the host against the VM's bound-secret
  fingerprints and the curated redaction seam before it is persisted
  (defence in depth under claim 13, not a claim of its own). A secret split
  across stdio chunks is caught by joining each chunk to its stream's last
  bytes, but a guest that pauses more than 500 ms mid-secret gets the part
  before the pause written; only the completing chunk is withheld, and two
  processes writing one stream at once can separate a split secret's pieces
  far enough to be missed. Holding
  output longer would delay every quiet stream, and the host holds
  fingerprints, not values, so it cannot recognise a secret's prefix. See
  `specs/contracts/studio-telemetry-contract.md`.

### Non-goals

- **Malicious host defense.**
- **Multi-tenant guests**, at the `mvm` layer.
- **Hardware-backed key attestation as a defense against a malicious host.**
  TPM2 measured-boot quotes are supported as an opt-in attestation input,
  but they do not by themselves defeat a compromised host.
- **Network policy enforcement inside the dev/test-only QEMU backend.**
  The `NetworkPolicy` type and the seccomp tier filter network syscalls,
  but QEMU's start path carries no untrusted workload and is
  type-excluded from the admitted launch path, so egress enforcement is
  deliberately not wired there.

## Claims ledger (claim → witness)

<!-- claims-catalog:begin -->
---
claim: catalog
status: Shipped
gated_phrases: []
exempt_paths: []
---

# Conformance claim catalog

The machine-checked map from each numbered security claim (the narrative
lives in `CLAUDE.md` §"Security model" and `specs/adrs/001-microvm-security-posture.md`)
to the witnesses that ratify it. `xtask check-claim-catalog` parses the
table below on every PR and fails when a named witness no longer exists,
so the claim list cannot silently drift from the tree.

Witness tokens are typed:

- `fn:NAME` — a `fn NAME(` must exist under `crates/` (a test, or the impl
  symbol the claim exercises).
- `ci:NAME` — `NAME` must appear in some `.github/workflows/*` file (a job
  key or lane name).

The witnesses here are a representative anchor per claim, not the full
test list — enough that a rename or deletion trips the gate. Grounding
each witness in an *external* authority (vs. a self-referential check) is
tracked separately as a follow-up audit (see "deferred follow-ups").

| #  | Claim | Witnesses | Authority | Status |
|----|-------|-----------|-----------|--------|
| 1  | No host-fs access from a guest beyond explicit shares | fn:seccomp_allows_listed_denies_unlisted, ci:seccomp-functional, fn:an_exec_under_the_admitted_standard_tier_cannot_open_a_socket, fn:a_started_process_under_the_admitted_standard_tier_cannot_open_a_socket, fn:an_exec_child_reports_a_seccomp_filter_and_no_new_privs, fn:a_warm_claimed_child_under_standard_cannot_open_a_socket, fn:a_warm_claimed_childs_workload_reports_a_seccomp_filter, fn:a_child_must_report_holding_the_admitted_seccomp_tier, fn:admitted_seccomp_tier_grants_sockets_only_to_a_launch_that_needs_them, fn:a_gpu_grant_admits_the_vsock_tier_and_no_wider, fn:vsock_tier_allows_an_af_vsock_socket_and_denies_af_inet, fn:standard_tier_denies_an_af_vsock_socket_with_eperm, fn:validated_conversion_enforces_mount_allow_list, fn:bare_mnt_is_refused_because_it_shadows_the_config_drive, fn:dir_share_two_part_defaults_ro, fn:libkrun_refuses_any_virtio_fs_share_before_mapping, fn:enforce_admitted_shares_refuses_unadmitted_or_mismatched | the plan's admitted seccomp tier, named to the guest as `mvm.seccomp=<tier>` on the kernel cmdline — or, for a child warm-claimed out of a standby parent that booted with no plan, on the post-restore handshake, which the child's agent must answer holding exactly that tier before the claim commits — and installed by the guest agent, after the child's other pre-exec setup and with `no_new_privs`, in every workload process it starts (entrypoint runs and the worker pool, exec, process control, detached runs, the console, lifecycle hooks and health probes); admission raises a tier below `network` to `network` when the launch admits egress, an ingress mapping or a host service, and signs the raised tier; a launch whose only socket need is a GPU grant is raised to `vsock` instead, which admits `AF_VSOCK` sockets for workload processes and nothing more — `socket` for any other address family still fails with `EPERM`, and a launch without a GPU grant keeps a tier that refuses vsock sockets too. Limits: a cold boot whose guest agent is older than the token runs its workloads unfiltered, which includes the one in the pinned image set a release binary boots until it assembles its own guest runtime; a warm claim whose child agent predates the handshake field, or reports any other tier, is refused rather than run unfiltered; a warm-process worker pool started in the standby parent ran unfiltered, so a claim admitting an enforcing tier over it is refused; a VM restored from a template snapshot keeps the tier its captured VM admitted, not the restoring launch's; a denied call fails with `EPERM` rather than killing the process + `mvm-setpriv --no-new-privs` + agent-side `PR_CAPBSET_DROP` + user-volume allow-list, refusing both descendants and ancestors of a runtime path / ro-default / admission-enforced shares (mvm-core + mvm-cli + mvm-backend + mvm-agentd) | Shipped |
| 2  | No guest binary can elevate to uid 0 | fn:drops_identity_groups_capabilities_and_enables_no_new_privs, fn:set_no_new_privs_actually_sets_the_kernel_bit, fn:rejects_a_drop_without_no_new_privs, fn:never_writes_a_uid_zero_entry, fn:the_rootfs_is_always_mounted_read_only, fn:the_workload_identity_is_never_root | `mvm-setpriv --no-new-privs` + a read-only rootfs mount (dm-verity sealed); nothing is mounted over `/etc/passwd`, `/etc/group` or `/etc/nsswitch.conf` separately, and the only writer of those files is the pre-drop provisioner, which appends a non-root workload entry and never rewrites a line. The helper test that drops identity runs only as root and skips otherwise | Shipped |
| 3  | A tampered rootfs ext4 fails to boot | ci:verified-boot-artifacts, fn:verify_and_resume_rejects_tampered_mem, fn:a_fresh_release_install_assembles_every_piece_from_its_own_archive, fn:a_single_flipped_byte_in_any_block_no_longer_matches_the_recorded_root, fn:seal_detects_post_format_rootfs_tamper, fn:every_runtime_identity_component_is_pinned | dm-verity + roothash on **block+ext4** backends — Firecracker + Option B; `ActivateEnvironment` supplies the root hashes to the initramfs agent. The runtime overlay's roothash is the one the host computed when it assembled the overlay from a guest-runtime archive (the source build's, or the release binary's own signed archive); the selected roothash is compared with the authenticated declaration and recorded in the signed runtime identity. The restore path also verifies the sealed snapshot envelope (HMAC + epoch) before resuming. A virtiofs root serves a trusted-host directory rather than a block device and therefore does **not** witness this claim; see "Claim 3 backend scoping" below | Shipped |
| 4  | A production-safe run cannot invoke DevOnly guest-agent verbs | fn:prod_safe_grant_refuses_all_dev_only_requests, ci:guest-agent-runtime-boundary | runtime profile + signed VerbGrant intersection | Shipped |
| 5  | Vsock framing + supervisor-config JSON + FlowMux decode/state are fuzzed | ci:fuzz_guest_request, ci:fuzz_sealed_frame, ci:fuzz_supervisor_config, ci:fuzz_network_flow_decode, ci:fuzz_network_flow_state, ci:fuzz_input_frame | cargo-fuzz | Shipped |
| 6  | The pre-built dev image is hash-verified | ci:hash-verify-tests, fn:acquire_from, fn:a_member_whose_bytes_differ_from_the_root_is_refused_and_removed, fn:the_hash_skip_hatch_does_not_admit_a_member_the_root_does_not_describe | signed image-set root + member SHA-256, over the kernels, base root filesystems, builder image and Stage 0 seeds; the guest runtime a release binary assembles its overlay, initramfs and SDK sidecars from is a CLI release asset and is claim 20's | Shipped |
| 7  | Cargo deps are checked on dependency-changing PRs, nightly, and before release signing | ci:cargo-deny, ci:cargo-audit, ci:reproducibility | RUSTSEC + deny.toml + shared pinned checker action; release jobs require successful checks of the calling revision; required PR checks depend on repository rules; reproducibility double-build | Shipped |
| 8  | Every workload runs from a signed, audited ExecutionPlan | fn:synthesize_plan, fn:admit_for_run, fn:verify_audit_chain, fn:a_tampered_payload_is_refused, fn:an_unknown_signer_is_refused, fn:a_not_yet_valid_plan_is_refused, fn:a_replayed_nonce_is_refused, fn:admission_refuses_before_signing, fn:propagates_synthesis_failures, fn:naively_dropping_old_entries_fails_verification_at_line_zero, fn:a_prune_record_that_over_claims_is_refused, fn:the_same_deletion_without_a_record_is_still_refused, fn:pruning_a_broken_chain_is_refused_before_anything_is_deleted, fn:a_spliced_segment_is_refused, fn:a_missing_segment_is_named_not_silently_skipped, fn:an_interrupted_rotation_continues_history_instead_of_restarting_it, fn:a_correctly_signed_seal_that_lies_is_refused_field_by_field, fn:truncating_through_the_seal_leaves_the_session_unsealed | Ed25519 + chain-signed audit log (ADR-014). The chain may be rotated into sequenced segments (Plan 319): `verify_audit_chain` now attests an unbroken chain from genesis **or from a signed handoff naming its predecessor segment and that predecessor's final chain hash**, and `verify_segment_set` attests the ordering and completeness of the segment set. A retired prefix may also be deliberately pruned (Plan 326): the chain then verifies **with a corroborated gap** rather than whole, and the prune record may only claim what the surviving handoff independently attests, so it cannot relabel an edit as a removal. Only the upper boundary of a pruned range is cross-checked. Each session that reaches its end is closed by a chain-signed `session.sealed` record (entry count, first/last entry, chain head, RFC 6962 root over the session's entries, link to the previous seal) that `trust audit verify <session>` holds to the chain field by field; truncating through a seal turns the session `UNSEALED`. Tail truncation of whole sessions, and of a session that never sealed, stays undetectable without an off-host witnessed root | Shipped |
| 9  | Every published bundle is content-addressed and re-verified | fn:read_and_verify_bundle, fn:verify_plan_bundle, fn:a_builtin_author_key_verifies_with_no_enrollment, fn:a_revoked_builtin_key_is_refused, fn:an_installed_rootfs_changed_after_install_is_refused_at_admission, fn:every_installed_artifact_is_checked_not_only_the_ones_the_plan_pins | SHA-256 content-addressing (Sprint 52 W2); a boot from an installed bundle pins its archive in the signed plan, and admission refuses (`plan.failed`, class `bundle-verify`) a boot whose extracted artifacts or manifest no longer match the signed manifest | Shipped |
| 10 | No untrusted workload reaches the network unless policy-admitted | fn:a_flow_no_rule_admits_is_refused_and_audited_under_the_default_policy, fn:open_tcp_to_unknown_host_is_refused_by_default_deny_gate, fn:policy_default_is_deny_all, fn:run_net_default_is_deny_all, ci:single-network-path, ci:fuzz_dns_codec, fn:private_link_local_loopback_ula_metadata_are_forbidden, fn:a_resolver_only_runs_after_the_admission_record, fn:admitted_projection_is_one_object_graph_for_every_network_surface, fn:assert_vsock_only_device_model, fn:verify_and_resume_refuses_nic_on_restore, fn:fork_restore_refuses_nic, fn:private_range_is_denied_by_default_and_readmitted_only_by_a_grant_naming_it, fn:metadata_and_the_absolute_ranges_are_never_readmitted, fn:a_name_that_resolves_inward_is_refused_as_the_address_it_reached, fn:an_embedded_ipv4_form_is_classified_by_the_address_it_reaches, fn:the_forward_leg_gets_the_gate_s_answer_not_a_fresh_lookup | one authenticated FlowMux endpoint + one admitted policy/budget/identity/audit projection + permanent single-path/socket-owner gate + bounded DNS codec fuzzing + DNS-answer SSRF/rebinding filtering + chain-signed per-query DNS audit; warm-restore and fork-restore refuse any restored device model carrying a NIC before resuming vCPUs + private-range default deny (RFC1918, ULA, multicast, reserved; re-admitted only by a grant naming the address) and absolute deny of metadata, loopback, link-local, CGNAT, the unspecified block and embedded IPv4 forms, each refusal audited with its class + the forward leg connects only to gate-admitted addresses | Shipped |
| 11 | App-dep volumes are CVE-scanned and SBOM-enumerated when sealed and hash-locked, and re-verified when the build cache reuses a volume | ci:app-deps-audit, fn:verify_sealed_volume, fn:verify_detects_tampered_content, fn:verify_detects_tampered_cve, fn:verify_detects_tampered_sbom, fn:apply_install_gate, fn:prod_rejects_high_cve_finding_pip_audit_shape, fn:prod_rejects_stub_sbom_as_missing_sbom | CycloneDX + pip-audit at seal time; No launch path attaches a dependency volume or verifies one at admission (issue #5962). The severity gate has no production launch caller and is declared dormant. | Shipped |
| 12 | Every host-side service binding is plan-gated and audited | fn:unbound_service_returns_not_bound, fn:a_policy_refusal_is_audited_without_the_argument_value, fn:service_call_rejects_unknown_envelope_fields | ExecutionPlan.services binding (ADR-020) | Shipped |
| 13 | The managed substitution path hands the guest placeholders, never raw secret values | fn:handed_placeholders_never_contain_the_secret_value, fn:endpoint_bin_serves_substitution_and_refuses_unbound_destination, fn:substitute_bound_credential | host-side substitution endpoint (ADR-023): the endpoint-minted environment handed to the guest contains placeholders, and the real credential is resolved only on the admitted host-side request path. The placeholders reach the workload per entrypoint call, not on the kernel cmdline (the `mvm.secret_env` token was removed); the bound-credential control uniquely names the real substitution implementation | Shipped |
| 14 | OCI image provenance is recorded in the chain-signed audit log | fn:oci_provenance_event_is_chain_signed_with_required_labels, fn:prod_pull_requires_digest_pin_before_network, fn:prod_run_image_requires_digest_pin_before_network | cosign + OCI digest (ADR-054), recorded on the claim 8 admission flow (ADR-014). Unchanged in substance by Plan 319, but a `plan.oci_provenance` entry may now sit in a retired segment, so the claim holds over the tenant's segment *set* rather than over `<tenant>.jsonl` alone — `mvmctl trust audit verify` walks the set | Shipped |
| 15 | A sealed production microVM has no shell, no DevOnly guest-agent verbs, and no PTY | fn:console_refused_on_sealed_image, ci:guest-agent-runtime-boundary, fn:following_the_console_never_writes_to_it, ci:no-ssh-forwarding, ci:sealed-prod-no-ssh | runtime profile + signed VerbGrant + host accessible-gate + console policy. The host→guest input plane is deliberately *not* claimed here: its properties are policy, not absence, and are witnessed at row 17. The two no-SSH lanes witness the absence of a remote-login path: `no-ssh-forwarding` is a source grep for SSH-capability tokens, `sealed-prod-no-ssh` mounts the runtime overlay this tree assembles and scans it for `sshd`, host keys, `sshd_config` and `authorized_keys`. Neither inspects the base root filesystems, which are built and published by the image repository | Shipped |
| 16 | Egress substitution keeps a raw secret off the guest, bound-only, no value in audit | fn:handed_placeholders_never_contain_the_secret_value, fn:network_endpoint_refuses_unbound_destination, fn:audit_chain_carries_no_secret_value, fn:substitution_is_audited_when_upstream_fails_after_send | egress substitution leak-gate; reinforces claims 12+13 on the egress delivery (ADR-023) | Preview |
| 17 | Workload stdin is grant-gated, single-writer, secret-scanned across frames, and every refusal is audited | fn:input_is_refused_without_a_plan_grant, fn:a_second_writer_is_refused_while_the_lease_is_held, fn:secret_material_split_across_frames_is_still_refused, fn:every_refusal_is_audited, fn:a_shell_entrypoint_with_the_grant_is_refused_and_names_the_reason, fn:the_endpoint_fingerprints_what_it_resolved_and_reports_no_value, fn:the_handshakes_two_halves_go_to_two_different_places, fn:a_secret_split_across_two_frames_does_not_reassemble_in_the_workload, fn:a_fingerprint_refusal_does_not_claim_the_bytes_are_the_secret | input grant token in a signed ExecutionPlan.services + per-VM lease with TTL + fingerprint-matching sliding-window secret scan + chain-signed payload-free refusal audit + sealed-tier shell-entrypoint refusal. Read the limits note below before treating this as enforced | Preview |
| 18 | A workload's resource consumption is bounded at admission — per workload and across the host — and its VMM process is memory- and task-bounded, and CPU-bound when a share is granted, at spawn where the host has a mechanism | fn:a_boot_past_the_headroom_is_refused, fn:budget_ignores_dead_machines, fn:budget_counts_the_configured_maximum_not_current_usage, fn:an_empty_host_admits_a_boot_within_headroom, fn:an_unreadable_charge_record_is_skipped_rather_than_fatal, fn:admission_refuses_a_grant_over_the_ceiling, fn:the_ceiling_bounds_memory_even_though_no_one_granted_it, fn:prod_refuses_a_cpu_grant_on_a_backend_that_cannot_bound_cpu, fn:the_libkrun_tier_cannot_bound_cpu_off_linux, fn:host_cpu_mechanism_gap_honors_hvf_quota_range, fn:relay_config_threads_cpu_share_to_quota_scheduler, fn:apply_grants_reads_quota_record_from_state_dir, fn:a_share_grant_binds_the_spawn_when_the_mechanism_is_present, fn:a_spawn_with_no_grant_still_gets_memory_and_task_ceilings, fn:a_vm_with_no_recorded_scope_reads_back_as_declared_not_as_an_error, fn:a_scope_with_a_resolvable_cgroup_reads_back_its_enforcement, fn:an_unresponsive_manager_fails_the_launch_instead_of_hanging_it, fn:an_admitted_boot_writes_the_achieved_tier_to_the_audit_chain, fn:a_grant_that_cannot_be_applied_undoes_the_launch, fn:a_grant_that_fails_to_apply_refuses_the_cli_boot, fn:emit_memory_limit_exceeded_names_the_ceiling_and_the_mechanism, fn:a_wall_clock_bound_needs_a_clock_that_can_stop_the_workload, fn:a_signed_plan_from_the_launch_path_arms_the_timer, fn:a_granted_cpu_share_binds_a_real_spawn_to_its_quota, fn:a_spawn_past_its_memory_ceiling_is_killed_and_the_kill_is_recorded, fn:a_vmm_pushed_past_its_memory_ceiling_is_killed_and_audited, fn:a_firecracker_restored_child_is_cpu_bounded_by_its_admitted_grant, fn:an_hvf_restored_child_is_cpu_bounded_by_its_admitted_grant, fn:a_claimed_child_over_the_host_ceiling_is_refused, fn:a_claimed_child_within_the_ceiling_is_admitted, fn:the_refusal_names_the_ceiling_and_the_request, fn:pool_matching_is_unchanged_by_the_bound | operator-configured per-workload ceiling + host-wide budget summed over live machines only (pid-marker probe, configured maximum not current usage) + cgroup v2 `cpu.max` on a systemd transient scope on Linux, or an in-process HVF run-loop scheduler on macOS, read back and written to the chain-signed audit log + cgroup v2 `memory.max` (guest RAM plus a fixed overhead margin, swap excluded) and `pids.max` on that same scope for every VMM spawn on a Linux host with a systemd user session, read back with their values and audited, with an OOM kill recorded as `plan.memory_limit_exceeded` on the waited exit-report path. CPU is declared-only for libkrun, wall clock is enforced on the tiers whose supervisor holds the admitted plan (libkrun, HVF, AppleContainer), wasm bounds via fuel and epoch, a forked child is re-bound at spawn, and a warm-claimed child is bounded by the host ceiling at admission but spawn-bound on only one of its three claim paths — read the "Preview 18 limits" note below before treating this as enforced | Preview |
| 19 | Every workload asset and pinned host share is content-identified in the signed plan, and share drift after admission fails closed | fn:admitted_share_digest_refuses_directory_changed_after_admission, fn:synthesized_plan_records_share_and_caller_asset_identities, fn:asset_identities_event_carries_kind_name_digest_labels, fn:asset_identity_rejects_malformed_digests, fn:test_audit_asset_id_parses | content-derived AssetIdentity records inside the signed ExecutionPlan (digest validated as 64-hex at the type boundary) + admission-time share digest pins re-verified by `enforce_admitted_shares` at mount time + synthesis auto-derivation of the compute environment + chain-signed `plan.asset_identities` emission + offline digest recomputation via `trust audit asset id` | Shipped |
| 20 | Every published release artifact is authenticated under the release workflow's identity, directly or through a signed checksum manifest, and the build, fetch, install, and self-update paths refuse an artifact whose required signature is missing or invalid | ci:verify-release, ci:release-provenance, fn:accepted_identities_are_the_versioned_release_workflow, fn:a_missing_bundle_refuses_and_names_the_asset, fn:acquire_refuses_a_root_without_a_signature, fn:the_hash_skip_hatch_does_not_waive_the_root_signature, fn:an_archive_without_a_bundle_is_refused, fn:a_real_release_bundle_verifies_under_its_tag, fn:self_update_refuses_an_unsigned_checksum_manifest_before_parsing, fn:self_update_refuses_a_checksum_manifest_signed_for_another_tag, fn:fresh_install_trust_precedes_verifier_execution, fn:fresh_install_requires_tag_pinned_bundle, fn:fresh_install_has_no_unsigned_fallback, fn:an_unsigned_release_runtime_is_refused_and_nothing_is_cached, fn:a_release_runtime_that_misses_its_digest_is_refused_before_its_signature, fn:a_release_whose_evidence_does_not_verify_publishes_nothing, fn:the_cached_files_are_the_bytes_that_were_verified, fn:bootstrap_keeps_a_hatched_download_out_of_the_install, fn:bootstrap_refuses_a_hatched_download_before_any_other_step, fn:authenticated_bundle_returns_its_actual_signer_and_refuses_wrong_identity, fn:release_proof_without_a_launch_owned_set_cannot_be_admitted, fn:release_runtime_admission_refuses_missing_or_unwritable_audit_even_in_dev, fn:admitted_runtime_identity_is_chain_signed_and_tamper_detected | keyless cosign over release archives and checksum manifests with Fulcio + Rekor bundles; raw kernels, root filesystems, and metadata are authenticated by digest entries in those signed manifests. The `verify-release` job re-verifies the signatures after publication and checks each covered blob; the build gate refuses a missing or malformed bundle and production image-set acquisition refuses an unsigned pinned root before parsing. `mvmctl env update` verifies in-process. `install.sh` uses an installed verifier or cosign when available; on a fresh host it authenticates the baked archive against its carried hash before probing its `mvmctl`. A legacy or unpinned archive uses a separately hash-pinned temporary cosign, and an unpinned archive is never executed before its mandatory exact-tag bundle verifies. Self-update verifies the checksum manifest's bundle under its exact tag before parsing it, then each tarball's own bundle; the hash-skip hatch waives neither. The guest runtime is signed as a release archive with its `.sha256` sidecar; an ordinary release launch shares one authenticated archive snapshot across attachment, signed plan admission and lifecycle custody, while a built registry pack keeps its dispatch recheck. The signed plan and chain-signed admission entry name the verified runtime, and restore, fork and warm claim verify the retained generation instead of treating fresh cache data as its authority; see "Claim 20 boundaries" for trusted-host limits | Shipped |
| 21 | OCI base images are OS-package- and kernel-inventoried, CVE-scanned against OSV, and SBOM-enumerated at pull time, and production admission refuses a missing scan, a sidecar bound to another digest, or any high/critical finding | fn:inventory_rootfs, fn:scan_inventory, fn:apply_base_image_gate, fn:a_prod_run_refuses_a_base_image_with_no_scan, fn:a_prod_run_refuses_a_base_image_with_a_high_severity_finding | the pull pipeline inventories the unpacked rootfs (dpkg status, apk installed, os-release, in-image kernel version; rpm is a named unsupported gap) and queries OSV directly over the repo HTTP client, writing `claims/<digest>.{cve.json,sbom.cdx.json}` beside the provenance record; `resolve_or_pull_run_image` applies the gate on every `--prod` run. Limits: the sidecars live in the host-controlled cache, so the gate verifies the scan's digest binding and verdict, not its honest production — a host insider can forge a clean sidecar (the image bytes themselves remain digest-pinned and dm-verity sealed); severity is best-effort (Debian/Alpine OSV records generally carry none, and `unknown` severities are reported but never gate-refusing); the gate covers registry-pulled images — the local ingest paths are dev-only | Shipped |

Row 16 is the egress-substitution leak-gate. Like claim 14 (OCI provenance),
it is registered here for witness machine-checking and tracked by its own doc
(`claim-egress-no-secret-to-guest.md`) at status `Preview`; promotion to a
numbered claim in ADR-001's source-of-truth table is a separate maintainer
decision. It does not restate or replace the broker rows 12/13 — those are the
shipped broker delivery; row 16 backs the same two invariants on the egress
substitution path.

**Preview 17 limits — what the input plane does and does not enforce.** Row 17
is `Preview` rather than `Shipped`. Three of the five limits below are closed;
the two that remain are permanent properties of what the enforcement *is*, not
gaps waiting on work. Stating that here is the point of a ledger; a row that
read as enforced while the enforcement was dormant would be the exact failure
this table exists to prevent.

1. **The secret scan is populated in production. (CLOSED.)** It used to be
   inert: `InputGate::bind` had no caller outside tests, so the known-secret
   set was empty on every real VM. The per-VM substitution endpoint — the one
   host process that holds a workload's credentials in the clear — now
   fingerprints each secret it resolves and reports the fingerprints on its
   ready handshake, and `StreamPlane::open_input` installs that set on the gate
   before a writer's first frame. Witnessed by
   `fn:the_endpoint_fingerprints_what_it_resolved_and_reports_no_value` and
   `fn:the_handshakes_two_halves_go_to_two_different_places`;
   `fn:a_secret_split_across_two_frames_does_not_reassemble_in_the_workload`
   drives the whole path, from the endpoint's report through a real plane to a
   workload process that must not receive the bytes.

   Three things the closure does not say. **Fingerprints, not values**: what
   crosses into the scanning process is a length, a 64-bit rolling hash and a
   category — never a credential, because the endpoint is a separate process
   and keeping it that way is the point (claims 12/13, and row 16). What that
   discloses, and why prefix fingerprints were rejected, is in ADR-035
   §"What binding a fingerprint discloses". **Scoped to the booting
   process**: the set is in memory, held by the invocation that spawned the
   endpoint — which is exactly the invocation that can stream, per limit 3, so
   this costs no reachability. **Scoped to secret-bearing plans**: a workload
   whose plan carries no secrets binds an empty set, which is the correct
   answer rather than a dormant one.
2. **The shell-entrypoint refusal now fires on a real entrypoint. (CLOSED.)**
   It used to be dormant: every production call site passed an empty
   `entrypoint_argv`, so the gate never saw a shell. The entrypoint is now
   resolved from the image's own build-time record — the `mvm-meta.json`
   sidecar beside the rootfs, written by both the `mkGuest` and OCI build
   paths — and read at admission, so the classification runs against what the
   image will actually exec. The gate also **fails closed**: an image whose
   entrypoint cannot be resolved is refused the grant rather than admitted
   unchecked, so the control cannot become dormant again by a caller
   forgetting to resolve one. Witnessed by
   `fn:a_shell_entrypoint_read_off_the_image_is_refused_the_stdin_grant` and
   `fn:an_image_that_cannot_say_what_it_runs_is_refused_the_stdin_grant`.
   What remains true is that the refusal is a heuristic over argv (limit 4).
3. **The input plane has an operator surface and runs on a real VM.
   (CLOSED.)** `mvmctl machine run --entrypoint --stdin -` opens the route
   through `StreamPlane::open_input` under the plan that boot was admitted
   under, pumps the caller's stdin through the gate in acceptance order,
   refreshes the lease while the writer is idle, and closes the workload's
   stdin on the caller's EOF. The grant is conditional on that request: a call
   that did not ask carries no `host.stream.v1` and its workload's stdin stays
   unreachable from outside the guest. Scope worth stating: only the
   invocation that *admits and boots* the workload can stream into it —
   `--attach` and `mvmctl session attach` dispatch into machines admitted by
   another process and hold no plan to write under, so they refuse.
4. **The scan is a backstop, not a defence. (OPEN, permanent.)** Base64, hex,
   any derivation, and a split that straddles the sliding window all defeat
   it. It catches a confused host-side caller, not a determined one. Giving
   the scan a populated set makes it *work*; it does not make it stronger than
   this. The real guarantee is upstream and structural: the host has no reason
   to send a secret into a guest, because secrets are substituted on egress
   (rows 13 and 16) rather than handed over. The same "heuristic, not proof"
   caveat applies to the shell classification in limit 2: a wrapper that
   `exec`s a shell defeats it, and no test over argv could separate a program
   that reads stdin from one that interprets it.
5. **A match is a hash match, not an identity. (OPEN, permanent.)** The gate
   holds fingerprints because it must not hold values, so two different byte
   sequences of the same length can match one. The gate refuses either way —
   failing closed is the right direction — and the refusal says what was
   compared rather than asserting the bytes are the secret
   (`fn:a_fingerprint_refusal_does_not_claim_the_bytes_are_the_secret`). The
   cost is the mirror image of limit 4: limit 4 is what the scan misses, this
   is what it may refuse without cause.
6. **The carry is blanket, and is released on silence. (CLOSED; its residual
   lives inside limit 4.)** Unable to tell a live secret prefix from an
   innocent tail, the scanner withholds a fixed `longest_secret - 1` bytes of
   every write on a secret-bearing VM. That imprecision is deliberate. A
   *precise* carry would make the withhold-or-deliver decision depend on
   content, and that decision is observable: a caller holding the input grant
   feeds one byte, watches whether anything came out, and walks a 40-byte
   credential out in about 40·256 probes rather than 256^40 — a
   secret-extraction path against exactly what row 13 protects. The blanket
   carry is what denies that signal.
   Its cost was a deadlock rather than latency: with a 40-byte bound secret the
   carry is 39, so a typed 11-byte request line delivered **zero** bytes, a
   workload answering per line never answered, and the write that would release
   the held tail never came. The gate now releases the withheld tail after
   `DEFAULT_IDLE_FLUSH_AFTER` (50ms) of writer silence, on **elapsed time
   alone** — never on what the bytes are, which is what keeps the oracle shut
   (`fn:the_idle_release_does_not_depend_on_what_the_withheld_bytes_are`,
   `fn:what_is_withheld_is_a_length_and_never_a_verdict_about_the_bytes`). The
   release cannot hand over a secret: what it releases already survived a scan
   of the buffer it came from. What it costs is context — a secret split across
   a silence longer than the threshold is no longer contiguous in the scanner
   and is missed
   (`fn:a_secret_split_across_two_writes_inside_the_threshold_is_still_refused`
   pins the covered side;
   `fn:a_secret_split_across_the_idle_gap_is_missed_and_that_is_the_price` pins
   the uncovered one). That needs the *sender* to pause mid-credential, which a
   confused caller does not do and a determined one does not need — base64
   already defeats the scan — so it sits inside limit 4 and does not widen it.

Limits 4 and 5 are permanent — properties of scanning and of hashing, not gaps
to fix. Limit 6 is closed; what it leaves behind is a residual inside limit 4
rather than a limit of its own. Promotion of row 17 to a numbered claim is
therefore a decision about whether numbered prose can carry limits 4 and 5 plus
the argv heuristic in limit 2, not a decision waiting on work.

### Claim 3 backend scoping

Claim 3's witness, dm-verity, is
block-device-specific: it ratifies the claim on the **block+ext4** backends
— Firecracker and the in-process Option B materialize path. A
**virtiofs root** (Plan 221 Option A) serves a host directory, not a block
device, so it cannot be dm-verity-sealed. Virtiofs-root is a dev/local-tier
boot mechanism carrying an explicitly weaker contract
(unpack-time per-layer sha256 + read-only serving from the trusted host, no
guest-enforced plan-bound re-verification); it does **not** witness claim 3.
Prod / sealed / `--prod` workloads — and Firecracker on every tier — stay on
Option B, where claim 3 holds unchanged. No numbered claim is weakened; this
note only scopes which backends the existing witness covers.

**Canonical kernel custody on Firecracker — limits.** A bundle carrying a
canonical Linux proof is launched on HVF and on Linux Firecracker; every other
backend refuses it. The two backends do not offer the same lifetime evidence.
HVF releases the kernel generation on an authenticated, instance-bound exit
proof. Firecracker releases it on a process-table identity only: the pid read
from the VM's pid file, accepted only if that process serves this VM's
`--api-sock`, recorded with its start time and the host boot id, and judged
exited when `/proc` no longer shows that start time or the boot id differs.
Firecracker is therefore not instance-bound in HVF's sense, and the identity
is only as trustworthy as the host's process table. An unreaped zombie still
has a process-table entry and counts as not exited, so its generation is
retained. A start that fails or crashes between boot and recording the
identity leaves the generation retained and the VM name blocked. This
narrows nothing in claims 3 or 8; it states what the Firecracker release
mechanism rests on.

**HVF kernel-descriptor-only boot — limits.** The HVF supervisor starts a
config that carries a kernel descriptor and neither frozen boot images nor a
caller registration as a legacy-policy boot (`startup_mode_for`). Frozen images
and a caller registration must arrive together with the kernel; any other mix
is refused, and `only_a_complete_checked_set_or_a_kernel_alone_may_start`
checks all eight combinations. What that boot does and does not rest on:

- **Admission happens in the launcher, not the supervisor.** A signed bundle's
  kernel owner reaches the launch config only through admission:
  `AdmittedKernel::capture` requires the owner's pin to equal the verified
  plan's bundle, and `bind_canonical_kernel` refuses an owner admission never
  verified. The supervisor does not re-verify the plan on a cold boot —
  `plan_to_arm` verifies only a restored child's — so it trusts the process
  that spawned it, as every legacy-policy HVF boot already did. A consumed
  caller registration (the checked boot) is the only form that makes the
  supervisor itself verify the plan, and it is not required for a kernel alone.
- **No plan, no boot.** A workload boot with no admitted plan is refused unless
  it is a builder or a standby (`CaptureAuthority::select`, tested by
  `a_launch_with_no_plan_and_no_operational_role_is_refused`), so a kernel
  descriptor cannot start a planless workload.
- **Seccomp and the audit chain do not depend on the startup mode.** The
  `mvm.seccomp=<tier>` token is derived from the launch config's admitted plan
  in `seccomp_cmdline_token`, before any supervisor starts; `plan.admitted` and
  `plan.launched` are written by the launcher's emitter. The claim-1 limits
  above (an older guest agent ignores the token) apply unchanged.
- **The signed bundle is not the only source of the descriptor.** The producer
  byte-continuity path (`kernel_read_sha256`) also hands the HVF supervisor a
  kernel descriptor with no images. It is a data-continuity check, not an
  admission capability, and a launch on it relies on the launcher's admission
  in the same way.
- **Limits.** No test boots a signed bundle on HVF end to end and then reads
  back the audit chain and the guest's seccomp state; the guarantees above are
  established per component. Whether the signed-bundle case should get its own
  explicit startup mode rather than reuse the legacy one is a design decision
  this note does not make; the legacy path is still used by every cold HVF
  launch that carries no caller registration.

**Claim 20 boundaries — five refusing paths and the installer trust root.** The
four consuming paths inside `mvmctl` verify the Sigstore bundle in-process
against the embedded trust root and refuse a missing, unparseable, or
foreign-signed one. The installer reaches the same verdict through a bounded
bootstrap path.

- **Build path — refuses.** `crates/mvm-build/src/release_signature.rs` fails the build on a missing or malformed bundle and names the asset, and accepts only the versioned release-workflow identity.
- **Fetch path — refuses.** `crates/mvm-cli/src/commands/env/artifact_verify.rs` rejects an unsigned manifest before parsing it, and the documented hash-skip hatch does not waive the manifest signature.
- **Self-update path — refuses.** `verify_signature` in `crates/mvm-cli/src/update.rs` used to shell out to `cosign` and return `Ok` when it was not on `PATH`. It now calls the build path's verifier with the CLI release train, so a host without cosign gets the same verdict as one with it. `a_real_release_bundle_verifies_under_its_tag` verifies a committed release bundle under its real tag and refuses it under another, which is what shows the tag and the identity template agree. The `checksums-sha256.txt` the archive is compared against goes through the fetch path's manifest check first, under the same tag-bound identity: an unsigned manifest is refused before it is parsed (`self_update_refuses_an_unsigned_checksum_manifest_before_parsing`), as are edited bytes and another release's genuine manifest (`self_update_refuses_a_checksum_manifest_signed_for_another_tag`). Neither `MVM_SKIP_HASH_VERIFY` nor `--skip-verify` waives it; `--skip-verify` waives only the archive's own bundle, so the archive stays authenticated through the manifest.
- **Guest-runtime launch check — shared within one launch.** A release launch asks several times whether the signed guest-runtime archive is authentic (admission, overlay, initramfs, dispatch, lifecycle bind). Within one launch those asks share one verification: a successful result is remembered, for that launch on that thread only, under the content of everything it read (archive digest, checksum, both signature bundles, version, architecture), so a changed byte of any of them verifies in full. A failure is never remembered, nothing is written for a later process to trust, and the next launch verifies from scratch (ADR-112). The guest-runtime launch check authenticates the archive bytes and reads the manifest; member consistency is established before signing and again at assembly, not at launch.
- **Install path — refuses.** An installed `mvmctl` remains the preferred
  verifier and host `cosign` remains the fallback. On a host with neither,
  `install.sh` compares the archive with the target-specific SHA-256 carried by
  the published installer before extracting or executing only its `mvmctl` as
  a temporary verifier. A legacy archive that predates `env verify-release`
  falls back to a temporary cosign whose version and target hash are pinned in
  the installer. A non-default version may supply an independent
  `MVM_TRUSTED_ARCHIVE_SHA256`; without one, no archive byte executes before
  the pinned cosign verifies its exact-tag bundle. A mismatched supplied hash,
  missing bundle, invalid verifier hash, or invalid signature refuses before
  installation. The release's guest runtime goes through the same two checks
  once the `mvmctl` archive has passed them: its digest against the checksum
  manifest, then its own bundle under the exact tag, before it is staged in the
  release directory's `guest-runtime/`. Only a 404 is tolerated, because
  releases published before the asset existed have none. The installer tests
  in `tests/install_sh.rs` cover an unsigned runtime, one whose digest the
  manifest does not record, and a release that predates the asset; they live
  outside `crates/`, so the ledger cannot cite them as `fn:` witnesses.
- **Guest-runtime path — refuses.** The guest runtime
  (`mvm-guest-bins-v<version>.tar.gz`) is the archive a release binary assembles
  its runtime overlay, universal initramfs and SDK sidecars from; it is a CLI
  release asset, not an image-set member, so claim 6 does not cover it.
  `release.yml` refuses to publish without exactly one, named for the tag, and
  signs both it and its `.sha256` sidecar; `verify-release-assets.sh` (the
  `verify-release` job) verifies both signatures, checks the sidecar against
  the bytes, and requires the archive's `manifest.json`. On the consuming side
  `acquire_release_guest_runtime` downloads the archive, its sidecar and both
  bundles into a staging directory and checks them there with the launch's own
  verifier: the archive's digest against the sidecar before any archive
  signature (`a_release_runtime_that_misses_its_digest_is_refused_before_its_signature`),
  then the signatures under the CLI release identity at exactly this version
  (`an_unsigned_release_runtime_is_refused_and_nothing_is_cached`,
  `a_release_whose_evidence_does_not_verify_publishes_nothing`). Only then is
  the set published as the release cache entry, byte for byte as checked
  (`the_cached_files_are_the_bytes_that_were_verified`). The archive's own
  manifest must then name this version and carry both architectures' agents. `mvmctl env update` acquires the new version's archive
  the same way before it replaces the binary, and refuses the update when the
  release publishes none
  (`an_update_to_a_release_without_a_runtime_refuses_before_replacing_anything`).

  A copy beside `mvmctl` (placed by `install.sh` or a package) still inherits
  its acquisition authority from that installation. A cached copy is checked
  again with the launch's verifier on every acquisition and refused, not
  replaced, when it fails. A download made with `MVM_SKIP_COSIGN_VERIFY` set is
  never written to the release cache and is never installed: bootstrap,
  first-use preparation, the image path, `mvmctl dev runtime-overlay build`
  and `mvmctl dev sdk-sidecar build` refuse it right after acquisition, before
  anything reaches the object store, the launch pieces, the OCI shims or the
  adoption record (`bootstrap_keeps_a_hatched_download_out_of_the_install`,
  `bootstrap_refuses_a_hatched_download_before_any_other_step`), because
  installing takes an `AuthenticatedReleaseArchive` that an `Unverified` result
  cannot produce. For the guest runtime the hatch accepts an unverified
  download, not an unverified install. It is narrower than the hatch as a
  whole: under it `mvmctl env update` still installs an `mvmctl` tarball whose
  signature was not checked, and bootstrap still installs a builder image whose
  verification was waived. `env update` acquires the guest runtime without
  installing anything from it; its follow-up bootstrap refuses and the update
  ends with a warning, so during a Sigstore outage a fresh release install
  cannot bootstrap. Pieces a hatched bootstrap assembled before this refusal
  existed stay in the cache until it is cleared.
  An ordinary signed-release launch independently authenticates the selected archive,
  checksum and available signature bundles once for that launch, retaining
  the verified archive bytes until it binds the selected overlay, verity tree
  and initramfs into one private lifecycle generation. The signed plan names
  that exact runtime identity, and `plan.admitted` records it in the chain-signed
  audit log before workload authority is released. Restore, fork and warm
  claim authenticate their *retained* generation, not an unrelated fresh
  launch's cache. A cache refresh cannot replace the verified archive snapshot;
  the launch still hashes selected bytes against the declaration and refuses
  drift. Each generation's artifact files are hard links into
  `runtime-evidence/shared_content`, shared by content across VMs; a launch
  re-hashes the linked inode it will boot and copies afresh rather than link a
  shared copy that is not its own, not read-only or no longer matches. These checks assume a trusted host account: a same-user
  process able to alter private generations is outside this custody guarantee.
  A built registry pack still has its separate dispatch-time selection recheck.
  `MVM_SKIP_COSIGN_VERIFY` remains the emergency-rotation hatch; it does not
  turn a path-only proof into verified launch authority.
  `signed_release_verification_is_once_per_launch_and_refuses_tampering`
  exercises a real signed release quartet — whichever one the directory it is
  pointed at holds — with test-only verification and member-walk counters, but
  is opt-in because a 20 MB signed archive is not committed to the repository.
  It is not a live Firecracker or HVF count witness. The gated witness of the
  same path is
  `a_launch_reads_the_manifest_of_authenticated_bytes_without_walking_members`,
  which drives the launch verifier with a stand-in signature check private to
  `mvm-build`'s tests; it witnesses the order and the absence of a member walk,
  not Sigstore verification.

The `manifest-verify`-gated tests on these paths run in the `Lint feature coverage`
job of `ci.yml`, which is what makes them citable: `check-claim-catalog` cannot
see a cfg gate, and before that step no lane ran them.

One implementation boundary remains outside the claim, and the installer has a
separate trust-root qualification:

- **An `mvmctl` built without `manifest-verify` cannot self-update.** It refuses
  rather than installing unverified, and the refusal names the feature and the
  `MVM_SKIP_COSIGN_VERIFY` escape. Release builds carry the feature.
- **The installer script is the fresh-host trust root.** Its baked target hashes
  are populated from the just-published release checksum manifest only after
  its bundle verifies under the exact release-workflow tag identity, before the
  stable installer is deployed. This authenticates the selected archive before
  its verifier capability is probed. Legacy releases use the separately
  code-reviewed cosign version and hashes carried in the same installer; its
  bytes are checked before execution. The subsequent Sigstore check
  independently authenticates the release archive. Pinning a different version
  cannot inherit the default release's hash, so it uses the independently
  pinned cosign unless the operator supplies an archive hash or a trusted
  verifier is already installed.

**Provenance is emitted, and it is L2.** The release job attests the binary
tarballs with `actions/attest-build-provenance`, recorded in the GitHub
attestation store and verifiable with `gh attestation verify`. It witnesses this
claim because the attestation is signed under the same workflow identity and
binds the artifact to it — one more way the same authenticity holds.

It does **not** upgrade the claim to say anything about build *integrity*. This
is SLSA Build L2: the attestation is produced by the same workflow that produces
the artifact, so a compromised release job forges both. What provenance adds over
the signature is the commit and the build inputs in a machine-readable predicate,
not evidence the build was uncorrupted. `ci:reproducibility` under claim 7 is the
control that speaks to that, because an independent rebuild landing on the same
bytes requires no trust in this builder at all.

Provenance covers the tarballs — the same set the pipeline signs directly. The
kernels, root filesystems and metadata remain anchored by digest inside the
signed manifests, exactly as the statement says.

## Maintaining this catalog

- Adding a claim: append a row with the next number (the gate enforces a
  contiguous `1..=N`) and at least one resolvable witness.
- Renaming a witnessed test/fn or CI lane: update the row in the same PR,
  or the gate goes red.
- The `Status` column accepts `Shipped` / `Preview` / `Planned` /
  `Not-claimed`, matching `check-no-overclaim`'s status vocabulary.

## Deferred follow-ups

- [ ] Audit each witness for *external-authority* grounding (assert against
  a reference implementation / oracle rather than the code's own output);
  record gaps in the Authority column. Tracked as its own issue.
- [ ] For any witness found to be self-referential, file a follow-up to add
  a reference oracle.
<!-- claims-catalog:end -->

## Appendix: Compliance mapping

The default postures below are decided; the requirement-by-requirement
control mapping for each framework is a living work item tracked outside
this ADR, not restated here as an exhaustive checklist.

**GDPR.** Default posture is data-minimization-by-default. The concrete
technical primitives this ADR and its sibling architecture provide toward
GDPR obligations are: a PII redactor that reduces what reaches any log or
audit entry; signed, exportable audit and snapshot bundles that support
data-portability requests; default-deny network egress and
encryption-everywhere as the "protection by design and by default"
posture; and an overlay-erasure primitive signed by the host identity key
that the fleet-orchestration layer's tenant-deprovisioning flow invokes
for right-to-erasure. Cross-border transfer and breach-notification
timelines are operational properties of a deployment, owned by whoever
operates the fleet, not by this library.

**HIPAA.** Default posture requires a signed agreement with any customer
storing protected health information before that data enters the system;
HIPAA compliance is a property of a deployment, not of this library by
itself. The technical safeguards this ADR maps to are: per-VM identity
keys and per-tenant signing keys for unique identification; the
chain-signed audit log for the audit-controls requirement; dm-verity
rootfs integrity and audit-chain HMAC for the integrity requirement; and
encrypted transport with forward-secret session keys for the transmission
security requirement. Administrative and physical safeguards are
operational, owned by the deployer.

**PCI DSS.** Default posture is scope reduction: mvm and its
fleet-orchestration sibling do not handle cardholder data, and any
customer who routes cardholder data through a workload takes on their own
PCI compliance burden without assistance or certification from this
project. An opt-in, stricter-defaults profile is available for the rare
customer who insists on processing cardholder data inside a workload
(mandatory volume encryption, no shared infrastructure across tenants, a
mandatory egress proxy with data-loss-prevention rules, extended audit
retention), but the project does not certify that profile — the customer
retains end-to-end PCI responsibility.

**SOC 2.** Every SOC 2 Trust Services Criterion this ADR bears on maps to
a concrete artifact already described above: encryption layers and
default-deny egress for the Control Activities criterion; the chain-signed
audit log and its total-coverage test for Monitoring; attestation and
per-tenant signing keys for Logical Access; the ADR/claim-catalog
discipline itself for Change Management; and the PII redactor for
Privacy. Availability, processing-integrity, and confidentiality
commitments beyond what is stated as a numbered claim above are
operational SLOs, not architectural decisions, and are tracked
separately.

## Appendix: Cardoso minimum-viable-policy checklist

Maps a widely-cited five-bullet minimum-viable sandbox policy to mvm's
claims.

| Minimum-viable-policy bullet | mvm status | Backing claim(s) |
|---|---|---|
| Default-deny outbound, then allowlist (or policy proxy) | pass | claim 10 |
| No long-lived credentials; short-lived scoped tokens | pass | claim 8 + claim 13 |
| Workspace-only filesystem; no host mounts beyond explicit shares | pass | claim 1 |
| Resource limits: CPU / memory / disk / timeouts / PIDs | partial | CPU, memory, and disk are enforced; `ExecutionPlan.resources` is scaffolded for timeout and PID-limit fields, which are not yet populated |
| Observability — log process tree, network egress, failures | pass | claim 8 + claim 10 + claim 12 |

**Beyond this minimum.** Properties mvm enforces beyond the five-bullet
floor: hermetic builds where the host environment never influences an
artifact; signed, admission-checked execution plans (claim 8); signed,
re-verified, content-addressed bundles (claim 9); hash-locked,
SBOM-bound, CVE-scanned, attested dependency volumes (claim 11); a
dm-verity rootfs that panics on tamper (claim 3); reproducible host-code
builds (claim 7); a production guest agent that ships without `do_exec`
(claim 4); binding-gated, audited host-service dispatch (claim 12); and
no raw secret crossing the broker channel (claim 13).

**Three questions.**

| Question | mvm answer |
|---|---|
| What is shared between this code and the host? | KVM ioctls on Linux; Hypervisor.framework calls on macOS; vsock for the control plane and binding-gated brokered host services (claim 12); one explicit virtio-fs share per declared mount. The host filesystem is never ambient. |
| What can the code touch? | Whatever the signed `ExecutionPlan` admits: declared shares, a declared egress allowlist (claim 10), declared volumes, declared brokered services (claim 12 binding). No raw devices, no host process namespace, no host network namespace. |
| What survives between runs? | Only volumes the plan declares persistent; sealed dependency volumes are read-only and hash-locked (claim 11). Everything else is ephemeral by default. |

## Appendix: Threat model — host services broker over vsock

The host services broker exposes a small set of host-side services to a
guest workload over vsock, gated by the signed plan's service bindings
(claim 12) and never returning a raw secret (claim 13). This appendix is
the structured threat enumeration for that surface.

**In scope.** The broker subprocesses and their per-VM lifecycle; the
vsock channel between the guest microVM and the host subprocesses; the
per-VM local IPC channels between the supervisor and each subprocess; the
cross-VM path from the supervisor to a fleet-orchestration agent; the
`ExecutionPlan.services` admission ceremony and the audit entries it
generates.

**Out of scope**, per this ADR's own scoping: physical attacks on the
host; multi-tenant guests; hardware-backed key attestation of the
workload itself as a defense against a malicious host; vulnerabilities in a third-party hypervisor's vsock
implementation, which are dependency-CVE-managed rather than reviewed
here (the in-house HVF backend's vsock implementation is not a
third-party dependency, so it is in-scope for review here).

**Adversary classes.**

| Class | Description | Capabilities |
|---|---|---|
| G — hostile guest | A workload running inside a microVM; the primary adversary. Full control over guest userspace; cannot escape the VM. | Sends arbitrary bytes to the broker's vsock ports; receives responses; observes timing. |
| N — hostile network peer | A network attacker between the supervisor and a remote fleet-orchestration agent. | Observes and tampers with network traffic, mitigated by identity pinning and TLS. |
| I — software insider | An unauthorized human with shell access to the host as some Unix user. In scope for logical (not physical) attacks. | Executes arbitrary code on the host; cannot escalate to root if not already root; cannot perform physical attacks. |

**Cross-cutting threats and mitigations.**

| ID | STRIDE | Adv. | Threat | Mitigation |
|---|---|---|---|---|
| X-S1 | Spoofing | G | Guest spoofs another workload's session by forging a session id | `AuthenticatedFrame` signature verification under a per-workload session key minted at admission and discarded at workload stop |
| X-S2 | Spoofing | I | Insider runs a fake broker subprocess binary | Cosign-verify at spawn; TOCTOU-resistant verify-then-exec; subprocess config signed under the release key |
| X-T1 | Tampering | I | Insider tampers with the audit chain on disk | Append-only file descriptor held by the audit-signing subprocess; a persisted chain head is independently verified; per-tenant encryption at rest |
| X-T2 | Tampering | I | Insider tampers with the host signer key on disk | On enclave-equipped hosts the key never leaves the enclave; on non-enclave hosts the key file is mode 0600, immutable once written, and rollback-detected by a monotonic counter |
| X-R1 | Repudiation | G | Guest denies having made a call | Every dispatch, allowed or denied, emits a chain-signed audit entry with the service, verb, outcome, and correlation id |
| X-I1 | Information disclosure | G | Guest reads another workload's local IPC socket | Per-VM socket paths under a supervisor-owned directory, mode 0600 |
| X-I2 | Information disclosure | G | Guest infers state from response timing | A latency floor pads responses for the sensitive service class; a per-workload call-rate budget escalates to an audited abuse signal |
| X-I3 | Information disclosure | I | Insider reads audit log contents | Per-tenant authenticated encryption at rest |
| X-I4 | Information disclosure | I | Insider reads in-memory secrets from a running subprocess | Per-workload cgroup and namespace isolation; secret-bearing pages are memory-locked; anti-debug and dumpable-flag hardening; a seccomp filter denies cross-process memory reads |
| X-D1 | Denial of service | G | Guest floods the broker to exhaust CPU or memory | Per-service token bucket, in-flight cap, lifetime quota, per-workload CPU and memory budgets, bounded receive queue |
| X-D2 | Denial of service | G | Guest forces a subprocess restart loop | A restart cap per workload lifetime; beyond it, an audited crash signal and workload pause |
| X-E1 | Elevation of privilege | G | Guest exploits a parser bug in the schema gate | Frame size cap enforced before parse, bounded recursion, a parse timeout, and a fuzzed parser; the subprocess's address space is fully isolated from the supervisor's |
| X-E2 | Elevation of privilege | G | Guest exploits a logic bug to call an unbound service | The binding gate refuses; covered by a dedicated regression test |
| X-E4 | Elevation of privilege | G | Guest triggers a memory-safety bug in the general broker to pivot into the secrets-handling subprocess | Architecturally impossible: the broker subprocesses share zero address space |

**Per-service notes.** The workload-emitted audit service refuses an
entry whose asserted workload id does not match the caller's
supervisor-assigned id, and tags workload-emitted entries under a
distinct audit category so they are never mistaken for a supervisor-asserted
entry; per-record and per-batch size and rate caps bound the amount of
audit noise a guest can inject. The introspection service returns only a
workload's own bound service set, so an unbound service is invisible to
probing.

**Residual risk, named and accepted.** A non-enclave host retains a
trust-on-first-use posture for the host signer key until hardware-enclave
support lands; `mvmctl doctor` surfaces this as a downgrade. All
workloads on a host share one audit-signing subprocess per VM, so a
defect there affects that workload's whole audit stream — mitigated by
keeping that subprocess minimal and security-reviewed. The host signer is
a single point of admission availability; loss of the key means no plan
can be admitted, with no recovery path today.

## Appendix: Claim implementation notes

Where each claim lives in the code, and the corrections earlier prose needed.
The ledger above binds; these notes do not add a claim or a witness, and a
witness the ledger already names is not repeated here.

### NIC-less guests (claims 10 and 13)

Every workload microVM backend boots the guest with a virtio-vsock device and
no net device: Firecracker's config sequence omits `/network-interfaces`,
libkrun pins `NetworkingMode::VsockDirect` (which never attaches a net
device), HVF's device model has none (`apple-container` is that device model
with a different kernel image, holding an `HvfRunner`), and the QEMU workload
driver emits no `-netdev`. Egress leaves only over the `NetworkFlow` channel
to the per-VM `mvm-network-endpoint`, whose `EgressGate` is the one decision
point; because the endpoint originates every outbound connection it can
authorize, substitute and log it. Wasm has no guest network and is outside
this funnel.

The builder VM is NIC-less on every backend, QEMU included: `nix build`
substituter traffic and dependency installs (`uv` / `pnpm`) ride the same
vsock relay under `NetworkPolicy::trusted_build_egress()`, through the one
proxy environment the guest init hands every builder job, and an install on a
builder booted without vsock egress is refused rather than dialed direct.
`xtask check-single-network-path` fails if a guest NIC, raw-packet stack,
second spawn site or socket owner appears, if builder code opens a socket
other than the egress client's readiness probe, if a host-binary manifest
names the retired guest-side `mvm-egress-proxy`, or if the QEMU builder gains
a NIC argument.

### Claim 1

Admission raises the seccomp tier from `standard` to `network` when the launch
admits egress, an ingress mapping or a host service, and signs the raised tier
(`workload_seccomp_tier`). The host names it on the guest kernel cmdline as
`mvm.seccomp=<tier>` (`seccomp_cmdline_token`), not in `ActivateEnvironment`,
whose `deny_unknown_fields` would make older guest agents refuse activation.
The agent admits it at activation (`admit_from_cmdline`) and installs it,
after the child's other pre-exec setup, in entrypoint runs and the worker
pool, exec, process control, detached runs, the console, lifecycle hooks and
health probes; a denied call fails with `EPERM`. A warm-claimed child gets its
tier from the claiming launch's signed plan: the runner hands it over on the
post-restore handshake (`ChildIdentity`), the child's agent admits it once
(`admit_restored`), and the claim is refused unless the agent reports holding
exactly that tier (`require_admitted_seccomp_tier`). An agent too old for the
field refuses the handshake, and so does a worker pool started unfiltered in
the parent. A cold boot whose guest agent predates the token still applies no
tier, including the agent in the pinned image set a release binary boots until
it assembles its own guest runtime.

### Claim 3

No CI lane boots a tampered rootfs under KVM; the witnesses check artifact
emission, snapshot-tamper rejection and a flipped data byte against the
recorded root hash.

### Claim 4

`scripts/check-prod-agent-no-exec.sh`, run by the
`guest-agent-runtime-boundary` job in `.github/workflows/security.yml`,
exercises the runtime profile and signed grant boundary.

### Claim 5

The guest-protocol fuzz targets live under `crates/mvm-agentd/fuzz/`; the
supervisor-config target is
`crates/deps/libkrun-sys/fuzz/fuzz_targets/fuzz_supervisor_config.rs`. The
third-party virtio-net frame parsers once tracked as an upstream fuzz gap have
no in-tree caller since the userspace network gateways were deleted with the
guest-NIC path; `specs/adrs/003-hypervisor-egress-policy.md` is written around
the vsock-only chokepoint.

### Claim 6

The production path is `acquire_image_set()` in
`crates/mvm-cli/src/commands/env/artifact_verify.rs`, which calls
`PublishedImageSet::acquire_from`. `fetch_expected_hashes` and
`verify_artifact_hash` in that module are test-only helpers, not evidence for
the production path. Image-set acquisition does not read
`MVM_SKIP_HASH_VERIFY`; the hatch still skips the bootstrap-kernel checks and
the per-binary checksums inside an already digest-verified overlay archive.
Never set it in CI. Retired members parse as
`ImageSetRole::RetiredGuestRuntime`. No function by this name exists, and
earlier doc comments that cited it were corrected:

<!-- absent:begin -->

`download_dev_image`

<!-- absent:end -->

### Claim 7

The `cargo-deny` and `cargo-audit` jobs in `security.yml` run nightly and on
release tags; `security.yml` has no `pull_request` trigger.

### Claim 8

The host keypair is `~/.mvm/keys/host-signer.ed25519` (mode 0600); plans
verify through `mvm_core::plan::verify_plan` (`plan` is a module of
`mvm-core`, not a crate). Entries go to `~/.mvm/audit/<tenant>.jsonl` and are
checked by `mvm_hostd::supervisor::verify_audit_chain`, surfaced by
`mvmctl trust audit verify`, which exits nonzero on drift. The chain rotates
into `<tenant>.seg-NNNNNN.jsonl` segments at `MVM_AUDIT_SEGMENT_BYTES` (4 MiB
default); nothing is deleted, every segment after the first opens with a
signed `chain.continued` handoff, and `mvmctl doctor` checks the live segment
plus the handoffs while `trust audit verify` walks every retired interior.
Tail truncation of whole sessions, or of a session that never sealed, stays
undetectable without an off-host witnessed root. Rejection paths are
exercised by workspace `cargo test` through `synthesize_plan`,
`host_signer::load_or_init_at`, `admit_for_run` and `AuditEmitter`;
`xtask check-no-display-on-secret-types` protects the host signer's redacted
`Debug`.

### Claim 9

The rejection ladder is exercised through
`mvm_core::plan::bundle::read_and_verify_bundle` and
`mvm_core::plan::bundle::verify_plan_bundle`; `mvmctl bundle fetch`
round-trip and `admit_for_run` tests assert refusal on pin-without-context and
pin-archive mismatch.

### Claim 10

An unrecognised preset name refuses rather than falling through to a
permissive default, at the CLI and on the wire alike
(`crates/mvm-contract/tests/egress_predicate_algebra.rs`). There is no
unrestricted-policy acknowledgement or warning: `mvmctl up` is not a
dispatched verb, and the acknowledgement variable earlier prose described is
read nowhere (its only mention is a doc comment in `mvm-contract::stream::edge`
saying another mechanism is shaped after it). Building one is tracked in the
issues.

**Cleartext under production (limit, not a numbered claim).** A workload
whose signed plan carries an agent-verb grant — every sealed production run,
and also a dev run given `--agent-verb` and an operator-admitted trial boot,
which become stricter — is read as production by the endpoint
(`production_posture`). Such a workload does not originate plain HTTP the
endpoint can identify as such unless the allow-list entry for that
destination opted in with `--allow-host http://HOST[:PORT]`. The
`EgressGate` refuses an admitted TCP flow to port 80 without the opt-in
(`production_refuses_a_port_80_flow_that_was_not_opted_in`,
`a_production_port_80_connect_is_refused_and_audited_as_cleartext`), and the
request leg refuses an `http://` upstream on any port without it
(`production_refuses_an_http_upstream_before_forward`); both record the
refusal with the reason "cleartext_denied". The opt-in is a field of the
policy entry, so it is inside the policy digest admission records in the
signed plan; that digest is the binding. The endpoint's start-up comparison
of its policy with that digest
(`a_cleartext_opt_in_the_plan_did_not_sign_is_refused`) is a consistency
check between two fields of one launcher-written config, not a signature
check. A production endpoint whose bound secret may reach an opted
destination refuses to start, so the opt-in never carries a credential in
cleartext (`production_refuses_a_secret_bound_to_a_cleartext_destination`).

Limits. Port 80 is the only plain-HTTP signal a spliced flow carries: plain
HTTP on any other port, spliced without termination, is not detected, so this
is not a promise that a production workload never sends unencrypted bytes.
The signal is the port, so TLS on port 80 and an `https://host:80` request are
refused without the opt-in too, and a production workload under an
unrestricted policy is refused all port 80 with no opt-in short of an
allow-list. An endpoint already running when a host upgrades keeps the old
behaviour until its VM restarts. A fleet-signed production plan that relies on
port 80 is refused until the fleet side can set the opt-in.

<!-- absent:begin -->

`MVM_ACK_UNRESTRICTED_NETWORK`.

<!-- absent:end -->

### Claim 11

The builder VM (`mvm-host-vm-init` plus the `LibkrunBuilderVm::run_build`
Install arm) installs dependencies into `~/.mvm/volumes/deps/<volume_hash>/`.
`mvm_build::app_deps` calls `mvm_core::deps_audit::verify_sealed_volume` when
the build cache reuses a volume. Every launch builds its plan with
`deps_volume: None`, and `verify_deps_volume_binding` has no production
caller. The seal-time lane applies
`mvm_build::app_deps_gate::apply_install_gate` and fails closed on
high/critical findings or a stub SBOM/CVE; production launch does not call
that gate, and the dormant-control manifest pins that limitation. The
`app-deps-audit` job in `.github/workflows/security.yml` runs nightly and on
release tags, not per PR: it runs `mvmctl dev compile` on
`examples/python/hello-app-with-deps/`, seals a clean and a high-CVE fixture
with `mvm-build`'s `mvm-app-deps-fixture-tool` example, checks
`mvmctl deps inspect --json`, the prod and dev gates, and that a byte-flip on
`cve.json` makes inspect refuse. A full builder-VM round trip (a real
`uv pip install` plus `pip-audit`) is not run by that lane.

### Claim 12

Payload-freedom for the stream plane's own audit entries is witnessed by
`stream_audit_entries_carry_the_binding_and_no_payload_bytes`. Earlier prose
for this claim named four tests, a fuzz target and three
`xtask check-handler-*` gates that never existed:

<!-- absent:begin -->

`service_call_denied_when_unbound`,
`service_call_denied_outside_profile`,
`audit_chain_contains_service_call_entries`,
`audit_chain_carries_no_payload_bytes`, and a
`fuzz_service_call.rs` target.

<!-- absent:end -->

### Claim 13

There is no secret-returning `host.secrets.v1` broker handler. Placeholders
reach the workload with each entrypoint call, never on the kernel command
line; the `mvm.secret_env` cmdline token and its encoder were deleted because
no booted guest read them. Six test names earlier prose listed do not exist:

<!-- absent:begin -->

`host_secrets_v1_denied_outside_allowed_destinations`,
`zeroize_drop_zeros_secret_bytes`,
`handler_inter_call_memory_hygiene`,
`host_secrets_v1_signed_payload_jcs_roundtrip`,
`secrets_subprocess_cannot_reach_supervisor_memory`,
`placeholder_in_outbound_request_dropped_and_audited`.

<!-- absent:end -->

### Claim 14

`mvmctl image pull` unpacks layers through
`mvm_fs::oci::unpack::unpack_layer` and materializes the ext4 rootfs
in-process with the pure-Rust writer, falling back to the builder VM for trees
too large or fragmented for it; the builder VM carries no extended attributes,
so a tree with `security.capability` or ACL xattrs that falls back is refused
rather than emitted without them. `mvmctl run --image` admits the plan and
then emits `plan.oci_provenance` through `AuditEmitter::emit_oci_provenance`
(`crates/mvm-hostd/src/audit/emitter.rs`). The `unpack_layer` fuzz
harness runs in `security.yml`'s `fuzz` job, and the six OCI hardening lanes
(`layer-unpack-adversarial`, `digest-mismatch-reject`, `malformed-manifest`,
`mutable-tag-prod-reject`, `reproducibility`, `image-runner-smoke`) are the
`oci-hardening` matrix in the same workflow; none gates a PR, and the ledger
row cites none of them.

### Claim 15

The sole interactive path is the agent-served PTY-over-vsock console
(`crates/mvm-agentd/src/console.rs`). The backend captures the guest console
write-only to `console.log` with no host input fd
(`mvm_vmm::host::console_capture::open_console_capture`), and the host
`enforce_accessible_gate` refuses `mvmctl machine console` on a sealed VM.
Serial-console passthrough was considered and rejected (fatal on an
input-less console).

### Preview 17 and 18

Preview 17's input gate is `crates/mvm-hostd/src/stream/input_gate.rs`; the
fleet stream-edge workflow in `mvmd` is its second production caller, which
closes no limit. Preview 18's admission ceiling is the operator config keys
`max_cpu_millicores`, `max_memory_mib` and `max_wall_clock_secs`, and its
budget `host_budget_memory_mib` and `host_budget_cpu_millicores`
(`crates/mvm-hostd/src/admission_budget.rs`); the spawn scope carries
`TasksMax=1024`.

### Claim 20

The self-update verifier once shelled out to `cosign` and returned `Ok` when
it was absent; it now uses the in-process verifier, so an `mvmctl` built
without `manifest-verify` cannot self-update. `MVM_SKIP_HASH_VERIFY` does not
waive the checksum-manifest signature, and `--skip-verify` waives only the
tarball's own bundle. `install.sh` verifies with the installed
`mvmctl env verify-release`, or with `cosign`, and tolerates only a 404 for
the guest runtime of releases that predate it (`tests/install_sh.rs`). A copy
of the guest runtime found beside `mvmctl` is held to its own manifest, not
re-verified against the signature at assembly. Under
`MVM_SKIP_COSIGN_VERIFY` the release guest runtime may be downloaded but never
installed: installing takes an `AuthenticatedReleaseArchive`, which
`authenticated_archive` will not build from an unverified result, so
bootstrap, first-use preparation, the image path and the two `mvmctl dev`
assembly verbs refuse it. Elsewhere the hatch still waives verification of
what is installed (an `env update` tarball, a builder image), so during a
Sigstore outage a fresh release install cannot bootstrap. Members are checked
against the manifest before signing (`check_release_archive`) and at
acquisition and assembly (`install_release_guest_runtime`), not at launch,
which reads only the first entry (`read_release_manifest`;
`a_launch_does_not_compare_members_with_the_manifest`,
`installing_an_authenticated_archive_still_walks_its_members`); the launch tests
use a stand-in signature check private to `mvm-build`, so they witness order
and the missing walk, not Sigstore. The published `v0.28.0-rc.2`, `rc.4` and
`rc.5` releases carry the guest-runtime asset.

## References

- `specs/adrs/007-vmbackend-single-trait.md` — the `VmBackend` trait
  boundary this ADR's tier matrix depends on; the `WorkloadBackend`
  marker trait that type-enforces the QEMU carve-out above is defined in
  `crates/mvm-runtime/src/workload_backend.rs`.
- `specs/adrs/014-signed-audited-execution-plans.md` — claim 8's signing
  and admission mechanics.
- `specs/adrs/020-host-services-broker.md` — claims 12 and 13's broker
  architecture, and the resident-daemon trust-gradient ledger.
- `specs/adrs/004-sealed-signed-builder-image.md` — the guest control
  surface the boundary-language decision above governs.
- `specs/adrs/023-secrets-subsystem-egress-substitution.md` — the
  substitution mechanism behind claim 13 and preview claim 16.
- `specs/adrs/024-wasm-sandbox-backend.md` — the `wasm-sandbox` backend's
  own decision record.
- `CLAUDE.md` §"Security model" — a one-line-per-claim index pointing at
  this ADR; the ledger above stays authoritative.
