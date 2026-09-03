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
│                    seccomp tier `standard` default             │
├───────────────────────────────────────────────────────────────┤
│ L4 — Guest agent (parses host messages, launches services)    │
│      enforced by: uid 901 setpriv, no_new_privs,               │
│                    runtime profile + signed VerbGrant,         │
│                    fuzzed deserialization + deny_unknown_fields│
├───────────────────────────────────────────────────────────────┤
│ L3 — Guest kernel (Linux from Nix, ephemeral, isolated)        │
│      enforced by: dm-verity rootfs + roothash on the kernel    │
│                    cmdline + a verity-aware init initramfs     │
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

The guest agent runs as uid 901 under `setpriv`; the host-side vsock
proxy socket is mode 0700; the proxy's port allowlist admits only the
agent port and the declared forward range; console and daemon logs are
mode 0600; and `~/.mvm` and `~/.cache/mvm` are mode 0700.

### The claims ledger

Every guarantee below is backed by a named test or CI lane, recorded in
the machine-checked ledger later in this document (between the
`claims-catalog` markers). `xtask check-claim-catalog` parses that table
on every PR and fails when a claim's witness no longer exists in the
tree — the claim list cannot silently drift from what the code actually
does. The narrative in this section states what each claim *means*; the
ledger is the checked source of truth for *what proves it*.

### The claims

Nineteen claims: sixteen numbered guarantees plus three preview claims not
yet promoted to the numbered set. L1 (the host) has no claim of its own
per the threat model above.

| # | Claim | Layer | Enforcement |
|---|---|---|---|
| 1 | No host-fs access from a guest beyond explicit shares | L2/L5 | Per-service uid; seccomp tier `standard` default; `setpriv --bounding-set=-all --no-new-privs`; user-volume allow-list with a read-only default; admission-enforced share matching |
| 2 | No guest binary can elevate to uid 0 | L2/L4 | `setpriv --no-new-privs`; `/etc/{passwd,group,nsswitch.conf}` are read-only bind mounts, so a compromised service cannot mint a uid-0 entry |
| 3 | A tampered rootfs ext4 fails to boot, on the block+ext4 backends | L3 | dm-verity sidecar + 64-hex roothash on the kernel cmdline + a verity-aware initramfs that owns the boot pivot in userspace; a flipped data block panics the kernel before userspace runs |
| 4 | A production-safe run cannot invoke DevOnly guest-agent verbs | L4 | The universal agent classifies requests and requires both the runtime profile and a signed `VerbGrant`; the runtime-boundary CI lane and grant unit test cover the complete DevOnly set |
| 5 | Vsock framing, supervisor-config JSON, and FlowMux's guest-facing decoder and session state are fuzzed | L2/L4 | `cargo-fuzz` targets cover `GuestRequest`, the sealed control envelope `SealedFrame` parsed off the wire, the host-side `SupervisorConfig` parser, FlowMux frame decoding, and valid-frame sequences against the shared session ceilings, stream-id retirement, credit accounting, and refusal-without-state-change invariants; every host↔guest type is `#[serde(deny_unknown_fields)]` |
| 6 | The pre-built dev image is hash-verified | supply chain | The per-arch checksums manifest is fetched and the artifact is streamed through SHA-256; a mismatch rejects and deletes the download |
| 7 | Cargo dependencies are audited on every PR | supply chain | `cargo-deny` and `cargo-audit` CI jobs; a reproducibility double-build catches non-determinism that could mask injection |
| 8 | Every workload runs from a signed, audited `ExecutionPlan` | cross-cutting | An Ed25519 host-signer keypair signs a typed plan; a validity window and a nonce replay-store gate admission; every admission emits chain-signed `plan.admitted` / `plan.launched` / `plan.failed` audit entries |
| 9 | Every published bundle is content-addressed, key_id-pinned, and re-verified at fetch and at admit time | supply chain | A rejection ladder covers unknown key, tampered manifest, key_id mismatch, tampered or missing artifact, unsafe path, schema bump, and pin-archive/pin-signature drift |
| 10 | No untrusted workload reaches the network unless explicitly admitted by policy | data containment | `NetworkPolicy` defaults to deny-all; Firecracker enforces it with an nftables default-deny ruleset on the TAP; libkrun enforces it with a gateway-bridge `PlanFlowPolicy` plus always-on deny-egress and per-tenant scans; an `unrestricted` policy emits an opt-in warning with a documented escape hatch |
| 11 | Every application-dependency volume is hash-locked, attestation-checked, CVE-scanned, SBOM-enumerated, and bound to the workload's audit chain | supply chain (app layer) | A sealed volume carries `content/`, `sbom.cdx.json`, `fetch.log`, `cve.json`, and a hash-chained `meta.json`; the admission verifier refuses a tampered volume; a production launch fails closed on a high or critical CVE finding |
| 12 | Every host-side broker service is bound to a signed `ExecutionPlan.services` binding, enforced before handler dispatch, and audited | cross-cutting | Binding-gated dispatch with a rejection ladder for unbound and out-of-profile calls; the handler registry is linted for policy-schema and composition coverage |
| 13 | No raw secret value crosses the broker channel | data containment | `host.secrets.v1` returns destination-bound, time-bound signed credentials only; raw secret bytes never leave the supervisor's address space; secret-bearing buffers are zeroized on drop |
| 14 | Every OCI image admission records provenance in the chain-signed audit log | supply chain | A `plan.oci_provenance` entry carries the registry host, repo, supplied reference, resolved manifest digest, layer digest list, trust policy, and cosign verdict; a production pull or run refuses a mutable reference before any network fetch |
| 15 | A sealed production microVM has no shell, no DevOnly guest-agent verbs, and no PTY | L4 | Only the dev `/init` variant serves a console; the sealed rootfs is dm-verity protected; the backend captures the guest console write-only, with no host input; the host accessible-gate refuses `console` on a sealed image; the universal agent's console and DevOnly handlers require the runtime profile and signed grant |
| 16 | *(Preview)* Egress substitution keeps a raw secret off the guest, bound-only, with no value in the audit log | data containment | Preview status; the limits are stated on this claim's row in the ledger below and are not restated here |
| 17 | *(Preview)* Workload stdin is grant-gated, single-writer, secret-scanned across frames, and every refusal audited | data containment | Preview status; the scan is a length-and-hash fingerprint match, not an identity, and the ledger row states what that does and does not catch |
| 18 | *(Preview)* A workload's resource consumption is bounded at admission, and bound at spawn where the host has a mechanism | cross-cutting | Preview status; admission bounding holds everywhere, spawn-time CPU control is partial and backend-dependent, and the ledger row enumerates which backends are covered |
| 19 | Every dataset, model, prompt, agent, policy, and compute environment named by a workload carries a content-derived identity in the signed plan, and a pinned host share that drifts after admission fails closed | cross-cutting | `--asset KIND:PATH` hashes the asset through the canonical `hash_source` tree walk into `AssetIdentity` records inside the signed `ExecutionPlan`; admission also pins each directory share's content digest, re-verified at mount enforcement, so a post-admission edit of the host directory is refused; synthesis auto-derives the compute-environment identity from the measured image/kernel/verity state; a `plan.asset_identities` chain-signed entry carries kind, locator, and digest labels; `mvmctl trust audit asset id <path>` recomputes the same digest offline for comparison |
| 20 | Every published release artifact is signed under the release workflow's identity, and the build and fetch paths refuse an unsigned or mis-signed one | supply chain | `release.yml` signs every release blob keyless through GitHub OIDC, publishing a bundle that carries the Fulcio certificate and the Rekor inclusion proof; the `verify-release` job re-downloads the published set and verifies it against an identity regexp pinned to this workflow at a tag; the build gate refuses a missing or malformed bundle, and the fetch gate refuses an unsigned manifest before parsing it, with the hash-skip hatch explicitly not waiving the signature. The self-update path is weaker by design and warns rather than refusing when cosign is absent |

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
   restore is deliberately not covered — a child does not inherit its parent's
   plan, because auditing a child's kill under the parent's identity would
   write a wrong entry rather than a missing one.
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
   (`fn:a_restored_child_is_cpu_bounded_by_its_admitted_grant`, once per
   backend). A same-identity `restore` binds nothing, deliberately rather than
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
   bind the pool rather than the claim. `bind_cpu_grant` wraps a `Command` and
   this tree has no post-spawn attach, so on those two paths a claimed child's
   CPU bound is a ledger entry and not a `cpu.max`. Wall clock is likewise not
   re-armed on a restored or claimed child, per limit 2.
5. **The budget is not a precise cliff. (OPEN, by choice.)** Two admissions
   racing each other can both read the same total and both be admitted,
   overshooting by one boot; closing that needs a host-wide lock held across
   measure-and-start. Its CPU arm sums only *granted* shares, so an ungranted
   workload is uncapped and contributes nothing. And its liveness and record
   reads fail open in the undercount direction — an unreadable charge record
   makes one machine invisible rather than refusing every boot on the host
   (`fn:an_unreadable_charge_record_is_skipped_rather_than_fatal`). Each is a
   deliberate choice of the undercount failure over the lockout failure, which
   is the same judgement limit 4's counting rule makes.

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

### Per-backend tier matrix

mvm ships four workload-capable VM backends plus a test-only mock and an
explicitly claims-free browser preview backend. A given run carries the
tier of its *active* backend, not the strongest tier the project
supports; `mvmctl doctor` renders this matrix per host with the active
backend highlighted, and the CLI surfaces a loud banner when the active
backend falls below Tier 1.

| Backend | L1 | L2 | L3 | L4 | L5 | Notes |
|---|---|---|---|---|---|---|
| Firecracker (Linux + KVM) | ✅ | ✅ | ✅ | ✅ | ✅ | **Tier 1** — the production workload runtime, selected automatically whenever native KVM is available. Every numbered claim holds. |
| HVF / Hypervisor.framework (macOS 26+ Apple Silicon) | ✅ | ✅ | ⚠️ block+ext4 verified boot only | ✅ | ✅ | Tier 2 — the in-house Hypervisor.framework VMM. Egress, admission, and substitution are enforced through a single per-VM vsock gating endpoint: there is no guest network interface and no separate userspace gateway sidecar. The macOS 26+ Apple Silicon default. |
| libkrun (Linux KVM, macOS Hypervisor.framework) | ✅ | ✅ | ⚠️ block+ext4 verified boot only | ✅ | ✅ | Tier 2 — comparable VMM TCB to Firecracker. The macOS 13–25 default and the Linux `--builder libkrun` / opt-in workload path. |
| QEMU (Linux KVM/TCG) | ✅ KVM where available | ⚠️ larger device-model TCB | ⚠️ partial verified boot | ✅ | ✅ | Tier 2 — a `mvm`-only Linux dev/test substrate, opt-in only, never reachable from the fleet orchestrator. It carries no untrusted multi-tenant workload, so claim-10 egress enforcement is deliberately not wired into its start path. This carve-out is type-enforced: a `WorkloadBackend` marker trait gates the admitted workload-launch path, and QEMU does not implement it, so it cannot reach that path regardless of prose. The test-only mock backend does implement the marker — it is a hermetic lifecycle test double that carries no real workload, so permitting it costs nothing. |
| `wasm-sandbox` (browser / WASI preview) | ❌ | ❌ | ❌ | ❌ | ❌ | **Off the isolation scale.** No KVM, no real kernel, no TAP/virtio/vsock. Asserts none of the numbered claims and declares its own non-virtualization honestly; fails closed on any kernel/TAP/vsock request. Opt-in only; auto-detection never selects it. It is safe *because* it is single-principal — a developer's own code in their own browser sandbox, where the "malicious guest" adversary class does not apply — not because it holds any isolation claim. Promotion to a real, claim-bearing microVM re-materializes the workload from recorded intent through the audited build and admission pipeline; nothing produced in this claims-free tier carries authority into a claim-bearing one. |

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

**The retired `l3-vsock` path.** ADR-036 and ADR-037 historically supplied an
opt-in raw-packet compatibility mode. ADR-042 superseded them, and the public
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
source for ssh-agent-forwarding identifiers as a regression backstop.
Every dev-tier hook — writable volumes, dev-lifecycle
side effects — stays visible in dry-run, admission and audit output, and
receipts; it is never hidden behind a convenience default.

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

- The project's security story is fifteen enumerated, CI-enforced claims
  plus two preview claims, each with a named witness, rather than a single
  vsock-only assertion resting on unstated layers beneath it.
- A new contributor gets one document that states what mvm protects
  against, what it explicitly does not, and how each protection is
  enforced in the tree today.
- The per-backend tier matrix makes "which guarantees does *my* run
  carry" a lookup, not a guess.

### Negative / accepted costs

- The production guest closure carries `setpriv`/`runuser` support for
  the per-service privilege drop.
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
| 1  | No host-fs access from a guest beyond explicit shares | fn:seccomp_allows_listed_denies_unlisted, ci:seccomp-functional, fn:validated_conversion_enforces_mount_allow_list, fn:bare_mnt_is_refused_because_it_shadows_the_config_drive, fn:dir_share_two_part_defaults_ro, fn:relay_config_maps_dir_shares_with_dax_and_read_only, fn:enforce_admitted_shares_refuses_unadmitted_or_mismatched | seccomp + setpriv (ADR-001 §W2) + user-volume allow-list, refusing both descendants and ancestors of a runtime path / ro-default / admission-enforced shares (mvm-core + mvm-cli + mvm-backend) | Shipped |
| 2  | No guest binary can elevate to uid 0 | fn:set_no_new_privs, fn:virtiofs_mount_flags_keep_workspace_read_only, ci:check-abi-layout | setpriv --no-new-privs + RO config binds (ADR-001 §W2.2) | Shipped |
| 3  | A tampered rootfs ext4 fails to boot | ci:verified-boot-artifacts, fn:verify_and_resume_rejects_tampered_mem, ci:check-abi-layout | dm-verity + roothash on **block+ext4** backends — Firecracker + Option B (ADR-001 §W3, ADR-106); the restore path also verifies the sealed snapshot envelope (HMAC + epoch) before resuming; virtiofs-root is a dev-tier path with a weaker contract that does **not** witness this claim (ADR-107) | Shipped |
| 4  | A production-safe run cannot invoke DevOnly guest-agent verbs | fn:prod_safe_grant_refuses_all_dev_only_requests, ci:guest-agent-runtime-boundary | runtime profile + signed VerbGrant intersection (ADR-001 §W4.3) | Shipped |
| 5  | Vsock framing + supervisor-config JSON + FlowMux decode/state are fuzzed | ci:fuzz_guest_request, ci:fuzz_sealed_frame, ci:fuzz_supervisor_config, ci:fuzz_network_flow_decode, ci:fuzz_network_flow_state, ci:fuzz_input_frame | cargo-fuzz (ADR-001 §W4.1/W4.2) | Shipped |
| 6  | The pre-built dev image is hash-verified | ci:hash-verify-tests, fn:download_runtime_overlay_rejects_checksum_mismatch | SHA-256 manifest (ADR-001 §W5.1) | Shipped |
| 7  | Cargo deps are audited on every PR | ci:cargo-deny, ci:cargo-audit, ci:reproducibility | RUSTSEC + deny.toml (ADR-001 §W5.2/W5.3) | Shipped |
| 8  | Every workload runs from a signed, audited ExecutionPlan | fn:synthesize_plan, fn:admit_for_run, fn:verify_audit_chain, fn:naively_dropping_old_entries_fails_verification_at_line_zero, fn:a_prune_record_that_over_claims_is_refused, fn:the_same_deletion_without_a_record_is_still_refused, fn:pruning_a_broken_chain_is_refused_before_anything_is_deleted, fn:a_spliced_segment_is_refused, fn:a_missing_segment_is_named_not_silently_skipped, fn:an_interrupted_rotation_continues_history_instead_of_restarting_it | Ed25519 + chain-signed audit log (ADR-014). The chain may be rotated into sequenced segments (Plan 319): `verify_audit_chain` now attests an unbroken chain from genesis **or from a signed handoff naming its predecessor segment and that predecessor's final chain hash**, and `verify_segment_set` attests the ordering and completeness of the segment set. A retired prefix may also be deliberately pruned (Plan 326): the chain then verifies **with a corroborated gap** rather than whole, and the prune record may only claim what the surviving handoff independently attests, so it cannot relabel an edit as a removal. Only the upper boundary of a pruned range is cross-checked. Tail truncation stays undetectable, as it was before rotation | Shipped |
| 9  | Every published bundle is content-addressed and re-verified | fn:read_and_verify_bundle, fn:verify_plan_bundle | SHA-256 content-addressing (Sprint 52 W2) | Shipped |
| 10 | No untrusted workload reaches the network unless policy-admitted | fn:policy_default_is_deny_all, fn:run_net_default_is_deny_all, ci:single-network-path, ci:fuzz_dns_codec, fn:private_link_local_loopback_ula_metadata_are_forbidden, fn:emits_resolved_query_with_ip_list, fn:admitted_projection_is_one_object_graph_for_every_network_surface, fn:assert_vsock_only_device_model, fn:verify_and_resume_refuses_nic_on_restore, fn:fork_restore_refuses_nic | one authenticated FlowMux endpoint + one admitted policy/budget/identity/audit projection + permanent single-path/socket-owner gate + bounded DNS codec fuzzing + DNS-answer SSRF/rebinding filtering + chain-signed per-query DNS audit; warm-restore and fork-restore refuse any restored device model carrying a NIC before resuming vCPUs | Shipped |
| 11 | Every app-dep volume is hash-locked, CVE-scanned and SBOM-enumerated | ci:app-deps-audit, fn:verify_sealed_volume, fn:apply_install_gate | CycloneDX + pip-audit (ADR-047) | Shipped |
| 12 | Every host-side service binding is plan-gated and audited | fn:unbound_service_returns_not_bound, fn:service_call_rejects_unknown_envelope_fields | ExecutionPlan.services binding (ADR-020) | Shipped |
| 13 | No raw secret value crosses the broker channel | fn:substitute | destination-bound signed credentials (ADR-023). Previously also cited fn:encode_secret_env_cmdline_round_trips_pairs_as_single_token, which round-trips an encoder with no production caller: `mvm.secret_env` is built by nothing and parsed by nothing, so that test witnessed an encoding, not a containment. The shipped mechanism injects placeholders on the invoke path from the endpoint-minted env file. The cmdline token stays in tree as designed-but-unwired — its doc argues it is the only per-VM channel a fresh sealed FC boot has — so wiring it is a live option, but it is not evidence today | Shipped |
| 14 | OCI image provenance is recorded in the chain-signed audit log | fn:prod_pull_requires_digest_pin_before_network, fn:prod_run_image_requires_digest_pin_before_network | cosign + OCI digest (ADR-017), recorded on the claim 8 admission flow (ADR-014). Unchanged in substance by Plan 319, but a `plan.oci_provenance` entry may now sit in a retired segment, so the claim holds over the tenant's segment *set* rather than over `<tenant>.jsonl` alone — `mvmctl trust audit verify` walks the set | Shipped |
| 15 | A sealed production microVM has no shell, no DevOnly guest-agent verbs, and no PTY | fn:console_refused_on_sealed_image, ci:guest-agent-runtime-boundary, fn:following_the_console_never_writes_to_it | runtime profile + signed VerbGrant + host accessible-gate + console policy (ADR-001 §W4.3 extension). The host→guest input plane is deliberately *not* claimed here: its properties are policy, not absence, and are witnessed at row 17 | Shipped |
| 16 | Egress substitution keeps a raw secret off the guest, bound-only, no value in audit | fn:handed_placeholders_never_contain_the_secret_value, fn:network_endpoint_refuses_unbound_destination, fn:audit_chain_carries_no_secret_value | egress substitution leak-gate; reinforces claims 12+13 on the egress delivery (ADR-023) | Preview |
| 17 | Workload stdin is grant-gated, single-writer, secret-scanned across frames, and every refusal is audited | fn:input_is_refused_without_a_plan_grant, fn:a_second_writer_is_refused_while_the_lease_is_held, fn:secret_material_split_across_frames_is_still_refused, fn:every_refusal_is_audited, fn:a_shell_entrypoint_with_the_grant_is_refused_and_names_the_reason, fn:the_endpoint_fingerprints_what_it_resolved_and_reports_no_value, fn:the_handshakes_two_halves_go_to_two_different_places, fn:a_secret_split_across_two_frames_does_not_reassemble_in_the_workload, fn:a_fingerprint_refusal_does_not_claim_the_bytes_are_the_secret | input grant token in a signed ExecutionPlan.services + per-VM lease with TTL + fingerprint-matching sliding-window secret scan + chain-signed payload-free refusal audit + sealed-tier shell-entrypoint refusal. Read the limits note below before treating this as enforced | Preview |
| 18 | A workload's resource consumption is bounded at admission — per workload and across the host — and CPU-bound at spawn where the host has a mechanism | fn:a_boot_past_the_headroom_is_refused, fn:budget_ignores_dead_machines, fn:budget_counts_the_configured_maximum_not_current_usage, fn:an_empty_host_admits_a_boot_within_headroom, fn:an_unreadable_charge_record_is_skipped_rather_than_fatal, fn:admission_refuses_a_grant_over_the_ceiling, fn:the_ceiling_bounds_memory_even_though_no_one_granted_it, fn:prod_refuses_a_cpu_grant_on_a_backend_that_cannot_bound_cpu, fn:the_libkrun_tier_cannot_bound_cpu_off_linux, fn:host_cpu_mechanism_gap_honors_hvf_quota_range, fn:relay_config_threads_cpu_share_to_quota_scheduler, fn:apply_grants_reads_quota_record_from_state_dir, fn:a_share_grant_binds_the_spawn_when_the_mechanism_is_present, fn:a_vm_with_no_recorded_scope_reads_back_as_declared_not_as_an_error, fn:an_admitted_boot_writes_the_achieved_tier_to_the_audit_chain, fn:a_wall_clock_bound_needs_a_clock_that_can_stop_the_workload, fn:a_signed_plan_from_the_launch_path_arms_the_timer, fn:a_granted_cpu_share_binds_a_real_spawn_to_its_quota, fn:a_restored_child_is_cpu_bounded_by_its_admitted_grant, fn:a_claimed_child_over_the_host_ceiling_is_refused, fn:a_claimed_child_within_the_ceiling_is_admitted, fn:the_refusal_names_the_ceiling_and_the_request, fn:pool_matching_is_unchanged_by_the_bound | operator-configured per-workload ceiling + host-wide budget summed over live machines only (pid-marker probe, configured maximum not current usage) + cgroup v2 `cpu.max` on a systemd transient scope on Linux, or an in-process HVF run-loop scheduler on macOS, read back and written to the chain-signed audit log. CPU is declared-only for libkrun, wall clock is enforced on the tiers whose supervisor holds the admitted plan (libkrun, HVF, AppleContainer), wasm bounds via fuel and epoch, a forked child is re-bound at spawn, and a warm-claimed child is bounded by the host ceiling at admission but spawn-bound on only one of its three claim paths — read the "Preview 18 limits" note below before treating this as enforced | Preview |
| 19 | Every workload asset and pinned host share is content-identified in the signed plan, and share drift after admission fails closed | fn:admitted_share_digest_refuses_directory_changed_after_admission, fn:synthesized_plan_records_share_and_caller_asset_identities, fn:asset_identities_event_carries_kind_name_digest_labels, fn:asset_identity_rejects_malformed_digests, fn:test_audit_asset_id_parses | content-derived AssetIdentity records inside the signed ExecutionPlan (digest validated as 64-hex at the type boundary) + admission-time share digest pins re-verified by `enforce_admitted_shares` at mount time + synthesis auto-derivation of the compute environment + chain-signed `plan.asset_identities` emission + offline digest recomputation via `trust audit asset id` | Shipped |
| 20 | Every published release artifact is signed under the release workflow's identity, and the build and fetch paths refuse an unsigned or mis-signed one | ci:verify-release, fn:accepted_identities_are_the_versioned_release_workflow, fn:a_missing_bundle_refuses_and_names_the_asset, fn:fetch_expected_hashes_refuses_an_unsigned_manifest_before_parsing, fn:skip_hash_verify_does_not_waive_the_manifest_signature | keyless cosign over every release blob with a Fulcio + Rekor bundle, re-verified post-publish by the `verify-release` job against an identity regexp pinned to this workflow at a tag; the build gate refuses a missing or malformed bundle and the fetch gate refuses an unsigned manifest before parsing (ADR-001 §W5). Limit: the self-update path warns rather than refusing when cosign is absent — see "Claim 20 limits" | Shipped |

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

**Claim 3 backend scoping (ADR-107).** Claim 3's witness, dm-verity, is
block-device-specific: it ratifies the claim on the **block+ext4** backends
— Firecracker and the in-process Option B materialize path (ADR-106). A
**virtiofs root** (Plan 221 Option A) serves a host directory, not a block
device, so it cannot be dm-verity-sealed. Per ADR-107, virtiofs-root is a
dev/local-tier boot mechanism carrying an explicitly weaker contract
(unpack-time per-layer sha256 + read-only serving from the trusted host, no
guest-enforced plan-bound re-verification); it does **not** witness claim 3.
Prod / sealed / `--prod` workloads — and Firecracker on every tier — stay on
Option B, where claim 3 holds unchanged. No numbered claim is weakened; this
note only scopes which backends the existing witness covers.

**Claim 20 limits — the three consuming paths do not share a posture.** The
claim is worded to say the build and fetch paths refuse, and not to say that
every path does, because one does not.

- **Build path — refuses.** `crates/mvm-build/src/release_signature.rs` fails the build on a missing or malformed bundle and names the asset, and accepts only the versioned release-workflow identity. Only the missing-bundle half is cited: the malformed-bundle test is `#[cfg(feature = "manifest-verify")]`, and every use of that feature in CI is `cargo run --example`, never `cargo test --features`, so no lane executes it. It is a good test that nothing runs, and `check-claim-catalog` cannot see a cfg gate — citing it would buy a witness that is green because it never executes. Wiring the feature into a test lane would make it citable.
- **Fetch path — refuses.** `crates/mvm-cli/src/commands/env/artifact_verify.rs` rejects an unsigned manifest before parsing it, and the documented hash-skip hatch does not waive the manifest signature.
- **Self-update path — warns.** `verify_signature` in `crates/mvm-cli/src/update.rs` returns `Ok` when `cosign` is not on `PATH`, so on that path the signature is best-effort and the SHA-256 pin is the control that still holds.

The gap is deliberate rather than unnoticed: a hard refusal there strands a user
whose host has no cosign, on the one command they would use to fix it. Whether
to close it is a live question, not a defect this claim is hiding — but the
claim must not be paraphrased as "every path refuses an unsigned release".

What this claim does **not** assert: build provenance. Nothing in the release
pipeline emits a SLSA provenance attestation for the binaries today, and the
signature proves who published an artifact rather than what went into it.
`ci:reproducibility` under claim 7 is the control that speaks to the second
question.

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
  record gaps in the Authority column. Becomes its own
  `specs/plans/<N>-claim-witness-authority-audit.md`.
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

## References

- `specs/adrs/007-vmbackend-single-trait.md` — the `VmBackend` trait
  boundary this ADR's tier matrix depends on; the `WorkloadBackend`
  marker trait that type-enforces the QEMU carve-out above is defined in
  `crates/mvm-backend/src/workload_backend.rs`.
- `specs/adrs/014-signed-audited-execution-plans.md` — claim 8's signing
  and admission mechanics.
- `specs/adrs/020-host-services-broker.md` — claims 12 and 13's broker
  architecture, and the resident-daemon trust-gradient ledger.
- `specs/adrs/021-pid0-portability-boundary.md` — the guest control
  surface the boundary-language decision above governs.
- `specs/adrs/023-secrets-subsystem-egress-substitution.md` — the
  substitution mechanism behind claim 13 and preview claim 16.
- `specs/adrs/024-wasm-sandbox-backend.md` — the `wasm-sandbox` backend's
  own decision record.
- `CLAUDE.md` §"Security model" — the narrative summary kept in lockstep
  with the claims ledger above.
