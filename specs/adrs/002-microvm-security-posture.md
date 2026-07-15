---
title: "ADR-002: microVM security posture — explicit guarantees, layered defenses"
status: Accepted
date: 2026-04-30
revised: 2026-06-05
supersedes: none
related: ADR-001 (multi-backend execution); plan 25-microvm-hardening; plan 53-cross-platform-roadmap
---

## Status

Accepted. Implementation tracked in `specs/plans/25-microvm-hardening.md`. Workstreams W1–W6 shipped 2026-04-30.

The 2026-05-07 revision adds the **Trust layers (Matryoshka model)** section, names the seven CI-enforced claims explicitly, and adds a **per-backend tier matrix** showing which claims hold for each backend in `AnyBackend`. None of the original decisions or surfaces change — the revision is a re-framing for legibility, motivated by plan 53 (cross-platform roadmap) where multiple backends with different tier coverage now coexist.

The 2026-05-10 revision adds the **Framework references** subsection (MITRE ATT&CK / D3FEND / CREF mapping for each of the seven claims). Doc-only; no code, CI, or test impact.

The 2026-06-05 revision reframes the **cold-state guarantee** as a property *being promoted* to a witnessed claim (Plan 167), pending its catalog witness. Doc-only; no code, CI, or test impact yet — the witness and numbered-table entry land in a follow-up implementation PR.

## Context

mvm runs untrusted-shaped Linux workloads in microVMs. Through Sprint
14 the project's stated security model was a single claim: "no SSH in
microVMs, ever — vsock-only communication, with the dev `Exec` handler
gated at compile time by the `dev-shell` Cargo feature." That claim is
true and load-bearing, but it is the *only* hardened layer. Everything
underneath it — the guest's own privilege model, the rootfs's integrity,
the host-side proxy socket, the supply chain by which the dev image
arrives, the deserializer that parses every host-to-guest message — is
soft. A failure in any one of those defeats the whole stack regardless
of the vsock claim.

The project's value proposition is that a developer can run third-party
or AI-generated code in a microVM and trust the isolation. That promise
demands that the protections be technical, verifiable, and stated
explicitly.

This ADR captures the decisions; the implementation sequence is in
`specs/plans/25-microvm-hardening.md`.

## Threat model

Adversaries, in priority order:

1. **A malicious guest workload.** Code running inside a microVM. Must
   not be able to read the host filesystem outside explicit shares,
   talk to the host network, escape the hypervisor, read another
   guest service's secrets, or tamper with the rootfs's baked closure.

2. **A same-host hostile process.** Another local user, or another
   process running as the host user, must not be able to talk to the
   dev VM's guest agent, read its console log, write to its rootfs
   cache, or tamper with launchd plists / GC roots.

3. **A compromised supply chain.** A malicious nixpkgs commit, a
   compromised GitHub account hosting prebuilt artifacts, or a
   typo-squatted Cargo dep, must not silently land code in a microVM
   without producing a verifiable signature failure.

A *malicious host* (the macOS or Linux machine running mvmctl itself)
is **explicitly out of scope**. mvmctl trusts the host with the
hypervisor, the GC roots, the launchd plists, the user's secrets in
`/mnt/secrets`, and the private build keys.

### Why a hardware boundary, not a userspace application-kernel sandbox

A recurring review question is why mvm isolates the workload behind a
hardware boundary (a VMM over KVM / Hypervisor.framework) rather than a
userspace application-kernel sandbox — the class of sandbox that
intercepts guest syscalls in a host-side process and re-implements a
kernel ABI on top of seccomp + namespaces. mvm chose the hardware
boundary deliberately: the isolation is enforced by the CPU (rings,
EPT, IOMMU) rather than by the correctness of a syscall-emulation
layer, there is no host-side syscall-compatibility surface to keep in
lockstep with the upstream kernel, and a bug in the boundary is a VM
escape (rare, hardware-assisted) rather than an in-process logic error
in an emulated `openat`/`mount`/`ptrace`. The userspace
application-kernel sandbox remains the reference point for mvm's
*in-guest* hardening layer (L4/L5), where the threat model is
narrower: an `openat2(RESOLVE_IN_ROOT | RESOLVE_NO_SYMLINKS)`-confined
OCI-layer unpacker that closes the path-resolution TOCTTOU class, and
an ioctl-syscall denylist on the guest agent. Those measures borrow
the application-kernel sandbox's syscall-discipline ideas without
adopting it as the primary isolation boundary. This is adjacent-threat
positioning, not a new numbered claim — it does not appear in the
claim table below.

## Trust layers (Matryoshka model)

mvm's defense-in-depth is structured as five trust layers nested like a
matryoshka doll. Each layer trusts the layer *below* it and nothing
else; an attacker has to break through every boundary above to reach
the host. A failure in any one layer is bounded — the layer below
still enforces its own contract.

```
┌───────────────────────────────────────────────────────────────┐
│ L5 — Workload (untrusted code, AI-generated, user scripts)    │
│      enforced by: per-service uid (W2.1), bounding-set drop   │
│                   (W2.3), seccomp tier `standard` (W1.1, W2.4)│
├───────────────────────────────────────────────────────────────┤
│ L4 — Guest agent (parses host messages, launches services)    │
│      enforced by: uid 901 setpriv (W4.5), no_new_privs,       │
│                   `do_exec` absent in prod (W4.3),            │
│                   fuzzed deser + deny_unknown_fields (W4.1-2) │
├───────────────────────────────────────────────────────────────┤
│ L3 — Guest kernel (Linux from Nix, ephemeral, isolated)       │
│      enforced by: dm-verity rootfs + roothash on cmdline +    │
│                   mvm-verity-init initramfs (W3)              │
├───────────────────────────────────────────────────────────────┤
│ L2 — VMM (userspace, Rust, seccomp-jailed, unprivileged)      │
│      enforced by: minimal device set (Firecracker), seccomp   │
│                   default-on, host-side proxy socket 0700     │
│                   (W1.2), port allowlist (W1.3)               │
├───────────────────────────────────────────────────────────────┤
│ L1 — Host + hypervisor (KVM on Linux, Apple VZ on macOS,      │
│                          Hypervisor.framework via libkrun)    │
│      enforced by: hardware (CPU rings, EPT, IOMMU); host      │
│                   hardening is the user's responsibility      │
└───────────────────────────────────────────────────────────────┘
```

The "matryoshka" framing comes from the 2026 microVM ecosystem
discourse (notably <https://emirb.github.io/blog/microvm-2026/>).
It is the same pattern used by other production microVM and
hardened-isolation platforms. The mvm
adaptation is that L5 is enforced *inside* the guest by uid/seccomp
(plan 26), so even a guest-kernel compromise (L3 fall) doesn't grant
arbitrary access to other in-guest services.

## The CI-enforced claims

Each claim is backed by a CI gate that fails the build if the claim
ceases to hold. Claims are mapped to the trust layer they *primarily*
defend; many claims have ripple effects across multiple layers, but
the primary defended layer is the one the gate fails first.

The original ADR shipped with seven claims. Claim 8 (signed
`ExecutionPlan`) was added by plan 64 / ADR-041 and named in
CLAUDE.md but not in this table until now. Claim 9 (signed
bundles) is Sprint 52 W2 — this commit catches the table up to
both. Claim 11 (app-dep audit pipeline — claim 9 in
`CLAUDE.md::Security model` because CLAUDE.md numbers from the core
8 + the SDK-port follow-on) was added by ADR-047 / Plan 73
Followups A + B.1/B.2/B.3 + C + D. Claims 12 and 13 (host services
broker — binding-gated dispatch + workload audit-entry attribution)
were added by Plan 104 / ADR-059, with Claim 13 rewritten by ADR-059's rescope
when `host.secrets.v1` was dropped from v1 scope and `host.audit.v1`
took its place as the load-bearing workload service. Claim 15
(no interactive access to a sealed production microVM) was added by
Plan 165 WS-C. The table jumps 13→15 deliberately: claim 14 (OCI image
provenance) is already in `specs/claims/catalog.md` and
`CLAUDE.md::Security model` but its promotion into this numbered table
is tracked under Plan 111, so the number is held aligned with the
catalog ledger rather than reused.

| # | Claim | Primary layer | Workstream | CI gate |
|---|---|---|---|---|
| 1 | No host-fs access from a guest beyond explicit shares | L2/L5 | W2.1, W1.1, W2.3, W2.4 | seccomp regression; per-service-uid bind audit |
| 2 | No guest binary can elevate to uid 0 | L2/L4 | W2.2, W2.3 | bind-mount RO assertion; setpriv `--no-new-privs` regression |
| 3 | A tampered rootfs ext4 fails to boot **(block+ext4 backends; see §"Verified-boot verity surface" for the virtiofs-root scoping)** | L3 | W3.1–W3.4 | `verified-boot-artifacts` + live-KVM tamper test in `security.yml` |
| 4 | The guest agent does not contain `do_exec` in production builds | L4 | W4.3 | `prod-agent-no-exec` symbol-grep job in `ci.yml` |
| 5 | Vsock framing + supervisor-config JSON are fuzzed | L2/L4 | W4.1, W4.2, Plan 88 W6 | `cargo-fuzz` targets in `crates/mvm-guest/fuzz/` (`GuestRequest`, `AuthenticatedFrame`, `fuzz_authed_path`) and `crates/mvm-libkrun/fuzz/` (`fuzz_supervisor_config`); `deny_unknown_fields` audit |
| 6 | Pre-built dev image is hash-verified | cross-cutting (supply chain) | W5.1 | `download_dev_image` SHA-256 check; `MVM_SKIP_HASH_VERIFY` only documented escape |
| 7 | Cargo deps are audited on every PR | cross-cutting (supply chain) | W5.2 | `cargo-deny` + `cargo-audit` jobs; reproducibility double-build (W5.3) |
| 8 | Every workload runs from a signed, audited `ExecutionPlan` | cross-cutting (policy + audit) | plan 64 W1–W4, ADR-041 | `synthesize_plan` / `host_signer::load_or_init_at` / `admit_for_run` / `AuditEmitter` round-trip + tamper rejection tests; `xtask check-no-display-on-secret-types` |
| 9 | Every published bundle is content-addressed, key_id-pinned, and re-verified at fetch **and at admit time** | cross-cutting (supply chain + integrity) | Sprint 52 W2 + admit-time re-verify follow-on | `mvm_plan::bundle::read_and_verify_bundle` + `mvm_plan::bundle::verify_plan_bundle` rejection-ladder tests: unknown-key, tampered manifest, key_id mismatch, tampered artifact, missing artifact, unsafe path, schema bump, pin-archive sha256 drift, pin-signature drift; `mvmctl bundle fetch` round-trip + `admit_for_run` tests asserting refusal on pin-without-context and pin-archive mismatch |
| 10 | No untrusted workload reaches the network unless explicitly admitted by policy | cross-cutting (data containment) | Sprint 52 W3 | `policy_default_is_deny_all` + `test_resolve_network_policy_default_is_deny_all`; `mvmctl up` emits an opt-in warning when the resolved policy is `unrestricted` (escape hatch is `MVM_ACK_UNRESTRICTED_NETWORK=1`); libkrun/Vz admitted `up` boots thread the signed plan by default so the gateway bridge enforces default-deny; non-deny CLI/template policies are lowered into a generated signed-policy bundle rather than an unsigned bare carrier |
| 11 | Every application-dep volume is hash-locked, attestation-checked, CVE-scanned, SBOM-enumerated, and bound to the workload's audit chain | cross-cutting (supply chain — app-layer deps) | ADR-047, Plan 73 Followups A + B.1/B.2/B.3 + C + D | `mvm_sdk::compile::deps_audit::{seal_volume, verify_sealed_volume}` tamper-detection unit tests; `mvm_build::app_deps_gate::apply_install_gate` prod/dev rejection tests; `app-deps-audit` CI lane in `ci.yml` (Followup D) — drives `mvmctl compile` on `examples/python/hello-app-with-deps/`, seals a clean + a HIGH-CVE fixture via `mvm-app-deps-fixture-tool`, asserts `mvmctl deps inspect --json` produces a well-formed report, asserts the prod gate refuses the HIGH-CVE fixture and the dev gate admits it, asserts a byte-flip on `cve.json` makes inspect refuse |
| 12 | Every host-side service the broker exposes is bound to a signed `ExecutionPlan.services` binding, enforced before handler dispatch, and audited via the chain-signed log | cross-cutting (policy + audit) | Plan 104 W2, ADR-059 | `service_call_denied_when_unbound` + `service_call_denied_outside_profile` + `audit_chain_contains_service_call_entries` + `audit_chain_carries_no_payload_bytes` rejection-ladder tests; `xtask check-handler-adr-coverage` + `xtask check-handler-policy-schema` + `xtask check-handler-composition` lints; `fuzz_service_call.rs` lane (Plan 104 W6) |
| 13 | No raw secret value crosses the broker channel; `host.secrets.v1` returns destination-bound, time-bound signed credentials only; raw secret bytes never leave the supervisor's address space | cross-cutting (data containment) | Plan 104 W5, ADR-067, ADR-059 | `host_secrets_v1_denied_outside_allowed_destinations` + `zeroize_drop_zeros_secret_bytes` + `handler_inter_call_memory_hygiene` + `host_secrets_v1_signed_payload_jcs_roundtrip` + `secrets_subprocess_cannot_reach_supervisor_memory` + `placeholder_in_outbound_request_dropped_and_audited` (S25 backstop) tests; ADR-067 hostile-guest matrix in W7 |
| 15 | No interactive access to a sealed production microVM | L4 | Plan 165 WS-C | `prod-agent-no-console` symbol-grep job in `security.yml` (the agent's PTY-over-vsock console is `dev-shell`-gated, so a sealed prod agent links no console symbol — same shape as claim 4's `do_exec` gate); host `console_refused_on_sealed_image` accessible-gate test; `prod_console_attachment_has_no_input` write-only-console-capture test |

L1 (host + hypervisor) has no claim of its own — the host is trusted
by definition (see Threat model). L1 *enables* claim 3 (verified boot
needs a hypervisor that respects the kernel cmdline). If the host is
compromised, every layer falls; that case is explicitly out of scope.

**Claim 10 on libkrun/Vz `up`.** As of 2026-06-17, admitted workload boots on
libkrun and Vz thread the signed `ExecutionPlan` by default. `plan_json`
presence selects the gateway-bridge supervisor, whose restart policy is
hard-fail; if the bridge cannot start or panics, the VM launch fails closed
rather than falling back to direct gvproxy. Explicit non-deny egress
(`--network-allow`, non-`none` `--network-preset`, or a template default) is
lowered at admission into a generated in-memory `PolicyBundle` and referenced
by the signed plan. Host allow-lists are DNS-pinned on the host into TCP
`/32`/`/128` L4 rows; an unresolvable requested host aborts admission instead
of widening egress. Deny-all remains the `local-default` no-bundle posture.
Firecracker remains uniform at the policy level via its nftables path; its
gateway sidecar is still an explicit `MVM_GATEWAY_BRIDGE=1` diagnostic path.

**Verified-boot verity surface (claim 3, current architecture).** The
dm-verity seal is produced by `mvm_build::oci_to_rootfs::verity`
(`veritysetup format` + a 64-hex roothash) and covers two read-only
images: the workload **rootfs** — sealed-prod `.mvm` artifacts carry
`rootfs.verity` + `roothash`, which the backend wires as a dm-verity
device on the kernel cmdline (`mvm-backend/src/microvm.rs`) and
`mvm-verity-init` mounts — and the **runtime overlay** attached to
every microVM (ADR-051, "sealed the same way it seals rootfs"). The
`verified-boot-artifacts` CI lane witnesses the seal end-to-end via the
runtime-overlay build (the standalone bundled prod image it formerly
built was retired by Plan 115); the live-KVM tamper test exercises the
boot-time panic on a flipped data block.

Claim 3's witness (dm-verity) is **block-device-specific**: it applies to
the **block+ext4** backends — Firecracker and the in-process Option B
materialize path (ADR-106). A **virtiofs root** (Plan 221 Option A) serves
a host *directory*, not a block device, so it cannot dm-verity a filesystem
whose blocks it does not own. Per **ADR-107**, virtiofs-root is a
**dev/local-tier** boot mechanism carrying an explicitly weaker contract —
unpack-time per-layer sha256 verification (plus cosign on policy-gated
pulls) then read-only serving from the trusted host, with no guest-enforced,
plan-bound re-verification of served files. It **does not witness claim 3**,
and prod / sealed / `--prod` workloads (and Firecracker on every tier) stay
on Option B, where claim 3 holds unchanged. See ADR-107 for the full
virtiofs-root integrity posture and the deferred promotion path.

### Backend symmetry (Plan 98)

Claims 1, 5, 7, 8, and 11 have **backend-symmetric evidence**: the
gate holds under both the libkrun-backed builder VM and the
Vz-backed builder VM (Plan 98). The libkrun-side evidence cited
above is the canonical reference; the Vz-side parity claims hold
with the same shape and are catalogued per-claim in **ADR-046 §"Vz
as a second builder backend (Plan 98)" → "Security claim parity"**.
Specifically:

- **Claim 1** — VirtioFsShare set-equality test (Plan 98 §2.S8).
- **Claim 5** — `crates/mvm-vz/fuzz/` parallels `crates/mvm-libkrun/fuzz/fuzz_supervisor_config.rs` (Plan 98 §2.S6).
- **Claim 7** — `crates/mvm-vz` participates in `deny` + `audit` like every workspace member (Plan 98 §2.S5).
- **Claim 8** — `mvmctl audit verify` after a Vz-driven `mvmctl up --prod` asserts chain cleanliness (Plan 98 §2.S3).
- **Claim 11** — cross-backend byte-equivalence of sealed deps volume `(content/, sbom.cdx.json, fetch.log, cve.json)` (Plan 98 §2.S2) + `meta.json` backend-neutrality (Plan 98 §2.S10) + Install-arm kernel parity (Plan 98 §2.S9).

Claims 2, 3, 4, 6, 9, 10 are guest-side or end-user-runtime concerns
that don't depend on which host VMM booted the builder, so the
existing libkrun-side evidence applies unchanged.

### Framework references

Each claim is named here in MITRE vocabulary. Adversary technique = the
ATT&CK behavior the claim *denies*; defensive technique = the D3FEND /
CREF technique the claim *instantiates*. Mapping is for cross-reference
only — the CI gate is the source of truth, not the framework code.

| # | Adversary technique denied | Defensive technique instantiated |
|---|---|---|
| 1 | T1611 (Escape to Host) | D3FEND: Process Segmentation, Mandatory Access Control · CREF: Privilege Restriction, Segmentation |
| 2 | T1548 (Abuse Elevation Control), T1068 (Exploitation for Privilege Escalation) | D3FEND: Local File Permissions, System Call Permissions · CREF: Privilege Restriction |
| 3 | T1542.003 (Bootkit), T1601 (Modify System Image) | D3FEND: System Boot Verification · CREF: Substantiated Integrity |
| 4 | T1059 (Command and Scripting Interpreter — surface eliminated, not detected) | CREF: Realignment (scope reduction by build-time exclusion) |
| 5 | T1190-class (Exploit of host↔guest interface) | CREF: Substantiated Integrity (deser path proven via fuzzing + `deny_unknown_fields`) |
| 6 | T1195.002 (Compromise Software Supply Chain) | D3FEND: Executable Integrity (hash + cosign signature verification) · CREF: Substantiated Integrity |
| 7 | T1195.001 (Compromise Software Dependencies and Development Tools) | D3FEND: Software Composition Analysis · CREF: Substantiated Integrity |
| 8 | T1565 (Data Manipulation), T1574 (Hijack Execution Flow — policy substitution variant) | D3FEND: Authentication, Authorization · CREF: Substantiated Integrity (every launch traces back to a signed, validity-windowed plan) |
| 9 | T1195.002 (Compromise Software Supply Chain — image variant), T1565.001 (Stored Data Manipulation) | D3FEND: Authentication, Executable Integrity · CREF: Substantiated Integrity (manifest-signed + per-artifact hash + key_id-pinned trust establishment) |
| 10 | T1071 (Application Layer Protocol — data exfiltration channel), T1041 (Exfiltration Over C2 Channel) | D3FEND: Network Traffic Filtering, Outbound Traffic Filtering · CREF: Privilege Restriction (deny-all default; egress is an explicit opt-in) |
| 11 | T1195.001 (Compromise Software Dependencies and Development Tools — app-layer variant), T1565.001 (Stored Data Manipulation — deps volume variant) | D3FEND: Software Composition Analysis, Executable Integrity · CREF: Substantiated Integrity (hash-locked + SBOM + attestation + CVE-scanned sealed volume bound to audit chain) |
| 12 | T1574 (Hijack Execution Flow — capability-granting variant), T1078 (Valid Accounts — unauthorized service invocation) | D3FEND: Authorization · CREF: Substantiated Integrity (signed binding gate → enforced dispatch → chain-signed audit on every call) |
| 13 | T1078 (Valid Accounts — unauthorized audit attribution), T1565 (Data Manipulation — audit-chain variant) | D3FEND: Authentication, Authorization · CREF: Substantiated Integrity (workload-emitted entries chain-signed under distinct `WorkloadAudit` category; workload-id mismatch refused at admission; chain verifier displays category alongside entry so operators can tell workload-asserted from supervisor-observed) |
| 15 | T1021 (Remote Services — interactive session into a sealed workload), T1059 (Command and Scripting Interpreter — interactive console surface eliminated, not detected) | CREF: Realignment (scope reduction by build-time exclusion — same family as claim 4 / `do_exec`) · D3FEND: Process Segmentation |

The cold-state guarantee (per-workload fresh boot, no warm pools — see
CLAUDE.md and the `mvmctl run` lifecycle) is today a structural property
of the runtime rather than a single CI gate. In framework terms it is
**CREF: Non-Persistence**, and denies T1546 (Event-Triggered Execution) /
T1547 (Boot or Logon Autostart) classes of persistence outright.

It is being **promoted to a witnessed claim** (Plan 167): a workload's
runtime state must not survive its own teardown, and the next boot on the
same host must be fresh. The promotion is *pending its witness* — the
catalog entry and `fn:` tests do not exist yet, so this property is not
yet in the numbered claim table and `check-claim-catalog` does not name
it. Scope is strictly **per-workload** (one guest = one workload). It is
not a between-tenant/concurrent-session isolation claim — that multiplexing
lives in mvmd — and it is not a claim about hypervisor/DRAM memory
scrubbing (the host is trusted; physical RAM sanitization on VMM exit is
out of scope). The witness covers state-dir / overlay / warm-pool
destruction at the mvm layer only.

Frameworks intentionally referenced:

- ATT&CK Enterprise (technique IDs `T….`) — adversary behavior
  catalog. Stable IDs across versions.
- D3FEND — defensive technique catalog. Class names used here (e.g.
  "System Boot Verification") are referenced rather than D3FEND IDs
  because the ID scheme has churned across releases and the class
  names are more durable.
- CREF (Cyber Resiliency Engineering Framework) — names the *kind* of
  resiliency each claim provides under the four CREF goals
  (Anticipate / Withstand / Recover / Adapt). Most mvm claims are
  Withstand-class; cold-state is Recover-class.

ATLAS (adversarial ML) is not mapped here — mvm hosts AI workloads but
makes no claim about their internals. Workloads are L5 (untrusted) and
all five layers above are model-agnostic.

## Surfaces

A complete enumeration of every surface that bears on these adversaries.
Each is addressed in the corresponding workstream of plan 25.

### Host → guest

| Surface | Today | Hardened |
|---|---|---|
| Vsock framing in `mvm-guest-agent` | `serde_json::from_slice`, no fuzzing, parses any `GuestRequest` | `deny_unknown_fields`, depth/size caps, fuzzed in CI (W4.1, W4.2) |
| `Exec` handler | Compile-gated by `dev-shell` feature, but no CI gate | CI greps the prod binary for `do_exec`; absence is enforced (W4.3) |
| `ConsoleOpen` | PTY data port multiplexed over vsock | Same; mitigated by per-service uid (W2.1) and proxy-socket lockdown (W1.2, W1.3) |
| `StartPortForward` bind address | Not audited | Asserted `127.0.0.1`-only by regression test (W4.4) |
| Guest agent's own privileges | Runs as PID 1 = uid 0 | Runs as uid 901 `mvm-agent` user under `setpriv` (W4.5) |

### Guest → host

| Surface | Today | Hardened |
|---|---|---|
| VirtioFS workdir share | Writable, scoped to project dir | Unchanged shape, but per-service uid means no service can write there without explicit user grant (W2.1) |
| VirtioFS datadir share | Writable, scoped to `~/.mvm` | Same; mode-locked containment via uid + `nosuid,nodev` mount opts (W2.3) |
| Host-side proxy socket | Mode inherits umask (typ. 0755) | Mode `0700` post-bind (W1.2) |
| Vsock proxy port-forward | Any port allowed | Allowlist: `GUEST_AGENT_PORT` (5252) + `PORT_FORWARD_BASE..+65535` (W1.3) |
| Console log + daemon log | Mode inherits umask | Mode `0600` (W1.4) |
| Block device passthrough | `nix-store.img` attached as `/dev/vdb`; host doesn't mount it | Documented invariant: host shall never `mount` this file. Static-check in code review. |

### Inside the guest

| Surface | Today | Hardened |
|---|---|---|
| Service privilege model | All services run as uid 900 in shared `serviceGroup` | Per-service uid, per-service group, mode-0400 secrets (W2.1) |
| `/etc/{passwd,group,nsswitch}` | Tmpfs-writable at runtime | Bind-mounted read-only after init (W2.2) |
| Service launch privileges | busybox `su -s sh -c …` | `setpriv --no-new-privs --bounding-set=-all --groups=<gid>,900` (W2.3) |
| Per-service syscall filtering | None (default tier `unrestricted`) | Default tier `standard`; per-service overrideable (W1.1, W2.4) |
| Rootfs integrity | None | dm-verity over the read-only ext4 lower layer; root hash on cmdline (W3.1-W3.4) |
| Capabilities | Inherited bounding set | Empty bounding set per service (W2.3) |

### Supply chain

| Surface | Today | Hardened |
|---|---|---|
| Pre-built dev image | HTTPS download, no integrity check beyond TLS | SHA-256 verified against const compiled into mvmctl (W5.1) |
| Cargo deps | No audit | `cargo-deny` + `cargo-audit` in CI; pre-commit local check (W5.2) |
| mvmctl binary reproducibility | Not verified | Double-build hash check in CI (W5.3) |
| SBOM | Not emitted | CycloneDX SBOM attached to releases (W5.4) |
| nixpkgs trust | `cache.nixos.org` trusted via `trusted-public-keys` | Inherited assumption; documented but not changed |
| Linux builder SSH | `sudo cp` writes `/etc/ssh/ssh_config.d/200-linux-builder.conf` | Documented; user-level prompt before sudo |

## Decisions

The following are decided and committed for v1 of this hardening:

1. **Defaults must be safe.** Every option whose value affects security
   defaults to the safer choice, and users opt *out* with documentation.
   No more `seccomp = unrestricted` defaults; no more `0755` socket
   defaults.

2. **Defense in depth, not a single chokepoint.** The vsock-only claim
   stays load-bearing, but every layer beneath it is also tightened.
   A failure in any one layer must not be catastrophic.

3. **Verified boot is mandatory for production microVMs.** The dev VM
   is exempt because its overlay-upper write layer can't compose with
   dm-verity; that exemption is named explicitly so the dev VM is
   never used as a "production microVM" by accident.

4. **The guest agent does not run as root in production.** Period. It
   doesn't need to, and the day-zero exploit cost of "uid 0 + buggy
   deser" is too high to keep paying.

5. **CI gates the security claims.** Every claim made in this ADR is
   backed by a CI check that fails the build if the claim is no
   longer true. Specifically: `cargo-deny`, `cargo-audit`, the `do_exec`
   symbol grep, the seccomp regression test, the proxy-socket perm
   test, the verity round-trip test, the bind-address test. Listed in
   plan 25 §W6.

6. **The threat model is documented and lived-with.** A malicious host
   is out of scope. Multi-tenant guests are out of scope. Hardware-
   backed key attestation is out of scope. These limits are in the
   ADR so we don't accidentally commit to defending against them.

## Per-backend tier matrix

mvm ships four VM backends (+ a test-only mock) — Firecracker, libkrun,
vz, and QEMU — each with different layer coverage. A given user run
carries the tier of its active backend, not the strongest tier the
project supports. The following matrix is what `mvmctl doctor` reports
and what the mvm-cli startup banner surfaces (loudly, when the active
backend falls below Tier 1). Plan 177 consolidated the former
8-backend set: Docker and Cloud Hypervisor were deleted in Phase 1,
microvm.nix folded into the QEMU backend, and the in-process
Apple-Container backend folded into the supervisor-model `vz` backend
in Phase 2.

| Backend | L1 | L2 | L3 | L4 | L5 | Notes |
|---|---|---|---|---|---|---|
| Firecracker (Linux + KVM) | ✅ | ✅ | ✅ | ✅ | ✅ | **Tier 1** — full ADR-002. All seven claims hold. |
| HVF / Hypervisor.framework (macOS 26+ Apple Silicon) | ✅ HVF | ✅ | ⚠️ no verified boot yet | ✅ | ✅ | Tier 2 — the in-house Hypervisor.framework VMM (Plan 214). vsock-only guest I/O: claim-10 egress is enforced through a per-VM gating endpoint over vsock — no gvproxy/vmnet, no guest NIC. Same `Hypervisor.framework` primitive as libkrun/Vz. Claim 3 partial (dm-verity targets Firecracker today); claims 1, 2, 4, 5, 6, 7 hold. **The macOS 26+ Apple Silicon auto-default** (`auto_select` picks HVF). |
| Vz / Virtualization.framework (macOS 13+) | ✅ HVF | ✅ Vz (Apple-controlled API surface on top of HVF) | ⚠️ no verified boot yet | ✅ | ✅ | Tier 2 — the single AVF backend (the former in-process Apple-Container path folded in here, Plan 177 Phase 2). Same `Hypervisor.framework` primitive as libkrun, smaller Apple-controlled API surface, balloon + snapshots. Claim 3 partial — dm-verity pipeline targets Firecracker today; claims 1, 2, 4, 5, 6, 7 hold. Opt-in on macOS via `--builder vz` / `--hypervisor vz`, and **sunsetting** in favor of the HVF backend (above) — no longer the macOS-26 auto-default. |
| libkrun / libkrun (Linux KVM, macOS HVF) | ✅ | ✅ | ⚠️ no verified boot yet | ✅ | ✅ | Tier 2 — claim 3 partial; comparable VMM TCB to Firecracker; the macOS 13-25 default and the Linux-without-KVM fallback per ADR-013. |
| QEMU (Linux KVM/TCG) | ✅ KVM | ⚠️ QEMU TCB much larger | ⚠️ partial verified boot | ✅ | ✅ | Tier 2 — claim 3 partial; QEMU's larger device model raises L2 audit cost. **Dev/test only** (Plan 166, was microvm.nix): selected by `mvm` for a Linux dev/test loop, never by `mvmd` — it carries no untrusted multi-tenant workload, so claim-10 egress enforcement is deliberately *not* wired into its start path (see the egress-enforcement note below). |
| `wasm-sandbox` (browser / WASI) | ❌ | ❌ | ❌ | ❌ | ❌ | **Off the isolation scale** (ADR-069). A portable backend for browser/wasm demos and previews (real WASI execution is deferred — Plan 144) — no KVM, no real kernel, no TAP/virtio/vsock. Asserts **none** of the numbered claims, declares its own non-virtualization honestly (`hardware_virtualization=false`), and fails closed on any kernel/TAP/vsock request. Opt-in only (`--hypervisor wasm-sandbox` / `browser`); `auto_select()` never returns it. See the Tier-0 preview note below. |

**Tier discipline**: Tier 1 is the production default and the only
tier that carries the *full* ADR-002 promise. Tier 2 carries six of
the seven claims with claim 3 (verified boot) tracked as a follow-up
once verified-boot lands for VZ/HVF. There is no Tier 3 anymore — the
only Tier-3 backend was Docker (a shared-kernel container that held
none of the L1–L3 isolation claims), and it was deleted in Plan 177
Phase 1 along with its auto-select warning banner. mvm refuses to
launder a container as a microVM, so no shared-kernel runtime ships.

`mvmctl doctor` (plan 40 folded the standalone `security` verb into
doctor) renders this matrix per-host with the active backend
highlighted.

**Claim-10 egress enforcement coverage (Plan 123 Phase A).** Claim 10's
default-deny egress is enforced at the host-side network chokepoint of the
two backends that run untrusted workloads: **Firecracker** via the nftables
`SupervisorEgressEnforcer` / `install_default_deny` (a default-deny ruleset on
the TAP, with the per-tenant allow-list layered on by the L4 gate), and
**libkrun** via the gateway-bridge `PlanFlowPolicy` (a deny-by-default
flow-open gate derived from the admitted plan's resolved policy) composed with
the always-on `MandatoryDenyEgressScan` + per-tenant `L4PolicyScan` /
`DnsSinkholeScan` packet scans. Both derive the same posture from the same
`NetworkPolicy` through their respective seams. **QEMU is
intentionally excluded**: it is a `mvm`-only dev/test backend (Plan 166), never
reached by `mvmd`, so it carries no untrusted multi-tenant workload and there
is no admission flow to source a policy from — forcing `deny_all()` onto its
start path would simply break all egress for a local dev loop. If QEMU were
ever promoted to a workload-bearing tier, claim-10 would have to be plumbed
through its start path first (`VmStartConfig` carries no egress-policy field
today); that is a deliberate future decision, not a Phase A gap. This refines
the "Network policy enforcement at hypervisor level" non-goal below, which
predates Plan 123's host-side enforcement. As of ADR-083 (see
"Consolidated from ADR-083" below) this exclusion is **type-enforced**: QEMU does not implement the
`WorkloadBackend` marker, so it cannot reach the admitted workload-launch
path at all — the carve-out is a compile-time constraint, not only prose.
(The mock backend implements the marker as the hermetic lifecycle test
double per ADR-045; it never carries a real workload.)

**Deny-all control-plane posture (DHCP/ARP).** A networked guest brings up
`eth0` at boot — link-up, then DHCP, then a static fallback on the gvproxy
subnet — before the agent drops privileges. Under a **deny-all** policy the
host-side flow gate drops *every* egress flow, and DHCP (UDP 67/68) is an egress
flow, so the guest's DISCOVER never reaches the gateway and no lease is offered.
The decision is **loopback-only, with no control-plane carve-out**: deny-all
means deny-all, including DHCP. This does not hang the guest — `udhcpc` runs with
`-n` (exit if no lease) and the guest then self-assigns the static gvproxy
fallback address, so `eth0` is administratively up but has no admitted egress;
only loopback and the (egress-denied) local link are usable. ARP / IPv6-ND are
non-IP L2 frames the bridge forwards unchanged (it gates IP 5-tuples, not L2);
they reach only the local gateway and admit no IP egress, so they are harmless
under deny-all and need no special handling. A *minimal DHCP/ARP carve-out* was
considered and rejected: the static fallback already keeps `eth0` up without one,
and a UDP 67/68 allowance would be one more flow-gate special case (and, if
scoped to "anywhere", a covert-channel surface) for no functional gain. When the
policy admits egress (allow-list / unrestricted) the flow gate opens and DHCP
flows normally. This is pinned by
`bare_deny_all_drops_dhcp_discover_through_the_live_bridge`.

**Tier-0 preview substrate (a naming bridge).** The `wasm-sandbox` backend
above asserts none of the numbered claims by design, so it sits *outside* the
Tier 1/2 isolation scale rather than below it — there is no "Tier 3" to demote
it to (Docker held that slot and was deleted). ADR-069 (proposed) builds a
dev-preview workflow on this backend and refers to it as the **Tier 0**
preview tier — "Tier 0" there meaning *zero production claims asserted*, not a
rung on the ascending-is-weaker scale used here. The two names describe the
same substrate; the threat-model framing is what makes the absence of claims
safe: Tier 0 is **single-principal** — a developer's own code running in their
own browser sandbox, endangering only themselves (adversary class 1's
"malicious *guest*" does not apply when the guest author and the only party at
risk are the same person). No production isolation claim is asserted or
needed. Promotion to a real, claim-bearing microVM does **not** lift the
preview's running state; it re-materializes the workload from recorded intent
through the audited build + admission pipeline (the claim 8 admission path,
claim 11 sealed deps, and claim 3 verified boot where the target backend
supports it), so nothing produced in a no-claims tier carries authority into a
claim-bearing one. The moment a `wasm-sandbox` host serves *more than one*
principal, this single-principal justification lapses and it would need to run
inside a real microVM — a requirement ADR-069 (proposed) would impose, not a
property enforced by this backend today.

## Consequences

### Positive

- The vsock-only claim becomes one of seven enforced claims, each with
  CI evidence.
- The dev VM's "trust mvmctl entirely" model is now an *explicit choice*
  the codebase makes, not a side-effect of missing layers.
- New contributors get a clear story: "here's what mvm protects against,
  here's what it doesn't, here's how each protection is enforced."

### Negative / accepted costs

- The production guest closure grows by ~1.5 MB to include
  `pkgs.util-linux` (for `setpriv`/`runuser`).
- dm-verity adds a second VirtioBlk device per VM and a few hundred
  ms to first-boot setup.
- `cargo-deny`/`cargo-audit` in CI will occasionally block merges on
  upstream advisories. This is the *point*; we accept the friction.
- Per-service uid means existing example flakes need a one-line audit
  to confirm they don't rely on the shared `serviceGroup` for cross-
  service file sharing. (None observed today.)

### Explicit non-goals

- **Malicious host defense.** Out of scope. Documented.
- **Multi-tenant guests.** Out of scope.
- **TPM/SEV/attestation.** Out of scope for v1.
- **Network policy enforcement at hypervisor level.** The
  `network_policy` field exists in `mvm-core` and the seccomp tier
  filters network syscalls, but the hypervisor itself doesn't enforce
  guest egress destinations beyond NAT vs. tap. *Superseded for the
  workload-bearing backends by Plan 123 Phase A* — egress is now
  enforced at the host-side network chokepoint (Firecracker nftables
  default-deny + libkrun gateway-bridge `PlanFlowPolicy`/scans; see the
  claim-10 egress-enforcement note under the per-backend tier matrix).
  Still a non-goal for the dev/test-only QEMU backend.

## Reversal cost

If a later decision wants to undo a layer (e.g. roll back per-service
uid because of a use case we didn't foresee):

- W1 items are one-line patches; trivially reversible.
- W2 items change the init contract; reversal requires a flake-API
  version bump because user flakes can become uid-aware.
- W3 (verity) is the biggest commitment; reversing means dropping the
  "rootfs integrity" claim from the security posture, which would
  warrant its own superseding ADR.
- W4-W5 items are CI/test additions; trivially reversible if they
  prove too noisy.

## References

- Plan: `specs/plans/25-microvm-hardening.md`
- Plan: `specs/plans/53-cross-platform-roadmap.md` (per-backend tier discipline)
- Related ADRs: `001-multi-backend.md`, `public/.../adr/001-firecracker-only.md`
- User-facing version of the layer model: `public/src/content/docs/security/matryoshka.md`
- Surface enumeration came from this session's audit; the seven
  numbered "additional surfaces" beyond the eight in the existing
  posture document are folded into the table above.
- The "matryoshka" framing draws on the 2026 microVM ecosystem
  discourse (e.g. <https://emirb.github.io/blog/microvm-2026/>);
  the same defense-in-depth pattern is used across the
  production microVM / hardened-isolation ecosystem.

## Appendix: Cardoso minimum-viable-policy checklist

Maps Cardoso's five-bullet "minimum viable policy" from
[A field guide to sandboxes for AI][cardoso] (2026-01-05) to mvm's
posture against the 13 CI-enforced claims in §"The CI-enforced
claims." Source-of-truth gap analysis at
[`specs/research/sandboxes-for-ai-cardoso-gap-analysis.md`](../research/sandboxes-for-ai-cardoso-gap-analysis.md);
workstream tracker at
[`specs/plans/111-cardoso-gap-coordination.md`](../plans/111-cardoso-gap-coordination.md).

[cardoso]: https://www.luiscardoso.dev/blog/sandboxes-for-ai

| Cardoso bullet | mvm status | Mechanism / claim | Evidence |
|---|---|---|---|
| Default-deny outbound, then allowlist (or policy proxy) | **pass** | **claim 10** | `policy_default_is_deny_all`; `test_resolve_network_policy_default_is_deny_all`; `mvmctl up` warns on `unrestricted` policy with explicit env opt-out; libkrun/Vz `up` defaults to the gateway bridge and generated signed-policy bundles for non-deny egress. DNS / broker / vsock carve-out audit tracked in Plan 111 Workstream A. |
| No long-lived credentials; short-lived scoped tokens | **pass** | **claim 8** + **claim 13** | G4 validity window + nonce on signed `ExecutionPlan`; Plan 104 `host.secrets.v1` returns destination-bound, time-bound signed credentials; raw secret bytes never leave the supervisor's address space. |
| Workspace-only filesystem; no host mounts beyond explicit shares | **pass** | **claim 1** | Per-service uid; seccomp `standard`; setpriv `--no-new-privs`; read-only bind-mounts on `/etc/{passwd,group,nsswitch.conf}`. |
| Resource limits: CPU / memory / disk / timeouts / PIDs | **partial** | CPU + memory + disk wired; `ExecutionPlan.resources` scaffolded; `timeout_seconds` / `pid_limit` not populated | Plan 37 §3.3 to be extended; ADR-041 schema table to be amended (Plan 111 Workstream C). |
| Observability — log process tree, network egress, failures | **pass** | **claim 8** + **claim 10** + **claim 12** | Chain-signed `~/.mvm/audit/<tenant>.jsonl`; `mvmctl audit verify` exits non-zero on tampering; service-call entries via `audit_chain_contains_service_call_entries`. |

### Beyond Cardoso's minimum

Properties mvm enforces that Cardoso's framework does not ask for.
Listed here for the audit-cleanly reader.

| Property | mvm status | Mechanism / claim |
|---|---|---|
| Hermetic builds — host environment never influences artifact | **pass** | "No host Nix, ever" (CLAUDE.md); source-checkout builds never depend on mvm-published artifacts (ADR-046) |
| Signed admission-checked execution plans | **pass** | claim 8 |
| Signed re-verified content-addressed bundles | **pass** | claim 9 |
| Hash-locked, SBOM-bound, CVE-scanned, attested dependency volumes | **pass** | claim 11 (ADR-047) |
| dm-verity rootfs that panics on tamper | **pass** | claim 3 |
| Reproducibility double-build of host code | **pass** | claim 7 |
| Production guest agent ships without `do_exec` | **pass** | claim 4 |
| Host-side broker dispatch is binding-gated and audited | **pass** | claim 12 (Plan 104 / ADR-059) |
| No raw secret crosses the broker channel | **pass** | claim 13 (Plan 104 / ADR-067 / ADR-059) |

### Cardoso three-question summary

| Question | mvm answer |
|---|---|
| What is shared between this code and the host? | KVM `/dev/kvm` ioctls (Linux); Hypervisor.framework calls (macOS Vz / libkrun); vsock for control plane + brokered host services (binding-gated per claim 12); one explicit virtio-fs share per declared mount. Host filesystem is never ambient. |
| What can the code touch? | Whatever the signed `ExecutionPlan` admits: declared shares, declared egress allowlist (claim 10), declared volumes, declared `host.*` brokered services (claim 12 binding). No raw devices. No host process namespace. No host network namespace. |
| What survives between runs? | Volumes the plan declares persistent (sealed deps volumes are RO and hash-locked per claim 11). Everything else is ephemeral by default. Snapshot/restore on workload microVMs not yet exposed — see Plan 111 Workstream B. SDK workload hooks (`before_build` / `before_start` / `after_start` / `before_stop` in `crates/mvm-sdk/src/compile/hooks.rs`) shape what runs at launch, not what survives across launches. |

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
lives in `CLAUDE.md` §"Security model" and `specs/adrs/002-microvm-security-posture.md`)
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
| 1  | No host-fs access from a guest beyond explicit shares | fn:seccomp_allows_listed_denies_unlisted, ci:seccomp-functional, fn:validated_conversion_enforces_mount_allow_list, fn:dir_share_two_part_defaults_ro, fn:libkrun_refuses_read_only_virtiofs_share, fn:enforce_admitted_shares_refuses_unadmitted_or_mismatched | seccomp + setpriv (ADR-002 §W2) + user-volume allow-list / ro-default / admission-enforced shares (mvm-cli + mvm-backend) | Shipped |
| 2  | No guest binary can elevate to uid 0 | fn:set_no_new_privs, fn:virtiofs_mount_flags_keep_workspace_read_only | setpriv --no-new-privs + RO config binds (ADR-002 §W2.2) | Shipped |
| 3  | A tampered rootfs ext4 fails to boot | ci:verified-boot-artifacts | dm-verity + roothash on **block+ext4** backends — Firecracker + Option B (ADR-002 §W3, ADR-106); virtiofs-root is a dev-tier path with a weaker contract that does **not** witness this claim (ADR-107) | Shipped |
| 4  | The guest agent has no do_exec in production builds | ci:prod-agent-runentry-contract | ELF symbol contract (ADR-002 §W4.3) | Shipped |
| 5  | Vsock framing + supervisor-config JSON are fuzzed | ci:fuzz | cargo-fuzz (ADR-002 §W4.1/W4.2) | Shipped |
| 6  | The pre-built dev image is hash-verified | ci:hash-verify-tests, fn:download_runtime_overlay_rejects_checksum_mismatch | SHA-256 manifest (ADR-002 §W5.1) | Shipped |
| 7  | Cargo deps are audited on every PR | ci:cargo-deny, ci:cargo-audit, ci:reproducibility | RUSTSEC + deny.toml (ADR-002 §W5.2/W5.3) | Shipped |
| 8  | Every workload runs from a signed, audited ExecutionPlan | fn:synthesize_plan, fn:admit_for_run, fn:verify_audit_chain | Ed25519 + chain-signed audit log (ADR-041) | Shipped |
| 9  | Every published bundle is content-addressed and re-verified | fn:read_and_verify_bundle, fn:verify_plan_bundle | SHA-256 content-addressing (Sprint 52 W2) | Shipped |
| 10 | No untrusted workload reaches the network unless policy-admitted | fn:policy_default_is_deny_all, fn:run_net_default_is_deny_all | default-deny network policy (Sprint 52 W3) | Shipped |
| 11 | Every app-dep volume is hash-locked, CVE-scanned and SBOM-enumerated | ci:app-deps-audit, fn:verify_sealed_volume, fn:apply_install_gate | CycloneDX + pip-audit (ADR-047) | Shipped |
| 12 | Every host-side service binding is plan-gated and audited | fn:unbound_service_returns_not_bound, fn:service_call_rejects_unknown_envelope_fields | ExecutionPlan.services binding (ADR-059) | Shipped |
| 13 | No raw secret value crosses the broker channel | fn:encode_secret_env_cmdline_round_trips_pairs_as_single_token, fn:substitute | destination-bound signed credentials (ADR-067) | Shipped |
| 14 | OCI image provenance is recorded in the chain-signed audit log | fn:prod_pull_requires_digest_pin_before_network, fn:prod_run_image_requires_digest_pin_before_network | cosign + OCI digest (specs/claims/claim-10-oci-image-provenance.md) | Shipped |
| 15 | No interactive access to a sealed production microVM | fn:console_refused_on_sealed_image, ci:prod-agent-no-console, fn:prod_console_attachment_has_no_input | dev-image-only console + dm-verity + host accessible-gate + dev-shell-gated agent (Plan 165 WS-C, ADR-002 §W4.3 extension) | Shipped |
| 16 | Egress substitution keeps a raw secret off the guest, bound-only, no value in audit | fn:handed_placeholders_never_contain_the_secret_value, fn:substitution_endpoint_refuses_unbound_destination, fn:audit_chain_carries_no_secret_value | egress substitution leak-gate; reinforces claims 12+13 on the egress delivery (ADR-067, specs/claims/claim-egress-no-secret-to-guest.md) | Preview |

Row 16 is the egress-substitution leak-gate. Like claim 14 (OCI provenance),
it is registered here for witness machine-checking and tracked by its own doc
(`claim-egress-no-secret-to-guest.md`) at status `Preview`; promotion to a
numbered claim in ADR-002's source-of-truth table is a separate maintainer
decision. It does not restate or replace the broker rows 12/13 — those are the
shipped broker delivery; row 16 backs the same two invariants on the egress
substitution path.

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

## Claims (narrative)

# `specs/claims/` — public claim gating files

Each file under this directory records the lifecycle status of one
public security or capability claim. Files are consumed by
`xtask check-no-overclaim`, which scans repo text (README, public
docs, code comments, CLI help) for "guarded phrases" associated
with a claim and refuses to admit those phrases when the claim's
status is anything other than `Shipped`.

The intent is to prevent the docs/website/README from saying "we do
X" before the CI gates that prove X actually pass. Plan 74 W0 and
plan 75 W0 introduce this pattern; both plans use it to gate the
OCI ingest, network policy, and other surface that's not yet
production.

## File format

```markdown
---
claim: <kebab-case-id>
status: Planned | Preview | Shipped | Not-claimed
gated_phrases:
  - "phrase to refuse outside this file"
  - "another phrase"
exempt_paths:
  - "specs/**"
  - "CHANGELOG.md"
---

# Claim <N> — <human title>

<description of the claim, what it asserts, what CI gate ratifies it>
```

Fields:

- `claim` — stable identifier. Used in error messages.
- `status` — see below.
- `gated_phrases` — list of substrings to refuse outside this
  claim file (and any path in `exempt_paths`). Case-sensitive.
- `exempt_paths` — glob list of paths where the phrases are
  always allowed (this file, history, etc.). `specs/**` is the
  default exemption for design docs.

## Status semantics

- `Planned` — claim is on the roadmap; phrases blocked everywhere except `exempt_paths`.
- `Preview` — claim partially shipped; phrases blocked in user-facing surface (README, public docs, landing page, CLI help) but admitted in design docs and changelog entries.
- `Shipped` — claim has CI proof; phrases admitted everywhere.
- `Not-claimed` — claim is explicitly out of scope; phrases blocked everywhere.

Bumping status is a deliberate PR; it's how a claim transitions from "we plan to do this" to "we say in public that we do this."

## Compliance mapping

_Consolidated from `specs/compliance/`._

# GDPR — Mapping

**Status:** STUB. Filled out in Phase 9 of `specs/plans/60-mvm-libkrun-migration.md`.
**Last verified:** N/A (stub created 2026-05-07).
**Owner:** mvm + mvmd platform team.
**Scope:** the open-source `mvm` library + the hosted mvmd cloud (when offered to EU customers).

## Default posture: data-minimization-by-default

GDPR is largely operational (privacy notices, lawful basis, controller/processor agreements). The technical aspects mvm must support are limited to data minimization, right-to-erasure, and breach detection.

## Articles mapped to mvm capabilities (Phase 9 to fill)

### Article 5 — Principles of processing

- [ ] (TBD) Data minimization: PII redactor (ADR-020) reduces what's logged.
- [ ] (TBD) Storage limitation: snapshot retention policies (plan 60 §"Snapshots — first-class feature") + audit log rotation.
- [ ] (TBD) Integrity and confidentiality: encryption layers (ADR-027).

### Article 17 — Right to erasure ("right to be forgotten")

- [ ] (TBD) mvmd tenant deprovisioning uses mvm overlay erasure certificates signed by the host identity key (ADR-028).
- [ ] (TBD) LUKS keyslot revocation + zero-fill on volumes.
- [ ] (TBD) Snapshot DEK destruction (cryptographic erasure).
- [ ] (TBD) Per-tenant audit log entries retained as redacted-only or destroyed (configurable; legal-hold default keeps redacted forms).

### Article 20 — Right to data portability

- [ ] (TBD) `mvmctl snapshot export` produces a portable, signed bundle of the VM state.
- [ ] (TBD) `mvmctl audit export --tenant <id>` produces a portable, signed audit bundle.

### Article 25 — Data protection by design and by default

- [ ] (TBD) Default-deny network egress (ADR-017).
- [ ] (TBD) Encryption-everywhere (plan 60).
- [ ] (TBD) Opt-in telemetry only.

### Article 30 — Records of processing activities

- [ ] (TBD) Audit chain (ADR-019) provides authoritative records.
- [ ] (TBD) Per-tenant query: `mvmctl audit export`.

### Article 32 — Security of processing

- [ ] (TBD) Encryption (in transit + at rest) per ADR-027.
- [ ] (TBD) Pseudonymization where applicable (PII redactor's tokenization scheme).
- [ ] (TBD) Resilience (snapshot pool + supervisor restart).
- [ ] (TBD) Process for regularly testing (continuous fuzzing, reproducibility).

### Article 33 — Notification of personal data breach (to supervisory authority within 72 hours)

- [ ] (TBD) Operational; mvmd hosted cloud handles. mvm contribution: audit events (ADR-019) capture every flow and tool call, enabling reconstruction.

### Article 34 — Communication of breach to data subject

- [ ] (TBD) Operational; mvmd handles.

### Article 35 — Data Protection Impact Assessment

- [ ] (TBD) Operational artifact; templated alongside ADR-018, ADR-029.

## Cross-border transfer

- [ ] (TBD) Operational; mvmd's choice of relay servers (iroh) and storage regions impacts this. Out of mvm's scope.

## Data subject access requests (Articles 15-22)

- [ ] (TBD) `mvmctl audit export --tenant <id>` and `mvmctl snapshot export <id>` provide the technical primitives. mvmd hosted cloud wraps them in a self-service UX (post-launch).

# HIPAA Security Rule — Mapping

**Status:** STUB. Filled out in Phase 9 of `specs/plans/60-mvm-libkrun-migration.md`.
**Last verified:** N/A (stub created 2026-05-07).
**Owner:** mvm + mvmd platform team.
**Scope:** the open-source `mvm` library + the hosted mvmd cloud (when launched and only after a Business Associate Agreement is signed).

## Default posture: BAA-required

The hosted mvmd cloud will require a Business Associate Agreement before customers can store Protected Health Information. The mvm library itself is the substrate; HIPAA compliance is an operational property of a deployment, not the library.

This document maps each technical safeguard from 45 CFR §164.312 (the HIPAA Security Rule's Technical Safeguards) to the implementing artifact in the mvm codebase.

## §164.312(a) — Access Control

### (a)(1) — Unique user identification (Required)
- [ ] (TBD) Per-VM Ed25519 identity key (ADR-018)
- [ ] (TBD) Per-tenant signing key (mvm-plan)

### (a)(2)(i) — Emergency access procedure (Required)
- [ ] (TBD) mvmd tenant deprovisioning backed by mvm overlay erasure certificates (ADR-028)
- [ ] (TBD) Recovery key escrow (opt-in) — documented in plan 60

### (a)(2)(ii) — Automatic logoff (Addressable)
- [ ] (TBD) Session idle timeout (`mvmctl session timeout`) — Phase 7

### (a)(2)(iii) — Encryption and decryption (Addressable)
- [ ] (TBD) Volume LUKS encryption (Phase 2)
- [ ] (TBD) Snapshot AEAD encryption (Phase 2)

## §164.312(b) — Audit Controls

- [ ] (TBD) Chain-signed HMAC audit log (ADR-019)
- [ ] (TBD) Audit total-coverage test (`tests/audit_total_coverage.rs`)
- [ ] (TBD) Audit categories: cmd, lifecycle, secret, flow, plan, policy, key, host, audit
- [ ] (TBD) Audit shipping to remote sink (`audit-remote-sink` feature)

## §164.312(c) — Integrity

### (c)(1) — Mechanism to authenticate ePHI
- [ ] (TBD) dm-verity rootfs integrity (Firecracker tier)
- [ ] (TBD) AEAD authentication on snapshots
- [ ] (TBD) HMAC chain on audit log

## §164.312(d) — Person or Entity Authentication

- [ ] (TBD) Attestation chain (ADR-018)
- [ ] (TBD) mTLS at mvmd-agent ↔ mvm-hostd hop (ADR-027)
- [ ] (TBD) Ed25519 identity keys per VM

## §164.312(e) — Transmission Security

### (e)(1) — Integrity controls
- [ ] (TBD) AuthenticatedFrame on vsock (ADR-026)
- [ ] (TBD) Replay protection (nonce + monotonic timestamp)

### (e)(2)(i) — Encryption (Addressable)
- [ ] (TBD) iroh QUIC TLS 1.3 (ADR-027)
- [ ] (TBD) mTLS at hostd hop
- [ ] (TBD) X25519 ephemeral session keys for vsock (forward secrecy)

## Operational requirements (out of mvm's scope, in mvmd's)

The HIPAA Security Rule has Administrative and Physical safeguards (§164.308 and §164.310) that are operational by nature: workforce training, contingency plans, facility access controls, etc. These belong to the deployer (mvmd hosted cloud or self-hoster), not the mvm library.

The Privacy Rule (45 CFR §164.500-534) is similarly operational and out of scope here.

## Breach notification

§164.404 requires breach notification within 60 days. Implementation is mvmd's: the hosted cloud will integrate the audit log + flow events into its incident-response system. mvm's contribution is making sure the events are *recordable* (not making them, that's the operator's job).

# PCI DSS — Scope Statement

**Status:** STUB. Filled out in Phase 9 of `specs/plans/60-mvm-libkrun-migration.md`.
**Last verified:** N/A (stub created 2026-05-07).
**Owner:** mvm + mvmd platform team.
**Scope:** the open-source `mvm` library + the hosted mvmd cloud (when launched).

## Default posture: out of scope

**mvm and mvmd do not handle cardholder data.** The default posture is PCI **scope reduction**:

- Customers who run mvm/mvmd are expected to delegate payment processing to an external PCI-compliant processor (Stripe, Adyen, Braintree, etc.) at their application layer.
- The microVMs run customer code, but cardholder data should never enter them. Customers who attempt to do so are subject to their own PCI compliance burden — mvm/mvmd does not assist or certify.
- This stance is publicly documented; customers cannot claim our compliance posture on their behalf.

## Opt-in `profile = "pci"` template (Phase 7b — not on default path)

For the rare customer who insists on processing PCI inside mvm, an opt-in template is available with stricter defaults:

- [ ] (TBD) Mandatory LUKS volume encryption
- [ ] (TBD) No shared infrastructure across tenants
- [ ] (TBD) Mandatory L7 egress proxy with cardholder-data DLP rules
- [ ] (TBD) Audit log retention ≥ 1 year
- [ ] (TBD) Mandatory quarterly ASV scans (operational; documented in `specs/runbooks/pci-asv.md`)
- [ ] (TBD) Mandatory annual penetration test (operational)

**We do not certify the PCI profile.** The template provides the substrate; the customer retains end-to-end PCI responsibility.

## Why we don't pursue PCI certification ourselves

- mvm is a microVM library; the PCI scope of certifying it would extend to the entire deployment, which we don't control in self-hosted scenarios.
- The hosted mvmd cloud may pursue certification at the platform layer (post-launch decision).
- PCI certification is operational, not technical: most controls are about audit, vendor management, and incident response — implementable but not what mvm is trying to be.

## PCI DSS 4.0 requirements vs. mvm capability (Phase 9 to fill)

### Requirement 1 — Network Security Controls
- [ ] (TBD) Default-deny egress (ADR-017)
- [ ] (TBD) L4/L7 proxy mediation (ADR-017)
- [ ] (TBD) Per-tenant network isolation

### Requirement 2 — Secure Configurations
- [ ] (TBD) Hardened defaults (W1-W6 from sprint 42)
- [ ] (TBD) `safe-openclaw` template defaults

### Requirement 3 — Protect Stored Account Data
- [ ] (TBD) AES-256 LUKS volume encryption
- [ ] (TBD) AEAD snapshot encryption
- [ ] (TBD) PII redactor configurable for cardholder-data patterns (ADR-020)

### Requirement 4 — Protect Cardholder Data with Strong Cryptography
- [ ] (TBD) TLS 1.3 mandatory; rustls + iroh (ADR-027)

### Requirement 5 — Anti-Malware
- [ ] (TBD) Out of scope at the library level; deployment concern.

### Requirement 6 — Secure Software Development
- [ ] (TBD) ADR coverage; reproducibility; SBOM; cosign signatures

### Requirement 7 — Restrict Access (need-to-know)
- [ ] (TBD) Per-tenant policy bundles (mvm-policy crate)

### Requirement 8 — Identify Users and Authenticate Access
- [ ] (TBD) Attestation + identity keys (ADR-018)

### Requirement 9 — Restrict Physical Access
- [ ] (TBD) Out of scope at the library level.

### Requirement 10 — Log and Monitor
- [ ] (TBD) Audit chain (ADR-019)
- [ ] (TBD) Metrics catalog
- [ ] (TBD) Audit retention via `audit-remote-sink`

### Requirement 11 — Test Security
- [ ] (TBD) Continuous fuzzing
- [ ] (TBD) Reproducibility check

### Requirement 12 — Security Policy
- [ ] (TBD) `SECURITY.md` + disclosure policy

# SOC 2 Type II — Controls Mapping

**Status:** STUB. Filled out in Phase 9 of `specs/plans/60-mvm-libkrun-migration.md`.
**Last verified:** N/A (stub created 2026-05-07).
**Owner:** mvm + mvmd platform team.
**Scope:** the open-source `mvm` library + the hosted mvmd cloud (when launched).

This document maps each SOC 2 Trust Services Criterion to the implementing artifact in the mvm codebase: a code path, a test, an ADR, or a CI gate. Auditors get a living traceability matrix; developers get a single source of truth for "what control does this PR affect."

## Trust Services Criteria mapping (to be filled in Phase 9)

### CC1 — Control Environment
- [ ] (TBD) Documented governance model
- [ ] (TBD) Code-quality controls (ADR-033)
- [ ] (TBD) Two-person review for security paths (CODEOWNERS)

### CC2 — Communication and Information
- [ ] (TBD) Audit log structure + chain-signed envelope
- [ ] (TBD) Customer-facing posture statement

### CC3 — Risk Assessment
- [ ] (TBD) Threat models per ADR (STRIDE tables)
- [ ] (TBD) AI-agent threat model (ADR-036)

### CC4 — Monitoring Activities
- [ ] (TBD) Metrics catalog coverage (plan 60 §"Comprehensive metrics catalog")
- [ ] (TBD) Audit total-coverage test (`tests/audit_total_coverage.rs`)

### CC5 — Control Activities
- [ ] (TBD) Encryption layers (ADR-027)
- [ ] (TBD) Access controls (mvm-policy)
- [ ] (TBD) Default-deny network egress (ADR-017)

### CC6 — Logical and Physical Access Controls
- [ ] (TBD) mTLS at hostd hop
- [ ] (TBD) Attestation chain (ADR-018)
- [ ] (TBD) Tenant isolation (cgroup, bridge, signing key per tenant)

### CC7 — System Operations
- [ ] (TBD) SLO commitments (plan 60 §"Reliability and SLOs")
- [ ] (TBD) Incident response runbooks (`specs/runbooks/`)

### CC8 — Change Management
- [ ] (TBD) ADR coverage gate (`xtask check-adr-coverage`)
- [ ] (TBD) Reproducibility double-build (Phase 9)
- [ ] (TBD) Cosign-signed releases (Phase 9)

### CC9 — Risk Mitigation
- [ ] (TBD) PII redaction (ADR-020)
- [ ] (TBD) Continuous fuzzing (Phase 9)
- [ ] (TBD) Vulnerability disclosure (`SECURITY.md`)

### Availability (A)
- [ ] (TBD) Per-VM crash rate target < 0.1%
- [ ] (TBD) Builder warm-pool 99.9%
- [ ] (TBD) Pause/resume correctness test

### Processing Integrity (PI)
- [ ] (TBD) Reproducibility check
- [ ] (TBD) Signed Plan protocol (ADR-018, mvm-plan crate)
- [ ] (TBD) Audit chain integrity

### Confidentiality (C)
- [ ] (TBD) Encryption at rest (LUKS, AEAD snapshots)
- [ ] (TBD) Encryption in transit (ADR-027)
- [ ] (TBD) Tenant destruction certificates (ADR-028)

### Privacy (P)
- [ ] (TBD) PII redaction (ADR-020)
- [ ] (TBD) Opt-in telemetry only
- [ ] (TBD) GDPR right-to-erasure via mvmd tenant deprovisioning and mvm overlay erasure certificates

## Threat model — host services broker (consolidated from specs/threat-models/)

# Threat model 02 — Host services broker over vsock

- **Status:** Proposed
- **Date:** 2026-05-27
- **Owner:** MVM Project
- **Related:** ADR-002 (this document, microvm security posture), [ADR-059 host services broker (original two-process design, and the four-subprocess hardening supersession)](059-host-services-broker.md), [Plan 104 host services broker](../plans/104-host-services-broker.md), [ADR-067 secret substitution mechanism](067-secrets-subsystem-egress-substitution.md), [SECURITY.md (CVE response runbook)](../../SECURITY.md), [mvmd ADR-0023](../../../mvmd/specs/adrs/0023-mvmd-host-services-delegation.md), [threat model 01 — runtime baseline](01-runtime-baseline.md) (TBD)

This document is the STRIDE walk for the host services broker introduced by ADR-059 / Plan 104 and refined by ADR-059's four-subprocess hardening section (§"Consolidated from ADR-061"). The ADRs are the decision records (architecture, choices); this document is the structured-threat enumeration with mitigation cross-references into Plan 104's §Hardening posture (Layers 1–11).

## Scope

**In scope:**

- The four broker subprocesses (`mvm-broker`, `mvm-secrets-dispatcher`, `mvm-host-signer`, `mvm-audit-signer`) and their per-VM lifecycle.
- The vsock channel (ports 5300 + 5301) between the guest microVM and the host subprocesses.
- The per-VM UDS channels between the supervisor and each subprocess.
- The cross-VM path from the supervisor to mvmd-agent over iroh ALPN, with respect to the four services Plan 104 ships.
- The `ExecutionPlan.services` admission ceremony and audit chain entries it generates.

**Out of scope** (per ADR-002 and ADR-059):

- Physical attacks on the host (cold-boot DRAM, DMA via Thunderbolt/PCIe, chip-off, side-channel power analysis, unauthorized firmware flashing).
- Multi-tenant guests (one guest = one workload).
- Hardware-backed key attestation by the workload itself.
- Vulnerabilities in the hypervisor's vsock implementation (KVM `vhost-vsock`, Firecracker, libkrun, cloud-hypervisor, Apple `vz`) — these are dependency-CVE-managed per ADR-059 §"Dependency CVE surface".

## Adversary model

Three adversary classes, in order of decreasing access:

| Class | Description | Capabilities |
| --- | --- | --- |
| **G — Hostile guest** | A workload running inside a microVM (the primary adversary). Has full control over guest userspace; cannot break out of the VM. | Sends arbitrary bytes to vsock 5300 + 5301; receives responses; observes timing |
| **N — Hostile network peer** | A network attacker on the path between the supervisor and mvmd-agent. | Observes + tampers with iroh ALPN traffic (mitigated by mvmd identity pinning + TLS 1.3) |
| **I — Software insider** | An unauthorized human with shell access to the host as some Unix user. **Newly in scope** per ADR-059's §Threat model narrowing of ADR-002's "malicious host" clause (which remains true for *physical* attacks). | Executes arbitrary code on the host; cannot escalate to root if not already root; cannot perform physical attacks |

For each service below, the STRIDE table notes which adversary class the threat applies to in the **Adv.** column.

## Cross-cutting threats (apply to all services)

| ID | STRIDE | Adv. | Threat | Mitigation |
| --- | --- | --- | --- | --- |
| X-S1 | S | G | Guest spoofs another workload's session by forging session id | `AuthenticatedFrame` Ed25519/P-256 verify under per-workload session key (minted at admission, discarded at workload stop); session id rotated per H-L4.3 |
| X-S2 | S | I | Insider runs a fake `mvm-secrets-dispatcher` binary | Cosign-verify at spawn (H-L3.1); TOCTOU-resistant verify-then-`fexecve` (H-L3.2); subprocess config signed under the same release key (H-L3.6) |
| X-S3 | S | N | mvmd-agent identity spoofed during initial bootstrap | mvmd public key pinned in `~/.mvm/keys/mvmd-pubkey`; admission refuses without pin (H-L6.4) |
| X-T1 | T | G | Guest tampers with response bytes before guest userspace consumes them | Out of scope at the broker boundary — guest controls its own userspace |
| X-T2 | T | I | Insider tampers with the audit chain JSONL on disk | `O_APPEND`-only FD held by `mvm-audit-signer` (H-L5.1); dir-immutable (`chattr +a` / `UF_APPEND`); `chain_head` persisted to a second location and verified by `mvmctl audit verify` (H-L5.2); per-tenant AEAD encryption at rest (H-L5.4) means insider sees only ciphertext |
| X-T3 | T | I | Insider tampers with the host signer key on disk | On enclave-equipped hosts (H-L2.1) the key never leaves the enclave; on non-enclave hosts (TOFU) the key file is mode 0600 + `chattr +i` once written + monotonic-counter (H-L2.2) detects rollback |
| X-T4 | T | I | Insider modifies a subprocess binary between cosign-verify and exec | TOCTOU-resistant mmap-then-`fexecve` (H-L3.2) narrows the window to a kernel syscall; subprocess refuses to start if its config signature doesn't verify (H-L3.6) |
| X-R1 | R | G | Guest denies having made a call later | Every dispatch — allowed or denied — emits a chain-signed audit entry with `(service, verb, outcome, correlation_id)` (Plan 104 §Audit chain); audit chain is JCS-canonical and chain-signed (H-L5.1+H-L5.2) |
| X-R2 | R | I | Insider operator denies having taken a privileged action | Operator actions (`mvmctl services revoke`, `mvmctl host-key rotate`, `mvmctl up --insecure-host`) emit chain-signed entries via `mvm-audit-signer` (H-L6.1) |
| X-I1 | I | G | Guest reads bytes from another workload's UDS path | Per-VM UDS paths under `~/.mvm/vms/<vm>/services/` with mode 0600; supervisor-owned (uid 0) — guest in the microVM never has host-side FS access regardless |
| X-I2 | I | G | Guest infers state from response timing | Rate limit applies to read-only services; `host.secrets.v1` pads to latency floor `BROKER_SECRETS_LATENCY_FLOOR_MS=5` (S26); per-workload total-call/minute budget escalates to `ServiceCallAbuse` audit |
| X-I3 | I | I | Insider reads audit log contents | Per-tenant ChaCha20-Poly1305 at rest, key derived from TPM/SE-bound master (H-L5.4) |
| X-I4 | I | I | Insider reads in-memory secrets from a running subprocess | Per-workload cgroup + PID/mount namespace (H-L1.4); `mlock` on secret-bearing pages (H-L3.9); `PR_SET_DUMPABLE=0` / `PT_DENY_ATTACH` + anti-debug startup check (H-L3.9, H-L3.11); seccomp denies `process_vm_readv` (H-L3.3) |
| X-I5 | I | I | Insider extracts host signer key from process memory | On enclave-equipped hosts: key never in process memory (H-L2.1). On non-enclave hosts: key in `mvm-host-signer` process only (H-L1.1), confined by the cgroup + namespace + seccomp + mlock stack |
| X-D1 | D | G | Guest floods broker with calls to exhaust CPU/memory | Per-`(workload_id, service_id)` token-bucket; in-flight cap; lifetime quota (S12); per-workload broker-CPU budget (`BROKER_CPU_BUDGET_MS_PER_MIN=50`); memory cap (`BROKER_INFLIGHT_MEM_CAP_BYTES=1048576`); bounded vsock receive queue (`BROKER_QUEUE_DEPTH=16`) (S6, S21) |
| X-D2 | D | G | Guest forces subprocess restart loop | 3-restart cap per workload lifetime; beyond → audit `<subprocess>.crashed_repeatedly` and workload pause (Plan 82 harness) |
| X-D3 | D | N | mvmd unavailable blocks cross-tenant cost queries | Circuit breaker per handler (S13); `host.cost.v1::tenant` returns `Err(Unavailable)` rather than stale data (R2 in mvmd Plan 52) |
| X-D4 | D | G | Guest exploits amplification attack (small request → large response) | Per-handler `response_size_cap()` default 64 KiB; `Err(ResponseTooLarge)` + audited (S11) |
| X-E1 | E | G | Guest exploits a parser bug in the schema gate to elevate within the subprocess | Frame size cap (64 KiB) enforced before parse; recursion cap 8; 50ms parse timeout; `serde_json` is the fuzzed parser (W6 `fuzz_service_call.rs`); subprocess address space is fully isolated from the supervisor's |
| X-E2 | E | G | Guest exploits a logic bug in the binding-gate to call an unbound service | Binding-gate refuses; `service_call_denied_when_unbound` regression test in W2 |
| X-E3 | E | I | Insider replaces a subprocess binary and waits for the next workload | Cosign-verify at spawn (H-L3.1) refuses tampered binary; Sigstore/Rekor transparency log (H-L8.1) exposes any secretly-signed builds |
| X-E4 | E | G | Guest triggers a use-after-free in the general broker that pivots into the secrets dispatcher | Out of scope of the pivot — the four subprocesses share zero address space (Layer 1). A UAF in `mvm-broker`'s parser cannot reach `mvm-secrets-dispatcher`'s grant table |

## Per-service threat walk

### `host.time.v1` (returns wall + monotonic time)

| ID | STRIDE | Adv. | Threat | Mitigation |
| --- | --- | --- | --- | --- |
| TIME-I1 | I | G | Wall clock leaks host's NTP-synced time, useful for cross-workload correlation | Considered low-impact; tenant-private fleets already correlate via mvmd. `host.time.v1` returns canonical UTC. |
| TIME-T1 | T | I | Insider moves host clock backward, making `mvm-audit-signer` log backdated entries | `audit.clock.jump_detected` audit emitted on negative jump (H-L5.5); audit timestamps anchored to TPM monotonic counter or kernel boottime |
| TIME-D1 | D | G | Guest spams `time/now` calls to consume broker CPU | Token-bucket per workload (X-D1) |

### `host.cost.v1` (workload + tenant verbs)

| ID | STRIDE | Adv. | Threat | Mitigation |
| --- | --- | --- | --- | --- |
| COST-S1 | S | G | Workload spoofs workload-id to read another workload's cost | `correlation_id` is supervisor-assigned (H-L4.6); supervisor passes workload-id from its own state, not from workload-supplied data |
| COST-S2 | S | N | mvmd response forged by network attacker | mvmd identity pinned (H-L6.4); TLS 1.3 + ChaCha20-Poly1305 + X25519 (H-L4.4); mvmd responses parsed with `deny_unknown_fields`; mvmd-signed catalog response (S23) |
| COST-I1 | I | G | `tenant` verb leaks cross-tenant data | mvmd-side tenant-scoped-authz (ADR-0008); supervisor refuses mvmd response if tenant_id ≠ workload.tenant_id |
| COST-I2 | I | G | Cost numeric values quantize-leak workload behavior to a multi-step attacker | Considered low-impact for v1; future plan may quantize values to coarse units |
| COST-D1 | D | N | mvmd slow → blocks broker thread | Per-handler call timeout (`host.cost.v1::tenant=150ms`); circuit breaker after 5 failures (S13) |

### `host.audit.v1` (workload-emitted audit entries — new in ADR-059's rescope)

> **Note.** This section replaces the previous `host.secrets.v1` table. `host.secrets.v1` and the entire `SECRET-*` threat set are dropped by ADR-059 (§"Consolidated from ADR-062"). `host.audit.v1` becomes the load-bearing workload-callable service in its place.

| ID | STRIDE | Adv. | Threat | Mitigation |
| --- | --- | --- | --- | --- |
| AUDIT-S1 | S | G | Guest emits an entry claiming a workload id it doesn't own (impersonation) | Handler refuses with `ServiceErrorCode::BadRequest` when entry's `workload_id` ≠ `ctx.workload_id`; supervisor-assigned `workload_id` (H-L4.6) is the authoritative source |
| AUDIT-S2 | S | G | Guest forges a `workload_audit` entry that looks like a `Admission` (system-asserted) entry | New `EventCategory::WorkloadAudit` variant is *distinct* from `Admission` and `ServiceCall`; `mvm-audit-signer`'s category allow-list pins the variant to the handler that produced it; `mvmctl audit verify` displays category alongside entry |
| AUDIT-T1 | T | G | Guest tampers with an emitted entry after signing | **Architectural impossibility:** chain entries are signed by `mvm-audit-signer` before append; tamper fails `mvmctl audit verify` per chain integrity (X-T2) |
| AUDIT-R1 | R | G | Guest denies having emitted a particular entry | Every `host.audit.v1` call emits a chain-signed entry with `(workload_id, correlation_id, ts, fields)`; the chain ties the workload id to the entry cryptographically |
| AUDIT-I1 | I | G | Entry leaks sensitive workload-internal state through `fields` | The chain entry's `fields` are workload-controlled — they can include whatever the workload chooses. Plan 104 §H-L5.6 (PII invariant) applies to *system-asserted* `correlation_id`s; workload-emitted `fields` are workload's responsibility. **Operator-facing tooling should display a privacy warning** when filtering by `WorkloadAudit` category. |
| AUDIT-D1 | D | G | Guest fills the chain with garbage entries to obscure forensics or exhaust audit storage | Per-handler rate limit (`BROKER_AUDIT_TOKENS_PER_SEC=20`); per-record cap (4 KiB); per-batch cap (100 entries / 256 KiB); per-workload lifetime quota (§S12); tenant-level cap (§H-L6.3); audit-log rotation policy (§H-L6.2) keeps chain bounded |
| AUDIT-D2 | D | G | Guest's `emit_batch` triggers `mvm-audit-signer` crash via malformed bytes | Per-record JSON schema validation in handler before batch forward; batch is rejected with `ServiceErrorCode::BadRequest` if any record fails. Audit-signer's own envelope parse (X-E1 equivalent) is the second line of defense |
| AUDIT-E1 | E | G | Guest exploits handler parser bug to inject a non-`WorkloadAudit` category entry | Handler signature pins `category = WorkloadAudit` literal at call-time; the category field is *not* forwarded from workload input. CI lint asserts the handler doesn't accept a workload-supplied `category`. Tested by `host_audit_v1_workload_cannot_set_category` |

### `broker.v1` (introspection: `list_services`)

| ID | STRIDE | Adv. | Threat | Mitigation |
| --- | --- | --- | --- | --- |
| BROKER-I1 | I | G | Guest enumerates services to discover unbound services and probe for them | Bindings are workload-supplied at admission; `list_services` returns only the workload's bound set. An unbound service is invisible. |
| BROKER-D1 | D | G | Guest spams `list_services` for amplification | Response size cap 64 KiB (S11); per-handler call timeout |

## Threats by adversary class — summary

**Hostile guest (G):** Capped by the five-rule capability gating (Plan 104 §"Capability gating") + per-handler `parse_payload` + token-bucket quotas + circuit breaker + latency floor + audit chain. The most credible escape path is a parser bug in `serde_json` exploited via the schema gate; W6 fuzz (`fuzz_service_call.rs`) closes this. A pivot from `mvm-broker` to `mvm-secrets-dispatcher` is architecturally impossible (Layer 1).

**Hostile network peer (N):** Limited to the mvmd path. Mitigated by TLS 1.3 + ChaCha20-Poly1305 + X25519 + mvmd identity pinning + signed catalog responses. The supervisor-to-subprocess UDS paths are not network-reachable.

**Software insider (I):** Newly in scope per ADR-059's four-subprocess hardening (supersedes its own original two-process design's threat-model boundary). The L1+L2+L5 hardening (key isolation + HW enclave + at-rest encryption + cgroup/namespace) means shell access yields neither the host signer key, nor the audit chain-signing key, nor the audit log plaintext, nor in-flight secrets. The remaining insider capability is "modify a subprocess binary on disk and wait for the next spawn," which is defeated by cosign-verify + Sigstore/Rekor transparency.

## Open issues / explicitly accepted residual risk

- **Non-enclave hosts retain TOFU posture for the host signer.** Plan 104 §H-L11.5 and ADR-059 §"Threat model" both acknowledge this. `mvmctl doctor` surfaces it as a downgrade row. Mitigation deferred to W8 hardware-enclave integration; software fallback retained for hosts without TPM/SE.
- **Single-tenant `mvm-audit-signer` per host.** All workloads on a host share the audit-signer subprocess (per-VM still, but one subprocess per VM). A `mvm-audit-signer` UAF affects all entries for that workload — mitigated by the audit-signer subprocess being minimal-code and security-reviewed.
- **`mvm-host-signer` is a single point of admission availability.** If down, no plans can be signed and no workloads can admit. Restart-with-backoff is the v1 mitigation; m-of-n quorum deferred. Documented operational behavior.
- **No alerting in v1 (G10).** Audit logs are forensics. Detection-time discovery of a compromise depends on downstream log-shipping which is out of scope.
- **No disaster recovery for lost keys (G11).** Lost host signer key = broken workloads with no recovery path. Future plan once W11 FIDO ceremony exists.

## See also

- ADR-059 (decision record) for architecture + claims.
- Plan 104 (implementation specifics) for build sequence + verification.
- ADR-002 (microvm security posture) for the broader trust model this narrows.
- ADR-067 (secret substitution mechanism) for the `host.secrets.v1` design.

## Runbook: W3 verified-boot verification (consolidated from specs/runbooks/w3-verified-boot.md)

# W3 verified-boot verification runbook

> Created: 2026-04-30
> Last updated: 2026-04-30 (full pass after initramfs fix)
> Parent plan: `specs/plans/27-w3-verified-boot.md`
> ADR: `specs/adrs/002-microvm-security-posture.md`
>
> **Status: ✅ all 5 steps PASS as of 2026-04-30.** The original
> Step 3 failure (Firecracker's aarch64 boot path auto-appends
> `root=/dev/vda ro` and last-wins clobbers `/dev/dm-0`) is fixed
> by an early-userspace verity initramfs that owns the boot pivot
> in userspace via `mvm-verity-init` + `switch_root`. The kernel-
> level `root=` setting is now irrelevant. Tamper test confirms
> the kernel panics with `data block N is corrupted`.

This runbook is the manual end-to-end verification for ADR-002 §W3
(verified boot via dm-verity). The `security.yml::verified-boot-artifacts`
CI gate covers the static-shape check; this runbook covers the live-
boot side that needs `/dev/kvm`, `firecracker`, and `veritysetup` —
all of which are present in the project's Lima dev VM (`mvmctl dev up`)
but not on a macOS host directly.

The whole runbook is mechanical: copy each block into
`limactl shell mvm-builder`, observe the expected signal, move on. Each step
is independently runnable so a partial failure is debuggable in
isolation.

## Prerequisites

Inside `limactl shell mvm-builder` (or any Linux/KVM host with the project
checkout at `$REPO`), confirm tooling:

```bash
ls -la /dev/kvm                    # crw-rw---- 1 root kvm 10, 232 …
which firecracker veritysetup nix  # all three on PATH
nix --version                      # ≥ 2.18 with flakes enabled
```

## Step 1 — Build, inspect artifacts, sanity-check the kernel

```bash
cd "$REPO"
out=$(nix build "./nix/default-microvm#packages.aarch64-linux.default" \
        --no-link --print-out-paths)

ls -la "$out"
# Expected: image.tar.gz, rootfs.ext4, rootfs.verity, rootfs.roothash, vmlinux

cat "$out/rootfs.roothash"
# Expected: a 64-char lowercase-hex string + newline

strings "$out/vmlinux" | grep -iE 'verity|dm-mod|device-mapper' | head
# Expected: matches for 'dm-verity', 'device-mapper', 'verity_algorithm',
# 'verity_mode', 'verity_version' — proves CONFIG_DM_VERITY=y took effect.
```

**Verified 2026-04-30**: store path
`/nix/store/rg208ijvys4vwfby3qmz7xs85bj347rs-mvm-default-microvm`
contained all four artifacts plus a 16 MiB Linux 6.1.169 aarch64
vmlinux with the expected verity strings.

## Step 2 — `veritysetup verify` round-trip

```bash
veritysetup verify \
    "$out/rootfs.ext4" \
    "$out/rootfs.verity" \
    "$(cat "$out/rootfs.roothash")"
echo "exit=$?"
# Expected: exit=0
```

**Verified 2026-04-30**: exit 0. The Nix-built sidecar matches the
ext4 it was built against, and the roothash produced by mkGuest is the
same one veritysetup recovers from the tree.

## Step 3 — Live Firecracker boot via the verity initramfs

The verity boot path uses the `rootfs.initrd` baked by mkGuest. The
kernel mounts the initramfs first, runs `mvm-verity-init` as PID 1,
which constructs `/dev/mapper/root` via DM ioctls, mounts it at
`/sysroot`, then `switch_root`s to the real init. The kernel-level
`root=` setting is irrelevant because the initramfs picks the real
root explicitly.

```bash
work=/tmp/w3-smoke
rm -rf "$work" && mkdir -p "$work"
cp "$out/vmlinux"        "$work/vmlinux"
cp "$out/rootfs.ext4"    "$work/rootfs.ext4"
cp "$out/rootfs.verity"  "$work/rootfs.verity"
cp "$out/rootfs.initrd"  "$work/rootfs.initrd"
chmod u+w "$work"/*

hash=$(cat "$out/rootfs.roothash")
python3 - <<EOF > "$work/config.json"
import json
boot_args = (
    "console=ttyS0 reboot=k panic=1 init=/init "
    f"mvm.roothash=${hash} mvm.data=/dev/vda mvm.hash=/dev/vdb"
)
print(json.dumps({
    "boot-source": {
        "kernel_image_path": "$work/vmlinux",
        "boot_args": boot_args,
        "initrd_path": "$work/rootfs.initrd",
    },
    "drives": [
        {"drive_id": "rootfs", "path_on_host": "$work/rootfs.ext4",
         "is_root_device": True, "is_read_only": True},
        {"drive_id": "verity", "path_on_host": "$work/rootfs.verity",
         "is_root_device": False, "is_read_only": True},
    ],
    "machine-config": {"vcpu_count": 1, "mem_size_mib": 256, "smt": False},
}, indent=2))
EOF

sudo timeout 30 firecracker --no-api --config-file "$work/config.json" \
    > "$work/fc.stdout" 2> "$work/fc.stderr"

grep -E 'mvm-verity-init|device-mapper:|switching to|/sysroot' "$work/fc.stdout"
```

**Expected** (verified 2026-04-30):

```
mvm-verity-init: starting
mvm-verity-init: data=/dev/vda hash=/dev/vdb roothash=…
mvm-verity-init: verity table = 419840 sectors, 209920 data blocks
mvm-verity-init: dm-ioctl kernel version 4.47.0
mvm-verity-init: DM_DEV_CREATE ok
[..] device-mapper: verity: sha256 using implementation "sha256-generic"
mvm-verity-init: DM_TABLE_LOAD ok
mvm-verity-init: dm-verity device active
mvm-verity-init: /sysroot mounted (verity-protected)
mvm-verity-init: switching to /init
[init] /etc/{passwd,group,nsswitch.conf} are read-only bind-mounts
```

The trailing `[init]` line confirms the real `minimal-init` script
reached userspace from the verity-protected `/dev/dm-0`. (Subsequent
warnings about missing config drives or `setpriv` flag conflicts are
unrelated to W3 — they're side effects of using the production rootfs
without the per-VM config/secrets drives.)

## Step 4 — Tamper-panic regression

Tampering inside the ext4 superblock guarantees verity sees the
corruption at first read (the kernel reads the superblock during the
initial mount). Picking a "deeper" offset gambles on that block
actually being read — verity is lazy, so a tampered byte that the
boot path never touches goes undetected. That's not a verity bug; it
just means the regression test has to point at a block ext4 is sure
to read.

```bash
# Restore from the unmodified store path before tampering.
cp "$out/rootfs.ext4" "$work/rootfs.ext4"
chmod u+w "$work/rootfs.ext4"

# Clobber 128 bytes inside the ext4 superblock at offset 1024.
dd if=/dev/urandom of="$work/rootfs.ext4" bs=1 count=128 \
   seek=1024 conv=notrunc

sudo timeout 15 firecracker --no-api --config-file "$work/config.json" \
    > "$work/fc-tamper.stdout" 2>&1
grep -E 'data block .* is corrupted|Kernel panic' "$work/fc-tamper.stdout"
```

**Verified 2026-04-30** — output:

```
[..] device-mapper: verity: 254:0: data block 1 is corrupted
mvm-verity-init: FATAL: mount(/dev/dm-0 → /sysroot, ext4): I/O error (os error 5)
[..] Kernel panic - not syncing: Attempted to kill init! exitcode=0x00000100
```

Verity returns `-EIO` for the corrupted read, the mount fails, PID 1
exits, and the kernel panics. The VM does NOT reach userspace.

## Step 5 — Dev-image exemption

```bash
out_dev=$(nix build "./nix/dev-image#packages.aarch64-linux.default" \
            --no-link --print-out-paths)
ls "$out_dev"
[ ! -f "$out_dev/rootfs.verity"   ] && echo "OK: no rootfs.verity"
[ ! -f "$out_dev/rootfs.roothash" ] && echo "OK: no rootfs.roothash"
```

**Verified 2026-04-30**: dev-image output contains
`image.tar.gz rootfs.ext4 vmlinux` only. The
`verifiedBoot = false` override in `nix/dev-image/flake.nix` is
correctly suppressing the verity sidecar.

## Findings

### Finding #1 (RESOLVED 2026-04-30) — Firecracker auto-appends `root=/dev/vda ro` on aarch64

**Resolution**: implemented option (2) below. mkGuest now bakes a
~250 KB cpio.gz initramfs at `rootfs.initrd` whose `/init` is
`mvm-verity-init` (a static-musl Rust binary). The initramfs runs
*before* the kernel commits to a root device, so Firecracker's
trailing `root=/dev/vda ro` becomes irrelevant — `mvm-verity-init`
constructs `/dev/mapper/root` via DM ioctls, mounts it, and
`switch_root`s explicitly. Live boot + tamper test both green.

**What**

Firecracker v1.14.1 on aarch64 unconditionally appends
`pci=off root=/dev/vda ro earlycon=uart,mmio,<addr>` to the kernel
cmdline regardless of what the API caller put in `boot_args`. With
verity in play, the cmdline ends up looking like:

```
root=/dev/dm-0 ro … dm-mod.create="…" pci=off root=/dev/vda ro earlycon=…
```

The kernel uses last-wins semantics for `root=`, so the user's
`root=/dev/dm-0` is silently overridden, and the kernel tries to
mount `/dev/vda` directly. dm-verity is constructed correctly but
never on the read path that matters.

**Why this matters**

The W3 implementation (`crates/mvm/src/vm/microvm.rs::configure_flake_microvm_with_drives_dir`)
sets `boot_args = "root=/dev/dm-0 ro rootwait init=/init {dm_create} {base_args}"`
when verity is on. The Apple Container path (`crates/mvm-apple-container/src/macos.rs`)
does the analogous thing. Both share the same defect: Firecracker's
auto-append (and presumably whatever the VZ code path does on macOS)
is not accounted for, so a verity-enabled production microVM still
boots off raw `/dev/vda`. Verity is initialized but doesn't gate
reads against the rootfs the running guest is actually using.

**Status**: ADR-002 §W3 claim (#3 — "a tampered rootfs ext4 fails to
boot") **does not yet hold in practice**. Static structure passes
(Steps 1, 2, 5 all green), the kernel constructs the verity device
correctly, but the cmdline plumbing means the kernel ignores the
verity-protected device and mounts the raw block device instead.

**Possible fixes** (in rough preference order)

1. **Drop our user-supplied `root=` and use a fixed dm name that the
   FDT default points at.** The dm-mod.create syntax accepts a
   `<name>` field; if we name the device so it ends up at
   `/dev/vda`, Firecracker's `root=/dev/vda` becomes the dm-verity
   target. Doesn't actually work — dm devices live under
   `/dev/dm-N` and `/dev/mapper/<name>`, not `/dev/vd*`.

2. **Use a tiny initramfs that does verity setup in early
   userspace, then `switch_root` to `/dev/mapper/rootfs`.** The
   initramfs runs `veritysetup open /dev/vda root <hash> /dev/vdb`
   and `exec switch_root /mnt /init`. This bypasses the
   cmdline-`root=` issue entirely because the kernel mounts
   the initramfs first and we choose the eventual root manually.
   Cost: an extra ~1MB artifact in the rootfs build, plus an
   initramfs builder in mkGuest. This is the typical real-world
   verity setup.

3. **Check if Firecracker has a knob to suppress the
   arch-specific cmdline append.** A quick look at v1.14.1
   source in `vmm/src/arch/aarch64/fdt.rs` shows the append is
   unconditional. A Firecracker feature request or patch is
   plausible but slow.

4. **Pre-process the boot_args so our `root=` is the LAST one.**
   Doesn't work — Firecracker appends after user input, not
   before.

5. **Use `root=253:0` (dm-0's major:minor) instead of
   `root=/dev/dm-0`.** Same problem: Firecracker still appends
   `root=/dev/vda ro` after, and last `root=` still wins.

The pragmatic path is **(2) initramfs**. It's well-understood, the
build cost is small, and it gives us full control over the boot
sequence without depending on Firecracker behavior.

**Action**: file as a follow-up under §W3 in plan 27 and gate the
ADR-002 claim #3 on it. Mark §W3 status as "host-side wired,
not enforcing — initramfs work outstanding" until this is closed.

### Finding #2 — `pkgs.cryptsetup` build is heavy on first build

`nix build .#default-microvm` on the Lima VM took ~30 minutes the
first time (it pulled and built `elfutils-0.194-dev` + a few other
non-cached deps). Cached build is fast. Document this in the
runbook so a first-time runner doesn't think the build is hung.

## Operator checklist

Before claiming the W3 boot regression passes, run all five steps
and check off:

- [x] Step 1: artifacts present + kernel has DM_VERITY strings.
- [x] Step 2: `veritysetup verify` exits 0.
- [x] Step 3: live boot mounts `/dev/dm-0` as root via verity initramfs.
- [x] Step 4: tampered ext4 panics in early boot (`data block N is corrupted`).
- [x] Step 5: dev-image build emits no verity sidecar.

All five green as of 2026-04-30. The runbook + the
`security.yml::verified-boot-artifacts` CI gate together provide the
technical receipt for ADR-002 claim #3 ("a tampered rootfs ext4
fails to boot").


## Consolidated from ADR-032 — Hosted-cloud invariants — no lock-in, metering precision, compliance-ready

## Status

Proposed. Invariants are enforced from Phase 0 (no hosted-cloud-only paths in mvm) through Phase 9 (compliance docs).

## Context

A future hosted, monetized mvmd P2P cloud is on the roadmap. We don't want to wake up at month 12 of the migration and discover the open-source library and the hosted product have diverged — that's both a license-compliance hazard and a vendor-lock-in trap that conflicts with the project's stated values.

Conversely, we don't want to under-invest in primitives the hosted cloud will depend on (precise metering, attestation, compliance docs) and pay a "hosted retrofit" tax later.

The right move is a small set of invariants the hosted cloud can rely on, enforced in mvm from day one of the migration.

## Decision

Five invariants. Every PR is reviewed against them.

### I1. No hosted-cloud-only code paths in `mvm` or `mvmctl`
The open-source library remains fully self-hostable. Anything specific to the hosted offering (e.g., Stripe billing, customer-tier-specific limits, hosted-only auth flows) lives in `mvmd` or higher. CI lint: grep for `cfg(feature = "hosted-only")` in mvm; fail if present.

### I2. Metering primitives are precise and tamper-evident
The metrics catalog (plan 60 §"Comprehensive metrics catalog") covers:
- Per-tenant CPU seconds, memory bytes, disk bytes, build seconds, egress bytes
- Per-tenant tool RPC counts (web_search, web_fetch, code_eval, …)
- Per-tenant snapshot bytes, snapshot count
- Per-tenant audit event count

Each metric is tied to a tenant_hash label (truncated SHA-256 of tenant_id; never raw tenant_id). Audit-logged on every read so dispute-resolution has an evidence trail.

### I3. Attestation is the basis of trust in hosted mode
In a self-hosted setup, attestation is good hygiene; in the hosted cloud, it's the basis of trust between customer and operator. Phase 6 implements attestation **at the strictness level the hosted cloud will require**, not a weaker dev-only version. mvmd may refuse unattested requests when running in hosted mode (a config flag, not a code fork).

### I4. Compliance docs are first-class artifacts
Phase 9 ships `specs/compliance/{soc2-controls,pci-scope,hipaa-mapping,gdpr-mapping}.md`. Stubs are created in Phase 0. Each compliance control maps to a test or ADR ID. CI checks doc staleness via timestamp on the "last verified" field.

### I5. Customer-facing data destruction is provable
`mvm` provides the overlay erasure primitive and destruction-certificate verifier; `mvmd` owns the customer-facing tenant lifecycle flow that invokes it. Certificates are signed by the host identity key so customers ending service get cryptographic proof their data was erased. This is a hosted-cloud requirement we choose to bake into the open-source substrate so self-hosters get it too.

## Consequences

**Positive**:
- Open-source library and hosted product never diverge silently.
- Compliance retrofitting later costs ~zero — the docs and primitives are already shipped.
- Customers (current and future) get a clean migration story off the hosted cloud if they want.

**Negative**:
- Some hosted-cloud-friendly shortcuts (e.g., baking in a default Stripe billing flow) are explicitly forbidden. mvmd takes the cost.
- Compliance docs are work overhead from day one; mitigated by template ADRs and table-of-contents-driven authoring.

## Alternatives considered

- **Build the hosted product first, retrofit the OSS later**: rejected. Retrofits never happen cleanly.
- **Build the OSS without hosted-cloud awareness**: rejected. Means month-12 retrofit of attestation, metering, destruction certificates — far more painful.

## Threat model impact

- I3 makes attestation a load-bearing security property in hosted mode. Threat model documented in ADR-018 (attestation chain).
- I5 is itself a security property: providing a proof-of-deletion has cryptographic guarantees attached. Documented in ADR-028 (tenant destruction).

## Compliance impact

- SOC 2: positive — I2, I4, I5 each map to specific Trust Services Criteria.
- PCI: neutral — these invariants don't add PCI scope; ADR-029 covers PCI specifically.
- HIPAA: positive — I3 (authentication via attestation), I5 (data deletion proof) align with §164.312.
- GDPR: positive — I5 satisfies right-to-erasure (Art. 17).


## Consolidated from ADR-063 — Boundary Language Policy

**Status**: Proposed
**Date**: 2026-05-28
**Cross-refs**: ADR-002 (security posture), ADR-060 (pid0 portability boundary), Plan 109 (guest control-layer dep-reduction + encryption design), Sprint 42 §Track E (Zig evaluation gates)

## Context

mvm's guest-side control surface (pid0 — agent, init, netinit, addon binaries) is Rust today, with a heavy transitive dependency tree at the boundary: `tokio`, `serde_json`, `ed25519-dalek`, `rtnetlink`, `seccompiler`, and hundreds of indirect crates. Sprint 42's Dependency Reduction Roadmap added a **Track E** that gates any Zig adoption behind two rules:

1. Do not introduce Zig for broad protocol-heavy replacements (`oci-client`, `pgp`) without a written tradeoff note covering native toolchain cost, cross-platform CI complexity, auditability, and risk reduction.
2. If Zig is evaluated at all, constrain it to narrow ABI shims or parser islands where the native surface is small and stable.

Track E names the gates but doesn't formalize them as a project-level policy. As Plan 109 runs the first concrete evaluation (a Zig vs lean-Rust-v2 A/B on `mvm-guest-netinit`), the team needs an ADR that the *next* contributor — or AI session — can consult without having to re-derive the discipline.

This ADR codifies the policy. It is deliberately framed broadly as "boundary language policy" — not "Zig policy" — so that the doc has value even if Plan 109's measurements reject Zig and the project stays Rust-only. The point is the rule, not the language.

## Decision

mvm's default boundary language is **Rust**. Adoption of any other language at the boundary requires evidence and is gated as below.

### 1. Default: Rust everywhere at the boundary

Every binary that runs in the guest's blast radius (pid0 control surface per ADR-060: init, netinit, agent, in-boot addons) and every host-side binary that participates in the audit chain or signs material is **Rust by default**.

The default is not negotiable case-by-case. Adopting a non-Rust binary requires the explicit process in §3.

### 2. First path for dependency reduction: lean Rust v2

Before considering a non-Rust language for any boundary binary, the team MUST evaluate whether the dep-reduction goal can be met within Rust. The "lean Rust v2" discipline:

- Replace `tokio` with `polling` + a small hand-rolled executor for binaries where async/await ergonomics are not load-bearing.
- Replace `serde_json` with hand-rolled per-variant parsers (or `nanoserde`) where the wire surface is small and stable.
- Replace `rtnetlink` / `netlink-packet-route` with `linux-raw-sys` + manual netlink for one-shot or narrow netlink usage.
- Replace heavy proc-macro derive chains with minimal-derive alternatives or inline implementations where reasonable.
- Existing precedent: `mvm-egress-proxy` (libc only, no tokio) demonstrates the discipline already shipping in this repo.

Plan 109's measurement framework (`specs/research/agent-evolution-tradeoff-note.md`) establishes the rubric for sizing this path. Subsequent dep-reduction proposals should use the same rubric so results are comparable.

### 3. Where non-Rust may be considered

Non-Rust languages MAY be proposed for boundary code only when **all** of the following hold:

- The binary has a **narrow ABI surface** (a small, stable set of syscalls or wire variants). Examples that qualify: a netlink-route installer, a virtio-vsock diagnostics probe, an ObjC/Swift bridge to a closed-source host framework (Apple Vz). Examples that do not qualify: anything with broad protocol stacks (OCI, PGP, OpenAPI, async runtimes).
- The binary is **not driving the audit chain**. Anything that emits to `~/.mvm/audit/<tenant>.jsonl` or computes/verifies signatures over `ExecutionPlan` material stays Rust. The audit chain is single-language by design (claim 8).
- The native language materially reduces the **supply-chain attack surface or boundary footprint**, with measurement evidence per Plan 109's rubric — not opinion.

Non-Rust languages MUST NOT be proposed for:

- Broad protocol stacks (OCI, PGP, OpenAPI, sigstore, OAuth, etc.).
- Async runtimes (`tokio` replacements). Building an event loop in another language is a workaround for "tokio is large" that re-creates the same async substrate without solving the underlying issue.
- Anything that interacts with the audit chain.
- Anything whose wire types are defined in `mvm-core` and shared across host/guest. The protocol stays Rust-canonical (Plan 109 §D2); any non-Rust implementation consumes a Rust-derived schema and round-trips byte-identically.

### 4. Required deliverables per non-Rust adoption

Any PR proposing a non-Rust boundary binary MUST include, before any prototype merge:

1. **Tradeoff note** in `specs/research/<topic>-tradeoff-note.md`. Template: `specs/research/agent-evolution-tradeoff-note.md` (Plan 109 W1). Symmetric analysis of the non-Rust path AND a lean-Rust-v2 alternative. Cover: toolchain cost, CI complexity, auditability, supply-chain surface comparison, maintenance/contributor-pool impact.
2. **Measurement comparison** with the lean-Rust v2 baseline against the rubric in Plan 109 W2/W2′. Primary metrics: dep-tree LoC reaching the boundary, transitive crate / module count + advisory exposure, stripped binary size, compile time, fuzz parity, reproducibility (claim 7), CI cost delta.
3. **Fuzz harness** equivalent to the existing `cargo-fuzz` targets covering the binary's parser surface. The non-Rust fuzzer must run in CI on the same PR cadence.
4. **Reproducible-build proof** — byte-identical rebuilds on `aarch64-linux` and `x86_64-linux` musl-static. Claim 7's invariant doesn't get a language carve-out.
5. **Supply-chain attestation** equivalent to `cargo-deny` / `cargo-audit`: a documented inventory of every external dependency (stdlib modules, compiler version, transitive includes) and a CI gate that fails on yanked / advisory-flagged inputs.
6. **Schema parity test** (per ADR-060 §8): the non-Rust binary consumes the Rust-canonical wire types and the build fails if the Rust types drift.

Each deliverable is **a CI gate**, not a discretionary review item. Without all six, the PR is not mergeable regardless of measurement outcome.

### 5. Reversibility

Any non-Rust boundary binary MUST be kept side-by-side with the existing Rust implementation until the non-Rust path is proven across at least one full release cycle. The default kernel cmdline path selects the Rust binary; the non-Rust binary is opt-in via flake option. This is Plan 109's I4 invariant generalized.

Adoption is then a separate PR that flips the default. Removal of the Rust binary is a *third* PR, no earlier than one release cycle after the default flip. The transition is irreversible only at that point.

### 6. Apple VZ ObjC/Swift shim — explicit carve-out

`mvm-vz-supervisor` (Plan 98 / ADR-056) uses Swift to bridge to Apple's closed-source Virtualization.framework. This is an existing exception that predates this ADR and is grandfathered. Any future Apple-framework integration MAY use Swift or ObjC under the same scoping discipline as §3 — narrow, framework-mandated, not part of the audit chain — but MUST still satisfy §4's deliverables.

## Consequences

**Positive:**

- Future contributors and AI sessions have a single document explaining when Zig (or any non-Rust language) is acceptable at the boundary. No need to re-derive the discipline from Track E plus folklore.
- The lean-Rust-v2 path becomes the explicit first move for any dep-reduction proposal, not a runner-up considered after a more exotic option.
- The six-deliverable bar (§4) makes prototype-to-adoption a measurable process, not a tribal-knowledge decision.

**Negative:**

- The deliverable bar may slow legitimate experimentation. Mitigation: tradeoff notes and prototypes can be authored cheaply (Plan 109 demonstrates this); only *adoption* requires the full bar.
- The schema-parity requirement (§3 "Rust-canonical types") forces hand-mirroring or codegen for any non-Rust implementation. Engineering cost is real and called out in Plan 109's analysis. Accepted.
- Codifies a status-quo bias toward Rust. This is intentional — the team is Rust-first and the audit chain is Rust-anchored. Lowering the bar would re-introduce the toolchain-tax compounding that Plan 109 §"Systems-design recommendation" specifically identifies as the strongest argument against multi-language sprawl.

**Neutral:**

- Does not retroactively bless or revoke any existing non-Rust code. The Vz Swift shim is grandfathered (§6); there is no other non-Rust code at the boundary today.
- Does not commit the team to evaluating any particular non-Rust language. Plan 109's Zig prototype is the first evaluation; nothing here commits to a second.

## Alternatives considered

**Alt 1: prohibit non-Rust at the boundary entirely.** Rejected because the Apple Vz Swift shim is load-bearing and the framework is closed-source. A blanket prohibition would either force re-implementation of Vz support in Rust (technically infeasible — Apple's framework requires Swift/ObjC) or block macOS Apple-Silicon support. A scoped policy is the workable middle.

**Alt 2: allow non-Rust freely, gate only by code review.** Rejected because boundary code reaches every microVM and supply-chain hygiene compounds. Discretionary review provides no consistent floor; the six-deliverable bar gives one.

**Alt 3: enumerate permitted languages (Rust, Zig, Swift) by name.** Rejected because it overcommits to today's set. The current text scopes by *constraints* (narrow ABI surface, not in audit chain, schema parity to mvm-core), which any future language candidate must satisfy. If a fourth language ever becomes a candidate, this ADR applies without amendment.

## References

- ADR-002 (microVM security posture, claims 1-10)
- ADR-060 (pid0 portability boundary — what the boundary binaries must do regardless of language)
- ADR-056 (Vz backend — grandfathered Swift shim, see §6)
- Plan 98 (Vz builder VM — Swift supervisor wiring)
- Plan 109 (guest control-layer dep-reduction + encryption design — this ADR is W4c)
- `specs/research/agent-evolution-tradeoff-note.md` (Plan 109 W1 — template for §4.1)
- `specs/SPRINT.md` Sprint 42 Track E (origin of the Zig evaluation gates this ADR codifies)
- `deny.toml` (existing Rust supply-chain policy this ADR generalizes)


## Consolidated from ADR-070 — Browser-reachable surface: verify, don't virtualize

**Status**: Accepted
**Date**: 2026-06-03
**Cross-refs**: ADR-002 (security posture — the signed/audited artifacts this verifies), ADR-041 (signed, audited execution plans — claim 8), ADR-014 (VmBackend single trait — the seam a wasm backend would *not* fit), Plan 33 (hosted MCP transport — mvm owns protocol, mvmd owns transport). Input: a comparison against a sibling browser-VM project that boots Linux in the browser via a RISC-V→wasm emulator.

## Context

A sibling browser-VM project runs full environments **in the browser**: a RISC-V RV64GC interpreter compiled to `wasm32`, booting an unmodified kernel, with a WebSocket relay for egress. The natural question for mvm was "should we grow an analogous browser capability?"

The answer turns on one distinction that is easy to miss. That project **emulates** a CPU; mvm **virtualizes** on real hardware (Firecracker/libkrun/Vz over KVM/HVF). You can ship a CPU emulator as wasm and run it in a tab. You **cannot** run KVM in a tab. So the headline browser-emulator capability — "boot the workload in the browser, serverless" — has no path into mvm's runtime model, and a `wasm`/emulator `VmBackend` is the wrong shape for the `VmBackend` trait (kernel path, ext4 rootfs, TAP, pause/resume, vsock — nearly all N/A; ADR-014). That dead end should be recorded so it is not relitigated.

What *does* transfer is the part underneath the emulator: **content-addressed, self-verifying artifacts that any peer can check by re-derivation, with no server to trust** (its Law L5 — `verify_kappa()`). mvm already produces exactly such artifacts — signed `ExecutionPlan`s, content-addressed bundles, and a chain-signed audit log (claims 8/9/14). Those are verifiable from bytes alone. That is the idea that maps cleanly onto mvm's strengths.

## Decision

1. **mvm will not pursue "run microVMs in the browser."** It is incompatible with hardware virtualization. No wasm/emulator backend.

2. **mvm grows a serverless, in-browser *verification* surface for its signed artifacts.** The first instantiation ships now: an audit-log verifier. `crates/mvm-verify` is a dependency-light, wasm-clean leaf crate that re-implements `mvm_supervisor::verify_audit_chain` against an in-memory `&str` + an Ed25519 public key; `web/audit-verify/` is a `#[wasm_bindgen]` shim + a static page. An operator drops a downloaded `<tenant>.jsonl` and the host signer's public key into a tab and gets a verdict — no host, no backend, nothing leaves the page.

3. **Verification cores must be wasm-clean leaf crates.** The browser surface may depend only on crates that compile to `wasm32-unknown-unknown` — no tokio/libc/rustix, no `mvm-supervisor`/`mvm-core` in the graph. `mvm-verify` depends only on `ed25519-dalek`, `sha2`, `base64`, `serde`, `serde_json`. Byte-exact parity with the native verifier is **pinned by a cross-crate test** (`mvm-supervisor`'s `mvm_verify_matches_supervisor_chain`): if the audit entry's serde shape drifts, CI fails there, not silently in the browser.

4. **The wasm artifact stays out of the main workspace.** `web/audit-verify/` is excluded from the Cargo workspace so `wasm-bindgen` and the `wasm32` target never enter `cargo build --workspace` or CI. Its logic is tested via the in-workspace `mvm-verify` crate; the page is built with `wasm-pack` (see `web/audit-verify/README.md`).

5. **Remote console/control stays in mvmd, not mvm.** A browser-reachable *console* (driving a live microVM remotely) is realistic — mvm's PTY-over-vsock console is a raw byte stream and `mvm-mcp` is already transport-agnostic — but the HTTP/WebSocket transport + tenant auth is fleet-orchestration territory, reserved for mvmd by Plan 33. mvm's obligation is only to keep the console byte-stream and the `mvm-mcp` protocol cleanly bridgeable, which they already are. This ADR does not add any host-side remote surface to mvm.

## Consequences

- A new, small, fully-tested crate (`mvm-verify`) that is independently useful: any Rust caller (CLI, mvmd, a future `mvmctl audit verify --stdin`) can verify a chain from bytes without the supervisor's heavy dependency graph.
- A serverless transparency tool: third parties can audit mvm's claim-8 log without running mvm or trusting a server — the strongest form of the "verify by re-derivation" property, applied to mvm's actual artifacts.
- The browser tool's correctness is guarded by a test in the security-critical crate, so the duplication (a mirrored `AuditEntry`) is drift-proof rather than hope-based.

### Follow-ups

- [ ] `mvmctl audit pubkey` — print the host signer's Ed25519 public key as hex, so operators have a first-class way to feed the verifier (today they must derive it from the keypair).
- [ ] Extend the verifier to **plan/bundle inspection** (`mvm_plan::verify_plan`, `read_and_verify_bundle` are already byte-oriented) — but only once `mvm-plan`'s graph is confirmed wasm-clean (it currently pulls `mvm-core`, which is not). May require lifting the pure verify path into a leaf crate, mirroring this ADR's pattern.
- [ ] If a hosted browser **console** is ever wanted, it is an mvmd effort (Plan 33), not mvm.

## Alternatives considered

- **A wasm/emulator `VmBackend`.** Rejected: wrong shape for the trait, and it would mean shipping a CPU emulator — a different product, not a backend.
- **Depend on `mvm-supervisor`/`mvm-plan` from the wasm crate.** Rejected: their graphs pull tokio/libc/rustix and do not compile to `wasm32`. Hence the leaf-crate rule (decision 3).
- **Re-derive the signed bytes via `serde_json::Value`.** Rejected: `Value` re-serializes object keys sorted, but the audit entry is signed in struct-declaration order, so a round-trip through `Value` would reorder keys and break every signature. `mvm-verify` mirrors the struct's field order and `skip_serializing_if` attributes instead, reproducing the signed bytes exactly.


## Consolidated from ADR-083 — Core security enforcement is a compile-time obligation on workload backends

**Status:** Accepted
**Amends:** [ADR-002](002-microvm-security-posture.md) (per-backend tier matrix — the workload / non-workload split becomes type-enforced rather than prose)
**Preserves:** all numbered claims; [ADR-004](004-hypervisor-egress-policy.md) and Plan 129 egress secret substitution (now a tracked compile-time obligation on macOS, not an optional follow-up)

## Context

`mvm` runs untrusted workloads across several backends behind the
`AnyBackend` enum. The cross-cutting security enforcement that backs the
claims — signed-plan admission, default-deny egress + flow audit, app-deps
seal, console lockdown, egress secret substitution — was applied in two
different ways:

- Some concerns run in a **shared funnel**: admission in the `up` launch
  path, the egress bridge in the per-backend supervisor, app-deps seal in
  the supervisor admission verifier. These apply to every workload backend
  uniformly.
- One concern, **egress secret substitution** (Plan 129), was hand-rolled
  as a free function (`spawn_substitution_endpoint`) called *inside*
  individual backends' `start()` methods — Firecracker and QEMU only.

Because nothing forced a backend to acknowledge that free function, libkrun
and vz silently never got it. The gap was invisible: a backend could be
fully wired for boot, admission, and egress *filtering* while missing an
entire security mechanism, and the type system was content. `BackendSecurityProfile`
(its `claims: [ClaimStatus; 7]` array) did not help — it is advisory, and
frozen at seven claims, so the substitution concern had no cell to be
missing from.

The lesson: a core security feature must not be expressible as *absent*
without a deliberate, visible decision. A declaration matrix that lets a
backend mark a core feature "unsupported" only *documents* the hole; it
does not prevent it.

## Decision

Introduce a marker trait and type-bar the admitted workload-launch path.

```rust
pub trait WorkloadBackend: VmBackend {}
```

- `FirecrackerBackend`, `LibkrunBackend`, `VzBackend` implement it. `mock`
  also implements it — it is the hermetic lifecycle test double (ADR-045)
  that stands in for a workload backend on the admitted path in tests and
  carries no real workload, so permitting it has no security cost. `qemu`
  (a real Tier-2 dev/test VMM) does **not** — it is the meaningful carve-out.
- `AnyBackend::as_workload_backend(&self) -> Option<&dyn WorkloadBackend>`
  converts via an **exhaustive match** — a new `AnyBackend` variant cannot
  compile without an explicit workload / non-workload decision.
- `require_workload_backend(&AnyBackend) -> Result<&dyn WorkloadBackend>`
  is the single boundary the admitted launch path runs; it refuses a
  non-workload backend before any VM starts.

The admitted launch arms in the `up` / `invoke` path call this guard before
dispatching, so a non-workload backend is refused, not launched.

This is the structural fix, not a capability matrix: a backend reaches the
untrusted-workload path only by being a `WorkloadBackend`, and the shared
funnel — not the backend — applies the cross-cutting enforcement. The lone
genuinely per-backend concern (the egress substitution *transport*, which
differs by backend mechanism) becomes a no-default `WorkloadBackend` method
in a follow-on phase, so it cannot be omitted either.

## Consequences

- **A new backend cannot reach the workload path silently.** It must either
  implement `WorkloadBackend` (and therefore the shared funnel applies) or
  be deliberately excluded — a visible, reviewable decision.
- **ADR-002's Tier-2 carve-out is now a type constraint.** QEMU's exclusion
  from claim-10 egress enforcement was previously prose ("dev/test only, not
  wired"); it is now enforced by types — `qemu` is not a `WorkloadBackend`,
  so it cannot be passed to the admitted launch path. (`mock` is permitted —
  the hermetic test double — but it never carries a real workload.)
- **Egress secret substitution on macOS becomes a required build.** When the
  substitution transport becomes a no-default `WorkloadBackend` method,
  libkrun and vz will not compile without implementing it. This reclassifies
  the macOS substitution port from an optional fast-follow to a compliance
  requirement. (The transparent :80/:443 terminator half entangles with the
  rvproxy migration — ADR-082 / Plan 193 — and is resolved by a design
  spike before implementation.)
- **`BackendSecurityProfile` stays advisory.** It continues to drive
  `doctor` posture output; it is no longer mistaken for the enforcement
  mechanism.

## Alternatives considered

- **Capability matrix + witness gate** (a `BackendCapabilityMatrix` with a
  `Supported`/`DeliberatelyUnsupported` cell per concern, plus an xtask gate
  asserting each `Supported` cell has a witness). Rejected: for a *core*
  feature, a `DeliberatelyUnsupported` cell documents a hole rather than
  preventing it, which is the opposite of the goal. The compiler forbids the
  actual failure (a missing implementation) for free.
- **Every backend enforces (close the Tier-2 carve-out).** Put the core
  obligation on `VmBackend` so even `qemu` must enforce egress. Deferred: it
  reopens ADR-002's settled Tier-2 decision and forces enforcement onto a
  dev/test backend that carries no untrusted workload. Recorded as a future
  option.
- **Shared launch funnel with a per-backend transport seam only
  (no-op-proofing).** Lift all enforcement into one pipeline so a backend
  cannot even supply an inert implementation. Deferred: a larger launch-path
  refactor; adopt only if inert seams prove to be a real problem (a witness
  gate is the cheaper escalation).

Implementation is sequenced in Plan 197.


## Consolidated from ADR-088 — Dev VM mutation promotion boundary: mutable dev state never implicitly feeds prod, and SSH-agent stays dev-tier only

**Status:** Accepted
**Relates to:** [ADR-002](002-microvm-security-posture.md) (prod vs dev posture),
[ADR-005](005-sealed-signed-builder-image.md) (declared-input trust model),
[ADR-041](041-signed-audited-execution-plans.md) (product ergonomics without
weakening the engine), [Plan 200](../plans/200-machine-ux-dx-layer.md) (machine
UX/DX), and [Plan 36](../plans/36-sealed-signed-builder-image.md) (dev vs prod
image posture)

## Context

Plan 200 adds a persistent dev-machine workflow on top of existing runtime
primitives: image-backed `machine create/start/exec/shell/stop`, `dev.init`,
volumes, and a future `ssh_agent` transport. That raises a boundary question:
if a developer mutates state inside a long-lived dev microVM, should later
production/prod builds be able to "see" those changes automatically?

The answer matters because mvm uses Nix and signed/admitted runtime contracts to
make production behavior reproducible and auditable. If a prod build can depend
on ambient mutable guest state, the system quietly regresses to "whatever
happened in the dev VM" instead of "declared source + config + artifacts."

The same question applies to SSH-agent authentication. ADR-002's "no SSH in
microVMs, ever" remains the stricter rule: forwarding an agent socket is not
permission to create an SSH session, install SSH clients or servers, bake SSH
configuration into a template, or mount/copy SSH key material. A forwarded
agent socket is a dev-tier host capability crossing into the guest and is
acceptable only on an explicitly local/dev tier, never on the sealed/prod path.

## Decision

1. **Mutable dev-VM state is not a production input.** A dev microVM is a
   mutable work surface only. Its rootfs mutations, ad hoc package installs,
   and `dev.init` side effects never implicitly flow into a prod/sealed build or
   runtime.

2. **Prod/sealed builds consume declared inputs only.** A prod build may depend
   on:
   - host workspace files and committed source;
   - declared config and lockfiles;
   - explicitly mounted host directories/volumes that are part of the build
     input model;
   - explicitly exported or promoted artifacts that re-enter the system as
     declared host-side inputs.

   A prod build may not depend on opaque live guest state.

3. **Promotion across the boundary is explicit.** If a dev workflow produces a
   change that should matter to prod, that change must cross the boundary as
   one of:
   - a host workspace edit;
   - an explicit sync/export from a dev volume back to the host;
   - a signed/exported artifact that later re-enters through an admitted input
     path.

   "It existed in the dev VM" is not itself a promotion mechanism.

4. **SSH-agent support is dev-tier only and does not authorize SSH sessions.**
   When implemented, `ssh_agent` means Unix-socket forwarding of
   `SSH_AUTH_SOCK` only. Private key files, `~/.ssh/`, host known-hosts
   material, SSH clients, SSH servers, and SSH config are never copied,
   mounted, or installed into guest templates. The feature is allowed only on
   an explicitly dev-tier machine/run posture and is refused on standard,
   sealed, or prod paths. Network/admission layers must still block SSH
   sessions; the agent socket is not a transport exception.

5. **Policy visibility is mandatory.** Whether a run/machine is using dev-only
   hooks such as `ssh_agent`, writable volumes, or `dev.init` must stay visible
   in dry-run, admission/audit, and receipts. The dev tier is not hidden behind
   convenience defaults.

## Consequences

- Prod builds stay reproducible and reviewable: the source of truth is host
  source/config/artifacts, not a mutable VM's leftover state.
- Dev workflows keep their ergonomics. A developer can still use a persistent
  mutable machine, but must explicitly promote anything that matters to prod.
- SSH-agent forwarding remains a narrow local-development feature without
  weakening the sealed/prod trust boundary or the project-wide SSH ban.
- Future features such as "sync back to host" or "export dev artifact" are
  allowed, but they must be explicit promotion verbs, not ambient leakage from
  guest state into prod inputs.

## Alternatives considered

- **Let prod builds read live guest state directly.**
  Rejected: breaks reproducibility, makes reviews/audit weaker, and turns
  "works in my dev VM" into an undeclared build input.

- **Disallow mutable dev machines entirely.**
  Rejected: too strict for the product goal. Persistent dev machines, `dev.init`,
  and future SSH-agent forwarding are useful, as long as their boundary to prod
  is explicit.

- **Support generic SSH by mounting keys, installing SSH clients/servers, or
  baking `~/.ssh/` material into templates.**
  Rejected: SSH sessions are banned by ADR-002, and host secret material must
  not cross the boundary. Agent-socket forwarding is the maximum acceptable
  dev-tier shape and does not permit an SSH session.

## Out of scope

- The concrete socket-forwarding transport for SSH-agent. This ADR sets the
  allowed posture and boundary, not the implementation mechanics.
- A particular host↔guest sync/export UX. This ADR requires explicit promotion
  but does not pick the final command shape.
- Changing the existing rule that prod/sealed machines reject dev-only hooks
  such as `dev.init`.

## References

- [Plan 200](../plans/200-machine-ux-dx-layer.md)
- [ADR-002](002-microvm-security-posture.md)
- [ADR-005](005-sealed-signed-builder-image.md)
- [ADR-041](041-signed-audited-execution-plans.md)
- [Plan 36](../plans/36-sealed-signed-builder-image.md)


## Consolidated from ADR-104 — Cloud control-plane trust boundary (multi-tenant superset of ADR-002)

- Status: Proposed
- Date: 2026-07-01
- Owner: MVM Project
- Related: ADR-002 (microVM security posture — the 15 claims, single-host scope), ADR-041 (signed audited execution plans — claim 8), ADR-059 (host services broker — claim 12 binding-gated dispatch), ADR-067 (destination/time-bound secret substitution — claim 13). Design input: `specs/notes/mvm-client-facade-design.md`, `specs/research/mvmd-cloud-readiness-assessment.md`.
- Sequenced by: cloud claim catalog + `two_org_isolation` witness (Task A, in `mvmd`); `mvm-client` facade Phase 2 (remote) is gated on this ADR being Accepted.

## Context

`mvm` (this repo) is the open-source, run-microVMs-locally product. `mvmd` (sibling
repo) is the paid, multi-tenant cloud where users *deploy* microVMs onto hosts we
operate. `mvm-studio` and — per the facade design — `mvmctl` reach **both**: a local
in-process path and a remote REST path to an `mvmd-gateway`, through one `MvmClient`
trait.

ADR-002 is the source of truth for the local security posture. Its threat model is
scoped, explicitly, to:

- a **single trusted local host** (the user owns the machine),
- **one guest = one workload** (no multi-tenant guests),
- **malicious host out of scope**.

The 15 CI-enforced claims all defend *that* boundary: a workload escaping onto the
*user's own* machine.

The cloud product **inverts every one of those assumptions**. We own the host; the
user is untrusted; **many** untrusted tenants share our hosts. The threat becomes
tenant→host and tenant→tenant escape — precisely the two items ADR-002 declares out of
scope (multi-tenant guests; an untrusted-host relationship from the tenant's view).

Introducing `mvmctl --remote <url>` also adds a **new actor** ADR-002 never modeled: a
remote control plane reachable over a network, with a network in between. A trait that
makes the local and remote calls look identical can hide that their security
*guarantees* are enforced by different authorities. That is a mental-model hazard, not
just a code one.

This ADR establishes the cloud tier's trust boundary as an explicit **superset** of
ADR-002, so "the cloud keeps every local guarantee, and adds the multi-tenant ones" is
a *checkable* statement rather than an aspiration.

## Decision

### 1. The cloud tier is ADR-002 plus a named set of multi-tenant claims

The 15 local claims remain necessary and continue to hold on the workload backends.
The cloud tier adds, at minimum:

- **CT-1 Cross-tenant isolation.** A principal scoped to tenant/org A cannot read or
  mutate any resource of tenant/org B — enforced on the request hot path *and* backed
  by a database-level fail-closed backstop (row-level security), so a forgotten
  handler check is not a breach.
- **CT-2 Admission under fleet authority.** Every deploy / lifecycle mutation is
  authorized by the control plane's policy engine before state change and recorded in
  the chain-signed audit log. (Mirrors claim 8, enforced by mvmd's authority.)
- **CT-3 Control-plane replay resistance.** Signed control-plane requests carry
  freshness (validity window + per-signer nonce) and are rejected on replay. (The
  `mvm-core` primitive for this is Task B; the reconcile-path wiring is mvmd's.)
- **CT-4 Per-tenant resource bounds.** A tenant's workloads cannot starve another's on
  a shared host — resource caps and/or placement isolation, per the co-location
  decision below.

The catalog is seeded here and owned as a living `specs/claims/catalog.md` in `mvmd`
(Task A). It is expected to grow (secret confidentiality across the boundary, egress
attribution, etc.); this ADR fixes the *discipline*, not the final list.

### 2. The trait unifies the call, never the trust

There are two authorities, and they are never silently merged:

- **Local path** — the authority is the local host, exactly as ADR-002 describes
  (host-signed `ExecutionPlan`, broker, local audit chain). `LocalBackend` runs the
  same `mvmctl` library over the same on-disk state.
- **Remote path** — the authority is `mvmd`. `GatewayBackend` is a **dumb courier with
  zero enforcement authority**: it presents credentials and ships intent; every
  security decision (RBAC, quota, admission, audit, rate-limit) is made server-side and
  the server treats the client as untrusted input regardless.

Security is therefore never a property of the transport the caller picked; it is
enforced at whichever authority owns that path. The facade must make the acting
authority observable, never present remote guarantees as if they were the local ones.

### 3. Key-domain separation

Local signing keys (`~/.mvm/keys/host-signer`) are the *local host's* authority and
must never be trusted by the fleet. The facade must not ship a locally-signed plan and
have `mvmd` honor that local signature — that is key-trust confusion. Remote DTOs carry
**intent**; `mvmd` re-admits and re-signs under its own fleet key. The shared wire
contract must not leak local signing material or host paths across the boundary. This
is a constraint on the DTO shapes, not only a runtime check.

### 4. Client-side rules are fail-closed

- **Prefer mTLS; require TLS.** HTTPS + cert validation by default; support the
  gateway's `require_client_cert` mode; **refuse plaintext to any non-loopback host**
  (the loopback sidecar is the only cleartext exception).
- **Ride the server's auth model exactly** — scoped bearer keys, honor expiry warnings,
  hard-fail on API-version skew. No bespoke client auth.
- **Credentials** — OS keychain (studio) or env var / mode-0600 file (CLI); never a
  token flag (leaks to `ps`/history); never logged; `zeroize` on drop; **endpoint-bound**
  so a token is never sent to a different `--remote` URL.
- **Untrusted-input hardening** — the shared DTOs are deserialized by the server from
  anyone with network reach: `#[serde(deny_unknown_fields)]`, size/depth limits,
  validation. Typed DTOs fail closed; today's `Result<Value>` surface does not.

### 5. Built is not wired: enforcement must fail CI when absent

A control that exists but is not on the request hot path with a passing witness is
treated as **absent**. Each cloud claim maps to a named test/CI gate (the mvm
claim→witness→gate discipline, ported to `mvmd`). This is a direct response to the
present state, where a production-grade IAM + RLS subsystem shipped ~100% built and ~0%
wired without turning CI red.

### 6. Sequencing

The `mvm-client` remote phase (`--remote` / mTLS / `GatewayBackend`) ships only once
this ADR is Accepted **and** cross-tenant enforcement (CT-1) is wired with a green
witness. Shipping a polished remote client over an unenforced authorization boundary
would make the insecure path easier to reach — the worst outcome.

## Threat model — new actors (relative to ADR-002)

In scope for the cloud tier, additional to ADR-002:

- **The network between client and `mvmd`.** Mitigated by TLS/mTLS, endpoint-bound
  credentials, replay resistance (CT-3), fail-closed client rules.
- **Other tenants on a shared host / control plane.** Mitigated by CT-1 (isolation +
  RLS backstop), CT-4 (resource bounds), and the co-location decision.
- **A tenant's untrusted workload versus the fleet host.** The ADR-002 guest-boundary
  claims (1–15) carry over unchanged and are the first line; multi-tenancy raises the
  blast-radius stakes but not the per-guest mechanism.

Still out of scope (named, deliberately):

- **A malicious `mvmd` operator / the host we operate.** We trust our own control-plane
  operators with the hypervisor and fleet keys, mirroring ADR-002's malicious-host
  exclusion. (Reducing this trust — confidential computing, hardware attestation — is a
  separate future ADR.)
- **Hardware-backed key attestation.** As ADR-002.

## Consequences

- "Same guarantees or stricter, in the cloud" becomes provable: the superset is
  enumerated and each element has a CI witness.
- The facade design gains a hard gate (§6): remote is not shippable until CT-1 is
  enforced, not merely designed.
- Honest current status at authorship: CT-1 is built (mvmd IAM + Postgres RLS) but not
  wired; CT-3's `mvm-core` primitive has landed (Task B) with the mvmd reconcile-path
  wiring outstanding; CT-2 is partial (prod-gated signature verify, no end-to-end
  gateway→agent signing); CT-4 is open (unrestricted co-location). This ADR does not
  claim these are done — it makes their absence a tracked, CI-visible gap.

## Alternatives considered

- **Keep ADR-002 as-is; handle cloud security ad hoc.** Rejected: there is then no
  checkable superset, and the built-≠-wired failure mode has nothing to make it red.
- **A separate cloud threat-model doc only, no ADR.** Partially adopted: a companion
  `specs/threat-models/` doc in `mvmd` may hold the long-form analysis, but the *trust
  boundary decision* belongs in the ADR ledger next to ADR-002 so the two are read
  together.
- **Make the trait fully uniform over local/remote, hiding the transport.** Rejected:
  uniformity of *interface* is good DX; uniformity of *apparent trust* is a hazard. The
  acting authority must stay observable (§2).

## Co-location decision (to resolve; drives CT-4 and unit economics)

Two honest options, called out so it is decided before more scheduler logic is built on
the current co-locate-freely default:

- **Dedicated node pools per tenant** — simplest, strongest isolation, lower density
  and thinner margins.
- **Hardened co-location** — denser and better economics, but defends the
  Firecracker/VMM boundary, network segmentation, and noisy-neighbor between untrusted
  tenants on shared silicon.

This is a product+security decision, not purely security; this ADR records it as the
open question gating CT-4 rather than pre-deciding it.


## Consolidated from ADR-108 — Verb-grant measured trust policy and the key-separation ceiling

- Status: Proposed
- Date: 2026-07-04
- Owner: MVM Project
- Related: ADR-002 (microVM security posture — trusted-host and hardware-attestation out-of-scope; claim 3 verified boot, claim 4 `do_exec`, claim 15 sealed interactivity), ADR-103 (plan-bound agent verb capabilities — the `VerbGrant` this ADR anchors), ADR-041 (signed audited execution plans — claim 8), ADR-090 (resident daemon trust gradient)
- Sequenced by: [Plan 215](../plans/215-plan-bound-agent-verb-capabilities.md) follow-on

## Context

ADR-103 delivered plan-bound agent-verb capabilities: a per-workload `VerbGrant`,
minted host-side, delivered to the guest on the kernel cmdline
(`mvm.verb_grant=<hex(VerbGrantEnvelope)>`), decoded by `/init` into
`/run/mvm/verb-grant.json`, pinned by the agent at boot
(`load_pinned_verb_grant`, `crates/mvm-guest/src/vsock.rs`), and enforced
subtractively after the class gate.

The `VerbGrantEnvelope` carries the grant **and** the verifying key
(`pubkey_hex`) in one blob. So the guest verifies the grant against a key
delivered by the same launcher, over the same channel, as the grant itself. The
in-tree comment states the limitation plainly: *"the verifying key rides in the
same launcher-provisioned envelope as the grant … NOT proof of an independent
issuer … A build-time-provisioned anchor is tracked."* That tracked item
(issue #1381 item 3) asked for "real cryptographic key separation via a
build-time trust anchor."

This ADR records the outcome of designing that anchor: **within ADR-002's scope,
real cryptographic key separation for the verb grant is not achievable**, and
states precisely why, what *is* achievable and valuable instead (a measured
trust *policy*), and the exact future path that would make key separation real.

## The ceiling: why in-scope key separation is not achievable

ADR-002 fixes two scope boundaries that jointly foreclose key separation here:

1. **The host is trusted.** mvmctl trusts the host with the hypervisor and the
   private build/signing keys. A "malicious host" is explicitly out of scope.
2. **No hardware-backed key attestation.** Explicitly out of scope.

Given these, consider every anchor the guest could verify the grant against:

- **Kernel cmdline** (today): launcher-provisioned, unmeasured by anything.
- **The `mvm-config` drive** (per-launch, `crates/mvm-backend/src/microvm.rs`):
  assembled by the host each boot, **no dm-verity sidecar, no roothash** —
  plaintext and unmeasured. Moving the key here is the same launcher-controlled,
  unmeasured channel as the cmdline: no gain.
- **A dm-verity-sealed rootfs file** (claim 3): genuinely measured and
  tamper-evident — **but the roothash is computed at *image-build* time** in the
  Nix derivation (`nix/images/runtime-overlay/flake.nix`), and at launch
  `probe_verity_sidecar` only *reads* the pre-baked roothash onto the cmdline.
  There is no per-launch re-seal. The **host-signer key is per-host and
  runtime-generated** (`~/.mvm/keys/host-signer.ed25519`, created on first
  `mvmctl` run — `host_keypair::load_or_init_at`), so it **cannot** be baked into
  a build-time-generic verity image: the key does not exist when the image is
  built.
- **A build-time key baked into the verity rootfs** could be measured, but a
  per-host runtime key cannot be *certified* by it: the release/build
  infrastructure never sees the host key, so no certificate chain from the
  build-time anchor to the host-signer key can exist.

Every anchor is therefore either (a) provisioned by the same trusted launcher
that provisions the grant (cmdline, config drive — no independence), or (b)
measured but build-time-generic and unable to carry the per-host key (verity
rootfs). Nothing measures the cmdline itself. The one construction that would
give a genuinely independent anchor — a launch-time key measured/attested by a
root the launcher cannot forge — requires hardware attestation (a vTPM / measured
boot quoting the launch key), which ADR-002 places out of scope.

Note also that the in-scope guest adversary — a **compromised guest workload**
attempting to escalate its own agent verbs — is already fully addressed by
*pinning timing*: the agent pins the grant at boot **before** any untrusted
workload runs, and the pinned value is immutable thereafter. Key separation adds
no defense against that adversary. The only residual value of an independent
anchor is defense-in-depth against a **trusted-but-buggy launch path**.

**Conclusion.** "Real cryptographic key separation for the verb grant" is a
non-goal under ADR-002. The delivered ADR-103 mechanism is, and remains,
**trusted-channel provisioning**: integrity over a launcher-provisioned blob,
rooted in kernel-cmdline provenance. It must **not** be promoted to the ADR-002
numbered claim ledger. This is the honest ceiling.

## Decision

Ship the achievable, non-theater improvement: make the guest's grant-trust
*policy* — not the key — **measured**, and make grant enforcement survive
restore. Concretely:

### 1. A measured `VerbTrustPolicy` baked into the sealed rootfs

A policy is **generic** (identical for every launch of an image), so unlike the
per-host key it *can* be baked at Nix-build time into the dm-verity-covered
rootfs. Define `mvm_core::plan::VerbTrustPolicy`:

```
VerbTrustPolicy {
    version: u32,                 // 1
    require_grant: bool,          // guest fails closed if a grant is required but absent
    grant_key_source: GrantKeySource,  // LaunchProvisioned (today) | Attested (future seam)
}
```

`mkGuest` bakes `/etc/mvm/verb-trust.json` into the rootfs. For **sealed prod
images** (`withDevShell = false`): `{ version: 1, require_grant: <staged, see
Rollout>, grant_key_source: "launch_provisioned" }`. For **dev / OCI images**:
the file is absent (⇒ no requirement — the permissive default is preserved).

### 2. Policy-driven guest enforcement (fail-closed code, staged bit)

At boot the agent reads the verity-measured `/etc/mvm/verb-trust.json` and acts
on it with a single code path:

- **No policy file** (dev / OCI) ⇒ no requirement; serve (permissive default).
- **Policy present, valid grant pinned** ⇒ serve.
- **Policy present, grant absent / malformed / verification-failed** ⇒ emit an
  **audited observability signal** ("verb-trust policy present but no valid grant
  pinned"), then fail closed **iff** enforcement is required. As shipped (see
  Rollout / Stage A), the enforcement trigger is `trust_decision(policy,
  grant_present, launch_requires_grant)`: fail closed when the launch asserts
  `mvm.require_grant=1` **OR** the baked `require_grant: true` **OR**
  `grant_key_source: attested`; otherwise serve (observe mode). Because Stage B/A
  bake `require_grant: false`, the enforcement in practice comes from the
  launch-asserted `mvm.require_grant=1` token (emitted only when the host
  delivered a grant), leaving mvmd / direct-launch instances in observe mode.

The fail-closed behavior is thus fully implemented in the guest from day one;
whether it *bites* is driven entirely by the measured `require_grant` bit. This
is the one genuinely valuable property: a sealed image's assertion *"I must run
under a grant"* is **dm-verity-measured** (claim 3), so a launch-path bug — or
tampering — that omits or corrupts the grant can no longer silently downgrade a
sealed workload to permissive class-gate-only operation. The *key* is still
launch-provisioned and honestly labeled `launch_provisioned`; only the *policy*
is measured.

An unexpected `grant_key_source: "attested"` (the future arm, not implemented
here) is treated as fail-closed, never a silent downgrade.

### Rollout (staged, to bound cross-repo risk)

`mkGuest` is shared: the sealed images it builds are also run by **mvmd** (the
separate fleet orchestrator), whose admission/launch/restore paths are not
verified by this work. Baking `require_grant: true` unconditionally could brick
an mvmd sealed workload whose launcher does not deliver a grant. Enforcement is
therefore rolled out in two stages, each a distinct PR:

- **Stage B (this ADR's implementation) — measure-now.** Ship the full mechanism
  with `require_grant: false` baked for sealed images: the policy type, the
  verity-measured file, the guest fail-closed **code path** (dormant at
  `false`), the audited observe signal, restore reconciliation, and the
  `grant_key_source` seam. Live-prove that every *mvmctl* sealed launch + restore
  flavor delivers a valid grant.
- **Stage A (shipped) — enforce, launcher-gated (Option A).** Investigating the
  Stage-A precondition established that **mvmd cannot be relied on to deliver a
  grant**: it boots instances through a *direct* Firecracker launch
  (`mvmd-runtime` `instance_start_inner`) that synthesizes no `ExecutionPlan`,
  mints no `VerbGrant`, and **bypasses mvm-backend's cmdline assembly entirely**.
  So flipping the *baked* bit to `require_grant: true` would fail-close every
  mvmd instance. Stage A therefore does **not** flip the baked bit (it stays
  `false`); instead enforcement is **launcher-gated**:
  - The host emits a `mvm.require_grant=1` kernel-cmdline token **only when it
    delivered a grant** (`require_grant_cmdline_token`, keyed on the
    `verb-grant.json` sidecar *existing* — so a corrupt sidecar still asserts
    enforcement and the guest fails closed rather than running grant-less),
    appended at the four mvm-backend cmdline builders
    (`microvm`/`qemu`/`libkrun`/`vz`) — all of which mvmd bypasses.
  - The guest reads it (`launch_requires_grant()` over `/proc/cmdline`) and
    `trust_decision(policy, grant_present, launch_requires_grant)` fails closed
    when enforcement is **launch-asserted OR baked-policy-required OR
    `grant_key_source: attested`**, and no grant is pinned.

  Net: mvmctl grant-delivering launches enforce; mvmd (and any direct-launch
  path) asserts nothing → always serves → **no brick, no mvmd change**. The
  measured `require_grant` field is retained for the observe signal and the
  `attested` seam; the enforcement *trigger* moved to the launch token. Trade-off
  vs. the original "flip the baked bit" plan: `require_grant` enforcement is now
  launcher-asserted rather than rootfs-measured — a slight weakening of the
  measured-policy property, accepted because a delivered grant is still
  pinned+enforced and the launcher emits the flag in the same routine that
  delivers the grant. A stale-sidecar guard unlinks a pre-existing
  `verb-grant.json` on re-stash so a reused persistent name cannot inherit a
  spurious enforcement assertion; an `xtask` gate machine-checks that
  `mvm.require_grant=1` appears only in the four allowlisted builders (guards the
  no-brick invariant).

### 3. Restore reconciliation (grant survives every restore flavor)

`require_grant` must hold across snapshot restore, not only fresh boot:

- **Pause/resume + warm-restore** (guest RAM saved/restored): the agent's pinned
  grant survives in memory; `require_grant` is already satisfied. No change.
- **`fs_quick` fork** (rootfs-only; agent restarts): mint a fresh child grant at
  fork admission and deliver it on the child's cmdline — the restarting agent
  re-pins via the existing boot path.
- **`vm_full` fork** (memory cloned; agent survives with the *parent's* grant
  while a *fresh child plan* with a new session/nonce is admitted at
  `checkpoint.rs`): the surviving grant is stale. Mint a fresh child grant and
  deliver it over the **existing** `PostRestore` vsock frame, extended with an
  optional `#[serde(default)] grant_envelope: Option<VerbGrantEnvelope>` (no
  schema-version bump — consistent with the repo's no-ceremony rule and
  `PostRestore`'s existing `serde(default)` fields). The guest re-pins via a new
  `re_pin_verb_grant(envelope)` in the `PostRestore` handler.

This also closes the pre-existing "forked children run class-gate-only"
follow-up (`restrict_agent_verbs: false` at the fork sites): forked children of a
sealed image now carry a valid grant matching their own admitted plan.

### 4. The future attestation seam

`grant_key_source` is the forward hook. When measured boot / a vTPM lands (an
explicit ADR-002 scope expansion, out of scope here), sealed images bake
`grant_key_source: "attested"`, and the guest requires the grant's verifying key
to match an attested launch measurement rather than trusting the cmdline
`pubkey_hex`. No wire/protocol churn is needed to reach that state — only the
policy value and the guest's key-source branch. This ADR deliberately leaves the
`Attested` arm defined-but-unimplemented (the guest treats an unexpected
`Attested` policy as fail-closed, never as a silent downgrade).

## Consequences

**Positive**
- A grant-delivering launch enforces the grant end-to-end: a launch that mints a
  grant asserts `mvm.require_grant=1`, so a bug/corruption that drops or mangles
  the delivered grant fails closed rather than silently downgrading to
  class-gate-only. (The *policy* is dm-verity-measured; the enforcement *trigger*
  is the launch token — see Rollout / Stage A for why.)
- Enforcement holds across all restore flavors; the "forked children run
  class-gate-only" gap is closed with a correct per-child grant.
- The honest limitation is documented in one place, and the future
  attestation upgrade has a defined, churn-free seam (`grant_key_source`).

**Negative / accepted**
- No real key separation is added (and, per the ceiling analysis, none is
  achievable in scope). This ADR does **not** move the verb-grant story onto the
  numbered claim ledger.
- New surface: one optional `PostRestore` field, a guest re-pin path, and
  mint-at-fork. All reuse existing frames/mechanisms.
- Under Stage A, a grant-delivering launch that asserts `mvm.require_grant=1` but
  then cannot pin a valid grant fails closed — the intended catch, but it raises
  the bar on the correctness of the launch paths that deliver grants. The
  launcher-gated design (Option A) bounds this to exactly the mvmctl paths that
  emit the token; mvmd and other direct-launch paths never assert it, so they are
  never fail-closed.

**Neutral**
- Dev / OCI images are unaffected (policy file absent ⇒ permissive default),
  consistent with the item-2 change that already mints the default grant only
  for sealed images (PR #1437).

## Alternatives considered

- **Bake the host-signer pubkey into the verity rootfs.** Infeasible: verity is
  build-time-generic; the per-host key does not exist at build time; no
  per-launch re-seal.
- **Per-launch full-rootfs re-seal** (recompute the roothash with the key baked
  in). Real "measured key," but heavyweight (per-launch verity over the whole
  rootfs) and of ~nil marginal value in the trusted-host model (the host controls
  key, roothash, and cmdline alike). Rejected.
- **Move the key onto the `mvm-config` drive.** The config drive is unmeasured;
  this is the same launcher-controlled channel as the cmdline. Security theater.
  Rejected.
- **Pull hardware attestation into scope.** The only construction that yields
  real key separation, but a deliberate ADR-002 scope expansion beyond this
  work; recorded as the future seam instead.
- **Stage A as a baked `require_grant: true` flip** (the original Rollout plan).
  Superseded before implementation: mvmd boots sealed images through a direct
  Firecracker path that delivers no grant, so a baked flip would brick every
  mvmd instance. Replaced by the launcher-gated `mvm.require_grant=1` token
  (Option A, see Rollout / Stage A), which enforces only where a grant was
  delivered and leaves mvmd untouched with no mvmd-side change.

## Out of scope

- A malicious host (ADR-002).
- Hardware-backed key attestation / measured boot (ADR-002) — the future seam,
  not built here.
- Promotion of the verb-grant story to the ADR-002 numbered claim ledger.


## Consolidated from ADR-109 — Attested launch anchor for real verb-grant key separation

- Status: Proposed (scope-expansion proposal — needs maintainer decision + an ADR-002 threat-model update before any implementation)
- Date: 2026-07-05
- Owner: MVM Project
- Related: ADR-108 (verb-grant measured trust policy — the honest ceiling this proposes to lift + the `grant_key_source: Attested` seam), ADR-002 (microVM security posture — currently lists hardware-backed key attestation / TPM / SEV out of scope for v1), ADR-041 (signed audited execution plans — claim 8), ADR-001 (Firecracker-only execution)
- Tracks: #1458

## Context

ADR-108 established, and this ADR does not re-litigate, that **real cryptographic
key separation for the verb grant is not achievable within ADR-002's current
scope**. The delivered mechanism is honest *trusted-channel provisioning*: the
guest verifies the grant against a key the trusted launcher provides, over a
channel the launcher controls. Every in-scope anchor (kernel cmdline, config
drive, even the dm-verity roothash) is launcher-provisioned, and the per-host
runtime host-signer key cannot be baked into a build-time-generic verity image.
The verb-grant story therefore deliberately stays **off** the numbered claim
ledger.

ADR-108 left a churn-free forward hook: `VerbTrustPolicy.grant_key_source` has an
`Attested` arm (defined, treated fail-closed, unimplemented), and `trust_decision`
already routes it. This ADR asks the real question that hook defers: **what would
it take to give the guest an anchor for the grant's verifying key that the
launcher — or a malicious host — cannot forge**, so the verb-grant story could
be promoted to a numbered claim?

## The requirement

Real key separation needs a trust root the guest can verify that is **independent
of the entity that provisions the grant**. In the trusted-host model that entity
is the host; against a *malicious* host it is still the host. So the requirement
splits by adversary:

- **Against a trusted-but-buggy launch path** (defense-in-depth, in-scope today):
  an anchor computed by something other than the launch code — e.g. a
  measurement device — so a launch bug that mis-provisions the grant is caught.
- **Against a malicious host** (currently out of scope): an anchor rooted in
  **hardware the host cannot impersonate** — i.e. a CPU that signs an attestation
  over the launch measurement with a key the host does not hold.

Only the second yields *real* key separation. The first is a strictly weaker
"measured, but still host-rooted" improvement.

## The hard constraint: the workload VMM has no attestation surface

**Firecracker — the workload VMM on Linux (ADR-001) — is deliberately minimal:
no vTPM device, no measured-boot/PCR surface, no attestation report.** So the
classic "guest reads a TPM quote" pattern is unavailable on the primary
workload backend. Any attestation story therefore also implies a **VMM change**,
not just a guest/host protocol addition. This is the crux that makes attestation
a multi-quarter initiative rather than an incremental follow-up.

## Options considered

1. **Host-emulated vTPM under a vTPM-capable VMM** (QEMU / Cloud Hypervisor +
   `swtpm`). The guest measures its boot into PCRs and the vTPM signs a quote.
   *But* the vTPM is emulated by the (trusted) host process, and its
   attestation key is host-held — so a **malicious host can forge the quote**.
   Gives a *standard attestation shape* and independence from a *buggy launcher*
   (the measurement is computed by the vTPM, not the launch code), but **not**
   real separation against a malicious host. Requires abandoning/augmenting
   Firecracker for workloads. Medium-heavy; modest security gain over ADR-108's
   launcher-gated enforcement.

2. **Confidential computing — SEV-SNP / TDX** (hardware memory encryption +
   remote attestation). The **CPU**, not the host, signs an attestation report
   over the launch measurement with a vendor-rooted key the host does not hold.
   This is the **only option that achieves real key separation against a
   malicious host** — the guest (or a relying party) verifies the report against
   the CPU vendor's root, binds the grant's verifying key to the attested
   measurement, and flips `grant_key_source: attested`. Requires: SEV-SNP/TDX
   hardware, a CC-capable VMM (QEMU / Cloud Hypervisor — **not** Firecracker), an
   attestation-verification service, and a threat-model change (a malicious host
   moves partly in-scope). Heaviest; the genuine answer.

3. **Per-install build-time anchor** (non-hardware, partial). At `mvmctl init`
   provision a per-install trust anchor and bake its public half into images
   built for that install; sign grants under a key certified by it. Independent
   of the *per-launch* code path, so it catches a buggy launcher, but the anchor
   is still host-generated and host-held — **no** defense against a malicious
   host, and it complicates the image-build determinism invariant. Marginal.

4. **Do nothing more; keep trusted-channel provisioning.** ADR-108's
   launcher-gated enforcement (Stage A) already gives defense-in-depth against a
   buggy launcher without any of the above cost. Against a malicious host,
   nothing short of option 2 helps, and a malicious host is out of scope. This is
   the honest status quo.

## Recommendation

**Do not pursue attestation as a near-term follow-up.** The only option that
delivers what #1458 asks for (real key separation) is **option 2 (confidential
computing)**, and it is gated on decisions far larger than the verb grant: a
confidential-computing workload backend, SEV-SNP/TDX hardware, an
attestation-verification service, and an ADR-002 threat-model expansion that
brings a malicious host partly in-scope. Options 1 and 3 add real cost for a gain
that does not exceed ADR-108's already-shipped launcher-gated enforcement in the
trusted-host model.

Concretely:

1. **Keep the `grant_key_source: Attested` seam as-is** (defined, fail-closed,
   unimplemented). No code change now.
2. **Gate any attestation work on a prior, standalone decision to adopt a
   confidential-computing workload backend.** That decision — not the verb grant
   — is the real fork; the verb-grant binding is a small consumer of it.
3. **Do not promote the verb-grant story to a numbered claim** until an anchor
   with genuine host-independence exists (option 2). Trusted-channel provisioning
   must not be described as key separation in the claim ledger.
4. If a CC backend is later adopted, a *follow-on* ADR designs the concrete
   binding: attestation-report verification, measurement→`pubkey` binding, the
   guest/relying-party verification point, and the `attested` policy semantics.

## Promotion criteria (what a numbered claim would require)

A future "verb grant is bound to an attested launch measurement" claim is
justifiable only when **all** hold, each with a machine-checked witness:

- The grant's verifying key is bound to a launch measurement attested by a root
  the host cannot forge (CPU vendor root, not a host-held key).
- The guest (or a relying party) rejects a grant whose key does not match the
  attested measurement — negative-path tested (forged report, wrong measurement,
  replay).
- The attestation-verification path is fuzzed / adversarially tested, consistent
  with the existing claim-catalog discipline (`specs/claims/catalog.md`).

Until then this stays a `Preview`-style note at most, never a numbered claim.

## Consequences

- **Positive:** the "future attestation" hand-wave becomes a concrete,
  honestly-scoped roadmap with the hard constraints named (Firecracker has no
  attestation surface; real independence needs confidential computing). Prevents
  building options 1/3 as security theater.
- **Negative / accepted:** no key separation is delivered now. #1458 is
  effectively answered "yes, but only via confidential computing, which is a
  separate large initiative" — this ADR records that answer rather than shipping
  a partial mechanism.
- **Neutral:** ADR-108's launcher-gated enforcement remains the current best
  in-scope posture and is unaffected.

## Out of scope (for this ADR)

- Selecting or building a confidential-computing workload backend (its own ADR).
- Any code change — this ADR is a direction/decision record, not an
  implementation plan.
- The malicious-host threat model itself, which ADR-002 would need to revise
  before option 2 could be claimed.


## Consolidated from ADR-111 — Runtime-owned reversible replacement on owned cleartext paths

**Status:** Proposed — 2026-07-13

## Summary

Land the first runtime-owned detect -> replace -> reinject slice for sensitive
values on owned cleartext request/response paths. The promise is narrow:
request-scoped opaque token replacement on outbound traffic plus exact-token
restore on the owned response path. No semantic recovery, no third-party async
callbacks, and no guest-visible plaintext persistence.

## Context

The existing substitution/redaction stack in `mvm` already has two useful
security properties:

1. declared secrets can stay off the guest entirely through host-side
   substitution
2. undeclared secret-shaped or PII-shaped content can be redacted before egress

That was still missing one product-critical capability: when the runtime owns
both sides of a cleartext request/response flow, it had no way to replace
sensitive spans on the outbound leg and restore them exactly on the inbound
leg. Without that, policy could safely scrub prompts or payloads before an
external AI/tool call, but any authorized caller-visible response still had to
choose between one-way redaction and raw passthrough.

The requirement for v1 is intentionally limited:

- runtime-owned paths only
- exact opaque-token restore only
- request-scoped correlation only
- no plaintext in proofs or ordinary audit/log views

## Decision

`mvm` adds a runtime-owned reversible replacement slice at the host
substitution proxy boundary.

### 1. Shared policy + proof types live in `mvm-core`

`ExecutionPlan` now carries a `ReversibleReplacementPolicy` that is signed,
admitted, and handed to `mvm-hostd` like the other policy-bearing plan fields.
The shared contract includes:

- sensitive classes: `secret`, `pii`
- replace / reinject surfaces
- fail-closed fallback mode
- request-scoped flow ids
- opaque rewrite tokens
- plaintext-free proof records carrying keyed digests and byte spans only

This keeps the policy part of the signed plan boundary rather than making it an
ephemeral host-local toggle.

### 2. Replacement happens before one-way redaction

On the outbound host-owned request path:

- the claim-10 destination gate still runs first
- reversible replacement runs before one-way redaction and before host-side
  declared-secret substitution
- the replacement engine detects secret-shaped and structured-PII spans
- matched values become request-scoped opaque tokens
- identical values within one flow reuse the same token

That ordering preserves the host-only placeholder model for declared secrets
while still allowing undeclared secret/PII content to be tokenized for exact
restore instead of only masked away.

### 3. Reinjection is exact-token-only on the owned response path

On the inbound response path, the runtime restores only exact token echoes from
the same flow state. If the external service paraphrases, transforms, splits,
or drops the token, nothing is restored. This is a deliberate contract, not a
best-effort heuristic.

### 4. Proofs and audit stay plaintext-free

Each replace/reinject event records:

- flow id
- event index
- sensitive class
- surface
- optional field name
- offset and lengths
- token id
- keyed HMAC digest of original bytes
- keyed HMAC digest of rewritten bytes
- policy / authorization decision labels

The audit chain carries those proof metadata records, not the plaintext value.

## Consequences

### Positive

- `mvm` now has a concrete v1 implementation of “tokenize outbound, exact-token
  restore inbound” for owned cleartext paths.
- The policy is part of the signed execution plan and therefore travels through
  the same admission / provenance path as the rest of the runtime controls.
- The implementation composes with the existing substitution and redaction
  layers instead of replacing them.

### Negative

- This is not a general semantic restoration mechanism. Model-transformed output
  will not restore.
- The v1 authority labels are local runtime labels such as `runtime_owned`; the
  cloud-side permission authority lives in sibling `mvmd`.
- The current proof substrate is an audit/proof metadata trail, not a full
  durable proof-access service.

## Non-goals

- paraphrase-aware recovery
- async callback or webhook reinjection
- cross-flow or cross-tenant token reuse
- guest-side plaintext reinjection defaults
- claiming macOS parity beyond the currently owned substitution-proxy path

## Follow-on work

1. Bind the runtime-owned authorization label to the sibling `mvmd`
   tenant/permission authority on cloud-managed paths.
2. Extend the proof model to a dedicated retrieval surface where that is needed.
3. Decide whether additional structured PII classes should become enabled by
   default beyond the current detector set.
