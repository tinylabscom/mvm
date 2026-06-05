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
were added by Plan 104 / ADR-059, with Claim 13 rewritten by ADR-062
when `host.secrets.v1` was dropped from v1 scope and `host.audit.v1`
took its place as the load-bearing workload service.

| # | Claim | Primary layer | Workstream | CI gate |
|---|---|---|---|---|
| 1 | No host-fs access from a guest beyond explicit shares | L2/L5 | W2.1, W1.1, W2.3, W2.4 | seccomp regression; per-service-uid bind audit |
| 2 | No guest binary can elevate to uid 0 | L2/L4 | W2.2, W2.3 | bind-mount RO assertion; setpriv `--no-new-privs` regression |
| 3 | A tampered rootfs ext4 fails to boot | L3 | W3.1–W3.4 | `verified-boot-artifacts` + live-KVM tamper test in `security.yml` |
| 4 | The guest agent does not contain `do_exec` in production builds | L4 | W4.3 | `prod-agent-no-exec` symbol-grep job in `ci.yml` |
| 5 | Vsock framing + supervisor-config JSON are fuzzed | L2/L4 | W4.1, W4.2, Plan 88 W6 | `cargo-fuzz` targets in `crates/mvm-guest/fuzz/` (`GuestRequest`, `AuthenticatedFrame`, `fuzz_authed_path`) and `crates/mvm-libkrun/fuzz/` (`fuzz_supervisor_config`); `deny_unknown_fields` audit |
| 6 | Pre-built dev image is hash-verified | cross-cutting (supply chain) | W5.1 | `download_dev_image` SHA-256 check; `MVM_SKIP_HASH_VERIFY` only documented escape |
| 7 | Cargo deps are audited on every PR | cross-cutting (supply chain) | W5.2 | `cargo-deny` + `cargo-audit` jobs; reproducibility double-build (W5.3) |
| 8 | Every workload runs from a signed, audited `ExecutionPlan` | cross-cutting (policy + audit) | plan 64 W1–W4, ADR-041 | `synthesize_plan` / `host_signer::load_or_init_at` / `admit_for_run` / `AuditEmitter` round-trip + tamper rejection tests; `xtask check-no-display-on-secret-types` |
| 9 | Every published bundle is content-addressed, key_id-pinned, and re-verified at fetch **and at admit time** | cross-cutting (supply chain + integrity) | Sprint 52 W2 + admit-time re-verify follow-on | `mvm_plan::bundle::read_and_verify_bundle` + `mvm_plan::bundle::verify_plan_bundle` rejection-ladder tests: unknown-key, tampered manifest, key_id mismatch, tampered artifact, missing artifact, unsafe path, schema bump, pin-archive sha256 drift, pin-signature drift; `mvmctl bundle fetch` round-trip + `admit_for_run` tests asserting refusal on pin-without-context and pin-archive mismatch |
| 10 | No untrusted workload reaches the network unless explicitly admitted by policy | cross-cutting (data containment) | Sprint 52 W3 | `policy_default_is_deny_all` + `test_resolve_network_policy_default_is_deny_all`; `mvmctl up` emits an opt-in warning when the resolved policy is `unrestricted` (escape hatch is `MVM_ACK_UNRESTRICTED_NETWORK=1`) |
| 11 | Every application-dep volume is hash-locked, attestation-checked, CVE-scanned, SBOM-enumerated, and bound to the workload's audit chain | cross-cutting (supply chain — app-layer deps) | ADR-047, Plan 73 Followups A + B.1/B.2/B.3 + C + D | `mvm_sdk::compile::deps_audit::{seal_volume, verify_sealed_volume}` tamper-detection unit tests; `mvm_build::app_deps_gate::apply_install_gate` prod/dev rejection tests; `app-deps-audit` CI lane in `ci.yml` (Followup D) — drives `mvmctl compile` on `examples/python/hello-app-with-deps/`, seals a clean + a HIGH-CVE fixture via `mvm-app-deps-fixture-tool`, asserts `mvmctl deps inspect --json` produces a well-formed report, asserts the prod gate refuses the HIGH-CVE fixture and the dev gate admits it, asserts a byte-flip on `cve.json` makes inspect refuse |
| 12 | Every host-side service the broker exposes is bound to a signed `ExecutionPlan.services` binding, enforced before handler dispatch, and audited via the chain-signed log | cross-cutting (policy + audit) | Plan 104 W2, ADR-059 | `service_call_denied_when_unbound` + `service_call_denied_outside_profile` + `audit_chain_contains_service_call_entries` + `audit_chain_carries_no_payload_bytes` rejection-ladder tests; `xtask check-handler-adr-coverage` + `xtask check-handler-policy-schema` + `xtask check-handler-composition` lints; `fuzz_service_call.rs` lane (Plan 104 W6) |
| 13 | No raw secret value crosses the broker channel; `host.secrets.v1` returns destination-bound, time-bound signed credentials only; raw secret bytes never leave the supervisor's address space | cross-cutting (data containment) | Plan 104 W5, ADR-049, ADR-059 | `host_secrets_v1_denied_outside_allowed_destinations` + `zeroize_drop_zeros_secret_bytes` + `handler_inter_call_memory_hygiene` + `host_secrets_v1_signed_payload_jcs_roundtrip` + `secrets_subprocess_cannot_reach_supervisor_memory` + `placeholder_in_outbound_request_dropped_and_audited` (S25 backstop) tests; ADR-049 hostile-guest matrix in W7 |

L1 (host + hypervisor) has no claim of its own — the host is trusted
by definition (see Threat model). L1 *enables* claim 3 (verified boot
needs a hypervisor that respects the kernel cmdline). If the host is
compromised, every layer falls; that case is explicitly out of scope.

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

Plan 53 (cross-platform roadmap) introduces multiple backends —
Firecracker, Apple Container, libkrun, Docker, microvm.nix — each
with different layer coverage. A given user run carries the tier of
its active backend, not the strongest tier the project supports. The
following matrix is what `mvmctl doctor` reports and what the
mvm-cli startup banner surfaces (loudly, when the active backend
falls below Tier 1).

| Backend | L1 | L2 | L3 | L4 | L5 | Notes |
|---|---|---|---|---|---|---|
| Firecracker (Linux + KVM) | ✅ | ✅ | ✅ | ✅ | ✅ | **Tier 1** — full ADR-002. All seven claims hold. |
| Cloud Hypervisor (Linux + KVM) | ✅ | ✅ | ⚠️ in flight | ✅ | ✅ | **Tier 1 peer** of Firecracker — same VMM-TCB shape (rust-vmm), wider device model (VFIO, virtio-fs, larger guests). Claim 3 (verified boot) lands alongside Firecracker via the shared `mvm-verity-init` initramfs path; the CH JSON-API spawn dance is the only delta. Selected over Firecracker when a workload needs VFIO/GPU passthrough or virtio-fs. |
| Apple Container (macOS 26+ Apple Silicon) | ✅ VZ | ✅ Containerization | ⚠️ no verified boot yet | ✅ | ✅ | Tier 2 — claim 3 partial; claims 1, 2, 4, 5, 6, 7 hold. |
| Vz / Virtualization.framework (macOS 13+) | ✅ HVF | ✅ Vz (Apple-controlled API surface on top of HVF) | ⚠️ no verified boot yet | ✅ | ✅ | Tier 2 — same `Hypervisor.framework` primitive as libkrun, smaller Apple-controlled API surface, balloon + (macOS 14+) snapshots. Claim 3 partial — dm-verity pipeline targets Firecracker today; claims 1, 2, 4, 5, 6, 7 hold. Opt-in via `--backend vz` / `MVM_BACKEND=vz`; `auto_select` keeps libkrun as the macOS default (ADR-056). |
| libkrun / libkrun (Linux KVM, macOS HVF) | ✅ | ✅ | ⚠️ no verified boot yet | ✅ | ✅ | Tier 2 — claim 3 partial; comparable VMM TCB to Firecracker; shipped as the cross-platform default per ADR-013. macOS arm64/x86_64 + Linux-without-KVM hosts land here. |
| Docker | ❌ shared host kernel | ❌ container runtime is L2=host kernel | ❌ shared with host | ✅ | ✅ | **Tier 3** — claims 1, 2, 3 do *not* hold; 4, 6, 7 hold; 5 N/A (unix socket). |
| microvm.nix (QEMU) | ✅ KVM | ⚠️ QEMU TCB much larger | ⚠️ partial verified boot | ✅ | ✅ | Tier 2 — claims 3 partial; QEMU's larger device model raises L2 audit cost. |

**Tier discipline**: Tier 1 is the production default and the only
tier that carries the *full* ADR-002 promise. Tier 2 carries six of
the seven claims with claim 3 (verified boot) tracked as a follow-up
once verified-boot lands for VZ/HVF. Tier 3 (Docker) carries only the
supply-chain and guest-agent claims; the L1–L3 isolation collapses to
the host kernel. Plan 53 §"Security posture decision" documents *why*
we keep Docker available but unpromoted — the convenience is real,
but we refuse to launder a container as a microVM in marketing or in
auto-selected defaults.

`mvmctl doctor` (plan 40 folded the standalone `security` verb into
doctor) renders this matrix per-host with the active backend
highlighted and prints a loud `MVM_ACK_DOCKER_TIER`-suppressible
warning banner whenever Tier 3 is auto-selected.

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
  guest egress destinations beyond NAT vs. tap. Noted, not addressed
  in this ADR; potential follow-up.

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
| Default-deny outbound, then allowlist (or policy proxy) | **pass** | **claim 10** | `policy_default_is_deny_all`; `test_resolve_network_policy_default_is_deny_all`; `mvmctl up` warns on `unrestricted` policy with explicit env opt-out. DNS / broker / vsock carve-out audit tracked in Plan 111 Workstream A. |
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
| No raw secret crosses the broker channel | **pass** | claim 13 (Plan 104 / ADR-049 / ADR-059) |

### Cardoso three-question summary

| Question | mvm answer |
|---|---|
| What is shared between this code and the host? | KVM `/dev/kvm` ioctls (Linux); Hypervisor.framework calls (macOS Vz / libkrun); vsock for control plane + brokered host services (binding-gated per claim 12); one explicit virtio-fs share per declared mount. Host filesystem is never ambient. |
| What can the code touch? | Whatever the signed `ExecutionPlan` admits: declared shares, declared egress allowlist (claim 10), declared volumes, declared `host.*` brokered services (claim 12 binding). No raw devices. No host process namespace. No host network namespace. |
| What survives between runs? | Volumes the plan declares persistent (sealed deps volumes are RO and hash-locked per claim 11). Everything else is ephemeral by default. Snapshot/restore on workload microVMs not yet exposed — see Plan 111 Workstream B. SDK workload hooks (`before_build` / `before_start` / `after_start` / `before_stop` in `crates/mvm-sdk/src/compile/hooks.rs`) shape what runs at launch, not what survives across launches. |
