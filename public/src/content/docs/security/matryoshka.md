---
title: "The Matryoshka model: how mvm isolates untrusted code"
description: "mvm runs untrusted Linux workloads in microVMs. This page explains the five trust layers, the CI-enforced security claims, and which claims hold for each backend."
---

mvm's job is to let you run **untrusted code** — third-party software, AI-generated scripts, CI runners, sandbox workloads — and trust the isolation. This page explains the security model in one diagram and one matrix.

## What you get by default

For the ordinary command — `mvmctl machine run --image ... -- ...` — mvm starts
from a deny-by-default posture. The exact enforcement tier is printed by
`mvmctl doctor` and in launch receipts, but the user-visible contract is:

- **A real microVM boundary:** each workload gets its own guest memory, virtual
  devices, and Linux kernel. A container is never silently substituted.
- **A private filesystem:** the image and the workload's ephemeral writable
  layer are visible inside the guest. Host directories are absent unless you
  explicitly mount them; mounts are a deliberate part of the launch plan.
- **No network by default:** there is no egress until you enable networking and
  admit destinations with `--allow-host`. Inbound access is not implied by an
  outbound rule.
- **No raw host secrets in the guest:** secret-aware egress substitutes
  credentials at the host boundary, so the workload receives only the
  placeholder or response it is authorized to use.
- **An auditable launch decision:** the image, resource limits, mounts, network
  posture, admission profile, and backend are captured in the signed execution
  plan before boot.

These defaults are intentionally stronger than “a VM with a public network.”
They make the safe path the shortest path while keeping explicit escape hatches
visible in the command line and the receipt.

### What mvm defends

mvm is designed to bound an untrusted guest that tries to escape to the host,
read another workload's state, use an undeclared host mount, reach private host
services, or obtain a credential that was not released for its destination.
The guest-to-host control channel is host-brokered and typed; it is not SSH and
does not require an inbound guest listener.

### What mvm does not defend

mvm trusts the host operating system, the selected hypervisor, and the release
or source artifacts used to build it. A compromised host or hypervisor is
outside this boundary. A workload can also misuse a destination, mount, secret,
or capability that its operator explicitly allowed. Multi-tenant sharing inside
one guest and hardware-backed remote attestation are not default guarantees.

### Your responsibility

Use the strictest profile that fits the workload, keep networking disabled when
it is unnecessary, allowlist only the destinations required, prefer read-only
mounts, pin production images by digest, set resource and lifetime limits, and
keep the host patched. The security posture is visible and enforceable, but it
cannot infer whether an explicitly granted capability is safe for your code.

## The five trust layers

```
┌───────────────────────────────────────────────────────────┐
│ L5 — Workload (your untrusted code)                       │
├───────────────────────────────────────────────────────────┤
│ L4 — Guest agent (parses host messages, launches code)    │
├───────────────────────────────────────────────────────────┤
│ L3 — Guest kernel (Linux, ephemeral, isolated)            │
├───────────────────────────────────────────────────────────┤
│ L2 — VMM (Firecracker, Rust, seccomp-jailed)              │
├───────────────────────────────────────────────────────────┤
│ L1 — Host + hypervisor (KVM / HVF)                        │
└───────────────────────────────────────────────────────────┘
```

Each layer trusts only the layer **below** it. An attacker has to break through every boundary above to reach the host. A failure in any one layer is bounded — the layer below still enforces its own contract.

This pattern (sometimes called the _matryoshka_ model after the nested Russian dolls) is the same defense-in-depth used across the production microVM / hardened-isolation ecosystem. mvm's adaptation is that **L5 is enforced inside the guest** — even a guest-kernel compromise doesn't give arbitrary access to other in-guest services. See [ADR-001](https://github.com/tinylabscom/mvm/blob/main/specs/adrs/001-microvm-security-posture.md) for the full decision record.

## The claims

mvm makes fifteen CI-enforced security claims, plus three preview claims whose
witnesses run but whose guarantee is narrower. Each one is backed by a test or a
continuous-integration check that fails the build if the claim ceases to hold.
The claims that defend a nesting layer are what the layer model is about; the
rest defend the supply chain and the admission path, which decide what is
allowed to run inside those layers at all.

| #   | Claim                                                                      | Defends layer            | How it's enforced                                                                                                                                        |
| --- | -------------------------------------------------------------------------- | ------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | No host-fs access from a guest beyond explicit shares                      | L2 / L5                  | Per-service uid + seccomp `standard` default + setpriv bounding-set drop; user-volume allow-list defaulting to read-only                                 |
| 2   | No guest binary can elevate to uid 0                                       | L2 / L4                  | `setpriv --no-new-privs` in launch path; `/etc/{passwd,group}` are read-only bind-mounts                                                                 |
| 3   | A tampered rootfs ext4 fails to boot                                       | L3                       | dm-verity sidecar + roothash on cmdline + a verity-aware initramfs owning the boot pivot                                                                 |
| 4   | A production-safe run cannot invoke DevOnly guest-agent verbs              | L4                       | Runtime profile + signed `VerbGrant` intersection; grant and conformance tests enforce the full DevOnly set                                              |
| 5   | Vsock framing, supervisor-config JSON, and the datapath ingress are fuzzed | L2 / L4                  | `cargo-fuzz` targets over the host↔guest messages, the supervisor config parser, and the userspace datapath ingress; `deny_unknown_fields` on every type |
| 6   | Pre-built dev image is hash-verified                                       | supply chain             | SHA-256 manifest streamed through the download; a mismatch rejects and deletes it                                                                        |
| 7   | Cargo deps are audited nightly and on every release tag                    | supply chain             | `cargo-deny` + `cargo-audit` jobs in `security.yml`; reproducibility double-build                                                                        |
| 8   | Every workload runs from a signed, audited `ExecutionPlan`                 | admission                | Ed25519 host-signer keypair; validity window + nonce replay-store; chain-signed admission entries                                                        |
| 9   | Every published bundle is content-addressed and key_id-pinned              | supply chain             | A rejection ladder at fetch and at admit time: unknown key, tampered manifest, key_id mismatch, unsafe path, pin drift                                   |
| 10  | No untrusted workload reaches the network unless policy admits it          | data containment         | Policy defaults to deny-all; the workload guest has no NIC, so egress leaves only over vsock to a host endpoint that authorizes it                       |
| 11  | Every application-dependency volume is sealed and audited                  | supply chain (app layer) | A hash-locked volume carrying an SBOM, a CVE scan, and a hash-chained manifest; admission refuses a tampered volume                                      |
| 12  | Every broker service is bound to a signed plan binding                     | admission                | Binding-gated dispatch, enforced before the handler runs, with a rejection ladder for unbound and out-of-profile calls                                   |
| 13  | No raw secret value crosses the broker channel                             | data containment         | Destination-bound, time-bound signed credentials only; raw secret bytes never leave the supervisor's address space                                       |
| 14  | Every OCI image admission records provenance in the audit log              | supply chain             | A provenance entry carries registry, repo, resolved digest, layer digests, and trust verdict; production refuses a mutable reference                     |
| 15  | A sealed production microVM has no shell, no DevOnly verbs, no PTY         | L4                       | Only the dev `/init` serves a console; console capture is write-only with no host input; the host gate refuses `console` on a sealed image               |

Three further claims — 16 (egress substitution keeps a raw secret off the
guest), 17 (workload stdin is grant-gated and secret-scanned), and 18 (workload
resource bounding) — are **preview**. Their witnesses run in CI, but each
carries a limits note in ADR-001 that has to be read before treating it as
enforced. See [CI-enforced security claims](/security/ci-claims/#preview-claims).

L1 (host + hypervisor) doesn't carry its own claim — the host is **trusted** by definition. If your host is compromised, every layer falls. Locking down the host (firewall, package hygiene, full-disk encryption) is your responsibility.

## Intent-bound admission profiles

Every workload also goes through a signed admission step before boot. `mvmctl machine run` synthesizes an `ExecutionPlan`, signs it with the host key, checks its validity window and replay nonce, then emits a chain-signed audit entry.

The plan now carries an `admission_profile`: a compact record of the workload's declared intent and the controls selected for that intent:

- intent, for example `vm:boot`, `code:execute`, or `agent:web-research`
- seccomp tier selected for the run
- network, filesystem, egress, and tool policy refs
- secret-release posture (`none`, plan-bound, or attestation-bound)
- audit taxonomy and required labels

This does **not** add a second seccomp implementation or new execution capability inside the sandbox. Runtime syscall filtering still comes from `mvm-runtime`'s `security/seccomp.rs` filter selection and the `mvm_core::crypto::seccomp::SeccompTier` syscall tiers. The admission profile records the selected tier in the signed plan so the audit chain can prove which security posture the workload was admitted under.

## Per-backend tier matrix

mvm runs on multiple backends. Not all backends carry every claim. The tier you
actually get depends on which backend mvm picks for your run.

The columns below are the **nesting layers**, so this matrix covers the claims
that defend a layer. The supply-chain and admission claims (6, 7, 8, 9, 11, 12,
14) are backend-independent *across the claim-bearing microVM backends* —
Firecracker, HVF, and libkrun — where they gate what is allowed to run before a
backend is chosen. They do not extend to every row below: QEMU is type-excluded
from the admitted workload path, and the browser tier is claim-free and asserts
none of the numbered claims. Both exclusions are restated in the rows
themselves.

| Backend                                          | L1  | L2  | L3  | L4  | L5  | Tier                                                                                                                                                                                                                                                                                                        |
| ------------------------------------------------ | --- | --- | --- | --- | --- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Firecracker** (Linux + KVM)                    | ✅  | ✅  | ✅  | ✅  | ✅  | **Tier 1** — full ADR-001. Every layer-defending claim holds.                                                                                                                                                                                                                                               |
| **HVF** (macOS 26+ Apple Silicon — auto-default) | ✅  | ✅  | ⚠️  | ✅  | ✅  | Tier 2 — claim 3 (verified boot) partial; `Hypervisor.framework`, vsock-only egress (no guest NIC). The macOS-26 auto-default.                                                                                                                                                                              |
| **libkrun** (Linux KVM, macOS Apple Silicon HVF) | ✅  | ✅  | ⚠️  | ✅  | ✅  | Tier 2 — same as HVF.                                                                                                                                                                                                                                                                                       |
| **QEMU** (Linux KVM/TCG)                         | ✅  | ⚠️  | ⚠️  | ✅  | ✅  | Tier 2 — claim 3 partial; QEMU's larger device model raises L2 audit cost. Deliberately outside claim 10's egress enforcement, because it carries no untrusted multi-tenant workload. **Dev/test only** (`--hypervisor qemu`; the no-`/dev/kvm` path via TCG software emulation). Never selected by `mvmd`. |
| **WebLinux** (browser tier)                      | —   | ❌  | ❌  | ❌  | ❌  | **Claim-free** — no numbered claims. A real Nix-built Linux kernel boots under QEMU-Wasm, but the browser's sandbox and process isolation are the only boundary: there is no hypervisor and no verified boot.                                                                                                                                 |

✅ = layer fully enforced. ⚠️ = layer partial (named exception). ❌ = layer collapsed (claim does not apply). — = not applicable.

### No container fallback

On every default and production path, mvm has **no Tier 3** and no container/Docker fallback. A shared-kernel container is not a microVM: its isolation comes from the host kernel's namespace and cgroup machinery, which is shared with the host. In 2024–2025 the container ecosystem produced multiple CVEs (Leaky Vessels, NVIDIAScape, runc race conditions, Docker Desktop priv-esc, runc masked-path) that yielded **host escape** from inside a container — none of which matter inside a microVM, where the guest kernel is isolated by hardware. If a host has no microVM-capable backend, mvm does not silently drop to a weaker boundary; it fails closed.

There is no carve-out. ADR-034 has been retired and the Docker dev-tier
backend removed (Plan 329). A host without a usable microVM backend fails
closed; mvm does not offer a shared-kernel container path on any default,
production, or explicitly selected runtime path.

### Browser-tier WebLinux backend

The `WebLinux` backend runs workloads inside the browser's own WebAssembly engine. It has **no hypervisor boundary**: a real Linux kernel boots, but under QEMU-Wasm rather than on hardware virtualization. This makes it a claim-free tier: it cannot assert any of the numbered security claims because there is no hardware isolation.

The browser-tier backend:

- Boots a real Nix-built Linux kernel under QEMU-Wasm inside a browser Worker
- Has no hardware isolation boundary — the browser sandbox and process boundary are the only ones
- Is **never auto-selected** and only available through explicit `--hypervisor web-linux`
- Is for demos, playgrounds, and browser-local development only
- Does **not** apply to production workloads

On a native host the backend is a fail-closed stub: it is selectable so the catalog and CLI help can list it, but every lifecycle call refuses and it is barred from carrying an untrusted workload.

Separately, the host-`wasmtime` `wasm` tier runs a user-supplied **WASI Preview 1** module directly with no Linux kernel at all. It is also claim-free and opt-in only, and its `mvm:egress` host import relays each request over a Unix socket to the same host-side substitution endpoint the vsock-backed tiers use — not to a browser `fetch()`.

### Choosing a tier

- **Production / untrusted code** → Tier 1. Linux + KVM + Firecracker. No exceptions.
- **macOS dev or CI on Apple Silicon** → Tier 2 (HVF or libkrun). Verified boot is the open item.
- **Linux dev/test without `/dev/kvm`** → Tier 2 QEMU (`--hypervisor qemu`, TCG software emulation). A real microVM, slower; dev/test only.
- **macOS Intel / native Windows** → unsupported for local microVM isolation today. There is no container fallback on any path: ADR-034 is retired, the Docker backend is removed, and `--hypervisor docker` is hard-refused. The one opt-in container-kernel tier is `apple-container`, which boots Apple's prebuilt container kernel on the in-house HVF VMM — a microVM, not a shared-kernel container. WSL2 with nested `/dev/kvm` is the supported Windows-adjacent libkrun workload path; a Hyper-V managed Linux builder remains future backend work.

`mvmctl doctor` reports your current tier on the running host.

## What's not promised

ADR-001 names three explicit non-goals so we don't accidentally commit to defending against them:

- **A malicious host.** mvm trusts the host with the hypervisor and the build keys. If your laptop or your server is compromised, every layer falls.
- **Multi-tenant guests.** One guest = one workload. Sharing a single guest VM between mutually-distrusting tenants is out of scope.
- **Hardware-backed key attestation _against a malicious host_.** An opt-in TPM2 provider ships (the `attestation-tpm2` feature), and its measured-boot quotes are a real host-measured attestation input. What it does not do is move the trusted-host boundary: the host still owns the TPM, the connection to it, and the launch material, so a compromised host stays out of scope. Real separation needs confidential-computing hardware (SEV-SNP/TDX), which no shipped backend targets.

If your threat model needs any of those, mvm is not the right tool today. ADR-001 documents these limits explicitly.

## See also

- [ADR-001 (full decision record)](https://github.com/tinylabscom/mvm/blob/main/specs/adrs/001-microvm-security-posture.md)
- [Plan 25 (microVM hardening — the implementation sequence for claims 1–7)](https://github.com/tinylabscom/mvm/blob/main/specs/plans/25-microvm-hardening.md)
- [Plan 53 (cross-platform roadmap — backend tier discipline)](https://github.com/tinylabscom/mvm/blob/main/specs/plans/53-cross-platform-roadmap.md)
- ["Your container is not a sandbox" (emirb, 2026)](https://emirb.github.io/blog/microvm-2026/) — the post that crystallized the matryoshka framing in the broader microVM ecosystem.
