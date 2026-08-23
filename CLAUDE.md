# mvm -- Firecracker MicroVM Development Tool

Backing: shipped-source
Validation: check-claim-catalog

## Project Overview

Rust CLI for building and running Firecracker microVMs on macOS and Linux. Handles the full dev lifecycle: bootstrapping, Nix-based image builds, single-VM management, and reusable template creation.

Multi-tenant fleet orchestration (tenants, pools, instances, agents, coordinators) lives in the separate [mvmd](https://github.com/tinylabscom/mvmd) repository.

```
macOS Host (this CLI) -> libkrun Linux VM -> Firecracker microVM (/dev/kvm)
Linux Host (this CLI) -> Firecracker microVM (/dev/kvm)
```

Lima was the historical macOS host abstraction. It was removed on 2026-05-14 (Plan 72 W0–W6 + Plan 75 W0). libkrun is the default macOS 13-25 backend; HVF (the in-house Hypervisor.framework VMM, vsock-only) is the macOS 26+ Apple Silicon default; Firecracker is the Linux KVM path. There is no `--lima` flag and no Lima fallback. The Apple Virtualization.framework backend was **removed** (Plan 226 R1P1) — HVF is the destination macOS workload backend, with libkrun as the fallback, and the removed backend's `--hypervisor` value is gone. `xtask check-no-vz` enforces exactly two things: no Virtualization.framework / Containerization API, Swift import, or SwiftPM manifest anywhere under the workspace root, and no bare `vz` / `Vz` / `VZ` word in the Rust we own. What it does **not** forbid — and explicitly permits — is the `apple-container` backend, which still exists: `BackendKind::AppleContainer`, selector `--hypervisor apple-container` (alias `container`), is the HVF workload runner booting Apple's prebuilt container kernel, a fetched binary artifact carrying no Swift and no VZ. It is opt-in only; auto-detect never returns it.

## Host dependencies (macOS)

The libkrun-backed builder VM (started automatically by `mvmctl bootstrap`, `mvmctl build`, or `mvmctl machine run`) needs two Homebrew packages installed:

```sh
brew install slp/krun/libkrun slp/krun/libkrunfw
```

- `libkrun` — the in-process VMM. `mvm-libkrun-supervisor` links against it.
- `libkrunfw` — bundles the TSI-patched Linux kernel libkrun's guests boot. Plan 86 / Plan 72 W5.D bullet 10 — `libkrun-sys::extract_bundled_kernel()` pulls the kernel out of the dylib's `.rodata` at runtime.

There is no third package and no gateway binary. Every libkrun lane — builder
VM, Stage 0, and workload — boots with an explicit virtio-vsock device and no
guest NIC, so there is nothing for a userspace network gateway to sit between.
The `MVM_NETWORKING` and `MVM_GATEWAY_BIN` knobs that used to select one are
gone, and `xtask check-single-network-path` fails the build if a gateway,
guest NIC, or second endpoint path comes back.

`mvmctl doctor` reports the libkrun install state and emits hints when it is missing.

For source-checkout contributors only: a **pinned** zig + cargo-zigbuild are
needed at `cargo build`-of-mvmctl time so `crates/mvm-cli/build.rs` can
cross-compile the embedded host-vm binaries (`mvm-host-vm-init`,
`mvm-egress-proxy`) as static `aarch64-unknown-linux-musl` (the
builder VM rootfs has no dynamic loader). See Plan 115 / ADR-004.

Provision it with one command — it installs the exact pinned zig (from the
`ziglang` PyPI package, read out of `[workspace.metadata.mvm.toolchain]`) plus
the musl rust targets:

```sh
just toolchain-embed
```

Do **not** `brew install zig`: Homebrew's zig drifts to newer releases that are
incompatible with the pinned `cargo-zigbuild` and fail with a cryptic
`CacheCheckFailed`. `build.rs` auto-detects the `ziglang`-installed zig and, if
the pinned zig is missing, errors with the exact fix. Override the zig binary
with `MVM_EMBED_ZIG=/path/to/zig` if needed.

End-users running a downloaded mvmctl don't need any of this — the
binaries are already embedded.

**macOS 26+ Apple Silicon** users need no Homebrew prerequisites for the HVF builder (the auto-detect default on that tier — see "Builder backend selection" below). The `slp/krun/*` Homebrew trio is only required if you explicitly opt into libkrun via `--builder libkrun` or `MVM_BUILDER_BACKEND=libkrun`.

## Builder backend selection (Plan 98)

The builder VM (the Linux guest that runs `nix build` inside `mvmctl machine build` / `mvmctl machine run --flake`) picks between three host VMMs:

- **hvf** — the HVF builder (Hypervisor.framework, no Homebrew deps). Default on macOS 26+ Apple Silicon. macOS-only.
- **libkrun** — third-party in-process VMM via the `slp/krun/*` Homebrew trio. Default on Linux and macOS 13-25. Works everywhere mvm runs.
- **qemu** — QEMU/microvm_nix builder (Linux dev/test substrate). Opt-in only.

(The Apple Virtualization.framework builder was removed in Plan 226 R1P1.)

Selection priority (highest first):

1. `--builder <libkrun|qemu|hvf>` global CLI flag.
2. `MVM_BUILDER_BACKEND=libkrun|qemu|hvf` env var (case-insensitive, whitespace-trimmed; unrecognised values — including any retired backend name — log a warning and fall through to auto-detect).
3. Auto-detect: macOS 26+ Apple Silicon → hvf; Linux → qemu; other macOS → libkrun.

`mvmctl doctor` reports the resolved choice on the `builder backend` line with format `<backend> — <source> — <availability>` so the override path is observable.

**Auto-fallback (ADR-007).** When the _auto-detected_ builder fails to **create its VM** — a VMM-level failure distinct from a `nix build` error — mvm transparently retries the next backend on macOS 26+ (hvf → libkrun). One policy (`builder_attempt_order` + `run_with_builder_fallback`) drives every builder entry point. A genuine build error surfaces unchanged with no retry, and an explicit `--builder` / `MVM_BUILDER_BACKEND` disables the fallback. On Linux the auto-detect default is **qemu**; the rootfs-backed libkrun builder now boots and builds on Linux/KVM (the guest kernel parses libkrun's virtio-mmio cmdline devices, and a poweroff-fallback halt defers to the on-disk build result) and is selectable as an explicit opt-in via `--builder libkrun`.

The backends produce byte-identical `BuilderArtifacts` (kernel + rootfs from the same `nix/images/builder-vm/` flake), so switching backends mid-development is supported.

Persistent builder state dirs live under `~/.mvm/cache/builder-vm/vms/`, distinguished by name prefix (`mvm-persistent-builder-vm-*` for libkrun, `mvm-persistent-builder-hvf-*` for hvf). The Stage 0 reaper (Plan 99 PR-1) is prefix-agnostic so all backends participate in `mvmctl cache prune` without code changes.

## Architecture

### Workspace Structure

17-crate Cargo workspace (Bar-A consolidation took 32→16; `mvm-vmm`, `mvm-backends`, and `mvm-http` were split back out afterwards). Root facade (`src/lib.rs`) re-exports the libraries.

**Libraries, low → high:**

- `mvm-contract` -- `#![no_std]` + alloc, `forbid(unsafe_code)`; the wasm/browser-capable foundation. The audit-log verifier (and, incrementally, the `Workload` IR + wire protocol + policy DTOs). Builds on `wasm32-unknown-unknown`.
- `mvm-core` -- std: types, IDs, config/paths (`MVM_HOME`), crypto, signing, routing. Absorbs `plan` (typed signed `ExecutionPlan`), `policy`, `crypto` (attestation/keystore/secret_store/snapshot + opt-in cosign behind `manifest-verify`). **Default build has no async deps**: `tokio` is optional, pulled only by the off-by-default `hostd-transport` or `manifest-verify` features. `xtask check-core-runtime-free` asserts `cargo tree -p mvm-core -e no-dev` carries no `tokio`.
- `mvm-fs` -- image → mountable rootfs: OCI distribution client (registry/manifest/layer fetch + allow-listed `unpack/`) + a pure-Rust, memory-safe, deterministic ext4 writer (no `mkfs`, no subprocess) + `overlay`. Absorbs the old `mvm-ext4` + `mvm-oci`.
- `mvm-net` -- `NetworkProvider` trait + provisioning/policy/registry seam (vsock/UDS + egress-tunnel plumbing). Was `mvm-network`; the concrete TAP/bridge impl lives in `mvm-runtime`.
- `mvm-build` -- Nix builder pipeline + artifact cache; hosts the builder-VM-only `[[bin]]`s (`mvm-host-vm-init` etc., cfg-gated Linux, cross-compiled + embedded by `mvm-cli/build.rs`).
- `mvm-vmm` -- backend-agnostic VMM device model and hypervisor seam: guest memory, FDT, arm64 kernel loading, virtio-mmio, the `hv::HypervisorVm`/`HypervisorVcpu` traits, the `driver::VmmDriver` seam, and the vsock transport. Low enough that `mvm-backends` can implement a backend without depending on `mvm-runtime`'s orchestration.
- `mvm-backends` -- the concrete VMM mechanics behind that seam (`fc/`, `legacy::{libkrun,qemu,hvf}`, `mock`). Orchestration stays in `mvm-runtime`; this crate owns only how a VM is built and run.
- `mvm-http` -- a minimal HTTP/1.1-over-rustls client, deliberately smaller than a general one (no HTTP/2, redirects, pooling, proxy, compression), to keep the hyper/tower stack out of the shipped `mvmctl` closure.
- `mvm-runtime` -- the big runtime crate (absorbs `mvm` + `mvm-backend` + `mvm-base`): the `VmBackend` trait and the `AnyBackend` dispatch over every backend, VM lifecycle (`vm/` templates + checkpoints), `microvm/` (Firecracker driver), `base/` (shell/ui/linux_env/cow host substrate), `storage/` (dm-thin), `network/` (the TAP/gateway impl behind the `mvm-net` seam). Re-exports the `mvmctl::runtime`/`::backend` contract.
- `mvm-client` -- the local/remote client facade: `LocalBackend` (default) + `GatewayBackend` (the `remote` feature), the canonical host-wide machine inventory (`inventory`, which backs `mvmctl machine ls` and non-CLI consumers), plus a re-export of `mvm-core`'s `MvmClient` trait and its `stream` reader. There is **no `dyn MvmClient` facade in the CLI** — `mvm-cli` uses `AnyBackend` directly for the backend surface, and the routing-everything-through-the-client refactor has not landed. Say what the code does, not what the plan said.
- `mvm-cli` -- Clap CLI (the `mvmctl` surface), bootstrap/doctor/build/run/machine commands; `build.rs` embeds the host binaries.

**Top of graph (daemons, SDK, FFI):**

- `mvm-hostd` -- host-side daemon roles, one crate with separate `[[bin]]`s (the process moat): the `supervisor` + `jailer` libs, the `broker`/`host_signer`/`audit_signer` subprocess bins, and the per-VM supervisor bins `mvm-libkrun-supervisor`/`mvm-hvf-supervisor`. Absorbs `mvm-supervisor`/`mvm-broker`/`mvm-host-signer`/`mvm-audit-signer`/`mvm-jailer-lite`/`mvm-vm-host`.
- `mvm-agentd` -- the in-guest daemon: vsock protocol (`vsock/`), console, integrations, entrypoint runtime, the `mvm-guest-agent` `[[bin]]`, and the addon/egress helper bins (`mvm-addon-dns`/`mvm-addon-vsock-bridge`, gated behind the off-by-default `addons` feature so the sealed agent stays tokio-free). Absorbs `mvm-guest` + `mvm-guest-helpers`.
- `mvm-sdk` -- SDK: decorator parser → canonical `Workload` IR → Nix template, runtime record mode, and the in-guest host-services C-ABI cdylib (`libmvm_host_services.so`) loaded by every language SDK. Language SDK surfaces live under `crates/mvm-sdk/sdks/`.
- `crates/deps/libkrun-sys` -- the libkrun C FFI (bindgen + `-lkrun`, gated by the `libkrun-sys` feature) **plus the safe wrapper** (`KrunContext`/`SupervisorConfig`). Was `mvm-libkrun`; lives low so `mvm-build`/`mvm-runtime` consume the wrapper.

`xtask` -- tooling + claim-gate lints. `mvm-conformance` -- dev-only cucumber-rs BDD harness running the security-claim scenarios against `mvmctl` (not a dependency of any shipped crate).

Root package: `src/lib.rs` (facade: `mvmctl::core`=mvm-core, `mvmctl::runtime`/`::backend`=mvm-runtime, `mvmctl::build`=mvm-build, `mvmctl::guest`=mvm-agentd, `mvmctl::security`=`mvm_core::crypto`) + `src/main.rs` (thin entry → `mvm_cli::run()`).

Binary: `mvmctl` (from root, delegates to mvm-cli)

**Dependency direction (high → low):** `mvm-cli` → {`mvm-runtime`, `mvm-hostd`, `mvm-client`, `mvm-sdk`} → `mvm-client` → `mvm-runtime` → {`mvm-fs`, `mvm-net`, `mvm-build`} → `mvm-core` → `mvm-contract`. `mvm-contract` (no_std) is the foundation; `mvm-core` builds on it. `mvm-agentd` (guest) and the per-role bin crates sit at the top; nothing depends on them as a library.

**Key module locations:**

mvm-contract: `verify` (audit-log verifier), `ir/` (Workload IR), wire/policy DTOs.

mvm-core: `plan/` (ExecutionPlan, bundle, signing, validity), `policy/` (security, audit, network_policy, bundle/resolver), `crypto/` (attestation, keystore, secret_store, snapshot_*), `protocol.rs`, `agent.rs`, `catalog.rs`, `config.rs` (paths/`MVM_HOME`)

mvm-runtime: `backend.rs` (`AnyBackend` dispatch + `FirecrackerBackend`), `driver/` + `workload_runner/` (the converged runner seam every claim-bearing workload boots through), `backends/hvf/`, `wasm_backend.rs`, `apple_container_backend.rs`, `mock.rs`; the libkrun/qemu/hvf VMM impls themselves live in `mvm-backends` (`legacy::{libkrun,qemu,hvf}`) and are re-exported from `lib.rs`. Also `microvm/` (Firecracker driver), `vm/` (templates + `template/lifecycle/`, checkpoints), `agent_session/` (filesystem store for durable agent sessions, the checkpoint analog), `base/` (shell, ui, linux_env, cow), `storage/`, `network/`, `codesign.rs`, `artifacts/`

mvm-fs: `oci/unpack/` (allow-listed unpacker), `oci/`, the ext4 writer, `overlay`

mvm-agentd: `vsock/`, `console.rs`, `integrations.rs`, `src/bin/mvm-guest-agent/` (the agent bin), `runner/`

mvm-hostd: `supervisor/`, `broker/`, `host_signer/`, `audit_signer/`, `jailer/`, `src/bin/{mvm-broker,mvm-host-signer,mvm-audit-signer}.rs`, the per-VM supervisor bins

mvm-cli: `commands/` (env, build/run, `machine`, guest RPC, artifacts/trust, local ops); `doctor/`, `commands/vm/up/`, `commands/image/`, `bench/` are decomposed module trees. Tenant lifecycle + deploy-to-control-plane commands live in mvmd, not mvmctl.

### Trait Architecture

`BuildEnvironment` is split into two traits in `mvm-core/src/build_env.rs`:

```
ShellEnvironment (base)
  shell_exec(), shell_exec_stdout(), shell_exec_visible()
  log_info(), log_success(), log_warn()

BuildEnvironment : ShellEnvironment (extends)
  load_pool_spec(), load_tenant_config()
  ensure_bridge(), setup_tap(), teardown_tap()
  record_revision()
```

- **Dev mode** (`mvmctl build`, `mvmctl machine build`): uses `dev_build()` with `&dyn ShellEnvironment`
- **Fleet mode** (in mvmd): uses `pool_build()` with `&dyn BuildEnvironment`

The `RuntimeBuildEnv` in mvm implements only `ShellEnvironment`. The full `BuildEnvironment` impl lives in mvmd-runtime.

### Key Design Decisions

- **Firecracker-only on Linux; libkrun (macOS 13-25) / HVF (macOS 26+) on macOS**: no Docker/containers on any auto-detected runtime path. The only container-tier backend is `--hypervisor apple-container` (Apple's prebuilt container kernel on the in-house HVF VMM), and `auto_select` returns it only when explicitly selected; it is not a fallback. Builds run Nix inside the builder VM (libkrun on macOS 13-25 / HVF on macOS 26+ / libkrun on Linux, with an auto-fallback to the QEMU builder where libkrun can't create its VM — ADR-007; note the _builder_ VMM is not Firecracker even on Linux). The QEMU/microvm_nix backend (Plan 166) is a **`mvm`-only dev/test backend, never used by `mvmd`** — it carries no untrusted multi-tenant workload. Egress default-deny is enforced at one seam for every workload runner — Firecracker, libkrun, HVF, QEMU, and `apple-container`, which holds an `HvfRunner` and substitutes only the kernel image, so it inherits that seam verbatim: the per-VM `mvm-network-endpoint`, whose shared `EgressGate` is the sole claim-10 decision point. `xtask check-single-network-path` pins every runner to that one spawn site and endpoint binary so a backend cannot grow a second gate. Wasm has no guest network and remains outside the microVM funnel.
- **Workload microVMs have no NIC**: every workload *microVM* backend boots the guest with a virtio-vsock device and **no net device at all** — Firecracker's config sequence omits `/network-interfaces`, libkrun pins `NetworkingMode::VsockDirect` (which never calls a net attach), HVF's device model has no net device (and `apple-container` is that same device model with a different kernel image), and the QEMU workload driver emits no `-netdev`. The non-microVM tiers reach the same end differently: the Wasm tier mediates no networking at all. Egress leaves the guest only over the `NetworkFlow` channel to the host-side endpoint. This is what makes claim 10 (default-deny), claim 13 (no raw secret to the guest), and the audit chain mechanically enforceable: the host endpoint _originates_ every outbound connection, so it can authorize, substitute, and log it. `xtask check-single-network-path` fails closed if a guest NIC, raw-packet stack, alternate spawn implementation, or second workload socket owner appears. The builder VM is the opposite tier and **does** have a NIC — see **Host dependencies**.
- **No SSH in microVMs, ever**: microVMs are headless workloads. No sshd, no SSH keys, no SSH users in any rootfs. Guest communication uses Firecracker vsock only. The builder VM (where Nix builds run) is headless too — no interactive shell or console, just a build engine you debug through its logs. See **Security model** below for the full posture.
- **Builder VM is headless**: there is no interactive shell into it. The builder VM exists solely to run `nix build` on behalf of `mvmctl build` / `mvmctl machine run`; `mvmctl bootstrap` optionally pre-fetches/builds its image ahead of time, but builds auto-bootstrap it on first use if you skip that step. On macOS 26+ Apple Silicon: a long-lived HVF builder VM with Nix + build tools. On other macOS: libkrun builder VM. On Linux with KVM: Firecracker directly. None of these start or SSH into a workload microVM — the builder VM and workload microVMs are always separate.
- **Headless microVMs**: `mvmctl run` and `mvmctl machine start` boot Firecracker as a daemon. Interactive access via `mvmctl machine console` (PTY-over-vsock, dev-mode only).
- **Local-command isolation**: `mvmctl start/stop` use a completely separate code path from orchestration.
- **Shell scripts inside run_in_vm**: complex ops are bash scripts handed to the active `LinuxEnv` backend (libkrun / HVF / Firecracker). Deliberate — they run inside the Linux VM, not on the macOS/Linux host.
- **Idempotent setup**: every step checks if already done before acting.
- **Templates use dev_build path**: `mvmctl build` runs `nix build` locally inside the builder VM (no ephemeral FC builder VMs). The `mvmctl template *` mutation namespace was removed; `template` is a read-only registry browser (`list`/`search`/`info`).
- **mvm-core stays whole**: orchestration types (tenant, pool, instance, agent, protocol) remain in mvm-core even though they're only used by mvmd. This avoids a third shared-types crate and keeps the facade dependency simple.
- **No `clippy::too_many_arguments`**: `#[allow(clippy::too_many_arguments)]` is banned outright — no exceptions in hand-written code (the only legitimate use is bindgen-generated FFI like `crates/deps/libkrun-sys/src/sys.rs`). When a function trips the lint, introduce a dedicated struct with a builder (Rust best practice) carrying those arguments and pass the built value. See AGENTS.md §"Clippy: Zero Warnings, Always".
- **Reuse first — never reimplement what exists**: before writing anything, search the workspace (`rg`, the facade re-exports, the owning module) for a helper, type, trait impl, or crate that already does the job, and call it. Duplicated logic drifts and is this repo's most common bug source. If an existing helper is _almost_ right, extend it — don't fork a second copy. Concrete standing rules: all `~/.mvm` paths go through `mvm-core::config` helpers (`mvm_home`, `vm_state_dir`, `mvm_keys_dir`, `mvm_cache_dir`, …) — never build them inline with `std::env::var("HOME")` + `.join(...)` (that ignores `MVM_HOME` and breaks worktree isolation); shell/VM ops go through the `ShellEnvironment`/`BuildEnvironment` traits.
- **Best-practice construction**: prefer many small single-purpose functions (each trivially unit-testable) over large branchy ones; use the **builder pattern** for types with more than a couple of (especially optional) fields instead of long positional constructors; express behavior that varies by backend/env/mode as a **trait with impls** (`VmBackend`, `ShellEnvironment`), not a `match` scattered across call sites; group related values into named config/params **structs** rather than threading bare arguments through layers; make illegal states unrepresentable with newtypes/enums over stringly-typed flags; and don't over-abstract (YAGNI) — reach for a trait/builder only when there's a real second case. If you can't write a focused test for a function, it's too big — split it. (See AGENTS.md §"Reuse First; Compose Small, Testable Units".)
- **Contributor builds never depend on mvm-published artifacts when matching source is available**: the compiled distribution channel is authoritative. A contributor-built `mvmctl` may detect its source checkout and build source-matched artifacts from the in-repo flakes; an official release binary always downloads verified, version-matched artifacts even when invoked from inside a clone. Filesystem proximity must never turn an official binary into a compiler frontend. A contributor modifying `nix/images/builder-vm/flake.nix` must see their change the next time the builder VM boots — via `mvmctl bootstrap` or auto-bootstrap on the next build — with no release-pipeline round-trip. See ADR-007 §"Two artifact layers, two acquisition paths" for the resolution rule and ADR-007 §"Why the contributor path doesn't download" for the rationale. **One contributor opt-out exists**: `MVM_BOOT_IMAGE=fetch` fetches the published boot image when the image is not what is being worked on and an unconditional image build is pure cost. The fetched image records `source: fetched` in its sidecar, so a stale prebuilt cannot later be mistaken for a build of the working tree; and `mvmctl doctor`'s `boot image` line reports which arm ran and why. Explicit acquisition overrides remain explicit; the channel governs automatic defaults.
- **Host Nix is never used by mvmctl**, even when present: `mvmctl` does not shell out to a host `nix` binary, does not consult `nix-darwin`'s `linux-builder`, and does not honor `nix-daemon` URLs in any code path. Every Nix evaluation goes through a VM we launched; builds run inside that builder VM via libkrun (macOS) or Firecracker (Linux). The reason is determinism and consistency: the same `mvmctl` produces the same artifacts on every host regardless of what the host happens to have installed. A contributor with host Nix installed must not see different behavior from a contributor without it. This invariant supersedes ADR-004's "host Nix remains an opt-in power-user path" clause for everything inside `mvmctl`.

## Security model

mvm makes fifteen CI-enforced security claims (numbered 1–15), plus three
`Preview` claims: 16 (egress-substitution leak-gate, ADR-023), 17
(workload input plane) and 18 (workload resource bounding — admission
ceiling + host-wide budget + spawn-time CPU scope). For all three,
witnesses are machine-checked but
promotion into ADR-001's numbered prose is a pending maintainer
decision, mirroring claim 14's path. Each one is
backed by a test or a workflow gate. **ADR-001
(`specs/adrs/001-microvm-security-posture.md`) is the source of truth**
for the claim numbering, threat model, and per-backend tier matrix;
this section is the summary.

**The ledger is the claims table inside ADR-001**, not a separate
catalog file: `xtask check-claim-catalog` parses that table (rows 1–18,
witnesses spelled `fn:<test_name>` / `ci:<job_name>`) and fails when a
named witness stops existing. `model/claims.toml` is the parallel
conformance ID register that `xtask check-conformance` reads. There is
no `specs/claims/` directory; earlier revisions of this file pointed at
`specs/claims/catalog.md`, which has never existed on this branch.

Keep the ADR-001 table in sync when you rename or move a witness. The
prose below is the narrative and the table is the ledger — and when the
two disagree, **the table is right**: it is gated and the prose is not.
Do not name a test here without checking it exists (`rg 'fn <name>'`);
several of the names below were fabricated and survived for months
precisely because nothing checks this file.

Claim lineage:

- Claims 1–7 ship with ADR-001's original posture.
- Claim 8 was added by the supervisor-wiring plan — see ADR-014
  (`specs/adrs/014-signed-audited-execution-plans.md`).
- Claim 9 (signed bundles content-addressed) is Sprint 52 W2.
- Claim 10 (default-deny egress) is Sprint 52 W3.
- Claim 11 (app-dep volume sealed) was added by ADR-014 / Plan 73
  Followups A + B.1/B.2/B.3 + C + D
  (`specs/adrs/014-signed-audited-execution-plans.md`).
- Claims 12 + 13 (host services broker — binding-gated dispatch and
  no raw secret over broker channel) were added by Plan 104 / ADR-020
  (`specs/adrs/020-host-services-broker.md`) /
  ADR-023 (`specs/adrs/023-secrets-subsystem-egress-substitution.md`).
- Claim 15 (no interactive access to a sealed production microVM) was
  added by Plan 165 WS-C — the same interactive-access threat family as
  claim 4 / `do_exec`.

OCI image provenance recorded in the chain-signed audit log is row 14
of the ADR-001 table, enforced under the claim 8 admission flow.

Companion doc: the Cardoso minimum-viable-policy mapping lives in
ADR-001 §"Appendix: Cardoso minimum-viable-policy checklist".

1. **No host-fs access from a guest beyond explicit shares.** Per-service
   uid (W2.1), seccomp `standard` default (W1.1, W2.4), and `setpriv
--bounding-set=-all --no-new-privs` (W2.3) confine each service.
2. **No guest binary can elevate to uid 0.** `setpriv --no-new-privs`
   in the launch path; `/etc/{passwd,group,nsswitch.conf}` are
   read-only bind-mounts so a compromised service can't mint a uid 0
   entry (W2.2).
3. **A tampered rootfs ext4 fails to boot.** dm-verity sidecar +
   kernel-cmdline roothash + `mvm-verity-init` initramfs (W3 —
   shipped 2026-04-30; see plan 27 and the claim-3 row of
   `specs/adrs/001-microvm-security-posture.md`'s "Claims ledger
   (claim → witness)" table — there is no separate runbook section).
   CI lane `verified-boot-artifacts` in `security.yml` asserts the
   artifacts are emitted; `verify_and_resume_rejects_tampered_mem`
   confirms a tampered snapshot is rejected before resume, and
   live-KVM tamper regression confirms the kernel panics before
   userspace on a flipped data block.
4. **A production-safe run cannot invoke DevOnly guest-agent verbs.**
   `scripts/check-prod-agent-no-exec.sh`, run by the
   `guest-agent-runtime-boundary` job in `.github/workflows/security.yml`,
   exercises the universal agent's runtime profile and signed grant boundary
   (W4.3). The unit and conformance tests enumerate the complete DevOnly
   request set.
5. **Vsock framing + supervisor-config JSON are fuzzed.** `cargo-fuzz`
   targets at `crates/mvm-agentd/fuzz/` cover `GuestRequest` and
   `AuthenticatedFrame` (W4.2). Plan 88 W6 adds
   `crates/deps/libkrun-sys/fuzz/fuzz_targets/fuzz_supervisor_config.rs` against the
   host-side `SupervisorConfig` parser the `mvm-libkrun-supervisor`
   binary reads on stdin. `#[serde(deny_unknown_fields)]` on every
   host↔guest type ensures unexpected fields fail-closed (W4.1). The
   third-party virtio-net frame parsers this section used to track as
   an upstream fuzz gap are no longer reachable from any lane: the
   userspace network gateways were deleted along with the guest-NIC
   path, so there is no in-tree caller and no frame for them to parse.
   `specs/adrs/003-hypervisor-egress-policy.md` is written around the
   vsock-only chokepoint.
6. **Pre-built dev image is hash-verified.** No function named
   `download_dev_image` exists; the real pipeline is
   `fetch_expected_hashes` + `verify_artifact_hash`
   (`crates/mvm-cli/src/commands/env/artifact_verify.rs`), which fetch
   the per-arch `*-checksums-sha256.txt` manifest, stream the
   artifact through SHA-256, and reject + delete on mismatch (W5.1).
   The builder-VM/dev-image orchestration in
   `crates/mvm-cli/src/commands/env/builder_vm/stage0_cache.rs`
   (`download_builder_vm_image`) and `.../builder_vm/default_microvm.rs`
   call them. `MVM_SKIP_HASH_VERIFY=1` is the documented emergency
   escape; never set it in CI.
7. **Cargo deps are audited on every PR.** `deny.toml` + the `deny`
   and `audit` jobs in CI (W5.2). Reproducibility double-build
   (W5.3) catches non-determinism that could mask injection.
8. **Every workload runs from a signed, audited `ExecutionPlan`.**
   `mvmctl machine run` synthesizes a typed `ExecutionPlan`, signs it under
   the host's Ed25519 keypair at `~/.mvm/keys/host-signer.ed25519`
   (mode 0600), verifies it through `mvm_core::plan::verify_plan`
   (`mvm_plan` is not a crate — `plan` is a module of `mvm-core`),
   enforces the G4 validity window + nonce replay-store, and only
   then dispatches the backend. Each admission emits
   `plan.admitted` / `plan.launched` / `plan.failed` chain-signed
   entries to `~/.mvm/audit/<tenant>.jsonl`; tampering breaks
   `mvm_hostd::supervisor::verify_audit_chain` (surfaced via
   `mvmctl trust audit verify`, which exits nonzero on detected drift).
   The chain rotates into sequenced segments once the active file reaches
   `MVM_AUDIT_SEGMENT_BYTES` (4 MiB default): `<tenant>.seg-NNNNNN.jsonl`
   beside the live `<tenant>.jsonl`. Nothing is deleted — rotation only
   splits. Every segment after the first opens with a signed
   `chain.continued` record naming its predecessor and that predecessor's
   final chain hash, so `verify_audit_chain` attests "unbroken from
   genesis **or** from a signed handoff", and `verify_segment_set` attests
   the set is ordered and complete: a removed segment is reported by
   number rather than passing silently. `mvmctl doctor` checks the live
   segment plus the handoffs and says that is what it checked;
   `mvmctl trust audit verify` walks every retired interior. Tail
   truncation stays undetectable, exactly as it was before rotation
   (Plan 319).
   Workspace `cargo test` exercises rejection paths on every PR
   (plan 64 W1–W4 — `synthesize_plan`, `host_signer::load_or_init_at`,
   `admit_for_run`, `AuditEmitter`; `xtask check-no-display-on-secret-types`
   protects the host signer's redacted `Debug`).
9. **Every published bundle is content-addressed, key_id-pinned, and
   re-verified at fetch and at admit time.** Sprint 52 W2 +
   admit-time re-verify follow-on.
   `mvm_core::plan::bundle::read_and_verify_bundle`
   - `mvm_core::plan::bundle::verify_plan_bundle` exercise the
     rejection ladder on every PR: unknown-key, tampered manifest,
     key_id mismatch, tampered artifact, missing artifact, unsafe
     path, schema bump, pin-archive sha256 drift, pin-signature
     drift. `mvmctl bundle fetch` round-trip + `admit_for_run` tests
     assert refusal on pin-without-context and pin-archive mismatch.
10. **No untrusted workload reaches the network unless explicitly
    admitted by policy.** Sprint 52 W3. `policy_default_is_deny_all`
    and `run_net_default_is_deny_all` (the ADR-001 row's witnesses)
    assert the default-deny posture. An unrecognised preset name refuses
    rather than falling through to a permissive default, at the CLI and on
    the wire alike (`crates/mvm-contract/tests/egress_predicate_algebra.rs`).

    This bullet used to claim that "`mvmctl up` emits an opt-in warning when
    the resolved policy is `unrestricted`", with an escape hatch of
    `MVM_ACK_UNRESTRICTED_NETWORK=1`. **None of that exists.** `up` is not a
    dispatched verb — `up::Args` is not a `Commands` variant, so its
    `--network-preset` and `--network-allow` fields are unreachable CLI
    surface. `MVM_ACK_UNRESTRICTED_NETWORK` is read nowhere in the workspace;
    its only occurrence is a doc comment in `mvm-contract::stream::edge`
    saying another mechanism is "shaped after" it. There is no unrestricted
    acknowledgement, so nothing is being bypassed — but nothing warns either,
    and `specs/plans/296` cites the non-existent hatch as prior art for its
    E7 redaction opt-out. Building the acknowledgement is Plan 306 WS5.
    Cardoso-flavoured
    audit of DNS / vsock control-plane carve-out / Plan 104 broker
    channels as covert egress is tracked in Plan 111 Workstream A.
11. **Every application-dep volume is hash-locked, attestation-checked,
    CVE-scanned, SBOM-enumerated, and bound to the workload's audit
    chain.** ADR-014 / Plan 73 Followups A + B.1/B.2/B.3 + C + D wire
    this end-to-end: the builder VM (`mvm-host-vm-init` +
    `LibkrunBuilderVm::run_build` Install arm) installs deps into a
    sealed volume at `~/.mvm/volumes/deps/<volume_hash>/` carrying
    `content/`, `sbom.cdx.json`, `fetch.log`, `cve.json`, and a
    hash-chained `meta.json`; `mvm-hostd`'s supervisor admission verifier
    calls `mvm_sdk::compile::deps_audit::verify_sealed_volume` before
    launch and refuses tampered volumes; `mvmctl machine run --prod` fails
    closed on high/critical CVE findings or stub SBOM/CVE
    (`mvm_build::app_deps_gate::apply_install_gate`); `mvmctl deps
   inspect` / `mvmctl deps audit` surface the sealed sidecars without
    a VM spawn. The `app-deps-audit` job lives in
    `.github/workflows/security.yml` (Followup D), not `ci.yml` — it runs
    on the nightly cron and on release tags, so this lane does **not**
    gate every PR. It lived in `ci-full.yml` until 2026-08-21, which was
    `workflow_dispatch`-only and had been triggered zero times since it
    was written: ADR-001's ledger cited `ci:app-deps-audit` for claim 11
    the whole time, against a lane that had never once run. (`ci-full.yml`
    still exists, as `Extended CI`, and now runs nightly — it kept the
    lanes that are neither security-bearing nor duplicated by `ci.yml`,
    including the repository's only macOS coverage.) It exercises
    `mvmctl build compile` on
    `examples/python/hello-app-with-deps/`, seals a clean + a high-CVE
    fixture via `mvm-build`'s `mvm-app-deps-fixture-tool` example,
    asserts `mvmctl deps inspect --json` reports a well-formed report,
    asserts the prod gate refuses the high-CVE fixture and the dev
    gate admits it, and asserts a byte-flip on `cve.json` makes
    inspect refuse via `verify_sealed_volume`. Full builder-VM round-trip
    (real `uv pip install` + `pip-audit` inside the libkrun /
    cloud-hypervisor builder VM) is still gated on Plan 72 W4/W5
    cutover; the CI lane exercises every code path that doesn't
    require a working microVM backend.
12. **Every host-side service the broker exposes is bound to a signed
    `ExecutionPlan.services` binding, enforced before handler
    dispatch, and audited via the chain-signed log.** Plan 104 W2 /
    ADR-020. Witnesses, per the ADR-001 row:
    `unbound_service_returns_not_bound` and
    `service_call_rejects_unknown_envelope_fields`.

    Earlier revisions of this bullet named — in quotes rather than
    backticks, because backticks assert a real identifier and these are
    names nobody ever wrote —
    "service_call_denied_when_unbound",
    "service_call_denied_outside_profile",
    "audit_chain_contains_service_call_entries",
    `audit_chain_carries_no_payload_bytes`, a `fuzz_service_call.rs`
    target, and three `xtask check-handler-*` gates. **None of them
    exist**, and none ever did on this branch. The ADR-001 row was
    always correct, so `check-claim-catalog` never went red — only this
    file was wrong, which is why the ledger and not the narrative is
    authoritative. Payload-freedom for the stream plane's own audit
    entries is witnessed by
    `stream_audit_entries_carry_the_binding_and_no_payload_bytes`.

13. **No raw secret value crosses the broker channel.**
    `host.secrets.v1` returns destination-bound, time-bound signed
    credentials only; raw secret bytes never leave the supervisor's
    address space. Plan 104 W5 / ADR-023 / ADR-020. Witnesses, per the
    ADR-001 row:
    `encode_secret_env_cmdline_round_trips_pairs_as_single_token` and
    `substitute`. The six test names this bullet used to list
    ("host_secrets_v1_denied_outside_allowed_destinations",
    "zeroize_drop_zeros_secret_bytes",
    "handler_inter_call_memory_hygiene",
    "host_secrets_v1_signed_payload_jcs_roundtrip",
    "secrets_subprocess_cannot_reach_supervisor_memory",
    "placeholder_in_outbound_request_dropped_and_audited") do not exist
    in the tree — same failure as claim 12's.
14. **Every `mvmctl run --image <oci-ref>` admission records the OCI
    image provenance in the chain-signed audit log.** Row 14 of the
    ADR-001 table. Plan 85 Phase E + F wire the user-facing OCI image
    runner to the same audit chain that backs claim 8.
    `mvmctl image pull` materializes the layer set in `mvm-fs`'s
    allow-listed unpacker (`mvm_fs::oci::unpack::unpack_layer`),
    materializes an ext4 rootfs — by default in-process on the host
    via the memory-safe pure-Rust writer (`mvm_build::rootfs::
materialize_ext4_pure`; ADR-004 supersedes ADR-017's builder-VM
    `mkfs` mechanism while preserving its roothash guarantee, and
    auto-falls-back to the builder VM for trees the writer can't
    faithfully emit, e.g. ones carrying `security.capability`
    xattrs) — and persists provenance metadata (registry host, repo, supplied
    reference, resolved manifest digest, layer digest list, trust
    policy, cosign verdict). `mvmctl run --image` admits an
    `ExecutionPlan` (claim 8 path) and then emits a
    `plan.oci_provenance` entry via
    `AuditEmitter::emit_oci_provenance`
    (`crates/mvm-cli/src/commands/vm/audit_chain.rs`) carrying those
    labels; `mvm_hostd::supervisor::verify_audit_chain` continues to detect
    drift, surfaced via `mvmctl trust audit verify`. `--prod` refuses
    mutable references before any network fetch
    (`crates/mvm-cli/src/commands/image/pull_core.rs::
prod_pull_requires_digest_pin_before_network` and
    `prod_run_image_requires_digest_pin_before_network` — `image` is a
    directory of modules, not a single `image.rs` file), demands an
    explicit registry policy, and requires cosign verification of the
    resolved digest before cache admission or boot. The OCI
    `unpack_layer` fuzz harness lives in
    `.github/workflows/security.yml`'s `fuzz` job (release-tag pushes
    - nightly cron + manual dispatch); the six OCI hardening lanes
      (`layer-unpack-adversarial`, `digest-mismatch-reject`,
      `malformed-manifest`, `mutable-tag-prod-reject`, `reproducibility`,
      `image-runner-smoke`) are the `oci-hardening` matrix in
      `.github/workflows/security.yml`, not `ci.yml` — so none of the six
      gate a PR; they run nightly and on release tags. They were six
      separate dispatch-only jobs in `ci-full.yml` until 2026-08-21 and
      had never been run. Note that ADR-001's ledger does not cite them:
      claim 14's row names no `ci:` witness, so this paragraph is prose
      about lanes the gate does not check, and the table is what binds.
15. **A sealed production microVM has no shell, no DevOnly guest-agent
    verbs, and no PTY.** The sole
    interactive path into a guest is the agent-served PTY-over-vsock
    console (`crates/mvm-agentd/src/console.rs`). The universal agent
    dispatches it only when the runtime profile and signed grant authorize
    the request. Plan 165 WS-C. Five independent layers: (1) only the dev `/init`
    variant serves a shell; (2) the prod rootfs is dm-verity sealed
    (claim 3); (3) the backend captures the guest console **write-only**
    to `console.log` with no host input fd
    (`mvm_runtime::libkrun::open_console_capture` — `mvm_backend` is
    not a crate, this is a function in `mvm-runtime` — and
    `following_the_console_never_writes_to_it`); (4) the host
    `enforce_accessible_gate` refuses `mvmctl machine console` on a sealed VM
    (`console_refused_on_sealed_image`); (5) the agent console and DevOnly
    handlers are grant-gated. CI: the `guest-agent-runtime-boundary` job in
    `.github/workflows/security.yml` runs the runtime refusal suite.
    Serial-console passthrough
    was considered and rejected (fatal on an input-less console); there
    is exactly one interactive transport and it is dev-only.
    This claim used to read "no interactive access", holding by
    **absence** — a sealed VM had no host→guest byte path at all. The
    workload input plane built one, so the claim shrank to the part that
    still holds by absence, which is what its three witnesses check. The
    input plane's own properties (stdin only, no program selection, no
    argv or env change, refused without a plan grant) are policy enforced
    by host code, and are claimed separately as `Preview` claim 17 with
    their limits.

`Preview` claim 17 — **workload stdin is grant-gated, single-writer,
secret-scanned across frames, and every refusal audited**
(`crates/mvm-hostd/src/stream/input_gate.rs`). Every leg has a production
caller: `mvmctl machine run --entrypoint --stdin -` opens the route under the
plan that boot was admitted under, the sealed-tier shell-entrypoint refusal
classifies an entrypoint resolved from the image's own `mvm-meta.json`
sidecar and fails closed when it cannot resolve one, and the secret scan is
populated — the per-VM substitution endpoint (the one process holding a
workload's credentials in the clear) fingerprints each secret it resolves
and `StreamPlane::open_input` installs that set. Only the fingerprint — a
length, a rolling hash and a category — crosses into the scanning process;
never a value. It stays a preview and not a numbered claim because of what
the enforcement is rather than whether it runs: a fingerprint match is a
length-and-hash match, not an identity, and encoding, derivation and a
window-straddling split defeat the scan permanently. ADR-001's ledger
carries the full limits note, marked closed or open individually; do not
paraphrase this row as enforced without it.

`Preview` claim 18 — **a workload's resource consumption is bounded at
admission, and bound at spawn where the host has a mechanism**. Admission
is the strong half and holds everywhere: an operator-configured
per-workload ceiling (`max_cpu_millicores` / `max_memory_mib` /
`max_wall_clock_secs`) plus a host-wide budget
(`host_budget_memory_mib` / `host_budget_cpu_millicores`) that refuses a
boot whose memory, on top of every live machine's admitted charge, would
exceed the headroom (`crates/mvm-hostd/src/admission_budget.rs`). The
budget counts only machines carrying a live pid marker — the same probe
the fork path trusts, so a crashed VM cannot lock the host out — and
counts each machine's configured maximum rather than the balloon's
current commitment. CPU is the partial half: a granted share wraps the VMM spawn in a
systemd transient scope on Linux and the achieved tier is read back off
`cpu.max`. On the in-house HVF VMM on macOS there is no host-level quota
primitive, so the run loop enforces the share in-process using the vCPU
thread's Mach CPU time; the achieved tier is read back from the scheduler's
measured record and audited. libkrun has no in-process vCPU control, so a CPU
grant there stays `declared` and `--prod` refuses it. Wall clock is enforced
by the per-VM supervisor on libkrun and HVF: the process that owns the guest
for its whole life arms a timer from the admitted plan, and a workload that
outruns its bound is killed with exit `124` and a chain-signed entry. A bound
whose kill could not be audited refuses to boot rather than running unbounded.
Firecracker has no such supervisor process and is not covered. wasm
fuel/epoch is declared and unwired, and a restored or warm-claimed child is
admission-bounded without its host-side CPU control **or its wall-clock
timer** being re-armed — a restore deliberately does not inherit the parent's
plan, since auditing a child's kill under its parent's identity would write a
wrong entry rather than a missing one.
ADR-001's ledger carries the "Preview 18 limits" note; do not paraphrase
this row as enforced without it.

The guest agent itself runs as uid 901 under setpriv (W4.5); the
host-side vsock proxy socket is mode 0700 (W1.2), the proxy port
allowlist drops anything outside the agent and forward ranges
(W1.3), and `~/.mvm` (and every child, `~/.mvm/cache` included) is mode 0700 (W1.5).

Out of scope (named in ADR-001):

- A malicious _host_. mvmctl trusts the host with the hypervisor and
  private build keys.
- Multi-tenant guests. One guest = one workload.
- Hardware-backed key attestation.

`mvmctl doctor` reports the live posture on the running host
(plan 40 folded the standalone `security` verb into doctor's
unified diagnostics report). Architecture detail, the claims ledger,
and the per-backend tier matrix are all in
`specs/adrs/001-microvm-security-posture.md`.

## Testing

No task is done without tests. Before marking any feature complete:

```bash
cargo fmt --all -- --check           # workspace-wide fmt; --all matters
cargo nextest run --workspace        # all tests must pass (process-parallel)
cargo test --workspace --doc         # doctests — nextest does NOT run these
cargo clippy --workspace -- -D warnings  # zero warnings
```

`cargo nextest run --workspace` (what `just test` and CI run) is the named
test gate — it's process-parallel and faster than `cargo test` on this
~4,350-test suite. The one gap: **nextest skips doctests**, so the
`cargo test --workspace --doc` line above (wrapped as `just test-doc`, and
folded into `just ci`) keeps doc-fence coverage gated. `cargo test
--workspace` still works as a fallback if nextest isn't installed.

For fast inner-loop iteration across worktrees, `just test-cached` wraps rustc
in sccache to share compilation across branches (needs `cargo install
sccache`).

**`--all-targets` has two blind spots**, and a change to a shared type's shape
(a new struct field, trait method, or enum variant) walks into both. It skips
any target behind `required-features` — `mvm-conformance`'s cucumber runner
needs `--features bdd`, and without it the same broken tree reports zero
errors — and on macOS it cannot compile `cfg(target_os = "linux")` files at
all, including Linux-gated *test* files, which `just check-linux` misses too
because that recipe is `--lib` only. `just check-gated` covers both. Skipping
it surfaces in CI as `check-nextest-groups` failing with "cargo nextest list
failed", a message that names neither the file nor the field.

**Always pass `--all` to `cargo fmt`.** Without it, fmt only checks the
manifest crate (whichever one the manifest points at), silently missing
drift in every other workspace member. CI runs `cargo fmt --all --
--check`; if you only check the local crate, the merge will still fail.
The pre-commit hook at `.githooks/pre-commit` auto-fixes with `cargo
fmt --all` and re-stages — `just install-hooks` wires
`core.hooksPath` to `.githooks/` so it fires on every commit.

The Justfile recipes wrap this correctly: `just fmt-check`, `just
clippy`, `just lint` (both), `just ci` (lint + test + doctests). Prefer
those over raw cargo invocations.

Every new module, type, or function needs test coverage:

- Types: serde roundtrip, default values
- Protocol/wire code: mock I/O roundtrip, tampered data rejection, error paths
- CLI: integration tests in `tests/cli.rs` for help text and argument parsing
- Security: positive path, negative path (wrong key, tampered, replay), edge cases

## Scratch & temporary files

Never write scratch, temporary, or intermediate files anywhere inside the repo working tree — not the root, not a subdirectory, not a hidden dotfile, not a gitignored path. This covers **every** kind of agent-created scratch (analysis lists, command output, intermediate JSON/TSV, logs, ad-hoc scripts, `git merge-file` inputs), not just screenshots/binaries. Write them under `/tmp/` instead. See AGENTS.md §"Screenshots & Temporary Files" for the full rule.

## Build and Run

```bash
cargo build
cargo run -- --help   # full verb surface: build/run/template/image/network/console/init/cache/doctor/…
```

Every subcommand is self-documenting via `--help`; the complete reference is
`public/src/content/docs/reference/cli-commands.md`. Build-time verbs
(`image`/`run`/`template`) live under `build`; `console` is an interactive PTY,
dev-mode only.

## Dev Network Layout

```
MicroVM (172.16.0.2, eth0)
    | TAP interface
Builder VM (172.16.0.1, tap0) -- iptables NAT -- internet
    | libkrun (macOS 13-25) / HVF (macOS 26+) / direct (Linux KVM)
macOS / Linux Host
```

## Documentation

- `public/src/content/docs/contributing/development.md` -- contributor guide, testing, CI/CD
- `public/src/content/docs/guides/nix-flakes.md` -- writing Nix flakes for microVM images (mkGuest API)
- `public/src/content/docs/guides/troubleshooting.md` -- common issues and fixes
- `public/src/content/docs/contributing/adr/001-firecracker-only.md` -- ADR: Firecracker-only execution
- `public/src/content/docs/reference/cli-commands.md` -- complete CLI command reference
- `specs/plans/` -- implementation specs and plans

## Naming a new plan

**Name it by slug, not by number**: `specs/plans/2026-08-15-sdk-surface-generated-from-rust.md`.
A date prefix keeps plans sorting chronologically, which is the only thing the
numbers were really giving.

Numbers were a sequential id picked at authoring time, and this repo adds
roughly three plans a day across concurrent branches — so two authors routinely
picked the same next-free number, and neither could see the other's claim until
its PR opened. 18 numbers ended up shared by two plans. Scanning open PRs before
picking does not fix it: a branch that has claimed a number and not yet opened
its PR is invisible to any scan.

The plans that already carry numbers keep them — renaming them would invalidate
hundreds of `Plan NNN` references for no benefit. `xtask check-plan-names`
freezes that set and fails a *new* number-named plan. Refer to a plan by its
path or title rather than a bare number.

## Sprint Management

- Active sprint spec: `specs/SPRINT.md`
- Completed sprints archived to: `specs/backlog/` (e.g. `specs/backlog/01-foundation.md`)
- When a sprint is completed, rename `specs/SPRINT.md` to `specs/backlog/<NN>-<name>.md` and create a new `specs/SPRINT.md` for the next sprint
- **Record what you delivered in its own file: `specs/sprint/delivery/<issue>-<slug>.md`.**
  Do **not** append to `specs/SPRINT.md` — its delivery section is a closed
  archive and `xtask check-sprint-append` fails if it grows. One append point
  shared by every concurrent session conflicted on essentially every rebase, and
  because a rebase forces a full re-gate, a paragraph of prose cost the other
  sessions ~20 minutes of re-proving code that had not changed. Separate files
  cannot collide. Read them together with `cargo run -p xtask -- sprint`.
- **Keep the rest of `specs/SPRINT.md` current as you work.** After completing any
  phase, task, or sub-task, reflect it in the active sprint spec in the SAME
  change: check off items (`- [x]`), update status labels (e.g.
  `**Status: COMPLETE**`), and add new test counts or notes. The sprint spec must
  always match what is actually implemented — see AGENTS.md §"Definition of Done"
  items 5–7, which bind the sprint spec, the plan checkboxes, and
  `specs/REFACTOR-STATUS.md` together.
- **Resolve a conflict in any of these by keeping BOTH sides.** Never take one
  side wholesale: upstream may have *rewritten* an entry your branch also edited,
  so `--ours`/`--theirs` silently drops someone's work. Verify after resolving
  that both entries are still present.

## Refactor status

We are in the middle of a major multi-plan refactor. `specs/REFACTOR-STATUS.md`
is the hand-maintained rollup of every in-flight plan's workstream checkboxes.
**Keep it current.** Whenever you land, merge, or descope a workstream in any
plan, tick/strike the matching box in `specs/REFACTOR-STATUS.md` in the SAME
change and bump its "Last updated" date. It is a quick index, not the source of
truth — if it disagrees with a `specs/plans/` doc, the plan doc wins; fix the
rollup. `specs/REFACTOR-STATUS.md` and `specs/SPRINT.md` move together with the
plan checkboxes — updating one and leaving the others stale is not done.
