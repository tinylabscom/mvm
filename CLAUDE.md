# mvm -- Firecracker MicroVM Development Tool

## Project Overview

Rust CLI for building and running Firecracker microVMs on macOS and Linux. Handles the full dev lifecycle: bootstrapping, Nix-based image builds, single-VM management, and reusable template creation.

Multi-tenant fleet orchestration (tenants, pools, instances, agents, coordinators) lives in the separate [mvmd](https://github.com/tinylabscom/mvmd) repository.

```
macOS Host (this CLI) -> libkrun Linux VM -> Firecracker microVM (/dev/kvm)
Linux Host (this CLI) -> Firecracker microVM (/dev/kvm)
```

Lima was the historical macOS host abstraction. It was removed on 2026-05-14 (Plan 72 W0–W6 + Plan 75 W0). libkrun is the default macOS backend; Apple Container is the macOS 26+ Apple Silicon backend; Firecracker is the Linux KVM path. There is no `--lima` flag and no Lima fallback.

## Host dependencies (macOS)

`mvmctl dev up` and the libkrun-backed builder VM need three Homebrew packages installed:

```sh
brew install slp/krun/libkrun slp/krun/libkrunfw slp/krun/gvproxy
```

- `libkrun` — the in-process VMM. `mvm-libkrun-supervisor` links against it.
- `libkrunfw` — bundles the TSI-patched Linux kernel libkrun's guests boot. Plan 86 / Plan 72 W5.D bullet 10 — `mvm-libkrun::extract_bundled_kernel()` pulls the kernel out of the dylib's `.rodata` at runtime.
- `gvproxy` — userspace virtio-net gateway. Plan 88 / ADR-055 §"Cross-platform backends" — passt is Linux-only, so macOS dispatches to gvproxy via libkrun's `krun_add_net_unixgram` path. `MVM_NETWORKING` unset → per-OS default (macOS=gvproxy, Linux=passt); only `passt` and `gvproxy` are accepted. Plan 102 W6.A removed the `tsi` mode (TSI bypassed virtio-net entirely, violating the claim-10 no-bypass invariant — see ADR-058).

On Linux contributor hosts swap `gvproxy` for `passt` from the distro
package manager (or build passt from source — see ADR-055 references).

`mvmctl doctor` probes the right gateway per OS and emits install hints when missing.

For source-checkout contributors only: zig + cargo-zigbuild are needed
at `cargo build`-of-mvmctl time so `crates/mvm-cli/build.rs` can
cross-compile the embedded host-vm binaries (`mvm-host-vm-init`,
`mvm-egress-proxy`) for aarch64-unknown-linux-gnu. See
Plan 115 / ADR-065.

```sh
brew install zig
cargo install cargo-zigbuild
```

End-users running a downloaded mvmctl don't need either tool — the
binaries are already embedded.

**macOS 26+ Apple Silicon** users can skip the `slp/krun/*` Homebrew trio when running with the Vz builder backend (the auto-detect default on that tier — see "Builder backend selection" below). Apple Virtualization.framework ships with the OS and needs no separate library install. The Homebrew trio is still required if you explicitly opt back into libkrun via `--builder libkrun` or `MVM_BUILDER_BACKEND=libkrun`.

## Builder backend selection (Plan 98)

The builder VM (the Linux guest that runs `nix build` inside `mvmctl build` / `mvmctl up` / `mvmctl dev`) picks between two host VMMs:

- **libkrun** — third-party in-process VMM via the Homebrew trio above. Default on Linux + macOS 13-25. Works everywhere mvm runs.
- **Vz** — Apple Virtualization.framework. Default on macOS 26+ Apple Silicon (mirrors the Apple Container runtime tier). macOS-only.

Selection priority (highest first):

1. `--builder <libkrun|vz>` global CLI flag.
2. `MVM_BUILDER_BACKEND=libkrun|vz` env var (case-insensitive, whitespace-trimmed; unrecognised values log a warning and fall through to auto-detect).
3. Auto-detect: macOS 26+ Apple Silicon → Vz; everywhere else → libkrun.

`mvmctl doctor` reports the resolved choice on the `builder backend` line with format `<backend> — <source> — <availability>` so the override path is observable.

Vz on macOS 13-25 is opt-in only via the flag/env override — auto-detect won't pick it because the deployment baseline is macOS 26+. The two backends produce byte-identical `BuilderArtifacts` (kernel + rootfs from the same `nix/images/builder-vm/` flake), so switching backends mid-development is supported.

Persistent builder state dirs live under `~/.cache/mvm/builder-vm/vms/`, distinguished by name prefix (`mvm-persistent-builder-vm-*` for libkrun, `mvm-persistent-builder-vz-*` for Vz). The Stage 0 reaper (Plan 99 PR-1) is prefix-agnostic so both backends participate in `mvmctl cache prune` without code changes.

## Architecture

### Workspace Structure

5-crate Cargo workspace with root facade:

- `mvm-core` -- pure types, IDs, config, protocol, signing, routing (NO runtime deps)
- `mvm-guest` -- vsock protocol, integration manifest/state (OpenClaw)
- `mvm-build` -- Nix builder pipeline (dev_build uses `ShellEnvironment` trait, pool_build uses `BuildEnvironment`)
- `mvm` -- shell execution, builder-VM / Firecracker VM lifecycle, UI, template management
- `mvm-cli` -- Clap CLI, bootstrap, update, doctor, template commands

Root package: `src/lib.rs` (facade re-exports `mvmctl::core`, `mvmctl::runtime`, `mvmctl::build`, `mvmctl::guest`) + `src/main.rs` (thin CLI entry -> `mvm_cli::run()`)

Binary: `mvmctl` (from root, delegates to mvm-cli)

**Dependency graph:**
```
mvm-core (foundation, no mvm deps)
├── mvm-guest (core)
├── mvm-build (core, guest)
├── mvm (core, guest, build)
└── mvm-cli (core, runtime, build)
```

**Key module locations:**

mvm-core: `build_env.rs` (ShellEnvironment + BuildEnvironment traits), `pool.rs`, `instance.rs`, `tenant.rs`, `template.rs`, `naming.rs`, `signing.rs`, `routing.rs`, `protocol.rs`, `agent.rs`, `catalog.rs` (image catalog), `dev_network.rs` (named networks), `config.rs` (XDG directory functions)

mvm: `shell.rs`, `config.rs`, `ui.rs`, `build_env.rs` (DevShellEnv impl), `vm/microvm.rs`, `vm/bridge.rs`, `vm/overlay.rs`, `vm/instance/`, `vm/template/`. Hypervisor backends live in `mvm-backend/` (`libkrun.rs`, `firecracker.rs`, `apple_container.rs`, `docker.rs`) and `mvm-libkrun/`.

mvm-build: `dev_build.rs` (local Nix builds via ShellEnvironment), `build.rs` (orchestrated builds via BuildEnvironment), `nix_manifest.rs`, `scripts.rs`

mvm-guest: `vsock.rs`, `console.rs` (PTY-over-vsock), `integrations.rs`, `builder_agent.rs`

mvm-cli: `commands/` (local microVM substrate commands: env, build/run, guest RPC, artifacts/trust, local ops). Tenant lifecycle, tenant policy authoring/review, and deploy-to-control-plane commands live in mvmd, not mvmctl.

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

- **Dev mode** (`mvmctl build`, `mvmctl template build`): uses `dev_build()` with `&dyn ShellEnvironment`
- **Fleet mode** (in mvmd): uses `pool_build()` with `&dyn BuildEnvironment`

The `RuntimeBuildEnv` in mvm implements only `ShellEnvironment`. The full `BuildEnvironment` impl lives in mvmd-runtime.

### Key Design Decisions

- **Firecracker-only on Linux; libkrun/Apple Container on macOS**: no Docker/containers on the runtime path. Builds run Nix inside the builder VM (libkrun on macOS, Firecracker on Linux KVM).
- **No SSH in microVMs, ever**: microVMs are headless workloads. No sshd, no SSH keys, no SSH users in any rootfs. Guest communication uses Firecracker vsock only. The dev environment is the builder VM (`mvmctl dev` / `mvmctl dev shell`), not the microVM. See **Security model** below for the full posture.
- **Dev mode**: `mvmctl dev` (or `mvmctl dev up`) auto-bootstraps then drops into a dev shell. On macOS 26+ Apple Silicon: boots an Apple Container with Nix + build tools via PTY-over-vsock console. On other macOS: libkrun builder VM. On Linux with KVM: Firecracker directly. `mvmctl dev down` stops it. `mvmctl dev shell` opens a shell. `mvmctl dev status` shows environment info. It does NOT start or SSH into a Firecracker microVM.
- **Headless microVMs**: `mvmctl start` and `mvmctl run` boot Firecracker as a daemon. Interactive access via `mvmctl console` (PTY-over-vsock, dev-mode only).
- **Dev mode isolation**: `mvmctl start/stop/dev` use a completely separate code path from orchestration.
- **Shell scripts inside run_in_vm**: complex ops are bash scripts handed to the active `LinuxEnv` backend (libkrun / Apple Container / Firecracker). Deliberate — they run inside the Linux VM, not on the macOS/Linux host.
- **Idempotent setup**: every step checks if already done before acting.
- **Templates use dev_build path**: `mvmctl template build` runs `nix build` locally inside the builder VM (no ephemeral FC builder VMs).
- **mvm-core stays whole**: orchestration types (tenant, pool, instance, agent, protocol) remain in mvm-core even though they're only used by mvmd. This avoids a third shared-types crate and keeps the facade dependency simple.
- **No `clippy::too_many_arguments`**: never suppress this lint. Refactor into smaller functions or a config/params struct.
- **Source-checkout builds never depend on mvm-published artifacts**: when `mvmctl` is run from a source checkout of this repo (anywhere `find_dev_image_flake()` / `find_builder_vm_flake()` returns `Some`), every VM image is built locally from the in-repo flakes — both the builder VM image (`nix/images/builder-vm/`) and the user-facing image (`nix/images/dev-shell/`, user `--flake`, etc.). The mvm-published prebuilts on GitHub releases are end-user infrastructure only; they are never a prerequisite for any source-checkout workflow. A contributor modifying `nix/images/builder-vm/flake.nix` must see their change in the very next `mvmctl dev up` with no release-pipeline round-trip. See ADR-046 §"Two artifact layers, two acquisition paths" for the resolution rule and ADR-046 §"Why the contributor path doesn't download" for the rationale.
- **Host Nix is never used by mvmctl**, even when present: `mvmctl` does not shell out to a host `nix` binary, does not consult `nix-darwin`'s `linux-builder`, and does not honor `nix-daemon` URLs in any code path. Every Nix evaluation goes through a VM we launched; builds run inside that builder VM via libkrun (macOS) or Firecracker (Linux). The reason is determinism and consistency: the same `mvmctl` produces the same artifacts on every host regardless of what the host happens to have installed. A contributor with host Nix installed must not see different behavior from a contributor without it. This invariant supersedes ADR-013's "host Nix remains an opt-in power-user path" clause for everything inside `mvmctl`.

## Security model

mvm makes thirteen CI-enforced security claims. Each one is backed by
a test or a workflow gate. **ADR-002
(`specs/adrs/002-microvm-security-posture.md`) is the source of truth**
for the claim numbering, threat model, and per-backend tier matrix;
this section is the summary. Implementation is sequenced in
`specs/plans/25-microvm-hardening.md`.

Claim lineage:

- Claims 1–7 ship with ADR-002's original posture.
- Claim 8 was added by plan 64 (`specs/plans/64-supervisor-wiring.md`)
  — see ADR-041 (`specs/adrs/041-signed-audited-execution-plans.md`).
- Claim 9 (signed bundles content-addressed) is Sprint 52 W2.
- Claim 10 (default-deny egress) is Sprint 52 W3.
- Claim 11 (app-dep volume sealed) was added by ADR-047 / Plan 73
  Followups A + B.1/B.2/B.3 + C + D
  (`specs/adrs/047-app-deps-audit-pipeline.md`).
- Claims 12 + 13 (host services broker — binding-gated dispatch and
  no raw secret over broker channel) were added by Plan 104 / ADR-059
  (`specs/adrs/059-host-services-broker.md`) /
  ADR-049 (`specs/adrs/049-vsock-substitution-service.md`).

A fourteenth property — **OCI image provenance recorded in the
chain-signed audit log** — has its own claim doc at
`specs/claims/claim-10-oci-image-provenance.md` and is enforced
under the claim 8 admission flow; promotion to the ADR-002 numbered
table is tracked in `specs/plans/111-cardoso-gap-coordination.md`.

Companion docs: the Cardoso minimum-viable-policy mapping lives in
ADR-002 §"Appendix: Cardoso minimum-viable-policy checklist", and
the source gap analysis is at
`specs/research/sandboxes-for-ai-cardoso-gap-analysis.md`.

1. **No host-fs access from a guest beyond explicit shares.** Per-service
   uid (W2.1), seccomp `standard` default (W1.1, W2.4), and `setpriv
   --bounding-set=-all --no-new-privs` (W2.3) confine each service.
2. **No guest binary can elevate to uid 0.** `setpriv --no-new-privs`
   in the launch path; `/etc/{passwd,group,nsswitch.conf}` are
   read-only bind-mounts so a compromised service can't mint a uid 0
   entry (W2.2).
3. **A tampered rootfs ext4 fails to boot.** dm-verity sidecar +
   kernel-cmdline roothash + `mvm-verity-init` initramfs (W3 —
   shipped 2026-04-30; see plan 27 + runbook
   `specs/runbooks/w3-verified-boot.md`). CI lane
   `verified-boot-artifacts` in `security.yml` asserts the artifacts
   are emitted; live-KVM tamper regression confirms the kernel
   panics before userspace on a flipped data block.
4. **The guest agent does not contain `do_exec` in production
   builds.** `prod-agent-no-exec` job in `.github/workflows/ci.yml`
   builds the agent without `dev-shell` and asserts the
   `mvm_guest_agent::do_exec` symbol is absent (W4.3).
5. **Vsock framing + supervisor-config JSON are fuzzed.** `cargo-fuzz`
   targets at `crates/mvm-guest/fuzz/` cover `GuestRequest` and
   `AuthenticatedFrame` (W4.2). Plan 88 W6 adds
   `crates/mvm-libkrun/fuzz/fuzz_supervisor_config.rs` against the
   host-side `SupervisorConfig` parser the `mvm-libkrun-supervisor`
   binary reads on stdin. `#[serde(deny_unknown_fields)]` on every
   host↔guest type ensures unexpected fields fail-closed (W4.1). The
   virtio-net frame parsers that Plan 87/88 brought online live
   inside libkrun (C), passt (C), and gvproxy (Go) — their fuzz
   coverage belongs upstream and is tracked in ADR-055 §"New
   untrusted-input surfaces".
6. **Pre-built dev image is hash-verified.** `download_dev_image`
   fetches the per-arch `*-checksums-sha256.txt` manifest, streams
   the artifact through SHA-256, and rejects + deletes on mismatch
   (W5.1). `MVM_SKIP_HASH_VERIFY=1` is the documented emergency
   escape; never set it in CI.
7. **Cargo deps are audited on every PR.** `deny.toml` + the `deny`
   and `audit` jobs in CI (W5.2). Reproducibility double-build
   (W5.3) catches non-determinism that could mask injection.
8. **Every workload runs from a signed, audited `ExecutionPlan`.**
   `mvmctl up` synthesizes a typed `ExecutionPlan`, signs it under
   the host's Ed25519 keypair at `~/.mvm/keys/host-signer.ed25519`
   (mode 0600), verifies it through `mvm_plan::verify_plan`,
   enforces the G4 validity window + nonce replay-store, and only
   then dispatches the backend. Each admission emits
   `plan.admitted` / `plan.launched` / `plan.failed` chain-signed
   entries to `~/.mvm/audit/<tenant>.jsonl`; tampering breaks
   `mvm_supervisor::verify_audit_chain` (surfaced via
   `mvmctl audit verify`, which exits nonzero on detected drift).
   Workspace `cargo test` exercises rejection paths on every PR
   (plan 64 W1–W4 — `synthesize_plan`, `host_signer::load_or_init_at`,
   `admit_for_run`, `AuditEmitter`; `xtask check-no-display-on-secret-types`
   protects the host signer's redacted `Debug`).
9. **Every published bundle is content-addressed, key_id-pinned, and
   re-verified at fetch and at admit time.** Sprint 52 W2 +
   admit-time re-verify follow-on. `mvm_plan::bundle::read_and_verify_bundle`
   + `mvm_plan::bundle::verify_plan_bundle` exercise the
   rejection ladder on every PR: unknown-key, tampered manifest,
   key_id mismatch, tampered artifact, missing artifact, unsafe
   path, schema bump, pin-archive sha256 drift, pin-signature
   drift. `mvmctl bundle fetch` round-trip + `admit_for_run` tests
   assert refusal on pin-without-context and pin-archive mismatch.
10. **No untrusted workload reaches the network unless explicitly
    admitted by policy.** Sprint 52 W3. `policy_default_is_deny_all`
    + `test_resolve_network_policy_default_is_deny_all` assert the
    default-deny posture; `mvmctl up` emits an opt-in warning when
    the resolved policy is `unrestricted` (escape hatch is
    `MVM_ACK_UNRESTRICTED_NETWORK=1`, never set in CI). Cardoso-flavoured
    audit of DNS / vsock control-plane carve-out / Plan 104 broker
    channels as covert egress is tracked in Plan 111 Workstream A.
11. **Every application-dep volume is hash-locked, attestation-checked,
   CVE-scanned, SBOM-enumerated, and bound to the workload's audit
   chain.** ADR-047 / Plan 73 Followups A + B.1/B.2/B.3 + C + D wire
   this end-to-end: the builder VM (`mvm-host-vm-init` +
   `LibkrunBuilderVm::run_build` Install arm) installs deps into a
   sealed volume at `~/.mvm/volumes/deps/<volume_hash>/` carrying
   `content/`, `sbom.cdx.json`, `fetch.log`, `cve.json`, and a
   hash-chained `meta.json`; `mvm-supervisor`'s admission verifier
   calls `mvm_sdk::compile::deps_audit::verify_sealed_volume` before
   launch and refuses tampered volumes; `mvmctl up --prod` fails
   closed on high/critical CVE findings or stub SBOM/CVE
   (`mvm_build::app_deps_gate::apply_install_gate`); `mvmctl deps
   inspect` / `mvmctl deps audit` surface the sealed sidecars without
   a VM spawn. The `app-deps-audit` job in `.github/workflows/ci.yml`
   (Followup D) gates every PR: it exercises `mvmctl compile` on
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
    ADR-059. `service_call_denied_when_unbound` +
    `service_call_denied_outside_profile` +
    `audit_chain_contains_service_call_entries` +
    `audit_chain_carries_no_payload_bytes` exercise the rejection
    ladder. `xtask check-handler-adr-coverage` +
    `xtask check-handler-policy-schema` +
    `xtask check-handler-composition` lint the handler registry.
    `fuzz_service_call.rs` (Plan 104 W6) exercises the dispatch
    surface.
13. **No raw secret value crosses the broker channel.**
    `host.secrets.v1` returns destination-bound, time-bound signed
    credentials only; raw secret bytes never leave the supervisor's
    address space. Plan 104 W5 / ADR-049 / ADR-059.
    `host_secrets_v1_denied_outside_allowed_destinations` +
    `zeroize_drop_zeros_secret_bytes` +
    `handler_inter_call_memory_hygiene` +
    `host_secrets_v1_signed_payload_jcs_roundtrip` +
    `secrets_subprocess_cannot_reach_supervisor_memory` +
    `placeholder_in_outbound_request_dropped_and_audited`
    (S25 backstop) tests; ADR-049 hostile-guest matrix in W7.
14. **Every `mvmctl run --image <oci-ref>` admission records the OCI
    image provenance in the chain-signed audit log.** Tracked as a
    standalone claim doc at
    `specs/claims/claim-10-oci-image-provenance.md`; promotion to
    the ADR-002 numbered table is queued in Plan 111. Plan 85 Phase E
    + F wire the user-facing OCI image runner to the same audit chain
    that backs claim 8 — see `specs/claims/claim-10-oci-image-provenance.md`.
    `mvmctl image pull` materializes the layer set in `mvm-oci`'s
    allow-listed unpacker (`mvm_oci::unpack::unpack_layer`), formats an
    ext4 rootfs in the builder VM (`mvm_build::oci_to_rootfs::
    materialize_to_ext4`, never on the macOS host — ADR-050), and
    persists provenance metadata (registry host, repo, supplied
    reference, resolved manifest digest, layer digest list, trust
    policy, cosign verdict). `mvmctl run --image` admits an
    `ExecutionPlan` (claim 8 path) and then emits a
    `plan.oci_provenance` entry via
    `AuditEmitter::emit_oci_provenance`
    (`crates/mvm-cli/src/commands/vm/audit_chain.rs`) carrying those
    labels; `mvm_supervisor::verify_audit_chain` continues to detect
    drift, surfaced via `mvmctl audit verify`. `--prod` refuses
    mutable references before any network fetch
    (`crates/mvm-cli/src/commands/image.rs::
    prod_pull_requires_digest_pin_before_network` and
    `prod_run_image_requires_digest_pin_before_network`), demands an
    explicit registry policy, and requires cosign verification of the
    resolved digest before cache admission or boot. The OCI
    `unpack_layer` fuzz harness lives in
    `.github/workflows/security.yml`'s `fuzz` job (release-tag pushes
    + nightly cron + manual dispatch); the
    `oci-layer-unpack-adversarial`, `oci-digest-mismatch-reject`,
    `oci-malformed-manifest`, `oci-mutable-tag-prod-reject`,
    `oci-reproducibility`, and `oci-image-runner-smoke` lanes in
    `.github/workflows/ci.yml` gate every PR that touches the OCI
    surface.

The guest agent itself runs as uid 901 under setpriv (W4.5); the
host-side vsock proxy socket is mode 0700 (W1.2), the proxy port
allowlist drops anything outside the agent and forward ranges
(W1.3), and `~/.mvm` / `~/.cache/mvm` are mode 0700 (W1.5).

Out of scope (named in ADR-002):

- A malicious *host*. mvmctl trusts the host with the hypervisor and
  private build keys.
- Multi-tenant guests. One guest = one workload.
- Hardware-backed key attestation.

`mvmctl doctor` reports the live posture on the running host
(plan 40 folded the standalone `security` verb into doctor's
unified diagnostics report). Architecture detail in
`specs/adrs/002-microvm-security-posture.md`. Implementation
sequence in `specs/plans/25-microvm-hardening.md`.

## Testing

No task is done without tests. Before marking any feature complete:

```bash
cargo fmt --all -- --check           # workspace-wide fmt; --all matters
cargo test --workspace               # all tests must pass
cargo clippy --workspace -- -D warnings  # zero warnings
```

**Always pass `--all` to `cargo fmt`.** Without it, fmt only checks the
manifest crate (whichever one the manifest points at), silently missing
drift in every other workspace member. CI runs `cargo fmt --all --
--check`; if you only check the local crate, the merge will still fail.
The pre-commit hook at `.githooks/pre-commit` auto-fixes with `cargo
fmt --all` and re-stages — `just install-hooks` wires
`core.hooksPath` to `.githooks/` so it fires on every commit.

The Justfile recipes wrap this correctly: `just fmt-check`, `just
clippy`, `just lint` (both), `just ci` (lint + test). Prefer those over
raw cargo invocations.

Every new module, type, or function needs test coverage:
- Types: serde roundtrip, default values
- Protocol/wire code: mock I/O roundtrip, tampered data rejection, error paths
- CLI: integration tests in `tests/cli.rs` for help text and argument parsing
- Security: positive path, negative path (wrong key, tampered, replay), edge cases

## Build and Run

```bash
cargo build
cargo run -- --help

# Dev mode
cargo run -- dev         # auto-bootstrap + drop into builder-VM shell (alias for dev up)
cargo run -- dev up      # same as above, explicit
cargo run -- dev down    # stop the builder VM
cargo run -- dev shell   # open shell in running builder VM
cargo run -- dev status  # show dev environment status

# Build from Nix flake
cargo run -- build --flake . --profile minimal --role worker
cargo run -- run --flake . --profile minimal --cpus 2 --memory 1024

# Templates
cargo run -- template create base --flake . --profile minimal --role worker --cpus 2 --mem 1024
cargo run -- template build base
cargo run -- template list

# Image catalog
cargo run -- image list              # browse bundled catalog
cargo run -- image search http       # search by name/tag
cargo run -- image fetch minimal     # build from catalog entry

# Networks
cargo run -- network create isolated # create named network
cargo run -- network list            # list all networks
cargo run -- network remove isolated # remove a network

# Console (interactive PTY, dev-mode only)
cargo run -- console myvm            # interactive shell
cargo run -- console myvm --command "uname -a"  # one-shot exec

# Setup & diagnostics
cargo run -- init                    # first-time setup wizard
cargo run -- security status         # security posture evaluation
cargo run -- cache info              # cache directory info
cargo run -- cache prune             # clean stale temp files
```

## Dev Network Layout

```
MicroVM (172.16.0.2, eth0)
    | TAP interface
Builder VM (172.16.0.1, tap0) -- iptables NAT -- internet
    | libkrun (macOS) / Apple Container (macOS 26+) / direct (Linux KVM)
macOS / Linux Host
```

## Documentation

- `public/src/content/docs/contributing/development.md` -- contributor guide, testing, CI/CD
- `public/src/content/docs/guides/nix-flakes.md` -- writing Nix flakes for microVM images (mkGuest API)
- `public/src/content/docs/guides/troubleshooting.md` -- common issues and fixes
- `public/src/content/docs/contributing/adr/001-firecracker-only.md` -- ADR: Firecracker-only execution
- `public/src/content/docs/reference/cli-commands.md` -- complete CLI command reference
- `specs/plans/` -- implementation specs and plans

## Sprint Management

- Active sprint spec: `specs/SPRINT.md`
- Completed sprints archived to: `specs/backlog/` (e.g. `specs/backlog/01-foundation.md`)
- When a sprint is completed, rename `specs/SPRINT.md` to `specs/backlog/<NN>-<name>.md` and create a new `specs/SPRINT.md` for the next sprint
