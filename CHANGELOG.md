# Changelog

All notable changes to **mvm** are recorded here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project
uses [SemVer](https://semver.org/) once it reaches 1.0.

## [Unreleased]

## [0.15.0] — 2026-06-03

### Added

- **Architecture-aware artifact model (Plan 134).** `GuestArch`/
  `KernelFormat` in `mvm-core`; `MicrovmBackend` + data-driven
  `BackendCompat` matrix + the `artifacts` module in `mvm-backend`;
  `NixMicrovmBuilder` adapter; static `ArtifactValidator` +
  `FirecrackerConfigWriter`; `mvmctl artifact model-inspect|
  model-validate|model-config|model-build`.
- **`mvmctl invoke` works end-to-end** (function workloads return their
  encoded result over vsock `RunEntrypoint`). The build-time `@mvm.app`
  decorator is stripped from the bundled source at compile time, so the
  guest never imports the SDK.
- **SDK publish workflows** — PyPI (`mvm`) + npm (`@runmvm/mvm`),
  release-triggered with a version==tag guard.
- **Stage 0 builder-VM nix-store persistence** across `dev up` runs.

### Fixed

- **Function-workload boot** is genuinely stable: PID 1 (the idle
  bootScript at `/etc/mvm/boot`) no longer aborts on a bare `mkdir`, so
  the VM stays up instead of rebooting at ~5s (previously boot→ping only
  "passed" via the agent answering inside that window).
- OCI→ext4 materialization is byte-deterministic on e2fsprogs ≥1.47
  (`-O ^orphan_file`), restoring the ADR-050 verity-cache invariant.

- **Plan 63 Phase 2 — encryption everywhere.** Closed in six
  workstreams (commits `b9e4e64`, `1ea9352`, `f7e39a7`, `a30f866`,
  `6fc798d`, plus this CHANGELOG entry):
  - **W1** — `mvm-security::key_rotation` module with `rewrap_dek`
    (dispatches on `WrapAlgorithm`; `Aes256Gcm` in-crate, `AesKwp`
    refused with a pointer at mvmd), `rotate_master_key` +
    `MasterKeyManifest` (versioned on-disk key store with atomic
    manifest writes), `migrate_wrapped_keys` (resumable bulk
    re-wrap), `rotate_luks_slot` (cryptsetup shell-out via
    mode-0600 tempfiles — never argv), `reseal_snapshot`
    (verify-under-old + reseal-under-new + atomic). 19 tests.
  - **W2** — every secret-carrying type wraps `secrecy::SecretBox<T>`.
    `KeyProvider::get_data_key` returns `SecretBox<Vec<u8>>`;
    `snapshot_hmac::load_or_init_key` returns
    `SecretBox<[u8; HMAC_KEY_BYTES]>`. xtask
    `check-no-display-on-secret-types` lint runs on every PR.
  - **W3** — `mvm-security::keystore` now ships `KeyringProvider`
    (OS-native keystore: macOS Keychain via `new_with_target`,
    Linux Secret Service, Windows Credential Manager) +
    `FileKeyProvider` (raw 32 bytes at `<keys_dir>/<tenant>.key`,
    mode 0600/0400) + `default_provider()` (auto-detects best
    available impl). `keyring = "3"` lifted into workspace deps.
    25 tests.
  - **W4** — `mvm-security::secret_store` with the `SecretStore`
    trait + `FileSecretStore` + `KeyringSecretStore` for
    multi-key tenant secrets (distinct from `KeyProvider`'s
    single-master-DEK shape). `mvmctl secret put/get/ls/rm`
    CLI surface; the `get` handler refuses TTY without `--force`.
    Audit log at `~/.mvm/audit/secrets.jsonl` records every CRUD
    op without ever recording the value. 25 tests.
  - **W5** — `mvm-security::snapshot_encryption` chunked
    AES-256-GCM file-bound primitives + integration into
    `mvm::vm::instance_snapshot::{pause_and_seal,
    verify_and_resume}`. Snapshots encrypt transparently when a
    tenant DEK is configured; HMAC seal covers the ciphertext.
    Resume probes for MVSE magic and refuses unencrypted-under-
    keyed-tenant as a downgrade defence (override via
    `MVM_ALLOW_UNENCRYPTED_SNAPSHOT=1` for one-time migration).
    19 tests.
  - **W6** — ADR-042 ("Encryption substrate") documents the full
    surface + this CHANGELOG entry. Plan 63 closes.

  Tests: workspace at **2082 passed / 0 failed** post-W6. Plan-60
  Phase 2 ("Encryption everywhere") moves from "substrate-only"
  to user-observably true; tenant DEK rotation works without
  re-encrypting data, snapshots are encrypted at rest, and
  `mvmctl secret put` is the documented prod-safe surface.

- **Plan 64 — supervisor wiring.** `mvmctl up` now admits a
  signed `ExecutionPlan` through `mvm-plan::verify_plan` + G4
  validity window + nonce replay-store, and emits chain-signed
  audit entries to `~/.mvm/audit/<tenant>.jsonl`. CLAUDE.md
  security claim 8 ("every workload runs from a signed, audited
  ExecutionPlan") is now user-observably true. ADR-041 documents
  the lifecycle; `policy_resolver::resolve_supervisor_components`
  (W5) is the substrate that hands `ResolvedSlots` to a future
  `Supervisor::launch` consumer once the mvm-hostd lift lands.

## [0.14.0] — 2026-05-11 — v1 → v2 cutover

**This release replaces v1 with a complete rewrite at the same canonical
project name (`mvm`) and binary name (`mvmctl`). The two versions are
not API-compatible. See [`MIGRATING-FROM-V1.md`](MIGRATING-FROM-V1.md)
for the upgrade path.**

The v1 final tip is preserved on this repository as the `legacy/v1`
branch and the `v1-final` tag — all v1 commit URLs, PR URLs, and
release-tag URLs (`v0.7.1`–`v0.13.0`) continue to resolve.

### Why a rewrite

v1 was a 5-crate skeleton with substantial Lima coupling on macOS, a
hand-rolled rootfs init path, and a hypervisor abstraction that
ossified around Firecracker. v2 is a 13-crate workspace built around:

- **`microvm.nix`** as the image-build substrate (deterministic,
  composable, declarative — replaces the hand-rolled rootfs init)
- **libkrun as the cross-platform default backend** (Linux/KVM
  via libkrun, macOS via Hypervisor.framework, Windows pending)
- **Firecracker preserved as Tier 1 on Linux+KVM** with explicit
  Cloud Hypervisor support for workloads that need VFIO/GPU/virtio-fs
- **Lima removed entirely** — direct host execution on Linux; Apple
  Container or libkrun on macOS
- **Busybox as PID 1** in guests (replaces NixOS+systemd; meets the
  ≤300 ms cold-boot p50 floor recorded in ADR-013)
- **`ExecutionPlan`-shaped substrate** for the supervisor / audit /
  policy work in plans 37 and 60 Phases 2–10

### Added

- 13-crate workspace: `mvm-core`, `mvm-security`, `mvm-storage`,
  `mvm-plan`, `mvm-policy`, `mvm-supervisor`, `mvm-providers`,
  `mvm-backend`, `mvm-base`, `mvm`, `mvm-build`, `mvm-guest`,
  `mvm-cli`, `mvm-mcp` (plus root `mvmctl` facade and `xtask`)
- `AnyBackend` dispatch with `auto_select()` per ADR-013: Linux+KVM →
  Firecracker; macOS 26+ on Apple Silicon → Apple Container or
  libkrun; KVM-less Linux / older macOS / Intel → libkrun;
  Cloud Hypervisor opt-in for VFIO/GPU
- `mkGuest` Nix function with three entrypoint forms (shell, command,
  services), build-time `accessible`/`sealed` mode inference, and
  `passthru.mvm` sidecar metadata threading
- `BuildMode::{Dev, Prod}` — `mvmctl up <flake>` defaults to Prod
  (sealed image, `mvmctl console` refused unless `--force`); `--dev`
  opts into the accessible image with `do_exec` available
- Cross-compiled real `mvm-guest-agent` in the rootfs (replaces the
  v1 stub; preserves the `prod-agent-no-exec` symbol gate)
- Snapshot-integrity HMAC at restore (`mvm-security::snapshot_hmac`)
- `mvm-security::snapshot_crypto` (AES-256-GCM primitives) and
  `mvm-security::keystore` (`KeyProvider` trait + `EnvKeyProvider`)
  — Phase 2 substrate
- `LibkrunBuilderVm` — Nix builds in a libkrun sandbox on
  macOS Intel / KVM-less Linux when host Nix isn't on `PATH`
- `mvmctl invoke` (Sprint 45 W3) — production-safe call surface for
  function-entrypoint workloads; `mvmctl exec` remains dev-only
- Workspace clippy gate: `clippy::too_many_arguments = "deny"`
- CI `lint` lane folds `fmt` + `clippy` + `xtask check-adr-coverage`
  into one runner (~3 min wall-clock saved per PR)
- 1937 workspace tests (up from v1's 1068)

### Changed (breaking)

- **`mvmctl up <flake>` produces a sealed image by default.**
  `mvmctl console <vm>` refuses with a clear error pointing at
  `--force` and `--dev`. v1 users who relied on `up` + `console` for
  a shell need `mvmctl up --dev <flake>` (intentionally less
  ergonomic in prod — security claim 4 is now enforced at runtime,
  not just at the CI symbol gate).
- **Lima is not used on macOS anymore.** v1's `mvmctl dev` booted a
  Lima VM; v2's `mvmctl dev` either uses Apple Container (macOS 26+
  Apple Silicon) or the host shell directly (Linux+KVM), and emits a
  clear bail with a libkrun-builder pointer on other hosts.
- **Image build substrate moved to `microvm.nix`.** v1's hand-rolled
  rootfs init paths are gone; users with custom `flake.nix` files
  need to migrate to `mkGuest` (the API is documented at
  `nix/lib/default.nix`).
- **The `mvm` binary was renamed to `mvmctl`** in v1's history; v2
  retains `mvmctl`. (Noted because the project is still called
  `mvm` and the rename trips up muscle memory.)
- **`mvmctl template` namespace retired.** Image building lives at
  `mvmctl build`; `mvmctl up --launch-plan` is the manifest path.
- **CLI argument parsing now uses `bon`-derived builders** for any
  command surface with more than ~3 args (workspace lint enforces).

### Removed

- v1's `mvm-runtime` crate — split into `mvm`, `mvm-base`, and
  `mvm-backend`
- v1's `mvm-apple-container` and `mvm-libkrun` crates — collapsed
  into `mvm-providers` (FFI/SDK shim layer)
- Lima support (`vm/lima.rs`, `lima.yaml.tera` template, all `mvmctl
  bootstrap` / `doctor` Lima checks)
- `tests/cli.rs.spec` — 900 lines of never-wired scaffolding

### Security

- 7 CI-enforced claims preserved from v1 (see CLAUDE.md "Security model"
  for the canonical statement):
  1. No host-fs access beyond explicit shares
  2. No guest binary can elevate to uid 0
  3. Tampered rootfs ext4 fails to boot (dm-verity)
  4. Guest agent has no `do_exec` in production builds
  5. Vsock framing is fuzzed
  6. Pre-built dev image is hash-verified
  7. Cargo deps are audited on every PR
- New in v2: snapshot HMAC at restore; `mvmctl console` accessible/
  sealed gate enforced at runtime; busybox-as-PID-1 in guests
  (smaller attack surface than systemd); `--force-with-lease` on the
  v1→v2 cutover itself (preserving v1 history)

### Known limitations / "not yet" list

These are intentional deferrals for the rewrite's first cut. Each
has a tracking pointer; none is silently broken.

- **mvmd contract build** is blocked on the upstream `libkrun
  0.4.5 ⊥ iroh-base 0.96.1 over sha2` conflict. Targeted package
  builds confirm every `mvmctl::*` path mvmd imports still resolves;
  end-to-end `cargo build --workspace` greens when the upstream
  resolves the dep version mismatch.
- **Live-KVM smoke** for `mvmctl up` + `mvmctl invoke` is gated on
  `MVM_LIVE_SMOKE=1` + `MVM_TEST_ROOTFS=...` and a capable host. The
  substrate compiles and skips cleanly without those — `tests/smoke_e2e_boot.rs::boots_real_rootfs_within_tripwire_then_tears_down_clean` runs the live exercise.
- **Cloud Hypervisor lifecycle** ships the JSON-over-Unix-socket
  control plane behind the same backend trait; pure pieces (config
  builder, path helpers, JSON escaping) carry 8 unit tests, but the
  spawn-dance is reviewed against CH's published API rather than run
  against a Linux+CH host (none in the dev environment).
- **L7 egress proxy runtime** has its foundation (PR-on-`legacy/v1`
  #23: `EgressMode` enum, `EgressProxy` trait, `StubEgressProxy`)
  but the mitmdump-driven runtime backing is plan 34 territory and
  hasn't shipped in v2 yet.
- **Phases 3–10 of plan 60** (network isolation, attestation,
  artifact capture, multi-tenant, supervisor surface, confidential
  computing) are sequenced but not started. Plan 60 carries the
  schedule; CLAUDE.md "Security model" lists what's shipped vs. what
  isn't.
- **Several v1 in-flight branches** carry feature work that hasn't
  been ported to v2 yet:
  - Plan 37 waves 2.2–2.6 (PII redactor, secrets scanner, SSRF guard,
    injection guard, L7 proxy v2) — slated for plan 60 Phase 2/3
  - Mesh DNS / vsock-bridge scaffolding (ADR-0018/0020) — slated for
    plan 60 Phase 3
  - Session lifecycle plans 51/52 — partial coverage in v2's
    `mvmctl invoke`; full surface deferred to a follow-up
  - Function-service factories plans 48/49 — landed in v2 at
    `nix/lib/factories/`; mvmforge consumes them via
    `mvm.lib.<system>`
  See [`MIGRATING-FROM-V1.md`](MIGRATING-FROM-V1.md) §"Feature parity
  status" for the per-feature delta.

[Unreleased]: https://github.com/tinylabscom/mvm/compare/v0.15.0...HEAD
[0.15.0]: https://github.com/tinylabscom/mvm/compare/v0.14.0...v0.15.0
[0.14.0]: https://github.com/tinylabscom/mvm/releases/tag/v0.14.0
