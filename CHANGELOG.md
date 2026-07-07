# Changelog

All notable changes to **mvm** are recorded here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project
uses [SemVer](https://semver.org/) once it reaches 1.0.

## [Unreleased]

## [0.16.1] — 2026-06-05

### Added
- **storage**: StorageProvider trait + LocalStorage (plan 123 B1)
- **storage**: EncryptedStorage at-rest arm, macOS (plan 123 B2)
- **storage**: Content-addressed + snapshot-upper volumes (plan 123 B3)
- **storage**: MountProvider registry + IR MountSource::External (plan 123 B4 steps 1-3)
- **storage**: S3 MountProvider via object_store, feature-gated (plan 123 B4 step 4)
- **backend**: SnapshotCapability per-backend warm-start tier (plan 123 C1)
- **network**: Mvm-network crate — NetworkProvider seam + NetworkMode::Custom (plan 123 A1/A2/A5)

### Documentation
- **plan-123**: Reconcile post-121 paths + pin B→A→C order
- **plan-123**: Tick B1 (StorageProvider trait + LocalStorage)
- **plan-123**: Mark Phase B storage/mount acceptance complete
- **plan-141**: Mark closed (merged via #609/#614); track passt live-KVM follow-up
- **plan-123**: Tick Phase A seam (A1/A2/A5); track claims-gated lift as follow-up

### Fixed
- **apple-container**: Don't re-copy an already-per-instance rootfs

### Release
- V0.16.1

## [0.16.0] — 2026-06-05

### Added
- **compile**: Warn when Node package.json deps won't be baked
- **cli**: Mvmctl kernel build (compile arm) via Stage 0
- **cli**: Kernel build --source download/auto + --arch
- **cli**: Dev up --kernel-source (boot on a downloaded kernel)
- **xtask**: Machine-check the security-claim → witness map
- **verify**: Serverless in-browser audit-log verifier (ADR-069)
- **builder**: Add verbose-gated console echo helper
- **builder**: Thread --verbose to stream Stage 0 console to stderr
- **kernel**: Elapsed heartbeat + --verbose console stream on compile
- **install**: Add curl-able install.sh
- **homebrew**: Formula template + render script + test
- **default-image**: Prod download (5-asset contract) + release job + test
- **nix**: Default-tenant flake build-validated (both variants) on the dev host
- **default-image**: BuildMode-aware resolution — dev builds locally (Task 3b)
- **volumes**: Custom volumes + fix Vz read-write-disk flock collision
- **dev**: Mount devpts in guest /init + add config::is_dev_mode (Plan 162)
- **crypto**: Collapse AEAD call sites into crypto::aead (plan 122 A1)
- **crypto**: MacOS volume-at-rest via per-file AEAD (plan 122 A2)
- **crypto**: 90-day KEK rotation timer (plan 122 B1)
- **crypto**: Per-rebuild DEK binding on WrappedKey (plan 122 B2)
- **crypto**: Content-addressed, Ed25519-signed snapshots (plan 122 C)
- **crypto**: VMGenID generation token + guest CSPRNG reseed (plan 122 D)
- **network**: Etherparse dep + pure L3/L4 parse + payload rebuild (Plan 141 Tasks 1-2)
- **network**: Observer::on_packet + Verdict/Directions/PacketCtx (Plan 141 Task 3)
- **audit**: Flow_observer_fault chain entry (Plan 141 Task 4)
- **network**: Per-observer latency recorder + scrape file (Plan 141 Task 5)
- **network**: Synchronous observer fan-out runner (Plan 141 Task 6)
- Flow-byte-log policy field + append-only writer (Plan 141 Task 7)
- **bridge**: Wire packet-observer pipeline into libkrun/gvproxy (Plan 141 Task 8)
- **bridge**: Frame-aware Passt loop + broaden metrics scrape filter (Plan 141 Task 9)
- **cache**: Flow-byte-log retention sweep in cache prune (Plan 141 Task 10)
- **vz-builder**: Gvproxy networking so cold nix builds can fetch nixpkgs

### Changed
- **sdk-ts**: Trailing commas in tsconfig (JSONC)
- **network**: Clippy — drop unnecessary drop(), flatten sweep with let-else (Plan 141)
- **release**: Defer x86_64-apple-darwin (Intel-macOS runners unavailable)

### Documentation
- **plan**: 145 — complete the build-time application-deps story
- **plan**: 145 — WS-B/C corrected (pnpm/yarn route to WS-A; warnings done in #553)
- **plan120**: Lead README + Python quickstart with the five-line Sandbox.exec
- **adr-046**: Kernel acquisition — compile or download
- **plan**: 147 — Lima test backend + Linux/FC core_demo E2E parity (deferred)
- **plan120**: Back-reference the deferred Lima/FC-parity/default-microvm bullets → Plan 147
- **plan**: 146 — WASI-polyglot workload language (deferred to the refactor)
- **notes**: WebAssembly support exploration — two framings, status, B recommendation
- **audit-verify**: Build the wasm bundle in the builder/dev VM, not the host
- **plans**: Add Plan 146 — cloud-hypervisor Tier-1 parity (Kuasar-referenced)
- **plans**: Add Plan 147 — portable runnable artifacts (mvmctl artifact run)
- **plan**: Add Plan 149 — mvmctl watch unified live operator event stream
- **plans**: Add Plan 150 (OSV deps scan + remediation) and Plan 151 (fs-access evidence)
- Contributor host-setup (libkrun vs Vz builder) + plan drafts 144/148
- **plan120**: Mark Status: COMPLETE — all acceptance boxes ticked
- **plans**: Resolve duplicate plan numbers 144/146/147 on main
- **plans**: Fix internal titles after 144/146/147 → 153/154/155 rename
- **plans**: Add 156 binary-size reduction; refresh 126 baseline + cross-refs
- **plans**: Add Plan 157 — warmed parent recipes (forkd-inspired)
- **spec**: Design for install.sh, Homebrew tap, download docs, compile logging
- **plan**: Implementation plan for install & download experience
- **kernel**: Note heartbeat + verbose streaming in module doc
- Guide for mvmctl kernel build (compile/download/auto)
- Releases & downloads reference
- **releases**: Expand Homebrew tap token setup steps
- **adr-002**: Document the verified-boot verity surface post-consolidation
- **plan-158**: Plan to restore the bundled default microVM image
- **specs**: Scrub prior-art product name from Plan 143
- **specs**: Record host-side Landlock-envelope widening as a deferred Plan 143 follow-up
- **specs**: Plan 161 — OCI-unpacker openat2 TOCTTOU fix + ADR-002 note
- **plan-158**: Dual dev/prod default image keyed on BuildMode
- **crates**: Finalize plan 121 — ADR-066 corrections, CLAUDE.md, old→new ident map
- **adr**: Descope B4 framing — authenticated frame stays its own protocol
- **plan**: Record B4 Option B as a tracked deferred follow-up
- **vz**: Stop over-claiming in-supervisor share refusal
- **plan**: Record B4 Step 2 (config_envelope) descope + Step 3 (paths) outcome
- **plan**: Close out B4 — descope Step 4 (subprocess) + Step 5, reconcile Acceptance
- Close out plan 121 — stamp COMPLETE + reconcile mvm-core runtime-free claim
- **plans**: Fold plan-121's 3 spawned follow-ups into their active plans
- **plan-121**: Record the production verification in the Status header
- **plan-121**: Cross-ref #587 extending the B4 paths centralization
- **plans**: Add Plan 162 — dev-mode interactivity (guest devpts + MVM_ENV=dev)
- **plans**: VZ support research — Rust-objc2 supervisor (152) + vz-inspired DX (159)
- **plan-141**: Note the Plan 152 drop-Swift conflict (reciprocal)
- **plans**: Resolve 152↔141 — split scope, Vz payload-tap rides Plan 152
- **plan-122**: Tick A1, mark A0 deferred
- **plans**: Reconcile 152 WS-D nested-virt with Plan 147 Lima
- **plans**: Add Plan 163 — Apple VZ support execution roadmap
- **plan-159**: Add vz DX/UX parity checklist + long-tail items
- **plan-126**: A1 dependency baseline + correct the Phase-B premises
- **plan-126**: B4 finding — aws-lc-rs is the oci-client/reqwest-0.13 chain (= C1)
- **plan-126**: B4 is upstream-blocked — oci-client hardcodes aws-lc
- **adr-066**: Reconcile §5/§7 with plan 122 (Phase E)
- **plans 123,140**: Cross-ref the plan 122 D VMGenID substrate + entropy-source decision

### Fixed
- **nix**: Keep kernel base.nix inside the builder-vm flake tree
- **cli**: Gate host_arch + download_kernel behind builder-vm
- **specs**: Renumber duplicate ADR-069 (browser verifier) to 070
- **gvproxy**: Free ssh-port + reap orphaned daemons on startup
- **nix**: Default-tenant flake evals — description must be a literal
- **nix**: Expose passthru.rootfs so the builder-VM dev build emits mvm-meta.json
- **ci**: Repair plan-121 CI breaks — architecture invariant allowlist + mvm-build dev-shell feature
- **hostd**: Drop useless i64::from on c_long syscall nr (clippy 1.95 on Linux)
- **volumes**: Mount user volumes in mkGuest /init (the dev VM's PID 1)
- **volumes**: Default user volumes read-only; allow-list mount roots
- **mkguest**: Gate Stage 2.3 modprobe behind user-volume presence
- **dev**: Libkrun dev VM console attach + e2e-core-demo recipe
- **bootstrap**: Drop stale per-crate source hash from builder-vm fingerprint
- **libkrun**: Wait for the vsock socket in start(), not just the PID file
- **dev**: Only open the interactive console when stdin is a TTY
- **release**: Install zig/cargo-zigbuild in the binary build job
- **ci**: Correct zig macOS arch name + ensure /opt in install-zigbuild
- **ci**: Install libkrun for macOS release builds; Intel on native runner
- **dev**: Idle PID 1 in the dev VM /init so it survives the console EOF (Plan 162)
- **bridge**: Bind gvproxy-facing datagram socket; live DHCP e2e test (Plan 141 follow-up)
- **build**: Give nested host-vm cargo its own target dir (release deadlock)
- **ci**: Smoke test reads global.requests_total (metrics now sectioned)
- **jailer**: Use SYS_newfstatat on aarch64 (no SYS_fstatat there)

### Performance
- **test**: Faster workspace test runs (nextest gate + embed-skip fast path)

### Refactored
- **kernel**: Use Relaxed ordering for heartbeat stop flag
- **crates**: Fold mvm-runner into mvm-guest as a [[bin]]
- **crates**: Fold mvm-base into mvm-backend::base (Lima-era leftover)
- **sdk**: Fold mvm-ir into mvm-sdk::ir (one SDK crate)
- **core**: Fold mvm-plan into mvm-core::plan
- **core**: Fold mvm-policy into mvm-core::policy (keep policy::security re-export)
- **core**: Fold mvm-security into mvm-core::crypto (pure crypto; no async in core)
- **backend**: Relocate+rename mvm-libkrun -> crates/deps/libkrun-sys
- **backend**: Fold mvm-providers into mvm-backend::providers
- **build**: Fold mvm-vz into mvm-build::vz (Swift-interface; cycle-avoided)
- **backend**: Relocate orphaned MvmContainerBridge swift pkg with providers
- **hostd**: Consolidate supervisor/broker/signers/jailer into mvm-hostd
- **vm-host**: Consolidate per-VM supervisors into mvm-vm-host (cfg-gated [[bin]]s)
- **guest**: Consolidate addon-dns + vsock-bridge into mvm-guest-helpers
- **build**: Move host-vm-init + egress-proxy into mvm-build [[bin]]s (ADR-065)
- **core**: Dedup length-prefixed framing into core::framing (B4 Option A)
- **core**: Route mvm-core data-dir derivations through a strict resolver (plan 121 B4)
- **cli,hostd,build**: Route data/cache-dir derivations through canonical resolvers (plan 121 B4)
- **core**: Centralize per-VM vsock/state paths in mvm-core::config
- **backend,build**: Route per-VM paths through mvm-core::config
- **cli**: Centralize ~/.mvm keys/audit/overlays/secrets via mvm-core::config
- **core**: Drop tokio from mvm-core's default closure (plan 126 B5 PR-1)
- **core**: Make mvm-core's default build runtime-free (plan 126 B5 PR-2)
- **crypto**: Sign snapshots with attestation identity, trusted-signer set (plan 122 C)

### Testing
- **cli**: Declare audit posture for the kernel command
- **install**: Hermetic install.sh download + tamper-reject test
- **fuzz**: Packet parse+rebuild fuzz target; tick Plan 141 (Task 11)

### Dev
- Default dev up to an interactive shell
- Fall back to libkrun for auto-selected vz builder

### Draft
- **nix**: Default-tenant flake — dev + prod variants (Plan 158 Task 1)

### Merge
- Bring feat/custom-volumes up to date with main

### Nix
- **kernel**: Shared config base + slim builder/workload split

### Security
- **volumes**: Admission-enforced shares + libkrun ro guard + claim witnesses

## [0.15.2] — 2026-06-03

### Added
- **security**: Implement claim-4 prod-agent symbol-contract check
- **sdk**: TypeScript/Node workloads end-to-end

### Documentation
- **notes**: File Vz + Apple Container builder papercuts from TS E2E

### Fixed
- **security**: Scope agent symbol greps to the mvm_guest_agent crate

## [0.15.1] — 2026-06-03

### Added

- **SDK package READMEs.** `sdks/python/README.md` rewritten against the
  current `mvmctl` surface (the old copy referenced the deprecated
  `mvmforge` CLI), and a new `sdks/typescript/README.md` mirrors it. These
  render on the PyPI (`mvm`) and npm (`@runmvm/mvm`) package pages; the
  registries are immutable per version, so this patch ships them to the
  live pages.

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

[Unreleased]: https://github.com/tinylabscom/mvm/compare/v0.15.1...HEAD
[0.15.1]: https://github.com/tinylabscom/mvm/compare/v0.15.0...v0.15.1
[0.15.0]: https://github.com/tinylabscom/mvm/compare/v0.14.0...v0.15.0
[0.14.0]: https://github.com/tinylabscom/mvm/releases/tag/v0.14.0
