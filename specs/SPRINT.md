# Sprint 42 — microVM hardening: load-bearing guarantees

**Goal:** turn the project's stated security claim ("no SSH in microVMs,
vsock-only") from a single load-bearing layer into a stack of seven
verifiable, CI-enforced guarantees. Implement the plan recorded in
[`plans/25-microvm-hardening.md`](plans/25-microvm-hardening.md) and
the architectural decisions in
[`adrs/002-microvm-security-posture.md`](adrs/002-microvm-security-posture.md).

**Branch:** `main`

## Why this sprint, why now

Today the vsock-only claim is *true* but it's the only hardened layer.
Everything underneath it — guest privilege model, rootfs integrity, the
host-side proxy socket, the supply chain, the deserializer that parses
every host→guest message — is soft. A failure in any one defeats the
entire stack regardless of the vsock claim. The project's value prop is
that a developer can run third-party or AI-generated code in a microVM
and trust the isolation. That promise demands the protections be
technical, verifiable, and stated explicitly.

ADR-002 captures the threat model and the seventeen surfaces audited;
plan 25 sequences the work into six independently-shippable workstreams.

## Current Status (v0.13.0, sprint open)

| Metric           | Value                    |
| ---------------- | ------------------------ |
| Workspace crates | 7 + root facade + xtask  |
| Total tests      | 1 068                    |
| Clippy warnings  | 0                        |
| Edition          | 2024 (Rust 1.85+)        |
| MSRV             | 1.85                     |
| Binary           | `mvmctl`                 |

## In-flight workstreams

### W1 — Cheap defaults that are wrong today  ✅ shipped

One PR, five surgical patches, no architecture changes. All five items
landed with regression tests; `cargo test --workspace` and
`cargo clippy --workspace --all-targets -- -D warnings` clean.

- [x] **W1.1** Default `seccomp` tier flipped from `unrestricted` →
      `standard` in `crates/mvm-cli/src/commands/vm/up.rs`.
- [x] **W1.2** Vsock proxy Unix socket chmod'd to `0700` immediately
      after bind, with `test_proxy_socket_is_chmod_0700` covering it.
- [x] **W1.3** Vsock proxy port allowlist: only `52` (guest agent),
      `10_000..=75_535` (port-forward), `20_000..=85_535` (console
      data) traverse the proxy. Anything else logs and drops.
      `test_proxy_port_allowlist` covers boundaries.
- [x] **W1.4** Console log + daemon stdout/stderr created with
      `mode(0o600)` via `OpenOptions::mode`. Same-host other users
      can't `tail` guest output anymore.
- [x] **W1.5** `mvm_core::config::ensure_data_dir` /
      `ensure_cache_dir`: idempotent create + chmod-to-0700 wired into
      every `dev up`. Test
      `test_ensure_private_dir_locks_existing_loose_perms` covers the
      upgrade path for hosts that pre-date the change.

### W2 — Defense in depth inside the VM  ✅ shipped  [`plans/26-w2-defense-in-depth.md`](plans/26-w2-defense-in-depth.md)

- [x] **W2.1** Per-service uid in `nix/minimal-init/default.nix::mkServiceBlock`.
      Auto-derived from `1100 + sha256_hex8(name) % 8000`, with each
      service getting its own uid+gid, membership in `serviceGroup`,
      and a per-service `/run/mvm-secrets/<svc>/` subdir (mode 0500
      dir, 0400 files, owned by the service uid). Caller-supplied
      `services.<n>.user` is honoured as the back-compat escape.
- [x] **W2.2** `/etc/{passwd,group,nsswitch.conf}` are now created in
      `/run/mvm-etc/`, then bind-mounted read-only at the live `/etc/`
      paths with the two-step `mount --bind` + `mount -o remount,bind,ro`
      Linux dance. Boot regression confirmed: `mount` reports
      `(ro,relatime)`, `echo … >> /etc/passwd` returns EROFS.
- [x] **W2.3** Service launch line is now
      `${utilLinux}/bin/setpriv --reuid=… --regid=… --groups=…,900 --bounding-set=-all --no-new-privs --inh-caps=-all -- /bin/sh -c '…'`.
      `pkgs.util-linux` is in the production closure unconditionally.
      (Initially shipped with `--clear-groups --groups=…`; that combo is
      mutually exclusive in util-linux setpriv and crashlooped every
      service on the W3 verity-boot regression. Plan 35 §C1.2 dropped
      `--clear-groups` — `--groups=` already replaces the supplementary
      set wholesale, so the security claim is unchanged.)
- [x] **W2.4** Service launch is wrapped with
      `${guestAgentPkg}/bin/mvm-seccomp-apply <tier> --` (new shim
      binary in `crates/mvm-guest/src/bin/mvm-seccomp-apply.rs`,
      Linux-only target). Default tier is `standard`; override via
      `services.<n>.seccomp = "essential" | … | "unrestricted"`.

### W3 — Verified boot via dm-verity  ✅ shipped — 2026-04-30 (initramfs landed, all 5 runbook steps green)  [`plans/27-w3-verified-boot.md`](plans/27-w3-verified-boot.md) | runbook: [`runbooks/w3-verified-boot.md`](runbooks/w3-verified-boot.md)

- [x] **Kernel** `firecracker-aarch64.config` enables
      `CONFIG_MD`, `CONFIG_BLK_DEV_DM`, `CONFIG_DM_INIT`, and
      `CONFIG_DM_VERITY` so the kernel can construct verity targets.
- [x] **W3.1** `nix/flake.nix::verityArtifacts` runs
      `veritysetup format` with `--data-block-size=1024` and a pinned
      zero salt, emits `rootfs.{ext4,verity,roothash}`
      deterministically.
- [x] **W3.2** Apple Container backend gained `VerityConfig` +
      `start_with_verity()`; opens the rootfs read-only, attaches
      the sidecar at `/dev/vdb`, attaches the verity initramfs via
      `setInitialRamdiskURL`, and passes `mvm.roothash=<hex>` on the
      cmdline. Mutual-exclusion check rejects `MVM_NIX_STORE_DISK`.
- [x] **W3.3** Firecracker backend extended `FlakeRunConfig` +
      `VmStartConfig` with `verity_path` / `roothash`. Cold-boot,
      snapshot-restore, and template-snapshot paths all probe for
      the sidecar + initramfs via `microvm::probe_verity_sidecar()`
      and pass `initrd_path` to `/boot-source` so the initramfs
      runs as PID 1.
- [x] **W3.4** `mkGuest` accepts `verifiedBoot ? true`;
      `nix/dev-image/flake.nix` sets `verifiedBoot = false` (overlay
      can't compose with verity). The dev sibling flake forwards
      the kwarg transparently.
- [x] **Initramfs** `nix/packages/mvm-verity-init.nix` builds a
      static-musl `mvm-verity-init` that runs as PID 1 from the
      cpio.gz at `nix/packages/verity-initrd.nix`. Reads
      `mvm.roothash=` from cmdline, builds `/dev/mapper/root` via
      DM ioctls (DM_DEV_CREATE → DM_TABLE_LOAD → DM_DEV_SUSPEND),
      mounts it at `/sysroot`, then `switch_root`s to the real
      `/init`. Bypasses Firecracker's auto-appended
      `root=/dev/vda ro` by owning the boot pivot in userspace.
- [x] **CI gate** `verified-boot-artifacts` lane in
      `security.yml` builds `nix/default-microvm/` and asserts
      `rootfs.{ext4,verity,roothash,initrd}` plus a 64-char hex
      roothash.
- [x] **Boot regression** (live KVM): full
      `specs/runbooks/w3-verified-boot.md` Step 3 green —
      `mvm-verity-init` reaches userspace from `/dev/dm-0`.
- [x] **Tamper regression** (live KVM): tampering the ext4
      superblock triggers
      `device-mapper: verity: 254:0: data block 1 is corrupted`
      and the kernel panics before userspace.

### W4 — Guest agent attack surface  ✅ shipped — 2026-04-30  [`plans/28-w4-guest-agent-attack-surface.md`](plans/28-w4-guest-agent-attack-surface.md)

- [x] **W4.1** `#[serde(deny_unknown_fields)]` applied to every type
      crossing the host↔guest boundary: `GuestRequest`, `GuestResponse`,
      `HostBoundRequest`, `HostBoundResponse`, `FsChange` in
      `crates/mvm-guest/src/vsock.rs`; `AuthenticatedFrame`,
      `SessionHello`, `SessionHelloAck` in
      `crates/mvm-core/src/policy/security.rs`. `MAX_FRAME_SIZE` audit
      kept the existing 256 KiB cap (the value is conservative for
      every current request shape). Six new regression tests cover the
      unknown-field rejection paths.
- [x] **W4.2** `cargo-fuzz` harness lives at
      `crates/mvm-guest/fuzz/` with two targets:
      `fuzz_guest_request` (host→guest enum) and
      `fuzz_authenticated_frame` (signed-envelope wrapper). Corpus
      seeded with valid frames committed under
      `corpus/fuzz_guest_request/`. Excluded from the main workspace
      because `libfuzzer-sys` only links under cargo-fuzz's wrapper.
      Driven by `just fuzz-guest-request` / `just fuzz-authenticated-frame`.
- [x] **W4.3** `scripts/check-prod-agent-no-exec.sh` builds the agent
      with `--no-default-features` and asserts the demangled symbol
      `mvm_guest_agent::do_exec` is absent. Wired into
      `.github/workflows/ci.yml` as the `prod-agent-no-exec` job and
      runnable locally via `just security-gate-prod-agent`. The grep
      anchors on the binary's crate name to skip stdlib's unrelated
      `<std::sys::process::unix::common::Command>::do_exec`.
- [x] **W4.4** Port-forward TCP target pinned to a
      `PORT_FORWARD_TCP_HOST` constant in
      `crates/mvm-guest/src/bin/mvm-guest-agent.rs`, with a regression
      test (`test_port_forward_target_is_loopback`) that parses the
      constant and asserts `IpAddr::is_loopback`. Audit confirmed the
      agent binds *no* TCP listeners — vsock binds only — so there is
      no `0.0.0.0` surface to defend.
- [x] **W4.5** Guest agent now launches as uid 901 (`mvm-agent`) via
      `setpriv --reuid=901 --regid=901 --groups=901,900
      --bounding-set=-all --no-new-privs --inh-caps=-all`.
      `nix/minimal-init/lib/04-etc-and-users.sh.in` provisions the
      `mvm-agent` user before `/etc` is bind-mounted read-only;
      `default.nix::guestAgentBlock` chgrps
      `/etc/mvm/{integrations,probes}.d/` to the shared service group
      so the dropped-privilege agent can still read its drop-ins.
      (Initially shipped with `--clear-groups`; dropped under plan 35
      §C1.2 — see W2.3 for the rationale.)

### W5 — Supply chain  ✅ shipped — 2026-04-30  [`plans/29-w5-supply-chain.md`](plans/29-w5-supply-chain.md)

- [x] **W5.1** Dev-image and default-microvm downloads in
      `crates/mvm-cli/src/commands/env/apple_container.rs` now fetch
      the release's per-arch checksum manifest, stream each artifact
      through SHA-256, and reject + delete the file on mismatch.
      `MVM_SKIP_HASH_VERIFY=1` documented as the emergency-rotation
      escape. Five regression tests in `hash_verify_tests` cover
      the happy path, the mismatch path, the env-var bypass, and the
      manifest-parser edge cases.
- [x] **W5.2** `deny.toml` at the workspace root + the `deny` job in
      `.github/workflows/ci.yml` runs `cargo deny check` (advisories,
      licenses, bans, sources). Three audited unmaintained-advisory
      ignores documented inline. Pre-commit hook runs the same
      locally when `cargo-deny` is installed.
- [x] **W5.3** `reproducibility` job in `ci.yml` builds `mvmctl`
      twice from a clean state with `SOURCE_DATE_EPOCH`,
      `CARGO_INCREMENTAL=0`, and `--remap-path-prefix` pinned, then
      `diff`s the SHA-256s. Mismatch fails the build with a clear
      `::error::` annotation.
- [x] **W5.4** Release workflow (`release.yml:205-247`) already
      emits a CycloneDX SBOM via `cargo-cyclonedx`, cosign-signs it,
      and attaches `sbom.cdx.json` + `.bundle` to every GitHub
      release.

### W6 — Documentation + CI gates  ✅ shipped — 2026-04-30  [`plans/30-w6-docs-and-ci-gates.md`](plans/30-w6-docs-and-ci-gates.md)

- [x] **W6.1** ADR-002 lives at
      `specs/adrs/002-microvm-security-posture.md`.
- [x] **W6.2** `CLAUDE.md` now carries a "Security model" section
      enumerating the seven CI-enforced claims, the test or workflow
      backing each, and the named non-goals from ADR-002.
- [x] **W6.3** New `.github/workflows/security.yml` consolidates
      `cargo-deny`, `cargo-audit`, the `prod-agent-no-exec` symbol
      grep, the reproducibility double-build, the cargo-fuzz lane
      (5min on PRs, 30min nightly cron), and the W5.1 hash-verify
      regression. Verity / boot lanes will land with W3.
- [x] **W6.4** `mvmctl security status` adds five live probes:
      vsock proxy socket mode, `~/.mvm` mode, prebuilt dev image
      cache state, `deny.toml` presence, and the hash-verified
      download claim. Non-JSON output prints the security + CI
      badge URLs. Unit tests cover probe shape and the deny-config
      lookup.

### W7 — Nix tree alignment with best-practices guide  🟡 in progress  [`plans/31-nix-best-practices-cleanup.md`](plans/31-nix-best-practices-cleanup.md)

Branch: `feat/nix-best-practices-cleanup`. Audit recorded in
[`specs/references/mvm-nix-best-practices.md`](references/mvm-nix-best-practices.md);
phased plan in
[`plans/31-nix-best-practices-cleanup.md`](plans/31-nix-best-practices-cleanup.md).

Scope summary (each phase is independently mergeable):

- **Phase 1** — In-place spirit-of-guide fixes. Bake `/etc/mvm/{integrations.d,probes.d}` perms into the rootfs at build time; replace runtime `find -delete` with `rm -f`; move `udhcpc.sh` into the Nix store; explicit `config = {}` on every nixpkgs import; `builtins.path { … name = "mvm-source"; filter = …; }` (drops `.git`, `target/`, `nixos.qcow2`, `.playwright-mcp/` from the eval-time copy); commit every missing `flake.lock`; add `variant = "prod" | "dev"` tag plumbed through `mkGuest` (visible in store path + `/etc/mvm/variant`); extend `scripts/check-prod-agent-no-exec.sh` to assert variant ↔ feature pairing; delete `nix/examples/{paperclip,openclaw}/`.
- **Phase 1.5** — Lima VM rename `mvm` → `mvm-builder` across runtime crates, CLI, lima template, Justfile, CLAUDE.md, memory entries. Bridge `br-mvm` stays. Migration is user-visible (one-line command, no auto-rename).
- **Phase 2** — Repo layout move to the guide's `nix/{packages,devshells,checks,apps,images,lib,…}` shape. Renames `nix/dev-image/` → `nix/images/builder/`, `nix/default-microvm/` → `nix/images/default-tenant/`, flattens `nix/dev/` to `nix/lib/dev-agent-overlay.nix` (it's an overlay, not an image). Updates mvmctl path strings + CI workflow paths (`release.yml:114,136,177`).
- **Phase 3** — New flake outputs split by execution environment. `packages.<sys>.{mvm,default}` (mvmctl Rust binary), `apps.<sys>.{mvm,default,dev}`, `devShells.<sys>.default` (host / dev-machine shell), `devShells.<sys>.builder` (Linux builder-VM-side shell), `checks.<sys>.{eval,build}`, `formatter.<sys>` (`nixfmt-rfc-style`), `treefmt.toml`. Replace `mkNodeService`'s 3-stage FOD-then-patch with `pkgs.buildNpmPackage`. Promote `xtask` to its own package and drop it from the agent fileset. Source rust toolchain from `rust-toolchain.toml`. Add `passthru.role = "builder" | "tenant"` to image derivations.
- **Phase 4** — Systems coverage: add `aarch64-darwin` to `eachSystem`. Gate Linux-only outputs (`mvm-guest-agent`, `firecracker-kernel`, builder devshell, image-build checks) via `optionalAttrs pkgs.stdenv.isLinux`. Darwin keeps `mvm`/apps/host-devshell/formatter/eval-only-checks per the guide's "macOS dev shells may include Lima/QEMU but must not pretend KVM-only features work locally."
- **Phase 5** — `ops/` scaffolding. Move `scripts/{install-systemd,dev-setup,mvm-install}.sh` into `ops/{systemd,bootstrap}/`. README per subdir documenting what host state each script changes and why elevated privileges are required. `mvmctl` host mutation in `network.rs` (TAP/iptables) is **flagged for product decision** — strict reading of the guide says move to `ops/networking/bridge-setup.sh` with `mvmctl dev up` becoming warn-only; lenient reading says user-invoked CLI ≠ `nix develop`, leave it. Pending decision before folding in.

Status:

- [x] **W7.1 (Phase 1)** — In-place rootfs/flake fixes — landed 2026-04-30; **builder-VM-side validation done 2026-05-01** inside `mvm-builder` against `nix/images/default-tenant#packages.aarch64-linux.default` (`mvm-default-microvm-prod`): `debugfs` confirms `/etc/mvm/{integrations.d,probes.d}` mode `0750`, `/etc/mvm/variant` content `prod\n` mode `0644`, `/tmp/udhcpc.sh` absent from rootfs (resolved to `/nix/store/*-mvm-udhcpc-action` script). `nix flake check` passes on all 9 flakes; `cargo test --workspace` 1067 pass; `nix eval` confirms `variant="prod"` on default-microvm and `variant="dev"` on dev-image.
- [x] **W7.2 (Phase 1.5)** — Lima VM rename `mvm` → `mvm-builder` — landed 2026-04-30; **migration verified done on dev box 2026-05-01** (`limactl list` shows only `mvm-builder`; legacy `mvm` removed). New constants `VM_NAME` / `LEGACY_VM_NAME` in `mvm-runtime::config`, six hardcoded literals in `doctor.rs` migrated to the constant, new `bootstrap::warn_if_legacy_lima_vm` detects legacy VM and prints a one-line manual migration command (no auto-rename), wired into both `mvmctl bootstrap` and `mvmctl dev up`. Docs (`AGENTS.md`, `specs/01-project.md`, `specs/runbooks/w3-verified-boot.md`, `public/.../{architecture,troubleshooting}.md`, `crates/mvm-runtime/README.md`) updated. 1067 tests pass.
- [x] **W7.3 (Phase 2)** — Repo layout move — landed 2026-04-30. `nix/{guest-agent-pkg,firecracker-kernel-pkg}.nix` → `nix/packages/{mvm-guest-agent,firecracker-kernel}.nix`; `nix/{minimal-init,rootfs-templates,kernel-configs}` → `nix/lib/`; `nix/dev-image/` → `nix/images/builder/`; `nix/default-microvm/` → `nix/images/default-tenant/`; `nix/examples/*` → `nix/images/examples/*` (paperclip + openclaw deletions staged from earlier `git rm`). Internal `import` paths in `nix/flake.nix` updated, sibling-flake `mvm.url` arithmetic fixed, mvmctl Rust path strings (`apple_container.rs`, `commands/{mod,vm/exec}.rs`, `mvm-build/dev_build.rs`, `fleet.rs`) updated, CI workflow paths in `release.yml` updated, all 7 flake.locks regenerated. `nix flake check --no-build` clean on every flake; `cargo test --workspace` 1067/1067; clippy clean.
- [x] **W7.4 (Phase 3)** — New flake outputs — landed 2026-04-30. New `packages.<sys>.{mvm,default,xtask}` (mvmctl Rust CLI + xtask runner via fileset-filtered `rustPlatform.buildRustPackage`). New `apps.<sys>.{mvm,default,xtask}` for `nix run`. New `devShells.<sys>.{host,default}` (everywhere) and `devShells.<sys>.builder` (Linux only). New `formatter.<sys> = pkgs.nixfmt-rfc-style` plus `treefmt.toml` covering nix/rust/shell/markdown. New `checks.<sys>.mvm-eval`. `passthru.role = "tenant" | "builder"` plumbed through `mkGuest`; `nix/images/builder/flake.nix` sets `role = "builder"`. Pre-commit hook runs `nix fmt --check` when `nix` is on PATH. **Deferred** (TODO comment in `nix/flake.nix:340-353`): `mkNodeService` 3-stage FOD-then-patch → `pkgs.buildNpmPackage` swap — needs Linux builder validation against hello-node before flipping (output layout changes from `$out/dist/...` to `$out/lib/node_modules/<pname>/dist/...`).
- [x] **W7.5 (Phase 4)** — `aarch64-darwin` + `x86_64-darwin` coverage — landed 2026-04-30. `flake-utils.lib.eachSystem` extended with both Darwin systems. `lib.mkGuest` exposed everywhere (function-only, no eager call). `packages.<sys>.{mvm,default,xtask}` cross-compile to native target. `packages.<sys>.{mvm-guest-agent,mvm-guest-agent-dev}` and `devShells.<sys>.builder` gated by `pkgs.lib.optionalAttrs pkgs.stdenv.isLinux`. Per-system attrs verified: `packages.aarch64-darwin = [default, mvm, xtask]`, `packages.x86_64-linux = [default, mvm, mvm-guest-agent, mvm-guest-agent-dev, xtask]`, `devShells.aarch64-darwin = [default, host]`. Reverted `mvmSrc = builtins.path` (incompatible with `lib.fileset.toSource`); per-package fileset already restricts closure.
- [x] **W7.6 (Phase 5)** — `ops/` scaffolding — landed 2026-04-30. New `ops/{bootstrap,permissions,networking,systemd}/` with READMEs documenting what each script mutates and why elevated privileges are needed. `git mv scripts/install-systemd.sh ops/systemd/install.sh`, `git mv scripts/dev-setup.sh ops/bootstrap/dev-setup.sh`, `git mv scripts/mvm-install.sh ops/bootstrap/install.sh`. `dev-setup.sh` header rewritten with mutation/idempotence summary. `public/.../development.md` updated to point at the new path. `ops/networking/` is documentation-only — `mvmctl`'s `network.rs` host-mutation question (strict vs. lenient guide reading) remains a deferred product decision flagged in the README and the plan.

## Success criteria

By sprint close, the project must be able to make these claims with
technical receipts (one CI gate per claim):

1. *No host-fs access from a guest beyond explicit shares.*
2. *No guest binary can elevate to uid 0.*
3. *A tampered rootfs ext4 fails to boot.*
4. *The guest agent does not contain `do_exec` in production builds.*
5. *Vsock framing is fuzzed.*
6. *Pre-built dev image is hash-verified.*
7. *Cargo deps are audited on every PR.*

W1 already supplies the regression infrastructure for #4 (proxy socket
perms test) and #2 (default seccomp tier). The remaining five claims
land with W2–W6.

## Phasing

W1 is shipped. W2–W6 are independent and can land in any order; W3
(verity) is the largest and likely deserves a sprint of its own if W2
+ W4 + W5 + W6 close out faster.

## Non-goals (named explicitly, see ADR-002)

- Defending against a malicious *host*. mvmctl trusts the host with
  the hypervisor, GC roots, and private build keys.
- Multi-tenant guests. One guest = one workload.
- TPM/SEV/hardware attestation. Out of scope for v1.
- Hypervisor-level egress policy enforcement L7 / DNS-pinning. The
  L3 tier shipped via plan 32 / Proposal D + `NetworkPreset::Agent`
  (PR #20). The L7 tier (mitmdump-based HTTPS proxy + DNS-answer
  pinning) is scoped in
  [`plans/34-egress-l7-proxy.md`](plans/34-egress-l7-proxy.md);
  PR #23 ships the foundation (`EgressMode::L3PlusL7`,
  `EgressProxy` trait, `StubEgressProxy`). Runtime backing remains
  a non-goal for Sprint 42.

## Sprint 43 — Nix-agent ecosystem adoption (in flight)

Master plan: [`plans/32-mcp-agent-adoption.md`](plans/32-mcp-agent-adoption.md).
Five proposals (A, A.2, B, C, D) plus cross-repo handoff plan 33.

### Shipped (PRs open, awaiting review)

- **PR #20** [`feat/mcp-agent-adoption`](https://github.com/tinylabscom/mvm/pull/20) ←
  `main` — plan 32 base. New `mvm-mcp` crate (protocol-only +
  stdio), A v1 stdio MCP server, B `nix/images/examples/llm-agent/`
  showcase flake, C local-LLM probe defaults, D v1
  `NetworkPreset::Agent` (L3-only). New ADRs 003 / 004; new plans
  32 / 33.
- **PR #21** [`feat/mcp-session-semantics`](https://github.com/tinylabscom/mvm/pull/21) ← #20 —
  A.2 v1 (session bookkeeping). `SessionMap` + `Reaper` trait +
  audit kinds + 30 s-tick reaper thread + Drop drain.
- **PR #22** [`feat/mcp-session-warm-vm`](https://github.com/tinylabscom/mvm/pull/22) ← #21 —
  A.2 v2 (warm-VM materialisation). `boot_session_vm` /
  `dispatch_in_session` / `tear_down_session_vm` exec primitives;
  per-session `Arc<Mutex<SessionVm>>` map; boot-race handling;
  reaper actually tears VMs down.
- **PR #23** [`feat/egress-l7-proxy`](https://github.com/tinylabscom/mvm/pull/23) ← #22 —
  L7 egress foundation. `EgressMode` enum (`Open` / `L3Only` /
  `L3PlusL7`), `EgressProxy` trait + `StubEgressProxy`, plan 34
  scoped.

All four PRs: `cargo build --workspace` clean, `cargo test --workspace`
green (mvm-mcp 31 tests including session lifecycle, mvm-core +6
EgressMode tests + 3 agent-preset tests, mvm-cli +2 probe tests),
`cargo clippy --workspace --all-targets -- -D warnings` clean,
`cargo build -p mvm-mcp --no-default-features --features
protocol-only` clean (mvmd-ready per plan 33).

### Deferred — concrete follow-ups

| Item | Plan | Why deferred | Estimated size |
|---|---|---|---|
| **L7 egress runtime backing** (7 tiers + 12 cross-cutting considerations folded — see plan 34 §"Cross-cutting considerations") | [`plans/34-egress-l7-proxy.md`](plans/34-egress-l7-proxy.md) | Heavyweight runtime dep (mitmdump pulls Python + cryptography, ~80 MiB closure); CA cert generation has corner cases (Name-Constrained per-VM leaves, rotation, expiry); DNS pinning needs IPv6 + CNAME-chain handling. Live-KVM integration testing is mandatory. New ADR-006 (PR #33) locks the cryptographic story before code starts. | ~1.5 sprints |
| **A.2 v2 live-KVM smoke** (cold-boot vs warm-VM latency comparison on `claude-code-vm`; race-condition test for parallel first-calls in same session; snapshot-resume against the Anthropic-allowlisted agent VM) | Plan 32 §"Proposal A.2" | Hardware not available in the dev environment; needs a Linux/KVM host with a real Firecracker stack. | ~1 day |
| **Hosted MCP transport (HTTP/SSE)** | [`plans/33-hosted-mcp-transport.md`](plans/33-hosted-mcp-transport.md) | Cross-repo: implementation lives in [mvmd](https://github.com/auser/mvmd). mvm-mcp's `protocol-only` feature is already shipped (PR #20) so mvmd can consume the wire schema unchanged. | mvmd owns sizing |
| **Per-template `default_network_policy`** ✅ shipped (PR `feat/template-default-network-policy`) | ADR-004 §"Decisions" 6 | `TemplateSpec` gains `Option<NetworkPolicy>` (back-compat via `#[serde(default)]` + `skip_serializing_if`). `mvmctl template create --network-preset agent` bakes it; `mvmctl up` consults it as fallback when no CLI flags supplied; `mvmctl template info` prints it. `llm-agent` README updated to use the baked default. | ~1 day |
| **CI lane `mcp-server-smoke`** ✅ shipped (PR #24) | Plan 32 §"Proposal A — CI gate" | Real JSON-RPC roundtrip script + CI job. Caught a real `logging::init` stdout-pollution bug in the process. | ~½ day |

### Sprint 43 success criteria

By sprint close, the project should be able to claim:

1. *LLM clients drive mvmctl as an MCP sandbox* (PR #20 — shipped).
2. *Sessions persist warm VMs across calls with idle/max reaping* (PRs #21 + #22 — shipped, live-KVM smoke deferred).
3. *Hardened LLM-agent VM exists as a worked example* (PR #20 / Proposal B — shipped).
4. *Local-LLM-first scaffolding* (PR #20 / Proposal C — shipped).
5. *L3 hypervisor egress allowlist with an `agent` preset* (PR #20 / Proposal D — shipped).
6. *L7 HTTPS proxy + SNI/Host enforcement* (foundation in PR #23, runtime in plan 34 — deferred).
7. *mvmd-ready protocol crate* (PR #20's `protocol-only` feature — shipped; mvmd consumption is plan 33's job).

5 of 7 are fully shipped on `feat/egress-l7-proxy`; 1 has its
foundation in place; 1 is cross-repo work. The sprint can close on
review approval of PRs #20–#23 — claim 6 is honestly stated as
"foundation shipped; runtime in plan 34" and that's the right
boundary given the runtime dep weight.

Cross-repo handoff for hosted MCP transport (HTTP/SSE) is documented
in [`plans/33-hosted-mcp-transport.md`](plans/33-hosted-mcp-transport.md);
implementation lives in mvmd, not this repo.

## Sprint 44 — Whitepaper alignment (proposed)

Master plan: [`plans/37-whitepaper-alignment.md`](plans/37-whitepaper-alignment.md).
Walks the V2 whitepaper (`specs/docs/whitepaper.md`) section by section,
identifies what `mvm` (the runtime/CLI half — not `mvmd`) is missing
relative to its claims, and sequences the work into six waves. Includes
ADR-004 (PII redaction lives in `mvm`, not `mvmd`) staged for creation
at `specs/adrs/004-pii-redaction-in-mvm.md` when implementation begins.

### Why this sprint

The whitepaper's load-bearing AI-native claims — signed `ExecutionPlan`
contract, Zone B runtime supervisor, L7 egress + PII redaction,
tool-call mediation, attestation-gated key release, signed policy
bundles, runtime artifact capture, audit binding to plan version — have
no code path on `mvm` today. Sprint 42 closed the local-isolation
substrate (W1–W6); Sprint 43 shipped MCP + L3 egress + the L7 proxy
foundation (PR #23). Sprint 44 builds the rest of the whitepaper's
runtime contract on top of that substrate.

### Wave breakdown

Effort labels: **XS** ≤ ½ day · **S** 1–2 days · **M** 3–5 days · **L** > 1 sprint.

- **Wave 0 — Whitepaper truth fixes (XS, prereq).** Soften §3.1 backend
  list, §14 hardware claims, §15.1 PII as design intent until built.
  Update CLAUDE.md / MEMORY.md: W3 dm-verity is **shipped**.
- **Wave 1 — Foundation (S+M).** New crates `mvm-plan`, `mvm-policy`,
  `mvm-supervisor` (lifted from `mvm-hostd`). `Supervisor::launch(plan)`
  happy path. Audit binds to plan/policy/image. Plus B6 (kill switch),
  B8 (cosign verify cache), B15 (zeroize lint), B16 (local registry),
  B19 (admission audit), B21 (config-change audit), C1 (supervisor
  self-attest), C3 (anti-debug), C4 (supervisor death = fail-closed),
  E2 (policy precedence), G4 (plan replay protection — latent bug fix).
- **Wave 2 — Differentiator (M).** L7 egress proxy in supervisor (plan
  34 expanded); inspector chain (SecretsScanner, SsrfGuard,
  InjectionGuard, DestinationPolicy); AiProviderRouter + PiiRedactor
  (detect-only first); tool-call vsock RPC + ToolGate wired. Plus B17
  (egress audit completeness with audit-emits-before-forward CI gate),
  B18 (tool audit), E1 (false-positive circuit breaker — ship-blocker),
  G1 (streaming session audit), G2 (retry-storm dedup).
- **Wave 3 — Identity & artifact closure (M).** Attestation key-release
  gate with TPM2 provider; per-run secret grants + revoke-on-stop;
  audit chain signing + per-tenant streams + export; artifact capture
  path (virtiofs `/artifacts` + ArtifactCollector). Plus B7 (audit
  buffering during mvmd outage), B9 (workload identity JWT), B10
  (memory scrub on stop), B11 (host-published trusted time), B12 (crash
  dump capture), B14 (snapshot integrity + plan-id binding), B20
  (secret-grant pairing CI), B22 (audit-write health metrics), C2
  (channel rekey), D1 (webhook inspection), D2 (RAG/retrieved-content
  inspection), D3 (file-upload inspection), E3 (attestation clock
  skew), E4 (disk-full audit), F1 (cost telemetry), F2 (stuck-workload
  detection), F4 (tenant-visible audit projection), G3 (cross-plan
  request stitching).
- **Wave 4 — Multi-tenant + release (M).** Per-tenant netns,
  per-tenant DEK, ReleasePin admission + two-slot policy rollback,
  DataClass admission gate.
- **Wave 5 — Surface & ergonomics (S+M).** Local HTTP API on supervisor
  Unix socket, `mvm-sdk` crate, cross-backend CI matrix on §3.3 fixture
  plan, threat-control matrix CI generator. Plus F3 (reproducible plan
  execution).
- **Wave 6 — Confidential & adapters (L, optional).** SEV-SNP / TDX
  provider real impls; Lima/Incus/containerd adapters; Vault / AWS SM /
  GCP SM secret providers.

### Cornerstones

Two pieces unblock everything else and should land first:

1. **`mvm_core::ExecutionPlan`** (§3.3, Wave 1) — typed, signed plan
   replacing scattered `RunParams` / `FlakeRunConfig`. Every
   "signed/audited/policy-pinned" claim hangs off this. Including
   `valid_from` / `valid_until` / `nonce` (G4) closes the latent
   replay bug.
2. **`mvm-supervisor` daemon** (§7B, Wave 1) — packages the existing
   `mvm-hostd` skeleton plus EgressProxy, ToolGate, KeystoreReleaser,
   AuditSigner, ArtifactCollector behind a single trusted process.
   Owns the data path so tenant code can't bypass policy.

### Differentiator

L7 egress + AI-provider PII redaction (§15 + §15.1, Wave 2). The
single most important AI-native claim in the whitepaper and currently
zero code. Ships as **detect-only** first to safely measure detector
quality on real traffic before transforms are enabled. **Fail-closed**
on detector error — any inspection failure blocks the request, never
forwards raw.

### Trust boundary decision (ADR-004)

PII redaction stays in `mvm`, not `mvmd`. The host running the microVM
is the only point at which a request body is in plaintext on
infrastructure we trust. Putting redaction in `mvmd` would collapse §8
plane separation, expand §13 control-plane blast radius (an `mvmd`
compromise would expose every prompt), break §19 residency, and add a
network round-trip per AI call. `mvmd` owns policy authoring,
signing, distribution, and fleet-aggregated reporting; `mvm` owns the
engine on the data path. ADR-004 staged in plan 37 Addendum A.

### Sprint 44 success criteria

By sprint close, the project should be able to claim:

1. *Workloads run from typed, signed `ExecutionPlan`s with replay
   protection.* (Wave 1)
2. *A trusted supervisor process owns the data path; tenant code
   cannot bypass policy.* (Wave 1)
3. *Every outbound egress event produces a signed, plan-bound audit
   entry.* (Wave 2)
4. *AI-provider requests pass through PII inspection; detector errors
   fail closed.* (Wave 2)
5. *Tool calls are mediated by the supervisor's `ToolGate` and
   audited.* (Wave 2)
6. *Attestation gates secret release; TPM2 implementation exists.*
   (Wave 3)
7. *Workload outputs are captured under `ArtifactPolicy` retention,
   not destroyed on exit.* (Wave 3)

Waves 4–6 are post-44 follow-ups; the sprint can close on Waves 0–3.

### Non-goals (named explicitly)

- **mvmd-side concerns:** fleet placement, releases / canary / rollout,
  host registration, cross-host wake/sleep, policy distribution,
  control-layer key rotation. Wire types live in
  `mvm_core::mvmd_iface` so mvmd can land later without reshaping
  `mvm`.
- **Hardware-attested vendor trust roots beyond TPM2 in the first pass.**
  SEV-SNP / TDX providers ship as `unimplemented!()` scaffolds.
- **Vendor-specific PII detector beyond regex/dictionary v0.**
  `Detector` trait is open for later additions.
- **Workflow-engine specific SDKs beyond the generic `mvm-sdk`.**
- **Model selection, prompt engineering, cost optimization, federated
  learning** (plan 37 Addendum H — application concerns, not runtime).

## Sprint 45 — Function-call entrypoints (in flight — substrate shipped, live smoke open)

Master plan: [`plans/41-function-call-entrypoints.md`](plans/41-function-call-entrypoints.md)
(mvm side, six workstreams). Comprehensive design rationale + 16
security mitigations: [`plans/41-function-entrypoints-design.md`](plans/41-function-entrypoints-design.md).
Architecture decision: [`adrs/007-function-call-entrypoints.md`](adrs/007-function-call-entrypoints.md).
Cross-repo: decorationer (mvmforge) `specs/adrs/0009-function-entrypoints.md`,
`specs/plans/0003-function-entrypoint-runtime.md`,
`specs/plans/0004-network-deny-default.md`.

### Status (2026-05-05)

mvm-side W1–W5 shipped to `main` in PRs #66–#71 (with #72 replacing
auto-closed #68 — see "Stack-merge artifacts" below). W6 (network
deny-default for function workloads) is captured cross-repo: the IR
shape lives in decorationer plan 0004, and the mvm-side TAP-skip glue
is mechanical once mvmforge plumbs the IR field. decorationer plan
0003 phase 1 (function-entrypoint IR variant + `Format` closed enum)
shipped as decorationer #3.

The live-KVM smoke fixture (`mkGuest extraFiles` + the `echo-fn` example
flake + `tests/smoke_invoke.rs` gated on `MVM_LIVE_SMOKE=1`) is **PR #73,
not yet run** — the substrate compiles and skips cleanly on incapable
hosts; the actual boot+invoke against a Linux/KVM (or macOS 26+ Apple
Container) host hasn't happened yet. That's the load-bearing open item.

### Why this sprint

Modal-style `f.remote(...)` semantics on top of mvm. Decorate a Python
or TS function, call it from the host, body runs in a microVM, return
value flows back. mvmforge already lands the deploy-time half
(decorator → IR → flake → boot); the function body is currently
ignored. What's missing is the call-time half — a constrained,
production-safe vsock verb that runs a baked program with stdin piped
and stdout/stderr captured.

The user's framing: a function call is an *implicit program*. The
image bakes a tiny wrapper (Python/Node runner generated by
mvmforge's Nix factories); mvm just runs it with stdin piped and
stdout captured. mvm doesn't learn Python or TS — it gets a
constrained verb that runs *the* baked entrypoint, with caps,
timeouts, per-call hygiene, snapshot integrity, and explicit-only
network grants.

The hard constraint inherited from this sprint and recorded in
CLAUDE.md memory: **everything ships at build time, ALWAYS.** No
closure shipping at call time, no runtime function registration, no
dynamic dispatch by name from outside. The wrapper, function body,
format, allowlist, and grants are all baked into the rootfs at
image-build time; only call-payload bytes (stdin) are runtime data.

### Workstream breakdown

Six workstreams, each independently shippable.

- **W1 — Wire protocol additions.**  ✅ shipped — PR #67. Adds
  `GuestRequest::RunEntrypoint` + `GuestResponse::EntrypointEvent`
  (streaming-shaped, buffered v1) + `RunEntrypointError` enum.
  `#[serde(deny_unknown_fields)]`; fuzz targets extended; agent
  stub arm in place.
- **W2 — Agent handler.**  ✅ shipped — PR #72 (recreated from
  auto-closed #68). New `crates/mvm-guest/src/entrypoint.rs`
  module: `EntrypointPolicy::production().validate()` reads
  `/etc/mvm/entrypoint`, `realpath`s, asserts mode/uid/prefix,
  holds fd; `execute()` spawns with `process_group(0)`,
  `RLIMIT_CORE=0`, `env_clear()`, drains stdout/stderr concurrently
  into capped buffers, kills on cap breach or timeout via SIGTERM
  → grace → SIGKILL escalation. `handle_run_entrypoint` in the
  agent serializes per-VM via static `Mutex`, creates per-call
  TMPDIR mode 0700 with RAII cleanup, writes `Stdout`/`Stderr`
  events streaming + returns terminal `Exit`/`Error`.
- **W3 — `mvmctl invoke` CLI.**  ✅ shipped — PR #69. New
  top-level verb. New `mvm_guest::vsock::send_run_entrypoint`
  streaming consumer (frame loop until `is_terminal()`). Boots
  transient VM via `boot_session_vm`, dispatches, tears down
  always. `--fresh`/`--reset` flags wired (informational in v1
  until session-pool plan lands). Exit-code mapping: wrapper's
  own code on `Exit`, 124 on timeout, 137 on `WrapperCrashed`,
  1 for everything else (Busy / PayloadCap / EntrypointInvalid
  / InternalError) with a warn-line to stderr.
- **W4 — Snapshot integrity (HMAC).**  ✅ shipped — PR #70. New
  `mvm-security/src/snapshot_hmac.rs`: `~/.mvm/snapshot.key`
  lazy-init mode 0600, HMAC-SHA256 over length-prefixed
  envelope (`be_u32(schema_version) || be_u64(vmstate_len) ||
  vmstate_bytes || be_u64(mem_len) || mem_bytes ||
  be_u32(version_len) || version_bytes`) — splice-resistance
  asserted by regression test. Atomic seal via `<file>.tmp` +
  fsync + rename; constant-time tag comparison on verify;
  fast-fail size check before streaming. Wired into
  `template/lifecycle.rs::seal_snapshot_artifacts` (post Firecracker
  create) and `microvm.rs::restore_from_template_snapshot` (before
  any Firecracker spawn). Migration: missing sidecar → warn +
  proceed by default; `MVM_SNAPSHOT_HMAC_STRICT=1` flips to hard
  error; `MVM_ALLOW_STALE_SNAPSHOT=1` accepts version-mismatch.
- **W5 — CI gates + doctor.**  ✅ shipped — PR #71. Combined
  `prod-agent-runentry-contract` lane (renamed from
  `prod-agent-no-exec`) — ONE build, ONE step, BOTH assertions:
  `do_exec` symbol ABSENT and `handle_run_entrypoint` symbol
  PRESENT on the same shipping binary. New `mvmctl doctor`
  probes: snapshot HMAC key (mode 0600, length); snapshot dirs
  (walk `~/.mvm/templates/*/artifacts/*/snapshot/` and report
  the first looser-than-0700 dir). New vsock verb
  `EntrypointStatus` for live-VM probing (prod-safe, no inputs;
  reports validated path + ok-flag).
- **W6 — Network: deny-default for function workloads.**  🟡
  cross-repo, IR side captured. Function-entrypoint workloads
  default `network.mode = "none"`. The IR shape (default
  derivation from `entrypoint.kind`, wildcard-egress rejection,
  granular grants in v2) is captured in decorationer plan 0004
  (decorationer #2 merged). mvm-side glue is mechanical: when
  mvmforge ships the IR change, mvm honours `mode = "none"` by
  skipping TAP allocation. **Open** — needs the mvmforge IR
  emit + an mvm-side regression test that asserts a `mode =
  "none"` workload truly has no TAP.

### Substrate validation (live smoke)

PR #73 adds the substrate-validation infrastructure:

- `mkGuest` `extraFiles` parameter — bakes arbitrary files into
  the rootfs at build time, owned root, with declared octal mode.
  `extraFiles ? {}` default keeps backward compat for every
  existing caller. The eventual mvmforge `mkPythonFunctionService`
  / `mkNodeFunctionService` factories will use this to bake
  `/etc/mvm/entrypoint` plus the wrapper.
- `nix/images/examples/echo-fn/` — minimal `mkGuest` invocation
  baking a wrapper at `/usr/lib/mvm/wrappers/echo` (`#!/bin/sh\nexec cat\n`)
  plus the marker. No language runtime; just exercises the
  substrate path.
- `tests/smoke_invoke.rs` — two `MVM_LIVE_SMOKE=1`-gated tests
  (round-trip + zero-stdin). Skip cleanly without the env var
  with an `eprintln!` diagnostic.

The substrate (compile, clippy, gated-skip behaviour) is verified;
the actual boot+invoke against a capable host is the open
load-bearing item.

### Cornerstones

Two pieces unblock everything else:

1. **`RunEntrypoint` vsock verb** (W1, W2) — the production-safe
   call substrate that mvmctl invoke and mvmforge SDKs both build
   on. Distinct from `do_exec` so the existing prod gate
   (`prod-agent-no-exec`) stays meaningful.
2. **Combined CI contract gate** (W5) — `prod-agent-no-exec` AND
   `prod-agent-has-runentry` against the *same* binary that ships.
   Prevents feature-flag drift from regressing half the contract
   silently.

### Cross-repo dependency

mvmforge (decorationer) plan 0003 ships in parallel — language SDKs
(Python + TS), Nix factories (`mkPythonFunctionService`,
`mkNodeFunctionService`), hardened wrapper templates. mvm exposes the
`RunEntrypoint` substrate; mvmforge consumes it. The cutover is
coordinated: when mvm's W6 lands the deny-default flip, mvmforge's
factories must already emit the new IR shape. mvmforge owns the
language-specific seccomp tiers (`standard-python`, `standard-node`);
mvm just exposes the tier-loading mechanism (already W2.4).

### Sprint 45 success criteria

By sprint close, the project should be able to claim:

1. *A constrained `RunEntrypoint` vsock verb runs the image's baked
   entrypoint program with stdin piped and stdout/stderr captured;
   `do_exec` remains dev-only.* (W1, W2, W5) — **substrate shipped
   #67/#72/#71; live-KVM exercise pending #73 run.**
2. *`mvmctl invoke` is the prod-safe call surface; `mvmctl exec`
   stays dev-only.* (W3) — **shipped #69; live-KVM exercise pending.**
3. *Firecracker snapshots are HMAC-verified at restore; tampering
   refuses resume.* (W4) — **shipped #70; tamper regression covered
   by unit tests; live-KVM exercise pending.**
4. *Function-entrypoint workloads default to no network; explicit
   IR grants are required for any reachability.* (W6) — **IR side
   captured (decorationer plan 0004); mvm-side TAP-skip pending the
   mvmforge IR emit.**
5. *Default logs do not contain stdin/stdout/stderr content.* (W2,
   W3) — **shipped — agent + mvmctl log metadata only.**
6. *Cross-repo cutover with mvmforge: a Python or TS function
   workload booted from a `mvmforge up` artifact accepts
   `mvmctl invoke <vm> --stdin <args>` and returns stdout encoded
   per the IR-declared format.* (Phase 5 integration test) —
   **blocked on decorationer plan 0003 phases 2–4 (decorator body
   preservation, host SDK call site, Nix factories).**

### Shipped (PRs landed on `main`)

| PR | Workstream | Content |
| --- | --- | --- |
| [#66](https://github.com/tinylabscom/mvm/pull/66) | Docs | ADR-007, plan 41, plan 41-design (16 mitigations), Sprint 45 entry |
| [#67](https://github.com/tinylabscom/mvm/pull/67) | W1 | Wire types: `RunEntrypoint`, `EntrypointEvent`, `RunEntrypointError`; fuzz target |
| [#72](https://github.com/tinylabscom/mvm/pull/72) | W2 | Agent handler + `entrypoint.rs` module + per-call hygiene + concurrency mutex (recreated from auto-closed #68) |
| [#69](https://github.com/tinylabscom/mvm/pull/69) | W3 | `mvmctl invoke` CLI + `send_run_entrypoint` streaming consumer |
| [#70](https://github.com/tinylabscom/mvm/pull/70) | W4 | Snapshot HMAC integrity (seal + verify wired into create/restore paths) |
| [#71](https://github.com/tinylabscom/mvm/pull/71) | W5 | Combined symbol-contract CI lane + doctor probes + `EntrypointStatus` verb |

Cross-repo (decorationer):

| PR | Content |
| --- | --- |
| [decorationer #1](https://github.com/tinylabscom/decorationer/pull/1) | ADR-0009 + plan 0003 (function entrypoint runtime — six-phase) |
| [decorationer #2](https://github.com/tinylabscom/decorationer/pull/2) | Plan 0004 (network deny-default for function workloads — IR side of W6) |
| [decorationer #3](https://github.com/tinylabscom/decorationer/pull/3) | Plan 0003 phase 1 — `Entrypoint::Function` IR variant + `Format` closed enum + new `function-app` corpus entry (byte-identical Python ↔ TS) |

### Deferred — concrete follow-ups

| Item | Plan | Why deferred | Estimated size |
|---|---|---|---|
| **Live-KVM smoke run** ([PR #73](https://github.com/tinylabscom/mvm/pull/73)) | Plan 41 W3 / W5 acceptance | Substrate compiles, clippy-clean, gated-skip works on macOS Darwin 25 host. Boot+invoke needs native Linux/KVM or macOS 26+ Apple Container — neither available in the dev session that wrote it. PR description names three plausible failure modes (`EntrypointInvalid` from chown/uid in fakeroot, vsock missing on host, `mvmctl template build --flake <path>` argv shape) so the human running it knows where to look. | ½ day on a capable host |
| **W6 mvm-side TAP-skip** | Plan 41 W6 + decorationer plan 0004 | mvmforge needs to ship the IR change first (decorationer plan 0003 phase 1 is in, but phase 2–4 SDK + Nix factory work hasn't started). Once the IR carries `entrypoint.kind = "function"` with the deny-default network mode, mvm honours it by skipping TAP allocation. | ~1 day after mvmforge ships |
| **Decorationer plan 0003 phase 2 — Python SDK** | decorationer plan 0003 | Decorator preserves function body in bundled source; emitter writes new IR; bundler ships function source; host call site shells out to `mvmctl invoke`. Blocks live-KVM smoke against a real Python wrapper. | ~2 days |
| **Decorationer plan 0003 phase 3 — TypeScript SDK** | decorationer plan 0003 | Mirror Phase 2 surface. | ~2 days |
| **Decorationer plan 0003 phase 4 — Nix factories** | decorationer plan 0003 | `mkPythonFunctionService` / `mkNodeFunctionService` emitting hardened wrappers (mode=prod with sanitized error envelope, `PR_SET_DUMPABLE=0`, no payload logging) at `/etc/mvm/entrypoint` via mvm's `extraFiles` (already in mvm #73). | ~3 days |
| **Session pool management** | follow-up plan (none yet) | Pre-baked invariant: *single-tenant for VM lifetime*. v1 reuses `boot_session_vm` / `dispatch_in_session` / `tear_down_session_vm` primitives directly. Sizing / eviction / per-tenant isolation / idle reaper are real but separable from the substrate. | ~1 sprint |
| **Streaming chunked output** | follow-up plan (none yet) | v1 wire is streaming-shaped but buffered up to 1 MiB per stream. Lifting the cap means real chunked emission from the agent and a streaming consumer in `send_run_entrypoint`. | ~1 week |
| **Schema-bound payloads (v2 of W3)** | decorationer plan 0003 | Derive JSON Schema from type hints (Python `pydantic` / TS `zod`). Wrapper validates inbound bytes before user code runs. | ~1 week |

### Stack-merge artifacts

The merge cascade left two cosmetic artifacts in the history that
are worth knowing about if you go grepping:

1. **PR #68 → #72**. When I merged #67 with `--delete-branch`, GitHub
   auto-closed #68 because its base branch (`feat/runentrypoint-wire-protocol`)
   was deleted. I rebased the same commits onto current main and
   re-PR'd as #72. W2's commit footer reads `(#72)`, not `(#68)`. #68
   shows on GitHub as **closed-not-merged** with identical content
   to the commit `26bae51` that did land.
2. **Source branches don't survive in commit metadata.** Every
   `feat/*` branch I created (W1 wire, W2 handler, W3 invoke, W4
   snapshot, W5 doctor) was deleted on merge. The squashed commits
   on `main` carry the PR# in the subject line, but the original
   pre-rebase commit DAGs (separate W2-rebase commits etc.) are
   gone from the remote. `git log` looks tidy; `git log --all
   --grep=runentrypoint` finds only the squashed forms.

Both are normal squash-merge consequences; documented here so the
next person to audit the timeline doesn't re-discover them as
suspicious.

### Non-goals (named explicitly)

- **Streaming chunked output.** v1 wire is streaming-shaped but
  buffered up to 1 MiB per stream; chunked v2 lifts the cap once a
  user hits it.
- **Pool sizing / eviction policy.** Session-VM primitives reused
  as-is; pool *management* is a follow-up plan with the pre-baked
  invariant *single-tenant for VM lifetime*.
- **Closure shipping at call time.** Forbidden by build-time-only
  rule; no runtime function registration, no dynamic dispatch.
- **Code-executing serializer formats.** IR enum is closed
  (`json`/`msgpack`); formats whose decoder runs arbitrary code
  are excluded. CI-enforced via wrapper grep.
- **Schema-bound payloads in v1.** v1 keeps caps + format
  validation only; v2 derives JSON Schema from type hints (Python
  `pydantic` / TS `zod`) and validates inbound bytes before user
  code runs.
- **Granular network IR fields in v1.** v1 ships deny-default with
  the existing one-bit `network.mode`; granular grants
  (`egress`/`peers`/`ingress`/`dns`) land in v2 — flipping the
  default later is breaking, the granular surface is additive.
- **Network deny-default flip for non-function workload kinds.**
  Backwards-incompatible for any workload that quietly relied on
  the implicit grant; separate ADR if proposed.
- **SLSA-style attestation of mvmforge artifacts.** v1 leans on
  reproducibility (W5.3) + dm-verity (W3); SLSA is v2+.
- **Multi-tenant guests within one VM.** ADR-002 already excludes;
  function entrypoints don't change this.
- **Authenticated invoke from non-local callers.** vsock socket
  mode 0700 (W1.2) gates to local user; cross-host authn is
  mvmd's problem.

## Completed Sprints

- [01-foundation.md](sprints/01-foundation.md)
- [02-production-readiness.md](sprints/02-production-readiness.md)
- [03-real-world-validation.md](sprints/03-real-world-validation.md)
- Sprint 4: Security Baseline 90%
- Sprint 5: Final Security Hardening
- [06-minimum-runtime.md](sprints/06-minimum-runtime.md)
- [07-role-profiles.md](sprints/07-role-profiles.md)
- [08-integration-lifecycle.md](sprints/08-integration-lifecycle.md)
- [09-openclaw-support.md](sprints/09-openclaw-support.md)
- [10-coordinator.md](sprints/10-coordinator.md)
- Sprint 11: Dev Environment
- [12-install-release-security.md](sprints/12-install-release-security.md)
- [13-boot-time-optimization.md](sprints/13-boot-time-optimization.md)
- [14-guest-library-and-examples.md](sprints/14-guest-library-and-examples.md)
- [15-real-world-apps.md](sprints/15-real-world-apps.md)
- [16-production-hardening.md](sprints/16-production-hardening.md)
- [17-resource-safety-release.md](sprints/17-resource-safety-release.md)
- [18-developer-experience.md](sprints/18-developer-experience.md)
- [19-observability-security.md](sprints/19-observability-security.md)
- [20-production-hardening-validation.md](sprints/20-production-hardening-validation.md)
- [21-binary-signing-attestation.md](sprints/21-binary-signing-attestation.md)
- [22-observability-deep-dive.md](sprints/22-observability-deep-dive.md)
- [23-global-config-file.md](sprints/23-global-config-file.md)
- [24-man-pages.md](sprints/24-man-pages.md)
- [25-e2e-uninstall.md](sprints/25-e2e-uninstall.md)
- [26-audit-logging.md](sprints/26-audit-logging.md)
- [27-config-validation.md](sprints/27-config-validation.md)
- [28-config-hot-reload.md](sprints/28-config-hot-reload.md)
- [29-shell-completions.md](sprints/29-shell-completions.md)
- [30-config-edit.md](sprints/30-config-edit.md)
- [31-vm-resource-defaults.md](sprints/31-vm-resource-defaults.md)
- [32-vm-list.md](sprints/32-vm-list.md)
- [33-template-init-preset.md](sprints/33-template-init-preset.md)
- [34-flake-check.md](sprints/34-flake-check.md)
- [35-run-watch.md](sprints/35-run-watch.md)
- [36-fast-boot-minimal-images.md](sprints/36-fast-boot-minimal-images.md)
- [37-image-insights-dx-guest-lib.md](sprints/37-image-insights-dx-guest-lib.md)
- [38-multi-backend-abstraction.md](sprints/38-multi-backend-abstraction.md)
- [39-developer-experience-dx.md](sprints/39-developer-experience-dx.md)
- [40-apple-container-dev.md](sprints/40-apple-container-dev.md)
- [41-microvm-one-shot-exec.md](sprints/41-microvm-one-shot-exec.md)

---

## Open Follow-ups (carryover from Sprint 41)

Tracked as GitHub issues so they're individually grabbable:

- [ ] [#3](https://github.com/tinylabscom/mvm/issues/3) — Live smoke for `mvmctl exec` on Linux/KVM and Lima dev VM (boot+exec+teardown, `--add-dir`, SIGINT, `nix build` of `nix/default-microvm/`). _Needs real hardware._
- [x] [#4](https://github.com/tinylabscom/mvm/issues/4) — Release artifacts for the bundled default microVM image. Release workflow now builds `nix/default-microvm/` per-arch and uploads `default-microvm-vmlinux-{arch}` / `default-microvm-rootfs-{arch}.ext4` / `default-microvm-{arch}-checksums-sha256.txt`. `ensure_default_microvm_image()` falls back to `download_default_microvm_image()` when Nix is unavailable or the local build fails. Cosign scope unchanged (artifacts unsigned, mirroring `dev-image`).
- [x] [#5](https://github.com/tinylabscom/mvm/issues/5) — mvmforge `launch.json` consumption: `ExecTarget::LaunchPlan` + entrypoint parser + `--launch-plan` flag. Image-from-launch-plan remains a future variant (mvmforge v0 `apps[].source` is itself "deferred").
- [ ] [#6](https://github.com/tinylabscom/mvm/issues/6) — Writable `--add-dir` (virtio-fs or 9p) — separate design / ADR required.
- [x] [#7](https://github.com/tinylabscom/mvm/issues/7) — Snapshot restore for `mvmctl exec` (easy branch: registered template, no `--add-dir`). The harder branch (parameterized snapshots for the `--add-dir` case) stays open under the same issue.
