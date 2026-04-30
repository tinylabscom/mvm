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
      `${utilLinux}/bin/setpriv --reuid=… --regid=… --clear-groups --groups=…,900 --bounding-set=-all --no-new-privs --inh-caps=-all -- /bin/sh -c '…'`.
      `pkgs.util-linux` is in the production closure unconditionally.
- [x] **W2.4** Service launch is wrapped with
      `${guestAgentPkg}/bin/mvm-seccomp-apply <tier> --` (new shim
      binary in `crates/mvm-guest/src/bin/mvm-seccomp-apply.rs`,
      Linux-only target). Default tier is `standard`; override via
      `services.<n>.seccomp = "essential" | … | "unrestricted"`.

### W3 — Verified boot via dm-verity  🟡 host-side shipped + verity device builds correctly, but Firecracker aarch64 cmdline-append clobbers `root=/dev/dm-0` (initramfs fix outstanding)  [`plans/27-w3-verified-boot.md`](plans/27-w3-verified-boot.md) | runbook: [`runbooks/w3-verified-boot.md`](runbooks/w3-verified-boot.md)

- [x] **Kernel** `firecracker-aarch64.config` enables
      `CONFIG_MD`, `CONFIG_BLK_DEV_DM`, `CONFIG_DM_INIT`, and
      `CONFIG_DM_VERITY` so `dm-mod.create=` parses on the cmdline.
- [x] **W3.1** `nix/flake.nix::verityArtifacts` runs
      `veritysetup format` with a pinned zero salt and emits
      `rootfs.{ext4,verity,roothash}` deterministically.
- [x] **W3.2** Apple Container backend gained `VerityConfig` +
      `start_with_verity()`; opens the rootfs read-only, attaches
      the sidecar at `/dev/vdb`, sets the kernel cmdline to
      `root=/dev/dm-0 ro` plus a full `dm-mod.create=…` string.
      Mutual-exclusion check rejects `MVM_NIX_STORE_DISK` + verity.
- [x] **W3.3** Firecracker backend extended `FlakeRunConfig` +
      `VmStartConfig` with `verity_path` / `roothash`. The Lima-VM
      cold-boot, snapshot-restore, and template-snapshot paths all
      probe for the sidecar via `microvm::probe_verity_sidecar()`
      and PUT a third `/drives/verity` to land it at `/dev/vdb`.
      `build_verity_dm_create_arg()` produces the same dm-mod.create
      shape as the Apple Container path.
- [x] **W3.4** `mkGuest` accepts `verifiedBoot ? true`;
      `nix/dev-image/flake.nix` sets `verifiedBoot = false` (overlay
      can't compose with verity). The dev sibling flake forwards
      the kwarg transparently.
- [x] **CI gate** `verified-boot-artifacts` lane in
      `security.yml` builds `nix/default-microvm/` and asserts
      `rootfs.{ext4,verity,roothash}` plus a 64-char hex roothash.
- [ ] **Initramfs (Finding #1)**: small initramfs that runs
      `veritysetup open … && switch_root` so Firecracker's
      auto-appended `root=/dev/vda ro` no longer overrides our
      `root=/dev/dm-0`. Without this the verity device is built
      but the kernel still mounts the raw rootfs.
- [ ] **Boot regression** (live KVM): boot a microVM with verity
      and assert `mount | grep dm-0`. Re-runs after Finding #1.
- [ ] **Tamper regression** (live KVM): flip a byte in
      `rootfs.ext4`, assert the kernel panics on first read.
      Re-runs after Finding #1.

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
      `setpriv --reuid=901 --regid=901 --clear-groups --groups=901,900
      --bounding-set=-all --no-new-privs --inh-caps=-all`.
      `nix/minimal-init/lib/04-etc-and-users.sh.in` provisions the
      `mvm-agent` user before `/etc` is bind-mounted read-only;
      `default.nix::guestAgentBlock` chgrps
      `/etc/mvm/{integrations,probes}.d/` to the shared service group
      so the dropped-privilege agent can still read its drop-ins.

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

- [x] **W7.1 (Phase 1)** — In-place rootfs/flake fixes — landed 2026-04-30. `nix flake check` passes on all 9 flakes; `cargo test --workspace` 1067 pass; `nix eval` confirms `variant="prod"` on default-microvm and `variant="dev"` on dev-image. Outstanding: `git rm` of `nix/examples/{paperclip,openclaw}` (sandbox blocked twice, needs manual removal or permission grant).
- [x] **W7.2 (Phase 1.5)** — Lima VM rename `mvm` → `mvm-builder` — landed 2026-04-30. New constants `VM_NAME` / `LEGACY_VM_NAME` in `mvm-runtime::config`, six hardcoded literals in `doctor.rs` migrated to the constant, new `bootstrap::warn_if_legacy_lima_vm` detects legacy VM and prints a one-line manual migration command (no auto-rename), wired into both `mvmctl bootstrap` and `mvmctl dev up`. Docs (`AGENTS.md`, `specs/01-project.md`, `specs/runbooks/w3-verified-boot.md`, `public/.../{architecture,troubleshooting}.md`, `crates/mvm-runtime/README.md`) updated. 1067 tests pass.
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
- Hypervisor-level egress policy enforcement (beyond NAT/tap choice).
  *Scoped for the next sprint as plan 32 / Proposal D —
  [`plans/32-mcp-agent-adoption.md`](plans/32-mcp-agent-adoption.md).
  Remains a non-goal for Sprint 42.*

## Up next (Sprint 43 preview)

[`plans/32-mcp-agent-adoption.md`](plans/32-mcp-agent-adoption.md) is
the approved master plan for the next sprint:

- **A** — `mvmctl mcp` server (single-tool MCP surface, ADR-003).
- **A.2** — MCP session semantics (snapshot-resumed VMs).
- **B** — `nix/images/examples/llm-agent/` showcase flake.
- **C** — local-LLM-default flip for `mvmctl template init --prompt`.
- **D** — hypervisor egress policy with domain-pinning (ADR-004).

Cross-repo handoff for hosted MCP transport (HTTP/SSE) is documented
in [`plans/33-hosted-mcp-transport.md`](plans/33-hosted-mcp-transport.md);
implementation lives in mvmd, not this repo.

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
