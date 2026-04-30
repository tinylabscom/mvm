# Plan: Align mvm Nix tree with `mvm-nix-best-practices.md`

## Context

The Nix tree under `nix/` was grown organically: flat layout, ad-hoc fragments, missing standard flake outputs, no dev shell, several boot-time `chgrp`/`chmod` ops that should live at rootfs-build time. The guide at `specs/references/mvm-nix-best-practices.md` is now the spec we want to satisfy.

This plan walks each section of the guide, audits the current state against it, and proposes a phased restructure. Phases are ordered so each is independently mergeable.

## Two-machine model (critical to the plan)

mvm has two distinct execution environments. Conflating them is what made the existing tree drift.

| Role | Where it runs | What Nix is for |
|---|---|---|
| **Development machine** (your M4 Mac) | host macOS | Editing source, `cargo build`/`test` on `mvmctl`, optionally `nix develop` for an ergonomic shell. **No image builds happen here.** |
| **Builder VM** | Apple Container on macOS 26+ Apple Silicon, otherwise a Lima Linux VM | Real `nix build` of microVM images, kernel, rootfs, guest agent. Dispatched into via `mvmctl dev` + `shell::run_in_vm`. Itself produced by `nix/dev-image/flake.nix`. |
| **Target microVM** (Firecracker / Apple Container guest) | inside the builder VM (or production host with KVM) | Runs the rootfs the builder VM produced. PID 1 = the `minimal-init` script. |

Implications for the guide:

- **Image-build flake outputs** (`packages.aarch64-linux.mvm-guest-agent`, the `mkGuest` rootfs derivation, etc.) only run inside the **builder VM**. Their tooling (qemu, firecracker, kernel build inputs) belongs in the *builder VM image*, not in the macOS host's dev shell.
- **Host dev shell** on `aarch64-darwin` is for hacking on the `mvmctl` Rust crate. It needs cargo + rust + lima + jq + just — *not* qemu/firecracker.
- **Builder VM dev shell** is what `nix/dev-image/flake.nix` already produces (it bundles `pkgs.nix`, `pkgs.git`, `pkgs.iptables`, etc. into a microVM rootfs that mvmctl boots). That image **is** the builder's dev shell — it's already a `mkGuest` consumer; the guide's tool list applies to the package set passed in there.
- The guide's `/dev/kvm` warning belongs **only** in the macOS host shell hook, telling the user: "On macOS, KVM doesn't exist; mvmctl will boot a Lima VM (or Apple Container) instead. Run `mvmctl dev up`."
- The guide's "Linux production correctness" target is the **builder VM** + the rootfs it emits, not the host.

This split also means:

- **Phase 1's bake-perms-into-rootfs changes happen inside the builder VM's Nix sandbox**, exactly where they belong. They don't touch the host.
- **`nix flake check ./nix` on macOS is eval-only** by design. Real build/test of `aarch64-linux` outputs happens via `mvmctl dev up && mvmctl build …` (which runs `nix build` inside the builder VM). Phase 3's `checks` output codifies both layers.

## Templates: do these changes propagate?

**Yes, for the rootfs-shape changes (Phase 1) — without touching template source.**

User templates (`mvmctl template create/build/list`) and the bundled `nix/examples/*` are independent flakes that reference the parent via:

```nix
inputs.mvm.url = "github:auser/mvm?dir=nix";   # or path:.../nix
# … then …
mvm.lib.${system}.mkGuest { … }
```

Phase 1 modifies `mkGuest`'s internals (`nix/minimal-init/default.nix`, `nix/rootfs-templates/populate.sh.in`). Any template that calls `mvm.lib.<sys>.mkGuest` picks up the new behavior on its next `nix build` — **no edits to the template's `flake.nix` required**. The next time `mvmctl template build <name>` runs (which dispatches `nix build` inside the builder VM), the rebuilt rootfs has:

- `/etc/mvm/{integrations.d,probes.d}` baked in at `0750 root:900`
- No runtime chmod/chgrp loop in the init script
- `udhcpc.sh` resolved to a `/nix/store` path instead of heredoc'd at boot

**Phase 2 (repo layout move) needs care.** Templates that pin to sub-paths of `nix/` (e.g., `path:../mvm/nix/minimal-init`) would break. The published URL convention is `github:auser/mvm?dir=nix` and the local convention is `path:.../nix` (the **directory containing `flake.nix`**). As long as `nix/flake.nix` itself doesn't move and keeps exporting `lib.<system>.mkGuest` with the same signature, templates don't need to change. **What does need updating:** any internal mvmctl logic that hard-codes paths like `nix/dev` or `nix/dev-image` (used by `--override-input mvm <abs>/nix/dev` per the dev-image flake's chained-input pattern).

**Templates definitely needing source updates** during Phase 2: only the *bundled examples* in `nix/examples/*/flake.nix`, because they live in this repo and reference sibling paths. User-authored templates outside this repo never reference internal paths.

---

## Audit: is this a clean build? Is dev/builder/prod cleanly separated?

Three different "builds" exist; they are *not* equally clean.

### Build 1 — `mvmctl` host binary (dev-machine cargo build)

Pure cargo workspace, edition 2024, no Nix involvement on the host. Reproducible modulo nixpkgs (which isn't used here). **Clean.**

### Build 2 — `mvm-guest-agent` + rootfs (`nix build` inside builder VM)

Mostly clean, with concrete cracks:

| Item | State | Risk |
|---|---|---|
| `pkgs.lib.fileset.toSource` for agent src (`guest-agent-pkg.nix:23-32`) | ✅ used | None |
| `closureInfo` + `make-ext4-fs` for deterministic rootfs (`nix/flake.nix:136-179`) | ✅ used | None |
| `pkgs.replaceVars` for init substitutions (`nix/minimal-init/default.nix:488`) | ✅ pure | None |
| `mvmSrc = ./..;` raw path (`nix/flake.nix:57,67`) | ❌ should be `builtins.path { path = ./..; name = "mvm-source"; }` | Store-path `name` field is auto-generated, can drift across NixOS releases |
| `import nixpkgs { inherit system; overlays = [...]; }` without `config = {}` (`nix/flake.nix:32`) | ❌ | nixpkgs may pick up host `~/.config/nixpkgs/config.nix` overrides |
| `flake.lock` committed | ⚠ Partial: present for `nix/dev-image/`, `nix/default-microvm/`, `nix/examples/hello/` only. **Missing** for `nix/flake.nix`, `nix/dev/flake.nix`, `nix/examples/{hello-node,hello-python,openclaw,paperclip}/flake.nix`. | Builds on a fresh checkout fetch a fresh nixpkgs revision → non-bit-reproducible across machines |

**Verdict:** image hash is *almost* reproducible. Closing the four issues above gets it to fully clean.

### Build 3 — the running microVM

The image as **shipped** is byte-for-byte deterministic; the image as **running** is not, because the init script mutates the rootfs at boot (`mkdir`/`chgrp`/`chmod` in `guestAgentBlock`, `lib/04-etc-and-users.sh.in`, `lib/06-optional-drives.sh.in`, `lib/08-signal-handlers.sh.in`). Two VMs booted from the same rootfs hash diverge in their on-disk `/etc` perms after first boot. That's the "spirit of guide" gap Phase 1 closes — bake static perms at build time so the live FS matches the shipped FS.

**Verdict:** rootfs hash stable, in-VM state drifts. Phase 1 makes the running VM match the shipped image.

## Image separation: dev / builder / prod

The current wiring has functional separation but the layout obscures it.

| Role | Flake | Consumes | Agent variant | Visible in artifact? |
|---|---|---|---|---|
| **User microVM (prod)** | user's own flake or `nix/examples/*` | `nix/flake.nix` lib | prod (no Exec handler) | ❌ name doesn't say |
| **User microVM (dev — `mvmctl exec`/`console` enabled)** | same source flake | `nix/dev/flake.nix` (re-export with dev agent injected) | dev | ❌ name doesn't say |
| **Builder VM image** | `nix/dev-image/flake.nix` | `nix/dev/flake.nix` (so its own agent is dev) | dev | ❌ name doesn't say |
| **Default fallback microVM** | `nix/default-microvm/flake.nix` | `nix/flake.nix` lib | prod | ❌ name doesn't say |

Concrete problems:

1. **Naming is misleading.** `nix/dev/` is **not** "the dev image" — it's "the parent flake re-exported with the dev agent injected" (a one-line wrapper). The actual *builder VM image* lives at `nix/dev-image/`. New contributors confuse the two on first read.
2. **No artifact-level marker for prod vs dev.** Both variants emit `name = "mvm-<name>"`. After a build you can't tell from the store path or `image.tar.gz` whether the Exec handler is compiled in. mvmctl logs it but the artifact doesn't carry the metadata.
3. **Builder VM image is structurally identical to a tenant image.** It just has more packages. There is no separate "builder rootfs" derivation — `nix/dev-image/` calls `mkGuest` like any other image. That's fine semantically, but means the builder is subject to the same reductions you'd apply to a tenant rootfs (e.g., dropping the seccomp shim if you ever wanted to). A `passthru.role = "builder" | "tenant"` tag would let downstream tooling (mvmctl, mvmd) special-case it.
4. **All image-producing flakes scattered:** `nix/dev-image/`, `nix/default-microvm/`, `nix/examples/*/`, plus the user's external template flake. They are conceptually one family ("`mkGuest` consumers") but live in unrelated paths.

Fixes (folded into the phases below):

- Phase 1 adds a `variant` tag plumbed through `mkGuest` so `passthru.variant ∈ {"prod","dev"}` and `name = "mvm-${name}-${variant}"`. Visible in the store path.
- Phase 2 moves `nix/dev/` → `nix/lib/dev-agent-overlay/` (renames it to match its role) and groups `nix/{dev-image,default-microvm,examples}/` under `nix/images/`.
- Phase 3's new `passthru.role = "builder" | "tenant"` is set by `nix/images/dev-image/flake.nix` only; everything else defaults to `"tenant"`.

## Audit: current state vs. guide

### Hard Rules

| Rule | Current | Status |
|---|---|---|
| Flakes as canonical entrypoint | `nix/flake.nix` exists | ✅ |
| `flake.lock` committed | `nix/dev-image/flake.lock` exists; missing for `nix/flake.nix` and siblings | ⚠ Partial |
| Support `nix develop` | No `devShells` output anywhere | ❌ |
| Support `nix build` | Yes, on `packages.<sys>.{mvm-guest-agent,mvm-guest-agent-dev}` | ✅ |
| Support `nix run` | No `apps.*` output | ❌ |
| Support `nix flake check` | No `checks.*` output | ❌ |
| No `with pkgs;` | Compliant | ✅ |
| No `rec` | Compliant | ✅ |
| No `<nixpkgs>` | Compliant | ✅ |
| Quoted URLs | Compliant | ✅ |
| Explicit `config = {}` / `overlays = []` | `nix/flake.nix:32-35` passes `overlays` but not `config = {};`. Several other call sites omit both. | ❌ |
| `builtins.path { path = ./.; name = "mvm-source"; }` | `nix/flake.nix:57,67`: raw `mvmSrc = ./..;` | ❌ |
| No `chown`/`chgrp`/`chmod`/`sudo`/`ip link`/`iptables` etc. in `flake.nix`, `devShells`, `shellHook` | None of those files contain such calls (init script does, but it's a build artifact running in-guest, not flake-level). Compliant **literally**, but the *spirit* — bake static perms at build time — is violated by `guestAgentBlock` and `lib/08-signal-handlers.sh.in`. | ⚠ Spirit |

### Host Mutation Boundary

| Rule | Current |
|---|---|
| Don't auto-create `/var/lib/mvm` | Currently created by `mvm-runtime`/Rust, not from `nix develop`. ✅ |
| Don't change `/dev/kvm` perms automatically | Compliant (Justfile + ops manuals). ✅ |
| `ops/{bootstrap,systemd,networking,permissions}/` | Directory does **not exist**. Host setup lives in `Justfile`, `scripts/`, and per-platform Rust code in `crates/mvm-runtime/src/vm/network.rs`. ❌ |

### Recommended Repo Layout

| Required | Current |
|---|---|
| `nix/packages/` | Missing — `nix/{guest-agent-pkg.nix, firecracker-kernel-pkg.nix}` are flat |
| `nix/devshells/` | Missing — no dev shell |
| `nix/checks/` | Missing |
| `nix/apps/` | Missing |
| `nix/overlays/` | Missing (rust-overlay is consumed but no first-party overlay exposed) |
| `nix/modules/` | Missing |
| `nix/images/` | Missing — image builders live under `nix/{dev-image,default-microvm,examples}/` |
| `nix/lib/` | Missing — fragments live under `nix/{minimal-init,rootfs-templates}/` |
| `ops/` | Missing entirely |

### Flake Outputs

| Required | Currently Exposed |
|---|---|
| `packages.${system}.mvm` | ❌ (only `mvm-guest-agent`/`-dev`; no `mvmctl` package) |
| `packages.${system}.default` | ❌ |
| `apps.${system}.mvm` | ❌ |
| `apps.${system}.default` | ❌ |
| `devShells.${system}.default` | ❌ |
| `checks.${system}.default` | ❌ |
| `formatter.${system}` | ❌ |
| `nixosModules.default` | ❌ (acceptable per guide — "if MVM provides modules") |
| `overlays.default` | ❌ (acceptable — only if downstream needs it) |

### Systems

Currently: `nix/flake.nix` → `[ "x86_64-linux" "aarch64-linux" ]`.
Guide requires also `aarch64-darwin` (dev target). macOS-only outputs (dev shell, formatter) plus the Lima/QEMU tools, omitting Linux-only items (Firecracker kernel build, KVM-bound checks).

### Dev Shell Rules

No dev shell exists. The "shell hook must not mutate host" rules are vacuously satisfied. Adding the dev shell is part of this work; it must follow the rules from the start.

---

## Phased Plan

### Phase 1 — In-place spirit-of-guide fixes (no layout change)

Lowest-risk; touches existing files only.

**1a. Bake static `/etc/mvm/*` perms into the rootfs build**
- `nix/rootfs-templates/populate.sh.in`: add `mkdir -p ./files/etc/mvm/probes.d` and set `chmod 0750` + `chgrp 900` (numeric gid; `mvm` group always allocated `900` per `lib/04-etc-and-users.sh.in:32`) on both `integrations.d` and `probes.d`. Make sure the surrounding directory `./files/etc/mvm` is `0755 root:root`.
- `nix/minimal-init/default.nix`: drop the runtime `mkdir`/`chgrp`/`chmod` loop in `guestAgentBlock` (lines 378-382). Keep the rest.

**1b. Replace runtime `find ... -delete` with `rm -f`**
- `nix/minimal-init/lib/08-signal-handlers.sh.in:28` → `rm -f /run/mvm-secrets/* 2>/dev/null || true` (subdirs survive because `rm` without `-r` skips them).

**1c. Move `udhcpc.sh` into the Nix store**
- `nix/minimal-init/default.nix`: define `udhcpcScript = pkgs.writeShellScript "mvm-udhcpc-action" ''…''` with the same heredoc body that is currently emitted at boot. Add `udhcpcScript = "${udhcpcScript}";` to `libSubsts`.
- `nix/minimal-init/lib/05-networking.sh` → rename to `05-networking.sh.in` (so `pkgs.replaceVars` runs over it). Replace heredoc + `chmod +x` with `udhcpc -i "$NET_IF" -s @udhcpcScript@ ...`.
- `nix/minimal-init/default.nix:464-472`: update `initLibs.networkingLib` path.

**1d. Explicit `config = {}` / `overlays = []`**
- `nix/flake.nix:32-35`: `pkgs = import nixpkgs { inherit system; config = {}; overlays = [ rust-overlay.overlays.default ]; };`
- `nix/dev-image/flake.nix:23`, `nix/default-microvm/flake.nix:21`, every `nix/examples/*/flake.nix` import: same pattern.

**1e. Reproducible source path**
- `nix/flake.nix:57,67`: `mvmSrc = builtins.path { path = ./..; name = "mvm-source"; };` (replaces raw `./..`).

**1f. Commit every missing `flake.lock`**
Currently only `nix/dev-image/`, `nix/default-microvm/`, `nix/examples/hello/` have committed locks. Generate and commit:
- `nix/flake.lock`
- `nix/dev/flake.lock`
- `nix/examples/hello-node/flake.lock`
- `nix/examples/hello-python/flake.lock`
- `nix/examples/openclaw/flake.lock`
- `nix/examples/paperclip/flake.lock`

This is the single biggest reproducibility win in Phase 1.

**1g. Variant tag on `mkGuest` outputs**
Add `variant` ("prod" | "dev") to `mkGuestFn`'s args and:
- `name = "mvm-${name}-${variant}"` so the store path differs.
- `passthru.variant = variant;` on the resulting derivation.
- Write `/etc/mvm/variant` into the rootfs at populate time so the running VM can self-identify.

`nix/dev/flake.nix` becomes the only caller that passes `variant = "dev"` (alongside the dev agent).

Phase 1 verification:
- `cargo build && cargo test --workspace && cargo clippy --workspace -- -D warnings`.
- `cargo run -- dev down && cargo run -- dev up && cargo run -- dev shell`, then in the booted dev VM:
  - `stat -c '%a %g' /etc/mvm/integrations.d /etc/mvm/probes.d` → `750 900`.
  - `ls -l /tmp/udhcpc.sh` → does not exist; the udhcpc helper resolves to a `/nix/store/...-mvm-udhcpc-action` path.
  - `journalctl`-equivalent — tail `/dev/console` on boot, no permission denials.
- On Linux KVM host: snapshot + restore a VM, exercise the `post_restore` path, confirm `/run/mvm-secrets` repopulates. (Skip on macOS QEMU per known vsock-snapshot limitation.)

### Phase 2 — Repo layout move + naming fixes

Pure file moves + `flake.nix` re-routing. No behavior change.

```
nix/
├── flake.nix              (top-level, re-exports the per-system attribute sets)
├── flake.lock
├── packages/
│   ├── mvmctl.nix               (Rust CLI package — new, Phase 3)
│   ├── mvm-guest-agent.nix      (was nix/guest-agent-pkg.nix)
│   └── firecracker-kernel.nix   (was nix/firecracker-kernel-pkg.nix; pulls kernel-configs/)
├── devshells/
│   ├── host.nix           (macOS / Linux dev-machine shell — Phase 3)
│   └── builder.nix        (Linux builder-VM-side shell — Phase 3)
├── checks/
│   ├── eval.nix           (host-side, eval-only — Phase 3)
│   └── build.nix          (builder-VM-side, real builds — Phase 3)
├── apps/
│   └── default.nix        (mvmctl `nix run` wrapper — Phase 3)
├── overlays/              (placeholder; not exposed unless needed)
├── modules/               (placeholder; only if mvm grows host modules)
├── images/                (every mkGuest consumer lives here)
│   ├── builder/           (was nix/dev-image/ — RENAMED for clarity, builder VM image)
│   ├── default-tenant/    (was nix/default-microvm/ — RENAMED, tenant default fallback)
│   └── examples/          (was nix/examples/, internal layout unchanged)
├── lib/
│   ├── mkGuest.nix        (extracted from current nix/flake.nix mkGuestFn)
│   ├── dev-agent-overlay.nix  (was nix/dev/flake.nix — flattened; it's a wrapper, not a flake)
│   ├── builder-tools.nix  (shared package set for builder.nix devshell + images/builder)
│   ├── minimal-init/      (was nix/minimal-init/)
│   ├── rootfs-templates/  (was nix/rootfs-templates/)
│   └── kernel-configs/    (was nix/kernel-configs/)
```

Three explicit renames worth highlighting:

- **`nix/dev/` → `nix/lib/dev-agent-overlay.nix`.** The current name is misleading (it's not "the dev image"). New name says what it does: it's an overlay applied to `mkGuest` that swaps the agent. **It also stops being a sibling flake** — it was only a flake to satisfy the `--override-input` chain. Phase 3's reworked override path can pass `--arg variant dev` to the parent flake instead.
- **`nix/dev-image/` → `nix/images/builder/`.** This is the *builder VM image*, not a generic "dev image."
- **`nix/default-microvm/` → `nix/images/default-tenant/`.** Says what it is: the default tenant rootfs.

Update every `path:..`, `path:../dev`, `import ./...` to match.

mvmctl-side path-string updates needed (audited via grep on `nix/dev`, `nix/dev-image`):
- `crates/mvm-build/src/pipeline/dev_build.rs:52,56-57` — change `candidate.join("nix/dev")` and the chained `--override-input` to point at the new mechanism (after Phase 2 refactor: pass `variant=dev` arg to the single parent flake instead of swapping flakes).
- `crates/mvm-cli/src/commands/env/apple_container.rs:857,1122` — error-message strings reference `nix/dev-image/flake.nix`. Update to `nix/images/builder/flake.nix`.
- `crates/mvm-cli/src/commands/env/dev.rs` — same sweep.

The bundled examples' `inputs.mvm.url = "path:../.."` (relative to `nix/examples/<name>/flake.nix`) keep pointing at `nix/` (which still has `flake.nix`), so no example change is needed for the move itself — only for any examples that reach into sub-paths (none currently do).

Phase 2 verification:
- `nix flake check ./nix` (eval) on macOS box.
- `nix build ./nix#packages.aarch64-linux.mvm-guest-agent` on a Linux builder, confirm same store path hash as before the move (or differs only by the `name` field if `builtins.path` changes the name).
- `cargo run -- dev up` round-trips.

### Phase 3 — New flake outputs (split by execution environment)

Each output below has an explicit "where this runs" annotation. macOS dev-machine outputs are eval-only or pure cargo. Linux builds happen inside the builder VM (which itself is a `mkGuest` consumer).

**3a. `packages.${system}.mvm` + `packages.${system}.default` — the `mvmctl` Rust binary**
- `nix/packages/mvmctl.nix`: `rustPlatform.buildRustPackage` over the workspace. Pinned to the same Rust toolchain as `mvm-guest-agent`.
- Where it runs: `aarch64-darwin` and `x86_64-darwin` (host install via `nix profile install`), plus `aarch64-linux`/`x86_64-linux` (mvmd box install).
- Wire into `nix/flake.nix` as `packages.${system}.{mvm,default}`.

**3b. `apps.${system}.{mvm,default}`**
- `flake-utils.lib.mkApp` over `packages.${system}.mvm`. `nix run github:auser/mvm -- --help` works on the dev machine without a full install.

**3c. `devShells.${system}.default` — host (dev-machine) shell**
- New `nix/devshells/host.nix`, exposed at `devShells.${system}.default` on **darwin systems** and as a leaner alternative on Linux (for contributors who don't run `mvmctl dev`).
- Tools (per guide, scoped to "edit the mvmctl crate"):
  - rust toolchain (matches `rust-toolchain.toml`), cargo, rustfmt, clippy, rust-analyzer
  - pkg-config, openssl
  - lima, qemu (so contributors can poke at the builder VM directly)
  - jq, just, git, nix tooling
  - **No firecracker** here — Firecracker requires `/dev/kvm`, which doesn't exist on macOS, and even on Linux contributors don't drive it directly from the host.
- `shellHook`:
  - Print rust/cargo/lima versions.
  - On macOS: `"You are on the development machine. Real microVM builds run inside the builder VM. Use 'mvmctl dev up' to start it."`
  - On Linux: detect `/dev/kvm`; if missing or inaccessible, print `"/dev/kvm is not accessible. See ops/permissions/kvm-access.sh — do NOT run it from this shell hook."`. **No chmod, no usermod, no mkdir.**
  - Always: nudge to `mvmctl dev up` for image work.

**3d. `devShells.${system}.builder` — builder-VM-side shell (Linux only)**
- New `nix/devshells/builder.nix`, exposed only on `*-linux`.
- Tools (per guide's full list, gated to where they make sense):
  - rust toolchain (so `cargo` works inside the builder VM if a contributor wants to iterate without the dispatch loop)
  - nix, git, jq, just, cacert
  - qemu, firecracker, kernel build deps (linux-headers, bc, flex, bison)
  - iproute2, iptables, bridge-utils (for inspecting the TAP/bridge wiring mvmctl creates)
- `shellHook`: prints `/dev/kvm` status as **diagnostic info only**. Inside the builder VM `/dev/kvm` is the whole point, so a missing-or-broken kvm is loud.
- This shell isn't entered via `nix develop` from the dev machine; it's the on-VM shell available to anyone who SSHes / `mvmctl dev shell`s into the builder VM. Practically: this shell *is* the package set already passed into `nix/dev-image/flake.nix`'s `mkGuest` call. Phase 3d formalizes that set into a reusable attribute (`mvm.lib.<sys>.builderTools`) so `nix/dev-image/flake.nix` consumes it and `devShells.<sys>.builder` exposes the same set for nix-develop-style usage.

**3e. `checks.${system}.default` — split eval vs build**
- `checks.aarch64-darwin.default` (host-side): runs `cargo check --workspace`, `cargo fmt -- --check`, `cargo clippy -- -D warnings`, plus `nix flake check`-style **eval** of every sibling flake under `nix/images/`.
- `checks.aarch64-linux.default` (builder-side): everything above **plus**:
  - Build a minimal `mkGuest` image and `mount`-inspect the rootfs to assert `/etc/mvm/{integrations.d,probes.d}` are `0750 root:900` (asserts Phase 1a).
  - Build `nix/images/dev-image` and confirm boot-up via Firecracker dry-run.
  - These run inside the builder VM (CI: a Linux runner with `/dev/kvm`).
- The split keeps `nix flake check ./nix` cheap on the dev Mac (eval only) without weakening Linux-side enforcement.

**3f. `formatter.${system}`**
- `pkgs.nixfmt-rfc-style`. Wire as `formatter.<sys>` for both darwin and linux.

**3g. (Deferred) `nixosModules.default`**
- Skip until `mvmd` (separate repo) lands and we have a shared host-provisioning surface.

Phase 3 verification:
- macOS dev box: `nix run ./nix -- --help` prints mvmctl help; `nix develop ./nix` drops into a cargo-ready shell with the macOS-appropriate hook output; `nix flake check ./nix` passes (eval).
- Builder VM (`mvmctl dev shell` then inside): `nix develop /host-shared/mvm/nix#builder` drops into the full build shell; `nix build /host-shared/mvm/nix#packages.aarch64-linux.mvm-guest-agent` succeeds; `nix flake check /host-shared/mvm/nix` (real check, not eval-only) passes.
- `nix fmt ./nix` reformats consistently from either side.

### Phase 4 — Systems coverage (`aarch64-darwin`) with strict gating

- Extend `nix/flake.nix`'s `flake-utils.lib.eachSystem` to include `"aarch64-darwin"` (and `"x86_64-darwin"` if anyone still uses Intel macs).
- Gate Linux-only outputs with `pkgs.lib.optionalAttrs pkgs.stdenv.isLinux { ... }`:
  - `packages.<sys>.{mvm-guest-agent, mvm-guest-agent-dev, firecracker-kernel}`
  - `lib.<sys>.mkGuest` (it produces a Linux rootfs; eval can succeed on Darwin but build cannot — keep eval working, gate build via `meta.platforms`)
  - `devShells.<sys>.builder`
  - `checks.<sys>.default`'s build-rootfs assertion
- Darwin keeps:
  - `packages.<sys>.{mvm,default}` (mvmctl)
  - `apps.<sys>.{mvm,default}`
  - `devShells.<sys>.default` (host shell)
  - `formatter.<sys>`
  - eval-only `checks.<sys>.default`
- This matches the guide's rule: "macOS dev shells may include Lima/QEMU tooling, but must not pretend KVM-only features work locally."

### Phase 5 — `ops/` scaffolding

Create the `ops/` tree. Move any **host-mutating** scripts that currently live in `Justfile` or `scripts/` into the right subdir, keeping them as plain shell scripts (not Nix). Each file gets a header explaining what it changes and why it requires elevated privileges.

```
ops/
├── bootstrap/
│   └── README.md           (entry doc — what bootstrap means, when to run)
├── permissions/
│   ├── README.md
│   └── kvm-access.sh       (one-shot: add user to kvm group on Linux; warn-only on macOS)
├── networking/
│   ├── README.md
│   └── bridge-setup.sh     (extracted from mvm-runtime/src/vm/network.rs scripted bits if applicable, otherwise documents how `mvmctl` does it)
└── systemd/
    └── README.md           (placeholder; mvmd's territory)
```

The dev shell's `shellHook` references these by path (`See ops/permissions/kvm-access.sh`).

This is the largest scope change and is best done as its own PR after Phases 1-4 land.

---

## Files modified by phase (checklist)

| Phase | File |
|---|---|
| 1a | `nix/rootfs-templates/populate.sh.in` |
| 1a | `nix/minimal-init/default.nix` (`guestAgentBlock`) |
| 1b | `nix/minimal-init/lib/08-signal-handlers.sh.in` |
| 1c | `nix/minimal-init/default.nix` (add `udhcpcScript`) |
| 1c | `nix/minimal-init/lib/05-networking.sh` → `05-networking.sh.in` (rename + edit) |
| 1c | `nix/minimal-init/default.nix` (`initLibs`) |
| 1d | `nix/flake.nix`, `nix/dev-image/flake.nix`, `nix/default-microvm/flake.nix`, `nix/examples/**/flake.nix` |
| 1e | `nix/flake.nix` |
| 1f | Generate + commit `nix/flake.lock`, `nix/dev/flake.lock`, `nix/examples/{hello-node,hello-python,openclaw,paperclip}/flake.lock` |
| 1g | `nix/flake.nix` (`mkGuestFn` adds `variant` arg, `name`/`passthru`), `nix/dev/flake.nix` (passes `variant = "dev"`), `nix/rootfs-templates/populate.sh.in` (writes `/etc/mvm/variant`) |
| 2 | All of `nix/` (rename/move) |
| 2 | `crates/mvm-build/src/pipeline/dev_build.rs`, `crates/mvm-cli/src/commands/env/{dev,apple_container}.rs` (path strings only) |
| 3 | `nix/packages/{mvmctl,mvm-guest-agent,firecracker-kernel}.nix` |
| 3 | `nix/devshells/{host,builder}.nix` (new — split by env) |
| 3 | `nix/checks/{eval,build}.nix` (new — split eval vs build) |
| 3 | `nix/apps/default.nix` (new) |
| 3 | `nix/lib/builder-tools.nix` (new — shared package set used by both `dev-image` and `devShells.<sys>.builder`) |
| 3 | `nix/images/dev-image/flake.nix` (consume `lib.builderTools` instead of inline list) |
| 3 | `nix/flake.nix` (output wiring) |
| 4 | `nix/flake.nix` (`eachSystem` arg, `optionalAttrs` gates) |
| 5 | `ops/{bootstrap,permissions,networking,systemd}/` (new dirs + READMEs) |
| 5 | Move `scripts/install-systemd.sh` → `ops/systemd/install.sh` |
| 5 | Move `scripts/dev-setup.sh` → `ops/bootstrap/dev-setup.sh` |
| 5 | Move `scripts/mvm-install.sh` → `ops/bootstrap/install.sh` |
| 5 | Update `Justfile` paths to point at new `ops/` locations |
| 1 (extension) | `scripts/check-prod-agent-no-exec.sh` — assert variant ↔ feature pairing |
| 3 (extension) | New `nix/packages/xtask.nix`; remove `xtask` from agent fileset in `nix/packages/mvm-guest-agent.nix` |
| 3 (extension) | New `apps.${system}.dev` wrapper (calls `mvmctl dev up`) |
| 3 (extension) | `.githooks/pre-commit` — add `nix fmt --check` step |
| 3 (extension) | New `treefmt.toml` (rust + nix + sh + md) |
| **Phase 1.5 (M)** | Lima VM rename `mvm` → `mvm-builder` across `crates/mvm-runtime/src/vm/lima.rs`, `crates/mvm-runtime/src/vm/network.rs`, `crates/mvm-cli/src/commands/env/dev.rs`, `crates/mvm-cli/src/bootstrap.rs`, `resources/lima.yaml.tera`, `Justfile`, `CLAUDE.md`, memory entries |
| **Phase 1.5 (M)** | Migration UX: detect legacy `mvm` Lima VM on first run, print one-line manual migration command — no auto-rename |
| **Phase 3a (N)** | Replace `mkNodeService`'s 3-stage FOD-then-patch pattern with `pkgs.buildNpmPackage`. Eliminates `chmod -R u+w` calls in `nix/flake.nix:271,297,307` |
| **Phase 1 (O)** | Delete `nix/examples/paperclip/` and `nix/examples/openclaw/`. Remove their memory entries from `MEMORY.md` |
| **Phase 1 (P)** | Remove `flake-utils` dep in `nix/flake.nix`. Replace `flake-utils.lib.eachSystem` with hand-rolled `eachSystem` already used elsewhere. Drop `flake-utils.url` from inputs |

## Other things this work needs to consider

These are real cross-cutting concerns in this codebase that intersect Phases 1-3 and would silently break or regress if missed.

### A. The `MVM_CONTAINER` boot path

`init.sh.in:25-28` and every `.sh` lib gate `mount`/`mkdir` calls on `MVM_CONTAINER=0|1`. Apple Container guests boot with `MVM_CONTAINER=1` and skip kernel-level mounts. Phase 1's bake-perms-into-rootfs is fine here — `populate.sh.in` runs at *build* time, not boot, so there's no container-vs-firecracker divergence. **But:** if Phase 1g's `/etc/mvm/variant` is read by code that also runs in container mode, the read needs to work in both. Verify the init writes nothing extra in container mode that breaks the Apple Container boot model already flagged in memory as an active blocker.

### B. The `dev-shell` Cargo feature ↔ `variant` tag must agree

`scripts/check-prod-agent-no-exec.sh` enforces "production agent has no `do_exec` symbol." Phase 1g introduces `variant = "prod" | "dev"` on the rootfs side. A `prod` rootfs containing a dev agent (or vice versa) is a footgun. Add a build-time assertion in `mkGuestFn`:

```nix
assert (variant == "dev") -> (guestAgent.passthru.devShell or false);
assert (variant == "prod") -> (!(guestAgent.passthru.devShell or false));
```

…and surface `passthru.devShell` from `guest-agent-pkg.nix`. This guarantees the variant tag and the agent's compiled feature set never disagree at the artifact level.

### C. CI workflow updates (Phase 2/3)

`.github/workflows/release.yml:114,136,177` builds:
- `./nix/dev-image#packages.${SYSTEM}.default` → after rename, `./nix/images/builder#packages.${SYSTEM}.default`
- `./nix/default-microvm#packages.${SYSTEM}.default` → `./nix/images/default-tenant#packages.${SYSTEM}.default`

Job names should also rename (`dev-image` job → `builder-image`) so artifact names in the release flow match the new vocabulary.

### D. Snapshot interaction with bake-time perms

Firecracker snapshots capture in-VM state. Today's snapshots have whatever the boot-time chmod/chgrp made the FS look like; Phase 1 changes that to "shipped image perms = running image perms." That means any snapshot captured pre-Phase-1 and restored post-Phase-1 will still show the *old* perms (snapshot wins over rebuilt rootfs). Document: existing snapshots must be rebuilt after Phase 1 lands. Cleanest path is bumping the rootfs `name` in Phase 1g's `variant` tag — the store-path change forces a snapshot-cache miss automatically.

### E. `wait_for_healthy` and `wait_for_integrations_healthy` (template snapshot-on-build)

Per memory: `wait_for_integrations_healthy` reads `/etc/mvm/integrations.d/*.json`. Phase 1a changes that dir's mode/owner from runtime (`0750 root:mvm`, gid 900 *after* `/etc/group` is populated) to baked (`0750 0:900` from rootfs build). Since the agent runs as uid 901 / gid 901 / supplementary 900, both regimes give it read access. Verify with a startup health check post-Phase-1.

### F. `nix flake check` cost on macOS

The bundled examples (`hello-node`, `paperclip`, `openclaw`) are heavy — they pull node, postgres, esbuild closures. Eval-only `nix flake check` on macOS still imports their definitions. If eval becomes slow, partition `checks.aarch64-darwin.default` to only the parent flake + `default-tenant`, and run example evaluation in a separate `checks.aarch64-darwin.examples` attribute. Worth measuring before deciding.

### G. `xtask` crate and `scripts/`

`guest-agent-pkg.nix:23-32` includes `xtask` in the source closure. After Phase 2 we may want `xtask` to be its own `packages.<sys>.xtask` (so `nix run .#xtask -- <task>` works) and excluded from the agent's `fileset`. Optional cleanup; no behavior change.

Several `scripts/*.sh` (`dev-setup.sh`, `install-systemd.sh`, `mvm-install.sh`) are *host-mutating*. The guide's `ops/` layout is the right home for them. Move:
- `scripts/install-systemd.sh` → `ops/systemd/install.sh`
- `scripts/dev-setup.sh` → `ops/bootstrap/dev-setup.sh`
- `scripts/mvm-install.sh` → `ops/bootstrap/install.sh`

Folded into Phase 5.

### H. Fileset filtering for the new `mvmctl` package

`packages.<sys>.mvm` (Phase 3a) needs to use `pkgs.lib.fileset.toSource` like `guest-agent-pkg.nix` does, otherwise every `specs/` or `public/` change rebuilds the binary. Already in scope, calling out explicitly so it doesn't get missed.

### I. Builder VM image must not embed the host CLI

`packages.aarch64-linux.mvm` is the mvmctl binary built for Linux (for mvmd-side install). It must **not** end up baked into `nix/images/builder/`'s rootfs — the builder VM only needs `mvm-guest-agent`, not the orchestrator. Audit the closure in Phase 3 to confirm `nix path-info -r ./nix/images/builder#packages.aarch64-linux.default` doesn't pull in the mvmctl binary.

### J. Rust toolchain consistency

`rust-toolchain.toml` pins the workspace toolchain. `nix/flake.nix:38` uses `pkgs.rust-bin.stable.latest.minimal` — *not* the pinned toolchain. The two can drift. Phase 3a should source the toolchain from `rust-toolchain.toml` (rust-overlay supports `(rust-bin.fromRustupToolchainFile ./../rust-toolchain.toml)`) so the host build, the Nix build, and the agent build all use the same compiler. This is a quiet bug today.

### K. `.git`-dependence in `mvmSrc`

`mvmSrc = ./..` includes `.git` in the eval-time path snapshot unless filtered. `pkgs.lib.fileset.toSource` already handles this in `guest-agent-pkg.nix`. Phase 1e's `builtins.path { path = ./..; name = "mvm-source"; filter = ...; }` should explicitly filter `.git`, `target/`, `nixos.qcow2` (the 21 GB file at the repo root!), and `.playwright-mcp/`. Without a filter, `nix build` would copy the 21 GB qcow2 into the store on every eval, which is catastrophic.

### L. `formatter.${system}` choice

Pick **one** of `pkgs.nixfmt-rfc-style` or `pkgs.alejandra` and stick with it. `nixfmt-rfc-style` is the official RFC 166 implementation — recommended. Add a `treefmt.toml` so `nix fmt` formats `*.nix`, `*.rs` (rustfmt), `*.sh` (shfmt), `*.md` (prettier) consistently.

## Items pulled in from earlier "out of scope"

After the audit, several originally-deferred items belong in this work because the guide's rules touch them directly. Folding them in:

### Pulled into Phase 1 (small additions)

- **Extend `scripts/check-prod-agent-no-exec.sh`** to assert the new `variant` tag (Phase 1g) agrees with the agent's compiled features. The guard becomes: "prod agent has no `do_exec` symbol AND the rootfs's `/etc/mvm/variant` reads `prod`." This closes a previously-unenforced pairing.

### Pulled into Phase 3 (output-additions sweep)

- **`xtask` as `packages.<sys>.xtask`**. Currently `xtask` rides along inside `mvm-guest-agent`'s source fileset, which means an unrelated `xtask` change rebuilds the agent. Promote it to its own package, and exclude `xtask` from the agent's fileset.
- **`apps.${system}.dev`**. Trivial wrapper that runs `mvmctl dev up`. Saves new contributors typing — `nix run github:auser/mvm#dev` is more discoverable than reading the README.
- **`nix fmt --check` in `.githooks/pre-commit`**. Once `formatter.${system}` and `treefmt.toml` land, wire them into the existing pre-commit hook so formatting drift fails locally instead of in CI.

### Promoted from "Phase 5 deferred" to "in this work"

`scripts/{install-systemd,dev-setup,mvm-install}.sh` are host-mutating shell scripts that exist *outside* of `nix develop` (so they don't violate the literal hard rule) but live at the wrong path per the guide's recommended layout. Move:

| From | To |
|---|---|
| `scripts/install-systemd.sh` | `ops/systemd/install.sh` |
| `scripts/dev-setup.sh` | `ops/bootstrap/dev-setup.sh` |
| `scripts/mvm-install.sh` | `ops/bootstrap/install.sh` |
| `install.sh` (repo root) | `ops/bootstrap/install.sh` (collapse with above) or keep at root and link |

Each gets a header comment listing what host state it changes and why elevated privileges are required (per the guide's "explicit reviewed files" requirement). Phase 5 becomes a small follow-up rather than a deferred separate effort.

## Items deferred — needs your decision

### `mvmctl` host mutation (network.rs / TAP+bridge+iptables)

This is the most consequential gap I haven't already folded in. `mvmctl dev up` and `mvmctl run` invoke `crates/mvm-runtime/src/vm/network.rs` to:

- Create a Linux bridge (`br-mvm`)
- Add TAP interfaces
- Configure iptables NAT rules

These are **host mutations**. They don't happen from `nix develop` (which doesn't exist yet, so it's vacuously compliant) — they happen from a user-invoked CLI command. The guide's hard rule names `iptables`, `ip link`, "bridge/TAP mutations" as forbidden in `flake.nix`/`devShells`/`shellHook`, and the "Host Mutation Boundary" section forbids automatic host setup. mvmctl currently does this automatically on first `dev up`.

Two ways to read the guide:

1. **Strict:** any host mutation should be a separate, explicit, user-run script under `ops/networking/`. `mvmctl dev up` should warn if the bridge isn't there and exit, telling the user to run `sudo ops/networking/bridge-setup.sh` once.
2. **Lenient:** the guide is about *Nix entry points* (`nix develop`/`shellHook`), not user-invoked CLIs. mvmctl asking for sudo and being explicit about what it changes is fine because it's not a hidden side effect — the user typed `mvmctl dev up`.

Reading 2 is closer to current reality and avoids a UX regression. Reading 1 is closer to the guide's spirit. **This is a product decision, not a Nix-cleanup decision** — flagging it but not folding it in until you say which read you want. If you want strict, it adds an item to Phase 5: extract the iptables/bridge calls from `network.rs` into `ops/networking/bridge-setup.sh`, and have `network.rs` run a precondition check + clear error message instead.

## Pulled in per your latest direction

### M. Rename the Lima VM

Currently the Lima VM is named `mvm` and the bridge is `br-mvm`. With the broader vocabulary cleanup ("builder VM" being the canonical term), rename to **`mvm-builder`**:

- **Lima VM name:** `mvm` → `mvm-builder` (so `limactl shell mvm-builder`, `limactl stop mvm-builder`)
- **Bridge name:** `br-mvm` → `br-mvm-builder`? Or keep `br-mvm` since the bridge is broader than just the builder? **Recommend keeping `br-mvm`** — the bridge serves *all* mvm microVMs, not just the builder, so the name remains accurate. Confirm before proceeding.
- **Runtime paths:** `/var/lib/mvm/` — keep. These are mvmd/orchestration paths and aren't VM-specific.
- **Log filter:** `RUST_LOG=mvm=info` keeps using crate name `mvm`. Per memory pitfall.
- **Apple Container path:** unaffected — the Apple Container builder is named separately (`mvm-dev` per `dev-image/flake.nix:25`).

Files touched (audit):

| File | Change |
|---|---|
| `crates/mvm-runtime/src/vm/lima.rs` | All literal `"mvm"` references for the VM name → `"mvm-builder"` |
| `crates/mvm-runtime/src/vm/network.rs` | `run_on_vm("mvm", ...)` calls → `"mvm-builder"` |
| `crates/mvm-cli/src/commands/env/dev.rs` | Status/help strings, lifecycle calls |
| `crates/mvm-cli/src/bootstrap.rs` | First-run setup |
| `resources/lima.yaml.tera` | If the template embeds the VM name |
| `Justfile` | Any `limactl shell mvm` commands |
| `scripts/dev-setup.sh` (after move to `ops/bootstrap/`) | Same |
| `CLAUDE.md` | Doc update — Lima VM name |
| Memory: `MEMORY.md` index entries that mention `mvm` Lima VM | Update |
| `nix/images/builder/flake.nix` (after rename in Phase 2) | The image's `name`/`hostname` could become `mvm-builder` to match — currently `mvm-dev`, which is also a reasonable target rename |

Backward compat: there's an existing Lima VM checkout on your dev machine literally named `mvm`. Migration: `mvmctl` first-run after upgrade detects the legacy `mvm` Lima VM and prints a one-line migration command (`limactl rename mvm mvm-builder` if Lima supports it; otherwise stop/start with new name). Don't auto-migrate — destructive operations stay user-visible per the broader "host mutation boundary" theme.

This becomes its own phase: **Phase 1.5** (between Phase 1 and Phase 2) so the rename lands before the directory restructure compounds the diff.

### N. Eliminate the FOD-then-patch pattern in `mkNodeService`

You're right to read the `chmod -R u+w $out` and `find ... -delete` as a smell — and once we delete `paperclip` and `openclaw`, the remaining cases all live in `mkNodeService` (`nix/flake.nix:257-329`). The reason they're there is the manual three-stage FOD pattern:

```nix
node-src   = mkDerivation { src; npm install; outputHash = npmHash; };  # FOD
node-pkg   = mkDerivation { src = node-src; autoPatchelf; };
node-built = mkDerivation { src = node-pkg; tsc / vite / prune; };
```

Each stage takes the previous stage's `0555` store output, copies it into a writable area, and `chmod -R u+w` to mutate. That's the smell.

The idiomatic nixpkgs replacement is **`pkgs.buildNpmPackage`**, which:
- Handles `npm ci`/`npm install` reproducibly via `npmDepsHash` (one FOD, internally)
- Provides standard `buildPhase`/`installPhase` hooks
- Supplies pre-`patchelf`'d output without a separate `node-pkg` stage
- No manual `chmod -R u+w $out` anywhere in the user-visible derivation

After replacement, `nix/flake.nix:257-329` becomes ~30 lines instead of ~75, and **all three** `chmod -R u+w` / `find ... -delete` calls in `mkNodeService` disappear.

The remaining `chmod u+w $out` outside `mkNodeService` is in `nix/firecracker-kernel-pkg.nix:18` for kernel build. That one is genuinely required (it patches the kernel config tree post-`unpackPhase`); it's idiomatic and stays.

Folded into Phase 3a alongside the broader package work.

### O. Delete `nix/examples/paperclip` and `nix/examples/openclaw`

Both examples are heavy (Postgres, OpenClaw bundling, ~75% of all `chmod`/`find` calls in `nix/`) and the OpenClaw one is flagged as an active blocker in memory. Removing them:

- Deletes `nix/examples/paperclip/` and `nix/examples/openclaw/` entirely.
- Removes their memory entries (the OpenClaw-specific pitfall list in `MEMORY.md` becomes stale).
- Removes their CI references if any (none in `release.yml` per audit).
- Keeps `nix/examples/{hello, hello-node, hello-python}/` as the canonical small examples.

Each was probably created to validate `mkGuest` against real workloads — that's now better served by `nix/images/builder/`'s own use of `mkGuest`. No coverage loss.

### P. Remove the `flake-utils` dependency

`nix/flake.nix:26,30` are the only places it's used. Replace `flake-utils.lib.eachSystem [...] (system: …)` with the hand-rolled pattern already in `nix/dev-image/flake.nix:21-25` and `nix/default-microvm/flake.nix:13-15`:

```nix
let
  systems = [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" ];
  eachSystem = f: builtins.listToAttrs (map (system:
    { name = system; value = f system; }) systems);
in eachSystem (system: …)
```

Drop `inputs.flake-utils.url` from `nix/flake.nix:26`. One fewer transitive input. `apps.${system}.default` (Phase 3b) does its own `{ type = "app"; program = …; }` literal instead of `flake-utils.lib.mkApp`.

## Clarification on Nix-derivation `chmod` / `find` (item N rationale)

Your concern is well-placed. The distinction the guide draws isn't "chmod is forbidden everywhere," it's "chmod is forbidden in *flake entry points that mutate the host*." Three different contexts where `chmod` appears:

| Context | Example | Compliant? | Why |
|---|---|---|---|
| `flake.nix` top-level / `shellHook` / `devShells.shellHook` | `shellHook = "chmod 0666 /dev/kvm";` | ❌ Hard rule violation. Mutates the host on `nix develop`. |
| Inside `pkgs.stdenv.mkDerivation`'s `buildPhase` / `installPhase` | `buildPhase = "chmod -R u+w $out && find ...";` | ✅ Compliant — runs in the Nix build sandbox as fake `nixbld` user, can only touch `$TMPDIR` and `$out`. Nothing outside the sandbox is reachable. Standard idiom for FOD-then-patch flows. |
| Inside a *generated init script* (the rootfs's `/init`) | `chgrp mvm /etc/mvm/integrations.d` | Spirit violation, not literal. Runs as PID 1 inside the guest VM, never on the host. The guide's letter doesn't ban it; the guide's spirit ("bake at build, not at boot") suggests moving it to rootfs build time. **This is what Phase 1 fixes.** |

The audit at the top of this plan separated these. The middle row (Nix-sandbox `chmod`) is the one that *looks* bad but isn't — it's a Nix idiom signalling an intentional override of store-path immutability for that derivation. The smell you correctly identified is when a *more idiomatic helper* (`buildNpmPackage`) exists and removes the need entirely. After Phase 3a (item N), the only remaining Nix-sandbox `chmod` is in `firecracker-kernel-pkg.nix` for kernel-config patching — which has no nixpkgs helper equivalent.

## Items that genuinely stay out of scope

- **mvmd-side modules** — separate repo.
- **`mvmctl` host mutation in `network.rs`** (TAP/bridge/iptables) — flagged above under "Items deferred — needs your decision." Pending your read of strict vs. lenient guide interpretation.

## Quick answers to your questions

1. **Will this update template files?** Phase 1 — **no template source changes needed**; the rootfs perm fixes propagate automatically next time a template is rebuilt (which happens inside the builder VM via `mvmctl template build`). Phase 2 — only the **bundled** `nix/examples/*/flake.nix` need any change (and only if they reach into renamed sub-paths, which none currently do), plus mvmctl's internal `--override-input` paths in `crates/mvm-build/src/pipeline/dev_build.rs` and `crates/mvm-cli/src/commands/env/{dev,apple_container}.rs`. **External user templates are unaffected** because they pin `mvm.url = "github:auser/mvm?dir=nix"`.

2. **Builder VM vs dev machine.** The plan has two distinct dev shells (`devShells.<sys>.default` host, `devShells.<sys>.builder` builder VM), heavy build tooling gated to Linux via `optionalAttrs pkgs.stdenv.isLinux`, and shared between `nix/images/builder/flake.nix` and `devShells.<sys>.builder` via a new `nix/lib/builder-tools.nix`. Phase 1's bake-perms-into-rootfs work runs inside the builder VM's Nix sandbox.

3. **Is this a clean build?** Three layers (see audit at top of plan):
   - Host cargo build of mvmctl: **clean.**
   - `nix build` of agent + rootfs: **almost clean** — gaps are missing `flake.lock`s, raw `mvmSrc = ./..`, missing `config = {}` on nixpkgs imports. Phase 1 closes all three.
   - Running microVM: **not clean** today — boot-time chmod/chgrp/find drift the live FS off the shipped FS. Phase 1 closes this by baking static perms into the rootfs and replacing `find` with `rm`. After Phase 1 the running VM matches the shipped image.

4. **Clear separation between dev images / builder images / built microVMs?** Functional separation exists, but **layout and naming obscure it**:
   - `nix/dev/` is misnamed — it's an overlay, not an image. Rename to `nix/lib/dev-agent-overlay.nix` (Phase 2).
   - `nix/dev-image/` *is* the builder VM image. Rename to `nix/images/builder/` (Phase 2).
   - Tenant default fallback: rename `nix/default-microvm/` → `nix/images/default-tenant/` (Phase 2).
   - No artifact-level marker for prod vs dev today. Phase 1g adds `variant` tag → store path becomes `mvm-<name>-{prod,dev}` and image gets `/etc/mvm/variant`.
   - No `role = builder | tenant` distinction at the artifact level today. Phase 3 adds `passthru.role`, set only by `nix/images/builder/flake.nix`.

## Recommendation

Land Phase 1 first (small, contained, captures the boot-time vs build-time split you raised, runs entirely inside the builder VM's Nix sandbox). Phase 2 is a clean follow-up move; templates outside this repo are unaffected. Phases 3-5 are larger; each can be its own PR.
