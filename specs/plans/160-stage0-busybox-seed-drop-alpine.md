# Plan 160 — Drop Alpine from Stage 0; seed the bootstrap with busybox + static Nix

## Status: Proposed (2026-06-05)

> **For agentic workers:** brainstorm/validate Phase 0 (the seed-source spike) BEFORE writing any code — the whole plan hinges on it. Steps use `- [ ]` checkboxes.

## Context

Stage 0 is the one-shot bootstrap that stands up the *first* working Nix, which then builds the real busybox-based builder-VM image (`nix/images/builder-vm/`). Today that seed is an **Alpine minirootfs**: `crates/mvm-build/src/stage0.rs` downloads + SHA-256 + **PGP-verifies** Alpine's tarball, libkrun boots its `/init` (`crates/mvm-build/src/stage0/init.sh`), and the script does `apk add e2fsprogs` then **`apk add nix git ca-certificates xz`** — i.e. Alpine exists *solely* to provide `apk` so it can install Nix.

This means the repo depends on **two** userlands: **busybox** everywhere that matters (the builder VM rootfs + every workload microVM, via `nix/lib/mk-guest.nix`'s `pkgsStatic.busybox`) and **Alpine** only as the throwaway Stage-0 scaffold. That split is incoherent, and it costs us:

- The **`pgp` crate (168-crate closure, the single biggest dep in the default `mvmctl` binary** — plan 126 A1 / `docs/investigations/dep-baseline.md`), which exists *only* to verify the Alpine seed tarball.
- An external supply-chain trust dependency on **Alpine's mirror + Natanael Copa's release key**, plus `apk` and its repo trust chain.

**Goal:** settle on busybox as the single userland. Seed Stage 0 with a **static Nix + static busybox (+ e2fsprogs + CA certs)** bundle, drop the Alpine minirootfs, `apk`, the embedded Alpine release key, and `verify_alpine_pgp_signature` — which **deletes the `pgp` dependency outright** (no feature-gating, no ADR caveat) and gives one userland story.

**Non-goals:** changing the libkrun boot sequence, the persistent `/nix` ext4 disk, or the builder-VM flake's *output* — only the *seed contents* + `init.sh`'s package-acquisition steps change.

## The hard part — Phase 0 spike (resolve before anything else)

Stage 0 is a chicken-and-egg: you cannot Nix-build the first Nix. Alpine solves it by being an **external prebuilt download**. The replacement must also come from outside the Nix build. Three candidate seed sources — **pick one in Phase 0**:

- [ ] **A. Official Nix release tarball** (`https://releases.nixos.org/nix/nix-<ver>/nix-<ver>-<arch>-linux.tar.xz`). Self-contained `/nix/store` with nix + its closure (coreutils, bash). Hash-pinned like Alpine is today; Nix releases are signed (verify the signing mechanism — if it's a detached sig we'd need a verifier, but a pinned SHA-256 is the binding check, mirroring today's Alpine hash pin). **Likely answer.** Open Qs: does the tarball's closure include enough of a userland for `/init` (mount/ip/**udhcpc**)? coreutils has no `udhcpc`/`ip` — so we still need **busybox** + **e2fsprogs** alongside it.
- [ ] **B. Project-built minimal seed** (a tiny `pkgsStatic.{nix,busybox}` + e2fsprogs rootfs, built by our own Nix and published as a *release* artifact). Cleanest contents, but it's an mvm-published prebuilt → collides with "source-checkout builds never depend on mvm-published artifacts" + "no prebuilt builder VM artifact until release" ([[feedback_no_prebuilt_builder_vm_artifact]]). Only viable if the seed counts as upstream-equivalent infra, not a build output. Needs an ADR.
- [ ] **C. `pkgsStatic.busybox` + `pkgsStatic.nix` from upstream binary caches**, fetched by hash. Depends on `pkgsStatic.nix` actually building/being cached for both arches — **HIGH-risk unknown**, verify in the pinned nixpkgs first.

- [ ] **Phase 0 exit:** one chosen source, a working `nix build` proven from that seed inside a real Stage-0 libkrun boot on aarch64 (this host) — **and** an **ADR** capturing the new bootstrap trust model (what we download, how it's pinned/verified, why dropping the Alpine PGP layer is safe — the seed is hash-pinned, same as the tarball is today). Coordinates with ADR-046 (two-artifact-layers / contributor path doesn't download mvm artifacts) and ADR-002.

### Phase 0 spike results (2026-06-05) — source A chosen, with a refinement

Measured against the official Nix release tarball (`releases.nixos.org/nix/nix-2.31.1/nix-2.31.1-<arch>-linux.tar.xz`):

- ✅ **Available + pinnable** for both `aarch64-linux` and `x86_64-linux` (HTTP 206). aarch64 2.31.1 `sha256 = 4ae8cb26dada33765f3068d185b36dcfe23efba2ba678048b70d36d8b1553850`, ~23 MiB.
- ✅ **Self-contained store** bundling `nix-2.31.1`, **`bash-5.2p37`**, `curl-8.14.1`, `xz-5.8.1`, **`nss-cacert-3.113.1`** (CA certs), glibc, openssl. So a shell + TLS trust come free; no separate ca-cert sourcing.
- ⚠️ **The bundled `busybox-1.36.1` is `busyboxMinimal`** — ships only `sh`/`ash`/`busybox` symlinks, **no `mount`/`ip`/`udhcpc`/`mountpoint`/`mkfs`**. nix uses it purely as the builder shell.
- ⚠️ **No `e2fsprogs`** in the closure (expected).

So the tarball is the right **Nix source**, but the seed still needs a **`/init` userland** for: mount pseudo-fs, bring up eth0 + get a lease (so nix can reach substituters), then `mkfs.ext4` + mount the persistent `/nix` disk. `mkfs.ext4` is **not** a sourcing problem — once the net is up, `nix build nixpkgs#e2fsprogs` (into a tmpfs/overlay store) provides it. The hard part is the **mount + network** bring-up, and:

- **busybox.net prebuilt binaries**: x86_64-only, stale (newest 1.35.0), **no reliable aarch64** → not a clean full-busybox source.
- A full `pkgsStatic.busybox` would have to be Nix-built → chicken-and-egg (need nix+net first).

**The design fork (decide in Phase 0):**
1. **Static Rust `stage0-init`** (recommended) — a small `aarch64-musl` PID-1 that does the mounts (libc `mount()`), brings up eth0 (static IP from the known gvproxy range, or a minimal DHCP), then `exec`s nix from the seed store. Reuses the repo's existing static-musl-init machinery (`mvm-host-vm-init` is already cross-compiled + embedded via `mvm-cli/build.rs` / ADR-065). Replaces `init.sh` entirely. No external busybox to source. Networking detail is the main work (today's `init.sh` leans on busybox `udhcpc`).
2. **Full static busybox companion** — pin a second download. Blocked by the aarch64 sourcing gap above; not clean.

So **the seed = the official Nix tarball + an in-repo static `stage0-init` binary** (no Alpine, no apk, no external busybox). This is bigger than "swap the asset" (it turns `init.sh` into a Rust binary) but it's the only path that doesn't reintroduce an external userland dependency. **Approved 2026-06-05.**

#### `stage0-init` design (grounded in the existing `mvm-host-vm-init`)

Most of it is already written in `crates/mvm-build/src/bin/mvm-host-vm-init.rs` and is directly reusable:
- **Mounts** — `mount_pseudofs()` (`:1766`) + `mount_user_virtiofs(tag,target,ro)` (`:1957`) use `nix::mount::mount` for proc/sys/dev + virtiofs (`/work`,`/out`) + the `/dev/vda`→`/nix` ext4 mount. **No busybox needed for mounts.**
- **`eth0` up** — already done via a Rust `SIOCSIFFLAGS|IFF_UP` ioctl (`:2008` notes "modern busybox expects the caller to" bring it up, and mvm-host-vm-init does).
- **The one new piece: DHCP.** Today's `init.sh` shells to busybox `udhcpc`, which the seed lacks. Replace with either (a) a **static IP** — gvproxy hands out a deterministic lease (fixed subnet/gateway), so the seed can hardcode/derive eth0's address + write `/etc/resolv.conf` with no DHCP at all (simplest, preferred); or (b) a ~100-line raw-socket DHCPDISCOVER/REQUEST in Rust if a lease is required. Validate gvproxy's actual range first.

**Constraint found:** the libkrun RootDir Stage 0 path carries **no kernel cmdline** (`libkrun_builder.rs:1154`), so the kernel-`ip=`-autoconfig lever is unavailable there — the init configures the net itself.

**mkfs.ext4 ordering:** with networking up, the init runs `nix` from the seed store (writable via a tmpfs overlay upper) to `nix build nixpkgs#e2fsprogs`, uses its `mkfs.ext4` to format `/dev/vda`, mounts it at `/nix`, then runs the real `nix build path:/work/nix/images/builder-vm#…`.

#### De-risk-first sequence (do NOT rip out Alpine until the new path boots)

Stage 0 is finicky ([[reference_cold_isolated_cache_stage0_badactivate]]). Keep Alpine as the fallback until proven:
- [ ] **0a:** write `stage0-init` (reusing mvm-host-vm-init's mount + eth0-up; new net-config); cross-compile + embed via `mvm-cli/build.rs` (ADR-065 pattern).
- [ ] **0b:** add the nix-tarball seed asset *alongside* Alpine behind a flag/env (`MVM_STAGE0_SEED=nix|alpine`); prove a real Stage-0 libkrun boot on aarch64 with the nix seed gets networking + completes `nix build` + emits `/out/{vmlinux,rootfs.ext4}`. **This is the gate.**
- [ ] **0c:** ADR for the bootstrap trust model; then Tasks 1–4 below rip out Alpine/apk/pgp and make the nix seed the only path.

## Build sequence (after Phase 0)

### Task 1: assemble the seed
- [ ] Produce the seed tarball(s) per the Phase-0 choice: static **busybox** (`/bin/sh`, `mount`, `ip`, `udhcpc`, `mountpoint`, `mkdir`, …), static **nix** (`nix build`, `nix daemon`), **e2fsprogs** (`mkfs.ext4` — busybox's `mke2fs` lacks reliable ext4), **CA certs**. Pin by URL + SHA-256.
- [ ] Keep size sane (target < ~25 MiB uncompressed; Alpine is ~4 MiB compressed today — note the delta).

### Task 2: `stage0.rs` — swap the asset + drop PGP
- [ ] Replace `ALPINE_MINIROOTFS_{AARCH64,X86_64}` / `ASSETS_*` / `alpine_minirootfs_for_host_arch` with the new seed asset table (`BootstrapAsset` already models URL + sha256 + mode — reuse it).
- [ ] Delete `ALPINE_VERSION`/`ALPINE_BRANCH`/`ALPINE_RELEASE_KEY_ASC`/`ALPINE_RELEASE_KEY_FINGERPRINT`, `verify_alpine_pgp_signature`, `VendorBlobPgp`'s PGP arm (or repurpose to a plain hash outcome), and `crates/mvm-build/src/stage0/alpine-ncopa-release-key.asc`.
- [ ] `prepare_assets` / `materialize_root_dir`: keep the SHA-256 verify (the binding integrity check); remove the PGP path. Materialize the seed rootfs layout (`/bin`, `/nix`, `/etc/ssl`, `/work`, `/out`, `/mvm-bins`, `/init`).
- [ ] **Remove `pgp` from `crates/mvm-build/Cargo.toml`.** Confirm `cargo tree -i pgp` is empty.

### Task 3: `init.sh` — apk → direct binaries
- [ ] Drop the `/etc/apk/repositories` write + all `apk update`/`apk add`. Keep the mount/`ip link`/`udhcpc` lines (busybox provides them, same as today).
- [ ] `mkfs.ext4` on `/dev/vda` from the seed's e2fsprogs (was `apk add e2fsprogs`).
- [ ] Start `nix` from the seed (`/nix/var` + daemon-socket + `NIX_SSL_CERT_FILE` setup) instead of `apk add nix`; run the same `nix build path:/work/nix/images/builder-vm#…` invocation.
- [ ] Update the file header comment (no Alpine).

### Task 4: docs + tests
- [ ] `nix/images/builder-vm/flake.nix` header + any Alpine references in docs/comments.
- [ ] Update/replace `stage0.rs` tests that pin Alpine hashes/fingerprint with the new seed's hash + a "no pgp / no apk" assertion.
- [ ] Grep sweep: no `apk`, `alpine`, `minirootfs`, `ncopa`, `pgp` left in `crates/mvm-build` (except historical changelog).

## Verification

- [ ] **End-to-end Stage 0 boot on this aarch64 host** (the real gate — Stage 0 is finicky; [[reference_cold_isolated_cache_stage0_badactivate]]): `mvmctl dev up` from a cold isolated `MVM_CACHE_DIR`/`MVM_DATA_DIR` builds the builder VM from the new seed, no Alpine fetched, `nix build` succeeds, `/out/{vmlinux,rootfs.ext4}` produced + promoted. Read `<vm_state_dir>/console.log` first on failure.
- [ ] `cargo tree -i pgp` empty; re-measure the default closure vs the 407 baseline (expect ~−168 minus overlap).
- [ ] `cargo nextest run -p mvm-build` + workspace build + `clippy -D warnings` + nightly fmt.

## Why this beats the plan-126 B3 alternatives

Plan 126 B3 considered *gating* or *dropping* the Alpine PGP verify to shed `pgp`. This is strictly better: it removes the **reason** `pgp` exists (the Alpine seed) rather than working around it, and it resolves the busybox-vs-Alpine incoherence. Supersedes the B3 task. Net dep win is the same headline (−168) but the architecture is cleaner and we lose an external trust dependency instead of a defense-in-depth layer.

## Deferred follow-ups
- [ ] If Phase 0 picks source B (project-built seed), the seed-publish pipeline + its ADR are their own workstream.
