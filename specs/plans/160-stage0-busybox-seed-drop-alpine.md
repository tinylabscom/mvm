# Plan 160 — Drop Alpine from Stage 0; seed the bootstrap with busybox + static Nix

## Status: Rip-out landed (2026-06-05) — nix seed is the ONLY Stage 0 path; Alpine/apk/pgp/`init.sh`/the Alpine release key deleted; `pgp` dropped from the tree (`cargo tree -i pgp` empty). Bootstrap trust model captured in **ADR-071**. Remaining (own follow-ups, not blockers): x86_64 + CI validation of the nix seed, persistent ext4 `/nix` store (a RAM optimization — tmpfs holds today), in-process xz decode.

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

#### 0a findings (2026-06-05) — both big risks are already solved in-repo

- **Networking is FREE.** Stage 0's libkrun launch (`libkrun_builder.rs::apply_networking_mode` → `with_passt`/`with_gvproxy` → `configure_with_gateway`) sets **`NET_FLAG_DHCP_CLIENT`**; `libkrun-sys/src/lib.rs:313` confirms the guest "sees a normal eth0 + DHCP + DNS… for **Stage 0**." So `stage0-init` needs **zero networking code** — the current `init.sh` `ip link`/`udhcpc` is legacy/redundant. The DHCP piece I flagged as "the one new thing" doesn't exist.
- **The nix-store overlay is already written.** `mvm-host-vm-init::setup_nix_store()` already does exactly the seed-store problem: `nix_store_dev_needs_format` (superblock probe) → `format_ext4` → `mount_fs` → **`mount_nix_overlay`** (lower = read-only rootfs `/nix`, upper = persistent disk) → bind over `/nix`, with a `seed_nix_store` copy fallback. With the nix tarball the seed's `/nix/store` (read-only virtiofs root) is the overlay **lower**; the persistent `/dev/vda` is the **upper** → nix sees its own closure + can write builds. Same pattern, just `/dev/vda` + the tarball seed.
- **Mounts + deps are reusable.** `mount_pseudofs()` + `mount_fs`/`mount_fs_idempotent` (via `nix = { features=["mount","reboot","signal","ioctl"] }`, already a `mvm-build` dep) cover proc/sys/dev/pts/shm + virtiofs + the ext4 mount. No busybox.

So `stage0-init` = `mount_pseudofs` + virtiofs shares + the (already-written) overlay nix-store on `/dev/vda` + env + `nix build <flake>` + copy `/out` + `poweroff` (nix `reboot`). The `e2fsprogs` worry is gone too — the overlay upper is formatted with the same `format_ext4` mvm-host-vm-init already uses (no external mkfs). **Architecture choice:** factor the shared mount/overlay/nix-store helpers out of `mvm-host-vm-init.rs` into a `mvm-build` module both bins use (preferred, avoids duplication) — but extract carefully (that bin is validated/working).

#### 0b ACHIEVED (2026-06-05) ✅ — nix-seed Stage 0 boots + builds end-to-end

A cold `MVM_STAGE0_SEED=nix MVM_BUILDER_BACKEND=libkrun mvmctl dev up` on this aarch64 host **completed successfully**: downloaded the pinned nix tarball → materialized the seed (`/init`=stage0-init ELF) → `stage0-init` ran nix → substituted the toolchain from cache.nixos.org → **built the builder-VM image (`vmlinux` 31M + `rootfs.ext4` 743M)** → the builder VM booted from it → `[mvm] Dev environment ready (libkrun)`. No Alpine, no apk, no pgp. The **tmpfs store did NOT OOM** on the full build, so the simple copy-to-tmpfs holds for now (the persistent ext4 disk is an optimization, not a blocker). The store-FS fix below (copy-to-tmpfs, option a) is what landed; option b (ext4 disk) is the optional follow-up.

#### 0b boot loop progress (2026-06-05) — the iteration that got there

Drove a real `MVM_STAGE0_SEED=nix MVM_BUILDER_BACKEND=libkrun` Stage-0 boot on this aarch64 host. Confirmed working: nix tarball download (sha-pinned) → seed materialize (`/init` = the static `stage0-init` ELF, `/nix/store` = the nix closure) → libkrun boot → **`stage0-init` runs as PID 1**: pseudo-fs + virtiofs mounts ✓, finds nix ✓, **`nix --version` runs ✓** (`nix (Nix) 2.31.1`). Fixed three real bugs along the way (the minimal seed rootfs lacks dirs the Alpine minirootfs had): create every mount target before `mount(2)` (`/tmp`,`/run`,`/run/nix-upper`); write `/etc/resolv.conf` (gvproxy DNS `192.168.127.1` — `NET_FLAG_DHCP_CLIENT` brings up eth0 but doesn't write resolv.conf, so "networking is free" was half-right); `NIX_REMOTE=` for single-user.

**The one remaining blocker — overlay-over-virtiofs:** `nix build` fails at `creating directory '/nix/store/.links': Network dropped connection on reset` (ECONNRESET). That errno on a local mkdir = a **virtiofs/FUSE backend error**: my `/nix` overlay uses the **virtiofs seed store as the overlay lower**, and overlayfs writes over a virtiofs lower fail in libkrun. (`mvm-host-vm-init`'s proven overlay uses an **ext4 block-device** lower — that's why it works.)

**Fix (the remaining 0b work):** get the seed store onto a **non-virtiofs writable** fs before nix writes. Either (a) copy the seed `/nix/store` (virtiofs) → a tmpfs `/nix` in `stage0-init` (simple; but the full builder-VM build may exhaust RAM — the very reason the persistent ext4 disk exists), or (b) the proper path: bootstrap nix in a small tmpfs, `nix build nixpkgs#e2fsprogs`, `mkfs.ext4 /dev/vda`, copy the store to the ext4 disk, build there (this also restores the persistent-store optimization). (b) is the real answer; it's the "persistent ext4 disk" follow-up, now required (not deferrable) because of the overlay-virtiofs finding. The seed has no `cp`, so the copy is a small recursive Rust walk (symlinks + modes).

#### De-risk-first sequence (do NOT rip out Alpine until the new path boots)

Stage 0 is finicky ([[reference_cold_isolated_cache_stage0_badactivate]]). Keep Alpine as the fallback until proven:
- [x] **0a:** wrote `stage0-init`; cross-compiled + embedded via `SEED_BINARIES` + `mvm-cli/build.rs`.
- [x] **0b:** added the nix-tarball seed *alongside* Alpine behind `MVM_STAGE0_SEED=nix|alpine`; **proved a full cold `dev up` on aarch64 builds the builder VM via the nix seed + reaches "Dev environment ready"** (no Alpine/apk/pgp). ✅
- [x] **0c:** **rip-out landed (2026-06-05).** The user directed settling on one userland *now* ("go back to busybox entirely … depend upon a single one"). `MVM_STAGE0_SEED` + the `Stage0Seed` enum are gone; the nix seed is the only path. Deleted: `init.sh`, `alpine-ncopa-release-key.asc`, all `ALPINE_*`/`ASSETS_*`/`alpine_minirootfs_for_host_arch`/`verify_alpine_pgp_signature`/`extract_alpine_tarball`/`fetch_signature`/`VendorBlobPgp`, and the `pgp` dep (`cargo tree -i pgp` empty; 379 unique crates vs 407 baseline). Bootstrap trust model → **ADR-071**. The x86_64 + CI validation that 0c originally gated *before* the rip-out is now an **after-the-fact follow-up** (below) — the aarch64/libkrun boot proof + the user directive were judged sufficient to drop the fallback.

## Build sequence (as landed — the Phase-0 spike refined the original tasks)

> The original Task 1/3 assumed a static-**busybox** companion download + a *modified* `init.sh`. Phase 0 showed busybox can't be sourced cleanly for aarch64, so the seed is the **official Nix tarball's closure + a Rust `stage0-init`** that *replaces* `init.sh`. Tasks below reflect what actually shipped.

### Task 1: the seed source — [x] official Nix release tarball
- [x] Pin `nix-<ver>-<arch>-linux.tar.xz` by URL + SHA-256 for both arches (`NIX_SEED_AARCH64`/`NIX_SEED_X86_64`/`NIX_SEED_VERSION`). Its `store/` is a self-contained `/nix/store` (nix + bash + curl + xz + nss-cacert). No separate busybox/e2fsprogs/CA-cert download — `stage0-init` provides the userland; e2fsprogs is a runtime `nix build` (deferred to the persistent-store follow-up).

### Task 2: `stage0.rs` — swap the asset + drop PGP — [x]
- [x] Removed `ALPINE_MINIROOTFS_*`/`ASSETS_*`/`ALPINE_VERSION`/`ALPINE_BRANCH`/`ALPINE_RELEASE_KEY_*`/`alpine_minirootfs_for_host_arch`/`Stage0Seed`. The nix-seed table (`assets_for_host_arch`/`asset_for_host_arch`) is the only one.
- [x] Deleted `verify_alpine_pgp_signature`, `extract_alpine_tarball`, `fetch_signature`, the `VendorBlobPgp` enum, and `signature_url`. `VendorBlobReport` is hash-only (`audit_detail` drops `pgp=`).
- [x] `materialize_root_dir(_in)` re-verifies the SHA-256 (fetch + extract), extracts `store/` → `<dest>/nix/store`, writes the embedded `stage0-init` as `/init`, creates `/work /out /mvm-bins`.
- [x] **Removed `pgp` from `crates/mvm-build/Cargo.toml`.** `cargo tree -i pgp` is empty.

### Task 3: PID 1 — [x] `stage0-init` replaces `init.sh`
- [x] `init.sh` deleted. `crates/mvm-build/src/bin/stage0-init.rs` (static `aarch64-musl`, embedded via `SEED_BINARIES` + `mvm-cli/build.rs`) does mounts + virtio-fs shares + tmpfs `/nix` (copy seed closure; overlay-over-virtiofs fails in libkrun) + `/etc/resolv.conf` (gvproxy DNS) + the same `nix build path:/work/nix/images/builder-vm#…` + copy to `/out` + poweroff. No apk, no networking code (libkrun `NET_FLAG_DHCP_CLIENT` supplies eth0).

### Task 4: docs + tests — [x]
- [x] Stage 0 + builder-VM-launch doc comments de-Alpine'd (`stage0.rs`, `stage0-init.rs`, `apple_container.rs`, `libkrun_builder.rs`). ADR-071 written.
- [x] `stage0.rs` tests replaced: nix-seed table/hash assertions + missing/tampered-tarball rejection; `cache.rs` fixture renamed to `nix-seed-*`.
- [x] Grep sweep: no `apk`/`alpine`/`minirootfs`/`ncopa`/`pgp` in `crates/mvm-build` live code (only the header note explaining what was removed).

## Verification

- [x] `cargo tree -i pgp` empty; 379 unique crates vs the 407 Plan 126 A1 baseline.
- [x] `cargo test -p mvm-build --lib stage0` (12 pass) + `cargo test -p mvm-cli --lib cache` (pass); `cargo build -p mvm-build -p mvm-cli` + `clippy -p mvm-build -p mvm-cli -D warnings` clean.
- [x] **End-to-end Stage 0 boot on this aarch64 host** (0b): cold `dev up` built the builder VM from the nix seed (`vmlinux` 31M + `rootfs.ext4` 743M) and reached "Dev environment ready (libkrun)" — no Alpine/apk/pgp.
- [ ] **x86_64 + CI** Stage 0 boot (the pin is in source, unbooted). Follow-up — see Status.
- [ ] nightly fmt + full `cargo nextest run --workspace` on CI (local mvm-backend test SIGKILL is environmental — [[reference_mvm_backend_test_binary_macos_codesign_sigkill]]).

## Why this beats the plan-126 B3 alternatives

Plan 126 B3 considered *gating* or *dropping* the Alpine PGP verify to shed `pgp`. This is strictly better: it removes the **reason** `pgp` exists (the Alpine seed) rather than working around it, and it resolves the busybox-vs-Alpine incoherence. Supersedes the B3 task. Net dep win is the same headline (−168) but the architecture is cleaner and we lose an external trust dependency instead of a defense-in-depth layer.

## Deferred follow-ups
- [ ] **x86_64 + CI validation** of the nix-seed Stage 0. The x86_64 pin (`NIX_SEED_X86_64`) is in source but unbooted; the boot proof is aarch64/libkrun only. Until this lands, the seed is validated on one arch.
- [ ] **Persistent ext4 `/nix` store.** `stage0-init` copies the seed closure into tmpfs each boot; the host attaches `nix-store-stage0-<arch>.img` (`/dev/vda`) but `stage0-init` doesn't yet bootstrap e2fsprogs + format + use it. RAM optimization (build once, reuse the closure), not correctness — tmpfs holds the full build. See ADR-071 "Status of work".
- [ ] **In-process xz decode.** `extract_nix_store_tarball` shells to host `tar -xJf` (first cut); a pure-Rust xz decoder removes the host-`tar` dependency.
