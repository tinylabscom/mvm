# ADR 071 - Stage 0 bootstrap trust model: hash-pinned Nix tarball seed, one userland

**Status**: Accepted
**Date**: 2026-06-05
**Cross-refs**: ADR-013 (libkrun pivot — host never needs Nix), ADR-046 (two artifact layers; contributor path never downloads mvm-published artifacts), ADR-065 (single builder/dev image; host-vm binaries cross-compiled to static `aarch64-musl` + embedded by `mvm-cli/build.rs`), ADR-068 (Stage 0 dispatches through the `BuilderVm` trait), ADR-002 (security posture — Stage 0 is the dev-tier builder VM, out of scope for the hardened workload claims). Planning input: Plan 160 (this seed swap), Plan 126 A1/B3 (dependency baseline — `pgp` was the single biggest closure in the default `mvmctl` binary).

## Context

"Stage 0" is the one-shot from-source bootstrap that stands up the *first* working Nix on a contributor host with no host Nix and no prebuilt artifacts (ADR-013, ADR-046). That first Nix then builds the steady-state busybox builder VM (`nix/images/builder-vm/`), which builds everything else.

The chicken-and-egg is unavoidable: **you cannot Nix-build the first Nix.** The seed has to come from outside the Nix build. The previous seed (Plan 91) solved it with an **Alpine minirootfs**: `stage0.rs` downloaded Alpine's tarball, SHA-256-checked it, **PGP-verified it against Natanael Copa's embedded release key**, and booted its `/init` (`stage0/init.sh`), which ran `apk add nix e2fsprogs …` — Alpine existed *solely* to provide `apk` so it could install Nix.

This made the repo depend on **two userlands**: busybox everywhere that matters (the builder VM rootfs + every workload microVM, via `nix/lib/mk-guest.nix`'s `pkgsStatic.busybox`), and Alpine only as a throwaway Stage-0 scaffold. The split cost us:

- The **`pgp` crate — a 168-crate closure, the single largest dependency in the default `mvmctl` binary** (Plan 126 A1) — which existed *only* to verify the Alpine seed tarball.
- An external supply-chain trust dependency on **Alpine's mirror + Copa's release key + `apk`'s repo trust chain**, layered on top of the SHA-256 pin that already bound the bytes.

## Decision

**Seed Stage 0 with the official Nix release tarball, hash-pinned, plus an in-repo static `stage0-init` PID 1. One userland — busybox. No Alpine, no `apk`, no PGP.**

### What we download and how it's pinned

The seed is the **official Nix release tarball** —
`https://releases.nixos.org/nix/nix-<ver>/nix-<ver>-<arch>-linux.tar.xz` — pinned by **URL + SHA-256** in source (`NIX_SEED_AARCH64` / `NIX_SEED_X86_64`, `NIX_SEED_VERSION` in `crates/mvm-build/src/stage0.rs`). Extracted, its `store/` *is* a populated `/nix/store` carrying `nix` + its full runtime closure: `bash`, `curl`, `xz`, **`nss-cacert`** (CA trust comes free), glibc, openssl. The tarball is a self-contained, upstream-published artifact — the same category Alpine's minirootfs was.

The **SHA-256 pin is the binding integrity check** (verified at fetch *and* re-verified at extract, fail-closed both times — `prepare_assets_in` + `materialize_root_dir_in`). A `VendorBlobReport` is emitted per fetch/revalidation into the chain (`LocalAuditKind::VendorBlobFetched`), carrying `url`, `sha256`, `bytes`, `outcome` — every supply-chain trust decision on the no-prebuilt-download path stays auditable.

### Why dropping the Alpine PGP layer is safe

A pinned SHA-256 over a specific upstream-published version is a *stronger* binding than a detached signature over a moving "latest": the hash names exactly one byte sequence, fail-closed, with no trust delegated to a third-party key whose rotation we'd have to track. The previous PGP step verified Alpine's tarball against Copa's key; that's a guarantee *about Alpine's release process*, not about the bytes we actually want — which the hash already nails. Removing it deletes an external trust dependency (Alpine mirror + key + `apk`) without weakening the integrity guarantee on the seed we boot. This is consistent with the repo's broader posture (ADR-046 — the contributor path is hermetic and never trusts mvm-published prebuilts; here it trusts only a hash-pinned upstream Nix release).

### The seed userland: `stage0-init`, not a shell script

The Nix tarball's bundled `busybox-1.36.1` is **`busyboxMinimal`** — `sh`/`ash` only, no `mount`/`ip`/`udhcpc`/`mkfs`. So the seed cannot provide a full `/init` userland from the tarball alone, and busybox.net has no reliable aarch64 prebuilt to pin alongside it (sourcing a second external userland would reintroduce exactly the dependency we're removing).

Instead the seed's PID 1 is **`stage0-init`** — a small static `aarch64-unknown-linux-musl` binary in this repo (`crates/mvm-build/src/bin/stage0-init.rs`), cross-compiled and embedded by `mvm-cli/build.rs` through the same machinery as the other host-vm binaries (ADR-065), registered via a host-side-only `SEED_BINARIES` list (it is never installed into a VM and is absent from the nix attrset / the host-binaries sync gate). `materialize_root_dir` lays down the extracted `/nix/store` and writes `stage0-init` as `/init`; libkrun runs it via `krun_set_exec`.

`stage0-init` does the irreducible bring-up in Rust (no external userland): mount the pseudo-filesystems + the `/work`/`/out`/`/mvm-bins` virtio-fs shares; make `/nix` a writable store (copy the seed closure into a tmpfs and bind it over `/nix` — **overlay-over-virtiofs writes fail in libkrun**, nix's `/nix/store/.links` hits `ECONNRESET`); write `/etc/resolv.conf` pointing at gvproxy's gateway (libkrun's `NET_FLAG_DHCP_CLIENT` brings up eth0 + DHCP but **not** DNS); then `nix build` the in-repo builder-VM flake (single-user: `NIX_REMOTE=` + `--option build-users-group ""`, default sandbox kept), copy `vmlinux` + `rootfs.ext4` to `/out`, and power off. This is the `BuilderVm::run_stage0` libkrun impl (ADR-068); the host-side contract (`/out/stage0-build.conf`, output modes) is unchanged.

## Consequences

- **`pgp` is deleted outright** — no feature gate, no caveat. `cargo tree -i pgp` is empty; the default `mvmctl` closure drops ~168 crates (379 unique vs the 407 Plan 126 A1 baseline, net of overlap).
- **One userland story.** Everything mvm boots is busybox: the seed's shell, the builder VM rootfs, every workload microVM. Alpine, `apk`, the embedded release key, and `init.sh` are gone from the tree.
- **`MVM_STAGE0_SEED` is gone.** The nix seed is the only Stage 0 path; there is no Alpine fallback to select. (No backwards compatibility — this is the first version.)
- **Security posture unchanged.** Stage 0 is the dev-tier builder VM (ADR-002 out-of-scope for the hardened workload claims). The seed integrity check is *strengthened in surface* (one hash-pinned upstream artifact, fail-closed at fetch + extract) and *narrowed in trust* (no third-party signing key).

## Status of work — validation caveat

Proven **end-to-end on aarch64 / libkrun** (this contributor host): a cold `mvmctl dev up` materializes the nix seed, boots `stage0-init`, runs `nix build` (substituting the toolchain from `cache.nixos.org`), produces `vmlinux` (31 MiB) + `rootfs.ext4` (743 MiB), boots the builder VM from them, and reaches "Dev environment ready (libkrun)" — no Alpine/apk/pgp. The tmpfs-copy store did not OOM on the full build.

Outstanding, sequenced as Plan 160 follow-ups (do not block this ADR):

- **x86_64 + CI validation** of the nix-seed Stage 0 (the boot proof is aarch64-only so far). The `x86_64` pin is in source but unbooted.
- **Persistent ext4 `/nix` store.** `stage0-init` currently copies the seed closure into tmpfs each boot; the host still attaches the persistent `nix-store-stage0-<arch>.img` disk (`/dev/vda`), but `stage0-init` does not yet bootstrap e2fsprogs + format + use it. This is a RAM optimization (build once, reuse the closure across `dev up` runs), not a correctness requirement — the tmpfs store holds for the full build.
- **In-process xz decode.** `extract_nix_store_tarball` shells to the host `tar -xJf` for the first cut; a pure-Rust xz path is polish.
