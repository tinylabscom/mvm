# Plan 164 — Multi-arch embedded host binaries (x86_64 Stage 0 + builder VM)

## Status: In progress (2026-06-05) — Tasks 1–3 landed + aarch64-regression-verified. **x86_64 PROVEN on real hardware (Hetzner box):** mvmctl embeds x86_64 host bins, the supervisor links libkrun, and `stage0-init` boots on `/dev/kvm` + networks + runs `nix build` for the x86_64 builder kernel. Remaining: kernel compile completes; the firecracker-arch-download bug (Plan 165 Task 3.1); CI lane.

> Sequenced *after* Plan 160 (the nix-tarball Stage 0 seed) lands. This plan makes the embedded-host-binary toolchain pick its target by guest arch so `mvmctl` works on **x86_64 Linux**, not just aarch64. It is a standalone ADR-065 follow-up, not part of Plan 160. Steps use `- [ ]` checkboxes.

## Context

`mvmctl` embeds three Linux host-vm binaries — `mvm-host-vm-init` + `mvm-egress-proxy` (baked into the builder/dev VM rootfs from `/mvm-bins`) and `stage0-init` (the Stage 0 nix-seed's PID 1, Plan 160). `crates/mvm-cli/build.rs` cross-compiles all three at mvmctl-build time and bakes the bytes into `embedded.rs` (ADR-065 / Plan 115).

**The bug: the embed target is a single hard-coded constant.** `Cargo.toml`:

```toml
[workspace.metadata.mvm.toolchain]
zig = "0.13.0"
cargo-zigbuild = "0.20.0"
target = "aarch64-unknown-linux-musl"   # ← the only target, regardless of host
```

`build.rs::read_pinned_toolchain` reads that `target`, and `main()` cross-compiles every binary to it. So an **x86_64** mvmctl embeds **aarch64** ELFs. On an x86_64 host, Stage 0 boots an x86_64 libkrun guest, libkrun `krun_set_exec`s `/init` = the embedded `stage0-init` — which is an aarch64 binary the x86_64 kernel cannot exec. Stage 0 dies before userspace. Same for `mvm-host-vm-init` in the builder VM.

This is a **pre-existing ADR-065 limitation** — all three embedded binaries have always been aarch64-only; Plan 160 only inherited it for `stage0-init`. mvmctl is **aarch64-guest only today**.

### What already works (so the fix is small)

Every *other* arch decision is already correct, because guest arch == host arch for the local builder/Stage 0 VM (you boot a same-arch KVM guest):

- **Seed selection** — `mvm_build::stage0::asset_for_host_arch()` uses `cfg!(target_arch)`, so an x86_64 mvmctl already picks `NIX_SEED_X86_64` (the pin Plan 160 left in source).
- **Builder-VM flake ref** — `stage0-init` computes the guest arch at runtime via `uname(2)` (`machine_arch()`), producing `path:/work/nix/images/builder-vm#packages.x86_64-linux.<attr>`.
- **The nix rootfs** — `nix/images/builder-vm/flake.nix` already builds `packages.<arch>-linux`; mkGuest installs the host-vm bins from `/mvm-bins` (the host-supplied, arch-correct bytes).

So the **only** broken link is the embed step. Fix `build.rs` to embed the guest arch's binaries and the rest flows.

## The fix + its ripples

### Core change

Replace the single pinned `target` with a **per-arch target table**, and have `build.rs` pick the entry matching the arch mvmctl is being compiled *for* (`CARGO_CFG_TARGET_ARCH`, which build scripts receive; for a native build it equals the host arch, and for a cross-build it is the arch the resulting mvmctl will run on — which is exactly the guest arch its embedded bins must match).

`Cargo.toml`:

```toml
[workspace.metadata.mvm.toolchain]
zig = "0.13.0"
cargo-zigbuild = "0.20.0"
# Per-arch musl target for the embedded host-vm binaries. build.rs picks
# the entry for CARGO_CFG_TARGET_ARCH (the arch mvmctl is built for == the
# arch of the guest it boots). musl, not gnu: these bins run as PID 1 /
# early services in a minimal rootfs with no FHS dynamic loader; a static
# musl build has no interpreter dependency. They are libc-only (no
# TLS/ring/openssl) so the musl build is unencumbered.
[workspace.metadata.mvm.toolchain.targets]
aarch64 = "aarch64-unknown-linux-musl"
x86_64  = "x86_64-unknown-linux-musl"
```

`build.rs::read_pinned_toolchain` resolves `target` from that table:

```rust
let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap(); // "aarch64" | "x86_64"
let target = p["targets"][&arch]
    .as_str()
    .unwrap_or_else(|| panic!(
        "no embedded-host-binary target pinned for arch `{arch}` in \
         [workspace.metadata.mvm.toolchain.targets] — mvmctl does not yet \
         support this guest arch (Plan 164)"
    ))
    .to_string();
```

`MVM_PINNED_TARGET` (the `cargo:rustc-env` at `build.rs:34`) then reflects the resolved per-arch target — its sole consumer is `doctor.rs:2119` (the `pinned_target` diagnostic line), which now correctly shows the host's actual embed target.

### Reduce the x86_64 toolchain burden (recommended)

Today `build.rs`'s `native` check is `host_triple.contains("linux") && host_triple.contains(strip_glibc(target))`. Because the host triple is `…-linux-gnu` and the target is `…-linux-musl`, this is **always false on Linux**, so every Linux build routes through `cargo zigbuild` (needs zig + cargo-zigbuild). That's unnecessary for a **same-arch** musl build: Rust builds `<arch>-unknown-linux-musl` natively from a `<arch>-unknown-linux-gnu` host with just `rustup target add <arch>-unknown-linux-musl` (these bins are libc-only, statically musl-linked — no `musl-gcc`, no zig).

Redefine `native` as **"Linux host whose arch matches the target arch"**:

```rust
let host_arch = host_triple.split('-').next().unwrap();       // "x86_64" | "aarch64"
let native = host_triple.contains("linux") && host_arch == strip_glibc(&pin.target).split('-').next().unwrap();
```

Result: on the x86_64 Debian box (and on aarch64 Linux contributors) the embed uses plain `cargo build --release --target <arch>-musl` — **no zig needed on Linux at all**. zig/`cargo-zigbuild` remain required only on **macOS**, where mvmctl cross-compiles Linux guest bins from Darwin (the existing aarch64 path; an x86_64-guest build from a macOS host would still zigbuild to `x86_64-unknown-linux-musl`).

### Unaffected by design

- **Nix attrset + sync gate** — `nix/lib/mvm-host-binaries.nix` and `manifest.rs` key on binary *names* + install paths, not arch. `check-mvm-host-binaries-sync` keeps passing untouched. The arch lives only in the host-side cross-compile, not the manifest.
- **Reproducibility / ADR-065 claim 11** — still holds *per arch*: an aarch64 mvmctl reproducibly embeds aarch64 bins, an x86_64 mvmctl reproducibly embeds x86_64 bins. Both targets + the zig/cargo-zigbuild versions stay pinned. The double-build reproducibility check runs per release artifact, each on its own arch.

## Build sequence (after Plan 160)

### Task 1: per-arch target table
- [x] `Cargo.toml` `[workspace.metadata.mvm.toolchain]`: replaced the scalar `target` with the `[…targets]` table above (`aarch64`, `x86_64`).

### Task 2: `build.rs` picks target by arch
- [x] `read_pinned_toolchain`: resolves `target` from `targets[CARGO_CFG_TARGET_ARCH]`, fail-closed with the unsupported-arch message for any arch not in the table.
- [x] (n/a) `CARGO_CFG_TARGET_ARCH` is part of the build-script env hash already; the target triple change reruns build.rs (it's already implied by the target triple, but make the dependency explicit).
- [x] Redefined `native` as Linux-host-arch-matches-target-arch (the recommended simplification above) so x86_64 Linux builds skip zig.
- [x] Unit-tested the arch→triple resolution + the unsupported-arch panic message (the `build.rs` `#[cfg(test)] mod tests` already covers `strip_glibc`/`extract_quoted_after` — add `resolve_target_for_arch`).

### Task 3: doctor wording
- [x] `doctor.rs` `pinned_target` now reflects the host-resolved target (display only, no logic change) now that the value is host-resolved (e.g. "embedded host-binary target: x86_64-unknown-linux-musl"). No logic change — it already prints `env!("MVM_PINNED_TARGET")`.

### Task 4: provision the x86_64 validation box — [x] (2026-06-05)
The Hetzner box `root@88.99.197.234` (`ssh -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=no -i ~/.ssh/hetzner-rvproxy`) is **x86_64 Debian 12 (bookworm), kernel 6.1, `/dev/kvm` present, 8 cores / 62 GiB**. Provisioned (repo rsync'd to `/root/mvm`; build via `/root/build.sh`, Stage 0 via `/root/stage0.sh`):
- [x] **Rust** via rustup + `rustup target add x86_64-unknown-linux-musl`.
- [x] **libkrun + libkrunfw from source** (not packaged on Debian). Needs `clang libclang-dev llvm-dev` (bindgen), and **`make BLK=1 NET=1`** — the default `make` omits the blk/net features, so `krun_add_disk`/`krun_add_net_*` are absent and the supervisor link fails. Installs to `/usr/local/lib64`; symlink into `/usr/local/lib` (build.rs link-search) + `ld.so.conf.d` for runtime.
- [x] **passt** (`apt install passt`) + a wrapper: passt run as root self-drops to nobody and (a) `getpwnam` is blocked by its own seccomp → use numeric `--runas 65534:65534`; (b) can't write its `-P` PID file in the root-owned state dir → rewrite the `-P` value to `/tmp`. **Finding:** the Linux libkrun path's passt-under-root friction is a real motivation for the QEMU dev backend (ADR-072 / Plan 165, slirp = no passt).
- [x] **Linker quirk:** rustc 1.96 defaults to `rust-lld` for x86_64-linux-gnu, which this Debian gcc can't drive (`cc: cannot read spec file './specs'`). Fix = `CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=clang` (+ `CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=clang`). Box-environmental; **not** committed (CI runners drive lld fine).
- [x] **musl C toolchain:** the native musl embed pulls `ring` (C, via reqwest in mvm-build's tree) → needs `musl-tools` + `CC_x86_64_unknown_linux_musl=musl-gcc`. **Finding:** the Task-2 "no zig on Linux" claim holds for pure-Rust bins but a musl C compiler is still needed for C deps.

### Task 5: x86_64 Stage 0 boot proof — [x] embed + supervisor proven; nix build in progress (2026-06-05)
- [x] `cargo build --bin mvmctl` on the box embeds **x86_64** `stage0-init`/`mvm-host-vm-init`/`mvm-egress-proxy` ELFs (`readelf -h` → `Advanced Micro Devices X86-64`); `mvm-libkrun-supervisor` links libkrun+libkrunfw; `mvmctl --version` runs. **The core Plan 164 deliverable is proven on x86_64 hardware.**
- [x] `mvmctl kernel build --builder libkrun --kernel-source compile` (the direct Stage 0 path — `dev up` on Linux first downloads firecracker, see Task 3.1): downloads + verifies `NIX_SEED_X86_64`, materializes the seed, libkrun boots the **x86_64 `stage0-init`** on `/dev/kvm`, networks via passt, and runs `nix build packages.x86_64-linux.builder-kernel`. Reaching the nix build proves the x86_64 stage0-init boots + networks end-to-end.
- [x] **EMFILE fix:** the seed-store copy hit `EMFILE` on x86_64 — fixed by (1) raising `RLIMIT_NOFILE` in `stage0-init` (committed; PID 1 lifts soft+hard) and (2) `ulimit -n` on the host before launch (the in-process virtiofs in the supervisor exhausts host fds copying the closure). **Finding:** mvm should raise the *supervisor's* host `RLIMIT_NOFILE` so users don't need `ulimit -n` — track as a libkrun-supervisor follow-up.
- [ ] Kernel compile completes → `/out/vmlinux` produced + promoted (long nix build; in progress).

### Task 6 (optional, after the boot proof): permanent CI lane
- [ ] An `ubuntu-latest` lane (exposes `/dev/kvm` — the existing `cloud-hypervisor`/`firecracker` lanes in `ci-full.yml` rely on it) that installs libkrun + builds mvmctl + runs a cold x86_64 Stage 0 smoke. Gated like the other VM-boot lanes (`continue-on-error` / change-filter) so a flaky runner can't block branch protection. **Never run unbounded** ([[feedback_never_run_core_demo_e2e_unbounded]]) — background + timeout + log-to-file.

## Verification
- [ ] aarch64 unchanged: `cargo build --bin mvmctl` on the dev Mac still embeds aarch64 bins; `file` confirms `ARM aarch64`; the Plan 160 aarch64 Stage 0 boot still works.
- [ ] x86_64 Stage 0 boots end-to-end on the Hetzner box (Task 5).
- [ ] `cargo test -p mvm-cli` (build.rs arch-resolution unit test) + `check-mvm-host-binaries-sync` still agrees on 2 entries + nightly fmt + `clippy -D warnings`.

## Non-goals / out of scope
- **x86_64 *release artifact*.** This plan makes the **source-build + embed** correct on x86_64 (contributor / the Hetzner box). Publishing an x86_64 mvmctl in `release.yml` stays deferred per the release-pipeline state ([[project_release_pipeline_gotchas]] — Intel deferral); it's a separate workstream that consumes this one.
- **Firecracker / Apple-Container Stage 0.** Stage 0 remains libkrun-only (ADR-068); the per-backend Stage 0 impls are Plan 133, independent of arch.
- **Cross-arch guests** (booting an x86_64 guest on an aarch64 host or vice-versa). Not supported and not wanted — the builder/Stage 0 VM is always same-arch as the host.

## Deferred follow-ups
- [ ] If a second non-x86_64/aarch64 arch is ever needed, the table + `CARGO_CFG_TARGET_ARCH` switch already scales — only a new pinned triple + a rust musl target are required.
