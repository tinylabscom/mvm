---
title: Development Guide
description: Getting started as a contributor to mvm.
---

Working with an AI coding agent on this repo? Read the
[AI Coding Workflow](/contributing/ai-coding-workflow/) guide alongside this one —
it covers claiming issues, the mandatory worktree flow, the Trail/Serena tooling
split, the fast feedback ladder, and what CI does and does not gate.

## Repository layout

The full map, with consumers and the `third_party/` / `crates/deps/` / `nix/`
boundaries, is [Repository Layout](/contributing/repository-layout/).

- `src/` and `crates/` contain the CLI entry point and Rust workspace crates.
  `crates/deps/` contains workspace dependencies, including the libkrun
  bindings and the locally adapted Mach-O signing crate.
- `third_party/` contains vendored upstream sources used by the root
  `[patch.crates-io]` overrides. Check each dependency's provenance and
  license before changing or removing it; `crates/deps/mvm-macho-sign` also
  contains adapted upstream code with its own provenance and license.
- `specs/` holds the PRD, architectural decisions and durable contracts.
  `schema/` holds machine-readable interfaces used by SDK generation.
  `model/` holds the conformance claims, authorities and ledger; its generated
  `CONFORMANCE.md` connects claims to scenarios and witnesses.
- `assets/` holds the macOS signing entitlement profiles used in builds and
  installation. `features/` and `tests/` hold behavioral and integration tests.
- `Justfile` provides the common commands, all in that one file.
  `scripts/` contains supporting scripts and `xtask/` contains Rust maintenance
  and validation commands.
- `nix/` contains Nix build definitions as well as packaging, operational
  tooling and tests. The Linux image layer belongs to `mvm-images`, but not
  every file under `nix/` is an image definition: the staged boundary is
  documented in [ADR-054](https://github.com/tinylabscom/mvm/blob/main/specs/adrs/054-image-boundary-linux-layer.md).
- `public/` contains the documentation site; `web/` contains web components.
  `examples/` contains example workloads and `bin/` contains executable tools.

## macOS documented-surface evidence

After the change under test has landed on `main`, an authorized maintainer can
collect evidence without running the Release workflow:

```bash
gh workflow run e2e-docs-evidence.yml --repo tinylabscom/mvm --ref main -f lane=macos
gh run list --repo tinylabscom/mvm --workflow e2e-docs-evidence.yml --limit 5
```

The dispatch admits only this repository's `main`, has `contents: read` only,
inherits no secrets, and neither publishes nor deploys. The run's `headSha`
(`gh run view --repo tinylabscom/mvm --json headSha,url`) identifies the tested
commit: the local reusable workflow and default checkout both use that event
SHA, not a later moving `main`. Its only input is `lane`, a choice of `linux`
or `macos`; there is no arbitrary ref or command input.

This runs the complete existing macOS HVF suite on the self-hosted Apple Silicon
runner, including both `0/2` and `1/2` shards, live and snapshot coverage, and
strict skip accounting. No runtime candidate is supplied; only scenarios tagged
`@runtime_candidate` may additionally report `needs-runtime-candidate`.
Release defaults still require both operating systems and a signed candidate.

Download both `e2e-docs-macos-logs-RUN_ID-RUN_ATTEMPT-JOB_INDEX` artifacts from
the run page within 14 days. Read each `e2e-docs.log` summary and its “did NOT
run” tally, not just the job status. For issue #4096, the scenario
`recorded prompts replay onto a fork of the session's base` in
`features/suites/s32_documented_surface/agent_prompt.feature` must actually pass:
turns one and two, replay onto a fork, turn three, replay the fork's session,
and turn four, with no step-checkpoint failure. It is not runtime-candidate
tagged and must not be accepted as skipped. Retain the run URL, tested SHA,
both shard summaries and witness output with the issue evidence.

A queued/offline runner, failed preflight, recorded-local-evidence fallback,
missing summary, skipped prompt scenario or failed shard is not a new live HVF
prompt/replay witness. This wiring alone does not complete #4096.

## Linux documented-surface evidence

After review and landing on `main`, an authorized maintainer can collect the
Linux Firecracker evidence for #4764 without Release or draft assets:

```bash
gh workflow run e2e-docs-evidence.yml --repo tinylabscom/mvm --ref main -f lane=linux
gh run list --repo tinylabscom/mvm --workflow e2e-docs-evidence.yml --limit 5
```

This is the same workflow with the other lane: it admits only this
repository's `main`, has only `contents: read`, inherits no secrets, accepts
no ref or command inputs, and does not publish or deploy. The local reusable workflow and checkout use the
event SHA; record it with `gh run view RUN_ID --repo tinylabscom/mvm --json headSha,url`.
It runs the full existing Linux suite, both `0/2` and `1/2` shards, with live,
directory-share and strict-skip flags unchanged. Only `@runtime_candidate`
scenarios may additionally report `needs-runtime-candidate`; Release defaults
still require both operating systems and a signed candidate.

Save both Linux shard job logs from the run page; this lane does not upload
log artifacts. Retain the run URL, tested SHA, both scenario summaries and their
“did NOT run” tallies, and the witness output. The scenario
`restarting refreshes a registered host directory snapshot` in
`features/suites/s26_volumes/volume_lifecycle.feature` must actually pass,
including the initial marker and the refreshed marker after stop/start. It is
not runtime-candidate tagged and must not be accepted as skipped. A failed
shard, missing summary or skipped witness is not Linux live evidence for the
socket-custody fix in #4808. This entrypoint alone does not complete #4764.

## Prerequisites

- **Rust 1.100.0** (Edition 2024) — install via [rustup](https://rustup.rs).
  `rust-toolchain.toml` pins ordinary builds, tests, linting, and release builds
  to this compiler. `just` recipes use the same LLVM backend and worktree target
  directory as plain Cargo; there is no separate Cranelift development build.
  Excluded browser/example Cargo projects inherit this root compiler too.
  Embedded Linux payloads use the same version through the reproducibility
  metadata installed by `just setup toolchain`; the toolchain check rejects
  divergence. Fuzzing retains nightly for sanitizer flags, and eBPF retains
  nightly for building the core library for BPF targets. Those tooling exceptions
  are not ordinary stable builds. Cargo package `rust-version` declarations
  describe minimum supported compilers, not a different selected toolchain.
- **Nix source builds** select first-party Cargo, rustc, and Clippy from the same
  source snapshot's Rust pin and locked Rust overlay, rather than a caller's
  ambient `rustPlatform`. The compiler runs on the build machine with the target's
  standard library; existing static-musl and dynamic-libc linker settings remain
  separate. An uncached overlay requires its immutable, hash-verified source
  download during evaluation. There is no fallback to an ambient compiler.
- **macOS 26+ Apple Silicon or Linux** — standard source-checkout development
  uses native HVF on macOS and native `/dev/kvm` on Linux. macOS 25 and older
  is not supported.
- **`zig` + `cargo-zigbuild`** — source-checkout contributors only; needed to build the Linux host binaries a VM boot uses, which an `embed-host-bins` build embeds and an unembedded `mvmctl` builds on first use. `just setup toolchain` installs the pinned Zig package into `~/.local/share/mvm/toolchains/zig/<version>` rather than system Python, so it works with externally managed Python on Ubuntu and Debian; the build detects the pinned binary there. End-users running a downloaded `mvmctl` don't need them.
- **Nix** — not needed on the host. Nix evaluation and `nix build` run inside the builder VM.

Direct Nix recipe sources must include `rust-toolchain.toml` and `nix/flake.lock`.
The source snapshot's lock is authoritative: overriding only the consumer's
rust-overlay flake input does not change the compiler. Direct callers must remove
the former `rustPlatform` and `clippy` arguments from first-party recipes.
Pin changes select new derivations; existing Nix store outputs remain immutable.
Third-party nixpkgs/libkrun builds are not part of this first-party compiler pin.

### Do I need to install libkrun?

No. Neither a downloaded release nor a standard source build installs, links,
or auto-selects it:

| Host | libkrun (`slp/krun/*`) needed? |
|---|---|
| macOS 26+ Apple Silicon | **No** — auto-detect picks the native **HVF** builder (Hypervisor.framework, ships with the OS, no Homebrew deps). |
| Linux + `/dev/kvm` | **No** — auto-detect picks the **Firecracker** builder, so libkrun is not part of the default builder path on native Linux hosts. |

The libkrun Cargo features remain for explicit source-checkout integration
development and CI coverage; end users do not compile them. `mvmctl doctor`
reports the resolved standard backend on the `builder backend` line
(`<backend> — <source> — <availability>`).

The contributor-only `--source compile` kernel path still uses the explicit
libkrun integration for its Stage 0 build. That path is not used by ordinary
source compilation or downloaded releases; end users consume the published
kernel artifacts. Contributors exercising that integration must install its
development prerequisites explicitly.

### Getting started

If you use Nix for contributor tools, `nix develop` opens the lean shell with
the Rust toolchain pinned by `rust-toolchain.toml` and the tools for normal
editing, checking, and testing. `nix develop .#full` adds Zig, libclang, release,
lint, and documentation tools. Run `just setup toolchain` in the full shell
before payload or release builds; it installs the exact Zig and cargo-zigbuild
pins used by this checkout. These shells do not build or publish images; that
work belongs to `mvm-images`.

The default shell is lean because first entry was slow when it carried the
payload toolchain. Measured in October 2026 inside the builder VM, with builder
image and payload preparation excluded:

| Host | First entry, before → after | Repeat entry, before → after |
| --- | --- | --- |
| x86_64 Linux, Firecracker builder, shared Nix store | 354.58 s → 14.21 s | 1.29 s → 1.29 s |
| Apple Silicon macOS, HVF builder, fresh guest store | 392.63 s → 245.43 s | 2.25 s → 1.50 s |

"Before" fetched Zig 0.13 and 0.15, cargo-zigbuild and libclang on entry.
`scripts/check-devshell-tiers.sh` keeps them out of the default shell and in
`.#full`; it runs in the Nix flake check lane after the merge, on every push to main.

A full clone downloads about 215 MiB, roughly 150 MiB of which is a build
directory committed by mistake in August 2026 and deleted in September. History
was not rewritten to remove it. Add `--filter=blob:none` to the clone below to
skip it: that clone downloads about 30 MiB and fetches older file versions only
when a command such as `git log -p` needs them.

```bash
git clone https://github.com/tinylabscom/mvm.git
cd mvm

# Source-checkout contributors: install the *pinned* zig, the Linux
# cross-targets for the active toolchain and the pinned cargo-zigbuild. Do NOT
# `brew install zig` — Homebrew's zig drifts off the pinned cargo-zigbuild and
# fails with a cryptic CacheCheckFailed.
just setup toolchain

cargo build
cargo run -- doctor     # reports the builder backend + anything missing

# A VM boot needs the Linux host binaries. This mvmctl builds them itself the
# first time it needs a builder VM, and says so before it starts.
cargo run -- bootstrap
```

> **Note — where the Linux host binaries come from.** Their musl cross-compile
> is the only work `mvm-cli`'s build script still does, and it runs only when
> you build with the `embed-host-bins` feature. Nothing else turns it on: not the
> release profile, not an environment variable. So a plain `cargo build
> --release` is as fast as a debug build, the same command produces the same kind
> of binary on every machine, and the edit/check/test loop (`cargo check`,
> clippy, nextest) never cross-compiles.
>
> Either way the result lands in the content store at `~/.cache/mvm/embed`,
> keyed to the sources it was built from, and every build restores from there:
> a debug `cargo build` after a release one carries the payload without
> compiling it. An `mvmctl` that still has none builds it in-process the first
> time it needs a builder VM, into the same store — one status line on stderr
> first, the compiler output with `-v` — so the next `cargo build` embeds it.
> It never compiles a second `mvmctl`. `just build embed` (or `just build embed --release`)
> builds the whole set up front, per-VM helpers included. Released binaries
> always carry the payload.

### When to build with `embed-host-bins`

`embed-host-bins` makes the build cross-compile the Linux host binaries and
compile them into `mvmctl`. It is the only switch for that, and it adds minutes
to a build, so use it deliberately.

| You are... | Use it? | Why |
| --- | --- | --- |
| Editing, running `cargo check`, clippy or the tests | No | None of these need the payload, and the cross-compile would sit in every iteration. |
| Running `mvmctl` from your own checkout, including the demo | No | An unembedded `mvmctl` builds the payload from its checkout the first time it needs a builder VM and caches it. Or use an installed release, which already carries it. |
| Building a release, or anything you hand to someone else | Yes | The recipient has no checkout to build the payload from. The tag-push release workflow passes the feature, so a downloaded binary is self-sufficient. |
| Running `just build embed` | Already on | The recipe passes it, and also builds the per-VM helpers next to the binary. |
| A CI lane that needs a builder VM and has no checkout to build from | Yes | Add `--features embed-host-bins` to its build. |
| Testing the cross-compile itself | Yes | `cargo nextest run -p mvm-cli --features embed-host-bins` is the lane that covers it. |

```sh
cargo build --release                                  # fast; no payload compiled
cargo build --release --features embed-host-bins       # slow; carries the payload
just build embed --release                                   # the same, plus the per-VM helpers
```

The pinned zig and `cargo-zigbuild` must be installed for the feature
(`just setup toolchain`); without them the build fails and names the fix.
The build script and `mvmctl` both find the zig `just setup toolchain`
installed; set `MVM_EMBED_ZIG=/path/to/zig` to use another binary.

On macOS, `just build embed` replaces any globally configured compiler-cache
wrapper with `scripts/rustc-macos-loader.sh` for that build. Cargo constructs
a new dynamic-library search path before invoking rustc, so the wrapper
restores the pinned Rust sysroot's `lib/` directory through
`DYLD_FALLBACK_LIBRARY_PATH` at the compiler boundary; ordinary builds keep
their configured wrapper. Some nightly distributions give `rust-objcopy` an
incorrect RPATH, and without the repair cargo-zigbuild repeatedly warns that
`libLLVM.dylib` is missing and embeds larger, unstripped binaries even though
the library exists. Cargo may replay warning text cached by compilation units
built before the repair; a new warning carries a new `dyld[PID]` and means the
current strip step still failed.

For live development, `bin/dev <command>` builds the `dev`-feature CLI and native
host helpers together before running it, with state isolated to the checkout
(and selected image checkout). Launch commands deliberately do not compile
missing host helpers, so the wrapper prepares them instead. It does not embed
the Linux builder payload; use `just build embed` when you explicitly want the full
embedded build ready before running a command (set
`MVM_EMBED_FEATURES=embed-host-bins,dev` for the same contributor surface).
Keep the same target directory and feature selection for repeated edits to
reuse Cargo artifacts.

> **Note — how the builder VM gets them.** The builder image does not have to
> carry `mvm-host-vm-init` or `mvm-builderd`. Every builder boot, on every
> backend, hands the guest a small initramfs — the *builder boot payload* —
> assembled from the running `mvmctl`'s own copies, and the guest runs those.
> An edit to either binary therefore reaches the builder at its next boot,
> after a rebuild of `mvmctl`, without a new builder image. The image and the
> payload agree on a versioned *builder boot ABI*, declared in the image's
> `/etc/mvm/builder-boot-abi`; ADR-004 records what each version promises.

> **Note — after a toolchain-version change.** `rust-toolchain.toml` pins an
> exact Rust version, and rustup keys installed cross-targets per toolchain
> *name*. When that pin changes (a version bump), rustup resolves a fresh
> toolchain that carries none of the Linux cross-targets, so `just check linux`
> or an `mvmctl` build fails with `error[E0463]: can't find crate for core …
> target may not be installed`. Re-run `just setup toolchain` to reinstall the
> targets for the new toolchain.

Or run the bootstrap script on a fresh machine:

```bash
./nix/ops/bootstrap/dev-setup.sh
```

### Guest runtime pieces from a source checkout

A source build assembles the runtime overlay, the universal initramfs and
both SDK sidecars on the host from one guest-runtime archive built from this
checkout (`mvm_build::runtime_pieces::assemble_runtime_pieces`), with no
`mvm-images` checkout and no builder VM. `mvmctl bootstrap` prewarms all four
that way whatever `MVM_RUNTIME_OVERLAY_ACQUIRE_MODE` says; the selector still
decides how the OCI guest runtime is keyed (by source under `build`, by
version otherwise) and opts bootstrap into source-built host helpers, which an
unreleased version needs. `mvmctl dev runtime-overlay build` assembles the
overlay from the same archive. Each assembled piece records its archive
digest in a file beside it (`ARCHIVE_ORIGIN_FILE`), and the `guest runtime`
line of `mvmctl doctor` names, per piece, the archive it came from and whether
it is this tree's or this release's.

After changing the guest-facing C ABI in `crates/mvm-host-services`, refresh
the sidecars explicitly:

```sh
./target/debug/mvmctl dev sdk-sidecar build
```

It packs both libc variants from this checkout's guest-runtime archive
(`pack_sdk_sidecars`), building the archive first if it is not cached. Each
variant is stamped with the cdylib source fingerprint a launch compares
against this checkout and with the digest of the archive it was packed from.
The image carries no loader and no `libc.so.6`; the workload process that
loads the library already has one. Outside a source checkout, `auto` packs
them from the published guest runtime of this version; there is no
`--source download`, because the image set carries no sidecar. A launch only
resolves prepared sidecars, so a stale or missing one is a warning or a
refusal naming this verb or `mvmctl bootstrap`, never an implicit rebuild.

## Building and Running

```bash
# Build
just build

# Prepare published runtime/image artifacts and the signed host helpers built
# for this exact clean source commit.
just run -- bootstrap
just run -- image pull alpine
just run -- pool warm 1 --image alpine

# Run CLI
just run -- --help

# Boot a prepared throwaway workload without compiling or downloading.
just run -- machine run --image alpine -- uname -a

# Release build (stripped, LTO)
just build release
```

CI publishes signed host-helper bundles for each `main` commit in the prerelease
`source-builds-` followed by its full 40-character commit SHA. A clean checkout
downloads that exact bundle during bootstrap. Only an archive HTTP 404 triggers
a lookup in the preserved legacy `source-builds` release; signature, authorization
and network failures never trigger fallback. Both locations require the same
source-workflow signature and matching `SOURCE_COMMIT` before installation. Dirty
checkouts and commits not yet published from `main` have no remote artifact by
construction; explicitly opt into local compilation with
`MVM_RUNTIME_OVERLAY_ACQUIRE_MODE=build mvmctl bootstrap`.

Already-built binaries that still use the legacy URL do not discover the new
tags automatically. If matching signed artifacts actually exist in a per-commit
release, select that exact base explicitly:

```bash
commit=$(git rev-parse HEAD)
MVM_SOURCE_HELPER_BASE_URL="https://github.com/tinylabscom/mvm/releases/download/source-builds-${commit}" mvmctl bootstrap
```

The binary must have been built cleanly from that same commit, and the base must
contain both its platform archive and matching `.bundle`. This override does not
bypass verification and makes no implicit probes of other locations. It cannot
recover an unpublished commit: for example, commit
`8be5cece93ccc01d0cfc4a8759d9dc2df146db91` had no published helpers when the
legacy release filled. Use the explicit local build mode above, or request a
separately authorized historical backfill. Rerunning that commit's frozen old
workflow still targets the full legacy release and is not a migration.

For an operator-approved backfill, dispatch **Source host helpers** on `main`
with `source_sha` set to the full lowercase source commit. The workflow rejects
non-`main` refs and sources that are not ancestors of its own immutable workflow
commit. An empty input retains the normal current-commit build.

Build tooling, signing and publication use the workflow revision, while a
separate checkout supplies the exact historical helper source. Archive names,
`SOURCE_COMMIT` and the destination `source-builds-<commit>` tag all use the
validated source SHA. Build jobs have read-only repository permissions and no
signing token. The publisher preserves existing complete archive/signature
pairs and refuses partial pairs; never delete assets or rerun with clobbering
to repair a partial release.

Before dispatch, obtain approval for the source SHA, exact workflow revision,
destination tag, three platform archives and their three `.bundle` signatures,
and the verification procedure. Afterwards, check that the tag resolves to the
source commit, the release is a non-latest prerelease, all six assets exist,
and each archive verifies against the source-workflow identity on `main` with
the matching `SOURCE_COMMIT`. Then test the explicit-base recovery command
above with a clean binary built from that historical commit in isolated state.
Neither a successful workflow run nor manual archive extraction proves that
bootstrap installation and repeat bootstrap work.

Source guest-runtime caches are keyed by the source fingerprint, version and
guest architecture. On a miss in an isolated `MVM_HOME`, the resolver can copy
a matching runtime from the default home cache, verifying its archive, member
digests and executable modes before publishing the isolated copy. It never
shares Cargo output, keys or VM state between homes.

The live BDD harness (`just e2e live-ci`) prewarms this source runtime once in
the suite's cache (`MVM_E2E_HOME/cache` when configured, otherwise the invoking
process's mvm cache). Scenario-declared isolated homes still take precedence
over the warm home; the harness seeds only a verified runtime archive into
those homes before live commands.
This avoids recompiling guest binaries for every scenario without relaxing
home isolation or increasing the lane timeout.

### Kernel builds

The builder-VM and workload microVM kernels are slim custom Linux
builds: one shared config plus a per-variant delta (the workload kernel
adds dm-verity; the builder kernel adds the nix-build sandbox and
egress-lockdown bits). The kernel flake lives in `mvm-images`, not in this
repository, so a compile needs a selected or sibling `mvm-images` checkout.
Because the config is
custom, `cache.nixos.org` has no substitute, so the first build on a
fresh machine compiles the kernel from source. It can take several minutes
depending on the host and is memory-heavy; later builds reuse the persistent
Nix store.

`mvmctl dev kernel build` makes that compile explicit and one-time. Image
backed runs from a source checkout also bootstrap this kernel automatically;
prebuilding it is useful when you want the first interactive run to be warm:

```bash
# Compile the builder kernel once into the cache + persistent nix store.
# The next build reuses it (substituted, not rebuilt).
just run -- dev kernel build --which builder

# Or both kernels:
just run -- dev kernel build --all

# The same policy applies to the direct kernel recipe:
MVM_KERNEL_SOURCE=download just build kernel
```

To skip the kernel compile entirely on a fresh machine, boot the builder
VM on a published kernel (once a release has shipped one):

```bash
# Build only the rootfs locally; fetch + hash-verify the kernel.
just run -- --kernel-source download bootstrap
# `auto` downloads if available, else compiles in-image (the default).
```

Notes:

- **Host-arch only for `--source compile`.** Stage 0 builds your host's
  architecture (aarch64 *or* x86_64).
  The other arch is published in the signed `mvm-images` image set,
  which builds both — fetch it with `--source download`.
- Editing `kernel/base.nix` or a variant delta in your `mvm-images` checkout? Just re-run the command — a
  custom config always compiles locally; downloads only ever return the
  kernel that shipped with that exact `mvmctl` release.

#### Iterating on the kernel config (slimming, adding a driver)

Changing `kernel/base.nix` / `workload.nix` / `builder.nix` in `mvm-images` and want to see the
effect? The loop is build → boot-smoke → measure:

```bash
# 1. Build the variant you touched (compiles your edited config in Stage 0).
just run -- dev kernel build --which workload

# 2. Boot-smoke it — a kernel that builds isn't proof it boots. Boot a
#    throwaway VM and confirm the in-guest agent answers over vsock.
just run -- machine run --flake examples/sleeper --hypervisor libkrun --name smoke -d
just run -- machine boot-report smoke   # "control plane  ready" == good
just run -- machine stop smoke
```

Two sharp edges worth knowing:

- **A build that passes the config guard still has to boot.** After
  `make olddefconfig`, the build asserts every requested `enable` is
  still `=y` and fails loudly if one got dropped by a missing
  dependency — but that guard can't tell you a *disable* removed
  something the boot path needed. Only the boot-smoke proves that, so
  never skip step 2.
- **`enable` and `disable` are scoped.** A disable in the shared
  `base.nix` hits *both* kernels; if only the workload should drop a
  symbol (or only the builder needs one), put it in that variant's
  delta. (The builder kernel, for example, keeps netfilter for its
  egress lockdown while the workload drops it.)
- **Reading the resolved `.config`.** Stage 0 hands the host a `vmlinux`,
  not the config. In the `mvm-images` checkout,
  `nix build .#workload-configfile` (see `kernel/README.md` there) produces
  it; the `=y` count and size metrics are produced by that repository's
  kernel build, not by this one.

## Testing

```bash
# Run all tests with nextest
just test

# Test a single crate
just test scoped mvm-core

# Run tests matching a filter
just test "test_snapshot"

# Full CI gate (lint + test)
just ci
```

### Test Organization

| Location | Type | What it tests |
|----------|------|---------------|
| `crates/*/src/**/*.rs` (`#[cfg(test)]`) | Unit tests | Internal functions within the crate |
| `crates/*/tests/*.rs` | Integration tests | Public API of each crate |
| `tests/cli.rs` | Binary tests | CLI arg parsing, help output, subcommand structure |

### Testing Conventions

- Unit tests go in `#[cfg(test)] mod tests {}` at the bottom of the source file
- CLI binary tests go in root `tests/cli.rs`
- Use `#[serde(default)]` when adding fields to structs used in test fixtures

### Hermetic lifecycle tests

Every state-changing verb emits exactly one local audit record per attempt,
including its no-op and failure branches, and `tests/audit_emissions_live.rs`
witnesses that without KVM, Nix, libkrun, GitHub or `sudo`. Each test runs the
compiled `mvmctl` as a subprocess with `MVM_HOME` and `HOME` in a per-test
temporary directory, because the audit emitter resolves its path from the
environment at call time; a subprocess gets its own environment and keeps
tests parallel. Each verb family reaches a hermetic stand-in instead of its
real substrate:

| Verbs | Stand-in |
|-------|----------|
| start, stop, TTL | `--hypervisor mock`, the in-memory `MockBackend` in `crates/mvm-runtime/src/mock.rs` |
| pause, resume | `CannedIO` behind the `SnapshotIO` trait in `crates/mvm-vmm/src/snapshot.rs` |
| guest filesystem and process RPCs | `MockGuestAgent` in `crates/mvm-runtime/src/mock_guest_agent.rs` |
| self-update | `MVM_UPDATE_API_URL` pointed at a loopback HTTP fixture |
| `env uninstall` | a versioned install staged inside the test's sandbox, so the developer's own install is never touched |

The mock backend exists only under the `test-support` feature, so a shipped
`mvmctl` never carries it. Nothing checks a stand-in against its real
counterpart beyond review, so keep each one honest when the real path changes.
This covers the per-attempt local audit stream, not the chain-signed plan
audit, which has its own tests.

### Gated E2E

The `MVM_E2E_SMOKE=1` gate covers `crates/mvm-sdk/sdks/python/tests/test_sandbox_exec.py`, which exercises `Sandbox.exec(*argv) -> ExecResult` against a real microVM. Default-skips on `pytest`; opt-in with `MVM_E2E_SMOKE=1 python -m pytest crates/mvm-sdk/sdks/python/tests/test_sandbox_exec.py`.

### Running on the shared KVM box

The self-hosted Linux KVM runner is one persistent machine that CI and
contributors share, and nothing on it is cleaned up between sessions. Work by
hand only inside a private `/srv/mvm/<name>` directory, with the checkout,
`CARGO_TARGET_DIR`, `MVM_HOME` and `TMPDIR` all under it. Before you finish,
stop every VM and process you started, by PID, and delete that directory.

A CI job that can run there must end with an `if: always()` step running
`nix/ops/hetzner/job-cleanup.sh`, which kills by PID whatever the job started
and removes its isolated home, state and temporary directories;
`tests/github_actions_self_hosted_runner.rs` fails the build if a job lacks
it. An hourly sweep on the box removes stale temporary directories that both
miss. `nix/ops/hetzner/README.md` has the details and the install steps.

## Targeted test feedback

Source `scripts/dev-env.sh` once in each worktree shell, then select the target
that owns the failure. Filtering test names alone still compiles the crate's
other integration targets; `--lib` and `--test` avoid that work:

```bash
source scripts/dev-env.sh
just test scoped mvm-cli roundtrip --lib
just test scoped mvmctl "" --test workspace_shard_isolation
```

Omitting the target flags preserves the existing whole-crate selection. The
command propagates nextest failures and keeps the pinned fast toolchain and
worktree-isolated target directory. This is the edit/test loop, not a replacement
for the final workspace tests, clippy and applicable Linux/BDD checks.

Cargo unifies features per invocation, and `-p <crate>` selects a smaller set
than `--workspace` (for instance `manifest-verify`, `test-support` and `addons`
are off for `mvm-cli`). Alternating the two in one target directory therefore
rebuilds about twenty workspace crates each time: 4 min 34 s on an Apple
Silicon laptop and 2 min 04 s on a 12-core Linux host in a measured run. Stay on
one selection style per worktree target directory, or point the other at its own
`CARGO_TARGET_DIR`.

For compile-time diagnosis, measure the same target and features each time:

```bash
cargo build --locked -p mvmctl --features dev --timings
CARGO_LOG=cargo::core::compiler::fingerprint=info cargo build --locked -p mvmctl --features dev
```

The HTML report is under `$CARGO_TARGET_DIR/cargo-timings/`; the second
command explains why Cargo considers a unit stale. Separate an empty-target
build, an unchanged build, and a one-file edit. Do not use `release-min` for
the edit/run loop: its size-oriented LTO is a shipping cost. Development
builds optimize concrete AES-GCM operations in `mvm-crypto::aead`, not all of
`mvm-core`, preserving encrypted I/O throughput without optimizing every
core module. Dev and test use the same Cargo codegen defaults, allowing fewer
units for non-incremental dependencies than for incremental workspace crates
without introducing a test-only profile mismatch.
Feature differences can still cause rebuilds. The two-job default limits
contention between worktrees; raising it on a host already running many builds
can make turnaround worse.

Ordinary workspace tests do not compile Cucumber. The existing `bdd` feature
enables both the conformance runner and its framework dependency; use
`just test bdd` for that suite. The conformance library's unit tests and
documentation-example checks remain part of ordinary workspace validation.

## Profiling

Functions carrying `#[instrument]` are timed when `MVM_SPAN_TIMINGS` is set.
Profiling is off otherwise — the timing layer is not installed at all.

```bash
MVM_SPAN_TIMINGS=1 mvmctl <command>              # table to stderr
MVM_SPAN_TIMINGS=json mvmctl <command>           # JSON to stderr
MVM_SPAN_TIMINGS=json MVM_SPAN_TIMINGS_OUT=/tmp/p.json mvmctl <command>
MVM_SPAN_TIMINGS=1 MVM_SPAN_TIMINGS_FILTER=mvm_fs=trace mvmctl <command>
```

The report is sorted by **self time** — time inside the function excluding
nested instrumented calls — which is the column that identifies what to
optimize. A row with high `total` but low `self` is an orchestrator whose cost
lives in a callee. `wall` above `total` means the span was open but not
entered; on async code that gap is time spent awaiting something else.

Percentiles come from a fixed-memory log-scale histogram and carry ~12% bucket
error. They are a profiling signal, not an SLO measurement.

Span timing is independent of `-v`: spans are measured even at the default
quiet log filter. To add a new measurement point, put `#[instrument(skip_all)]`
on the function. Prefer coarse entry points — recording takes a process-wide
lock on span close, so instrumenting a per-item inner loop distorts the
measurement it is meant to produce. Measured cost, debug build: 12 ns/span with
profiling off, ~4 us/span with it on, and aggregate throughput rises rather
than falls under contention (`cargo test -p mvm-core --test
span_timing_overhead -- --nocapture`).

When profiling is enabled, the served metrics endpoint also carries
`mvm_span_calls_total`, `mvm_span_self_seconds_total`,
`mvm_span_total_seconds_total`, and `mvm_span_max_seconds`, each labelled with
`target` and `span`. Nothing is exported when profiling is off. This is the
scrape endpoint only, not `mvmctl ops metrics`: a profile accumulates in the
process that ran the instrumented code, and a short-lived CLI invocation
renders its output before doing any work, so those series would always be
empty there.

To diff two runs rather than read two tables, `bench::span_profile` captures a
profile from a child `mvmctl` and compares them. It gates on **per-call** self
time, so a run with more iterations does not read as a regression, and reports
call-count changes separately — a function called twice as often is a different
defect from one that got slower.

### Exporting traces to a collector

`mvmctl` can send its spans to any OpenTelemetry collector over OTLP/HTTP with
JSON encoding. Export is off unless an endpoint is set, and it reads the
standard OpenTelemetry variables, so an existing collector setup applies as is:

```bash
# Local collector listening on the default OTLP/HTTP port.
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318 mvmctl <command>

# Hosted collector with an API key; header values are percent-encoded.
OTEL_EXPORTER_OTLP_ENDPOINT=https://otlp.example.com \
OTEL_EXPORTER_OTLP_HEADERS='authorization=Bearer%20<token>' \
mvmctl <command>
```

| Variable | Meaning | Default |
| --- | --- | --- |
| `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` | Full traces URL, used exactly as given | unset |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Base URL; `/v1/traces` is appended | unset |
| `OTEL_EXPORTER_OTLP_HEADERS` | `name=value` pairs, comma-separated | none |
| `OTEL_EXPORTER_OTLP_TIMEOUT` | Per-request timeout in milliseconds | `10000` |
| `OTEL_SERVICE_NAME` | `service.name` resource attribute | the executable name |
| `MVM_OTLP_FILTER` | Which spans are exported, as a `tracing` filter | `info` |

`https://` endpoints are accepted anywhere. `http://` is accepted only for a
loopback host (`localhost`, `127.0.0.0/8`, `::1`), so span contents and any
credential in the headers never cross a network unencrypted; any other
`http://` endpoint, or a malformed header, prints one line on stderr and leaves
export off without affecting the command. An endpoint that embeds a username or
password is refused the same way: put credentials in
`OTEL_EXPORTER_OTLP_HEADERS`, whose values are never printed.

Like span timing, export has its own filter and is independent of `-v`. Spans
are sent in batches from a background thread through a bounded queue: a slow or
unreachable collector costs dropped spans while the command runs. A failed
batch is dropped, not retried, and only the first failure is reported. As the
command returns, queued spans are flushed, waiting at most the export timeout,
so an unreachable collector can add up to that timeout to the command's exit.
Lower `OTEL_EXPORTER_OTLP_TIMEOUT` if that matters more than the last spans.
The same flush runs when a command ends early, such as one that exits with a
guest's exit code: `mvmctl` leaves through a helper that flushes first, bounded
by the same timeout. After Ctrl-C the wait is capped at about one second, so an
interrupted command returns the prompt promptly and keeps only the spans that
could be sent in that time.

Exported spans carry the fields `tracing` records on them, the same data the
logs carry at the matching level. A trace is a diagnostic view: the
chain-signed audit log remains the record of what ran.

Only the host-side `mvmctl` process exports. Nothing is exported from inside a
microVM, and the per-VM supervisors and host daemons do not export yet. A trace
is an analysis aid; the chain-signed audit log remains the record of what ran.

## Discovering development commands

Run `just` to list the recipes. There is one per job — `build`, `check`,
`test`, `lint`, `fmt`, `ci`, `run`, `e2e`, `docs`, `release`, `clean`,
`setup`, `mem` — and a variant is the recipe's first argument:
`just check gated`, `just test scoped mvm-core`, `just lint clippy`. The
comment above each recipe in the `Justfile` describes its variants.

`e2e`, `docs`, `setup` and `mem` only make sense with a variant, so run bare
they print their variants and do nothing else: `just docs` prints the usage,
`just docs dev` starts the preview server and `just docs build` builds the site.

## Linting and Formatting

```bash
just fmt          # Format all code
just lint clippy  # Lint (zero warnings required)
just lint         # Both format check + clippy
```

### Style Rules

- **Edition 2024**: `use` statements don't need `extern crate`; let chains supported
- **No `clippy::too_many_arguments`**: never suppress this lint — refactor into a params struct
- **No `format!()` in `format!()` named args**: extract to a variable first
- **Cross-crate imports**: always use `mvm_core::`, `mvm_runtime::`, etc.

### Rules are gates, not review conventions

A code-quality rule that lives only in review drifts, so each one is a check
that fails a PR by name:

- **Workspace clippy lints** in the root `Cargo.toml`
  (`[workspace.lints.clippy]`): `too_many_arguments`, `await_holding_lock`,
  `await_holding_refcell_ref` and `undocumented_unsafe_blocks` are `deny`. The
  only `too_many_arguments` suppression is bindgen output in
  `crates/deps/libkrun-sys/src/sys.rs`.
- **`unsafe` is scoped, not banned.** Crates that parse untrusted bytes or
  carry the contract deny or forbid it at the crate root (`mvm-fs`,
  `mvm-core`, `mvm-contract`, `mvm-crypto`, among others); FFI and ioctl code
  uses it in small documented blocks.
- **Architecture invariants are `xtask` checks**, one module per rule under
  `xtask/src/check_*.rs`, run through `cargo run -p xtask -- check-all`. A new
  rule is a new check, not a line in a shared config.
- **Exactly two root feature surfaces.** Product behaviour folds into `host`
  (what the host runs) or `user` (what a user runs); `dev` is their union and
  `default` a lean subset. Every other root feature must be on the internal or
  build-only allowlist in `xtask/src/check_two_surfaces.rs`, so adding one
  forces the choice in that PR: fold it into a surface or justify the
  allowlist entry. The rule governs the root `[features]` table only, not what
  a library crate gates internally.

## Architecture Principles

### Multi-Backend

mvmctl's supported local microVM hosts are native Linux with `/dev/kvm` and Apple Silicon running macOS 26+. Firecracker is the Linux workload baseline and native HVF covers supported Macs without libkrun. WSL2 nested KVM and a Hyper-V managed Linux builder are future backend work.

### Host vs. VM

All Linux build operations run inside the builder VM on macOS:

```rust
// On Linux this runs directly on the host; on supported macOS hosts it
// routes into the libkrun-backed builder VM.
mvm_runtime::shell::run_in_vm("ip link add br-tenant-1 type bridge")?;
```

On native Linux, `run_in_vm` executes directly on the host. On supported macOS Apple Silicon hosts, it delegates into the builder VM.

### Key Patterns

- **Idempotent operations**: every setup step checks if already done before acting
- **Config drive for metadata**: instance metadata delivered via read-only ext4 disk
- **Vsock, not SSH**: guest communication uses vsock directly on all supported backends
- **Same rootfs everywhere**: Nix-built ext4 images work on all backends

### Adding New Types

When adding fields to structs in serialized state:

1. Add `#[serde(default)]` to the new field for backward compatibility
2. `cargo test --workspace` to find all broken test constructions
3. Fix each one
4. Add a unit test for the new behavior

## Developer Workflow Commands

Beyond the standard build/test/lint cycle, mvmctl provides commands for managing the dev environment:

```bash
# First-time host setup (installs deps, stages the builder VM image)
just run -- bootstrap
# `init` is a different verb: it scaffolds mvm.toml + flake.nix in a project dir
just run -- init ./my-app

# Bundled image catalog — browse the entries `init --catalog` can scaffold from
just run -- catalog list            # browse bundled catalog
just run -- catalog search http     # search by name/tag
just run -- catalog info minimal    # show one entry
# (`mvmctl image` is a different namespace: pull/ls/inspect/rm of cached OCI images.)

# Named dev networks
just run -- network create isolated # create a named network
just run -- network list            # list all networks
just run -- machine run --flake .  # attach VM to a network

# Interactive console (PTY-over-vsock, no SSH) — `console` lives under `machine`
just run -- machine console myvm            # interactive shell
just run -- machine console myvm --command "uname -a"  # one-shot exec

# Cache and diagnostics
just run -- cache info              # show cache dir and disk usage
just run -- cache prune             # clean stale temp files
just run -- doctor                  # dependency checks + security posture
# There is no `security` verb — plan 40 folded it into `doctor`.
```

### Console Access

microVMs have no SSH. Interactive access is via `mvmctl machine console` which uses PTY-over-vsock:
- Authenticated via the existing Ed25519 vsock protocol
- Dev-mode only (`access.console` must be `true` in the guest security policy)
- Single session per VM, 15-minute idle timeout
- Supports Firecracker, libkrun, and HVF backends

### Directory Layout

All dev tool state lives under one root, `~/.mvm` (relocate the whole tree
with `MVM_HOME`; `rm -rf ~/.mvm` removes every trace):

| Path | Purpose |
|------|---------|
| `~/.mvm/` | Data: keys, audit chains, volumes, bundles, machine specs |
| `~/.mvm/vms/` | Per-VM state: sockets, pid files, console logs, FC workspace |
| `~/.mvm/cache/` | Build artifacts, images, VM runtime state |
| `~/.mvm/config/` | User config (`config.toml`) |
| `~/.mvm/run/` | Ephemeral per-session state |
| `~/.mvm/state/` | Logs, audit trail |
| `~/.mvm/share/` | Templates, network definitions, VM name registry |

## CI/CD

| Workflow | Trigger | What it does |
|----------|---------|--------------|
| `ci.yml` | PRs, push to main, manual dispatch | Scoped fast gate: formatting, clippy, policy checks, workspace test compilation and sharded tests, Windows portability checks, and static documentation checks; required verdict is `Test` |
| `ci.yml` (merge queue) | Merge group | `Lint core` and `Build workspace tests` for code changes (formatting, clippy and a compile of every test target against latest main), plus `Docs static` for documentation changes; other validation lanes passed on the PR head and run again on push to main |
| `merge-queue-watch.yml` | Merge-group CI completion, every fifteen minutes, manual dispatch | Re-runs a failed merge-group CI once only when it scheduled zero jobs; opens or updates a `Merge queue stalled` issue if the queue head has waited over 30 minutes |
| `ci-main.yml` | Push to main, manual dispatch | The slow lanes (feature suites, BDD, aarch64, release-profile and musl witnesses, eBPF, Linux coverage, Nix evaluation, boot ceiling), gated by `Test (main)`; a pull request and the merge queue never list them |
| `release.yml` | Tags matching `v*` | Builds 3 platform binaries (`aarch64-apple-darwin`, `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`), creates GitHub Release |
| `publish-crates.yml` | Manual dispatch with a tag (dry run by default); pull requests that change the publish machinery run the dry run | Publishes the public crate (`mvm-contract`) to crates.io; every other crate is `publish = false` |
| `workers.yml` | Website change merged to main, release, version tag, or manual dispatch | Deploys docs to Cloudflare Workers Static Assets |

Two rules keep that split honest:

- **Every `ci.yml` lane is a dependency of the `Test` aggregate and is
  checked in its result step.** A lane named by neither spends runner time
  and gates nothing: its failure cannot block a merge.
- **No `security.yml` lane gates a merge.** Those lanes run on release tags,
  nightly and on dispatch, never on a pull request or in the merge queue, so a
  claim witness can go red while the change that broke it lands green. The
  enforcement is `security-lane-watch.yml`, which opens or updates one
  tracking issue, and the release-tag run before anything ships.
  `cargo-deny` and `cargo-audit` are the exception: `ci.yml` calls
  `supply-chain.yml` when a pull request changes dependencies. Moving the
  cheap claim lanes onto pull requests would add runner cost but little
  wall-clock time; that trade is a maintainer's decision and is not taken.

The `main merge queue` ruleset allows 40 minutes for checks (longer than the
expected 25-minute worst case). The watchdog never retries a CI run with a
failed job or changes queue membership. Investigate and close its tracking
issue after recovery; a GitHub Actions outage can delay the watchdog too.

The SDK publishing workflows retain the raw `npm-dist` tarballs and
`pypi-dist-*` wheels for 30 days, including dry runs. Download them from the
same workflow run when reviewing package contents, license notices, and native
library provenance; smoke reports alone are not package-content evidence.
Missing distribution files fail the artifact upload. This retention window
does not replace published release assets or a permanent evidence archive.

### Reproducing a CI lane locally

`just ci` runs `just lint` (fmt, clippy, clippy with `bdd`, the model gates,
`xtask check-all`, the toolchain pin), the nextest suite, doctests and the
hermetic BDD run. `xtask check-all` is the same driver the `lint-policy` job
runs; it is the gate list, and a unit test in `xtask/src/check_all.rs` fails
when a workflow runs a gate `xtask` does not dispatch, or when a gate is left
out of `check-all` without a recorded reason.

| Coverage | Owning job | Local command |
|----------|------------|---------------|
| Policy gates | `ci.yml` `lint-policy` | `just lint policy` |
| Gates outside `check-all` | `ci.yml` (`check-declared-backing`), `ci-main.yml` (`check-nextest-groups`), `release.yml` (`check-binary-size`), `claim-witness-freshness.yml`, `e2e-docs.yml` (`check-release-evidence`) | `cargo run -p xtask -- <gate>` |
| aarch64 tests | `ci-main.yml` `test-workspace-aarch64` (native runner) | `cargo nextest run --workspace --exclude mvm-fs --all-targets` on an aarch64 Linux host |
| wasm32 / no_std `mvm-contract` | `ci-main.yml` `test-linux`, via `scripts/ci-linux-coverage.sh` | `just check embedded` for the riscv32 build; the wasm32 build and wasmtime test steps are in the script |
| Windows portability | `ci.yml` `lint-windows` | `cargo check --target x86_64-pc-windows-gnu -p mvm-contract -p mvm-core -p mvm-vmm` |
| Fuzz targets compile | `ci.yml` `lint-policy` (when a manifest or fuzz dir changes) | `cargo check --locked --manifest-path crates/<crate>/fuzz/Cargo.toml --all-targets` |
| Fuzz runs | `security.yml` `fuzz` (nightly, tags) | `just test fuzz fuzz_guest_request`, or `cargo +nightly fuzz run <target>` in the fuzz directory |
| eBPF telemetry | `ci-main.yml` `test-ebpf-telemetry` | `just check ebpf`, then `cargo test -p mvm-hostd --features ebpf-telemetry --lib` |
| Supply chain | `security.yml` `cargo-deny`, `cargo-audit` (nightly, tags) | `just lint supply-chain` |
| Release build | `release.yml` `build` | `just build release` |
| Linux-gated and feature-gated type checks | `ci.yml` `test-workspace-build` | `just check gated` |

The pre-commit hook runs fmt and scoped clippy only; everything above is a
manual or CI step.

### Static documentation gate

`Docs static` runs on pull requests and merge groups touching `README.md`,
`AGENTS.md`, `public/src/content/docs/`, `crates/mvm-sdk/sdks/`, or `examples/`.
It also runs on pushes to main and manual dispatches. A failed or cancelled
lane fails the required `Test` aggregate. The docs scope does not enable the
compiler/test matrix; the existing code scope applies independently, including
to root README/instruction files, SDK sources, examples, and selected pages
read by Rust tests.

The lane runs three existing source-only checks:

```bash
cargo run -p xtask -- check-cli-help-matches-docs
cargo run -p xtask -- check-doc-links
cargo run -p xtask -- check-doc-claims
```

This is a static smoke gate, not execution of the documentation corpus.
The CLI check compares top-level command declarations with the CLI reference,
not every flag or example. The link check resolves repository and internal-site
links in the published docs, not external URLs. The claims check scans the
published docs and root README for its configured overclaim phrases. Selecting
the full corpus as a trigger does not extend those checks to every file in it.
The lane builds xtask, not the CLI or language SDKs, and does not parse or run
every documented configuration or command.

Authoritative executable documented-example coverage remains the
`bdd-conformance` lane in `ci-main.yml`, unscoped on every push to main and
manual dispatch. BDD stays postmerge: failures there require a fix-forward;
passing `Docs static` does not prove the examples execute successfully.

### Website deployment

Run the site commands from the repository root through the `public` workspace:

```bash
pnpm --dir public install --frozen-lockfile
pnpm --dir public check
pnpm --dir public deploy
```

`pnpm --dir public deploy` builds the Astro site and publishes it to the `mvm`
Worker with Static Assets. Use `pnpm --dir public deploy:preview` to upload a
previewable Worker version without changing production traffic.

Website changes under `public/`, `web/mvm-demo/`, or `web/mvm-demo-guest/`
also deploy automatically after they merge to `main`. Pull requests build and
validate the site without publishing it.

The checked-in `public/wrangler.toml` is the deployment contract. It keeps
static assets on Cloudflare's asset-serving path by default; do not add a
Worker entry point or `assets.run_worker_first` unless every request genuinely
needs code execution.

## Release Process

```bash
# 1. Bump version in root Cargo.toml [workspace.package]
# 2. Update CHANGELOG.md
# 3. Commit and tag
git add -A && git commit -m "release: v0.3.0"
git tag v0.3.0

# 4. Push (triggers release.yml)
git push && git push --tags
```

The deploy guard (`scripts/deploy-guard.sh`) validates the tag matches the workspace version before publishing.
