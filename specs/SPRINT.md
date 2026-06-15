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

## Current Status (v0.16.1)

> This file is a **cumulative multi-sprint log** — it opened at Sprint 42
> (immediately below) and has grown through **Sprint 62**. Recent active work:
> Sprint 60 (core demo green, in flight), Sprint 61 (app-builder surface,
> proposed), Sprint 62 (ADR-080 wasm preview → microVM ship, in flight). Read a
> given sprint's own section for its live status; the table below is the current
> workspace snapshot, not Sprint 42's.

| Metric           | Value                                  |
| ---------------- | -------------------------------------- |
| Version          | v0.16.1                                |
| Workspace crates | 15 (ADR-066 §1; Plan 121 folded 32→15) |
| Total tests      | ~4,350 (`cargo nextest`)               |
| Clippy warnings  | 0                                      |
| Edition          | 2024 (Rust 1.85+)                      |
| MSRV             | 1.85                                   |
| Binary           | `mvmctl`                               |

## Planning updates

- [x] **Implemented + dual-host-validated** [`plans/198-host-side-flake-build-cache.md`](plans/198-host-side-flake-build-cache.md) — host-side workload-flake build cache. `mvmctl up --flake` / `build image` re-ran `nix build` in a builder VM on every call, rediscovering the cache hit only after the full eval (the cache key, the nix revision, is only knowable post-eval). `crates/mvm-build/src/pipeline/build_cache.rs` fingerprints every nix input host-side (user-flake tree + the filtered workspace tree that covers `path:/work/nix` + the `buildRustPackage` `src` + profile + mode + mvmctl version), drift-guarded so `EXCLUDED_BASENAMES` ⊆ `workspace-filter.nix` (hashing a superset of nix's inputs is sound — bust ≥ as often as nix). `fingerprint → revision` records under `~/.mvm/dev/build-cache/` (atomic, traversal-guarded); `dev_build` short-circuits the builder VM when the record maps to a build dir whose `rootfs.ext4` exists (`MVM_NO_BUILD_CACHE` disables). Secondary: config/secrets drives populate-at-format via `mkfs.ext4 -d` (no loop mount/sudo). **Validated:** warm `up` 30 s → **1.01 s** (x86_64 KVM/Firecracker box, builder skipped) and `build image` 121 s → **1.80 s** (macOS 26 Apple-Silicon, libkrun builder); both bust correctly on a flake edit. Backends proven: qemu (Linux) + libkrun (Mac); the short-circuit fires before builder selection so it's backend-independent. 13 unit tests; `cargo clippy` + nightly fmt clean. `crates/mvm-build` + `crates/mvm-backend`.
- [x] Implemented [`plans/199-host-runtime-packaging-and-crate-boundaries.md`](plans/199-host-runtime-packaging-and-crate-boundaries.md) Workstream A: optional source-built Nix `mvmctl` package, default package, and host overlay now exist without changing the Linux-only `mkGuest` API; tests assert source-checkout Nix packages do not fetch project release binaries and native VMM linkage remains explicit/opt-in. Installation docs keep binary release install as the primary user path and host Nix as optional.
- [ ] Authored and docs-synced [`plans/200-machine-ux-dx-layer.md`](plans/200-machine-ux-dx-layer.md): the beginner product path is `mvmctl machine run/create/start/exec/shell/stop/pack` over existing runtime primitives, with binary-first install, no host-Nix prerequisite for normal use, image-backed one-shot docs before flakes/manifests, explicit network opt-in, persistent named machines, SDK parity, verified portable artifacts, measured hot-start claims, and a strict `mvm.toml` schema v2. The same pass de-duplicates ownership so Plan 200 owns beginner UX, Plan 199 owns install/host packaging, Plan 126/156 own dependency and binary-size mechanics, Plan 155 owns low-level artifact execution, Plan 159/189 stay VZ-specific, Plan 193/197 stay security substrate, and Plan 198 is completed perf input.
- [x] Added [`plans/132-programmable-storage-io.md`](plans/132-programmable-storage-io.md), a security-first plan for typed block request contracts, declared storage transforms, compressed ephemeral volumes, plan-bound storage policy, guest storage status, and a gated Linux-only userspace block-device spike.
- [x] Added [`plans/182-trait-hygiene-and-backend-catalog.md`](plans/182-trait-hygiene-and-backend-catalog.md), a focused cleanup plan to unify duplicate micro-traits (`Clock`, `KeyProvider`), move backend name/tier/marker metadata behind one catalog source, and constrain macro use to a single backend-catalog generator instead of broader trait-impl macros.
- [x] **DONE** — [`plans/184-backend-descriptor-registry.md`](plans/184-backend-descriptor-registry.md) promoted the shipped backend catalog into a first-class compile-time `BackendDescriptor` registry: descriptor-named helpers, dual `instantiate`/`instantiate_dyn` constructors with a dyn↔enum parity test, doctor migrated to `instantiate_dyn`, `AnyBackend` narrowed to genuinely enum-specific operations (no duplication remained), boundary + ordering-freeze tests, and arch/supervisor docs describing the behavior/discovery/dispatch ownership split. `VmBackend` stays the sole behavior trait; the registry is static (no runtime plugins).
- [x] Added [`plans/185-idiomatic-rust-hygiene.md`](plans/185-idiomatic-rust-hygiene.md), a bounded cleanup plan for project-wide Rust idioms: shared test env guards, poisoned-lock policy, clearer internal names, typed selectors at module boundaries, params structs/builders, function splits only where they add testable structure, unsafe/platform/feature-boundary audits, error-shape cleanup, fixture consolidation, secret/debug exposure checks, and Rustdoc verification.
- [x] Started Plan 185 implementation: added `mvm_core::util::test_env::TestEnv` behind `cfg(test)` / `mvm-core/test-support`, covered restore behavior with unit tests, and migrated `mvm-core` keystore env tests away from direct process-global env mutation. Verified with `cargo test -p mvm-core test_env`, `cargo test -p mvm-core keystore`, and `cargo clippy -p mvm-core --all-targets -- -D warnings`.
- [x] Advanced Plan 185 into `mvm-backend`: backend selector/started-VM marker tests now use `TestEnv` and `tempfile::TempDir` instead of manual `HOME`/`MVM_DATA_DIR` save-restore blocks, while keeping the legacy backend env lock until the rest of that crate migrates. Verified with `cargo test -p mvm-backend backend` and `cargo clippy -p mvm-core -p mvm-backend --all-targets -- -D warnings`.
- [x] Advanced Plan 185 test isolation into `mvm-cli` and `mvm-build`: checkpoint/console and dev/Vz builder tests now use `TestEnv`-scoped process env, lifecycle-hook tests use deterministic runner fakes instead of shell timing, and the entrypoint stdout-cap test no longer asserts a host-load-sensitive wall-clock bound. Also fixed detached direct-boot mock `up` to skip the 30s guest-agent wait when no `MVM_PORTS` forwarding is requested. Verified with `cargo test -p mvm-cli --lib direct_boot`, `cargo nextest run --workspace --test audit_emissions_live`, `cargo clippy -p mvm-cli --lib -- -D warnings`, and serial escalated reruns of `mvm-guest` process-heavy targets.
- [x] Completed Plan 185 Phases 1–3 + started Phase 5: Phase 1 `TestEnv` migration finished across mvm-core/mvm-hostd/mvm-build/libkrun-sys/mvm-cli (duplicate local env-test locks deleted; only host-gated mvm-backend env tests remain for CI/Linux); Phase 2 poison-lock policy decided and applied (env serializers folded into `TestEnv`, runtime state locks fail-closed); Phase 3 naming/typed-selectors landed `storage::Backend`→`DeviceMapperBackend` (#892), the two `EgressProxy` traits split by layer into `VmEgressProxy`/`SupervisorEgressProxy` (#894), and typed `BackendKind` selectors over `name()` strings in pool.rs (#895); Phase 5 Task 8 first pass added per-block `SAFETY:` invariants to the 12 simple-syscall mvm-guest blocks (entrypoint/volume/exec_stream/process_rpc/netinit/worker_pool), with the deeper console/verity/objc2 clusters deferred; Phase 5 Task 9 (feature/dep boundaries) closed by verification — `test-support` is dev-only across all six consumers (empty feature def) and the optional heavy stacks (egress-ca/hostd-transport/manifest-verify/schemars/attestation) stay `dep:`-gated + documented, with `cargo tree -e no-dev` tokio-free and `check-core-runtime-free` enforcing it in CI. Verified per-crate clippy (host + `aarch64-unknown-linux-musl` for the Linux-gated guest code) and touched-area tests (773 mvm-hostd supervisor, 14 storage, 14 pool).
- [x] Advanced Plan 185 Phase 5 Task 8 into the deeper unsafe clusters: audited the `mvm-verity-init` PID-1 bin (13 `unsafe` blocks — dm-verity ioctls, `copy_nonoverlapping` payload assembly, mount/chdir/chroot/execv). Every block now carries a verifiable per-block `SAFETY:` invariant; `do_ioctl` gained a `# Safety` doc stating the fd/`data_size` contract. Applied Step 2 to the fixed-payload ioctls — VERSION/DEV_CREATE/DEV_SUSPEND route through a safe `dm_ioctl_fixed(fd, cmd, &mut DmIoctl)` wrapper, with a `const _` assertion pinning `DM_IOCTL_STRUCT_SIZE == size_of::<DmIoctl>()` so the soundness argument is machine-checked; dropped a redundant typed deref that re-set `DM_READONLY_FLAG` through the only-u8-aligned `Vec` pointer (the flag is already set in the payload), leaving one documented raw-pointer ioctl for the variable-length TABLE_LOAD path. Verified `cargo clippy -p mvm-guest --bin mvm-verity-init --target aarch64-unknown-linux-musl --all-features -- -D warnings`, the 12 cmdline-parser unit tests, and nightly `cargo fmt --all -- --check`.
- [x] Advanced Plan 185 Phase 5 Task 8 into `mvm-guest/console.rs`: verified the guest agent is multithreaded by the time it serves a ConsoleOpen request (monitoring, probe, integration, and forward-proxy threads all spawn before the accept loop), so the post-fork child's `putenv` (malloc + global `environ` mutation) and `execvp` were an async-signal-safety violation — a latent allocator-lock deadlock, not a SAFETY-note candidate. Replaced it: the child's environment is now assembled in the parent before `fork()` and handed to `execve` (absolute `/bin/sh`, no PATH search); the pure core `build_shell_env_from` is unit-tested without touching process env. Also gave every unsafe block in the module a concrete fd-ownership / pointer-validity / async-signal-safety SAFETY invariant. Verified host + `aarch64-unknown-linux-musl` clippy, 6 console unit tests (2 new), and nightly `cargo fmt --all -- --check`.
- [x] Finished the in-flight `mvm-guest` clusters of Plan 185 Phase 5 Task 8: the `mvm-guest-agent` bin's four remaining un-annotated `unsafe` blocks (two post-bind `close(fd)` cleanups in the port-forwarder + accept-loop setup, and two test bodies that call the async-signal-safe signal handlers directly) now carry concrete SAFETY invariants. With this, the simple-syscall + console + verity + agent guest clusters are all annotated; only `mvm-vm-host/vz_objc.rs` (objc2 FFI) remains, deliberately held until the Plan-152 vz work is quiet. Verified host + `aarch64-unknown-linux-musl` clippy on the bin, the 5 signal-handler unit tests, and nightly `cargo fmt --all -- --check`.
- [x] Started Plan 185 Phase 4 Task 6 (params structs over long arg lists), anchored on the `#[allow(clippy::too_many_arguments)]` suppressions that CLAUDE.md forbids. Refactored the live `mvm-build::firecracker::boot_builder_vsock` (9 args) into a `BuilderVsockBoot` params struct — destructured by-ref at the top so the body stays byte-identical, removing the suppression; the one caller (the vsock builder backend) builds the struct inline. Audit finding: the `mvm` Firecracker instance/pool lifecycle subtree (`vm/instance/`, `vm/pool/`) is dead code — unwired from `vm/mod.rs` (no `mod instance`/`mod pool`), confirmed with a `compile_error!` probe — so the `fc_config`/`jailer` suppressions there are stale-on-dead and belong to a separate dead-code-removal pass, not a params refactor. The remaining live candidates (`sign_into_headers`, `terminate_and_substitute`) are claim-12 security paths, deferred for careful treatment. Verified `cargo clippy -p mvm-build --lib -- -D warnings` (passes the workspace deny lint without the allow) and nightly `cargo fmt --all -- --check`.
- [x] Finished Plan 185 Phase 4 Task 6 — eliminated every remaining hand-written `#[allow(clippy::too_many_arguments)]`. The two claim-12 security paths became builder structs, bodies byte-for-byte preserved by destructuring the built value at the top: `substitution_proxy::sign_into_headers` → `SignRequest::builder()…build()` (#926), `terminator::tls::terminate_and_substitute` → `TlsTermination::builder()…build()` (#927, with the production `substitution_proxy` call site + two terminator tests updated). Separately, the `compile_error!`-confirmed dead FC instance/pool/tenant lifecycle cluster (`vm/instance/`, `vm/pool/`, `vm/tenant/`, `bridge.rs`, `disk_manager.rs`) was deleted, and `security/jailer.rs` trimmed to its one live `jailer_available()` probe — removing the `launch_jailed` suppression by deletion (#931, ~3.8k lines, zero live code touched). With these the workspace has no hand-written `too_many_arguments` allow left (only bindgen FFI). Verified per-PR `cargo clippy -p mvm-hostd`/`-p mvm`/`-p mvm-cli --all-targets -- -D warnings`, the 85 sign + 66 terminator + 203 `mvm` lib tests, `cargo check --workspace --all-targets`, nightly `cargo fmt --all -- --check`, and the spec-ref/spec-number gates.
- [x] Started Plan 182 implementation: `mvm_core::time::{Clock, SystemClock}` now owns the shared wall-clock seam, replacing the duplicate local `Clock` traits in `mvm-hostd` supervisor aggregate/circuit-breaker code and `mvm-cli` plan admission. Verified with `cargo test -p mvm-core time`, `cargo test -p mvm-hostd circuit_breaker`, `cargo test -p mvm-hostd launch_rejects_expired_plan`, `cargo test -p mvm-cli plan_admission`, and `cargo clippy -p mvm-core -p mvm-hostd -p mvm-cli --all-targets -- -D warnings`.
- [x] Landed Plan 182 Task 2: removed the dead duplicate runtime `KeyProvider` module (`crates/mvm/src/security/keystore.rs`), kept `mvm_core::crypto::keystore` as the sole key-provider surface, and updated the stale overlay docs to point at the core trait. Verified with `cargo test -p mvm-core keystore`, `cargo test -p mvm --no-run`, and `cargo clippy -p mvm-core -p mvm --all-targets -- -D warnings`.
- [x] Advanced Plan 182 backend-catalog wiring: added `crates/mvm-backend/src/catalog.rs` with one `backend_catalog!` metadata table, preserved legacy started-VM marker probe order explicitly, moved `AnyBackend::{from_hypervisor,for_started_vm,tier,list_all}` and doctor's balloon/warm-start backend sets onto that catalog, and froze the visible backend matrix/order with backend + doctor tests. Verified with `cargo test -p mvm-backend backend`, `cargo test -p mvm-cli doctor`, and `cargo clippy -p mvm-backend -p mvm-cli --all-targets -- -D warnings`.
- [x] **Plan 182 CLOSED.** All code/docs landed (via #802); the final `cargo test --workspace` box is closed as documented-environmental — package-by-package + `-E 'not package(mvm-backend)'` are green, and the single-invocation aggregate only SIGKILLs the `mvm-backend` unit-test binary via macOS amfid codesign on this host (not an assertion failure; CI runs the full aggregate green).
- [x] Updated the architecture reference for Plan 182: `public/src/content/docs/reference/architecture.md` now documents the actual workspace crates, the canonical trait seams (`VmBackend`, `BuilderVm`, `BackendLauncher`, `NetworkProvider`, `VolumeBackend`, `ServiceHandler`, `SecretStore`, `KeyProvider`, etc.), the trait ownership rule, and the current builder-VM/runtime-backend split. Also removed stale Lima-era wording in `mvm-core` environment trait comments.
- [x] Finished the remaining Plan 182 code cleanup: the backend catalog macro now also owns `BackendKind`/`AnyBackend` kind+constructor+inner mappings, and a separate `mvm` test flake was fixed by serializing one stray `MVM_DATA_DIR` mutation in `vsock_transport` and making reconcile's test lock poison-tolerant. Verified with `cargo test -p mvm-backend`, `cargo test -p mvm`, `cargo check --workspace`, and `cargo clippy --workspace --all-targets -- -D warnings`. The literal aggregate `cargo test --workspace` still hits a host-side `SIGKILL` in the `mvm-backend` unit binary even though the package-local runs are green.
- [ ] Proposed [`plans/193-rvproxy-network-substrate.md`](plans/193-rvproxy-network-substrate.md): replace the external gvproxy (macOS libkrun-`unixgram` + Vz `vfkit`) and passt (Linux Firecracker) host gateways with the sibling-repo Rust-native `rvproxy` daemon. Cross-repo — requirements authored into `rvproxy/specs/plans/014-mvm-adoption-requirements.md`. Biggest win: rvproxy's native flow-decision/audit API replaces mvm's in-line `gateway_bridge` datapath wrapper (Plan 141 splice+etherparse) that exists only because gvproxy/passt have no flow API; also fixes the per-backend divergence and the gvproxy ERROR-on-builder-VM-poweroff noise (a tracked, gvproxy-unfixable bug). Gated on rvproxy confirming the libkrun-`unixgram` transport. Surfaced 2026-06-12 while validating the Plan 177 cold-build dev-up smoke (which passed: fresh image booted, agent reachable via `dev status --json`, clean `dev down`).
- [x] Landed [`plans/161-oci-unpacker-openat2-and-adr-note.md`](plans/161-oci-unpacker-openat2-and-adr-note.md) (Plan 143 R2 + R3): the OCI layer unpacker — the one place mvm parses attacker-controlled tar layers — now resolves every write through an `openat2(RESOLVE_IN_ROOT | RESOLVE_NO_SYMLINKS)` directory handle and creates the leaf with `*at` calls (`openat2`/`mkdirat`/`symlinkat`/`linkat`/`mknodat`), closing the check-then-use TOCTTOU that a `symlink_metadata` parent walk + later `open(2)` left open. `parent_chain_has_symlink` is reduced to a cross-platform fail-fast pre-filter; non-Linux keeps the path-based fallback (the unpacker runs only in the Linux builder VM in production). Added a concurrent symlink-swap witness — box-verified to **fail** against the pre-openat2 write and **pass** with the fix — plus a deterministic escape corpus and a dependency-free USTAR fuzz-corpus arm. ADR-002 §Threat model gains the "why a hardware boundary, not a userspace application-kernel sandbox" positioning note (no new numbered claim). Verified: `cargo test -p mvm-oci` green on macOS (fallback, 84) and a real Linux host (openat2, 73 unit + 15 integration); `cargo clippy -p mvm-oci --all-targets -- -D warnings` clean on both; nightly `cargo fmt --all --check` + `check-no-spec-refs-in-comments` clean. Deferred: whiteout-removal openat2 conversion (tracked in the plan).
- [x] Follow-up to the above (Plan 161 deferred item): routed the whiteout-**removal** path through `openat2` too. `Rooted::apply_regular_whiteout` / `apply_opaque_whiteout` resolve the target's parent via `openat2(RESOLVE_IN_ROOT | RESOLVE_NO_SYMLINKS)` and remove via `*at` (`statat`/`unlinkat` + a `rustix::fs::Dir` dirfd recursion that preserves current-layer paths), closing the same check-then-use TOCTTOU on the removal side. Added a second concurrent-swap witness (`concurrent_symlink_swap_during_whiteout_removal_never_escapes_root`), box-verified to delete an out-of-root file against the pre-openat2 removal (0.04s) and to hold with the fix; both race witnesses are now wall-clock-bounded (~1.5s) so swapper contention can't blow up CI time. `parent_chain_has_symlink` is kept as the cross-platform fail-fast + non-Linux self-guard (deleting it would drop the only guard on the non-Linux fallback for no Linux benefit; `std::fs::remove_dir_all` is already within-tree race-safe). Verified: `cargo test -p mvm-oci` green on macOS (fallback, 86) and a real Linux host (openat2, 74 unit + 15 integration); `cargo clippy -p mvm-oci --all-targets -- -D warnings` clean on both; nightly fmt + spec-ref lints clean.
- [x] Landed [`plans/126-dependency-reduction.md`](plans/126-dependency-reduction.md) Task D1 (forbidden-dep gate): extended `xtask check-forbidden-deps` with a **default-closure ban** — it resolves `mvmctl`'s default-feature normal-edge closure via `cargo tree` and fails if `sigstore`/`opendal`/`pgp` (the deliberately-gated heavy deps, cut to behind off-by-default features) re-enter it. Exact package-name match (so `sigstore-protobuf-specs` doesn't false-trip); the existing `sea-*`/`mysql` lockfile-name ban stays. Checked against the *closure* not the lockfile because `sigstore` legitimately lives in `Cargo.lock` behind `manifest-verify`. `aws-lc-rs` is deliberately not gated (still in the closure via `oci-client → rustls`, B4 blocked upstream); `tokio`-in-`mvm-core` stays covered by `check-core-runtime-free`. Gate already wired into `ci.yml` + `ci-full.yml` — no new CI step. 6 unit tests (matcher exact-match/sort/dedup) + an end-to-end run verified to **trip** when a present crate is added to the ban list and pass after revert. `cargo clippy -p xtask --all-targets -- -D warnings` + nightly fmt + spec-ref lints clean. Remaining D1 work: the `dep-baseline.md` measurement write-up.
- [ ] Planned [`plans/195-builder-vm-fingerprint-narrowing.md`](plans/195-builder-vm-fingerprint-narrowing.md): kill the builder-VM cache churn (the ~9s Stage 0 re-materialize on most `dev up` runs) by dropping the redundant whole-workspace `Cargo.lock` from `builder_vm_source_fingerprint` — the builder-VM flake forbids `buildRustPackage`, so the embedded host-bin byte-hash (L3) already captures the only baked Rust precisely. Commit 2 tightens `build.rs` rerun triggers so L3 stays authoritative. Build-perf only, no security-claim impact (claim-mapping in the plan). Splits out Plan 193's recorded build-perf finding. Plan 194 reserved for ADR-081 A3.
- [x] Closed out Plan 126 D1 Step 2 — the dependency **final measure** in [`docs/investigations/dep-baseline.md`](../docs/investigations/dep-baseline.md): re-measured with the canonical A1 commands, the default binary closure is **407→347 (−60, ~15%)** and the lockfile **722→683 (−39)**. `sigstore`/`opendal`/`pgp` are all out of the default closure (pgp via plan 160's Alpine→busybox Stage-0 seed — the bulk of the −60, honestly attributed rather than all claimed for 126); `aws-lc-rs` is the sole remaining heavy default-closure target (B4 blocked upstream by `oci-client`). Documented the four ratchets that hold the cut (`check-forbidden-deps` closure ban, `check-core-runtime-free`, cargo-deny `multiple-versions=deny`, cargo-deny/audit). Docs + measurement only, no code change. (Anchored after the 195 line to avoid a 3-way conflict with in-flight #852/#853.)
- [x] Landed [`plans/124-guest-agent-lean-overlay.md`](plans/124-guest-agent-lean-overlay.md) Step 1.5 (D1.2a — protocol type stubs): wired `schema/protocol-v0.json` (the `emit_protocol_schema` SSOT from D1.1) into the existing `xtask gen-stubs`/`check-stubs` pipeline. `gen_stubs.rs` is now a data-driven `StubArtifact` list — only the emit command (the protocol bin needs `--features schema`), output paths, and root class name vary — so both schemas regenerate the Python dataclasses + TS interfaces in one command. New committed stubs: `sdks/python/mvm/_protocol/protocol.py` (root `Protocol`, with the `GuestRequest`/`GuestResponse` Union tree) + `sdks/typescript/src/protocol/protocol.ts`; a hand-written `_protocol/__init__.py` re-exports the roots. Regenerating also refreshed the **IR** stubs, stale since 2026-06-06 (Plan 191's `files`/`MaterializedFile` IR field + spec-ref stripping) because the drift gate isn't yet in CI — a live demo of the drift the Plan 128 CI wiring would catch. Verified: generated modules import (`python -c`) + type-check (`tsc --noEmit --strict`); `cargo xtask check-stubs` GREEN (no drift); `cargo clippy -p xtask --all-targets -- -D warnings` + nightly fmt + `check-no-spec-refs-in-comments` clean; 3 new descriptor unit tests. Remaining D1.2: the RPC method surface + Rust agent enum (Step 2); CI no-drift gate stays with Plan 128.
- [x] Landed [`plans/128-testing-fuzz-claim-gates.md`](plans/128-testing-fuzz-claim-gates.md) Task C3 Step 2 — wired the SDK stub **no-drift gate** into CI: `cargo run -p xtask -- check-stubs` now runs in the Lint job of `ci.yml` + `ci-full.yml`, with `astral-sh/setup-uv` (pinned `@v8.2.0`) + `actions/setup-node@v6` providing the `uvx`/`npx` the codegen shells out to. The cross-platform-determinism worry that deferred this (124 D1.0) is resolved up front: rsynced main to the dev-kvm Linux box and ran `check-stubs` there — byte-clean (no drift) on Linux node18/py3.11 against the macOS-committed stubs (node22/py3.12), proving the pinned generator versions (not the host toolchain) fix the output. The IR + protocol *type* stubs can no longer silently rot (exactly the week-long drift D1.2a swept up). Also ticked C3 Steps 1 + 3 (`check-guest-agent-in-all-images`, `check-forbidden-deps`) — already live in the Lint job, the rollup just hadn't recorded them. The method-surface `gen-sdk` drift folds into the same gate when D1.2 Step 2 lands.
- [x] Landed [`plans/124-guest-agent-lean-overlay.md`](plans/124-guest-agent-lean-overlay.md) D1.2 Step 2a — the machine-readable **request→response contract**, the prereq for any typed RPC-client generator. The pairing "which `GuestResponse` answers which `GuestRequest`" lived only in the agent dispatch `match` (~35 scattered arms); declared it as data in `crates/mvm-guest/src/vsock.rs`: typed name-only projections `Verb` (35 verbs) + `ResponseVariant` (26) via a `name_enum!` macro (so each enum's `ALL` slice can't drift from its variants), `Verb::response_contract() -> ResponseContract { responses, kind: Unary|Stream }`, and exhaustive `GuestRequest::verb()` / `GuestResponse::variant()` projections (adding a wire variant fails to compile until mapped); `verb_name()` now delegates to `verb().name()` (one list, not two). 4 streaming verbs (Exec/RunCode/RunEntrypoint/ProcWait), 31 unary; `Error`/`UnsupportedInProfile` universal. 8 unit tests incl. a drift guard that every `GuestResponse` variant is contracted-or-universal. No wire-shape change → `check-stubs` green. **Key finding (re-scopes Step 2):** the Python/TS SDKs don't speak vsock — they shell to `mvmctl` (ADR-0010) — so the literal "RPC method surface in the SDK" is dead code; the real vsock client is the **Rust host**, so Step 2b is a host-side typed client (the circular "Rust enum from the schema" sub-goal is dropped). Verified: `cargo test -p mvm-guest` 260 green, `cargo clippy -p mvm-guest --all-targets -- -D warnings` clean, nightly fmt clean, `cargo check --workspace --all-targets` green, `check-stubs` no drift.
- [x] Landed [`plans/124-guest-agent-lean-overlay.md`](plans/124-guest-agent-lean-overlay.md) D1.2 Step 2b — the **contract-checked host-side RPC client**, the first consumer of Step 2a's contract. In `crates/mvm-guest/src/vsock.rs`: `check_response(req, resp)` (pure) maps the universal `Error`→`RpcError::Agent` + `UnsupportedInProfile`→`RpcError::UnsupportedInProfile` and rejects any frame whose `variant()` isn't in the verb's `response_contract()` as `RpcError::OffContract` — a misbehaving agent is caught at the boundary, not mis-deserialized at a call site. `call_unary` = `send_request` + `check_response`; `call_streaming` loops `read_frame` + `check_response` until `GuestResponse::is_stream_terminal()`. **Design call:** a *generic* contract-driven client, not per-verb codegen — the contract is already typed Rust data, so a generic client gives full type-safety with no codegen machinery (per-verb ergonomic methods are an SDK-veneer/D1.3 concern). Reuses the existing framing helpers — no new wire code. 9 tests: pure `check_response` cases + `UnixStream::pair()` round-trips incl. an off-contract rejection. Proof-of-use: migrated the `instance_snapshot.rs` PostRestore call site off raw `send_request` (its hand-rolled `Error`/unexpected handling collapses into the client). No wire change → `check-stubs` green. Verified: `cargo test -p mvm-guest` 269 green, `cargo clippy -p mvm-guest -p mvm --all-targets -- -D warnings` clean, nightly fmt clean, `cargo check --workspace --all-targets` green, `check-no-spec-refs-in-comments` clean. Remaining: migrate the hot `mvm-cli` call sites (Step 2c, gated on Plan 189).
- [x] Landed [`plans/124-guest-agent-lean-overlay.md`](plans/124-guest-agent-lean-overlay.md) D1.2 Step 2c — the `mvm-cli` unary call sites adopt the client. Migrated every unary `send_request` site onto `call_unary`: `commands/vm/wait.rs` (ReadinessStatus), `readiness.rs` (IntegrationStatus), `session.rs` (UpdateIdleTimeout), `console.rs` (ConsoleOpen). Each shed its hand-rolled `Error` / `UnsupportedInProfile` / unexpected-variant arms — the contract guard now maps those to typed `RpcError` at the boundary (net −17 lines, diffs *delete* code). Turned out **not** gated on Plan 189 after all: those worktrees touch `commands/env/*`, while these sites live in `commands/vm/*` (verified uncontended). Left on raw `send_request`: the fire-and-forget `ConsoleResize` (`.ok()` discards the result, so validation buys nothing) and the `exec`/`proc`/`cp` streaming paths (already on dedicated `send_*_streaming` helpers). Behavior-preserving refactor: 257 `commands::vm` tests green (no test asserts the old error strings), `cargo clippy -p mvm-cli --all-targets -- -D warnings` clean, nightly fmt clean, `cargo check --workspace --all-targets` green, `check-no-spec-refs-in-comments` clean. The live "agent honors the contract" assertion rides on the existing real-guest e2e for these paths. D1.2 is now done bar the SDK-veneer (D1.3 / Plan 125).
- [x] Closed out [`plans/124-guest-agent-lean-overlay.md`](plans/124-guest-agent-lean-overlay.md) at **core-complete**. The full D1.2 RPC thread is on main (stubs #857 + check-stubs CI gate #859 + 2a contract #864 + 2b client #865 + 2c adoption #871), atop the lean-agent / universal-agent / verity-overlay spine. **Descoped Phase E (signed config-on-device)** as a superseded premise: it was specified to replace a vsock config round-trip and add integrity, but runtime config is build-time-baked into `/etc/mvm/runtime.json` and integrity-sealed by **dm-verity (claim 3)** — there is no vsock round-trip to remove, and a signed device would only duplicate verity's integrity while adding a device-parser + sig-verify attack surface (claim-5 fuzz growth) for no realized benefit. It only earns its keep under a generic-image-per-launch-config or non-verity (libkrun/Vz) integrity story, neither realized today; revisit then against the real need. Remaining Plan 124 items are independent efforts: D1.3 SDK veneer → Plan 125; KVM live verity-boot validation (box-gated); libkrun/Vz overlay attach (its own plan); no_std agent core (stretch). Docs-only.
- [x] Started [`plans/125-cli-sdk-dx-surface.md`](plans/125-cli-sdk-dx-surface.md) Task B1a — Sandbox **copy** in **both** SDKs. `sb.copy_in`/`sb.copy_out` (Python) + `sb.copyIn`/`sb.copyOut` (TS) shell `mvmctl cp <host> <vm>:<guest>` / `mvmctl cp <vm>:<guest> <host>` — `mvmctl cp` already round-trips a file host↔guest over the agent fs RPC, so the SDKs are thin wrappers (`_LiveTransport.cp` / `LiveTransport.cp`). Live-mode-only like `exec` (record mode raises `SandboxModeError`; declarative staging uses `files.write`). **Built both SDKs in lockstep** (not Python-then-TS-later) since they're mirrors and the capability lives in `mvmctl` — doing one would create the drift the plan warns against. TDD via the fixture-`mvmctl` harness: Python 4 new tests (full suite 138 green, ruff-clean on the new code) + TS 4 new tests (full suite 71 green, `tsc` build + `typecheck` clean). **Split out B1b (`forward`/ports)**: `mvmctl forward` blocks (spawns socat proxies, waits for Ctrl-C), so it needs detached background-process spawn + teardown wiring into `Sandbox.kill`/`__exit__` in both SDKs — a distinct pattern from `cp`'s request/response, hence its own task. Note: the Python/TS SDK test suites are not yet PR-CI-gated (only `publish-pypi`/npm packaging run) — verified locally. `sdks/`-only change, no Rust/schema touch → Rust gates + `check-stubs` unaffected.
- [x] Landed [`plans/125-cli-sdk-dx-surface.md`](plans/125-cli-sdk-dx-surface.md) Task B1b — Sandbox **forward/ports** in **both** SDKs (the deferred half of B1). `sb.forward(host_port, guest_port)` spawns `mvmctl forward <vm> --port <host>:<guest>` (CLI port spec is `HOST:GUEST`). The hard part: **`mvmctl forward` blocks** (runs socat proxies until Ctrl-C), so the SDK can't shell-and-wait — it launches it **detached** (`subprocess.Popen` / `child.spawn`) and **tracks the handle** on the transport (`_forwards` / `forwards`); `kill()` **terminates every forwarder before `mvmctl down`** so a proxy never outlives the VM (wired through `Sandbox.kill` / `__exit__` / `[Symbol.dispose]`). Live-mode-only like `exec`/`copy` (record mode raises `SandboxModeError`; declarative ports use `mvm.network(ports=...)`). TDD via the fixture harness with an optional blocking `sleep` in the `forward` case so a test can **prove teardown**: Python 3 new tests incl. a terminated-on-kill witness (suite 141 green, new code ruff-clean) + TS 3 new tests incl. the same witness (suite 74 green, `tsc` build + `typecheck` clean). `sdks/`-only; Rust gates + `check-stubs` unaffected.
- [x] Landed [`plans/125-cli-sdk-dx-surface.md`](plans/125-cli-sdk-dx-surface.md) Task D1 — **TS `exec` parity** (the TS `Sandbox` had only `create`/`kill`/`commands`/`files`; Python's top-level `exec` had no TS counterpart). Added `sb.exec(argv, { env?, timeout?, cwd? }): ExecResult` mirroring Python's `commands_exec`: dev-only gate (prod template → `SandboxDevOnly`, claim 4, **before** any shell), `mvmctl proc start … -- argv` → pid_token → `mvmctl proc wait <token>` capturing `{ exitCode, stdout, stderr }`; live-mode-only (record → `SandboxModeError`). De-duped the `-e KEY=VAL` env encoding into a shared `encodeEnvFlags` helper used by both `commandsStart` + `commandsExec` (reuse-first, not a fork). 5 new TS tests via the fixture harness (extended its `proc` case to answer `wait` with configurable stdout/exit) — captured-output, non-zero-exit, env-forwarding, prod-`SandboxDevOnly`-with-no-proc-traffic, record-mode-refusal; suite 79 green, `tsc` build + `typecheck` clean. `exec` is **synchronous** (mirrors Python's current sync exec); the async surface is B2. `sdks/typescript`-only.
- [x] Landed [`plans/125-cli-sdk-dx-surface.md`](plans/125-cli-sdk-dx-surface.md) Task B2 — **async surface** in both SDKs. Python: `async with Sandbox.create(...) as sb: r = await sb.aexec(...)` — added `__aenter__`/`__aexit__` (async context manager, teardown via `asyncio.to_thread(self.kill)`) + `async def aexec`. **One impl, two faces:** `aexec` = `await asyncio.to_thread(self.exec, …)`, running the existing blocking `exec` in a worker thread (the codebase's established `to_thread` pattern), so `SandboxDevOnly` / `SandboxModeError` / `ExecResult` behave identically; sync `exec`/`with` untouched. Named `aexec` (not `exec`) because one Python method can't be both sync and async — the plan's `await sb.exec` is realized as `await sb.aexec` (a-prefix idiom); the same class carries both `with` and `async with`. TS: `[Symbol.asyncDispose]` for `await using sb = Sandbox.create(...)` (the counterpart to Python's `async with`); `await sb.exec(...)` already works (sync return, await passthrough). A non-blocking spawn-based TS exec is a noted follow-up (a real second impl, not a thin wrapper). TDD: Python 4 new tests via the fixture harness (its `proc` case now answers `wait`) — suite 145 green, new code ruff-clean; TS 2 new tests — suite 81 green, `tsc` build + `typecheck` clean. `sdks/`-only.
- [x] Landed [`plans/125-cli-sdk-dx-surface.md`](plans/125-cli-sdk-dx-surface.md) Task B3 — **lifecycle polish** in both SDKs, **completing Phase B**. Added `sb.id` (the live VM id when live, else the workload id) + `sb.info() -> SandboxInfo { id, workload_id, build_mode, live }` — a local identity/mode snapshot (no VM round-trip; `build_mode` is `"dev"`/`"prod"` when live, `None`/`null` in record mode). `SandboxInfo` is a frozen dataclass (Python, exported) / exported interface (TS). The plan's other B3 items were already in place — the one-live-process invariant + sync/async context-manager teardown already have tests (double-create-refusal, sync + async CM-kills-on-exit). 4 new Python tests + 2 new TS tests (id/info, live + record): Python suite 149 green (new code ruff-clean), TS suite 83 green (`tsc` build + `typecheck` clean). Phase B (imperative `Sandbox`: create/exec/copy/forward/id/info, sync+async, dev-tier-gated) is now complete in both SDKs. `sdks/`-only.
- [x] Landed [`plans/125-cli-sdk-dx-surface.md`](plans/125-cli-sdk-dx-surface.md) Task C1 — **`CodeSandbox`** typed code-runner preset in both SDKs (first of Phase C). `CodeSandbox(image="python:slim")` with `run(code)->stdout`, `run_script(host_path)` (copy_in + run), `install_package(pkg)` — a thin preset over the imperative `Sandbox` (`exec`/`copy_in`), no new mechanism. Picks the runner from the image (`node*` → `node`/`-e`/`npm install`, else `python`/`-c`/`pip install`); raises typed `CodeError` (exit_code/stdout/stderr) on a non-zero exit. New `sdks/python/mvm/_helpers.py` + `sdks/typescript/src/_helpers.ts` (where C2's `BrowserSandbox` will join), exported per package; `kill`/context-manager delegate to the underlying Sandbox. 5 new Python + 5 new TS tests via the fixture harness — Python suite 154 green (new file ruff-clean), TS suite 88 green (`tsc` build + `typecheck` clean). `sdks/`-only.
- [x] Landed [`plans/125-cli-sdk-dx-surface.md`](plans/125-cli-sdk-dx-surface.md) Task C2 — **`BrowserSandbox`** preset in both SDKs, **completing Phase C**. `BrowserSandbox("chromium")` = a `Sandbox` on a browser image with its CDP port (9222) forwarded via `Sandbox.forward`; `endpoint()` returns the host-side CDP HTTP base (`http://localhost:<host_port>`) for a CDP client (`connectOverCDP`/`browserURL`, which discovers the per-session ws URL). Image + port preset only — no new mechanism. Optional `host_port` override; unknown browser raises. Joins `CodeSandbox` in `_helpers.{py,ts}`. The reachable-URL test is the E2E-gated leg; unit tests cover the wiring (forward + endpoint + custom-port + unknown-browser): 3 new Python + 3 new TS — Python suite 157 green (ruff-clean), TS suite 91 green (`tsc` build + `typecheck` clean). Phase C (`CodeSandbox` + `BrowserSandbox`) is complete; remaining Plan 125 is Phase E (coherence test, `--secret`, doctor table, profiles, host-services SDK). `sdks/`-only.
- [x] Landed [`plans/125-cli-sdk-dx-surface.md`](plans/125-cli-sdk-dx-surface.md) Task E1 — **one IR, two front-ends (coherence test)**. `crates/mvm-sdk/src/decorator/coherence.rs`: the same hello-app (name, `python_image`, resources, bridge network+ports, env literal + `secret` binding) declared identically in the Python **and** TypeScript decorators lowers to an **equal canonical `Workload`** — the only field that differs is the entrypoint shim `language` (`python` vs `node`, set per-SDK by construction; even `app.source` is the same project root `.`). The test is non-vacuous (`assert_ne` on the raw IRs, then `assert_eq` after normalizing just that one field) and provably catches drift (perturbing a shared field fails it). **Reframe:** the plan named four surfaces (decorator, runtime-record, `mvm.toml`, flake) but only the decorator is a `Workload` authoring surface — and it has two language front-ends, so the real "one derivation engine" guarantee is the Python⇔TypeScript mirror. `mvm.toml` is the build-sizing manifest (no role/network/deps — it points at a flake), the flake is the derivation the one engine *emits* (`build_flake_nix`, IR→Nix), and runtime-record observes argv → a `Command` entrypoint that can't equal a `Function`. Writing flake→IR / toml→IR parsers to satisfy the literal wording would be dead speculative code. 2 tests; `cargo test -p mvm-sdk` 256 green, clippy + nightly fmt + `check-no-spec-refs-in-comments` clean, `cargo check --workspace --all-targets` green. Rust-side. Remaining Phase E: E3 doctor capability table, E4 named profiles, E5 host-services SDK.
- [x] Landed [`plans/125-cli-sdk-dx-surface.md`](plans/125-cli-sdk-dx-surface.md) Task E2 — **`--secret NAME:host`**. `mvmctl up … --secret openai:api.openai.com` adds a `SecretRef` to the workload. New `parse_secret_binding(spec) -> SecretRef` in `commands/shared/parse.rs` (alongside `clap_port_spec`/`parse_volume_spec`): splits `NAME:HOST[,HOST...]`, defaults `auth_type = Bearer` + env-var mount `NAME`, requires ≥1 host (claim-12 binding). Wired as a repeatable `--secret` flag on `up`: the parsed SecretRefs inject into the loaded workload IR's first-app env (`EnvValue::SecretRef`) **before** `lower_workload_secrets`, so they ride the same lowering → `plan.secrets` → admission path as baked secrets; `--secret` with no workload errors. Richer bindings (sigv4/hmac/file/custom-var) stay with `mvmctl secret set`. 6 parser unit tests. Verified: `cargo test -p mvm-cli` (up suite 49 + parser 7 green — injection behavior-preserving for no-`--secret`), clippy + nightly fmt + `check-no-spec-refs-in-comments` clean, `cargo check --workspace --all-targets` green. First Rust-side Plan 125 slice (the rest were `sdks/`).
- [x] Landed [`plans/125-cli-sdk-dx-surface.md`](plans/125-cli-sdk-dx-surface.md) Task E3 — **`doctor` backend-capability matrix**. `mvmctl doctor` now renders a **Backend capability matrix (per backend)**: one row per real backend (firecracker/libkrun/qemu/vz; the Tier 3 `mock` test double excluded) consolidating the per-backend tradeoffs behind `--hypervisor` — snapshot tier (live-memory/save-restore/disk-only), network disposition (`tap-net` + `vsock`), storage disposition (`fs-checkpoint`), `balloon`, and the boot-latency axis (`standby-pool`). `collect_capability_table()` reads every field straight off `VmBackend` (catalog `warm_start_support_descriptors()` set + `capabilities()` + `snapshot_capability()` + `supports_standby_pool()`) so the table is runtime truth, not a hand-maintained copy; `BackendCapabilityRow` is serialized under `capability_table` in `doctor --json`. RED-first row-assertion test (symbols absent → fail) pins firecracker=live-memory/tap/vsock/balloon, libkrun=disk-only/no-tap/standby-pool, qemu=disk-only/slirp, vz=vsock (host-gated fields left platform-robust); a serde test pins the JSON field. `cargo test -p mvm-cli` 943 lib + 72 doctor green, clippy + nightly fmt + `check-no-spec-refs-in-comments` clean. Rust-side. Remaining Phase E: E4 named profiles, E5 host-services SDK.
- [x] Landed [`plans/125-cli-sdk-dx-surface.md`](plans/125-cli-sdk-dx-surface.md) Task E4 — **named security profiles**. `resolve_security_profile(name)` in `mvm-core::policy::security_profile` maps a name → `SecurityProfile { seccomp: SeccompTier, egress: NetworkPreset, snapshot_allowed, deployable }`. **Binary production-vs-development model** (not a strictness gradient): **`production` is the default** — the highest-security, production-ready posture (seccomp `standard` floor + deny-all egress + no snapshot) and **the only deployable profile**; **`dev`** is a development-only convenience (unrestricted seccomp + open egress + snapshots) carrying `deployable = false`, so it **can never reach production** — which is exactly why it's allowed to be loose. The invariant `every deployable profile is_bounded()` is asserted, so a one-word profile can never silently un-sandbox a *deployable* workload. Aliases `prod`/`production`, `dev`/`development`; unknown name fails closed. Surface: `--security-profile <name>` on `up` (`--profile` was already the flake profile) — default `production`, supplies the defaults for `--seccomp` + the egress preset, explicit `--seccomp`/`--network-preset` win, production is byte-identical to today's seams; the prod build path (`--prod`) **refuses a non-deployable profile** via `enforce_profile_deployable` (extracted + unit-tested). RED-first: 6 resolver tests (mvm-core) + 4 precedence/deploy-guard tests + 1 CLI-parse test (mvm-cli). `cargo test -p mvm-core/-p mvm-cli` green (954 cli lib), clippy + nightly fmt + spec-ref + `check-core-runtime-free` + `cargo check --workspace --all-targets` clean. (Snapshot-allowance enforcement is a follow-up; `up` has no snapshot flag yet — the resolver carries the disposition.) Rust-side. Remaining Phase E: E5 host-services SDK; plus the unstarted Phase A (52→≤15 nested CLI).
- [x] Landed [`plans/125-cli-sdk-dx-surface.md`](plans/125-cli-sdk-dx-surface.md) Task E5 **slice E5.1 — Layer 1 broker transport** (the foundational piece all host services ride on; E5 is the sole remaining Plan 125 task, security-critical — claims 8/12/13). **Resolved two security questions before writing any transport.** (1) *Guest-facing port*: the supervisor's guest-facing broker listener is unbuilt (deferred), so the path is the `host_listen_ports` allowlist mechanism `SUBSTITUTION_PORT` uses — added `BROKER_PORT = 5300` (the broker's documented port; reuses the freed pre-broker secrets-channel number) to `mvm-guest::vsock`, disjoint from 5251/5252/5253 and the 10k/20k forward/console ranges. (2) *Session binding (claim 12)*: the broker path carries a **bare `ServiceCall`, not an authenticated frame** — the host derives workload identity from the connection (the supervisor builds `ServiceCallCtx`; the registry's bound-set comes from the admitted `ExecutionPlan.services`), so the guest presents nothing and holds no key/secret. **The client is advisory-only**: every gate (binding, `host.audit.v1` category-forcing, size/rate caps, correlation-id assignment) is host-side. **Homed in `mvm-guest`** (`broker_client.rs`), sibling to `substitution_client.rs` — not `mvm-sdk` as the scoping note read, because mvm-sdk has neither `mvm-guest` nor `mvm-core` as a runtime dep (dev-dep only), while mvm-guest is the in-guest crate baked into the image and already carries the vsock/framing primitives + the `mvm-core` broker types. API mirrors the substitution relay: `call(stream, &ServiceCall) -> Result<Value, BrokerError>` (testable core; one call per connection — the host assigns `correlation_id`, so no multiplexing) + `broker_call(req, timeout)` (`connect_host_vsock(BROKER_PORT)` + `call`); `ServiceResponse::Err` surfaces as typed `BrokerError::Service { code, message }`, transport/framing as `BrokerError::Transport`. RED-first, 5 mock-I/O unit tests over `UnixStream::pair()` (mirroring the host `broker_proxy` mocks): Ok-payload roundtrip + exact-envelope assertion, `Err`→typed error, oversize-frame rejection (>256 KiB read cap), truncated-body rejection, malformed-JSON-body rejection. `cargo test -p mvm-guest` green (274 lib + suites, 0 failures), `clippy -p mvm-guest --all-targets -D warnings` + nightly fmt `--all` + `check-no-spec-refs-in-comments` + `check-core-runtime-free` + `cargo check --workspace --all-targets` all clean. Remaining: E5.2 typed `host.audit.v1` (host forces `workload_audit`, caps), E5.3 PyO3/napi veneer + live-VM E2E (box), E5.4 `host.time.v1`/`host.cost.v1`.
- [x] Landed [`plans/125-cli-sdk-dx-surface.md`](plans/125-cli-sdk-dx-surface.md) Task E5 **slice E5.3a — reserve `BROKER_PORT` in `host_listen_ports`** (the host-side first brick toward the live broker round-trip). **Grounding found E5.3 is much larger than "veneer + E2E"**: the broker-services subprocess lifecycle is unbuilt — `BrokerProxy::new`, `AuditSignerProxy::new`, and the broker `serve` are all **test-only**, and the per-VM supervisors spawn nothing but `codesign`, so nothing spawns `mvm-broker` / `mvm-audit-signer` per VM or binds the broker UDS. E5.3a is the correctly-sized first step: register `BROKER_PORT` (5300) in `host_listen_ports` on **both workload backends** (libkrun `add_host_listen_port`, vz `vsock.host_listen_ports`), the same **fail-closed staging** `SUBSTITUTION_PORT` uses — registered unconditionally, but nothing binds the per-VM UDS until E5.3b spawns the broker, so a stray guest dial gets `ECONNREFUSED` (no eager listener, no hang). RED-first: dedicated disjoint-union assertion tests per backend (`BROKER_PORT must be in host_listen_ports` ∧ `must not appear in vsock_ports`/`vsock.ports`), mirroring the substitution-port tests; watched both go red then green. `cargo test -p mvm-backend` green (320 passed, 0 failed — no codesign SIGKILL this run), clippy `-D warnings` + nightly fmt `--all` + `check-no-spec-refs-in-comments` + `check-core-runtime-free` + `cargo check --workspace --all-targets` clean. **The large remainder — E5.3b broker-services subprocess lifecycle (spawn+supervise `mvm-audit-signer` + `mvm-broker` per VM, `BROKER_PORT`→UDS bind, `ServiceCallCtx` enrichment incl. correlation rewrite, spawn process-moat hardening, PyO3/napi veneer, live-VM E2E) — is grounded in `specs/notes/plan-125-e5-3b-broker-services-lifecycle-scoping.md`; it's process-moat work (Plan 128-adjacent), recommended as its own workstream.** Remaining E5: E5.3b (above), E5.4 `host.time.v1`/`host.cost.v1`.
- [x] Landed [`plans/193-rvproxy-network-substrate.md`](plans/193-rvproxy-network-substrate.md) **WS-1 (proven) + WS-1.5 (parity-gate scaffold + CI lane)**. WS-1: a live `mvmctl dev up` through **rvproxy** on macOS/libkrun built the builder-VM rootfs cold (~540k egress connections relayed; DHCP + DNS + sustained download) and reached "Dev environment ready" — the libkrun-`unixgram` transport is confirmed. Took three rvproxy fixes (sibling repo): DNS reply sourced from the gateway IP (rvproxy #38), guest-bound TCP segmented to the MTU (#42 — a full-size response was EMSGSIZE-tearing the vfkit unixgram transport), and read/write timeouts cut to per-poll budgets (#53 — a 30s read froze the single-threaded pump ~30s per idle poll, crawling the boot). WS-1.5: `scripts/rvproxy-gateway-parity.sh` runs the claim-10 / flow-audit / Plan-129-substitution witness families plus the one binary-discriminating conformance witness (`gvproxy_dhcp_offer_roundtrips_through_bridge`) against **both** gvproxy (control) and rvproxy (candidate via `MVM_GATEWAY_BIN`), refusing the default flip unless rvproxy genuinely runs and passes — validated head-to-head on macOS (both PASS) and negatively (a non-gateway binary → REFUSED). CI lane `.github/workflows/rvproxy-parity.yml` is **live**: macos-latest (ADR-038: ~10× ubuntu cost, so paths-filtered off unrelated PRs), builds the candidate from a pinned rvproxy rev (`RVPROXY_DEFAULT_REF`, `workflow_dispatch`-overridable) via the `RVPROXY_CHECKOUT_TOKEN` repo secret, fails closed without it. Secret provisioned + validated green end-to-end in CI 2026-06-15 (gvproxy PASS + rvproxy PASS + enforcement witnesses green), then promoted to `workflow_dispatch` + a paths-filtered `pull_request` trigger on the gateway-contract files. The enforcement arm is bridge-side and binary-agnostic until **WS-2** ports enforcement onto rvproxy's native flow API (deleting the Plan 141 splice) — the cross-repo-gated substantive remainder; making the lane a *required* check is a branch-protection decision.
- [x] Designed [`plans/193-rvproxy-network-substrate.md`](plans/193-rvproxy-network-substrate.md) **WS-2** (the substantive remainder — moving claim-10/flow-audit/Plan-129 enforcement off the in-line `gateway_bridge` splice onto rvproxy's native flow API, then deleting the splice + the Plan-141 per-backend `on_packet` hooks). Surveyed both repos 2026-06-15: rvproxy has a mature audit **export** sink + a packet-level `ByteTransform` but **no native flow-decision seam** — no per-flow open decision, no `FlowOpened`/`FlowClosed` events, no flow-level drop (`DecisionEmitter` declared/unimplemented; `flow_decision_sink_failures` named/unimplemented). So WS-2 is 🔴 **blocked on rvproxy building R2**, not on mvm code. Wrote the mvm-side design (Plan 193 §"WS-2 design": enforcement inventory the native path must reproduce; consumption = config + event sink, not an in-process trait; who-calls audit; parity-first failing-test plan — witnesses run against the native path and must match the splice before it's deleted) and authored the precise R2 flow-decision/audit contract into rvproxy `specs/plans/014` R2 (flow-open deny-by-default as config-enforced policy + reserved sync callback; flow-lifecycle events into mvm's chain-signed audit; per-packet observe/modify/**flow-kill**; fail-closed + no-bypass contractual). **Correction in both docs:** the *declared* egress-secret substitution stays in mvm's host-side vsock/`:443` terminator — NOT a gateway plugin (live creds in the data-plane gateway widen the blast radius); only undeclared redaction + the placeholder-leak drop move onto the gateway. Under ADR-082 (no new ADR). Specs-only; hands off to the rvproxy session to build R2.
- [x] Started the [`plans/193-rvproxy-network-substrate.md`](plans/193-rvproxy-network-substrate.md) **R2 build** (rvproxy side). **Slice 1 — deny-by-default flow decision — MERGED to rvproxy main (rvproxy #97):** `default_egress_deny` on PolicyConfig/GatewayConfig, enforced at the single `policy_destination_reason` chokepoint (covers TCP/UDP/DNS-resolver), reason `"deny-by-default"`; backward-compatible (defaults false, preserves the `cidr_allowlist_miss` path); wired through the `[policy]` config. TDD on the quiet Hetzner box: transport 170 / cli 89 / policy 2 / config 79, fmt + clippy -D warnings clean. So WS-2's blocker is lifting: R2 is being built, not just designed. **Slice 2 (flow-lifecycle events: `FlowOpened`/`FlowClosed{reason}` + a consumable sink) is in flight by a PARALLEL session — not this one.** Slices 3 (flow-context transform + flow-kill) and 4 (mvm-rule-carrying redaction) stack on slice 2. Full slices 2–4 spec + pickup prompt: [`specs/notes/rvproxy-r2-session-closeout-and-handoff.md`](notes/rvproxy-r2-session-closeout-and-handoff.md). After all four land, mvm consumes them, proves native-path parity via the WS-1.5 gate, then deletes the splice.

## Dependency Reduction Roadmap (analysis checkpoint: 2026-05-26)

**Objective:** reduce Rust dependency count, shrink binary/build
surfaces, and remove high-risk/high-churn third-party crates where the
project only uses a narrow slice of functionality.

**Measured baseline (analysis only, before any reduction PRs):**

- [ ] `Cargo.lock` package entries: `723`
- [ ] `cargo tree -p mvmctl --edges normal,build,dev --prefix none | sort -u | wc -l`: `610`
- [ ] `cargo tree -p mvm-cli --edges normal,build,dev --prefix none | sort -u | wc -l`: `537`
- [ ] `cargo tree -p mvm-build --edges normal,build,dev --prefix none | sort -u | wc -l`: `416`

**Scope note for the current live-test gating work:**

- [ ] Be explicit in PR descriptions and follow-up sessions that moving
      the 5 heavy live tests behind a `live-tests` feature is mainly a
      compile-surface / accidental-execution / workflow win, not a raw
      dep-graph-count win.
- [ ] The crates referenced by those gated tests (`flate2`,
      `mvm-libkrun`, `tempfile`, `which`, `mvm-oci`) are already pulled
      by main code or other tests, so the lockfile / unique-node counts
      should not be expected to drop materially from that change alone.
- [ ] Treat the live-test gating work as enabling infrastructure for
      future dependency reduction, not as the dependency-reduction
      endpoint itself.

### Track A — Immediate low-risk cuts

- [ ] Replace root-test `httpmock` usage with an in-repo
      `tokio::net::TcpListener` fixture.
      Target surface: `tests/audit_emissions_live.rs` and any other
      root tests using `httpmock`.
      Expected impact: remove `httpmock`'s dev-only closure
      (`~187` unique packages in isolation), including `async-std`,
      `hyper 0.14`, `http 0.2`, and `base64 0.21`.

- [ ] Replace `mvm-oci` test `wiremock` usage with the same in-repo
      tokio-based fixture.
      Target surface: `crates/mvm-oci/tests/`.
      Expected impact: remove `wiremock`'s dev-only closure
      (`~127` unique packages in isolation).

- [ ] Unify `which` on one version workspace-wide.
      Current state: `which 6.0.3` is pulled by `mvm-build`; `which 7.0.3`
      is used elsewhere.
      Expected impact: remove duplicate `which`/`rustix` lineage and
      simplify lockfile churn.

- [ ] Replace `names` with a local generator or deterministic fallback.
      Current call site: `crates/mvm-cli/src/commands/vm/up.rs`.
      Expected impact: small package-count win, trivial rewrite.

- [ ] Evaluate replacing `inquire` prompts with stdio helpers.
      Current call sites: `crates/mvm-base/src/ui.rs`,
      `crates/mvm-cli/src/ui.rs`,
      `crates/mvm-cli/src/commands/ops/secret.rs`.
      Decision gate: accept simpler UX in exchange for lower dep count.

- [ ] Evaluate replacing `indicatif` spinners with a local stderr
      spinner or no spinner.
      Current call sites: `crates/mvm-base/src/ui.rs`,
      `crates/mvm-cli/src/ui.rs`.
      Decision gate: accept simpler UX in exchange for lower dep count.

### Track B — Feature trimming and duplicate-stack cleanup

- [ ] Narrow `tokio` workspace features away from `features = ["full"]`.
      Start with crates that inherit the workspace dep without
      per-crate narrowing:
      `crates/mvm/`, `crates/mvm-build/`, `crates/mvm-backend/`,
      `crates/mvm-addon-dns/`, and the bare `tokio = { workspace = true }`
      entries in `crates/mvm-guest/`.
      Goal: reduce compile graph size, binary surface, and accidental
      feature union.

- [ ] Re-run `cargo tree --workspace --duplicates` after the tokio audit
      and record the post-audit duplicate list in this section.

- [ ] Keep feature-gated optional stacks off the default path unless
      clearly justified.
      Review items when touched:
      `notify` / `notify-debouncer-mini`,
      `opendal`,
      `hickory-resolver`,
      `sigstore`.

### Track C — Medium-cost structural cuts

- [ ] Remove `bindgen` from the normal `mvm-libkrun` build path by
      checking in generated bindings or otherwise freezing the generated
      Rust surface.
      Current surface: `crates/mvm-libkrun/build.rs`.
      Expected impact: remove a build-only closure (`~28` unique packages
      in isolation) and `libclang` coupling during normal builds.

- [ ] Evaluate replacing `hickory-proto` in `mvm-addon-dns` with a
      minimal in-house DNS codec for the exact record types and packet
      shapes the addon resolver supports.
      Current surface: `crates/mvm-addon-dns/src/lib.rs`.
      Expected impact: moderate package-count reduction (`~71` unique
      packages in isolation).

- [ ] Evaluate feature-gating schema/code-analysis stacks that are not
      required for the default CLI/runtime path, especially `schemars`.
      Current surface: `crates/mvm-ir/`, `crates/mvm-sdk/`.
      Goal: keep schema emission available while reducing the default
      build/test surface when those paths are not in use.

- [ ] Keep `tree-sitter` as an intentional core dependency for source-
      derived entrypoint and workload analysis.
      Current surface:
      `crates/mvm-sdk/src/compile/func_describe.rs`,
      `crates/mvm-sdk/src/compile/reachability.rs`,
      `crates/mvm-sdk/src/decorator/python.rs`,
      `crates/mvm-sdk/src/decorator/typescript.rs`,
      `crates/mvm-sdk/src/addon/validator.rs`.
      Constraint: do not treat `tree-sitter` removal as a dependency-
      reduction goal unless product scope changes and source-derived
      entrypoint analysis is explicitly being removed.

- [ ] If tree-sitter optimization is needed, limit it to packaging and
      feature-boundary work:
      per-language grammar gating, isolating non-default compile paths,
      or moving optional analysis surfaces behind explicit features.

### Track D — Strategic rewrites

- [ ] Spike replacing `oci-client` inside `mvm-oci` with a minimal
      internal registry client built on the existing workspace
      `reqwest 0.12` stack.
      Current surface:
      `crates/mvm-oci/src/manifest.rs`,
      `crates/mvm-oci/src/layer.rs`.
      Scope limit for the spike:
      manifest fetch, auth header wiring, image-index selection, blob
      download, digest verification.
      Expected impact: remove `oci-client`'s large closure
      (`~222` unique packages in isolation) and eliminate the second
      `reqwest 0.13` / `hyper` / `http` family from the workspace.

- [ ] If the `oci-client` spike succeeds, land it before attempting the
      PGP rewrite.

- [ ] Rewrite the narrow Alpine detached-signature verifier in
      `mvm-build` to remove the `pgp` crate.
      Current surface:
      `crates/mvm-build/src/stage0.rs::verify_alpine_pgp_signature`.
      Scope limit:
      armored public-key parse, fingerprint pinning, armored detached
      signature parse, detached verification over the tarball bytes.
      Expected impact: remove `pgp`'s large closure
      (`~208` unique packages in isolation).

### Track E — Zig evaluation gates

- [ ] Do not introduce Zig for broad protocol-heavy replacements
      (`oci-client`, `pgp`) without a written tradeoff note covering:
      native toolchain cost, cross-platform CI complexity, auditability,
      and whether the native dependency truly reduces overall risk.

- [ ] If Zig is evaluated at all, constrain it to narrow ABI shims
      or parser islands where the native surface is small and stable.
      First plausible candidate: generated-FFI replacement work around
      `bindgen`, not the OCI or PGP stacks.

First concrete evaluation: [Plan 109 — Guest control-layer dep-reduction + encryption design](plans/109-zig-pid0-exploration.md) (Sprint 58).

### Execution order

- [ ] PR 1: remove `httpmock` / `wiremock`
- [ ] PR 2: tokio feature audit
- [ ] PR 3: small utility cleanup (`which`, `names`, optional UI deps)
- [ ] PR 4: `oci-client` spike branch and go/no-go review
- [ ] PR 5: land `oci-client` rewrite if approved
- [ ] PR 6: `pgp` rewrite if still justified after the OCI work

Recent maintenance:

- [x] Started Plan 113 for the security-first docs relaunch: added a product information architecture plan, new SDK overview/runtime/decorator pages, a Nix-vs-OCI guide, a security claim ledger, homepage links, and cold-mode/snapshot docs that treat builder VM secure builds plus Firecracker/Vz snapshot recovery as current platform pillars with backend-specific limits. The plan now also captures the desired persistent builder DX (`cargo run -- dev up` for the developer builder VM, `cargo run -- build` for the non-interactive build worker) and platform posture (Linux/macOS current, Windows future in mvm#428).
- [x] Added Plan 114 for secure sandbox product parity: reframed the work away from cloning another product's docs/site and toward product capability parity, with explicit imperative runtime SDK, declarative decorator SDK, `mvm` runtime ownership, secure builder VM, cold-mode lifecycle, OCI compatibility, and secret/network parity decisions.
- [x] Corrected the Plan 114 runtime SDK audit after reviewing the existing SDK work: `sdks/python`, `sdks/typescript`, `crates/mvm-sdk::runtime`, and `mvmctl run --mode plan|live` already provide the core `Sandbox.create(...)` record/live path. The remaining parity work is now scoped to productizing that surface: command result capture/streaming, file read/list/remove, logs, ports, snapshot/cold/resume, detach/destroy, and security tests around host-executed runtime scripts.
- [x] Expanded the docs tree toward secure sandbox product parity: added language quickstarts (Python, Node.js, Rust, C), core concepts, design principles, SDK reference/language status pages, architecture overview/core/security/networking pages, FAQ/changelog, static `/llms.txt`, and additional tutorials for desktop automation, interactive terminal, any-language workloads, long-running services, and error handling. The generated docs build now covers 105 pages.
- [x] Replaced the incomplete `Working in the MicroVM` page with a real local sandbox-management overview, added a dedicated `mvmctl` sandbox management page, and added a coding-agent tutorial focused on narrow filesystem access, explicit egress, and intentional state retention.
- [x] Kept tutorials separate from guides, moved Tutorials directly after Working in the MicroVM in the sidebar, and added a lifecycle-states page that defines running, paused, cold, restoring, stopped, and cleaned sandbox states with security notes and SDK parity links.
- [x] Added an SDK security model page that makes host execution, guest execution, builder boundary, data crossings, network, secrets, receipts, and snapshot retention explicit across runtime and decorator workflows.
- [x] Added an SDK operations cookbook that maps current Python/TypeScript runtime SDK calls to target helpers and secure CLI fallbacks for commands, files, logs, ports, pause/resume, snapshots, and cleanup.
- [x] Added a declaration cookbook for decorator-style Python and TypeScript workloads, covering Nix images, narrow source bundles, dependencies, command/function entrypoints, explicit egress, secret references, hooks, and pre-build review.
- [x] Added an agent tool contract guide that turns `mvm` sandbox execution into a bounded model-facing request/response API with validation, CLI-backed execution, SDK target shape, network grants, secret references, retention choices, redaction, and audit correlation.
- [x] Added a secrets-and-credentials guide and tightened config/secrets examples around reference-first credential delivery, managed refs, file-shaped secret caveats, agent grants, redaction, and retained-state sensitivity.
- [x] Added a persistent-workspaces guide covering encrypted managed volumes, host-backed mounts, copy-in/copy-out, snapshots versus volumes, agent workspace state, and cleanup policy for stateful sandboxes.
- [x] Added a network-egress policy guide that separates outbound grants from port exposure and documents deny-first CLI patterns, SDK declaration policy, agent-tool validation, browser automation cautions, backend enforcement notes, and review checks.
- [x] Added an observability-and-results guide covering command result correlation, receipts, audit IDs, logs, boot reports, metrics, redaction rules, metric-label hygiene, and typed failure classification for SDK and agent integrations.
- [x] Replaced the core Working-section stubs for commands, filesystem, networking, and persistence with concrete local `mvmctl` workflows and security notes, so the sandbox-management path no longer routes users into "content coming soon" pages.
- [x] Removed the remaining plan-62 docs stubs from the public docs tree: replaced Console, Connect an LLM, Templates, Programmatic use, Limits, Security claim pages, Examples, and GCP/Hetzner deployment stubs with current-status content. Also replaced stale `mvmctl template build/list` examples in quickstart, config/secrets, troubleshooting, and architecture docs with manifest-backed `mvmctl build`, `mvmctl up`, and `mvmctl manifest *` flows.
- [x] Added SDK product-reference pages for sandbox types and errors/metrics, covering general/code/browser/desktop/builder sandbox patterns, current CLI paths, planned high-level helpers, command result shape, error taxonomy, metric scopes, and audit-correlation requirements without claiming unimplemented APIs as shipped.
- [x] Fixed the Linux `passt` supervisor startup regression that was failing PR #460's `Test` lane: `mvm-libkrun::passt::spawn` no longer passes `--log-file` into private scratch dirs, and a regression test now asserts the generated passt argv omits that flag while preserving the pid-file path.
- [x] Cleaned up Plan 98 Slice 2B after Slice 2A merged: the `mvmctl dev` Vz-routing change now rebases directly onto `main`, compiles in both `builder-vm` and `default-features = false` `mvm-cli` builds, removes the stale §2.C1 grace guard, and keeps `MVM_BUILDER_BACKEND=vz` / `--builder vz` selecting the Vz dev backend only when that backend is actually available.
- [x] Hardened source-checkout macOS dev-image builds after the Vz builder regression: when auto-detect selects `vz` and there is no explicit `--builder` / `MVM_BUILDER_BACKEND` override, `ensure_dev_image` now retries the builder path with `libkrun` after a Vz bring-up failure instead of aborting `mvmctl dev up`; explicit overrides still fail loudly.
- [x] Restored the intended interactive `mvmctl dev up` DX: bare `dev` and explicit `dev up` now open a shell by default again, `--no-shell` opts out for scripts, and the recovery hints plus CLI reference were updated to match the shipped behavior.
- [x] Enforced the Plan 45 local-volume encryption-at-rest boundary: `mvmctl volume create` now creates managed local volume directories only on encrypted backing storage, and `mvmctl volume mount` fails closed unless the resolved managed/ad-hoc host directory is backed by encrypted storage (encrypted macOS volume or Linux dm-crypt/LUKS chain), while mounted volumes remain normal plaintext filesystems inside the guest.
- [x] Follow-up PR after the local-volume encryption gate: made encryption an mvm-owned per-volume property instead of only a host-backing precondition. `mvmctl volume create` now provisions a locked AES-256-GCM encrypted archive with wrapped per-volume key metadata, `volume unlock` is required before mount, `volume lock` reseals and removes plaintext, managed mounts refuse locked volumes, and security tests cover missing keys, tampered ciphertext, locked mount refusal, and clean unlock/lock round-trips.
- [x] Added [`adrs/053-guest-protocol-versioning-and-readiness.md`](adrs/053-guest-protocol-versioning-and-readiness.md) and [`plans/84-banger-runtime-lessons.md`](plans/84-banger-runtime-lessons.md), a proposed follow-up workstream translating the useful parts of Banger's runtime design into mvm protocol versioning, readiness states, control/data-plane boundaries, backpressure reporting, explicit builder-mode policy, receipts, explainability, and first-use DX.
- [ ] Plan 74 W1 in progress (hard cutover, no Ping compat shim): `ProtocolHello` / `ProtocolHelloAck` / `ProtocolMismatch` wire types, closed `GuestCapability` enum, `negotiate_protocol` + `require_capabilities` helpers, and the guest-agent prelude that rejects any non-hello first request with `ProtocolMismatch { required_action: upgrade_host }`. FS RPC, process RPC, run-entrypoint, console, and idle-timeout call sites fail closed on missing capabilities. Pending in W1: volume mount/unmount call sites, fuzz target updates for the new variants, and the hard-cutover regression test.
- [x] `mvmctl dev status` now reports the same Apple Container dev image paths that `dev up` boots (`~/.mvm/dev/current`, versioned prebuilts, or launchd-provided paths), instead of only checking the legacy cache location.
- [x] Added an opt-in `runtime_boot_bench` live test for already-built runtime images, covering serial boots and three-way concurrent fan-out against a 200 ms per-VM budget.
- [x] Source-checkout `mvmctl dev up` now refuses to download published prebuilts, preserving the "dev reflects local flakes" invariant.
- [x] Extended `runtime_boot_bench` with TOML config-file input, Apple Container backend defaults, configurable CPU/memory sizing, and Apple guest-agent readiness probing.
- [x] Removed the remaining third-party sandbox Cargo dependency and backend/builder compile paths; `Cargo.lock` no longer carries the transitive SeaORM/SQLx stack, including the MySQL driver.
- [x] Clarified the local platform policy after the cleanup: supported builder/runtime hosts are macOS Apple Silicon and native Linux with `/dev/kvm`; macOS Intel and native Windows are unsupported, while WSL2 nested KVM and a Hyper-V managed Linux builder remain future backend work.
- [x] Added ADR-048 and Plan 74 to turn the external-sandbox-runtime comparison into claim-gated `mvm` runtime work (external project referred to obliquely per [[feedback_no_competitor_names_anywhere]]; trait key in auto-memory `reference_external_sandbox_control_plane_oblique_key`): docs hygiene, OCI ingest, programmable networking, secret placeholders, SDK-owned lifecycle, measured cold-starts, and filesystem backend contracts.
- [ ] Plan 74 W0 (claims hygiene and docs guardrails) in flight — new public Sandbox parity status page (`security/sandbox-parity-status.md`), `cargo xtask check-doc-claims` lint covering `<100ms` / `any OCI image` / `secrets cannot leak` / variants, `mvmforge` cleanup in `guides/exec.md` and `reference/cli-commands.md`, gap-analysis updated for current `crates/mvm-sdk` layout and mvmd ADR-0020 handoff, and a new `specs/plans/83-w1-w6-attack-plan.md` sequencing sidecar that defers risk discussion to plan 74's `## Risks` section (R1-R12).
- [x] Added intent-bound admission profiles to signed `ExecutionPlan` v4, binding intent, seccomp tier, policy refs, secret-release posture, and audit taxonomy without adding new sandbox execution capability.
- [x] Documented the host-orchestrated builder VM flow across the website docs, clarifying that `mvmctl build` runs from the host while Nix evaluation/builds execute inside the builder VM and runtime boot benchmarks consume already-built artifacts.
- [x] Aligned `dev_build` with the builder VM invariant by removing the host-Nix dispatch probe from the normal path; Nix builds now route through the libkrun builder VM when builder-VM support is compiled in.
- [x] Added builder-VM smoke/failure unit coverage for `dev_build`: the test seam now accepts a fake `BuilderVm`, asserts the flake job and mount shape, proves the path does not probe or invoke host-side Nix, fails closed on builder errors, and gives each staging directory a per-build nonce to avoid same-process collisions.
- [x] Added CLI-level source-checkout policy coverage for `ensure_dev_image`: source dev flakes now require the sibling builder-VM flake, missing libkrun fails before build dispatch, builder failures refuse published-prebuilt fallback, and the installed/prebuilt path remains available only when no source dev flake is detected.
- [x] Hardened builder-VM image bootstrap policy: source checkouts may reuse an existing local builder image cache, but cache misses now fail closed instead of downloading published builder-VM prebuilts that could mask local `nix/images/builder-vm/` changes.
- [x] Added the Stage 0 local builder-image bootstrap path: dev images now carry `/sbin/mvm-builder-init`, `LibkrunBuilderVm` accepts an explicit bootstrap image override, and source-checkout builder-cache misses route to a local `nix/images/builder-vm/` build instead of a network artifact fetch.
- [x] Hardened Stage 0 builder-cache promotion: local builder-image bootstraps now build into a hidden staging directory, validate kernel/rootfs artifacts, and promote into the live cache only after validation succeeds.
- [x] Bound source-checkout builder-image cache reuse to a SHA-256 fingerprint of `nix/images/builder-vm/{flake.nix,flake.lock}`, so stale but structurally valid builder caches are rebuilt instead of masking local source changes.
- [x] Added source-built builder-cache artifact digest metadata; source checkout cache hits now require the fingerprint and cached `vmlinux` / `rootfs.ext4` / optional `cmdline.txt` digests to match before reuse.
- [x] Added safe source-checkout builder-cache diagnostics; verbose output now reports non-sensitive cache decision reason codes such as `hit`, `fingerprint_mismatch`, and `artifact_digest_mismatch`.
- [x] Plan 77 W3: bracketed the Stage 0 builder VM bootstrap with three new `LocalAuditKind` events (`stage0_boot`, `stage0_cache_promoted`, `stage0_failed`) so a contributor can answer "did `dev up` actually run Stage 0, when, and how did it land" after the fact. Failure paths carry a `stage=<build|validate|promote>` tag and a sanitized one-line reason for downstream filtering.
- [x] Plan 77 W2: serialized Stage 0 builder VM bootstraps via an `flock(2)` advisory lock at `~/.cache/mvm/builder-vm/stage0.lock` and folded orphan-staging-dir cleanup into `mvmctl cache prune` (with the same lock so the sweep cannot race a live bootstrap).
- [x] Added source-built builder-cache provenance metadata; source-checkout cache hits now require a non-sensitive provenance summary matching the source fingerprint and artifact filename set, with `missing_provenance` / `provenance_mismatch` diagnostics.
- [x] Added builder-cache readiness to `mvmctl dev status`; it reports source/release cache readiness and safe reason codes without rebuilding or printing local paths, raw artifact digests, or artifact contents.
- [x] Added `mvmctl dev cache inspect` with `--json`; it reports sanitized dev-image presence plus source/release builder-cache readiness without rebuilding, booting, or printing local paths, raw artifact digests, or artifact contents.
- [x] Plan 77 W4: gated `download_builder_vm_image` and its helpers behind the off-by-default `release-artifact-bootstrap` feature so contributor builds cannot reach the published-prebuilt path at compile time, with `perform_builder_vm_download_published_bails_without_feature` locking the structural-failure shape into the test suite.
- [x] Plan 74 W1 mvmd handoff: created the mvmd ADR-0020 tracking issue for OCI ingest consumer policy, pinned the W1.1 `mvm-oci` / `oci_to_rootfs` API surface, and cross-linked the sandbox parity status page to the mvmd tracker.
- [x] Resolved ADR-049's AWS SigV4 substitution open question: Python, TypeScript, and Rust SDK runtime surfaces now expose `register_substitution_handler(name, fn)` plus AWS credential-loading helpers so SigV4 signs resolved credentials instead of placeholders.
- [x] Plan 85 Phase A.2: `mvm-oci` now applies OCI `.wh.<name>` and `.wh..wh..opq` whiteouts without materializing marker files, preserves same-layer entries regardless of tar ordering, and carries the first `cargo-fuzz` unpack harness plus CI lane.
- [x] Plan 85 Phase A.3: `mvm-oci` now accepts tar hardlink entries, materializing same-layer targets as hardlinks, lower-layer targets as full copies, and refusing missing or unsafe targets with audited refusal reasons.
- [x] Plan 85 Phase A.4: `mvm-oci` now preserves allow-listed `SCHILY.xattr.*` pax attributes (`user.*`, `security.capability`, `security.selinux`) through `UnpackOptions::xattr_policy`, drops denied attributes with report warnings, and keeps tar's implicit xattr unpacking disabled.
- [x] Plan 85 Phase A.5: `mvm-oci` now materializes only the allow-listed Linux character devices `dev/null`, `dev/zero`, `dev/random`, and `dev/urandom` with their standard major/minor pairs, records `device_nodes_written`, and refuses every other character/block special file with audit tag `device_node_refused`.
- [x] GitHub #110 follow-up: `mkGuest` now trims the copied kernel module tree to the `vmw_vsock_virtio_transport` dependency closure plus module metadata, keeping the stock-kernel vsock path while removing the hundreds-of-MB rootfs growth from copying every kernel module.
- [x] W1b.1 CI follow-up (2026-05-27): documented the broker subprocess crates structurally in `Cargo.toml` for the architecture invariant (instead of file-path allowlist entries), and hardened the oversized-frame broker server test to accept either EOF or `ECONNRESET` on rejection.
- [x] W1b.2a CI follow-up (2026-05-27): documented the broker subprocess crates structurally in `Cargo.toml` for the architecture invariant (instead of file-path allowlist entries), and hardened the oversized-frame broker server test to accept either EOF or `ECONNRESET` on rejection.
- [x] CI follow-up (2026-05-27): Plan 104 W1b.2b.2 now marks the broker subprocess crates structurally in `Cargo.toml` for the architecture invariant (instead of file-path exceptions), tolerates EOF-or-reset on the oversized-frame rejection test, removes the stale `CommandExt` import in supervisor spawn, and documents the `SecretsProxy` debug carveout for the secret-type lint.
- [x] CI follow-up (2026-05-27): Plan 104 W1b.2b.1 now marks the broker subprocess crates structurally in `Cargo.toml` for the architecture invariant (instead of file-path exceptions), tolerates EOF-or-reset on the oversized-frame rejection test, removes the stale `CommandExt` import in supervisor spawn, and documents the `SecretsProxy` debug carveout for the secret-type lint.
- [x] Plan 85 Phase A.6: `mvm-oci` now preserves regular-file setuid/setgid bits by default with `UnpackReport::setid_entries` audit annotations, refuses them under `SetidPolicy::RefuseUnsigned` with audit tag `E_OCI_SETUID_UNSIGNED`, and marks cosign-verified preservation via `SetidPolicy::PreserveVerified`.
- [x] Plan 85 Phase B foundation: `mvm-build::rootfs::materialize_ext4` now allocates the host sparse rootfs image, sizes it from OCI uncompressed bytes with the 64 MiB floor, and delegates `mkfs.ext4` + copy into the existing libkrun builder VM via a one-shot shell job and attached output disk.
- [x] Plan 85 Phase B smoke scaffold: `mvm-oci` can resolve Linux platform manifests from image indexes, and the gated `oci_image_runner_smoke` test pulls `docker.io/library/alpine:3.20`, unpacks layers, injects a minimal `/init`, materializes ext4 through the builder VM, and boots it through `mvm-libkrun-supervisor` when `MVM_OCI_IMAGE_RUNNER_SMOKE=1` is set.
- [x] Plan 85 Phase C cache inspection: `mvmctl image ls`, `inspect`, and `rm` now operate on the local OCI cache index under `~/.cache/mvm/oci/`, with registry filtering, JSON output, safe path validation, reference-counted layer GC, CLI docs, and audit posture coverage.
- [x] Plan 85 Phase D pull slice: `mvmctl image pull <ref> [--prod]` now resolves the current Linux platform manifest, verifies and caches the manifest/config/layer blobs, unpacks layers through the Plan 85 unpacker, materializes `rootfs.ext4` through the builder VM, and records the result in the local OCI cache index. Production pulls require digest-pinned references.
- [x] Plan 85 Phase D run-image slice: `mvmctl run --image <ref> -- <cmd>...` now resolves or pulls an OCI image through the local cache, emits `ImageFetch` when the composed path performs a pull, boots the cached materialized `rootfs.ext4` with the existing transient runner, and treats `--prod` as OCI production policy requiring a digest-pinned reference before any pull or boot.
- [x] Plan 85 Phase E Claim 10 preview: OCI pulls now persist a provenance JSON sidecar with registry, repo, supplied reference, resolved digest, layer digest list, trust policy, and verification status; `mvmctl run --image` admits a signed plan before launch and writes `plan.oci_provenance` into the audit chain.
- [x] Plan 85 Phase F Claim 10 ship gate: `--prod` OCI pulls and `run --image --prod` now require a digest-pinned reference plus an OCI policy (`MVM_OCI_POLICY` or `$MVM_DATA_DIR/oci-policy.toml`) with allowed registries and trusted cosign keyless identities; the resolved digest is verified with `cosign verify` before cache admission or boot, and missing, invalid, denied, or signature-disabled policies fail closed.
- [x] Plan 85 Phase G registry auth foundation: `mvm-oci` now accepts explicit bearer/basic registry credentials without reading Docker config or shelling out to credential helpers; `mvmctl image pull` and `run --image` resolve bearer tokens from `MVM_OCI_BEARER_TOKEN_<HOST>` or `MVM_OCI_BEARER_TOKEN`, pass them through secret-carrying types, and audit only the credential source name.
- [x] CI follow-up (2026-05-27): fixed the Plan 100 W1 prep `mvm-cli` compile regression by routing the new `nested-kvm` doctor probe through a local helper that degrades cleanly when the `builder-vm` feature is off, so `default-features = false`/packaging builds no longer reference `mvm_build::builder_backend_select`.
- [x] Hardened builder-VM reliability follow-ups from GitHub triage: Stage 0 seed selection now skips cached dev rootfs images that lack `/sbin/mvm-builder-init`, source-built builder VM artifacts must contain that init before promotion, cached builder images fail fast when `cmdline.txt` is missing, libkrun supervisor waits have a bounded `MVM_BUILDER_VM_TIMEOUT_SECS` escape hatch, and flake builds now carry the Nix store-path hash through `/job/store-path` for stable `revision_hash` reuse.
- [x] Resolved spec-number collisions across `specs/plans/` and `specs/adrs/` by renumbering duplicate-prefixed files, updating references, and adding `cargo xtask check-spec-numbers` to CI so future duplicate Plan/ADR prefixes fail before merge.
- [x] Shortened top-level `mvmctl --help` command summaries and added a regression test keeping each summary to 72 characters or less.
- [x] Tightened the public `mvmctl` command surface around the local microVM substrate boundary: removed `deploy`, `policy`, and `tenant` from the Clap tree, deleted their unreachable command modules, and updated the CLI reference with the retained command families. Tenant lifecycle, tenant policy review/update, and deployment to the hosted control plane are now documented as `mvmd` responsibilities.
- [x] GitHub #95 scaffold retarget: narrowed the in-guest DNS / vsock bridge work to local addon developer plumbing (`mvm-addon-dns` + `mvm-addon-vsock-bridge`) and documented that distributed mesh, tenant policy, and cryptographic routing belong in `mvmd`; zone-loader and peer-header/binding tests remain the implementation base.
- [x] GitHub #95 bridge slice: `mvm-addon-vsock-bridge` now loads loopback bindings with explicit `tcp_port`, starts one TCP listener per loopback IP/port, dials the host addon proxy over vsock, writes the peer header before application bytes, and proxies bidirectionally with binding validation and regression coverage.
- [x] GitHub #95 DNS contract correction: `mvm-addon-dns` now treats exact configured production-equivalent hostnames as authoritative instead of requiring `*.addon.local`, preserving application connection strings while forwarding every non-configured name upstream.
- [x] GitHub #95 DNS server slice: `mvm-addon-dns` now has a loopback-only UDP DNS server that answers exact configured A records, forwards non-configured names through an explicit upstream resolver snapshot, refuses non-loopback binds and self-upstreams, and keeps empty-zone no-op behavior.
- [x] GitHub #95 init + reload slice: `mvm-addon-dns` ships a SIGHUP reload path over an `Arc<RwLock<Zone>>` so the live UDP listener swaps records without dropping in-flight queries (malformed/missing zone files leave the previous state intact). `mkGuest` builds `mvm-addon-dns` via `nix/packages/mvm-addon-dns.nix` and bakes it into every rootfs at `/usr/local/bin/mvm-addon-dns`; `/init` activates the supervisor only when a zone file is present, snapshotting `/etc/resolv.conf` into `/run/mvm/upstream-resolv.conf`, bind-mounting `127.0.0.1`/`::1` over `/etc/resolv.conf`, and forking the binary under `setpriv` with ambient/inheritable `CAP_NET_BIND_SERVICE` only. Guests without addons keep the build-time resolv.conf byte-for-byte.
- [x] Hardened `mvmctl secret`: `put` now prompts with hidden interactive input when no value source is supplied and still accepts stdin/file/inline sources, while `get` is now a presence check only and can never print the raw secret value. CLI docs and ADR-042 were updated to reflect the write-only-after-set contract.
- [x] GitHub #109 bootstrap unblock: source-checkout builder-VM cache misses now prefer local Stage 0 dev images but can fall back to the signed/hash-verified published dev image as a seed only, while still refusing to download published builder-VM images so local `nix/images/builder-vm/` changes are built from source.
- [x] Encrypted the file-backed local secret store at rest: `FileSecretStore` now writes only `MVMS1` AES-256-GCM records, refuses legacy plaintext records, keeps its local store key mode 0600, keeps file-backed entries visible in auto backend mode, and tests no-plaintext-on-disk plus tamper rejection.
- [x] Stamped the secret audit contract into both audit sinks: JSONL and chain-signed `secret.*` events now carry `secret_visibility=write_only` and `storage_security=encrypted_at_rest` without exposing secret values.
- [ ] Plan 86 / ADR-054 (in flight): ur-seed Stage –1 bootstrap layer closes the Plan 77 W5 contributor catch-22 (host with no contract-compliant dev image cannot bootstrap a builder VM, and a builder VM cannot be built without a dev image). New `nix/ur-seed/flake.nix` produces a self-contained tarball (musl-static `mvm-builder-init` + busybox-static + full builder-VM package closure + TSI-patched kernel + kernel modules). New `mvmctl dev fetch-ur-seed` (release mirror, opt-in, never auto-invoked) and `mvmctl dev import-ur-seed --from <tarball>` (air-gapped). Stage 0 dispatch order extended to fall through to the ur-seed cache after the dev-image probe; seed-contract validator accepts `image_kind=ur-seed`. `mvm-builder-init` now sets a canonical PATH at PID-1 entry so PATH lookups (`iptables`, etc.) resolve.
- [ ] Plan 86 follow-up (in flight): live ur-seed validation showed the Stage 0 builder cache can exhaust the 64 GiB libkrun virtio-blk store before the source-checkout builder VM image evaluates. The active fix now avoids copying the baked-in `/nix` seed into the persistent disk by preferring an overlay `/nix` mount, adds a `packages.<system>.stage0-rootfs` builder-VM flake output so ur-seed does not build the TSI kernel closure in Stage 0, and has the ur-seed Stage 0 path supply the final libkrunfw kernel from the host cache before promotion. Existing installed ur-seed tarballs still embed the old init, so a refreshed ur-seed artifact is required before the live smoke can prove the full path.
- [x] GitHub #370 builder workspace hardening: `mvm-builder-init` now mounts the libkrun builder VM `work` virtio-fs tag with `MS_RDONLY`, keeping the host workspace read-only from guest builds while leaving `/out` and `/job` writable for artifacts and result metadata. A Linux unit test pins the tag-to-mount-flag policy.
- [x] GitHub #371 builder nix-store serialization: libkrun builder jobs now open/create the shared `nix-store-<arch>.img` with an exclusive host-side file lock before attaching it as a writable virtio-blk disk, hold the lock through supervisor shutdown and artifact finalization, and fail fast with an actionable message when another builder VM already owns the image. Unit coverage pins sparse-image creation and concurrent lock refusal.
- [ ] Plan 87 / ADR-055 (in flight): libkrun networking via passt + virtio-net, replacing the experimental TSI mode that broke nix's substituter and source fetches (HTTP/2 multiplexing, HTTPS redirect chains, the offline-mode probe). New `mvm-libkrun::sys::add_net_unixstream_fd` FFI + host-side `mvm-libkrun::passt::{spawn, PasstHandle}` (socketpair → spawn passt → SIGTERM+grace+SIGKILL Drop). `KrunContext::NetworkingMode { Tsi, Passt { mac, scratch_dir } }`; `run_supervisor` owns the passt child for the libkrun process lifetime. `MVM_NETWORKING={tsi,passt}` env var; default flipped to Passt by Plan 87 PR3. `mvm-cli` keeps `libkrun-sys` opt-in, but the root `mvmctl` binary enables it by default on macOS via a target-gated dep entry (`cfg(target_os = "macos")`) so contributor `cargo run -- dev up` reaches `extract_bundled_kernel()` without a manual `--features libkrun-sys`. `mvmctl doctor` probes for passt and emits a `brew install passt` hint when missing. In-VM wiring: ur-seed flake ships `/etc/udhcpc/default.script` (DHCP → /run/resolv.conf), `/etc/resolv.conf -> /run/resolv.conf` symlink, and a `1.1.1.1`/`8.8.8.8` fallback at `/etc/resolv.conf.fallback`; `mvm-builder-init::setup_network` seeds the fallback before udhcpc runs and passes `-s` to invoke the hook.

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
      Follow-up #223 pins cryptsetup/veritysetup 2.8.6 by release
      tarball hash in both the builder-VM OCI-pull path and the
      Nix-built runtime-overlay baseline so nixpkgs bumps cannot
      silently change sidecar bytes.
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
- [x] **W7.2 (Phase 1.5)** — Lima VM rename `mvm` → `mvm-builder` — landed 2026-04-30; **migration verified done on dev box 2026-05-01** (`limactl list` shows only `mvm-builder`; legacy `mvm` removed). New constants `VM_NAME` / `LEGACY_VM_NAME` in `mvm::config`, six hardcoded literals in `doctor.rs` migrated to the constant, new `bootstrap::warn_if_legacy_lima_vm` detects legacy VM and prints a one-line manual migration command (no auto-rename), wired into both `mvmctl bootstrap` and `mvmctl dev up`. Docs (`AGENTS.md`, `specs/01-project.md`, `specs/runbooks/w3-verified-boot.md`, `public/.../{architecture,troubleshooting}.md`, `crates/mvm/README.md`) updated. 1067 tests pass.
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
| **Hosted MCP transport (HTTP/SSE)** | [`plans/33-hosted-mcp-transport.md`](plans/33-hosted-mcp-transport.md) | Cross-repo: implementation lives in [mvmd](https://github.com/tinylabscom/mvmd). mvm-mcp's `protocol-only` feature is already shipped (PR #20) so mvmd can consume the wire schema unchanged. | mvmd owns sizing |
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
security mitigations: [`plans/81-function-entrypoints-design.md`](plans/81-function-entrypoints-design.md).
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

remote function-call semantics on top of mvm. Decorate a Python
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
- **W7 — Warm-process function dispatch (ADR-0011 tier 2).**  🟡
  in progress  [`plans/43-warm-process-function-dispatch.md`](plans/43-warm-process-function-dispatch.md).
  Adds an opt-in worker pool inside the guest agent so
  function-entrypoint calls can reuse a long-running wrapper
  process across invokes instead of cold-spawning per
  `mvmctl invoke`. Driven by a new mvmforge-owned
  `/etc/mvm/runtime.json` carrying a `concurrency.kind =
  "warm_process"` field (`max_calls_per_worker`, `max_rss_mb`,
  `pool_size`, `in_process`, `max_queue_depth`). When the field
  is absent, the cold path (W2) stays bit-identical. Host wire
  (`RunEntrypoint` + `EntrypointEvent`) is unchanged; the agent
  synthesizes the existing event stream from a single buffered
  framed response per worker call. M12 (one in-flight call per
  VM) is bypassed under warm-process — the new invariant is "one
  in-flight call per worker, ≤ `pool_size` concurrent." The
  `prod-agent-no-exec` symbol gate keeps passing; the plan adds a
  positive-evidence assertion for the new
  `mvm_guest::worker_pool` module. mvm-side only — mvmforge ships
  the IR + factory + runner-wrapper changes in a coordinated
  follow-up (cross-repo ADR-0011).

### Substrate validation (live smoke)

PR #73 adds the substrate-validation infrastructure:

- `mkGuest` `extraFiles` parameter — bakes arbitrary files into
  the rootfs at build time, owned root, with declared octal mode.
  `extraFiles ? {}` default keeps backward compat for every
  existing caller. (Update post-ADR-0010 §3 Option A flip: the
  `mk{Python,Node,Wasm}FunctionService` factories now live in
  this repo at `nix/lib/factories/` and use this to bake
  `/etc/mvm/entrypoint` plus the wrapper.)
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
`RunEntrypoint` substrate; mvmforge consumes it. (Update: ADR-0010
§3 was later amended back to Option A — the factories themselves
landed in this repo at `nix/lib/factories/`; mvmforge consumes them
via `mvm.lib.<system>`.) The cutover is
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
| **Decorationer plan 0003 phase 4 — Nix factories** *(landed in mvm post-Option-A flip; see `nix/lib/factories/`)* | decorationer plan 0003 | `mkPythonFunctionService` / `mkNodeFunctionService` emitting hardened wrappers (mode=prod with sanitized error envelope, `PR_SET_DUMPABLE=0`, no payload logging) at `/etc/mvm/entrypoint` via mvm's `extraFiles` (already in mvm #73). | ~3 days |
| **Session pool management** | follow-up plan (none yet) | Pre-baked invariant: *single-tenant for VM lifetime*. v1 reuses `boot_session_vm` / `dispatch_in_session` / `tear_down_session_vm` primitives directly. Sizing / eviction / per-tenant isolation / idle reaper are real but separable from the substrate. | ~1 sprint |
| **Streaming chunked output** | follow-up plan (none yet) | v1 wire is streaming-shaped but buffered up to 1 MiB per stream. Lifting the cap means real chunked emission from the agent and a streaming consumer in `send_run_entrypoint`. | ~1 week |
| **Schema-bound payloads (v2 of W3)** | decorationer plan 0003 | Derive JSON Schema from type hints (Python `pydantic` / TS `zod`). Wrapper validates inbound bytes before user code runs. | ~1 week |
| **Guest agent signal handling** — W1 + W2 shipped; W3 (SIGHUP config reload) backlog | [`plans/44-agent-signal-handling.md`](plans/44-agent-signal-handling.md) | SIGTERM/SIGINT now flip an atomic flag the accept loop polls, triggering `WorkerPool::shutdown` for an orderly drain. Symbol-contract gate extended with `install_signal_handlers` positive evidence. SIGHUP config reload (W3) unblocks once mvm wants in-place config reload — today the agent has no hot-reloadable config surface, so it's not load-bearing. | ~½ day W1+W2 shipped |

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

## Sprint 46+ — Cross-platform expansion (proposed)  [`plans/53-cross-platform-roadmap.md`](plans/53-cross-platform-roadmap.md)

**Goal:** turn cross-platform support into a coherent multi-platform release without forking the security narrative. Decision recorded in plan 53 as **Option B — Pragmatic**: Firecracker stays the security baseline, Apple Container is the macOS exception, **libkrun** is the only new backend (Intel Mac + macOS-no-Lima), Docker stays as Tier 3 with loud warnings, Windows is first-class via WSL2 with bootstrap automation.

**Why this sprint, why now:** today mvm fully supports Linux + KVM (Firecracker) and macOS 26+ Apple Silicon (Apple Container, plan 23). Older macOS, Intel Macs, and Windows hosts are second-class. The 2026 microVM ecosystem (SlicerVM, libkrun, AWS nested-virt EC2) makes a coherent multi-platform release tractable; we want to land it before the gap widens.

**Three sequential sprint slots:**

- **Sprint 46 — Foundation (~5 days, narrative + UX, zero arch risk).** Plans A (Matryoshka ADR rewrite), B (Doctor security-claims-by-tier output), C (PVM FAQ entry), J (AWS deployment guide), K (Ubicloud deployment guide), plus deferred-backlog placeholder files for Plans F/G/H.
- **Sprint 47 — macOS parity + Windows foundation (~1 sprint).** Plan D (APFS CoW for Apple Container templates) + Plan I.1 (Windows CI lane) + Plan I.2 (Windows install docs, WSL2-first).
- **Sprint 48 — libkrun + Windows installer (~1.5 sprints).** Plan E (libkrun backend — Intel Mac + macOS-no-Lima) + Plan I.3 (winget manifest) + Plan I.4 (WSL2 bootstrap automation). Sprint 48 ships **scaffolding** for libkrun (final API, dispatch, doctor, install hints); the spike phase that lands real C bindings + boot validation is tracked separately in [`plans/57-libkrun-spike.md`](plans/57-libkrun-spike.md).

**Deferred backlog (rationale captured in plan 53):**

- **Plan F — Cloud Hypervisor backend.** *Rejected* for security-posture reasons. Every advantage CH ships (nested KVM in guests, GPU passthrough, larger device model, Windows-guest support) is exactly what Firecracker excluded for attack surface. Adding CH would fork the security narrative. Trigger conditions to revisit are documented in plan 53 §Plan F.
- **Plan G — crosvm backend.** *Deferred.* Niche for our user base; libkrun (Plan E) covers the embeddable cross-platform niche. Trigger: real Chrome OS / Android demand.
- **Plan H — rust-vmm internalization.** *Rejected for now.* Composing rust-vmm crates into a working VMM is *building a VMM*; that's Firecracker's and libkrun's job. Trigger: custom-VMM-required feature.

**Sprint 46+ success criteria (per slot):**

- After Sprint 46: ADR-002 displays the layer model + per-backend tier matrix; `mvmctl doctor` and `mvmctl run` emit the Docker-tier warning banner; AWS + Ubicloud deployment guides published; deferred plans 54/55/56 placeholder files committed.
- After Sprint 47: macOS Apple Container template instantiation <1s via APFS CoW; `cargo build --workspace` green on Windows; Windows install docs (WSL2-first) published.
- After Sprint 48: libkrun runs on Linux + KVM, macOS Apple Silicon (no Lima), and macOS Intel; `winget install mvm` works on Windows; `mvmctl bootstrap` on Windows configures WSL2 + Ubuntu + mvm automatically.

**Non-goals (named explicitly):**

- Cloud Hypervisor backend (Plan F, rejected).
- Promoting Docker to a first-class Windows path via pre-built rootfs distribution (would conflict with the security posture).
- Native-Windows microVMs via Cloud Hypervisor + WHPX (depends on Plan F).
- Eliminating Lima from the macOS *build* path (libkrun solves runtime only; build-on-host is future work).

## Sprint 49 — Filesystem Volumes (sandbox-runtime parity, in flight)

Branch: [`feat/sprint-46-filesystem-volumes`](https://github.com/tinylabscom/mvm/tree/feat/sprint-46-filesystem-volumes) — branch name preserved for PR continuity; the sprint itself was relabeled from 46 to 49 during merge to disambiguate from Sprint 46 (cross-platform foundation, already merged via #97).
Plan: [`plans/45-filesystem-volumes.md`](plans/45-filesystem-volumes.md).
mvmd companion: [`mvmd/specs/plans/29-filesystem-volumes.md`](../../mvmd/specs/plans/29-filesystem-volumes.md) (sister repo — needs corresponding rename).

### Why this sprint

mvm's in-flight share registry (untracked on `feat/sandbox-sdk-foundation`) does not match the established sandbox-runtime Volume primitive shape: those volumes are **named, multi-attach, filesystem-semantics**. We replace the share registry with a `Volume` primitive that ships in mvm-core (wire types) plus a new `mvm-storage` crate (trait + impls for `LocalBackend` + `ObjectStoreBackend` via `opendal`, with mandatory `EncryptedBackend<B>` decorator). mvmd consumes `mvm-storage` via the `mvmctl` git facade and reconciles with its existing `StorageBucket` primitive (see Plan 45 §"Discoveries during implementation" D1).

### Workstream breakdown (mvm-side, post-D5 / Path C)

- **W-Volume — local volume primitive** (Phase 1, 5, 6, 8): `mvm-core` wire types + `mvm-storage` minimal crate (trait + `LocalBackend` only) + `volume_registry.rs` + `mvmctl volume create/ls/rm` (local) + `MountPathPolicy` extension for Nix paths.
- **W-Mount-API — declarative mount at boot** (Phase 7, 10): `mvmctl up --volume <name>:<path>` + `MountVolume`/`UnmountVolume` vsock verbs + `mkGuest.volumeMounts` Nix attrset.
- **W-RemoteClient — `--remote` proxy to mvmd** (new, replaces the dropped W-DataPlane): small `mvmctl::mvmd_client` module (~50–100 LoC, uses workspace `reqwest`). Supports `volume create|ls|rm|cp|read|write|attach|detach|snapshot create|snapshot ls|snapshot restore` against mvmd REST. `~/.mvm/config.toml` `[remote]` section: `endpoint`, `api_key_ref`, `default_org`, `default_workspace`. All optional.
- **W-Doctor — FDE check** (Phase 9): `mvmctl doctor` reports FileVault/LUKS state. **Warns** on dev box (no enforcement); mvmd enforces hard-block on workers.
- **Out-of-scope on mvm side (per D5, moved to mvmd Sprint 137 W2)**: `ObjectStoreBackend` impl, `EncryptedBackend<B>` decorator, AES-256-GCM / AES-SIV / HKDF crypto code, `opendal` dep — all live in mvmd.

### Cross-repo dependency

mvmd Sprint 29 (`mvmd/specs/plans/29-filesystem-volumes.md` — sister repo file needs corresponding rename) follows mvm Plan 45 phases 1-3 landing on `main`. mvmd consumes `mvmctl::storage` via the existing git workspace dep. Decision blocker on the mvmd side: extend `StorageBucket` (recommended) vs. add parallel `FilesystemVolume` — see Plan 45 §D1.

### Sprint 49 success criteria (post-D5 / Path C)

- mvm `volume` CLI replaces `share` CLI with no compat shim (greenfield rename, in-flight share files deleted).
- `mvmctl volume create scratch` (local) round-trips: VM boot with `--volume scratch:/mnt/scratch`; write file from guest; tear down VM; reboot; reattach; file persists. Plus multi-attach proof (two local VMs see same file).
- `mvmctl volume create fixtures --remote --backend s3 --url s3://...` proxies through mvmd REST and returns 200; data plane via `--remote` round-trips against MinIO (mvmd-side integration test, not mvm-side — covered in mvmd Sprint 137 W2).
- `mvmctl doctor` reports FDE state (warns on non-FDE; mvmd-side hard-block tested separately).
- Path safety: `volume cp ../etc/passwd …` rejected; `/nix*` mount denied by `MountPathPolicy`.
- `cargo test --workspace` and `cargo clippy --workspace -- -D warnings` clean.
- All `prod-agent-no-exec`, `cargo deny`, `cargo audit`, fuzz-corpus CI gates green.
- `mvm-storage` crate has minimal deps: `tokio`, `bytes`, `async-trait`, `mvm-core`, `mvm-security`. **No `opendal`, no AEAD crates** — those land in mvmd Sprint 137 W2.

### Phasing

Phases 1-10 in Plan 45's "Implementation order" map to mvm-side work and are all shipped (mvm-core types, `mvm-storage` crate, runtime registry, CLI subcommand, guest vsock verbs, security policy, doctor FDE check, mkGuest extension). Phases 13-18 are mvmd-side (covered in mvmd Sprint 137). Phase 11 (live KVM smoke) is deferred to [Plan 58](plans/58-filesystem-volumes-live-kvm-smoke.md) because it requires real KVM hardware — the deferral is documented so the work isn't lost when Sprint 49 closes.

### Non-goals (named explicitly, see Plan 45 §"Out of scope (v1)")

B1–B18 in Plan 45 §"Out of scope (v1)" — buckets-as-separate-primitive, cross-host backends (NFS/CephFs), mountable provider-backed volumes, hot attach/detach, cross-workspace ACL grants, volume export/import, tags/labels, soft-delete, read cache, webhooks, `data_disk` (plan 38), scheduler volume-affinity, per-volume LUKS, strong-consistency snapshots, HSM/KMS-backed master keys, compression/dedup, usage analytics. Each is preserved in Plan 45 with what/why/trigger so they can be picked up in future sprints.

### Live-KVM smoke (Phase 11 → [Plan 58](plans/58-filesystem-volumes-live-kvm-smoke.md))

Plan 45 Phase 11 (live KVM smoke fixture) deferred to its own plan 58 — needs a KVM-capable host that no longer fits in a software-only PR. Plan 58 captures the six scenarios (single-VM round-trip, persistence, multi-attach, RO enforcement, scope isolation, Nix-path denial) so the work isn't lost when Sprint 49 closes. (Numbered 58 because plan 46 was already taken by the metering-API work merged in #89.)

## Sprint 50 — mvm migration: Phase 0 + Phase 1 (foundation, facade, libkrun backend) — IN FLIGHT  [`plans/60-mvm-libkrun-migration.md`](plans/60-mvm-libkrun-migration.md)

**Status (2026-05-08):** Phase 0 ✅ shipped; Phase 1 W1–W4 ✅ shipped on `feat/micro` (12 commits). The LibkrunBackend is fully wired against upstream libkrun 0.4.5; `auto_select()` picks it as the cross-platform default (macOS arm64/x86_64 + Linux without KVM); the `nix/` flake using microvm.nix is up and `nix flake check --no-build` is clean; the docs site is migrated and refactored to a token-based light+dark mode system; mvmd's contract gate is green against `../mvm` via the local `.cargo/config.toml` patch.

Full plan in [`plans/60-mvm-libkrun-migration.md`](plans/60-mvm-libkrun-migration.md). The plan is checkpointed into 11 phases (0, 1, 2, 3, 4, 5, 6, 7, 7a, 7b, 8, 9, 10) — each with explicit exit tests, ADR coverage, sprint rotation, and a demo gate.

**Branch:** `feat/micro` (moves to `feat/migrate-to-mvm` once Phase 0 settles).

### Why this sprint, why now

The current `mvm` is a 5-crate, ~520-LOC skeleton; the previous iteration at `../mvm` is a mature 13-crate stack. The user wants a clean cut to a libkrun-first build/exec model with feature parity, multi-language SDKs (Rust + Python + TypeScript), encryption-everywhere, attestation-everywhere, audit-everywhere, and a hosted-cloud-ready posture. mvmd depends on the `mvmctl` facade, which we cannot break — Phase 0 protects that contract before any other work.

### Phase 0 exit criteria

- [x] Plan saved to `specs/plans/60-mvm-libkrun-migration.md`
- [x] Sprint 50 documented here in SPRINT.md (this section)
- [x] Phase-0 ADRs stubbed: 013 (libkrun pivot, with microvm.nix fallback), 014 (VmBackend trait), 027 (iroh encryption layering), 031 (cross-platform strategy), 032 (hosted-cloud invariants), 033 (code-quality enforcement), 035 (feature flag taxonomy), 038 (CI execution policy)
- [x] Compliance doc stubs: `specs/compliance/{soc2-controls,pci-scope,hipaa-mapping,gdpr-mapping}.md`
- [x] Root `Cargo.toml` workspace block rewritten with full crate list + feature flags + workspace lints (`too_many_arguments = "deny"`). Workspace lint landed on `feat/cloud-hypervisor-lifecycle` — `[workspace.lints.clippy] too_many_arguments = "deny"` plus `[lints] workspace = true` opt-in in every crate's Cargo.toml.
- [x] `mvm-core`, `mvm-storage`, `mvm-plan`, `mvm-policy`, `mvm-security` ported from previous iteration; all present under `crates/`.
- [x] `src/lib.rs` facade re-exports every workspace crate (`pub use mvm_core as core;` etc.); post-W8 also re-exports `mvm_backend as backend`.
- [x] `mvm-backend/`, `mvm-providers/` are real crates with concrete impls now (W7/W8 ended the façade-only state). The "removed" wording in the original criterion meant "no longer skeleton-only" — true.
- [x] CI matrix runs Linux (every PR, `ci.yml`), macOS (release-tag pushes per ADR-038, `release.yml`), Windows (separate `windows.yml`, informational/non-blocking until WSL2 bootstrap closes the unix-isms list).
- [x] `xtask check-adr-coverage` implemented (`xtask/src/check_adr_coverage.rs`); wired into `ci.yml` as informational (`continue-on-error: true`) — the workspace carries ~12 forward references to unwritten ADRs from the compliance doc stubs that would block a hard gate today.
- [ ] **mvmd contract gate**: `cd ../mvmd && cargo build --workspace` blocked by pre-existing `libkrun 0.4.5` ⊥ `iroh-base 0.96.1` over `sha2` (same blocker as every prior slice). Targeted package builds + manual surface audit confirm every `mvmctl::*` path mvmd imports still resolves; the contract is preserved in shape, the gate just can't execute end-to-end until the upstream dep conflict resolves.

### Wave plan (each wave is a checkpoint)

**Phase 0 — foundation + facade preservation:**

- **W0.1** ✅ — metadata + 7 Phase-0 ADR stubs + 4 compliance stubs (`343abfa`)
- **W0.1.1** ✅ — CI execution policy (push → ci.yml; release → rest) + githooks tracked + ADR-038 (`5318567`)
- **W0.2** ✅ — workspace reshape: 13 crates from `../mvm` verbatim + facade preserved + mvmd contract gate green (`1c3e00c`)

**Phase 1 — first tracer bullet (libkrun backend):**

- **W1.1** ✅ — LibkrunBackend variant in `AnyBackend` + dispatch + 11 unit tests (`8c7211d`)
- **W1.2** ✅ — `libkrun = "0.4.5"` workspace dep wired; 4 of 6 lifecycle methods real (`is_available` / `list` / `status` / `stop` / `stop_all`); resources/ imported; 244/244 lib tests green (`4072484`)
- **W1.3** ✅ — `start()` and `logs()` real; `.ext4 → .raw` hard-link bridge via `ensure_libkrun_rootfs_alias()`; 2 new alias unit tests (`a8cb2e7`)
- **W1.3.1** ✅ — no-OCI invariant codified in ADR-013 + plan 60 (`c1d5b01`)
- **W2** ✅ — `auto_select()` priority slots Libkrun at #2 (cross-platform default per ADR-013); `Platform::has_libkrun()`; docs site migrated; `tailwind.css` + `custom.css` refactored to token-based light+dark mode (no hardcoded colors except the macOS-Aqua terminal-dot trio); ADR-013 docs page (`3438a24`, `6261bc4`)
- **W3** ✅ — `tests/smoke_libkrun.rs` with `MVM_LIVE_SMOKE=1` gate; live test exercises start/stop/alias bridge against a real `mkfs.ext4` fixture; sanity test always runs (`0668c60`)
- **W4** ✅ — `nix/flake.nix` imports microvm.nix; `nix/profiles/minimal.nix`; `nix flake check --no-build` clean; 3 structural tests guard the flake's shape; "Building MicroVM Images" docs page (`5a9b765`)
- **W4-fix** ✅ — reframe: flake is a library, users keep their own `flake.nix` + `mvm.toml`; `lib.<system>.mkGuest` placeholder; internal fixtures renamed `internal-minimal-*`; docs rewritten user-flake-centric (`c323140`)
- **W5** ✅ — real `mkGuest` in `nix/lib/mk-guest.nix` + `nix/lib/default.nix`. Three entrypoint forms (`shell` / `command` / `services`) with sealed-vs-accessible auto-inferred from form (or explicit `dev` override). Same flake works for both modes — the builder writes `passthru.mvm.{accessible, sealed, entrypointKind}` and `/etc/mvm/variant` so `mvmctl console` can gate. `nix/tests/mk-guest-eval.nix` validates the inference. Rust shell-out test runs the eval when nix is on PATH; skips silently otherwise.
- **W5-perf** ✅ — ADR-013 amended with per-backend boot-time budgets and the busybox-as-PID-1 architectural commitment. NixOS+systemd is too slow (1-3s on Firecracker); the previous iteration's busybox path approached the upstream Firecracker reference of ~125ms. Sprint perf gates pinned: Firecracker ≤200ms, libkrun/libkrun ≤500ms, Apple Container ≤1s. (`a5fa7d2`)
- **W5.1** ✅ — `mkGuest` rewritten end-to-end: NixOS+systemd path replaced with hand-rolled busybox-as-PID-1. Static `pkgsStatic.busybox` PID 1, custom `/init` script (POSIX sh, no bashisms) that mounts pseudofs + tmpfs and execs the rendered entrypoint. ext4 image emitted via `nixpkgs/nixos/lib/make-ext4-fs.nix`. `passthru.mvm.{initSystem, expectedBootMs}` exposed for CI gates. 9/9 nix-eval assertions green; user-facing surface unchanged.
- **W5.2** ✅ — crate-layout cleanup: collapsed `mvm-libkrun` + `mvm-apple-container` into a single **`mvm-providers`** crate (FFI/SDK shim layer); created **`mvm-backend`** as a thin re-export façade for the dispatch types (`AnyBackend`, `FirecrackerConfig`). The concrete backend impls (`firecracker.rs`, `libkrun.rs`, etc.) stay under `mvm/src/vm/` for now because they reach into `mvm::{config, shell, ui, vm::microvm, vm::image}` at compile time — extracting them needs those modules to move down to a shared crate first. ADR-012 amended with a disambiguation note distinguishing the public Provider concept (mvmd) from the internal `mvm-providers` shim crate (mvm). 1788+ tests still green.

- **W6** ✅ — end-to-end boot smoke harness landed: `tests/smoke_e2e_boot.rs` boots a real Nix-built rootfs through `LibkrunBackend::start_with_mode`, asserts the sandbox shows up in `list()`, measures cold-boot wall-clock, and tears down clean. **Cross-platform**: runs on Linux/KVM and macOS/HVF (libkrun's libkrun supports both); Windows excluded only because libkrun's Windows path isn't wired (ADR-031). Gated by `MVM_LIVE_SMOKE=1` + `MVM_TEST_ROOTFS=/path/to/rootfs.ext4`; skips silently otherwise. Single-shot tripwire 2× the ADR floor (= 600ms); the strict statistical gate (`xtask perf --runs 100`) lands in Phase 9. ADR-013 boot budget tightened to a unified **≤ 300 ms cold p50 floor across every backend**; mkGuest's `passthru.mvm.expectedBootMs` and the docs page table updated to match. 9 nix-eval assertions + 4 structural tests + 3 smoke tests all green.

- **W6.1** ✅ (rootless half) — privilege-drop infrastructure landed in mkGuest. `setpriv --reuid + --regid + --clear-groups + --no-new-privs` wraps the entrypoint `exec` line; `/etc/passwd`/`/etc/group` get baked with the agent + worker rows; `passthru.mvm.{uids, rootlessEntrypoint}` surfaces the resolved values. Defaults: dev → entrypoint uid 0 (debug shell ergonomics: `apt install`, `mount`, etc.); prod → entrypoint uid 1000 (rootless workload per ADR-002 W2.1); agent always uid 990. Override knob `uids = { agent = N; entrypoint = M; }` for either direction. ADR-013 amended with the privilege model + the dev/prod default rationale; docs page gets a "Rootless workloads" section. 15/15 nix-eval assertions green (6 new); +6 since the previous wave.
- **W6.1.1** ✅ (supervision pattern + stub agent) — `/init` now forks the agent in the background under setpriv→uid 990 before setpriv-exec'ing the entrypoint. The agent binary at `/usr/local/bin/mvm-guest-agent` is a placeholder stub (sh script that logs startup and sleeps) — the real Rust binary swap is W6.1.2 (needs cross-compile infrastructure). Every derivation surfaces `passthru.mvm.agentBinary = "stub" | "real"` so production deployments can refuse to boot stub images via policy lint (lands later). 16/16 nix-eval assertions green (1 new for agentBinary metadata). ADR-013 §"Guest agent supervision" + the docs page agent-status note land in this wave.
- **W6.x — Lima removal** ✅ — `crates/mvm/src/vm/lima.rs` deleted (the 130-LOC Lima integration); `lima_state.rs` deleted entirely (zero callers); `Platform::needs_lima()` now permanently returns `false` (existing `if needs_lima() { … }` branches become dead code, prune in a follow-up); `vm/lima.rs` re-added as a thin no-op shim so mvm-cli imports keep compiling (every fn `Ok(NotFound)` / `Ok(())`); `auto_select`'s confusing "Firecracker via Lima fallback" #6 step rewritten as "production-target default reachable only in narrow feature-gating cases." ADR-013 amended with a substantial new section, **§"Linux builder via libkrun (no Lima)"**, naming the design: on macOS hosts without a configured Linux builder, mvm bootstraps one in a libkrun sandbox (OCI image; Nix store bind-mounted; artifacts extracted back to host). The OCI carve-out is consistent with the runtime non-goal — builders live in a different trust zone than runtime. install/macos.md updated to "zero-config default; existing builder still honored." Real libkrun-builder implementation is its own follow-up wave.
- **W6.y — Cloud Hypervisor stub backend** ✅ — `crates/mvm/src/vm/cloud_hypervisor.rs` ships the stub `CloudHypervisorBackend: VmBackend` with the final shape (capabilities = pause+resume+snapshots+vsock+tap, security profile = Tier 1 with claim-3 partial, `is_available` reads `Platform::has_cloud_hypervisor`). Wired into `AnyBackend::CloudHypervisor` + `from_hypervisor` matcher (`cloud-hypervisor` / `cloud_hypervisor` / `ch` / `clh` aliases). `auto_select` is unchanged — Firecracker stays the default for KVM hosts; CH is opt-in for workloads that need VFIO/GPU/virtio-fs/larger guests beyond what Firecracker supports. ADR-013 gains §"Cloud Hypervisor as a Tier 1 peer of Firecracker" carrying the rationale + the tier classification + the schedule bump (CH was post-Phase-10 in the original plan; user asked for backend flexibility, so it's now near-term). 9 new dispatch + capability + alias tests; 0 fail across the workspace.

- **W6.2 — `mvmctl console` accessible/sealed gate (skeleton)** ✅ — new `crates/mvm/src/vm/runtime_meta.rs` (backend-agnostic `VmRuntimeMeta { mode, accessible }` struct + serde + `read`/`write` helpers; backward-compat parsing of pre-W6.2 `{"mode":"…"}` files as `accessible: true`). `commands/vm/console.rs` gains `--force` clap arg + `enforce_accessible_gate(name, force)` called before any vsock attach. Refusal message names the cause and points at `--force`. 4 new gate tests under `accessible_gate_tests` + 5 round-trip tests on the meta module. Libkrun's `record_start_mode` delegates to the new shared module.
- **W7.x.1 — libkrun-as-Linux-builder Wave 1 (contract scaffolding)** ✅ — new `crates/mvm-build/src/builder_vm.rs` with pinned `BUILDER_OCI_IMAGE = "docker.io/nixos/nix:2.24.10"`, contract types (`BuilderMounts`, `BuilderJob`, `BuilderArtifacts { …, accessible: Option<bool> }`), `BuilderVm` trait matching ADR-013's 6-step flow, and `StubBuilderVm` returning `BuilderVmError::NotYetImplemented` with an error message that names ADR-013 + the recovery path (host Nix or `nix-darwin`'s linux-builder). 6 unit tests. `thiserror = "1"` added to mvm-build deps.
- **W6.2 ↔ W7.x.1 sidecar bridge** ✅ — `ArtifactManifest` struct in `builder_vm.rs` mirrors `passthru.mvm` exactly (camelCase wire format → byte-identical to `nix eval --json $flake#…passthru.mvm`); `write_to_dir` / `read_from_dir` helpers; `runtime_meta::from_sidecar(mode, rootfs_dir)` reads sidecar, defaults to `accessible: true` if absent, propagates errors only on malformed JSON. The sidecar is the courier carrying the accessible flag from build-time Nix metadata to runtime — see the explanation block below.
- **W6.2.1 — sidecar producer + cross-backend consumer wired** ✅ — public `mvm_build::builder_vm::emit_sidecar_via_passthru_query(env, attr, build_dir, dev_override, impure_flag)` runs `nix eval --json …passthru.mvm` and writes `<build_dir>/mvm-meta.json`. Called from both `pipeline::dev_build` (mvmctl path) and `backend::host::HostBackend::extract_artifacts` (mvmd pool path). Public `runtime_meta::record_from_rootfs(name, mode, rootfs)` writes the sidecar's `accessible` into per-VM `mode.json`. Wired into `LibkrunBackend::start_with_mode`, `FirecrackerBackend::start`, `AppleContainerBackend::start`, `LibkrunBackend::start` — all four real backends now honor the gate consistently. CloudHypervisorBackend stub is skipped until its real lifecycle lands.
- **W6.2.2 — `BuildMode::{Dev, Prod}` (command dictates posture)** ✅ — `dev_build` signature gains `mode: BuildMode`; `dev_override_flags` returns `""` for Prod (no `--override-input mvm`, no `--impure`, prod guest agent without `do_exec`, sealed image). All `dev_build` callers (`vm::up::run` x2, `commands::build::build`, `vm::template::lifecycle` x2) pass `BuildMode::Prod` by default. Mirrors the auto-memory rule "image composition is transparent — invocation context, not flake state." Behavior change: `mvmctl up <flake>` now produces a sealed image and `mvmctl console` refuses on it (CLAUDE.md security claim 4 is finally true at runtime, not just at the CI gate).
- **W6.2.3 — `--dev` / `--prod` CLI flags** ✅ — new `commands/shared/build_mode.rs` with `BuildModeFlags` (clap-flatten-able, mutually exclusive). `mvmctl up` and `mvmctl build` embed the struct. `--dev` opts into Dev posture for debugging; `--prod` is explicit (same as default). Clap rejects `--dev --prod`. 4 parser-level tests + 3 resolver tests.

**The W6.2 → W7 data flow now runs end-to-end:**
```
Nix derivation passthru.mvm        (build time, in the flake's mkGuest)
   ↓ emit_sidecar_via_passthru_query (nix eval --json)
<build_dir>/mvm-meta.json           (sidecar — courier file)
   ↓ VmBackend::start (any of 4 real backends)
   ↓ runtime_meta::record_from_rootfs
~/.mvm/vms/<name>/mode.json         (per-running-VM state)
   ↓ mvmctl console
   ↓ enforce_accessible_gate
refuse if accessible: false         (W6.2 gate fires; --force overrides)
```

**Working tree state at session end (2026-05-08, all uncommitted):** 11 logical changesets sitting on `feat/micro`. Build clean, `cargo clippy --workspace --all-targets -- -D warnings` clean, `cargo test --workspace` clean (one pre-existing parallel-env-var flake in `mvm-core::config::tests::test_mvm_cache_dir_env_override` re-runs deterministic; not introduced here). Plus uncommitted plan-62 docs additions and Lima dead-branch cleanup.

### Up next (in priority order — for the fresh session picking this up)

#### Phase 1 close-out (the remaining gates for the migration plan-60 Phase 1 demo)
- [x] **W7 — backend extraction (alt backends + handle registry)** ✅ — landed on `feat/w7-backend-extraction` (4 commits, 2026-05-10). New `mvm-base` crate carries the leaf substrate (`ui`, `runtime_meta`, `cow`); the 5 alt backends (`apple_container`, `cloud_hypervisor`, `docker`, `libkrun`, `libkrun`) moved out of `mvm/src/vm/` into `mvm-backend/src/`; the dependency direction flipped from `mvm-backend → mvm` (re-export façade) to `mvm → mvm-backend` (consumer). Handle registry in `mvm-backend::handle_registry` closes the W6.2-era gap where `StartMode::Attached` was intent-only metadata: `mvmctl up --attached` now teardowns the sandbox on Ctrl-C via the CLI's existing top-level signal handler. `cargo test --workspace --no-fail-fast` 1895/0; clippy clean. mvmd contract gate not run (pre-existing `libkrun 0.4.5` ⊥ `iroh-base 0.96.1` over `sha2`).
- [x] **W6.1.2 — cross-compile real `mvm-guest-agent` Rust binary** ✅ — landed on `feat/w6.1.2-real-guest-agent` (1 commit, 2026-05-10). New `nix/packages/mvm-guest-agent.nix` runs `rustPlatform.buildRustPackage` against the workspace at `mvmSrc` (threaded through `nix/flake.nix → nix/lib/default.nix → nix/lib/mk-guest.nix` via `self`), builds `mvm-guest-agent` + `mvm-seccomp-apply` + `mvm-verity-init` from the `mvm-guest` Cargo target. `mk-guest.nix`'s `agentBinary` attr swapped from the sh-stub to `${guestAgentPkg}/bin/mvm-guest-agent`. `withDevShell = isDev` ties the `dev-shell` Cargo feature to the same toggle that controls `accessible`/`sealed` — dev images get `do_exec`, prod images don't (preserving the `prod-agent-no-exec` CI gate from ADR-002 §W4.3). `passthru.mvm.agentBinary` flipped `"stub"` → `"real"`. Eval test in `nix/tests/mk-guest-eval.nix` updated. New passthru exports `guestAgentPkg`, `seccompApplyBinary`, `verityInitBinary` for the seccomp/verity wiring follow-ups (W2.4 and W3 own those sites). `cargo test --workspace --no-fail-fast` 1895/0 — no Rust-side deltas.
- [x] **W8.A + W8.B — Firecracker stack relocation** ✅ — landed on `feat/w8-firecracker-direct-launch` (4 commits, 2026-05-10). The split scope reflects what was actually load-bearing vs. dead:
    - **W8.A** (`ccfb27d`) deleted truly-unreachable Lima symbols that W7 missed: `linux_env::LimaEnv` + impl, `config::{render_lima_yaml, render_lima_yaml_with, LimaRenderOptions, find_lima_template}`, `config::LEGACY_VM_NAME`, `resources/lima.yaml.tera`, `mvm`'s `tera` dep, plus updates to stale "inside the Lima VM" doc comments. Revealed that the runtime path was *already* Lima-free since W7 — `create_linux_env` returns `NativeEnv` or `AppleContainerEnv`, never Lima — so the "Firecracker direct-launch rewrite" framed in the original W8 description was unnecessary. The shell + linux_env + Firecracker stack already runs on the host directly via `bash -c`.
    - **W8.B** (`46e19cb` + `4cec0c5`) finished the architectural goal: every concrete `VmBackend` impl now lives in `mvm-backend`. Substrate moved to `mvm-base` (`config`, `shell/`, `linux_env`, plus a new `snapshot_integrity` lifted from `template::lifecycle`); the FC stack moved to `mvm-backend` (`firecracker`, `microvm`, `microvm_nix`, `network`, `image`, `backend`); 17 files in `mvm-cli` + 3 in `mvm` + 2 root-tree smoke tests migrated to `mvm_backend::*` imports; `mvmctl::backend` facade re-export added so the public surface mirrors `mvmctl::core` / `mvmctl::runtime`.
    - Re-exports kept for back-compat: `mvm::{config, linux_env, shell, ui, shell_mock}` (mvmd consumes `mvmctl::runtime::shell` etc. from ~30 files) and `mvm::vm::{cow, runtime_meta}` (mvmd's W6.2 console gate). Removing them would force a sibling-repo update.
    - `cargo test --workspace --no-fail-fast` 1884 / 0; clippy clean. mvmd contract gate not run — pre-existing `libkrun 0.4.5` ⊥ `iroh-base 0.96.1` over `sha2` blocker (same as W7); manual audit confirms every `mvmctl::*` path mvmd imports still resolves to the same shape.
- [x] **W8.C — Wire `mvmctl dev` on Linux+KVM** ✅ — landed on `feat/w8c-dev-mode-linux` (1 commit, 2026-05-10). New `commands/env/linux_native` module (130 LOC) treats the host shell as the dev environment: `dev up` runs the W8.B-relocated `mvm_backend::firecracker::install`/`download_assets`/`prepare_rootfs`, prints "ready", and optionally spawns `$SHELL -i`; `dev down` is a no-op (the host is the environment); `dev shell` spawns `$SHELL -i`; `dev status` reports `/dev/kvm`, Firecracker, and asset state with a kvm-group hint when `/dev/kvm` is missing. The `DevBackend` selector enum in `commands/env/dev.rs` now branches three ways — `AppleContainer` (macOS 26+ AS), `LinuxKvm` (Linux/WSL2 with /dev/kvm), `Unsupported` (everything else). `bail_no_dev_backend()` updated to point macOS Intel / pre-26 / no-KVM Linux / Windows at the W7.x.2 libkrun-builder-VM follow-up, the planned home for those hosts. `cargo test --workspace --no-fail-fast` 1884/0; clippy clean.
- [x] **W6.1.2 — cross-compile real `mvm-guest-agent` Rust binary** ✅ — landed on `feat/w6.1.2-real-guest-agent` (1 commit, 2026-05-10). New `nix/packages/mvm-guest-agent.nix` runs `rustPlatform.buildRustPackage` against the workspace at `mvmSrc` (threaded through `nix/flake.nix → nix/lib/default.nix → nix/lib/mk-guest.nix` via `self`), builds `mvm-guest-agent` + `mvm-seccomp-apply` + `mvm-verity-init` from the `mvm-guest` Cargo target. `mk-guest.nix`'s `agentBinary` attr swapped from the sh-stub to `${guestAgentPkg}/bin/mvm-guest-agent`. `withDevShell = isDev` ties the `dev-shell` Cargo feature to the same toggle that controls `accessible`/`sealed` — dev images get `do_exec`, prod images don't (preserving the `prod-agent-no-exec` CI gate from ADR-002 §W4.3). `passthru.mvm.agentBinary` flipped `"stub"` → `"real"`. Eval test in `nix/tests/mk-guest-eval.nix` updated. New passthru exports `guestAgentPkg`, `seccompApplyBinary`, `verityInitBinary` for the seccomp/verity wiring follow-ups (W2.4 and W3 own those sites). `cargo test --workspace --no-fail-fast` 1895/0 — no Rust-side deltas.
- [ ] **Phase 1 close-out** — demo run + checkpoint review against `mvm` Phase 1 exit tests in plan 60.

#### Architectural completion of W6.2.x (smaller follow-ups)
- [x] **W6.2.3 follow-up — BuildMode round-trips on manifest builds** ✅ — landed on `feat/w6.2.3-template-buildmode` (1 commit, 2026-05-10). The original framing referenced `mvmctl template build`, but that namespace was retired in plan 38; the surviving entry point is `mvmctl build <manifest>` via `template_build_from_manifest`. Threading: `mode: BuildMode` arg added; `commands/build/build.rs` passes `args.build_mode.resolve()` through `build_manifest` → `template_build_from_manifest` → `dev_build`. Persistence: `TemplateRevision` gains `Option<String> build_mode` (serialized `"dev"`/`"prod"`; absent on pre-W6.2.3 records, deserialised as `None`). Doesn't participate in `cache_key()` — that stays `flake_lock + profile`, matching the rule that the key identifies "what would Nix build," not "in what posture." Cleanup: the by-id `template_build` / `template_build_with_snapshot` / `cleanup_snapshot_vm` helpers had no callers (plan 38 retired their CLI consumers) and were deleted (~420 LOC); the orphaned `vm_exec_stdout` helper went too. 3 new tests; `cargo test --workspace --no-fail-fast` 1898/0; clippy clean.
- [x] **W7.x.2 — libkrun-as-Linux-builder Wave 2 (real impl)** ✅ — landed on `feat/w7x2-libkrun-builder-vm` (1 commit, 2026-05-10). `LibkrunBuilderVm` in `mvm-build/src/builder_vm.rs` replaces the `StubBuilderVm`-as-only-impl pattern: pulls `docker.io/nixos/nix:2.24.10` via libkrun's `PullPolicy::IfMissing`, spawns a sandbox with the three ADR-013 bind-mounts (`/work` ← flake src RO, `/nix` ← host store RW when present, `/out` ← writable artifact dir), runs `nix build` via `sandbox.shell()`, copies the resolved store path's artifacts to `/out`, and reads the sidecar to populate `accessible`. Defaults: 4 vCPU / 4 GiB; `with_resources(cpus, mem_mib)` override. `dev_build` got a `env_has_nix` probe at the top — falls through to the new `dev_build_via_libkrun` helper when nix isn't on the env channel. The fallback makes `mvmctl build` work on macOS Intel / pre-26 / no-KVM Linux without host Nix; on those hosts the user gets a sealed image equivalent to a Prod-mode host build (the Dev-mode `--override-input mvm git+file://...` override is host-Nix-specific; threading it through to the builder VM is a follow-up). 11 new tests; `cargo test --workspace --no-fail-fast` 1895/0; clippy clean.
- [x] **CloudHypervisor real lifecycle** ✅ — landed on `feat/cloud-hypervisor-lifecycle-real` (1 commit, 2026-05-11). New `crates/mvm-backend/src/ch_runtime.rs` (~280 LOC) wraps Cloud Hypervisor's JSON-over-Unix-socket API behind sync helpers: `start_ch_daemon` spawns the daemon nohup-setsid; `api_put`/`api_put_empty` shell-out to `curl --unix-socket` (same pattern as `microvm::api_put_socket`); `build_vm_config(VmConfigArgs)` produces the `PUT /api/v1/vm.create` body as a pure function; `is_pid_alive` + `reap` + `list_ch_vms` close the lifecycle loop. `CloudHypervisorBackend::start` wires `record_from_rootfs` (W6.2 console gate consistency); `stop` does graceful `vm.shutdown` → `vmm.shutdown` → SIGTERM-cleanup; `status`/`list` walk the per-VM dirs under `VMS_DIR` looking for `ch.pid` (the discriminator vs FC's `fc.pid`). Same commit also collapsed `ci.yml`'s 7 PR-time jobs to 5 by folding `fmt` + `clippy` + `check-adr-coverage` into a single `lint` runner — ~3 min wall-clock + 2 runner-minutes saved per PR. **Untested-without-Linux+CH-host caveat**: mvm CI has no Linux+CH runner, so the spawn-dance and shell-out paths are reviewed against CH's published API but unrun. Pure pieces (JSON config builder, path helpers, JSON-string escaping) carry 8 unit tests. Out of scope and named in-doc: TAP networking (`tap_networking: false` in capabilities), snapshot/restore, dm-verity, rich `run-info.json`. `cargo test --workspace --no-fail-fast` 1913/0; clippy clean.

#### Smaller cleanup items (mechanical, low-risk)
- [x] **Lima dead-symbol sweep** ✅ — slice 2 of W7 deleted `Platform::needs_lima`, `bootstrap::{is_lima_required, ensure_lima, install_lima_linux, warn_if_legacy_lima_vm}`, `shell::inside_lima`, `vm/lima.rs`, the Lima branches in `commands/env/{bootstrap, dev, setup, uninstall}.rs`, the Lima checks in `commands/build/{build, validate}.rs`, and the orphaned `commands/env/shell.rs::open_shell` (Lima-only) + `shared::format::shell_escape` (its only consumer). `mvmctl dev` on non-Apple-Container hosts now bails with a clear W8 reference.

### Sidecar manifest — the W6.2 ↔ W7 courier (key concept for the fresh session)

A "sidecar" is a small metadata file written next to the primary build artifact. We use `mvm-meta.json` next to `rootfs.ext4` as the courier carrying `passthru.mvm` (Nix-evaluation metadata) into the runtime path without requiring the runtime to invoke Nix or mount the rootfs. The shape mirrors `mkGuest`'s `passthru.mvm` exactly so a future `nix eval --json` consumer can dump straight into the struct. Lives at `crates/mvm-build/src/builder_vm.rs::ArtifactManifest`.

Two reasons we use a sidecar instead of embedding the metadata inside the rootfs:
1. **Host reads it without mounting the rootfs.** `mvmctl console` runs on the host before the VM boots; mounting an ext4 image on macOS or Linux-without-root is awkward.
2. **Atomic with the artifact.** Same directory, same build step. A stale sidecar paired with a wrong rootfs is impossible.

### Sprint 49 ↔ Sprint 50 convergence (volumes / mvm-storage)

Sprint 49 (plan 45 — filesystem volumes) is shipping in parallel on `feat/sprint-46-filesystem-volumes`. Its mvm-side deliverables overlap Phase 2 of this migration:

- New crate `mvm-storage` with `VolumeBackend` trait + `LocalBackend` impl + generic contract test suite
- `mvm-core::volume` wire types (`OrgId`, `WorkspaceId`, `Volume`, `VolumeName`, `VolumeBackendConfig`, `ObjectStoreSpec`, `WrappedKey`)
- `mvm::vm::volume_registry` (replaces `share_registry`; spawns virtiofsd)
- vsock `MountVolume` / `UnmountVolume` verbs replacing `MountShare` / `UnmountShare`
- `mvmctl volume create|ls|rm` + `mvmctl up --volume <name>:<path>`
- `mvm-security::policy::VolumeNamePolicy` + `MountPathPolicy` `/nix*` deny extension
- `mkGuest.volumeMounts` Nix attrset surfacing into the boot manifest

**Convergence rule:** when Sprint 49 lands on `main`, the migration plan's Phase 2 (encryption everywhere + volumes) absorbs plan 45's mvm-side artifacts as-is — we do **not** re-derive `mvm-storage` or volume types from `../mvm/crates/`. The migration's Phase 2 work then becomes additive: AEAD-encrypted snapshots layer on top of `VolumeBackend`; key rotation reuses plan 45's `WrappedKey` shape; FDE doctor check folds into Phase 9.

Backend tier matrix gap closed simultaneously: ADR-002 now lists Cloud Hypervisor (Tier 1 peer of Firecracker — wider device model, VFIO/GPU/virtio-fs) and libkrun / libkrun (Tier 2, cross-platform default per ADR-013). Plan 45's `LocalBackend` mounts via virtiofsd; CH's wider device model is what makes virtio-fs natively viable on the Tier 1 path.

### Cornerstones

- Facade preservation is the single load-bearing constraint of Phase 0
- ADR coverage is enforced in CI from the start (no architectural drift without an ADR)
- Cross-platform CI matrix (Linux + macOS + Windows) lands now so Phase 7b's TypeScript SDK + computer-use don't surprise us

### Non-goals (explicit)

- Libkrun integration (Phase 1)
- Encryption + key rotation (Phase 2)
- Network isolation (Phase 3)
- Any user-facing CLI surface beyond `--help`/`--version` (Phase 1+)
- mvm-studio (Tauri) wiring (Phase 5)

## Sprint 51 — close the v1→v2 refactor (in flight)  [`plans/60-mvm-libkrun-migration.md`](plans/60-mvm-libkrun-migration.md), [`plans/63-phase-2-encryption-everywhere.md`](plans/63-phase-2-encryption-everywhere.md), [`plans/64-supervisor-wiring.md`](plans/64-supervisor-wiring.md)

**Goal:** finish every remaining plan that the v1→v2 refactor
depends on, so the campaign can declare itself closed. Sprint 50
landed Phase 0 + 1 of the migration; Sprint 51 carries the
remaining plan-60 phases, the closed-form plans the supervisor /
encryption / signal threads needed, and the function-call surface
that mvmforge depends on.

**Status (2026-05-11 — evening, after batch 2):** 10 + 15 = 25
commits landed on `origin/main` across two focused batches.
The morning batch (batch 1) closed four plans (64, 63, 62, 44)
and the plan-60 Phase 6 policy-bundle TOML substrate. The
evening batch (batch 2) closed plan-60 Phase 6 hardware
attestation, plan-60 Phase 3 Slices A + B + four resolver-
tightening follow-ons (live L4Gate, hooked W5 resolver into
`admit_plan_for_boot`, full L7 inspector chain,
LiveArtifactCollector, fail-loud `disabled_inspectors`,
LiveKeystoreReleaser, bundle.pii wiring), the plan-60 Phase 4
`audit_total_coverage` scaffold with recursive per-subgroup
classification, plan-60 Phase 4 audit-stream URL-shape
validation, and 9 live drive-and-assert audit-emission tests
covering cache / network / manifest / secret subcommands.
Workspace now at **2311 tests / 0 failed**; clippy
`-D warnings` clean; nightly fmt clean; xtask
`check-no-display-on-secret-types` clean. CLAUDE.md
security claims 1–8 all true on every host. ADR-041 (signed +
audited `ExecutionPlan`) and ADR-042 (encryption substrate)
document the closed surfaces. Remaining work covers Phase 3
Slice C (smoltcp/TUN + firewall + DNS endpoint), Phase 4 audit
end-to-end drive-and-assert promotion + `bundle.audit` wiring,
Phases 5 / 7 through 10, plans 48/49/51/52 (function-call
surface), plan 61 (overlays + billing), and the partial-plan
sweep (32 / 16 / 18).

### Shipped — campaign batch 1 (2026-05-11 morning)

| Plan | Workstream(s) | Commit |
|---|---|---|
| 64 — supervisor wiring | W5 — `PolicyRef` resolver substrate | `0aee20f` |
| 63 — encryption everywhere (Phase 2) | W2 — `SecretBox<T>` wrapping pass | `b9e4e64` |
| 63 | W3 — `KeyringProvider` + `FileKeyProvider` in mvm-security | `1ea9352` |
| 63 | W1 — `key_rotation` primitives (rewrap_dek, rotate_master_key, migrate_wrapped_keys, rotate_luks_slot, reseal_snapshot) | `f7e39a7` |
| 63 | W4 — `mvmctl secret put/get/ls/rm` + `SecretStore` backends | `a30f866` |
| 63 | W5 — chunked AES-GCM in `pause_and_seal` / `verify_and_resume` | `6fc798d` |
| 63 | W6 — ADR-042 + CHANGELOG + plan-60 Phase 2 mark-up | `8baa4e7` |
| 62 — docs sidebar restructure | Substrate (21 stubs + sidebar config) had already landed; this commit just marks the status | `ae10ad9` |
| 44 — agent signal handling | W3 — SIGHUP config reload (hot-reloadable subset via atomics) | `05f956e` |
| 60 — libkrun migration | Phase 6 — on-disk policy-bundle TOML format (`mvm_policy::toml_loader` + W5 resolver upgrade) | `a457012` |
| 60 | Phase 4 — LifecycleHooks + secret/cmd dual-emit + audit Recorder substrate | `d174a46`, `0cdd6b1`, `c096757`, `80f05bd` |
| 60 | Phase 7 — host-mediated tools (substrate + time_now + web_fetch + web_search + upload + download), Brave + Tavily providers, reqwest fetcher, MCP dispatcher trait evolution, env-var operator config | `fab5edd`, `e500c18`, `a4ca401`, `72597e7`, `81fed76`, `8bcb2ed`, `f92e53a`, `c538180`, `0d0f3eb`, `5e62e5a` |
| 60 | Phase 9 — `cargo xtask perf` rootfs-size + boot budgets | `b42e784` |
| 60 | Phase 10 — in-repo close-out (status notes on plan-60 phase headers, Cargo.toml repository URL already canonical); workspace-parent filesystem rename + mvmd git pin bump remain operator actions | (this commit) |

### Shipped — campaign batch 2 (2026-05-11 evening)

| Plan | Workstream(s) | Commit |
|---|---|---|
| 60 — libkrun migration | Phase 6 — `mvm_security::attestation` (`IdentityKey` lifecycle + signed report) + feature-gated `HwAttestationProvider` stubs (TPM2 / SEV-SNP / TDX) + `mvmctl attest {export, verify, status}` CLI | `d0ba736` |
| 60 | Phase 3 Slice B — `mvm-policy::L4RuleSpec` + `mvm_supervisor::proxy::l4` (`L4Gate` trait, `LiveL4Gate::from_specs`) + `HickoryDnsResolver` + W5 resolver wires `slots.network` | `51581a8` |
| 60 | Phase 3 Slice C scaffold — `FirewallEnforcer` contract + fail-closed `NoopFirewallEnforcer` + `LinuxNftFirewall` adapter, now wired into `Supervisor::launch` before backend dispatch with teardown on backend launch failure / `stop` | `509d2c1` |
| 60 | Phase 3 Slice C follow-on — `FirewallSpec::from_vm_slot` derives VM identity/TAP from Firecracker runtime `VmSlot` metadata and supervisor launch validates specs before firewall install or backend dispatch | `d252f92` |
| 60 | Phase 3 Slice C follow-on — `BackendLauncher::prepare_launch` returns runtime `VmSlot` metadata before tenant launch; `Supervisor::launch` now derives firewall specs from that backend slot plus the supervisor proxy interface | `ab4a792` |
| 60 | Phase 3 Slice C follow-on — `FirecrackerRunConfigLauncher` adapts prebuilt Firecracker `FlakeRunConfig` into the supervisor `BackendLauncher` slot without starting tenant code during `prepare_launch` | `bd084f7` |
| 60 | Phase 3 Slice C follow-on — `Supervisor::with_*` assembly methods wire backend, policy, audit, artifact, and firewall slots without public-field mutation while preserving launch-time firewall validation | `b13fb54` |
| 60 | Phase 3 follow-on — `up.rs::admit_plan_for_boot` calls `resolve_supervisor_components`; typed audit-chain `error_class` per failure mode | `ac87e8d` |
| 60 | Phase 3 follow-on — `slots_from_bundle` delegates to `build_inspector_chain`, picking up SsrfGuard / SecretsScanner / InjectionGuard / PiiRedactor + honoring `disabled_inspectors` | `bf8079a` |
| 60 | Phase 3 follow-on — `LiveArtifactCollector::from_policy(&bundle.artifact)` (NotImplemented carries `capture_paths` count + retention) | `72f272f` |
| 60 | Phase 3 follow-on — `validate_egress_policy_inspector_names` fail-loud at admission on typos in `disabled_inspectors` | `586e0cd` |
| 60 | Phase 3 follow-on — `LiveKeystoreReleaser::from_policy(&bundle.keys)` (closes last Noop slot in `slots_from_bundle`) | `36db455` |
| 60 | Phase 3 follow-on — `bundle.pii.{mode, categories}` → `PiiRedactor::from_policy` + `build_inspector_chain_with_pii`; first slot where Live impl changes runtime behavior | `dc31b10` |
| 60 | Phase 4 scaffold — `tests/audit_total_coverage.rs` walks `mvm_cli::cli_command()` + asserts every top-level subcommand has an `AuditPosture` classification | `c036cea` |
| 60 | Phase 4 scaffold — recursive per-subgroup coverage (13 subgroup tables, ~54 leaf classifications including third-level `manifest tag` + `manifest alias`) | `dabd955` |
| 60 | Phase 4 follow-on — `validate_audit_policy_stream_destinations` fail-loud at admission on unknown URL schemes in `bundle.audit.stream_destinations` (`ResolveError::AuditPolicyInvalid`, `error_class = policy-audit-invalid`) | `c5c37f2` |
| 60 | Phase 4 follow-on — `bundle.audit` now constructs the admission audit emitter: policy-bound admission requires `chain_signing = true`, keeps the default local per-tenant chain, and replicates exact JSONL chains to `file://...` stream destinations. `https://` / `unix://` transports remain fail-closed until implemented. | `27f2d68` |
| 60 | Phase 4 follow-on — `tests/audit_emissions_live.rs` first 3 live drive-and-assert tests (cache prune, cache prune --dry-run negative, network create) | `d852f5a` |
| 60 | Phase 4 follow-on — 3 more live tests (network remove, manifest prune --orphans, secret put) | `3759af8` |
| 60 | Phase 4 follow-on — 3 secret-cluster live tests (secret get/ls/rm); discovered + pinned the on-disk action-name decoupling (`ls` → `"list"`, `rm` → `"delete"`) | `b22feae` |
| hooks | `chore(hooks)` — pre-commit hook no longer re-stages unstaged WIP via `git add -u`; snapshots originally-staged paths up front | `0338c66` |

Notes on commit-message vs diff mismatches in batch 2 (worth a
`git log` reader knowing about):

- `d774200` carries the "per-subgroup audit coverage" message but
  the diff is actually two other-agent files (`cmd_audit.rs` +
  `mod.rs`) that landed under it during a parallel branch race.
  The *actual* per-subgroup recursive walk shipped as `dabd955`
  immediately after with a clarifying header.
- `b22feae` is titled `test(libkrun): satisfy clippy::io-other-error
  on Linux` but its diff also includes 107 lines of new
  `audit_emissions_live.rs` content (the secret get / ls / rm
  cluster). The pre-commit hook's `git add -u` re-staged unstaged
  WIP in the working tree. `0338c66` fixed the hook so this
  pattern won't recur.

### Shipped — campaign batch 3 (2026-05-12, in flight as PR #106/#107/#108)

Plan 60 Phase 4 audit-emit ergonomics + behavioral hardening, plus
the cleanup-host-fs and MockBackend refactors that unlock VM-lifecycle
live testing. Three open PRs stack on `main`:

| PR | Branch | Scope | Live tests |
|---|---|---|---|
| #106 | feat/sprint-51-batch-3 | `audit_emit!` macro + `LocalAuditBuilder` API + `xtask check-audit-positional` lint + CI gate + 37-site positional emit migration + DRIFT-001 (libkrun feature gate) + ADR-013 builder-VM swap | 6 → 26 |
| #107 | feat/cleanup-host-fallback (targets #106) | `cleanup_old_dev_builds` drops `&dyn ShellEnvironment` for plain `std::fs`; `mvmctl cleanup` runs without a dev VM; SnapshotDelete live + 4 ReadOnly negative pins | 26 → 31 |
| #108 | feat/mock-backend (targets #107) | `MockBackend` substrate (`AnyBackend::Mock` variant, 10 unit tests); `MVM_DIRECT_BOOT` LocalAudit emit parity + `--detach` fix; `up_with_mock_backend` end-to-end; `set-ttl` live + 8 more ReadOnly negative pins; ADR-044 documenting the convention | 31 → 40 |

Coverage now: every Emits row in `AUDIT_POSTURE` that doesn't require
a running Firecracker / Apple Container / Docker / libkrun / Nix
builder / GitHub network has a live drive-and-assert test. 15 ReadOnly
leaves pin the no-emit invariants.

Still hard (architectural refactors required to test hermetically):
`pause` / `resume` (talk directly to FirecrackerIO, not through
`AnyBackend.pause`/`resume`); `fs` / `proc start/signal/kill/stdin`
(guest agent over vsock — needs vsock mock); `volume mount/unmount`
(VM-attached); `build → TemplateBuild` (Nix builder); `update`
(network); `uninstall` positive (real system paths).

Reference: ADR-044 (`specs/adrs/044-audit-emit-macro.md`).

### Remaining workstreams (priority order)

| # | Plan / phase | Est. days | Notes |
|---|---|---|---|
| 1 | Plan 60 Phase 3 Slice C — smoltcp/TUN userspace-TCP consumer + host firewall (nft / pf / WFP) + DNS server endpoint + per-tenant netns lift | 8-12 | The remaining Phase 3 work after Slices A + B + four resolver follow-ons closed in batch 2. Turns `L4Gate::evaluate` decisions into accept/drop on per-VM TAPs; brings up the firewall additive layer; provisions the resolver guest VMs point `/etc/resolv.conf` at. Pairs with the mvm-hostd lift (#7 below). |
| 2 | Plan 60 Phase 4 — persistent observability | 5-8 | Scaffold shipped in batch 2 (`tests/audit_total_coverage.rs` recursive coverage of all CLI subcommands at every depth). Remaining: Prometheus + OTLP metrics endpoint; promote `audit_total_coverage` `Emits` rows to live drive-and-assert tests as each command gains a hermetic fixture; wire `bundle.audit.{chain_signing, stream_destinations}` into `AuditEmitter` construction; structured logs; event bus on `tokio::sync::broadcast`. |
| 3 | Plan 60 Phase 5 — DX layer (Python SDK, manifests, mvm-studio handshake) | 7-10 | `python/mvm` wheels via pyo3; `cargo xtask gen-stubs` for typed APIs. Templates from `../mvm/templates/` rewritten on microvm.nix. |
| 4 | Plan 60 Phase 7 — MCP server + host-mediated tools + sessions | 7-10 | PR #105 exposes `run`, `mvm.time_now`, `mvm.web_fetch`, `mvm.web_search`, `mvm.upload`, and `mvm.download`; CI smoke now asserts that MCP tool set and the secret audit live test pins `MVM_SECRET_STORE_BACKEND=file` for hermetic Linux runners. Remaining follow-up: snapshot/eval and tmux-style sessions. |
| 5 | Plan 60 Phase 7a — install/rebuild/persistent overlay erasure | 10-12 | Encrypted persistent overlay (extends plan 45's volume work); rolling rootfs swap; overlay-erasure tooling emits destruction certificates. Tenant lifecycle UX belongs in mvmd. |
| 6 | Plan 60 Phase 7b — built-in templates + TypeScript SDK | 5-7 | `ai-sandbox` / `safe-openclaw` / `computer-use` / `repl` templates with bundled policy bundles. `typescript/@mvm/sdk` napi-rs binding for hot paths. |
| 7 | Plan 60 Phase 8 — mvmd integration contract verification | 3-5 | Port `mvm/src/hostd/{mod,server}.rs`; `PROTOCOL_VERSION` const; wire-format stability test. **Coordinated with parallel mvmd work** — see "Cross-repo coordination" below. The mvm-hostd supervisor lift this depends on is what makes every Live impl in `slots_from_bundle` (shipped batch 2) actually enforce. |
| 8 | Plan 60 Phase 9 — perf + supply chain + SBOM | 7-10 | Cold-boot ≤500 ms Firecracker / ≤1 s libkrun; rootfs ≤20 MB; PGO + MUSL builds; cosign-keyless artifacts; RFC 3161 timestamping. |
| 9 | Plan 60 Phase 10 — rename + archive | 1 | `git mv mvm mvm` + update CI paths + bump mvmd's git pin. |
| 10 | Plans 48 + 49 + 71 — function-service factories (ADR-010) + workload helper | 7-10 | Wrapper-template relocation + function-service factory pattern. Plan 71 wires `mkFunctionService` into a one-line IR-to-image helper (`mkFunctionWorkload`); unblocks Phase 5 Slice E3 live-VM smoke. |
| 11 | Plans 51 + 52 — session-lifecycle verbs + fd3 control channel (ADR-011) | 10-14 | Largest substrate change in the function-call line. |
| 12 | Plan 61 — runtime overlays + billing | 14-21 | Dev/prod image transparency + sandbox-runtime billing dimensions. Six phases. |
| 13 | Status sweep — plan 32 tail (MCP adoption tiers L1/L2/L4), plan 16 (microvm-nix-integration), plan 18 (nix-openclaw-integration) | 3-5 | Several minor plans with partial completion — audit + close or roll into a follow-up sprint. |

**Total remaining envelope:** ~90 calendar days after batch 2
(was ~100). Sprint 51 spans multiple sub-sprints in practice;
treat the workstream rows as the unit of scheduling.

### Cross-repo coordination (mvmd)

Plan 60 Phase 8 depends on parallel work in the mvmd repo. The
hand-off prompt for the mvmd session:

```
We're closing out the mvm refactor (plan 60 in the mvm repo).
Three mvmd-side workstreams to unblock Phase 8:

M1 — Unblock `cargo build --workspace`. mvmd has a sha2 dep
     conflict per plan-64 notes. Resolve it, then bump the mvm
     git pin to a SHA ≥ a457012 (plan 60 Phase 6 TOML loader).

M2 — Stand up `mvm-hostd` daemon. Listens on Unix socket
     `/run/mvm-hostd/control.sock` mode 0600. Receives
     `HostdRequest::{Start, Stop, Status}` carrying
     `SignedExecutionPlan`. On Start: verify envelope, call
     `mvm_cli::commands::vm::policy_resolver::
     resolve_supervisor_components(&plan)`, build a Supervisor
     with `.with_egress` / `.with_tool_gate` / `.with_keystore`
     / `.with_artifact_collector(slots.*)` + a FileAuditSigner,
     then `supervisor.launch(&signed, &trusted_keys).await`.
     Implement the `BackendLauncher` adapter wrapping
     `mvm_backend::AnyBackend::start()` — the piece plan 64 W3
     intentionally deferred (ADR-041).

M3 — Wire-format stability. Add `pub const PROTOCOL_VERSION: u32`
     to mvm's `mvm_core::protocol` (PR to mvm repo). New
     `tests/mvmd_compat.rs` in mvmd: round-trips
     `AgentRequest::Reconcile`, `HostdRequest::Start`,
     `HostdResponse::Started` against frozen-byte fixtures.

Verification: `cd ../mvm && cargo test --workspace`'s mvmd-compat
test passes against your branch. When green, plan 60 Phase 8
unblocks on the mvm side.
```

### Standing constraints

- CLAUDE.md "Security model" defines the 8 CI-enforced claims;
  don't regress any.
- Workspace lint `clippy::too_many_arguments = "deny"` — use
  struct args, not 5+ positionals.
- xtask `check-no-display-on-secret-types` flags Debug/Display
  on Secret/Token/Password/Wrapped*Key types. Stay clean or
  annotate `// allow(secret-debug): <reason>`.
- Every workstream: one commit + one tests-green checkpoint,
  pushed directly to `origin/main` per the post-cutover flow
  (no PR — the cutover commit `7184b9a` established this).

### Verification gates (run after every workstream)

```
cargo test --workspace --no-fail-fast       # ≥ 2098 + new
cargo clippy --workspace --all-targets -- -D warnings
cargo +nightly fmt --check
cargo run -p xtask -- check-no-display-on-secret-types
```

### Sprint 51 success criteria

By close of Sprint 51, the project can claim:

1. *Every plan 60 phase ships, including hardware-attestation
   stubs, the L4/L7 proxies, observability, the DX layer,
   templates, MCP, install/rebuild, mvmd integration, perf
   gates, and the v1→v2 rename.*
2. *Function-call surface plans (48, 49, 51, 52) close — the
   substrate mvmforge consumes is stable.*
3. *Plan 61's runtime overlay + billing model ships.*
4. *Partial-completion plans (32, 16, 18) close or roll forward
   into a successor sprint with explicit status.*
5. *CLAUDE.md security claims 1–8 stay true; ADR-002 §"Out of
   scope" remains accurate.*
6. *`cargo test --workspace` passes; clippy `-D warnings` clean;
   nightly fmt clean; xtask secret-debug lint clean.*

### Non-goals (deferred / shelved / out-of-repo)

These were deferred for stated reasons; Sprint 51 leaves them
alone:

- **Plan 15 — WASM container support** (SHELVED — no real WASM
  workload exists; OCI artifact format hasn't stabilized far
  enough).
- **Plan 53 — cross-platform roadmap** (rejected on security-
  posture grounds).
- **Plans 54 / 55 / 56 — cloud-hypervisor / crosvm / rust-vmm
  internalization** (deferred; CH already has Tier 1 backend
  status without internalization).
- **Plan 59 — llm-txt self-doc** (relocated to mvmd repo; out
  of scope here).

### What "campaign closed" looks like

Sprint 51 closes when:

1. Every `### Phase N` in plan 60 has a "✅ shipped" status
   header.
2. Plans 44, 48, 49, 51, 52, 61, 62, 63, 64 all have
   "all workstreams shipped" status headers.
3. Plans 32, 16, 18 are either fully shipped or have an
   explicit closure note ("rolled forward to sprint 52", "no
   longer relevant", etc.).
4. The workspace test count is ≥ 2500 (rough envelope based on
   how many workstreams are pending × typical per-workstream
   test growth).
5. CHANGELOG.md `[Unreleased]` section captures every shipped
   plan with date, commit SHAs, and links to ADRs.

## Sprint 52 — elastic memory + portable signed bundles (in flight)

Two ergonomics + reach gaps in the platform that need closing
without compromising the eight ADR-002 security claims. The
decision document outside the repo enumerates eight candidates;
this sprint lands the top two:

1. **Virtio-balloon elasticity** — "mem cap, not commitment."
2. **Portable image bundles + per-artifact attestation in a signed
   envelope** — content-addressed `.mvmpkg` replaces the
   manifest-path-hash registry keying.

### W1 — Virtio-balloon elasticity  ✅ shipped

Workloads opting into `mem_initial_mib` boot with a pre-inflated
balloon and only commit a fraction of `memory_mib`; a host-side
reclaim controller adjusts the balloon over the VM's life.

Shipped:

- `mvm-core` — `VmStartConfig::mem_initial_mib`,
  `VmCapabilities::balloon`, `BalloonState`,
  `VmBackend::balloon_set_target` + `balloon_state` trait methods.
- `mvm-backend::microvm` — `FlakeRunConfig::mem_initial` +
  validate(); FC start path PUTs `/balloon` with
  `deflate_on_oom: true`; new `balloon_set_target` / `balloon_state`
  free functions wrap the FC PATCH + GET endpoints.
- `mvm-backend::cloud_hypervisor` — `VmConfigArgs::balloon_mib`,
  emits the top-level `"balloon"` field in vm.create JSON, and
  `balloon_set_target` posts to `/api/v1/vm.resize`
  (`desired_balloon`); `balloon_state` parses `/api/v1/vm.info`.
- `mvm-backend::{apple_container, docker, libkrun, libkrun,
  microvm_nix}` — `VmCapabilities::balloon = false` declared
  honestly with rationale next to each (Apple's VZ has no
  virtio-balloon; Docker is cgroup-mem not balloon; libkrun's C
  API + libkrun builder don't surface balloon control today).
- `mvm-core::manifest` — `mem_initial: Option<String>` field with
  `parse_human_size`-backed validation (rejects zero, rejects
  `>= mem`); `Manifest::mem_initial_mib()` helper.
- `mvm-backend::image::RuntimeConfig.mem_initial` for the
  `--config` flow.
- `mvm-cli::commands::shared::start::VmStartParams.mem_initial_mib`
  threading through both `up.rs` call sites.
- `mvm-cli::exec::ExecRequest.mem_initial_mib` threading;
  short-lived session VM and `mvmctl exec` default to `None`
  (no balloon).
- `mvm-supervisor::balloon` — pure-function `BalloonPolicy`
  (two-threshold band + guest floor) returning `BalloonAction`
  decisions. Defaults: inflate above 0.80, deflate below 0.60,
  step 64 MiB, guest floor 64 MiB. Fully unit-tested.

Shipped in the W1 close-out commit:

- `HostPressureSource` trait + `SysinfoPressureSource` cross-
  platform impl. Linux PSI (`/proc/pressure/memory`) and macOS
  `vm_pressure` are stronger signals; alternative impls behind the
  same trait are the natural next refinement.
- `BalloonController<P>` with a pure `tick(vm_states, apply)`
  method: reads pressure once per tick (not per VM), decides each
  VM's action via `BalloonPolicy`, applies via the caller's
  closure. `TickOutcome` per VM carries the decision + applied
  flag + per-VM error. Pressure-read failure aborts the whole
  tick rather than applying with a stale value.
- `mvmctl doctor` "Memory ballooning (virtio-balloon)" section
  enumerates every backend's `capabilities().balloon`; surfaces a
  warning when no backend on the host advertises support.
- `Manifest::mem_initial` flows end-to-end:
  `Manifest::mem_initial_mib()` → `PersistedManifest.mem_initial_mib`
  → `TemplateSpec.mem_initial_mib` → `up.rs` resolves
  `final_mem_initial = rt_config.or(tmpl_mem_initial).filter(0 < n < final_memory)`.
  Old slot records that predate the field deserialise as `None`
  (no behaviour change).

Outstanding (deferred to follow-ups):

- Live-KVM smoke: assert host RSS climbs/falls as the controller
  inflates/deflates against a real Firecracker guest. Needs CI
  infrastructure that mvm doesn't have today.
- PSI / `vm_pressure` `HostPressureSource` impls. The current
  sysinfo-based source is "used/total" — fine for dev-laptop
  ergonomics, too coarse for production scheduling.
- Spawn the tick into a real loop inside the supervisor's main
  loop. Today the controller is a library piece; wiring it into
  the supervisor's lifecycle is the integration follow-up.

### W2 — Portable image bundles + per-artifact attestation  ✅ admit-time re-verify shipped

Sigstore-style trust model: bundle ships a signed `manifest.json`
with per-artifact SHA-256s; the publisher's public key lives
out-of-band at `~/.mvm/trusted-publishers/<key_id>.pub`. dm-verity
(claim 3) gives independent per-block integrity inside the rootfs.
Bundle hash + `key_id` pin into `PlanArtifact` so admission
re-verifies on every launch.

Shipped (`mvm-plan::bundle`):

- `BundleManifest` (canonical-JSON, `deny_unknown_fields`),
  `BundleArtifact`, `ArtifactRole` enum, `VerityInfo` binding.
- `KeyId` — content-derived identifier (sha256(pubkey) truncated to
  32 hex chars). Well-formedness validator.
- `write_bundle()` — emits a tar archive of `manifest.json` +
  `manifest.sig` + `artifacts/*`. Pre-flight asserts the signing
  key matches the manifest's declared `key_id` and that every
  artifact byte-blob matches its declared sha256 + size_bytes.
- `read_and_verify_bundle()` — 6-step verification sequence:
  schema-version sniff (pre-sig) → key_id probe (pre-sig) →
  trust-store lookup → Ed25519 verify → full manifest parse →
  per-artifact sha256 + size + path-safety re-check. All four
  failure modes (UnknownKey, SignatureInvalid,
  ArtifactSha256Mismatch, UnsafePath) reject before extraction.
- `TrustStore` trait + `FsTrustStore` rooted at
  `~/.mvm/trusted-publishers/<key_id>.pub`. Pubkey files are 32
  raw Ed25519 bytes — no PEM, no headers; populated out-of-band
  for now (`mvmctl trust add` is the follow-up).
- `PlanArtifact` (re-exported from `mvm_plan::PlanArtifact`):
  `bundle_sha256` + base64 `manifest_sig` + `key_id`. Sized for
  inlining inside an `ExecutionPlan`; the supervisor's admit path
  re-verifies in a follow-up.
- 18 new unit tests covering: clean round-trip, unknown-key
  rejection, tampered manifest rejection (sig fail or parse fail),
  wrong key under correct key_id (KeyIdMismatch), tampered
  artifact byte rejection (with same-length tamper to exercise the
  hash path), missing-artifact rejection, unsafe-path rejection
  (`..`), schema-version-bump rejection, write-time key/key_id
  mismatch detection, write-time artifact sha256 drift detection,
  trust-store file load + miss + malformed-key-id short circuit,
  PlanArtifact JSON round-trip + signature re-decode + deny-unknown-fields.

Shipped in the W2 close-out commit:

- `mvmctl bundle export <TEMPLATE> --out <PATH> [--label]`:
  resolves the template's current revision (kernel + rootfs +
  optional initrd + optional dm-verity sidecar), hashes each
  artifact, builds a `BundleManifest`, signs with the host signer
  (same key that signs `ExecutionPlan` envelopes), and writes the
  archive. Refuses to ship a bundle whose declared sha256/size or
  key_id doesn't match the signing key / actual bytes — caught at
  write time so misconfigured publishers never ship unverifiable
  bundles.
- `mvmctl bundle fetch <SOURCE> [--trust-store <DIR>] [--json] [--allow-http]`:
  reads the archive (from a local path **or** an `https://` URL —
  HTTPS uses rustls + webpki-roots through the existing
  `crate::http::download_file` helper, written to a temp file
  that drops on scope exit), looks the publisher pubkey up via
  `FsTrustStore` (defaults to `~/.mvm/trusted-publishers/`), runs
  the full 6-step rejection ladder, prints a verified-bundle
  summary (sha256, key_id, publisher, arch, profile, label,
  artifact count, verity yes/no) or full manifest JSON. Plain
  `http://` URLs are refused by default — the Ed25519 signature
  still catches tampering, but HTTP exposes traffic metadata, so
  the user must opt in explicitly via `--allow-http` (with a
  launch-time warning). Refuses on any verification failure
  before extraction.
- `mvmctl trust add <PUBKEY> [--force]`: reads 32 raw Ed25519
  pubkey bytes, derives `key_id`, writes `<key_id>.pub` to the
  trust store (mode 0644). Refuses to overwrite without `--force`.
  Trust-store directory created at mode 0700 on first use.
- `mvmctl trust list [--json]`: enumerates the store, filters to
  well-formed `<key_id>.pub` entries, sorted output.
- `mvmctl trust remove <KEY_ID>`: unlinks by key_id; refuses if
  the key_id is malformed (32 hex chars expected).
- `cmd_audit::verb_name` + `AUDIT_POSTURE` table extended with
  `bundle` (DelegatesToSub: export = `InteractiveOrControl`,
  fetch = `ReadOnly`) and `trust` (DelegatesToSub: add/remove =
  `InteractiveOrControl` until the audit-chain emitter wiring
  lands; list = `ReadOnly`).
- ADR-002 9th claim shipped: *every published bundle is
  content-addressed, key_id-pinned, and re-verified at fetch.*
  Backed by `mvm_plan::bundle::read_and_verify_bundle` rejection-
  ladder tests. ADR-002 also caught up to document claim 8
  (signed `ExecutionPlan`, already shipped in plan 64 / ADR-041
  but never previously in the ADR table).

Shipped in the W2 admit-time re-verify commit:

- `ExecutionPlan::bundle: Option<PlanArtifact>` field. Schema
  bumped 2 → 3 — older verifiers fail closed with
  `UnsupportedSchema` because they don't know how to enforce the
  re-verify the new field implies. Schema-sniff order preserved:
  signature → version → parse, so an unknown future bundle field
  can't bypass the verifier.
- `BundleResolver` trait + `FsBundleResolver` rooted at
  `~/.mvm/bundles/<bundle_sha256>.mvmpkg` (default-path matches
  the `FsTrustStore` shape).
- `verify_plan_bundle(pin, resolver, trust)` — wraps
  `read_and_verify_bundle` and cross-checks the archive's
  `bundle_sha256` + `manifest_sig` + `key_id` against the plan's
  pin. Distinct `PlanBundleError` variants for each rejection
  shape (Resolve, Verify, BundleSha256Mismatch, KeyIdMismatch,
  SignatureMismatch, SignatureRead).
- `admit_for_run` accepts an optional
  `BundleAdmissionContext { resolver, trust }` parameter. When
  the plan pins a bundle, admit_for_run runs
  `verify_plan_bundle` after the signature/window/nonce checks.
  Plan pinned but context absent = operator misconfiguration =
  refuse (fail closed, not fail open).
- `SynthesisInput.bundle_pin: Option<PlanArtifact>` carries an
  upstream pin into the synthesized plan via
  `plan.bundle = input.bundle_pin.clone()`. Today's `mvmctl up`
  path passes `None`; the CLI flag that populates it (`--bundle-pin
  <path>` reading a fetched + verified `.mvmpkg`) is the next
  surface-completing commit.
- 4 new admit-level tests (positive + 3 refusals) plus 8 new
  `verify_plan_bundle` tests covering every PlanBundleError
  variant.

Shipped in the W2 follow-on (registry replacement + bundle-pin
CLI + audit-kind variants):

- **Bundle registry** at `~/.mvm/bundles/<sha>/`. New
  `BundleRegistry::install` atomically extracts a verified
  `.mvmpkg` (stage to `<sha>.partial/`, rename to `<sha>/`),
  also persists the archive bytes at `<sha>.mvmpkg` so
  `FsBundleResolver` continues to find them. `find(sha)` returns
  an `InstalledBundle` with `path_for_role()` / `path_for_name()`
  helpers. `template_artifacts_dispatched` and the three other
  `_dispatched` variants now disambiguate 64-char hex ids:
  templates-slot wins when present, fall through to bundle
  registry otherwise. Bundle-served templates default vcpus/mem
  from operator config (manifest doesn't carry resources today).
- **`mvmctl bundle install <SOURCE> [--force]`** verb. Reuses
  `BundleSource` parser from fetch.rs (local path or `https://`);
  runs the verification ladder, atomically installs, prints
  `Installed bundle <sha> (N artifacts, key_id=...)`.
- **`mvmctl up --bundle-pin <PATH>`** flag. Reads the archive,
  verifies via `FsTrustStore::default_path()`, derives the
  `PlanArtifact` triple via `bundle_pin_from_archive`, hands an
  in-memory `BundleAdmissionContext` to `admit_for_run`. Claim 9
  re-verify fires on every launch.
- **`LocalAuditKind::TrustAdd` / `TrustRemove`** added to the
  audit-kind enum + casing pins + serde round-trip test.
  `mvmctl trust add/remove` now emit via
  `mvm_core::audit::emit`; `AUDIT_POSTURE` TRUST_SUB flipped from
  `InteractiveOrControl` → `Emits(...)`.
- `BUNDLE_SUB::install` row added with posture
  `InteractiveOrControl` (will flip to `Emits("BundleInstall")`
  once the install audit hook ships).

Closed out in the W2 final commits (`90cef3d`, `ad3f52c`,
TBD-resources):

- `LocalAuditKind::BundleInstall` variant + emit from
  `mvmctl bundle install` + AUDIT_POSTURE flipped to
  `Emits("BundleInstall")`.
- `mvmctl bundle gc <SHA>` and `--all` verbs +
  `BundleRegistry::remove` + `list` + new
  `LocalAuditKind::BundleGc`. Interactive --all confirms unless
  `--yes` (or non-TTY).
- `BundleResources { vcpus, mem_mib }` optional field on
  `BundleManifest`. **BUNDLE_SCHEMA_VERSION bumped 1 → 2.** v1
  bundles deserialise cleanly with `resources = None`; v2 with
  resources are the new default for `mvmctl bundle export`.
  Older verifiers see `schema_version = 2` and refuse with
  `UnsupportedSchema` (deliberate fail-closed).
  `bundle_artifacts_for_sha` prefers manifest resources over
  operator config when present; CLI `--cpus` / `--memory` still
  override.

W2 is now fully shipped end-to-end with no outstanding follow-ups.

### W3 — Network default flip (deny-by-default)  ✅ shipped

Pre-Sprint 52 `NetworkPolicy::default()` returned `unrestricted()`
— the entire rest of the ADR-002 model confined the guest at every
other layer, but egress was wide open. W3 flips the safe default
to `deny_all()`. Workloads that need network access opt in
explicitly via `--network-preset` / `--network-allow` /
`mvmctl trust`-provisioned template policies.

Shipped:

- `NetworkPolicy::default()` in
  `crates/mvm-core/src/policy/network_policy.rs` returns
  `Self::deny_all()` (was `Self::unrestricted()`).
- `mvmctl up` warning when the resolved policy is unrestricted —
  both for the explicit-CLI-flag path
  (`--network-preset unrestricted`) and for templates whose baked
  `default_network_policy` is unrestricted. Names the source so
  the user knows where the opt-out came from. Suppressible via
  `MVM_ACK_UNRESTRICTED_NETWORK=1` for CI / scripted use.
- ADR-002 10th claim shipped: *no untrusted workload reaches the
  network unless explicitly admitted by policy.* Framework refs
  added (ATT&CK T1071 / T1041; D3FEND Network Traffic Filtering;
  CREF Privilege Restriction).
- Tests updated:
  - `policy_default_is_deny_all` (renamed from
    `policy_default_is_unrestricted`) asserts the deny-all shape.
  - `test_resolve_network_policy_default_is_deny_all` flipped to
    match. Comment notes the pre-Sprint-52 expectation.
- 334 supervisor + all-crate lib tests green;
  `cargo test --test audit_total_coverage` green; clippy clean.

Breaking change disclosure for release notes:

> **Breaking:** `mvmctl up` and the rest of mvm now refuse network
> egress by default. Workloads that previously relied on
> implicit unrestricted egress must pass
> `--network-preset unrestricted` (which emits a launch-time
> warning) or one of the safer presets (`dev`, `agent`,
> `registries`). The escape hatch
> `MVM_ACK_UNRESTRICTED_NETWORK=1` suppresses the warning.

Outstanding (deferred follow-ups):

- CI lane `network-default-is-deny` — a black-box assertion that
  `mvmctl up` with no flags refuses outbound connectivity from
  inside the guest. Needs a live-KVM smoke harness mvm doesn't
  have today; the unit-level guarantee shipped in this commit.
- `mvmctl doctor` could surface the network default visibly in
  its security-posture section as a corollary of claim 10. The
  posture section reads from `BackendSecurityProfile`; teaching
  it about runtime policy defaults is a small follow-on.

### W4 — OCI export (reach to non-KVM hosts) ✅ shipped

Sprint 52 follow-on item from the original ranking (`#4a` in the
decision doc) — extends mvm-built workloads to hosts without KVM
by exposing the OCI tarball Nix already produces internally.

Shipped:

- `template_build_from_manifest` now copies `image.tar.gz` into
  the slot's revision dir (when the flake's `mkGuest` opted into
  `dockerTools.streamLayeredImage`). Best-effort — flakes that
  don't emit it just don't get one.
- New `mvmctl manifest export-oci <TEMPLATE> --out <PATH>` verb.
  Resolves a slot-hash / manifest-path / legacy name to the slot
  dir, finds the OCI tarball alongside the rootfs, copies it to
  `--out`. Clear error when the tarball is absent (with the
  rebuild hint).
- `LocalAuditKind::ImageExportOci` variant + snake_case wire pin
  (`image_export_oci`) + all-variants serialize roundtrip.
- AUDIT_POSTURE MANIFEST_SUB gains an `export-oci` row with
  `Emits("ImageExportOci")`.
- 2 new tests: resolve-to-slot-hash rejects unknown shas with a
  hint, verb is registered in the CLI tree.

End-to-end flow:

```
# Build the template on a KVM host
mvmctl build <manifest>
# Export to a Docker-loadable tarball
mvmctl manifest export-oci <slot> --out ./mvm-workload.tar.gz
# On any host with Docker / Podman
docker load -i mvm-workload.tar.gz
docker run mvm-...
```

Outstanding (deferred):

- Bundle-source path: `mvmctl bundle export-oci <sha>` for
  installed bundles, not just slot-built templates. Bundle
  manifests don't currently carry the OCI tarball; adding it
  would be a bundle-schema bump.
- Direct `--push <registry>` for one-step deployment. The current
  shape is "copy to a file, then docker push manually" — `--push`
  would streamline.

### W5 — secure one-shot `run` UX ✅ shipped

Follow-on from the agent sandbox CLI review: expose the secure happy
path as `mvmctl run`, while preserving `mvmctl exec` as the lower-level
dev-compatible spelling.

Shipped:

- New top-level `mvmctl run` command delegates to the existing cold
  transient execution machinery.
- `--profile restrictive|standard|dev|permissive` gates host-impacting
  options before dispatch.
- `standard` is the default and refuses writable host shares; `restrictive`
  refuses env injection and all host shares; `permissive` requires
  `MVM_ACK_PERMISSIVE_RUN=1`.
- `mvmctl run --receipt <path>` writes a host-signed JSON receipt with
  invocation hashes, output hashes, and exit status; raw argv/env values
  and raw output are deliberately omitted.
- `mvmctl run --json` emits an unsigned machine-readable execution summary
  using the same redacted invocation/outcome shape as receipts. Guest stdout
  and stderr are not streamed in JSON mode; only hashes and byte counts appear.
- `mvmctl run --dry-run` validates and explains the run plan without resolving
  an image, building/downloading the default image, booting a VM, writing a
  receipt, or executing the command. `--dry-run --json` emits the same redacted
  preflight shape for machine callers, hashing manifest arguments, argv, env
  values, host paths, and receipt paths.
- Live smoke coverage for `mvmctl run --json --receipt` is gated behind
  `MVM_LIVE_SMOKE=1` and compares the public JSON summary to the signed
  receipt without allowing raw guest output into either artifact.
- `mvmctl receipt verify <path>` verifies the receipt signature against
  the local host-signer public key, with `--pubkey` for portable checks.
- `mvmctl sandbox gc` adds a dry-run-by-default cleanup path for stale
  sandbox registry entries. `--apply` only removes stopped/expired entries
  that no backend reports as live and emits `SandboxGc`.
- `mvmctl sandbox gc --json` emits the same candidate/removal decision as a
  machine-readable summary and preserves dry-run-by-default behavior unless
  `--apply` is supplied.
- `mvmctl cp` copies one regular file across the host/VM boundary with exactly
  one `VM:/absolute/path` endpoint, a default 16 MiB cap, no overwrite unless
  `--force`, guest-side path-policy validation, and `VmFileCopy` audit without
  host paths or file contents.
- `mvmctl cp --json` emits a redacted machine-readable copy summary with
  direction, VM name, guest path, byte count, and effective copy options; host
  paths and file contents are omitted.
- The policy explain/lint/diff/export CLI surface was removed from `mvmctl`
  during the CLI-boundary cleanup. The underlying policy bundle types and
  admission resolver remain in `mvm`; tenant policy review and rollout UX live
  in `mvmd`.
- CLI reference and parser tests cover the new command and profile surface.

### Sprint 52 success criteria

1. *A workload with `mem_initial = "256M"` and `mem = "1024M"`
   boots on Firecracker and cloud-hypervisor with the balloon
   pre-inflated to 768 MiB; the host commits 256 MiB.*
2. *`AnyBackend::balloon_set_target` adjusts a running FC VM's
   commitment without reboot, observable through `balloon_state`.*
3. *A `.mvmpkg` bundle built on machine A round-trips through the
   registry, fetches to machine B, and `mvmctl up` succeeds; a
   tampered manifest fails admission with a clear error.*
4. *`mvm_plan::verify_plan` refuses an `ExecutionPlan` pinned to
   a bundle whose `key_id` is not in the consumer's trust store.*
5. *Backwards compatibility: every existing workspace test plus
   `cargo clippy --workspace --all-targets -- -D warnings` stays
   green throughout.*

## Sprint 53 — Claim-safe sandbox parity (W0 in flight) [`plans/74-claim-safe-sandbox-parity.md`](plans/74-claim-safe-sandbox-parity.md) | [`adrs/048-claim-safe-sandbox-parity.md`](adrs/048-claim-safe-sandbox-parity.md) | [`plans/83-w1-w6-attack-plan.md`](plans/83-w1-w6-attack-plan.md)

### W0 — Claims hygiene and docs guardrails  🟡 in flight

Stops overclaiming before runtime work (W1-W6) lands. Ships a public
"Sandbox parity status" page that classifies every claim
(`claims-hygiene` / `oci-ingest` / `network-policy` /
`secret-non-leakage` / `sdk-lifecycle` / `cold-start` /
`filesystem-backends`) as Shipped / Preview / Planned / Not claimed;
adds `cargo xtask check-doc-claims` to the `lint` CI job, which
rejects gated marketing phrases (`<100ms` and variants, `any OCI
image`, `arbitrary OCI image`, `secrets cannot leak`, `never enters
the guest`) on public docs unless the file marks the relevant claim
Shipped or carries an `<!-- allow(doc-claim:<id>): <reason> -->`
opt-out; strips live `mvmforge` references from
`guides/exec.md` and `reference/cli-commands.md` (the deliberate
migration guide stays); updates the external-sandbox gap-analysis note
for the current `crates/mvm-sdk` + `crates/mvm-sdk-macros` layout
and the mvmd ADR-0020 cross-repo handoff; and lands plan 74's
`## Risks` section (R1-R12, eight cross-cutting plus four
architectural) plus the `83-w1-w6-attack-plan.md` sequencing
sidecar so W1-W6 don't get re-planned mid-flight.

### W1-W6 — Proposed

OCI ingest, programmable network policy, secret placeholders,
SDK-owned lifecycle, cold-start measurement, extensible filesystem
backends. Sequencing, dependencies, and per-workstream attack plans
in `plans/83-w1-w6-attack-plan.md`. Risk R9 (TLS substitution
mechanism — proxy-with-CA vs vsock side-channel vs host-side
reconstruction) is the single architectural gate; recommended to
land its own ADR before W2 codes the proxy.

## Sprint 54 — Builder-VM maturation (in flight, off-book tracking)

Plans 87-95 cover the builder-VM evolution from TSI-patched stock
kernel → slim custom kernel + passt/gvproxy networking + Alpine
Stage 0. Most of this work landed via individual PRs without a
dedicated sprint section; this entry exists so the in-flight pieces
don't fall off.

### Tracked plans

- ✅ [`plans/87-passt-virtio-net.md`](plans/87-passt-virtio-net.md) — virtio-net via passt on Linux.
- ✅ [`plans/88-gvproxy-macos-backend.md`](plans/88-gvproxy-macos-backend.md) — virtio-net via gvproxy on macOS.
- ✅ [`plans/89-persistent-builder-vm.md`](plans/89-persistent-builder-vm.md) — persistent builder VM (multiple W3 PRs landed).
- ✅ [`plans/90-gateway-frame-fuzz.md`](plans/90-gateway-frame-fuzz.md) — fuzz coverage for the gateway frame parsers.
- 🟡 [`plans/91-stage0-alpine-bootstrap.md`](plans/91-stage0-alpine-bootstrap.md) — Alpine Stage 0 bootstrap (PR #417 open).
- 🟡 [`plans/92-minimal-builder-vm-kernel.md`](plans/92-minimal-builder-vm-kernel.md) — slim custom kernel via `linuxManualConfig` + `tinyconfig` (committed locally on `worktree-plan-92-stock-kernel`; carried forward by Plan 95's PR).
- 📝 [`plans/93-fast-secure-dev-path-followups.md`](plans/93-fast-secure-dev-path-followups.md) — **post-Plan-91 follow-ups, planning only.** Phase 0 (PR-A): fingerprint correctness fix in `builder_vm_source_fingerprint` — a shipping security gap independent of Plan 91. Phase 1: fast Layer 2 dev cycles (lazy/split dev shell + cross-compile our crates on host + lazy in-VM nix fetch). Phase 2: sub-200 ms runtime microvm launch (kernel/initrd minimisation, agent-startup parallelism, warm-pool of pre-spawned libkrun supervisors). Phase 3: DX polish (`mvmctl doctor` enrichment, `cache info`, progress UI, public docs, CI reproducibility lane). Targets: sub-30 s warm `mvmctl dev up`, sub-200 ms cold microvm launch, no LONG dev cycles. Not yet started — saved to track direction.
- 🟡 [`plans/95-builder-vm-kernel-slimming.md`](plans/95-builder-vm-kernel-slimming.md) — **Plan 92 followup.** Aggressive ARM64 SoC platform cluster disables (W3) + permanent `kernel-configfile` flake output for audit (W2). Lands as one PR carrying Plan 92's base commits forward. (W1 "drop microvm.nix input" was dropped post-survey — `nix/lib/` still requires it.)

### Sprint 54 success criteria

- Plan 92's kernel switch is live on `main` (via Plan 95's bundled PR).
- Plan 95's SoC cluster disables measurably shrink `vmlinux` (10-30% on aarch64).
- `cargo run -- dev up` boots end-to-end on aarch64-darwin with the slim kernel.
- Alpine Stage 0 (Plan 91) merged via PR #417.

### Non-goals

- Kernel-warning surfacing UX (Plan 95 W4, deferred to follow-up issue).
- Dropping the `microvm.nix` flake input — locally unused in builder-vm but required by `nix/lib/default.nix` for the root flake's NixOS-module path; rework deferred (Plan 95 W1 was dropped post-survey).
- microvm.nix as a *kernel* or *workload-build* base — explicitly rejected in Plan 95 §Problem and Plan 92 §Decision.

### 2026-05-21 → 2026-05-22 `mvmctl dev up` unblock stack (executor notes)

PRs landed on `main` to walk Stage 0 → persistent builder VM → inner `nix build`:

- ✅ #418 / #419 — early Stage 0 wiring (merged 2026-05-20).
- ✅ #420 — Plan 96 dev-up followups, including `nix-store --load-db` of seeded /nix/store paths (`a6242604`).
- ✅ #421 — ext4 geometry recovery + udhcpc path + dev-image flake lock pin.
- ✅ #422 — builder-VM fingerprint expansion to cover `mvm-builder-init` / `mvm-egress-proxy` / `Cargo.lock` (`155b561f`).
- ✅ #423 — `mkGuest` skips `addon-dns` bake for the builder VM (Stage 0 OOM mitigation).
- 🟡 #424 (`worktree-stage0-error-handler`) — `mknod /dev/null` insurance + `/dev` probe at boot + error-handler hardening so the next Stage 0 nix-build failure surfaces its real stderr instead of `can't create /dev/null: nonexistent directory`. All checks green; ready to merge.
- 🟡 `worktree-dev-fd-symlinks` (PR pending) — adds `/dev/fd → /proc/self/fd` (plus `std{in,out,err}`) at builder-VM boot and in `mkGuest /init`, surfaces `<job_dir>/nix-stderr.log` path + 4 KiB tail on `finalize_flake_job` failure, and prints job dir at dispatch. Closes the `mvm-guest-agent-0.14.0.drv` inner-build failure observed at the very last step of `mvmctl dev up` — every Rust derivation in the dev image's closure was tripping nixpkgs's `cargoInstallHook` line 27 process substitution on a missing `/dev/fd`. Full plan + diagnosis log in [`backlog/42-tracking.md`](backlog/42-tracking.md).

### Carryover follow-ups (pre-existing test breakages on `main`)

Discovered while running `cargo test --workspace --all-features` to gate the dev-fd-symlinks PR. All three reproduce on a freshly-stashed clean `main` checkout; none are caused by the dev-fd-symlinks diff. Each needs its own small follow-up PR.

1. `mvm-build::libkrun_builder::tests::run_build_surfaces_environment_gaps_for_install_variant` — host-environment-dependent. On a macOS contributor host with libkrun installed via Homebrew (which `CLAUDE.md` recommends as the dev-deps install), the test runs the supervisor path past the gap-detection short-circuit and gets `BuilderVmError::NixBuildFailed("supervisor exited with non-zero status (1); ...")` instead of the asserted `LibkrunUnavailable | ExtractionFailed`. Test was written for CI runners that lack libkrun. Fix: gate on a "libkrun absent" probe in the test, or assert the post-spawn `NixBuildFailed` shape too.
2. `mvm-cli::commands::env::apple_container::dev_status_image_tests::builder_cache_status_reports_source_provenance_drift` — fixture panics with `builder VM source fingerprint missing /var/folders/.../Cargo.lock`. Caused by `155b561f` (PR #422) expanding the fingerprint to require a `Cargo.lock` in the workspace root, but this test fixture builds an isolated temp flake dir without one. Fix: stage an empty `Cargo.lock` (or copy the workspace one) into the fixture's temp workspace root before invoking the fingerprint code.
3. `mvm-cli::commands::env::apple_container::dev_status_image_tests::builder_cache_status_reports_source_cache_hit_without_paths` — identical cause as (2).

## Sprint 55 — `Virtualization.framework` backend (`vz`) — ✅ COMPLETE (closed 2026-06-13; vz at full macOS-libkrun parity)  [`plans/97-vz-backend.md`](plans/97-vz-backend.md) | [`adrs/056-vz-backend.md`](adrs/056-vz-backend.md)

**Close-out verdict (2026-06-13): Vz is 100% — at full parity with the
macOS libkrun stack.** Every layer the libkrun/Firecracker path supports
works on `--hypervisor vz`, live-proven on this macOS-26 Apple-Silicon
host. The two capabilities NOT present on vz — secret substitution
(claim 13) and dm-verity verified boot (claim 3) — are absent on the
**macOS default (libkrun) too**, identically (same `ClaimStatus` in
`libkrun.rs`/`vz.rs`; substitution's `spawn_substitution_endpoint` is
called only by the Linux-host QEMU/FC backends). They are Linux-host /
prod-tier features whose macOS port is a **shared cross-backend
follow-up**, not a vz gap. See the close-out validation entry below and
the reconciled success criteria. Deny-by-default egress + chain-signed
audit (claim 10) ARE active on vz.

Adds a fourth macOS hypervisor backend (`vz`) parallel to libkrun and
Apple Container, using Apple's `Virtualization.framework` directly via
a small Swift supervisor binary. Collapses the nested
`macOS → libkrun → Firecracker` workload-microVM pipeline into a
single Vz-hosted Linux VM on macOS 13+, and adds Vz as a builder-VM
option alongside libkrun. **Additive only** — libkrun stays the macOS
default, Firecracker stays the Linux default and the production deploy
default; Vz is opt-in via `MVM_BACKEND=vz` / `--backend vz`.

### Why this sprint

Apple's `Virtualization.framework` has supported Linux guests since
macOS 11 and exposes virtio-blk / virtio-net / virtio-vsock /
virtio-console / virtio-rng / virtio-fs natively — exactly the device
classes our guests already drive. Today, workload microVMs on macOS
nest Firecracker inside a libkrun-hosted Linux VM because Firecracker
needs `/dev/kvm`. Vz can host Linux guests directly, so a Vz backend
collapses the nesting on macOS, adds the macOS 11–25 / Intel coverage
gap that Apple Container (macOS 26+ ASi) leaves unfilled, and gives us
balloon + snapshot support on macOS 14+ without changing any guest-side
code (vsock CID 3 / ports 5252, 10000+, 20000+ remain unchanged).

### Workstream breakdown

- ✅ **Phase A** — `mvm-vz-supervisor` Swift binary. Builds clean
      under macos-13+, ad-hoc codesigned with
      `com.apple.security.virtualization`, strict deny-unknown-fields
      JSON decoder, vsock unix-socket bridges, gvproxy network
      attachment, resource-cap validation against Vz host limits,
      capture-only console.
- ✅ **Phase B** — `VzBackend` impl in `crates/mvm-backend/src/vz.rs`,
      `BackendKind::Vz`, `MVM_BACKEND=vz` / `--backend vz` opt-in.
      `auto_select()` unchanged. Full lifecycle: start (resolve +
      spawn + pipe JSON + PID wait), stop (SIGTERM → SIGKILL),
      status, list, logs. `mvmctl doctor` reports availability +
      supervisor-binary path. `cargo build` auto-builds the Swift
      supervisor via `mvm-vz/build.rs`. Acceptance smoke (full boot
      to vsock 5252) deferred — gated on dev-shell artifacts; every
      backend bit is in place.
- 🟡 **Phase C (primitive only)** — `VzBackend::run_attached`
      foreground-supervisor primitive landed. The full builder-VM
      orchestration (`VzBuilderVm` impl of `BuilderVm`) is a
      follow-up slice gated on either mirroring `LibkrunBuilderVm`'s
      ~3,300 lines of substrate (virtio-fs `/work`/`/out`/`/job`,
      `mvm-builder-init` PID 1, Nix store overlay, kernel-panic
      console-log watcher, cmd.sh emission) or refactoring the
      shared parts behind a hypervisor-agnostic seam first.
- ✅ **Phase D** — `specs/adrs/056-vz-backend.md` filed; ADR-002
      backend table gained the Vz row. `.github/workflows/ci.yml::vz-macos`
      lane matrices the build over macos-13 + macos-latest with
      entitlement assertion + strict-decoder smoke.
- ✅ **Phase E (core)** — Supervisor control-socket IPC + pause /
      resume / balloon / snapshot SAVE. `<vm_state_dir>/control.sock`
      mode 0700; newline-framed protocol; Rust
      `vz_control::send_command` + `VzBackend` verbs (pause / resume
      / balloon_set_target / snapshot_save) wired through. RESTORE +
      audit-chain hashing of snapshot files remain follow-ups (needs
      CLI verb + different supervisor startup mode).

### Plan 98 — finishing slices  [`plans/98-vz-builder-vm.md`](plans/98-vz-builder-vm.md)

Vz builder one-shot driver (Phase 97 Phase C) shipped env-var-only.
Plan 98 closes the remaining gaps: auto-detect, `--builder` CLI flag,
`mvmctl doctor` reporting, Vz **persistent** parity with libkrun's
`mvmctl dev`, Install E2E on Vz, CI floor (`macos-latest` lane only —
no macos-26 self-hosted runner required), and docs (CLAUDE.md +
ADR-046 extension with security-claim-parity language). Plan 99 PR-1
(#448) is the Stage 0 audit/cache contract this builds on.

- [x] **Phase 1** — Selection user-surface (auto-detect + `--builder` flag + doctor + §0.x gap fixes). Shipped as [#455](https://github.com/tinylabscom/mvm/pull/455).
- 🟡 **Phase 2** — Vz persistent driver + Install E2E + security parity. Decomposed into four slices for review-sized PRs:
  - [x] **Slice 2A** — `VzPersistentBuilderVm` driver scaffold (§2.1-§2.3, §2.10, §2.C2). Shipped as [#460](https://github.com/tinylabscom/mvm/pull/460).
  - [x] **Slice 2B** — `mvmctl dev` routes through Vz when builder backend resolves to Vz + remove §2.C1 grace guard + §2.S11 env-var regression test. Shipped as [#461](https://github.com/tinylabscom/mvm/pull/461). §2.5 cross-backend coexistence dispatch + §2.8 doctor running-VM indicator deferred to a small follow-up (the prefix isolation in Slice 2A is the foundation).
  - 🟡 **Slice 2C** — Split into Slice 2C-ADRs (ADR text — [#465](https://github.com/tinylabscom/mvm/pull/465)) + the §2.S2-§2.S10 / §2.S13 security tests batch. ADR text shipped; security tests gated on macos-26 self-hosted hardware lane (§3.6) since they need real boots to validate.
  - [x] **Slice 2D** — Hermetic source-grep guards on the §2.11 in-repo-flake invariant. Shipped as [#464](https://github.com/tinylabscom/mvm/pull/464). True-E2E "Vz boots the in-repo flake" needs macOS 13+ hardware and folds into §3.6.
- [x] **Phase 3** — CI floor on `macos-latest` Vz construction smoke + Linux libkrun auto-detect assertion. Shipped as [#462](https://github.com/tinylabscom/mvm/pull/462). §3.6 (real `uv pip install` E2E under Vz on macos-26 self-hosted runner) stays deferred — gated on Plan 72 W4/W5 cutover same as the libkrun E2E Install round-trip.
- 🟡 **Phase 4** — Docs: CLAUDE.md selection-policy section shipped as [#458](https://github.com/tinylabscom/mvm/pull/458) (§4.1); ADR-046 extension + ADR-056 cross-link shipped as [#465](https://github.com/tinylabscom/mvm/pull/465) (§4.2 + §4.2c partial). The remaining §4.2a (ADR-002 per-claim sub-notes), §4.2b (ADR-047 "Backend symmetry" sub-paragraph), and the ADR-055/041/057 one-line cross-references ship as a small prose follow-up. This SPRINT.md close-out is §4.3 itself.

### Cross-cutting

- [ ] Build / distribution / versioning (Swift toolchain in CI,
      `Package.resolved` pinned, lockstep version with `mvmctl`,
      source-checkout determinism — no prebuilt download).
- [ ] Apache-2.0 + MIT dual license on the Swift package.
- [ ] mvmd backend-enum addition follow-up (cross-repo).
- [x] Tracking issue for the cataloged **future work — Windows host
      via WHP** ([#428](https://github.com/tinylabscom/mvm/issues/428);
      separate initiative, not in this sprint).

### Security claims under Vz

Full audit lives in [`plans/97-vz-backend.md` §"Can we still make all
nine ADR-002 security claims?"](plans/97-vz-backend.md). Summary: all
nine **inherit unchanged** from existing claim-machinery now that the
supervisor is Rust (the Swift binary was deleted in Plan 152, so the
two "new/extends" items below collapsed into the shared Rust pipeline):

- **Claim 5** — the supervisor config parser is the Rust `SupervisorConfig`
  serde struct (`#[serde(deny_unknown_fields)]`), fuzzed by
  `crates/mvm-build/fuzz/fuzz_targets/fuzz_supervisor_config.rs` in the
  `security.yml` `fuzz` job — the same harness that backs the libkrun
  supervisor parser. The original Swift `JSONDecoder` / Swift↔Rust
  equivalence criterion is **retired**: there is no Swift decoder to
  reach equivalence with (Plan 152 deleted the Swift crate).
- **Claim 8** — `VzBackend::start_with_mode` routes through
  `mvm_supervisor::admit_for_run`; fail-closed test asserts bypass
  refuses launch.
- **Claim 7** — the Vz supervisor is now an ordinary workspace binary
  (`mvm-vm-host` → `mvm-vz-supervisor`), so it rides the existing cargo
  reproducibility double-build + `cargo-deny`/`cargo-audit` supply-chain
  pipeline like every other crate. No separate Swift toolchain or SPM
  `Package.resolved`; the "extends" framing is **retired**.

Additional security items (kernel cmdline lockdown, resource-cap parity,
console mode lockdown, VM identifier handling, supervisor as a security
boundary, crash diagnostics, MDM detection) covered in Plan 97
§"Security considerations" — checkboxes tracked in the plan file.

### Live Vz validation — unblocked 2026-06-11

Sealed-workload `/init` on Vz now detaches stdin from the input-less
console (`< /dev/null`), closing the foot-gun where a workload's PID 1
hit EOF ~5 s after boot and triggered a kernel reboot. `examples/sleeper`
is the designated long-lived fixture for live Vz round-trip validation.

The first live bringup attempt (2026-06-11) hit a different, pre-existing
wall before boot: the builder VM's boot-time egress lockdown (OUTPUT DROP,
proxy-uid-only — active since iptables-legacy landed on 2026-06-05) drops
every nix fetch, so any cold or new-dep flake build on macOS fails with
"Could not resolve host". Diagnosed end-to-end (Stage 0 fetches fine; the
builder VM on the same host cannot resolve) and opened as **Plan 183**
(`specs/plans/183-builder-vm-egress-posture-and-dns.md`): scope the
lockdown to the install arm, add a static-gvproxy fallback for the Vz
builder's DHCP no-lease, make resolv.conf writable. Live bringup + fork
semantic-A spike resume as Plan 183 WS-D.

**2026-06-12: Plan 183 complete — first live Vz workload boot.** Cold
`dev up` fetches inside the builder again (libkrun + Vz; the Vz no-reply
link was an unbound guest-side datagram socket, fixed in WS-E), and the
sleeper fixture booted on Vz through the full admitted path: agent on
vsock, `vm_full` checkpoint + `pause`/`resume` round-trips green. The
fork semantic-A spike is answered: VZ refuses machine-state restore into
a changed device config (`VZErrorDomain:12`), so semantic B stands and a
live two-copy Vz fork goes through the fs_quick class. fs_quick-on-Vz,
vm_full-restore gvproxy re-spawn, and restore idempotency are tracked as
Plan 183 follow-ups.

**2026-06-12 (later): two-copy fork live.** `vm checkpoint fork <fs_quick>
--new-id <child> --boot` admits a fresh plan for the child (hash of the
forked rootfs, parent's resource shape, fresh nonce) and boots it without
clobbering the materialized copy; parent and child ran side by side for
over an hour, each with its own agent, gvproxy, and admitted identity.
Sidecar propagation made instance dirs self-describing (mvm-meta.json
travels with rootfs clones and checkpoint content), which is what lets
checkpoint-derived rootfs trees pass the runtime-meta boot gate.

**2026-06-13: instant memory fork productized.** The vm_full fork arm now
admits a fresh claim-8 plan for the forked child before spawning it.
The working model is semantic B without the stopped-parent constraint:
VZ validates the restored machine state against the saved device
configuration, so MAC and machine-id are fixed by the snapshot — the
child keeps them, which is safe because every VM runs behind its own
per-VM gvproxy with no shared L2 segment. Forking a RUNNING parent
(the spike result: 0.91 s (with full claim-8 admission) wall-time to a second live VM with both
control planes responsive) is now the production contract.
`--cpus`/`--memory` are refused on vm_full forks with a clear error
pointing to fs_quick for resize; bridge-style non-gvproxy attachments
are hard-refused at fork time (gvproxy-only invariant). The child's
supervisor config carries its own plan, tenant, and audit substrate —
the parent's plan is not reused.

**2026-06-13: Vz warm pool (saved-standby) live.** `pool warm` boots a seed, captures its memory+rootfs into the pool, stops it (pid=0 saved standby); `up --warm-pool-size N` then claims a compatible standby — "Claimed a warm standby — skipping cold boot" fires, the restored VM is alive and pause/resume-responsive. Latency is workload-dependent: on the trivially-fast default image a warm claim (~2.3 s) matches a cold boot (~2.1 s) because restoring 512 MiB of memory costs about what a tiny guest's cold boot does; the reclaim materializes for heavy-init workloads. Two live-found bugs fixed: the gateway-bridge drainer now decodes the signed plan envelope (not a bare plan), and the seed supervisor-config is persisted into the pool dir (the seed's own dir is torn down at stop).

**2026-06-13: warm pool self-replenishes (#840).** After a Vz claim drains the pool, `up` hands the re-warm to a detached `mvmctl pool warm` subprocess (own process group, null stdio, inherits env) so `up` returns immediately and the pool tops itself back up in the background — making the pool production-usable rather than draining to zero on first claim. The child does the idle-check + rootfs hash off `up`'s hot path. Live: claim drained the pool 1→0, the detached re-warm booted a fresh seed and refilled to 1 idle, `up` never waited. Known follow-up (documented in-code): no pool lock means concurrent claims against the same image can transiently overshoot target by ~1 each (ages out via the standby TTL); a pool-dir flock is the clean fix. Companion perf (#846): the warm claim now reuses the rootfs sha claim-8 admission already computed (`ExecutionPlan.image.sha256`) instead of re-hashing the rootfs a second time on the launch hot path — byte-identical compat, chosen over coupling the key to the Plan 189 WS-2 fingerprint (which would weaken the claim-8 byte-identity guarantee).

**2026-06-13: close-out full-stack validation + criterion reconciliation.**
Ran the headline chain live on the macOS-26 Vz host and reconciled every
Sprint 55 / Plan 97 criterion (see "success criteria" above). Evidence by leg:

- **Boot + admit + agent (legs 1/3):** `up --hypervisor vz` on the cached
  default image wrote the full claim-8 chain — `cmd.up.invoked → plan.admitted
  → plan.policy_resolved → plan.launched → cmd.up.completed` — the guest booted
  (ext4 root mounted, `Run /init`), and the guest agent reached `control plane
  ready` listening on vsock 5252. (The host-side vsock connect saw intermittent
  resets on this run — the known Vz vsock-bridge flakiness; the `examples/sleeper`
  fixture run earlier this sprint achieved a stable host↔agent connection.)
  `dev up --builder vz` cold-build is Plan 183 WS-D (703 in-builder fetches, 0
  resolve failures).
- **App-deps sealed volume (leg 2):** claim 11's `verify_sealed_volume` is
  hypervisor-agnostic and the `VzBuilderVm` runs the identical job substrate as
  `LibkrunBuilderVm`; claim-11 gates green on the cold builder path (Plan 183
  WS-D). Not re-run backend-specifically in this pass — the sealing + verify is
  backend-independent by construction.
- **Secrets / egress (leg 4):** deny-by-default egress (claim 10) is live on the
  vz launch — `doctor` reports `claim 10 holds (deny_all)` and the booted guest's
  netinit installed the deny CIDRs (cloud-metadata / link-local / cgnat /
  loopback); the chain-signed audit recorder is active (chain written + verifies).
  Secret **substitution (claim 13)** has since been ported to macOS via the `Uds`
  vsock-5253 channel and is **DATA-PLANE PROVEN LIVE on vz** (2026-06-15, Plan 197
  Phase 2a; the `up --name -d` → `vm wait` → `invoke --attach` driver sidesteps the
  5252 early-boot race): httpbin reflects the real Bearer credential while the guest
  holds only the `mvm-secret-…` placeholder (claim 13), a non-allowed host is refused
  by the endpoint (claim 12), and repeated dials keep the 5253 listener accepting.
  Endpoint spawn is gated by the #909 pre-start `plan.json` persist on both the `up`
  and `invoke`/`run` arms. The transparent :80/:443 terminator (claim 16) is
  Linux-only by architecture (`SO_ORIGINAL_DST` + nft TAP REDIRECT) and is `None`
  on QEMU too — its macOS form is Plan 197 Phase 2b (rvproxy-gated).
- **Audit (leg 5):** `trust audit verify --tenant local` on the vz workload's
  chain exits 0 ("verifies clean: 8 entries"); a one-byte tamper of the
  `plan.admitted` entry makes it exit 1 ("audit chain verify failed: signature
  invalid").
- **Doctor claims (leg 6):** `doctor` resolves `Active backend: vz`, Tier 2,
  L1–L5 layer coverage, claims **1 and 2 hold**, **claim 10 holds**, with
  `dropped_claims = [3]` — claim 3 (dm-verity verified boot) is `DoesNotHold` on
  the macOS tier, **identically for libkrun, vz, and qemu** (all Tier 2). So it
  is a Tier-2-macOS property at parity, not a vz regression.

Item-F close-out: warm-pool overshoot flock CLOSED (`warm_to_target` holds a
pool-dir `FileLock` across read→spawn; deterministic test). Stale vz `doctor`
notes truthed-up (claim 5 holds via the Rust `SupervisorConfig` fuzz; control
socket shipped). Persistent-builder gvproxy + the `doctor` builder-egress line
remain deferred-with-reason (Plan 183 follow-ups); VzIngest/`mvm-vz-drainer`
dead-code sweep stays a dedicated follow-up (Plan 152 block).

Post-closeout dev-loop polish (2026-06-15): vz `up`/`down` taken sub-second.
The startup orphan-helper sweep was collapsed from a per-VM-dir `pgrep -f` +
per-pid `ps` storm (seconds across hundreds of cached builder scratch dirs)
into a single `ps -axww` snapshot matched in-process (#868). The plan's image
digest is cached on a `<rootfs>.sha256cache` size+mtime sidecar instead of
re-hashing ~230 MB on every boot (#868). `down` no longer waits out the host
SIGKILL grace: the supervisor escalates the graceful ACPI stop to a forced
`stopWithCompletionHandler` after a short window and exits clean (#868).
`up --console` boots straight into the PTY-over-vsock console, forcing the dev
image since a sealed prod image ships no console agent (#870). A companion fix
stops the startup sweep from reaping live managed/dev VMs reparented to launchd
(#868). Net: warm `up` ~0.45 s, `down` ~0.45 s with no SIGKILL.

### Sprint 55 success criteria — reconciled 2026-06-13 (post-Swift, post-convergence)

Each criterion below is marked **met**, **amended** (criterion text no
longer matches reality; reworded + then met), or **blocked**. The
reconciliation pass closed the Vz backend effort; see the close-out
log under "Live Vz validation" for the evidence trail.

- [x] **Phase A** — met. The Rust `mvm-vz-supervisor` boots a workload
  image end-to-end with working vsock to the guest agent. The original
  text said "dev-shell image"; the designated long-lived fixture is
  `examples/sleeper` (a dev-shell PID 1 hits console EOF ~5 s after
  boot — see WS-E). Live 2026-06-12.
- [x] **Phase B** — met (criterion **amended**). `MVM_BACKEND=vz
  mvmctl run` boots a workload microVM directly on macOS. The
  "≥30% cold-boot win vs. nested libkrun→Firecracker" clause is
  **retired**: post-Plan-177 convergence there is no nested
  libkrun→Firecracker workload path on macOS to benchmark against —
  both macOS backends host the Linux guest directly, so the nesting
  collapse the 30% target proxied for is achieved by construction.
  (On the trivially-fast default image a vz boot ~2.1 s is on par with
  a libkrun boot; the win materializes for heavy-init workloads via the
  warm pool, not raw cold boot.)
- [x] **Phase C** — met (criterion **amended**). `MVM_BUILDER_BACKEND=vz
  mvmctl build` produces a **functionally equivalent** rootfs: same Nix
  derivation, same boot + guest-agent behavior. The original
  "byte-identical hash" clause is **retired** as unmeetable — ext4
  image assembly is non-deterministic (mtimes / inode ordering /
  free-block layout differ every build), so even two libkrun builds of
  the same derivation differ byte-for-byte. Functional parity is the
  correct bar and it holds: the two backends consume the identical
  `nix/images/builder-vm/` flake and the same `VzBuilderVm` /
  `LibkrunBuilderVm` job substrate.
- [x] **ADR-056 landed; ADR-002 backend table updated** — met.
- [x] **Phase E (macOS 14+)** — met. `mvmctl checkpoint` (the renamed
  snapshot surface) round-trips a workload microVM: `vm_full`
  save/restore live-proven (Plan 159 WS-2), incl. responsive control
  plane on the restored VM and restore-while-running refusal.
- [x] **`cargo test --workspace` + `cargo clippy --workspace -D warnings`
  clean with both backends compiled in** — met (the standing CI gate;
  the lone local caveat is the `mvm-backend` test-bin macOS codesign
  SIGKILL, an environmental amfid issue, not a code defect).
- [x] **`mvmctl doctor` reports claims on a Vz-backed workload microVM**
  — met (criterion **amended**), live-confirmed 2026-06-13: `doctor`
  resolves `Active backend: vz` and reports claims **1 and 2 hold**,
  **claim 10 holds** (`deny_all`), with `dropped_claims = [3]`. The
  original "claims 1, 2, 3 green" wording is **amended**: claim 3
  (dm-verity verified boot) is `DoesNotHold` on the macOS tier — and it
  is so **identically for libkrun and vz** (`libkrun.rs` and `vz.rs`
  carry the same `ClaimStatus::DoesNotHold` + "dm-verity pipeline
  targets Firecracker today" note). So claim 3 is a Tier-2-macOS
  property at exact parity with the macOS default, not a vz regression;
  wiring the verified-boot pipeline to the macOS backends is a shared
  follow-up (claim 3 is a Firecracker/prod-tier property by ADR-002).

### Non-goals (explicit)

- Replacing libkrun as the macOS default.
- Touching the Linux Firecracker path in any way — it remains the
  default and the production deploy path.
- Removing the nested Firecracker-in-libkrun path on macOS (it stays
  available; Vz is parallel).
- Vz on Linux (user-confirmed not wanted; Firecracker-direct is better
  on every dimension that matters).
- Live VM migration across hosts.

## Sprint 56 — Symmetric trust boundary + claim 10 (proposed)  [`adrs/057-symmetric-builder-vm.md`](adrs/057-symmetric-builder-vm.md) | [`plans/100-symmetric-builder-vm-rollout.md`](plans/100-symmetric-builder-vm-rollout.md) | [`adrs/058-claim-10-bytes-leaving-trust-boundary.md`](adrs/058-claim-10-bytes-leaving-trust-boundary.md) | [`plans/101-in-guest-volume-encryption-and-gateway-audit.md`](plans/101-in-guest-volume-encryption-and-gateway-audit.md)

### Why this sprint

Two structural gaps in the current trust story:

1. Linux host's userland is in the TCB; macOS host's isn't (asymmetric trust). The same `mvmctl` should give the same claim posture on both. See [ADR-057](adrs/057-symmetric-builder-vm.md).
2. RW tenant volumes are plaintext while mounted; gateway traffic is unaudited. A compromised host can read tenant data and exfil silently — both invisible to the audit chain. Plan 63 / ADR-042 cover host-side snapshot crypto + secret store, but not the in-use mount surface. See [ADR-058](adrs/058-claim-10-bytes-leaving-trust-boundary.md).

### W1 — Symmetric builder VM  🟡 in flight  [`plans/105-plan-100-w1-linux-builder-vm.md`](plans/105-plan-100-w1-linux-builder-vm.md)

See [Plan 100](plans/100-symmetric-builder-vm-rollout.md). Lifts claim 1 ("no host-fs access from a guest") to true-on-both-OSes via identical builder-VM TCB. Retires the direct-Firecracker-on-Linux path.

Plan 100 W1 — implementation tracker (Plan 105). First slice: env-gated `MVM_LINUX_BUILDER_VM=1` dispatch + `has_nested_kvm()` predicate + `mvmctl doctor` `nested-kvm` line. Opt-in only; default unchanged. The default flip + direct-Firecracker retirement is W6.

- [ ] **W0** — feasibility prototype (off-branch, throw-away): measure cold-start latency on a Linux + nested-KVM host. Numbers feed into the W1 PR body.
- [x] **W1** — `MVM_LINUX_BUILDER_VM` env-gate in `crates/mvm-build/src/builder_backend_select.rs` + `Platform::has_nested_kvm()` predicate + hermetic unit tests. Shipped in PR #479.
- [x] **W3-doctor** — `mvmctl doctor` reports nested-KVM availability + extends the Plan 98 `builder backend` line with the `MVM_LINUX_BUILDER_VM` source. Bundled with W1 prep (PR #479).
- [x] **W2** — Linux Nix image build validation. Paths-gated `builder-vm-image-linux` lane in `ci.yml` builds the builder-vm flake on Ubuntu and asserts the four output artifacts land on disk. Bundled with W1 prep PR (#479).
- [ ] **W6 dispatch flip** — brainstorm in [Plan 106](plans/106-plan-100-w6-dispatch-flip.md) (decision locked 2026-05-27 on Approach A: shared libkrun host VM, Firecracker per workload). Executable phases A1–A6 tracked in [Plan 107](plans/107-plan-100-w6-approach-a.md).
  - [x] **A1a** — protocol type rename (`BuilderRequest`/`Response` → `HostVmRequest`/`Response`) + `LibkrunPersistentBuilderVm` → `LibkrunPersistentHostVm` + new workload stub variants + 9 hermetic tests. Shipped in PR #503.
  - [x] **A1b** — crate rename (`mvm-builder-init` → `mvm-host-vm-init`) + Stage 0 byte-scan migration (`/sbin/mvm-host-vm-init` + 15 sites in `apple_container.rs`) + Nix flake updates + guest-side workload arms with `unimplemented!()` stubs until A2.2. Shipped in PR #506. Cached pre-rename rootfs images fail-closed on first `mvmctl dev up` after merge.
  - [x] **A2** — Firecracker-in-guest launch path.
    - [x] **A2.1 + A2.2 + A2.3** — bake `firecracker` into the builder-vm rootfs at `/usr/bin/firecracker`; `WorkloadStart` arm spawns a workload microVM via a `WorkloadVmm` trait (no VMM lock-in — `FirecrackerVmm` is the only Firecracker-aware type, spawns `firecracker --config-file`); per-workload state dir at `/var/lib/mvm/workloads/<id>/` with collision-detect + `Drop` cleanup; `WorkloadFailed` fail-closed response. Hermetic tests only (no live KVM). Shipped in PR #507.
    - [x] **A2.4** — live spawn smoke (`workload-spawn-smoke-linux` lane): boots a real Firecracker workload via `start_workload` on a stock GHA runner at **L1** `/dev/kvm` (the runner stands in for the host VM; no nested KVM needed). The original "nested-KVM" framing was over-claimed — true L2 nesting (Firecracker inside a libkrun guest, the no-`ptrace` uplift) is **deferred to A4.5**'s live-KVM smoke.
    - [x] **A2.5** — `builder-vm-image-reproducibility` lane double-builds `nix/images/builder-vm/` and asserts byte-identical outputs (guards A2.1's firecracker closure). Release/nightly/dispatch only.
  - [x] **A3** — vsock nesting hop. In-host-VM forwarder (`workload_proxy`) bridges a fixed forward port (21472) → each workload's Firecracker `v.sock`, multiplexed by a `<workload_id> <port>` handshake; host-side `NestingHopTransport`; bounded-concurrency guardrail (`ConnectionLimiter`); workload agent unchanged. Hermetic tests (framing/tamper/oversize/bit-equivalence/cap). A3.a/b/c in #513; A3.d/A3.5 follow-up. Live cross-hop boot deferred to A4.5.
  - [ ] **A4 / A5 / A6** — `mvmctl up` wires the path / retire direct-Firecracker / docs + claim rewording. Each its own PR per Plan 107.
- [ ] **W4 / W5 / W7 / W8** — gated on Plan 107 A4 landing.

### W2 — Volume confidentiality (claim 10 leg 1)  🟡 proposed

See [Plan 101 W1–W5](plans/101-in-guest-volume-encryption-and-gateway-audit.md). LUKS-in-guest + ExecutionPlan-delivered wrapped keys. Distinct from Plan 63's host-side snapshot crypto; this covers the in-use mount surface.

### W3 — Audited gateway traffic (claim 10 leg 2)  🟡 in progress

See [Plan 101 W6–W10](plans/101-in-guest-volume-encryption-and-gateway-audit.md). gvproxy + passt emit flow events into the audit chain. Sample-rate aggregation keeps audit volume sane.

Wave breakdown:

- W6 — gateway audit substrate: in flight via [Plan 102](plans/102-gateway-audit-substrate-impl.md) (design contract) + [Plan 103](plans/103-w6a-implementation-tracker.md) (W6.A implementation tracker). W6.A lands the no-bypass + observable + mediable substrate across all three backends (libkrun+passt, libkrun+gvproxy, Vz+gvproxy) as a 9-commit PR; W6.B real flow extraction follows.
- W7 — `LocalAuditKind` flow event schema: shipped (PR #450).
- W8 — sample-rate / 30s aggregation + `NetworkAuditConfig`: not started, depends on W6.
- W9 — `mvmctl audit traffic` CLI surface: not started, depends on W6/W7.
- W10 — `claim-10-audit-tamper` CI gate: not started, depends on W6.

Scope clarification: W6 covers **north-south** only (microVM ↔ internet through the per-VM gateway). The mvm topology multiplexes per-VM gvproxy/passt instances; inter-microVM traffic on the same host goes through the tenant bridge (`br-tenant-<id>`) and is **not** visible to gateway audit.

Out of scope for this sprint:

- East-west microVM ↔ microVM audit — proposed as a new wave (W11) needing a different capture mechanism (`tc mirred`, eBPF, or libpcap on the TAP). Not blocking W6.
- Secret detection + egress obfuscation — separate proposal track. Requires L7 visibility (TLS MITM or cooperating in-guest hook); needs its own brainstorm + ADR before any code.
- Side-channel information leakage via flow timing — inherent to any flow audit; accepted in ADR-058 amendment landed via [Plan 103](plans/103-w6a-implementation-tracker.md).
- Audit-metadata-at-rest encryption — the chain itself is plaintext on host disk under `~/.mvm/audit/<tenant>.jsonl`. Tenant *data* is encrypted (claim 10 leg 1); tenant *metadata* is not. Future claim 10.1 candidate; not this sprint.
- Multi-user shared host with the same UID — same-UID local attacker can read the gateway subscriber socket; documented as accepted. Mode 0700 covers cross-UID; cross-UID-same-user is out of scope.
- Per-byte content capture by default — coverage (every byte traverses the bridge) is structural; full pcap into the chain is opt-in for forensics (future `network_audit.mode = full_pcap`), not default. Aggregated `FlowBytes` lands in W8.
- L7 URL inspection (path-level allowlist) — composes via `L7EgressProxy` Phase 2 (TLS MITM with workload-CA trust); substrate exists, finalization is a separate plan ([Plan 34 / ADR-006](adrs/006-name-constrained-egress-ca.md)).
- DNS-over-HTTPS bypass mitigation — separate Plan 74 follow-up: mandatory-deny well-known DoH endpoints.

### W4 — Crypto attestability (claim 10 leg 3)  🟡 proposed

See [Plan 101 W11–W14](plans/101-in-guest-volume-encryption-and-gateway-audit.md). Key fingerprints + `mvmctl doctor claim_10` row + docs. New `claim-10-audit-tamper` CI gate.

### Sprint 56 success criteria

- New `claim-10-audit-tamper` CI job gates every PR.
- `mvmctl doctor` reports both claim 1 (symmetric TCB) and claim 10 (in-guest crypto + flow audit) as green.
- Threat-model test (a host process attempting to read the volume backing file mid-workload) confirms ciphertext-at-rest.
- Builder VM lifecycle is identical on macOS and Linux; direct-Firecracker code path retired.
- ADR-002 claim list extends from 1–9 to 1–10; CLAUDE.md security model updated.

### Non-goals (explicit)

- TLS termination / L7 packet inspection in the gateway bridge (substrate composes via `L7EgressProxy` per [Plan 34 / ADR-006](adrs/006-name-constrained-egress-ca.md); not this sprint's work).
- Host filesystem encryption (FDE is user's concern).
- Hardware-backed key attestation (still future).
- Reintroducing Lima (removed 2026-05-14; symmetric posture achieved via `mvm-libkrun` on both hosts).
- Per-byte content capture by default — coverage is structural via the W6.A bridge ([Plan 103](plans/103-w6a-implementation-tracker.md)); capture is opt-in future mode.
- Side-channel information leakage via flow timing (accepted in ADR-058 amendment).
- Audit-metadata-at-rest encryption (future claim 10.1).
- Cross-tenant network management (per-tenant gateway pool, egress quotas, tenant-level rollup) — mvmd cross-repo plan (`mvmd-network-manager`); flagged in [Plan 103](plans/103-w6a-implementation-tracker.md) `## Phase 6`, owned in mvmd.

## Sprint 57 — Host services broker over vsock — IN PROGRESS  [`plans/104-host-services-broker.md`](plans/104-host-services-broker.md) | [`adrs/059-host-services-broker.md`](adrs/059-host-services-broker.md) + [`adrs/061-host-services-broker-hardening.md`](adrs/061-host-services-broker-hardening.md) + [`adrs/062-host-services-broker-rescope-drop-secrets.md`](adrs/062-host-services-broker-rescope-drop-secrets.md)

### Why this sprint

> **Rescoped 2026-05-28 — ADR-062.** Originally drafted around `host.secrets.v1` as the load-bearing forcing function. Project-direction review dropped `host.secrets.v1` and `mvm-secrets-dispatcher` from v1 scope; the architecture is now **3 subprocesses** (down from 4), and **`host.audit.v1`** (workload-emitted audit entries) becomes the load-bearing workload service in place of secrets. The W1a–W1b.2b.3 hardening infrastructure (already merged via PRs #478, #480, #481, #482, #483, #486) is preserved unchanged.

Today admission to microVMs is single-process: the supervisor signs `ExecutionPlan`s, writes the audit chain, and would (under ADR-049's original design) also broker any host-side services workloads need. This sprint pivots the host-side surface to a **three-subprocess broker architecture** (per Plan 104 §Hardening posture L1, narrowed by ADR-062): `mvm-broker` (uid 903, general handlers including the new `host.audit.v1`), `mvm-host-signer` (uid 904, host-signer key isolation), and `mvm-audit-signer` (uid 905, sole audit-chain writer). Each subprocess runs under seccomp + setpriv + per-workload cgroup + namespace isolation. The supervisor becomes a pure launcher + admission controller + IPC router; the host signer key is never loaded into the supervisor's address space, and the audit chain-signing key is never loaded into anything but `mvm-audit-signer`. Workloads gain a first-class **`host.audit.v1`** path for emitting their own chain-signed audit entries (distinct `WorkloadAudit` category so the verifier can tell workload-asserted from supervisor-observed). Designed for **highest-defensible security** — hardware-enclave host signer (W8, Apple SE + Linux TPM 2.0), per-binary cosign + TOCTOU-resistant exec + config-signing, per-spawn subprocess response keys, algorithm-identifier byte for crypto agility, audit-log encryption at rest with TPM-derived keys, Sigstore/in-toto supply-chain transparency, threat-model expanded to include software insider attacks. Cost (post-rescope): roughly 2–3 sprints of work; one less subprocess + no SDK matrix to maintain.

### Workstream breakdown

- [ ] **W1 — Three-subprocess infrastructure substrate** (envelope, registry, single vsock listener per VM on port 5300; three new crates: `mvm-broker`, `mvm-host-signer`, `mvm-audit-signer`; supervisor subprocess lifecycle for all three; UDS proxy code paths; cosign-verify + TOCTOU-resistant exec + config-signing per subprocess; per-workload cgroup + namespace isolation; resource caps; binary hardening; doctor host-posture checks; KSM/THP off; `fido_touch_required()` stub on `mvmctl up --prod`) — *rescoped from "four-subprocess" by ADR-062; `mvm-secrets-dispatcher` + port 5301 dropped*
- [x] W1b.1 CI follow-up (2026-05-27): documented all four broker subprocess bins as architecture-invariant substrate allowlist entries, and hardened the oversized-frame broker server test to accept either EOF or `ECONNRESET` on rejection.
- [x] W1b.2a CI follow-up (2026-05-27): documented all four broker subprocess bins as architecture-invariant substrate allowlist entries, and hardened the oversized-frame broker server test to accept either EOF or `ECONNRESET` on rejection.
- [x] W1b.2b.1 CI follow-up (2026-05-27): documented all four broker subprocess bins as architecture-invariant substrate allowlist entries, hardened the oversized-frame broker server test to accept either EOF or `ECONNRESET`, removed the stale Linux `CommandExt` import, and annotated `SecretsProxy` with the project-standard `allow(secret-debug)` justification.
- [x] W1a CI follow-up (2026-05-27): documented `mvm-broker` as an explicit architecture-invariant substrate allowlist entry, and hardened the oversized-frame server test to accept either EOF or `ECONNRESET` on rejection.
- [x] W1b.2b.3 CI follow-up (2026-05-27): switched the architecture invariant from file-path exceptions to crate metadata for the four broker subprocess crates, hardened oversized-frame subprocess tests to accept EOF or `ECONNRESET` and skip sandbox `EPERM` on local UDS bind, fixed the supervisor `tokio::process::Command` `pre_exec` hook, and annotated `SecretsProxy` with the approved `allow(secret-debug)` justification.
- [ ] **W2 — `ExecutionPlan.services` + admission wiring + audit-signer wiring** (schema bump 4→5; registry assembly; `EventCategory::ServiceCall` routed through `mvm-audit-signer`; `O_APPEND` audit FD + dir-immutable; chain-head persistence; at-rest encryption; time-source integrity; rate-limit / lifetime-quota / circuit-breaker; session-key rotation; operator-action audit entries)
- [ ] **W3 — `host.time.v1`** (handler in `mvm-broker` + `broker.v1/list_services` + delete `HostBoundRequest::QueryHostTime`)
- [ ] **W4a — `host.cost.v1` workload-scope** (handler in `mvm-broker`; no mvmd dep)
- [ ] **W4b — `host.cost.v1` cross-tenant via mvmd** (depends on mvmd Plan 52 W1+W2+W3; mvmd-response validation; tenant-level secret quotas; mvmd identity pinning)
- [x] **W5 — `host.secrets.v1` inside `mvm-secrets-dispatcher`** — **DELETED by ADR-062 (2026-05-28).** Subprocess scaffold removed in PR C of the rescope sequence; the rest of the W5 surface (per-spawn response signing, seccomp policy compliance, side-channel audit, latency floor) was secrets-specific.
- [ ] **W3-audit — `host.audit.v1` (workload-emitted audit entries)** *(new in ADR-062)* — `HostAuditV1Handler` in `mvm-broker`; verbs `emit` + `emit_batch`; per-record cap 4 KiB; rate limit 20/sec/workload; `audit_durability = PerCall`; new `EventCategory::WorkloadAudit` variant in `mvm-audit-signer`; workload-id mismatch refused; chain verifier distinguishes workload-asserted from system-asserted entries
- [ ] **W6 — Fuzz + CI + mutation testing** (`fuzz_service_call.rs`, UDS-proxy fuzz, `xtask check-handler-*` + `xtask check-subprocess-fd-inheritance` lints, `cargo-mutants` lane, cross-backend test matrix, hostile-subprocess test per subprocess kind)
- [x] **W7 — ADR-049 §W3 SDK matrix** — **DELETED by ADR-062 (2026-05-28).** Per-language credential-substitution hook libraries no longer needed: `host.secrets.v1` is dropped, no `mvm-secret://` placeholder exists, no SDK has anything to substitute.
- [ ] **W8 — Hardware-enclave host signer** (Apple Secure Enclave on macOS + Linux TPM 2.0; algorithm-identifier byte enables P-256; `mvmctl host-key rotate` ceremony + TPM monotonic counter for rollback resistance; audit-encryption key migration to TPM/SE-derived master; software fallback retained with loud doctor downgrade)
- [ ] **W9 — Supply chain + release hardening** (Sigstore/Rekor transparency log entries per subprocess release; in-toto attestations alongside SLSA; per-binary hermetic + reproducibility-double-build lane; CODEOWNERS + branch protection; `cargo-mutants` lane; crypto-crate pinning + `deny.toml` + RFC-8785 JCS conformance)
- [ ] **W10 — Documentation + threat model** (`specs/threat-models/02-host-services-broker.md` STRIDE walk per service; `SECURITY.md` CVE response runbook; `docs/security/{audit-fields,deployment-modes}.md`; operator runbook; CLAUDE.md update)
- [ ] **W11 — Operator FIDO ceremony full implementation** (may slip to Sprint 58 follow-on; Yubikey-touch on `mvmctl up --prod`; encrypted-USB fallback for non-FIDO hosts; doctor probes; `mvmctl host-key rotate` requires FIDO touch)

### Cross-repo dependency (mvmd)

- [ ] mvmd **Plan 52** — host services cross-VM endpoints (`../mvmd/specs/plans/52-host-services-cross-vm-endpoints.md`)
- [ ] mvmd **ADR-0023** — mvmd as cross-VM delegate (`../mvmd/specs/adrs/0023-mvmd-host-services-delegation.md`)

mvmd Plan 52 W1+W2+W3 must land before mvm W4b opens; mvm W1–W4a + W5–W11 have no mvmd dep and land in parallel.

### Security claims under this sprint

Two new claims at numbers **12** and **13** (ADR-002 rows updated by ADR-062 — Sprint 56 holds claim 10):
- **Claim 12** — Every host-side service is bound to a signed `ExecutionPlan.services` entry, enforced before dispatch, audited via the chain.
- **Claim 13** *(rewritten 2026-05-28 by ADR-062)* — Every workload-emitted audit entry (via `host.audit.v1`) is chain-signed by `mvm-audit-signer` under the `WorkloadAudit` category, distinguishable from supervisor-emitted entries; tampered entries fail `mvmctl audit verify`; workload-id mismatch refused at admission.

ADR-059 additionally documents the narrowing of ADR-002's "malicious host" out-of-scope clause: physical attacks (cold-boot, DMA, hardware tampering) remain out of scope, but *software* insider attacks (shell access to the host by an unauthorized operator) are newly in scope thanks to L1 process isolation + L2 hardware-enclave keys + L5 at-rest audit encryption.

### Sprint 57 success criteria

- [ ] `ExecutionPlan.services` schema landed and signature-verified at admission (`SCHEMA_VERSION` bumped 4→5).
- [ ] All **three** subprocesses (`mvm-broker`, `mvm-host-signer`, `mvm-audit-signer`) cosign-verified at spawn, configured via signed JSON config, running under per-arch seccomp + setpriv + per-workload cgroup + namespace isolation. *(`mvm-secrets-dispatcher` dropped by ADR-062.)*
- [ ] `mvm-broker` listens on vsock 5300; dispatches `host.time.v1` / `host.cost.v1` / `host.audit.v1` / `broker.v1`.
- [ ] `mvm-host-signer` is the sole holder of the host signer key; supervisor signs plans via UDS RPC. HW-enclave path live on macOS SE + Linux TPM 2.0 (W8); software-fallback row in doctor.
- [ ] `mvm-audit-signer` is the sole writer to `~/.mvm/audit/<tenant>.jsonl`; sole holder of the audit chain-signing key; `O_APPEND` FD + dir-immutable + chain-head persistence + at-rest AEAD encryption all enforced; allow-listed categories include `Admission` / `ServiceCall` / `WorkloadAudit`.
- [ ] `host.audit.v1` accepts `emit` + `emit_batch` from bound workloads; per-record cap 4 KiB; per-workload rate limit 20/sec; chain entries land under `WorkloadAudit` category distinguishable in `mvmctl audit verify`; workload-id mismatch refused.
- [ ] Subprocess crash isolation verified for each kind: kill any subprocess → supervisor survives, workload sees `Err(Unavailable)`; kill supervisor → all three subprocesses exit cleanly via pdeathsig/kqueue.
- [ ] `HostBoundRequest::QueryHostTime` deleted; internal caller migrated to broker.
- [ ] `fuzz_service_call.rs` ≥5min/PR in CI; UDS-proxy fuzz lane; `xtask check-handler-*` + `xtask check-subprocess-fd-inheritance` lints block orphans; `cargo-mutants` lane catches mutation escapes.
- [ ] Cross-backend test matrix green on libkrun / Firecracker / Apple Container / vz; **single vsock port (5300) listens on all four backends** (vz requires new `VZVirtioSocketListener` Swift class).
- [ ] Per-binary reproducibility-double-build lane green for all three subprocesses; Sigstore/Rekor entries present for the release artefacts; in-toto attestations alongside SLSA.
- [ ] mvmd Plan 52 endpoints live (iroh ALPN, signed catalog responses); mvm W4b green; cross-tenant authz refused; malformed-mvmd-response rejected; tenant-level audit quota enforced; mvmd identity pin enforced.
- [ ] `mvmctl doctor` refuses admission on weak hosts (KASLR, KPTI, SMEP/SMAP, Spectre-v2, LSM, KSM, THP, etc.) and on known-affected vsock CVE versions; `--insecure-host` audits + warns.
- [ ] `mvmctl up --prod` invokes `fido_touch_required()` stub (audits `operator.fido.unverified`); W11 full FIDO ceremony lands within the sprint or slips with explicit Sprint-58 ticket.
- [ ] `specs/threat-models/02-host-services-broker.md` published; `SECURITY.md` CVE response runbook updated; CLAUDE.md security model updated to reference Plan 104 + new claim numbers + ADR-062 rescope.
- [ ] Falsifiability: throwaway `host.dev.echo.v1` lands in one handler file (in-process in `mvm-broker`) without touching envelope/registry/auth.

### Non-goals (explicit)

- Streaming responses. `host.monitoring.v1` deferred.
- Addon-provided handlers shipping in v1. v1 only ships the substrate; v2 ships actual addons.
- The `unsafe_guest_tls_inspection` proxy-with-CA path from ADR-049. Separate plan.
- Non-HTTP secret substitution. ADR-049 already declares out of scope.
- Cross-tenant aggregation. `host.cost.v1::tenant` is single-tenant-scoped.

### Follow-up (the host-logging follow-up plan (number TBD) — separate spec)

- [ ] `host.logging.v1` — workload-emitted structured logs to tenant log sink (depends on mvmd Plan 51 W3).
- [ ] `host.audit.v1` — workload-emitted chain-signed audit entries under `EventCategory::WorkloadAudit`.
- [ ] ADR-060 — workload-audit semantics + chain rotation policy.
## Sprint 58 — Guest control-layer dep-reduction + encryption design (proposed)  [`plans/109-zig-pid0-exploration.md`](plans/109-zig-pid0-exploration.md)

### Why this sprint
Track E in Sprint 42 set the gates for Zig adoption. Sprint 58 is the first concrete evaluation using those gates, structured as a paired A/B between **Zig** and **lean Rust v2** prototypes of the same small binary (`mvm-guest-netinit`). Goal: *evidence*, not adoption. Produce two measured prototypes + a vsock encryption design doc + three foundational ADRs + a provider capability matrix + a threat-model delta. Outcome can be "Zig wins" (propose follow-on Zig plans), "lean Rust v2 wins" (propose a Rust-internal agent dep-reduction plan), or "neither prototype meaningfully wins" (shared workstreams still land).

> **Renumbering note (2026-05-29):** Originally drafted as Sprint 57 + Plan 105; both slots were claimed concurrently on `main` (Sprint 57 by the host-services-broker work above; Plan 105 by `105-plan-100-w1-linux-builder-vm.md`). This sprint is now **Sprint 58** referencing **Plan 109**. Same content otherwise.

Systems-design recommendation: **stay Rust, adopt lean Rust v2 as the agent's evolution path, treat the Zig prototype as a measurement check.** Reasoning lives in [Plan 109 §"Systems-design recommendation"](plans/109-zig-pid0-exploration.md#systems-design-recommendation-taken-position).

Scope:
- the **guest-side control-layer surface** (`mvm-guest-agent` and its sibling pid0-class binaries),
- **not** the data plane (Plan 102 gateway audit, claim 9 sealed deps, claim 10 OCI provenance all stay untouched),
- **not** any backend (libkrun, Firecracker, Apple VZ, Apple Container, Cloud Hypervisor all preserved).

### W1 — Tradeoff note 🟡 proposed
Symmetric analysis of Zig and lean-Rust v2 paths. `specs/research/agent-evolution-tradeoff-note.md`.

### W2′ — Lean Rust v2 prototype: `mvm-guest-netinit` (primary track) 🟡 proposed
Same binary rewritten with `polling` + `linux-raw-sys` + manual netlink (no tokio, no rtnetlink, no netlink-packet-route). Lives at `crates/mvm-guest-netinit-lean/`. Built first.

### W2 — Zig prototype: `mvm-guest-netinit` (measurement check) 🟡 proposed
Smallest pid0-class binary in Zig. Lives at `zig/mvm-guest-netinit/`. Built second to put a number on what Rust leaves on the table.

### W3 — Vsock encryption design 🟡 proposed (paper only)
Noise_NK + X25519 + ChaCha20-Poly1305 + SHA-256. Host pubkey via `mkGuest { hostPubkey = …; }`. Stream-level wrap. `specs/research/vsock-control-plane-encryption.md`. Implementation deferred to a follow-on plan. Lands regardless of which prototype wins.

### W4 — Three new ADRs (drafts) 🟡 proposed
- control-plane-vs-data-plane (promotes ADR-053 hint to a contract)
- pid0-portability-boundary
- boundary-language-policy (codifies Track E gates; framed so it stays useful even if the answer is "Rust everywhere for now")

Lands regardless of which prototype wins.

### W5 — Provider capability matrix 🟡 proposed
`specs/reference/provider-capabilities.md` derived from `VmCapabilities` struct + `AnyBackend` variants. Lands regardless.

### W6 — Threat-model delta + audit invariants 🟡 proposed
Append §"Threats added" + §"Audit invariants under the agent-evolution exploration" sections to ADR-002. Lands regardless.

### Sprint 58 success criteria
- [ ] W1 tradeoff note committed (symmetric Zig + lean-Rust analysis)
- [ ] W2 (Zig) prototype runs in libkrun guest on macOS-arm64 + Linux-x86_64 with parity to baseline Rust
- [ ] W2′ (lean Rust v2) prototype runs with the same parity
- [ ] Three-column measurement table populated (baseline Rust / lean Rust v2 / Zig)
- [ ] W3 design doc committed with recommended protocol locked
- [ ] W4 three ADR drafts committed as `proposed`
- [ ] W5 capability matrix committed
- [ ] W6 ADR-002 §Threats + §Audit invariants sections committed
- [ ] `cargo test --workspace` green
- [ ] All current backends still pass per-backend CI lanes
- [ ] Outcome recommendation written (Zig wins / lean Rust v2 wins / neither)

### Non-goals (explicit)
- Rewriting `mvm-guest-agent` in any language (separate future plan)
- Replacing any backend
- Implementing vsock encryption (paper only)
- Replacing `mvm-verity-init` or `mvm-builder-init` in any language
- Egress secret detection (Plan 103 territory)
- Touching Apple VZ Swift shims (ADR-056 / Plan 98 own that)
- Renumbering existing claims or ADRs

## Sprint 59 — fast + secure dev path (Plan 93 Phases 1–3)  🟡 in flight  [`plans/93-fast-secure-dev-path-followups.md`](plans/93-fast-secure-dev-path-followups.md)

### Why this sprint
Plan 93 Phase 0 (fingerprint correctness) shipped in PR #504; its dependency Plan 91 (Alpine Stage 0) is on `main`. This sprint lands the three remaining phases as a chain of small PRs, ordered so cheap/unblocked observability lands first (every later optimization is then *provable*), then the high-value daily-DX work, then the launch-latency levers (some gated on the unmerged Plan 92/95 slim kernel). Security is the binding constraint: no lever bypasses signed-`ExecutionPlan` admission (claim 8), Ed25519 vsock session auth / no-TSI-bypass (claim 10), the audit chain, or the no-prebuilt-download supply-chain invariants. Worktree: `worktree-plan-93-fast-secure-dev-path`.

### Resolved design decision
Phase 1 host cross-compile targets **`<arch>-unknown-linux-musl` static**, not glibc-gnu — a glibc binary needs a `/lib` loader a Nix rootfs lacks; musl-static is self-contained and matches `mvm-builder-init`'s existing pattern. This deletes the pinned-sysroot fetch and its supply-chain surface.

### Workstream breakdown (PR chain)
- [x] **PR-1 — bench harness** `mvmctl bench microvm-launch` (Phase 2 Lever 0; everything measurable hangs off it; libkrun-only in v1; must drive real plan admission). Measurement substrate landed + unit-tested.
- [~] **PR-10a — live bench probe** (Phase 2 Lever 0 follow-up; [`plans/119-live-bench-probe-impl-plan.md`](plans/119-live-bench-probe-impl-plan.md)). Landed: `LibkrunProbe::measure_once` now boots the canonical default-microvm image through the real `admit_for_run` path (`bench_probe::boot_measure_once`), times four `BootMarks` spans, polls vsock readiness, tears down; `libkrun-live` feature-gated (stock CI skips — hosted macOS runners lack HVF nested virt); `HostDescriptor` carries kernel sha + cmdline. Validated end-to-end on the dev host through `backend.start`. **Blocked:** committed baseline JSON needs a freshly-built default-microvm image — the cached one is stale (predates W1.4b runtime-overlay sidecar) so `backend.start` refuses it. Deferred: `BootTimingReport` guest-monotonic cross-check (v1 reads readiness via atomic `ping`).
- [x] **PR-2 — `LocalAuditKind::VendorBlobFetched`** (Phase 3; additive observability foundation).
- [x] **PR-3 — `cache info` / `doctor` enrichment + Stage 0 progress** (Phase 3 observability). Deferred: doctor next-run HIT/MISS fingerprint + docs (Item 5).
- [ ] ~~**PR-4 — dev-shell split** `dev-minimal`/`dev-compile`~~ **SUPERSEDED by [ADR-064](adrs/065-single-builder-dev-image.md)** (landed on `main` 2026-05-29): single `builder-vm` flake with `default`/`dev` attrs, not a dev-image split.
- [ ] ~~**PR-5 — musl cross target**~~ **SUPERSEDED by ADR-064**: glibc via `cargo zigbuild`, not static musl.
- [ ] ~~**PR-6 — `mvmctl dev compile` + per-VM binbridge bind-mount**~~ **SUPERSEDED by ADR-064**: Linux binaries embedded into `mvmctl` at its build time (`build.rs` + `include_bytes!`), extracted to `~/.cache/mvm/host-bins/` — no runtime bind-mount.
- [ ] ~~**PR-7 — two-runner reproducibility CI lane**~~ folds into ADR-064's build-time cross-compile.
- [ ] ~~**PR-8 — `/nix` warm-reuse contract**~~ re-scoped under ADR-064's single-flake model.
- [ ] **Phase 1 re-plan** — implement [ADR-064](adrs/065-single-builder-dev-image.md) as the new Phase 1, coordinated with the `specs/prompts/93-phase-1-2-3-fast-secure-dev.md` track (do not race it).
- [~] **PR-9 — adaptive readiness poll** (Phase 2 Lever 2). Landed: `adaptive_backoff` + `wait_for_guest_agent` rewired (20ms→500ms cap; cuts up to ~480ms dead time per readiness detection; timing-only, connect→negotiate ordering untouched). Deferred (tracked): the `connect_and_authenticate` combiner and the guest `socket/bind/listen`-first reorder — both touch the sealed-prod Ed25519 auth path / agent main and need a live VM to validate.
- [ ] **PR-10 — warm pool of supervisors** `--warm-pool-size N` default 0 (Phase 2 Lever 3; guests unbooted until admission; control UDS reuses `deny_unknown_fields` parser + new fuzz target).

### Deferred (tracked in Plan 93 §deferred follow-ups)
- [ ] Phase 2 Lever 1 kernel cmdline trim — gated on Plan 92/95 merge (plumbing + override allowlist land now).
- [ ] Phase 2 Lever 4 VMM balloon — blocked on libkrun upstream balloon C API.
- [ ] Vz + Firecracker/Linux coverage for the bind-mount and the launch bench.

### Sprint 59 success criteria
- [ ] `mvmctl bench microvm-launch` produces a versioned JSON report + regression-gates against a baseline.
- [ ] Edit to a guest crate reaches the running dev shell in <10 s via `dev compile` with no VM rebuild ("no LONG dev cycles").
- [ ] `dev up` boots `dev-minimal` by default; `dev up --compile` boots `dev-compile`.
- [ ] Reproducibility CI lane is byte-identical across two `macos-14` runners.
- [ ] PRs 9–10 show measured handshake / process-spawn deltas (sub-200 ms headline itself gated on Plan 92/95).
- [ ] `doctor` / `cache info` explain Stage 0 hit/miss without grepping the audit log; `vendor_blob_fetched` audited.
- [ ] No security regression: admission + Ed25519 auth + TSI refusal + control-socket frame rejection covered by negative-path tests; `cargo test --workspace` green; `cargo clippy --workspace --all-targets -- -D warnings` clean.

### Non-goals (explicit)
- `--prod` admission policy (lives in mvmd).
- Host-side Nix store mirror / external build-cache providers.
- Backward-compat shims (first version — hard cutover; stale caches blown away on upgrade).
- Stage 0 architecture (Plan 91) and slim kernel (Plan 92/95) — depended on, not re-litigated.

## Sprint 60 — Core demo green + un-freeze + Lima test-env (Stage C, in flight)  [`plans/120-core-demo.md`](plans/120-core-demo.md)

Prove the #1 spine end-to-end on macOS/libkrun and lock it behind a regression guard: `mvmctl dev up` → `compile examples/python/hello-app/app.py` → `up --flake` (build in-VM, boot) → guest agent answers `Ping` over vsock. Work is on `feat/artifact-model` (the canonical, most-advanced Plan 120 line — has the gvproxy unhang fix `0ca06ee2`, workload-boot `5d81dc4e`, `Sandbox.exec` `c989fac7`).

### W1 — Spine pieces  ✅ shipped
- [x] `ArtifactSidecar` → `ArtifactManifest` rename (Plan 120 Task 1).
- [x] `mvmctl compile <app.py>` decorator lowering locked + stale docstring fixed; `compile_hello_app.rs` (Task 2).
- [x] `Sandbox.exec(*argv) -> ExecResult` API (dev-tier one-shot, `SandboxDevOnly`/`SandboxModeError` guards) + gated `test_sandbox_exec.py` (Task 5 API).
- [x] `core_demo_e2e.rs` written, `MVM_E2E_SMOKE`-gated, + `ci.yml::core-demo-e2e` lane + `development.md` docs (Task 3).

### W2 — Un-freeze hardening  ✅ shipped (commit `898b8507`)
- [x] `core_demo_e2e` watchdog thread (`exit(124)` after `MVM_E2E_DEADLINE_SECS`, default 2400s) + every `mvmctl` call bounded (stdio→files, own process group SIGKILLed on a per-step budget). Kills the `Command::output()` pipe-EOF freeze that cost several sessions. **Operating rule:** run the E2E only bounded + backgrounded.

### W3 — Drive the E2E green  🟡 in flight (Plan 120 Task 4)
- [ ] `MVM_E2E_SMOKE=1 just e2e-core-demo` green on a macOS/libkrun host, end-to-end, run bounded + backgrounded; close each surface red→green→commit.
- [ ] Lead the quickstart/README with the five-line `Sandbox.exec` example (Task 5 §4).
- [ ] Tick the §4 acceptance boxes in [`plans/117-cleanup-and-rearchitecture-brief.md`](plans/117-cleanup-and-rearchitecture-brief.md).

### W4 — Lima test-env `VmBackend`  🟡 queued (after W3 green)  [`adrs/066-target-architecture.md`](adrs/066-target-architecture.md) §177
- [ ] Implement Lima as a test/dev-tier, prod-refused `VmBackend` (a virtual `/dev/kvm` for the Firecracker E2E path, `MVM_E2E_BACKEND=lima`) — a second, hang-immune substrate.
- [ ] Flip ADR-066 §177 + AGENTS.md from "not built in this rewrite" → "built for test env" (owner-approved 2026-06-02).

### Deferred — image-slimming track (owner-deferred 2026-06-02, later track)
- [ ] Workload images are already minimal by design; remaining levers are planned-but-unstarted — Plan 131 (slim build-layer / erofs-vs-squashfs), Plan 124 (lean agent deps), Plan 126 (dep reduction), Plan 127 (boot/size harness). Plan 139 finding: dev loop is ~99% in-VM build time, so slimming is low-leverage and should be measurement-first.

### Sprint 60 success criteria
- [ ] The core demo is green end-to-end on macOS/libkrun behind the gated `core_demo_e2e`, and the test cannot freeze a session.
- [ ] `cargo test --workspace` green; `cargo clippy --workspace -- -D warnings` clean; `cargo fmt --all -- --check` clean.

### Non-goals (explicit)
- Image slimming (deferred, above) and Linux/Firecracker E2E parity (own plan).
- Encryption-at-rest + Noise vsock (Plan 122).

## Sprint 61 — App-builder product surface (proposed)  [`plans/181-app-builder-product-surface.md`](plans/181-app-builder-product-surface.md) | [`adrs/079-app-builder-product-surface.md`](adrs/079-app-builder-product-surface.md) | boundary: [`adrs/070-browser-reachable-verification-surface.md`](adrs/070-browser-reachable-verification-surface.md)

Graft the AI-app-builder *product loop* (create → coding agent → **live preview
URL**, stop/wake/keepalive lifecycle, streamable task/files API, one-command
install) onto mvm's hardened microVM substrate — **without** the weak isolation a
sibling self-hosted app-builder backend uses to get that DX cheaply (Docker
socket, host-path mounts, auth/caps off). Every workstream ships an mvm-side
primitive and names the mvmd-side product leg that consumes it (ADR-070 reserves
transport + tenant auth for mvmd / Plan 33). The one mvm-local product piece is a
single-machine `localhost` dev ingress so `mvmctl up`/`run` hands you a working
URL on one box.

### W1 (Plan 181 WS-D) — Install / uninstall DX  🟡 proposed
- [ ] `curl | sh` installer (folds the unowned Plan 159 WS-5 D item): prereq
  detection via `doctor`, idempotent, never touches anything outside mvm dirs.
- [ ] "Next steps" output after `env bootstrap` / `dev up` / `up`: control
  surface + preview URL(s) + literal runnable copy-paste commands.
- [ ] Graduated `env uninstall` (`--images` / `--data` / `--all`), keep-workspaces
  default, "removes only what mvm created".

### W2 (Plan 181 WS-B) — Lifecycle verb taxonomy  🟡 proposed
- [ ] `vm stop` (free RAM, wake-on-access) / `vm rm` (drop instance, **keep
  workspace**) / `vm purge` (drop instance + workspace) / `vm keepalive` (extend
  idle TTL on the Plan 118/170 reaper).
- [ ] Workspace-data lifecycle is a named concept in `mvm_core::config`; `--json`
  reports its state; each verb emits a distinct chain-signed `cmd.*` audit event.

### W3 (Plan 181 WS-A) — Preview ingress  🟡 proposed (headline)
- [ ] Published-ports model signed into the `ExecutionPlan` (audited, not ambient)
  + per-port routing label (`s-<vm>-<port>`) at the gateway seam
  (`gateway_bridge.rs` / rvproxy, Plan 179) — L4 publication, no HTTP parsing.
- [ ] Wake-on-access `VmBackend` hook (calls `warm_start`, Plan 123 C4 / Plan 175)
  on a connection to a stopped, RAM-freed instance.
- [ ] Local single-machine dev ingress: tiny first-party reverse proxy mapping
  `http://s-<id>-<port>.preview.localhost` → published host port + wake hook;
  `up`/`run` prints the URL(s). No auth/TLS/wildcard-DNS (mvmd owns those).
- Note: a DX benchmark vs a peer self-hosted sandbox backend confirmed preview URL is
  the *only* local-DX gap to close here (idle-sleep/wake + HTTP control plane are mvmd's;
  warm pool 118 + sub-second up/down 198 obviate its lazy-wake) and validated the L4 +
  local-proxy-first shape over an ambient per-route HTTP proxy — see Plan 181 WS-A.

### W4 (Plan 181 WS-C) — Streamable task + files protocol  🟡 proposed
- [ ] Async task protocol over agent-RPC (Plan 169) reusing `ExecEvent` streaming
  (Plan 172); the "agent" is an **opaque runner**, not a baked-in binary.
- [ ] SSE-ready event serialization (mvmd forwards as `text/event-stream`).
- [ ] Files API parity on the existing `fs` RPC (read/write/append, no `exec`);
  thin `mvmctl vm task` / `vm files` verbs for local testing.

### Cross-repo dependency (mvmd)
Consumes published-ports + routing label + wake hook (W3) for fleet preview URLs;
the task/files vsock protocol + SSE shape (W4) for its HTTP API; the
idle-TTL/keepalive contract (W2) for its density loop (Plan 170 WS-D).

### Sprint 61 success criteria
- [ ] `mvmctl up --flake <app>` with a published port prints a working
  `s-<id>-<port>.preview.localhost` URL on one machine; hitting it after `vm stop`
  wakes the instance.
- [ ] The four lifecycle verbs honor the instance-vs-workspace split with
  distinct audit events; a headless task streams incremental events and `vm files`
  reads/writes without `exec`.
- [ ] No claim regresses (`xtask check-claim-catalog` green; default-deny egress
  intact; only published ports routable); `cargo nextest run --workspace` +
  `--doc` green; clippy/fmt clean.

### Non-goals (explicit — see Plan 181 §Non-goals)
- Container isolation / Docker-socket control plane; host-path mounts into a
  workload; auth-off / caps-off defaults; baked-in coding agents; any
  multi-tenant HTTP listener or tenant auth in mvm (mvmd per ADR-070 §5).

## Sprint 62 — ADR-080 Tier-0 wasm preview → microVM ship (in flight)  [`adrs/080-wasm-preview-promotion-and-capability-policy.md`](adrs/080-wasm-preview-promotion-and-capability-policy.md)

### Why this sprint

ADR-080 decides the bridge from a no-claims browser/wasm dev-preview tier (the
ADR-069 `wasm-sandbox` backend, recorded as off-the-isolation-scale "Tier 0" in
ADR-002) to a claims-bearing production microVM: promotion is a **trace, never a
snapshot** (record-mode → IR → audited rebuild); one capability policy projects
to two enforcement fidelities (WASI fine-grained / kernel coarse); and eight
fail-closed preconditions (P1–P8 in ADR-080 §8) gate the promotion path until
each has a witness. The sprint lands those preconditions incrementally.

### Workstream breakdown

- **P5 — capability projection seam** ✅ LANDED (Plan 188, #801): `mvm-core::policy::projection`
  — `canonicalize_effective`/`to_wasi_grants`/`clamp`, mandatory-deny + rebinding
  refusal, mutation-verified cross-projection + clamp property witnesses.
- **P1/P3/P4 — trace hardening** ✅ LANDED (Plan 186, #809): op/size/duplicate limits +
  fuzz harness (P1); content-digest capture + verify + `--recording-sha256` (P3);
  `Divergence` gate on `run --mode plan` (P4). The P2 interim pin **caught + fixed a
  live shell-injection** in the FilesWrite lowering (path now base64-encoded into the
  hook; verified against `/bin/sh`).
- **P7 — secret-scan admission** ✅ LANDED (Plan 187, #811): `scan_recording_for_secrets`
  (env/argv/decoded-file payloads via the Plan 129 `SecretsScanner`) hard-refuses
  `run --mode plan` on embedded raw secrets; `SecretRef` skipped; compile warns.
- **P5 kernel close-out** ✅ LANDED (Plan 190): kernel L4 egress decision converges on
  `CanonicalEgress::permits` via `canonicalize_l4` (lenient — mandatory-deny-overlap
  allowed at construction; runtime `permits()` + `MandatoryDenyEgressScan` enforce it);
  `L4Policy`/`LiveL4Gate` duplicate deleted; claim-10 witnesses migrated; zero behaviour
  change; equivalence witness `kernel_egress_canonical_permits_agrees_with_hand_written_oracle`.
- **ADR-002 Tier-0 note** ✅ LANDED (#816): records the `wasm-sandbox` backend off the
  isolation scale + the Tier-0 single-principal threat-model framing.
- **P2 full** ✅ LANDED (Plan 191): `FilesWrite` lowers to the declarative `App.files` IR
  field, baked into the rootfs at build time via `mkFunctionService` `extraFiles` (base64
  decoded at build, never in a guest shell); the `before_start` shell hook is removed.
  Reserved `/etc/mvm/*` paths take precedence over user files.

### Deferred (ADR-080 §8 ledger)

- **P6** — preview-fetched component digests carried into the IR; mutable refs refused
  under `--prod`.
- **P8** — single-session relay primitive (websocket session-token binding + wasmtime
  fuel/memory/wall-clock caps); multi-principal host execution must run wasmtime-in-microVM.
- The **WASI-context mapping** (`WasiEgress` → `WasiCtxBuilder`) for the in-microVM
  wasmtime runner — now designed under ADR-081 (below).
- Multi-tenant streaming service, sessions, auth, billing — **mvmd's**, per ADR-070.

### Wasm-component runner (ADR-081) — design + A1 plan only; implementation NOT started

[`adrs/081-wasm-component-runner.md`](adrs/081-wasm-component-runner.md) decides the
prod-tier execution for ADR-080 §4's WASM-component regime: wasmtime as an in-guest
binary (never a host dep); a `.wasm` admitted as a content-addressed artifact (claim
8/9); fs/env capabilities clamp-authored by extending the Plan 188 projection seam
from network to fs/env; AOT-compile at build for prod (no in-guest JIT → guest seccomp
forbids `PROT_EXEC`), JIT for preview; WASI P1 v1 with a P2-ready seam. Decomposes into
three plans:

- **A1 — WASI capability projection (fs/env)** ✅ IMPLEMENTED (pending review on
  `feat/plan-192-wasi-fs-env-projection`)
  ([`plans/192-wasi-capability-projection-fs-env.md`](plans/192-wasi-capability-projection-fs-env.md)):
  pure-logic `mvm-core` extension (`CanonicalFs`/`CanonicalEnv`, `clamp_fs`/`clamp_env`
  intersection-only, WASI preopen/env-name generator, `WasiCapPolicy` bound,
  clamp-never-widens witnesses). Foundation for A2/A3. Decision logic only — no wasmtime,
  no I/O, no enforcement; zero new deps; runtime-free gate green.
- **A2 — `.wasm` artifact admission** 🔲 plan not yet written (queued as Plan 193).
- **A3 — guest runner + Nix bake + AOT** 🔲 plan not yet written (queued as Plan 194).

Owner-gated: A1 is pure decision logic with no runtime/enforcement surface; A2/A3 (the
`.wasm` admission + the in-guest runner that actually executes wasm) **must not begin**
until explicitly directed.

### Sprint 62 success criteria

- Every ADR-080 §8 precondition that gates the promotion path either has a landed
  witness or fails closed (promotion refused) until it does. `xtask
  check-claim-catalog` stays green; no ADR-002 numbered claim regresses.

### Non-goals (explicit)

- Asserting the wasm-in-microVM "double posture" as a claim before the wasmtime
  runner exists (the unwitnessed-claim anti-pattern ADR-002 guards against).
- Any production isolation claim for Tier 0 — it is single-principal dev preview,
  by design.

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
- [x] [#414](https://github.com/tinylabscom/mvm/pull/414) / [#415](https://github.com/tinylabscom/mvm/pull/415) — Stage 0 root-dir bootstrap: replaces the cpio initramfs path with libkrun `krun_set_root` + `krun_set_exec`. Path is dormant when `~/.mvm/dev/current/` exists; activates on fresh contributor hosts.
- [ ] [#416](https://github.com/tinylabscom/mvm/issues/416) — Stage 0 root-dir fallback bug: the pinned `nix-portable-aarch64` upstream asset is a macOS Mach-O binary, not a Linux ELF; the in-VM `exec` returns 127 and the dispatch never completes a Nix build. Tracked by [Plan 91](plans/91-stage0-alpine-bootstrap.md) — replaces `nix-portable` with an Alpine Linux minirootfs bootstrap (hash + PGP-verified, fetched from Alpine's official mirror, then `apk add nix-bin` for the in-VM Nix), plus an end-to-end Stage 0 CI smoke so a wrong-bootstrap regression can't ship again.
- [x] [#7](https://github.com/tinylabscom/mvm/issues/7) — Snapshot restore for `mvmctl exec` (easy branch: registered template, no `--add-dir`). The harder branch (parameterized snapshots for the `--add-dir` case) stays open under the same issue.
- [x] Docs parity maintenance — added an audit-and-receipts guide covering signed run receipts, audit-chain verification, boot reports, metrics, payload redaction, and SDK correlation targets.
- [x] Docs parity maintenance — added a policy-profiles guide covering restrictive/standard/dev/permissive run modes, host-share rules, env injection, seccomp tiers, dry-run, and receipt verification.
- [x] Docs parity maintenance — added a runtime-modes SDK guide covering record, plan, live, and static declaration flows plus host-code security implications.
- [x] Docs parity maintenance — added a declaration-workflow SDK guide covering static declarations, IR inputs, runtime recordings, build artifacts, and security review steps.
- [x] Docs parity maintenance — added a lifecycle-matrix SDK guide separating current CLI support, current Python/TypeScript SDK support, and runtime parity targets.
- [x] Docs parity maintenance — added a control-surfaces architecture page covering CLI, SDKs, MCP stdio, console, guest RPC, and not-claimed local management surfaces.
- [x] Docs parity maintenance — added a platform-support reference page covering Linux, macOS, Windows future work, Docker fallback, host/backend status, and guest target strings.

### Plan 118 WS-1 1b — supervisor warm pool: deferred follow-ups

1a (#748) + 1b-i (#751, mechanism) + 1b-ii (reaper + doctor column + `mvmctl pool
warm/status` + bench state-dir fix) shipped. Remaining, individually grabbable:

- [ ] **`up`/`run` auto-claim wiring.** `claim_or_cold` is closure-ready (it builds the
  `StandbyClaim` per the selected standby so the name-keyed audit substrate
  `gateway-<vm>.sock` resolves for the standby-id). The wiring is held back on two
  coupled items: (a) a claimed VM runs under its **standby-id** (its vsock socket dir is
  baked at spawn), so `up.rs` must rebind the ~40 downstream `vm_name` references for a
  warm launch — risky surgery in the core command; (b) a claim forces the supervisor's
  **`run_with_bridge`** path (the attach carries tenant+plan+audit), which `up.rs:~1906`
  documents as not-working-by-default on libkrun ("gvproxy vfkit socket empty") — though
  that comment predates Plan 123 Phase A (#727/#647) wiring egress policy *live* on the
  libkrun bridge, so it may be stale. **First step: confirm a libkrun bridge-path boot
  works end-to-end** (run the `#[ignore]`'d `valid_attach_boots_and_agent_reachable`), then
  do the name-rebind. Until then `up` always cold-boots; `mvmctl pool warm` pre-spawns
  standbys but nothing auto-claims them.
- [ ] **`--warm-pool-size` flag on `up`** (threads to `VmStartConfig.warm_pool_size` +
  replenish-on-use) — lands with the auto-claim, since replenish without claim only
  accumulates unclaimed standbys.
- [ ] **Multi-kernel pool keying.** v1 is default-kernel + default-resources only
  (`StandbyCompat` = kernel sha256 + vcpus + mem; non-matching launches cold-boot).
  Generalize to per-(kernel,shape) targets + eviction once a second shape is common.
- [ ] **Honour an explicit `--name` / extra `--volume`s for warm launches.** v1 only
  claims for auto-named, volume-less launches (1a's attach threads only the rootfs; a
  claimed VM is named by standby-id).
- [ ] **Committed bench baseline + cold-vs-warm delta.** The state-dir fix unblocks the
  probe; a real baseline still needs a freshly-built `default-microvm` image (rides
  PR-10a's deferral).

#### Plan 118 WS-1 1b auto-claim — live validation findings (2026-06-10)

The `up` auto-claim wiring shipped (try_warm_claim/replenish/--warm-pool-size, fail-open).
A live libkrun bridge boot was confirmed: `MVM_GATEWAY_BRIDGE=1 mvmctl up --flake
examples/exit_code --hypervisor libkrun --wait` → **exit 7** (the `up.rs` "bridge gvproxy
broken" comment is STALE — `run_with_bridge` boots end-to-end today). Two real fixes/finds:

- [x] **Standby attach timeout 30s → 30 min.** A pool standby legitimately waits to be
  claimed; the 1a `ATTACH_TIMEOUT=30s` made standbys self-exit before a later `up` could
  claim them. Bounded now by the pool reaper TTL, not a short self-timeout.
- [x] **libkrun mkGuest warm claim FIRES end-to-end** (PR #758). Three coupled bugs masked
  it: (1) **SUN_LEN** — the full 64-char binding nonce in the control-socket filename
  overflowed the macOS unix-socket path limit, so every standby died instantly at bind;
  fixed to a short `control.sock` under the nonce-derived `standby-<16hex>` dir. (2) The
  compat **kernel key is uncomputable pre-boot** for mkGuest (bundled kernel materialized at
  `start_enter`); `kernel_identity()` now returns a constant for libkrun (workload-
  independent standby), computed identically at claim + replenish. (3) the 30-min standby
  timeout (#757). Plus standby stderr is captured to `<pool>/<id>/standby.stderr.log`.
  Live-validated: a second `up --warm-pool-size 1` prints "Claimed a warm standby …".
- [ ] **`pool status` lists dead-but-unreaped standbys as "idle"** (it shows recorded
  state, not liveness). Cosmetic — `select_idle_compatible` correctly skips dead pids;
  filter the display by `pid_alive` for accuracy.
- [ ] Independent bug: `libkrun_sys::home_mvm_keys_dir()` hardcodes `$HOME/.mvm/keys` and
  ignores `MVM_DATA_DIR`, so `validate_audit_substrate` rejects an isolated data dir. Route
  it through `mvm_core::config`.

### Plan 118 WS-1 — Vz saved-standby warm pool (item 3) — DONE

Vz arm of the standby pool ships saved-standby (frozen {rootfs, memory, machine-id} triple
captured via `capture_vm_full`). No live supervisor after capture — pid=0 sentinel. Claim
path reuses `build_child_supervisor_config` + `VzChildSupervisorSpawner` (same fork plumbing,
pool-sourced blobs instead of checkpoint-sourced). Compat key adds `image_sha256: Option<String>` —
a Vz compat with Some(sha) only matches a standby for the same image; libkrun None is
unaffected. `reap_stale` skips liveness for pid=0 entries (TTL-only eviction).
`mvmctl pool warm --rootfs <path>` is the Vz entry point; doctor reports `vz=true` on
macOS 14+. All libkrun pool tests pass untouched. 298 mvm-backend lib tests, 974 mvm-cli
tests, 5117 workspace tests all green. Self-replenish landed in #840: a Vz claim that
drains the pool triggers a detached background `pool warm` re-warm so the pool is
self-maintaining (claim returns fast; the pool tops itself back up off the hot path).
