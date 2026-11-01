# Cleanup inventory (umbrella #4839)

Backing: preview
Validation: none — this records measurements taken on one commit; it is not a claim of enforcement.

Measured at `152ed1cebf1009da677f2298fab8209a49ffe671` (origin/main, 2026-10-31). It owns no status: the issues
do. Every number below comes from the command printed beside it. Scope is the
three #4839 checklist boxes named in §0; it does not touch #3731.

## 0. Boxes this document addresses

- §1 "Record supported binaries, guest artifacts, targets/features, released contracts, and security invariants. Use the repository graph and verify its coverage."
- §1 "Split the inventory into atomic child workstreams with owners, dependencies, acceptance criteria, and validation commands."
- §6 "Inventory capabilities, flags, environment/configuration options, modes, backends, compatibility layers, and supported combinations; retire only those shown obsolete."

## 1. Supported shape

### 1.1 Graph coverage (what was and was not checked)

- `list_projects` shows the `mvm` graph at branch `main`. `check_index_coverage` on five paths (`crates/mvm-cli/src/commands/mod.rs`, `mvm-hostd/src/bin/mvm-broker.rs`, `mvm-builder-guest/src/bin/mvm-host-vm-init.rs`, `mvm-agentd/src/bin/mvm-guest-agent/main.rs`, `crates/mvm-core/images.lock`) reports `indexed_at` 2026-10-08, `index_mode: fast`, and:
  `mvm-hostd/src/bin` and `mvm-agentd/src/bin` are **excluded subtrees**; the other three have no recorded coverage and `metadata_changed`/`not_tracked` freshness.
- Conclusion: the graph is three weeks stale and excludes the `src/bin` directories that hold most binaries, so it cannot verify the binary list. The lists below are derived from `cargo metadata`, `images.lock`, ADR-001 and CLAUDE.md instead. Re-running this with a fresh full-mode index is the open gap.

### 1.2 Packages and binaries

- `cargo metadata --no-deps --format-version 1` -> **32 packages**, **54 `bin` targets** in 14 packages (the rest are library-only).

| Package | Bins | Binaries |
|---|---|---|
| `mvm-agentd` | 20 | `audit-probe`, `emit_protocol_schema`, `fake-runner`, `mvm-addon-dns`, `mvm-addon-vsock-bridge`, `mvm-builder-agent`, `mvm-display-bridge`, `mvm-egress-client`, `mvm-entrypoint-test-wrapper`, `mvm-exit-report`, `mvm-guest-agent`, `mvm-guest-netinit`, `mvm-oci-entrypoint`, `mvm-ping`, `mvm-runner`, `mvm-seccomp-apply`, `mvm-setpriv-fixture`, `mvm-tool-helper`, `mvm-tool-shim`, `syscall-probe` |
| `mvm-build` | 2 | `mvm-egress-proxy`, `mvm-test-image-lock-holder` |
| `mvm-builder-guest` | 3 | `mvm-builderd`, `mvm-host-vm-init`, `stage0-init` |
| `mvm-client` | 2 | `emit_instruction_trust_schema`, `emit_policy_schema` |
| `mvm-contract` | 2 | `emit_assurance_schema`, `emit_pack_spec_schema` |
| `mvm-core` | 2 | `emit_broker_schema`, `mvm-extension-pack-verify` |
| `mvm-fs` | 1 | `mvm-extension-image` |
| `mvm-gpu` | 1 | `mvm-gpu-endpoint` |
| `mvm-hostd` | 10 | `mvm-apfs-snapshot-helper`, `mvm-audit-signer`, `mvm-broker`, `mvm-extension-provider`, `mvm-host-agent`, `mvm-host-signer`, `mvm-hvf-supervisor`, `mvm-libkrun-supervisor`, `mvm-network-endpoint`, `mvm-signer-helper` |
| `mvm-hostlib` | 2 | `emit_host_abi_methods`, `emit_host_abi_schema` |
| `mvm-sdk` | 6 | `emit_addon_schema`, `emit_runtime_schema`, `emit_sdk_ctors`, `emit_sdk_env`, `emit_sdk_errors`, `emit_workload_schema` |
| `mvm-setpriv` | 1 | `mvm-setpriv` |
| `mvmctl` | 1 | `mvmctl` |
| `xtask` | 1 | `xtask` |

Roles (from CLAUDE.md, cross-checked against the table): host CLI `mvmctl`; host daemons in `mvm-hostd`; builder-VM binaries `mvm-host-vm-init`, `mvm-builderd`, `stage0-init` (embedded by `mvm-cli/build.rs`) plus `mvm-setpriv`; guest runtime archive `mvm-guest-bins-v<version>.tar.gz` carrying the `mvm-agentd` guest bins, `mvm-setpriv`, `libmvm_host_services.so` (glibc and musl) and the GPU shims; schema emitters `emit_*`; test probes/fixtures (`audit-probe`, `fake-runner`, `syscall-probe`, `mvm-ping`, `mvm-setpriv-fixture`, `mvm-entrypoint-test-wrapper`, `mvm-test-image-lock-holder`).

### 1.3 Guest artifacts and released contracts

- `crates/mvm-core/images.lock` (`schema_version = 2`): image set `image-set/v0.2.4` from `tinylabscom/mvm-images` with a pinned `manifest_sha256`; `[compatibility] builder_boot_abi = 1`; sections `[image_set]`, `[compatibility]`, `[boot_image]`, `[stage0_kernel]` (aarch64 and x86_64 seeds), `[legacy]` (`boot-image/v0.1.5`). Command: `grep -nE '^\[|^(name|release_tag|builder_boot_abi)' crates/mvm-core/images.lock`.
- Image set is the Linux layer only (ADR-054); overlay, SDK sidecars and initramfs are retired roles that `mvmctl` assembles from the guest runtime archive shipped with each release.
- Contracts: signed `ExecutionPlan`; `.mvmpkg` bundle (`mvm_core::plan::bundle`); image-set contract; builder boot ABI 0/1/2; base-image contract 0/1; C ABIs `mvm_hostlib_*` (ABI 1.7 per CLAUDE.md) and `libmvm_host_services.so`; guest-agent vsock protocol.

### 1.4 Targets and features

- Targets: macOS 26+ Apple Silicon HVF (default); macOS 13-25 libkrun (explicit); Linux KVM Firecracker (default builder); QEMU (opt-in); `apple-container` (opt-in); wasm tier. Builder auto-detect: Apple Silicon macOS -> hvf, Linux+KVM -> firecracker, else qemu (CLAUDE.md "Builder backend selection").
- Cargo features per package: see the `features` array of `cargo metadata` above; notable gates are `embed-host-bins`, `manifest-verify`, `release-channel`, `libkrun-sys`, `libkrun-live`, `hvf-live-validation`, `wasm-backend`, `trusted-apfs`, `test-support`, `bdd` (mvm-conformance).

### 1.5 Security invariants

- The ADR-001 claims table (`specs/adrs/001-microvm-security-posture.md`, the table headed `| # | Claim | Witnesses | Authority | Status |`) has **21 numbered rows**. CLAUDE.md's text says "rows 1–19" and names claims 1–20; the table is authoritative (and has 21). That prose lag is a doc discrepancy to fix, not a code one.
- Standing invariants: no NIC in any workload or builder VM (`check-single-network-path`); no SSH in microVMs; host Nix never used; vsock-only auditable data plane.

## 2. Child workstreams

Owners: every issue below has no assignee (`gh issue view <n> --json assignees` returned none), so each owner is `unassigned`. Mapping is to the #4839 checklist sections (`gh issue view 4839 --json body`); open linked issues are listed with their current titles.

| # | Workstream (umbrella section) | Depends on | Open issues | Acceptance | Validation |
|---|---|---|---|---|---|
| W1 | Baseline and ownership (§1) | none | #4839 | release baseline recorded; branches/PRs inventoried; this doc | `check-adr-coverage`, `check-witness-citations`, `check-asserted-absence` |
| W2 | Remove slop/duplication (§2) | W1 | #4926 Retire the singular-entrypoint compatibility path | no narration/history comments; retained invariant comments | `rg` for banned patterns; `cargo clippy --workspace -- -D warnings` |
| W3 | Dependencies and crates/features (§3) | W1 | #4542 Consolidate small workspace crates | each dep/feature has a consumer or is removed | `cargo metadata`; `cargo run -p xtask -- check-all` |
| W4 | Release compilation (§4) | W1 | none open | repeated-compile causes measured and fixed | `cargo build --release --timings` |
| W5 | Toolchain/dev/CI paths (§5) | W1 | #4657, #4840, #4875, #4764, #4714 | bounded local feedback and CI latency; hermetic pair-image tests; pinned toolchain | `just ci`; workflow runs |
| W6a | Capability surface (§6) | W1 | #4926 | §3 of this doc reviewed per flag/env knob; obsolete ones retired with callers | `mvmctl --help` recursion; `rg` of knob |
| W6b | Thin CLI over mvm-client (§6, shared with #3731) | W6a | #3730, #4412, #4413, #4414, #4415, #4416 | zero production CLI reaches inventoried | `check-thin-cli` |
| W6c | Rust/tests/docs simplification (§6) | W2 | #4230, #3716 | misleading tests replaced by outcome tests | `cargo nextest run --workspace` |
| W7 | Demo critical path | none | #4507, #4508, #4509, #4510, #4511, #4655, #4391, #4764 | demo issues closed (deadline in the umbrella) | per issue |

Open issues referenced anywhere in the umbrella body: 40 (`gh issue view` on every `#NNNN` in the body; 80 refs, 37 merged).

## 3. Capability and flag inventory

No built `mvmctl` existed (`ls target/debug/mvmctl` in the main checkout: absent) and a build was out of scope, so the CLI surface is derived from the clap definitions in `crates/mvm-cli/src`, not from `--help`. Method: `rg -c '^\s*#\[arg\('` -> 901 `#[arg]` attributes; `derive(...Subcommand)` -> 58 matches; `derive(...Args)` -> 213. A script then parsed every `Subcommand` enum for its variants.

### 3.1 Global flags (struct `Cli`, `commands/mod.rs`)

`--log-format`, `--fc-version`, `--builder <libkrun|qemu|hvf|firecracker>`, `--kernel-source <compile|download|auto>`, `-v/--verbose` (alias `--debug`).

### 3.2 Top-level verbs (enum `Commands`)

Visible: machine, build, dev, deploy, deployments, kernel, generate, template, init, doctor, backend, prepare, explain, why, bench, plugin, completions, watch, pack, run, bootstrap, env, manifest, image, shell-init, ops, network, catalog, cache, pool, secret, bundle, trust, policy, pull, search, agent-session, deps, capture, artifact. Hidden: dashboard, `__sdk-no-vm`, `__builder-vm-bootstrap`, `__builder-egress-supervisor`, `__builder-shell-job`, storage, reconcile, seccomp-audit, persistent-builder, `__qemu-vsock-bridge`.

### 3.3 Subcommand enums (script output)

- `commands/agent_session.rs` `AgentSessionAction` (7): `open`, `ls`, `show`, `park`, `resume`, `renew`, `replay`
- `commands/backend/mod.rs` `BackendCmd` (4): `list`, `add`, `remove`, `detect`
- `commands/build/group.rs` `BuildCmd` (9): `compile`, `validate`, `kernel`, `runtime-overlay`, `sdk-sidecar`, `address`, `image-set`, `guest-bins`, `export-template` (hidden)
- `commands/build/kernel.rs` `Cmd` (1): `build`
- `commands/build/persistent_builder.rs` `Sub` (4): `start`, `submit`, `stop`, `status`
- `commands/build/runtime_overlay.rs` `Cmd` (1): `build`
- `commands/build/sdk_sidecar.rs` `Cmd` (1): `build`
- `commands/bundle/mod.rs` `BundleAction` (4): `fetch`, `push`, `install`, `gc`
- `commands/capture/mod.rs` `CaptureCmd` (3): `project`, `resolve`, `verify`
- `commands/catalog/mod.rs` `CatalogAction` (3): `list`, `search`, `info`
- `commands/deployments/mod.rs` `DeploymentsAction` (1): `ls`
- `commands/deps/mod.rs` `DepsAction` (5): `inspect`, `audit`, `capture`, `install`, `capture-live`
- `commands/env/caller_identity.rs` `Action` (2): `enroll`, `show`
- `commands/env/group.rs` `EnvCmd` (8): `caller-identity`, `bootstrap`, `cleanup`, `uninstall`, `update`, `verify-release`, `verify-runtime`, `sign`
- `commands/generate.rs` `GenerateAction` (3): `sdk`, `template`, `prompt`
- `commands/image/boot/mod.rs` `BootAction` (4): `status`, `check`, `update`, `verify`
- `commands/image/dev.rs` `DevAction` (1): `ensure`
- `commands/image/mod.rs` `ImageAction` (8): `build-layer`, `pull`, `ls`, `inspect`, `rm`, `boot`, `dev`, `revocations`
- `commands/image/revocations.rs` `Action` (2): `update`, `status`
- `commands/manifest/alias.rs` `AliasAction` (3): `set`, `rm`, `ls`
- `commands/manifest/mod.rs` `ManifestAction` (8): `ls`, `info`, `rm`, `prune`, `verify`, `tag`, `alias`, `export-oci`
- `commands/manifest/tag.rs` `TagAction` (3): `add`, `rm`, `ls`
- `commands/mod.rs` `Commands` (50): `machine`, `build`, `dev`, `deploy`, `deployments`, `kernel`, `generate`, `template`, `init`, `doctor`, `backend`, `dashboard` (hidden), `prepare`, `explain`, `why`, `bench`, `plugin`, `completions`, `watch`, `pack`, `run`, `__sdk-no-vm` (hidden), `bootstrap`, `__builder-vm-bootstrap` (hidden), `__builder-egress-supervisor` (hidden), `__builder-shell-job` (hidden), `env`, `manifest`, `image`, `storage` (hidden), `shell-init`, `ops`, `network`, `catalog`, `cache`, `pool`, `reconcile` (hidden), `secret`, `bundle`, `trust`, `policy`, `pull`, `search`, `agent-session`, `deps`, `capture`, `artifact`, `seccomp-audit` (hidden), `persistent-builder` (hidden), `__qemu-vsock-bridge` (hidden)
- `commands/ops/attest.rs` `AttestAction` (3): `export`, `verify`, `status`
- `commands/ops/audit.rs` `AssetAction` (1): `id`
- `commands/ops/audit.rs` `AuditAction` (16): `tail`, `verify`, `sessions`, `asset`, `prune`, `show`, `posture`, `verify-cert`, `publish-root`, `prove`, `verify-inclusion`, `provenance`, `receipts`, `decisions`, `usage`, `transcript`
- `commands/ops/audit.rs` `ProvenanceAction` (1): `export`
- `commands/ops/audit.rs` `ReceiptsAction` (2): `export`, `verify`
- `commands/ops/audit.rs` `DecisionsAction` (6): `list`, `show`, `export`, `trace`, `impact`, `similar`
- `commands/ops/cache.rs` `CacheAction` (4): `prune`, `info`, `status`, `repair`
- `commands/ops/config.rs` `ConfigAction` (3): `show`, `edit`, `set`
- `commands/ops/group.rs` `OpsCmd` (3): `metrics`, `config`, `mcp`
- `commands/ops/mcp.rs` `Transport` (1): `stdio`
- `commands/ops/network.rs` `NetworkAction` (4): `create`, `list`, `inspect`, `remove`
- `commands/ops/secret.rs` `SecretAction` (7): `put`, `get`, `set`, `login`, `providers`, `ls`, `rm`
- `commands/ops/transcript.rs` `TranscriptAction` (5): `arm`, `disarm`, `reconcile`, `list`, `export`
- `commands/pack/mod.rs` `PackAction` (15): `ls`, `rm`, `system`, `list`, `rollback`, `prune`, `download`, `update`, `info`, `verify`, `lock`, `compile`, `search`, `pull`, `registry`
- `commands/pack/mod.rs` `SystemAction` (5): `list`, `rollback`, `prune`, `download`, `update`
- `commands/pack/registry/mod.rs` `RegistryAction` (5): `install-local`, `ls`, `rm`, `update`, `revocations`
- `commands/pack/registry/revocations.rs` `Action` (1): `update`
- `commands/plugin.rs` `PluginAction` (2): `list`, `install`
- `commands/policy.rs` `PolicyAction` (5): `resolve`, `show`, `validate`, `diff`, `groups`
- `commands/pool.rs` `PoolAction` (3): `warm`, `status`, `refill` (hidden)
- `commands/storage/mod.rs` `StorageAction` (2): `info`, `gc`
- `commands/template.rs` `TemplateAction` (3): `list`, `search`, `info`
- `commands/trust/instructions.rs` `InstructionsAction` (4): `init`, `sign`, `verify`, `policy`
- `commands/trust/mod.rs` `TrustAction` (7): `add`, `list`, `remove`, `instructions`, `attest`, `receipt`, `audit`
- `commands/vm/artifact.rs` `Cmd` (4): `model-inspect`, `model-validate`, `model-config`, `model-build`
- `commands/vm/checkpoint.rs` `CheckpointCmd` (7): `create`, `restore`, `ls`, `rm`, `fork`, `diff`, `verify`
- `commands/vm/exec.rs` `ReceiptAction` (1): `verify`
- `commands/vm/fs.rs` `FsCmd` (7): `read`, `write`, `ls`, `stat`, `mkdir`, `rm`, `mv`
- `commands/vm/group.rs` `VmCmd` (24): `pause` (hidden), `resume` (hidden), `snapshot` (hidden), `save` (hidden), `checkpoint` (hidden), `cp` (hidden), `fs` (hidden), `proc` (hidden), `prompt`, `diff`, `apply`, `undo`, `redo`, `replay` (hidden), `display`, `wait` (hidden), `boot-report` (hidden), `set-ttl` (hidden), `forward` (hidden), `telemetry`, `sandbox` (hidden), `session` (hidden), `volume` (hidden), `rekernel`
- `commands/vm/proc.rs` `ProcCmd` (6): `start`, `ls`, `signal`, `kill`, `stdin`, `wait`
- `commands/vm/sandbox.rs` `SandboxAction` (1): `gc`
- `commands/vm/session.rs` `Cmd` (10): `ls`, `info`, `kill`, `set-timeout`, `start`, `attach`, `exec`, `run-code`, `console`, `reap`
- `commands/vm/snapshot.rs` `SnapshotCmd` (2): `ls`, `rm`
- `commands/vm/volume.rs` `VolumeCmd` (10): `create`, `unlock`, `lock`, `catalog`, `snapshot`, `restore`, `delete`, `mount`, `ls`, `unmount`

TOTAL 57 enums 315 variants


Caveat: the script is a regex over source, so variant names use the kebab-case of the Rust name unless `name =` is set, and a `rename_all` attribute would be missed. Per-verb flags (the 901 `#[arg]` sites) are not enumerated here; that needs a built binary (`mvmctl <verb> --help` recursion) and is the remaining gap for this box.

### 3.4 Environment knobs

Command: `rg --no-heading -n '"MVM_[A-Z0-9_]+"' crates src -g '*.rs' -g '!**/tests/**' -g '!**/tests.rs'`, grouped by crate -> **307 distinct `MVM_*` string literals** (crate with most hits first, count in parentheses). Literals include non-knob strings (path fragments, test-only names); that classification is not done.

Documented as removed / non-existent (checked with `rg -l '"<NAME>"' crates src -g '*.rs'`):

| Knob | Source of the statement | Literal still in code? |
|---|---|---|
| `MVM_NETWORKING`, `MVM_GATEWAY_BIN` | CLAUDE.md: gone with the gateway | no (0 files each) |
| `MVM_ACK_UNRESTRICTED_NETWORK` | CLAUDE.md claim 10: never existed | no (comment only, outside `*.rs` string literals) |
| `MVM_NO_VM` | not documented as removed; listed because it is read by the SDKs (`__sdk-no-vm`) | not as a Rust literal (0 files) |

Only these are documented as removed; the retired-backend names for `MVM_BUILDER_BACKEND` warn and fall through. Deciding which of the 307 others are obsolete is not done here.

| Literal | Owning crate(s) (hits) |
|---|---|
| `MVM_ACK_PERMISSIVE_RUN` | mvm-cli(1) |
| `MVM_ACK_RAW_STREAM_EDGE` | mvm-contract(1) |
| `MVM_ACTIVATION_FILE` | mvm-runtime(3) |
| `MVM_AC_E2E` | mvm-runtime(1) |
| `MVM_AC_E2E_ROOTFS` | mvm-runtime(2) |
| `MVM_ADDON_DNS_BIND_ADDRS` | mvm-agentd(3) |
| `MVM_ADDON_DNS_FLOWMUX_RESOLVER` | mvm-agentd(1) |
| `MVM_ADDON_DNS_UPSTREAM_ADDRS` | mvm-agentd(5) |
| `MVM_ADDON_DNS_UPSTREAM_RESOLV_PATH` | mvm-agentd(4) |
| `MVM_ADDON_DNS_ZONE_PATH` | mvm-agentd(2) |
| `MVM_ADDON_LOOPBACK_BINDINGS_PATH` | mvm-agentd(1) |
| `MVM_AEAD_TEST_CHILD_KEY_PATH` | mvm-core(1) |
| `MVM_AEAD_TEST_CHILD_START_PATH` | mvm-core(1) |
| `MVM_AGENT_EGRESS_ENDPOINT_SOCK` | mvm-agentd(1) |
| `MVM_AGENT_TRANSPORT` | mvm-agentd(1) |
| `MVM_AGENT_UNIX_SOCK` | mvm-agentd(1) |
| `MVM_ALLOW_LOCAL_BUILDER_BUILD` | mvm-cli(2), mvm-client(1), mvm-hostd(1) |
| `MVM_ALLOW_STALE_SNAPSHOT` | mvm-runtime(2) |
| `MVM_ALLOW_UNENCRYPTED_SNAPSHOT` | mvm-runtime(1) |
| `MVM_ALLOW_UNENCRYPTED_VOLUME_STORAGE` | mvm-core(1) |
| `MVM_ALLOW_UNSIGNED_RUNTIME` | mvm-build(1) |
| `MVM_APFS_SNAPSHOT_HELPER_SOCKET` | mvm-fs(1) |
| `MVM_API_TOKEN` | mvm-hostd(2) |
| `MVM_ATTRIBUTION_ANSWER_PID` | mvm-agentd(2) |
| `MVM_ATTRIBUTION_CLIENT` | mvm-agentd(2) |
| `MVM_ATTRIBUTION_CREDENTIAL_WITNESS` | mvm-agentd(1) |
| `MVM_ATTRIBUTION_SERVER` | mvm-agentd(2) |
| `MVM_AUDIT_SEGMENT_BYTES` | mvm-core(1) |
| `MVM_AUDIT_SIGNER_PATH` | mvm-vmm(5) |
| `MVM_AUDIT_WITNESS` | mvm-hostd(2) |
| `MVM_AUTO_DEV` | mvm-vmm(5) |
| `MVM_AUX_BIN_DIR` | mvm-vmm(1) |
| `MVM_BACKEND` | mvm-client(5), mvm-cli(3) |
| `MVM_BASE_CONTRACT_TEST_CHILD` | mvm-cli(1) |
| `MVM_BDD_CVE_INITRAMFS` | mvm-conformance(1) |
| `MVM_BDD_CVE_KERNEL` | mvm-conformance(1) |
| `MVM_BDD_SNAPSHOT` | mvm-conformance(1) |
| `MVM_BOOT_IMAGE` | mvm-build(1) |
| `MVM_BOOT_IMAGE_TAG` | mvm-core(1) |
| `MVM_BROKER_PATH` | mvm-vmm(3) |
| `MVM_BUILDER_AGENT_PORT` | mvm-build(1) |
| `MVM_BUILDER_BACKEND` | mvm-cli(10), mvm-build(1) |
| `MVM_BUILDER_BOOT_STAGE` | mvm-builder-guest(1) |
| `MVM_BUILDER_CLOSURE_NAR` | mvm-runtime(1) |
| `MVM_BUILDER_CMD_FILE` | mvm-runtime(2) |
| `MVM_BUILDER_KERNEL` | mvm-runtime(1) |
| `MVM_BUILDER_LOCK_WAIT_SECS` | mvm-build(1) |
| `MVM_BUILDER_MEM_MIB` | mvm-runtime(1) |
| `MVM_BUILDER_MODE` | mvm-build(1) |
| `MVM_BUILDER_ROOTFS` | mvm-runtime(1) |
| `MVM_BUILDER_STORE_GC_GIB` | mvm-build(1), mvm-cli(1) |
| `MVM_BUILDER_VM_BOOTSTRAP_ACTIVE` | mvm-build(1) |
| `MVM_BUILDER_VM_BOOTSTRAP_BIN` | mvm-build(1) |
| `MVM_BUILDER_VM_TIMEOUT_SECS` | mvm-build(1) |
| `MVM_BUILD_SOURCE_COMMIT` | mvm-cli(1) |
| `MVM_BUILD_SOURCE_DIRTY` | mvm-cli(1) |
| `MVM_BUILD_STUB_OUTDIR` | mvm-cli(1), mvm-build(1) |
| `MVM_CALLER_FIXTURE_ENABLE` | mvm-hostd(3) |
| `MVM_CALLER_FIXTURE_RECORD` | mvm-hostd(4) |
| `MVM_CALLER_REGISTRATION_REPLAY_DENIED` | mvm-hostd(1) |
| `MVM_CALLER_REPLAY_CHALLENGE` | mvm-hostd(2) |
| `MVM_CALLER_REPLAY_CHILD` | mvm-hostd(2) |
| `MVM_CALLER_WITNESS_BIN` | mvm-hostd(4) |
| `MVM_CALLER_WITNESS_KERNEL` | mvm-hostd(4), mvm-client(1) |
| `MVM_CALLER_WITNESS_PIN_JSON` | mvm-client(1), mvm-hostd(1) |
| `MVM_CALLER_WITNESS_ROOT` | mvm-hostd(4), mvm-client(1) |
| `MVM_CALLER_WITNESS_SOURCE` | mvm-hostd(4), mvm-client(1) |
| `MVM_CALLER_WITNESS_START_GATE` | mvm-hostd(3), mvm-client(1) |
| `MVM_CLI` | mvm-sdk(1) |
| `MVM_COLD_BUILD` | mvm-core(1) |
| `MVM_DECLARED_DIR_PROBE_CLI_PATH` | mvm-vmm(1) |
| `MVM_DECLARED_DIR_PROBE_HELPER_PATH` | mvm-vmm(1) |
| `MVM_DEV` | mvm-cli(1) |
| `MVM_DEV_DAEMON` | mvm-vmm(4) |
| `MVM_DIAGNOSTIC_APPROVED_REQUEST_SHA256` | mvm-client(1) |
| `MVM_DIAGNOSTIC_FIXTURE_ROOT` | mvm-client(1) |
| `MVM_DIAGNOSTIC_INPUT_ROOT` | mvm-client(1) |
| `MVM_DIAGNOSTIC_PREFLIGHT_INPUT_ROOT` | mvm-client(1) |
| `MVM_DIRECT_BOOT` | mvm-client(8), mvm-cli(2) |
| `MVM_DUMP_CORPUS` | mvm-conformance(1) |
| `MVM_EBPF_LIVE_TESTS` | mvm-hostd(2) |
| `MVM_EGRESS_LISTEN` | mvm-agentd(1) |
| `MVM_EGRESS_VSOCK_PORT` | mvm-builder-guest(2), mvm-agentd(1) |
| `MVM_EMBED` | mvm-cli(1) |
| `MVM_EMBED_CACHE_DIR` | mvm-cli(1) |
| `MVM_EMBED_CACHE_MAX_BYTES` | mvm-cli(2) |
| `MVM_EMBED_CARGO` | mvm-build(1) |
| `MVM_EMBED_NO_CACHE` | mvm-cli(2) |
| `MVM_EMBED_RUSTC` | mvm-build(1) |
| `MVM_EMBED_ZIG` | mvm-build(1) |
| `MVM_ENDPOINT_HANDSHAKE_TIMEOUT_SECS` | mvm-vmm(1) |
| `MVM_ENV` | mvm-core(6), mvm-cli(1) |
| `MVM_FAILURE_DIAGNOSTICS` | mvm-core(1) |
| `MVM_FC_BOOT_SMOKE` | mvm-builder-guest(1) |
| `MVM_FC_IDLE_POOL` | mvm-backends(1) |
| `MVM_FC_SMOKE_KERNEL` | mvm-builder-guest(1) |
| `MVM_FC_SMOKE_ROOTFS` | mvm-builder-guest(1) |
| `MVM_FC_VERSION` | mvm-core(3), mvm-cli(1) |
| `MVM_FLAKE_URL` | mvm-compiler(1) |
| `MVM_FLEET` | mvm-cli(1) |
| `MVM_FLOWMUX_GUEST_SIGNING_KEY_PATH` | mvm-agentd(2) |
| `MVM_FLOWMUX_INGRESS_TARGETS_PATH` | mvm-agentd(1) |
| `MVM_FOREGROUND_APPROVED_PROVENANCE_SHA256` | mvm-client(1) |
| `MVM_FOREGROUND_PROVENANCE_PATH` | mvm-client(1) |
| `MVM_FORMAT` | mvm-agentd(1) |
| `MVM_FRESH_PROCESS_TEST_CHILD` | mvm-cli(1) |
| `MVM_FUNCTION` | mvm-agentd(1) |
| `MVM_GATEWAY_TOKEN` | mvm-cli(1) |
| `MVM_GATEWAY_URL` | mvm-cli(1) |
| `MVM_GPU_ENDPOINT_PATH` | mvm-vmm(1) |
| `MVM_GPU_RPC` | mvm-gpu-shim-core(1) |
| `MVM_GPU_TEST_EXPECT_NATIVE` | mvm-gpu(1) |
| `MVM_GUEST_BUILD_VERBOSE` | mvm-build(1) |
| `MVM_GUEST_CONSOLE_VERBOSE` | mvm-backends(1) |
| `MVM_GUEST_PRIVILEGED_TESTS` | mvm-agentd(5) |
| `MVM_HARD_EXPIRY_FIXTURE` | mvm-hostd(2) |
| `MVM_HIGH_CAPABILITY_PROBE_CHILD` | mvm-agentd(1) |
| `MVM_HOME` | mvm-runtime(95), mvm-cli(67), mvm-core(52) |
| `MVM_HOSTLIB_PATH` | runmvm-client(1), mvm-sdk(1) |
| `MVM_HOSTLIB_PATH_ENV` | mvm-sdk(2) |
| `MVM_HOST_AGENT_DAEMON` | mvm-vmm(1) |
| `MVM_HOST_AGENT_IDLE_TIMEOUT` | mvm-hostd(1) |
| `MVM_HOST_AGENT_PATH` | mvm-vmm(2), mvm-hostd(2), mvm-cli(1) |
| `MVM_HOST_AGENT_WORKER` | mvm-hostd(1) |
| `MVM_HOST_BIN_DIR` | mvm-build(1), mvm-builder-guest(1), mvm-agentd(1) |
| `MVM_HVF_AGENT_DEBUG` | mvm-vmm(1) |
| `MVM_HVF_AGENT_SOCKET` | mvm-runtime(3) |
| `MVM_HVF_BOOTARGS` | mvm-backends(2), mvm-vmm(2), mvm-runtime(1) |
| `MVM_HVF_BOOTARGS_EXTRA` | mvm-runtime(4), mvm-backends(2), mvm-vmm(2) |
| `MVM_HVF_DIAGNOSTICS_TEST_CHILD` | mvm-vmm(1) |
| `MVM_HVF_DIAGNOSTICS_TEST_SYNC_FD` | mvm-vmm(1) |
| `MVM_HVF_DISK` | mvm-runtime(5) |
| `MVM_HVF_ENABLE_TRUSTED_SNAPSHOT` | mvm-runtime(2) |
| `MVM_HVF_INITRAMFS` | mvm-runtime(1) |
| `MVM_HVF_INITRD` | mvm-runtime(6) |
| `MVM_HVF_KERNEL` | mvm-runtime(10) |
| `MVM_HVF_LEGACY_CONFIG_REPLAY` | mvm-vmm(3), mvm-backends(2), mvm-hostd(1) |
| `MVM_HVF_SIGNED` | mvm-vmm(2), mvm-hostd(2) |
| `MVM_HVF_STARTUP_DIAGNOSTICS_FD` | mvm-hostd(1), mvm-vmm(1) |
| `MVM_HVF_SUBSTITUTION_SOCKET` | mvm-runtime(1) |
| `MVM_HVF_SUPERVISOR_PATH` | mvm-client(5), mvm-hostd(4), mvm-vmm(3) |
| `MVM_HVF_TIMEOUT` | mvm-runtime(6), mvm-backends(1) |
| `MVM_HVF_VIRTIO_DEBUG` | mvm-vmm(1) |
| `MVM_HVF_VSOCK` | mvm-runtime(1) |
| `MVM_HVF_WARM_REQUIRE_CLAIM` | mvm-cli(3) |
| `MVM_HYPERVISOR` | mvm-client(5), mvm-cli(3) |
| `MVM_IDLE_TIMEOUT` | mvm-hostd(1) |
| `MVM_IMAGES_DIR` | mvm-build(2), mvm-client(2), mvm-vmm(1) |
| `MVM_INSTALL_LIB_DIR` | mvm-cli(1) |
| `MVM_IR_OUT` | mvm-sdk(1) |
| `MVM_ISOLATED_HELPER_TEST_MODE` | mvm-cli(1) |
| `MVM_KERNEL_HANDOFF_UNIT_CHILD` | mvm-runtime(1) |
| `MVM_KERNEL_PATH` | mvm-client(3) |
| `MVM_KERNEL_SOURCE` | mvm-hostd(3), mvm-cli(2) |
| `MVM_KRUN_LOG` | mvm-hostd(1) |
| `MVM_LAUNCH_SAMPLE_JSON` | mvm-core(1) |
| `MVM_LIBKRUN_HEADER` | deps(1) |
| `MVM_LIBKRUN_SUPERVISOR` | mvm-vmm(2) |
| `MVM_LIBKRUN_SUPERVISOR_PATH` | mvm-build(3), mvm-backends(1), mvm-vmm(1) |
| `MVM_LINUX_BUILDER_VM` | mvm-build(4), mvm-cli(3) |
| `MVM_LIVE_KERNEL` | mvm-runtime(1) |
| `MVM_LIVE_LUKS` | mvm-runtime(1) |
| `MVM_LIVE_ROOTFS` | mvm-runtime(1) |
| `MVM_MACHINE_MAX_OUTPUT_BYTES` | mvm-sdk(1) |
| `MVM_MACHINE_TIMEOUT_SEC` | mvm-sdk(1) |
| `MVM_MATERIALIZE_BUILDER_VM` | mvm-build(3), mvm-cli(1) |
| `MVM_MODULE` | mvm-agentd(1) |
| `MVM_MVMD_API_KEY` | mvm-cli(1) |
| `MVM_MVMD_URL` | mvm-cli(1) |
| `MVM_NATIVE_CALLER_TEST` | mvm-hostd(1) |
| `MVM_NATIVE_CALLER_TEST_NAMESPACE` | mvm-hostd(2) |
| `MVM_NATIVE_CALLER_TEST_OPERATION` | mvm-hostd(2) |
| `MVM_NATIVE_CALLER_TEST_PIN` | mvm-hostd(4) |
| `MVM_NETWORK_PERF_BACKEND` | mvm-hostd(1) |
| `MVM_NETWORK_PERF_CPU` | mvm-hostd(1) |
| `MVM_NETWORK_PERF_HOST_ID` | mvm-hostd(1) |
| `MVM_NETWORK_PERF_IMPLEMENTATION` | mvm-hostd(1) |
| `MVM_NETWORK_PERF_SAMPLES` | mvm-hostd(1) |
| `MVM_NETWORK_PERF_SOURCE_COMMIT` | mvm-hostd(1) |
| `MVM_NETWORK_PERF_STORAGE` | mvm-hostd(1) |
| `MVM_NODE` | mvm-cli(1) |
| `MVM_NO_AUTO_DEV` | mvm-vmm(4) |
| `MVM_NO_BUILD_CACHE` | mvm-build(1) |
| `MVM_NO_LEGACY_BANNER` | mvm-hostd(3) |
| `MVM_NO_PERSISTENT_BUILDER` | mvm-cli(1), mvm-build(1) |
| `MVM_NO_UPDATE_CHECK` | mvm-cli(1) |
| `MVM_OCI_BEARER_TOKEN` | mvm-cli(5) |
| `MVM_OCI_BEARER_TOKEN_GHCR_IO` | mvm-cli(2) |
| `MVM_OCI_POLICY` | mvm-cli(5) |
| `MVM_OTLP_FILTER` | mvm-cli(1) |
| `MVM_OWNED_STOP_MODE` | mvm-hostd(2) |
| `MVM_OWNED_STOP_VM` | mvm-hostd(2) |
| `MVM_PACK_REGISTRY` | mvm-client(1) |
| `MVM_PHASE_TIMING` | mvm-core(1) |
| `MVM_PINNED_CARGO_ZIGBUILD` | mvm-cli(1) |
| `MVM_PINNED_TARGET` | mvm-cli(1) |
| `MVM_PINNED_ZIG` | mvm-cli(1) |
| `MVM_PRESERVE_TRANSIENT_STATE` | mvm-cli(3) |
| `MVM_PRINT_ADDRESS_VECTORS` | mvm-core(2) |
| `MVM_PRODUCTION` | mvm-core(4), mvm-cli(1), mvm-vmm(1) |
| `MVM_PYTHON` | mvm-cli(1) |
| `MVM_QEMU_BRIDGE_PATH` | mvm-vmm(5), mvm-backends(3) |
| `MVM_REGEN_AUDIT_CORPUS` | mvm-hostd(1) |
| `MVM_RESIDENCY` | mvm-cli(4), mvm-hostd(3), mvm-client(1) |
| `MVM_RESOLVE_SUBPROCESS_BIN_TEST_UNSET_PATH` | mvm-vmm(1) |
| `MVM_ROOTFS_PATH` | mvm-client(2) |
| `MVM_RUNTIME_CONFIG` | mvm-agentd(1) |
| `MVM_RUNTIME_DISPATCH_DIR` | mvm-agentd(1) |
| `MVM_RUNTIME_OVERLAY` | mvm-agentd(4) |
| `MVM_RUNTIME_OVERLAY_ACQUIRE_MODE` | mvm-hostd(3), mvm-build(1), mvm-client(1) |
| `MVM_RUNTIME_OVERLAY_SOURCE_ROOT` | mvm-build(1) |
| `MVM_SDK_MODE` | mvm-sdk(1) |
| `MVM_SDK_MODE_ENV` | mvm-sdk(2) |
| `MVM_SDK_OUT_PATH` | mvm-sdk(1) |
| `MVM_SDK_OUT_PATH_ENV` | mvm-sdk(2) |
| `MVM_SDK_RUN_PROFILE` | mvm-sdk(1), mvm-cli(1) |
| `MVM_SDK_RUN_PROFILE_ENV` | mvm-sdk(2) |
| `MVM_SECRET_STORE_BACKEND` | mvm-client(1), mvm-core(1) |
| `MVM_SESSION_TAG` | mvm-agentd(1) |
| `MVM_SIGNER_HELPER_PATH` | mvm-hostd(3) |
| `MVM_SKIP_BOOTSTRAP` | mvm-cli(1) |
| `MVM_SKIP_BUILDER_VM_AUTO_BOOTSTRAP` | mvm-build(1), mvm-cli(1) |
| `MVM_SKIP_COSIGN_VERIFY` | mvm-cli(9), mvm-build(5), mvm-client(2) |
| `MVM_SKIP_HASH_VERIFY` | mvm-cli(8), mvm-build(1), mvm-client(1) |
| `MVM_SKIP_RECONCILE` | mvm-cli(1) |
| `MVM_SNAPSHOT_HMAC_STRICT` | mvm-runtime(2) |
| `MVM_SOURCE_COMMIT` | mvm-cli(2) |
| `MVM_SOURCE_DIRTY` | mvm-cli(2) |
| `MVM_SOURCE_HELPER_BASE_URL` | mvm-cli(1) |
| `MVM_SOURCE_PATH` | mvm-agentd(1) |
| `MVM_SPAN_TIMINGS` | mvm-cli(1), mvm-core(1) |
| `MVM_SPAN_TIMINGS_FILTER` | mvm-core(1) |
| `MVM_SPAN_TIMINGS_OUT` | mvm-cli(1), mvm-core(1) |
| `MVM_STAGE0_BUILD_ATTR` | mvm-builder-guest(2) |
| `MVM_STAGE0_CONFIG_ATTR` | mvm-builder-guest(1) |
| `MVM_STAGE0_FLAKE` | mvm-builder-guest(1) |
| `MVM_STAGE0_OUTPUT_MODE` | mvm-builder-guest(2) |
| `MVM_SUBSTITUTION_ENDPOINT_PATH` | mvm-vmm(6), mvm-runtime(2), mvm-hostd(2) |
| `MVM_TELEMETRY_COLLECT` | mvm-vmm(1) |
| `MVM_TEMPLATE_LOCAL_API_KEY` | mvm-cli(3) |
| `MVM_TEMPLATE_LOCAL_BASE_URL` | mvm-cli(3) |
| `MVM_TEMPLATE_LOCAL_MODEL` | mvm-cli(3) |
| `MVM_TEMPLATE_LOCAL_PROBE_TARGETS` | mvm-cli(6) |
| `MVM_TEMPLATE_NO_LOCAL_PROBE` | mvm-cli(3) |
| `MVM_TEMPLATE_OPENAI_BASE_URL` | mvm-cli(2) |
| `MVM_TEMPLATE_OPENAI_MODEL` | mvm-cli(2) |
| `MVM_TEMPLATE_PROVIDER` | mvm-cli(5) |
| `MVM_TEMPLATE_REGISTRY` | mvm-cli(1) |
| `MVM_TEMPLATE_REGISTRY_ACCESS_KEY_ID` | mvm-runtime(1) |
| `MVM_TEMPLATE_REGISTRY_BUCKET` | mvm-runtime(1) |
| `MVM_TEMPLATE_REGISTRY_ENDPOINT` | mvm-runtime(2) |
| `MVM_TEMPLATE_REGISTRY_INSECURE` | mvm-runtime(1) |
| `MVM_TEMPLATE_REGISTRY_PREFIX` | mvm-runtime(1) |
| `MVM_TEMPLATE_REGISTRY_REGION` | mvm-runtime(1) |
| `MVM_TEMPLATE_REGISTRY_SECRET_ACCESS_KEY` | mvm-runtime(1) |
| `MVM_TENANT` | mvm-cli(6) |
| `MVM_TENANT_ID` | mvm-cli(1) |
| `MVM_TENANT_KEY_ACME` | mvm-runtime(1), mvm-core(1) |
| `MVM_TENANT_KEY_ACME_1` | mvm-runtime(1) |
| `MVM_TENANT_KEY_BADLEN` | mvm-core(1) |
| `MVM_TENANT_KEY_FOO_BAR` | mvm-core(1) |
| `MVM_TENANT_KEY_LOCAL` | mvm-runtime(1) |
| `MVM_TENANT_KEY_MVM_TEST_ENV_FALLBACK` | mvm-core(1) |
| `MVM_TENANT_KEY_MVM_TEST_LOOKUP_BAD` | mvm-core(1) |
| `MVM_TENANT_KEY_MVM_TEST_LOOKUP_UNSET` | mvm-core(1) |
| `MVM_TENANT_KEY_NOKEY_TENANT` | mvm-runtime(1) |
| `MVM_TENANT_KEY_TESTX` | mvm-core(1) |
| `MVM_TEST_CANONICAL_ENVIRONMENT` | mvm-client(1) |
| `MVM_TEST_CANONICAL_KERNEL` | mvm-runtime(3), mvm-core(2), mvm-bundler(1) |
| `MVM_TEST_CANONICAL_OUTPUT` | mvm-client(1) |
| `MVM_TEST_CANONICAL_ROOTFS` | mvm-client(1) |
| `MVM_TEST_CGROUP_DIR` | mvm-vmm(1) |
| `MVM_TEST_FIRECRACKER_INVOKED` | mvm-backends(2) |
| `MVM_TEST_INSTALL_DIR` | mvm-cli(1) |
| `MVM_TEST_RUNTIME_UMASK_OUTPUT` | mvm-build(2) |
| `MVM_TEST_SIGNED_RUNTIME_ARCHIVE` | mvm-client(1) |
| `MVM_TEST_SIGNED_RUNTIME_VERSION` | mvm-client(2) |
| `MVM_TEST_SOURCED_SECRET` | mvm-cli(1) |
| `MVM_TEST_STALE_SOCKET_PATH` | mvm-vmm(2) |
| `MVM_TEST_SUDO_MARKER` | mvm-cli(1) |
| `MVM_TEST_SUDO_PID_FILE` | mvm-backends(1) |
| `MVM_TEST_WEB_FETCH_ALLOWLIST_DEFINITELY_NOT_SET_XYZZY` | mvm-hostd(1) |
| `MVM_TEST_WEB_FETCH_ALLOWLIST_PARSE` | mvm-hostd(1) |
| `MVM_TEST_WEB_FETCH_ALLOWLIST_TRIM` | mvm-hostd(1) |
| `MVM_TEST_WEB_SEARCH_ALLOWLIST_PARSE` | mvm-hostd(1) |
| `MVM_TEST_WEB_SEARCH_DEFINITELY_NOT_SET_PLUGH` | mvm-hostd(1) |
| `MVM_TOOL_CAPABILITY_TEST_STAGE` | mvm-agentd(1) |
| `MVM_TOOL_CAPABILITY_TEST_STASH` | mvm-agentd(1) |
| `MVM_TOOL_READY_FD` | mvm-agentd(2) |
| `MVM_TOOL_STAGING_DIR` | mvm-hostd(1) |
| `MVM_TRUSTED_APFS_LIVE` | mvm-fs(1) |
| `MVM_TRUSTED_ENV_PROBE` | mvm-agentd(1) |
| `MVM_TSX` | mvm-cli(7) |
| `MVM_UNINSTALL_CHECKER` | mvm-cli(1) |
| `MVM_UNPACK_DIRECTORY_UMASK_CHILD` | mvm-fs(1) |
| `MVM_UPDATE_API_URL` | mvm-cli(2) |
| `MVM_UPDATE_DOWNLOAD_URL` | mvm-client(11), mvm-cli(7), mvm-build(1) |
| `MVM_UPDATE_MCP_TOOL_CONTRACT` | mvm-cli(1) |
| `MVM_VERIFY_TIMING_MEMORY_MIB` | mvm-runtime(1) |
| `MVM_VERIFY_TIMING_ROOTFS_MIB` | mvm-runtime(1) |
| `MVM_VOLUMES` | mvm-core(5) |
| `MVM_WEB_FETCH_ALLOWLIST` | mvm-hostd(1) |
| `MVM_WEB_SEARCH_ALLOWLIST` | mvm-hostd(1) |
| `MVM_WEB_SEARCH_DEFAULT` | mvm-hostd(1) |
| `MVM_WORKLOAD_KERNEL_VARIANT` | mvm-build(1) |
| `MVM_WORKSPACE_PATH` | mvm-build(2), mvm-builder-guest(1) |
| `MVM_WRAPPER_CONFIG_PATH` | mvm-cli(3) |

## 4. Reproduce

`git -C <worktree> rev-parse HEAD` = `152ed1cebf1009da677f2298fab8209a49ffe671`; `cargo metadata --no-deps --format-version 1`; the `rg` commands above; `gh issue view 4839 --json body`.
