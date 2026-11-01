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

§3.1-§3.3 were first derived from the clap definitions (no built binary then). §3.3a below is generated from a built `mvmctl --help` walk and supersedes them for flags. Source method: `rg -c '^\s*#\[arg\('` -> 901 `#[arg]` attributes; `derive(...Subcommand)` -> 58 matches; `derive(...Args)` -> 213. A script then parsed every `Subcommand` enum for its variants.

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


Caveat: the script is a regex over source, so variant names use the kebab-case of the Rust name unless `name =` is set, and a `rename_all` attribute would be missed. Per-verb flags are enumerated in §3.3a.

### 3.3a Verb and flag tree (generated from `--help`)

Built from `9168754adca89a00dbaf4bee109bd1966b2081bf` with `~/.cargo/bin/cargo build -p mvmctl` (debug, worktree-local target dir, 14m12s), then `python3 scripts/gen-cli-surface-inventory.py --bin target/debug/mvmctl`. Defaults are not in `--help` output here, so they come from source counts instead: `rg -o default_value crates/mvm-cli/src -g '*.rs'` -> 109 sites; `rg -o 'env *= *"'` -> 0 (no clap-level `env =` binding; knobs are read by hand, see §3.4); `rg -o deprecated` -> 0 (no clap deprecation markers); `hide *= *true` -> 34 (§3.6). Per-flag default values are therefore not tabulated.

<!-- cli-tree:begin -->
Verb paths walked: **264** (every `Commands` listed by `--help`, recursively); flag and positional entries in their `Options`/`Arguments` sections, excluding `-h`/`-V`: **852**. Root flags (propagated to every verb by clap) are listed once, under `(root)`. `--help` here is width-constrained (`constrain_help_output`, `crates/mvm-cli/src/commands/mod.rs`), so descriptions, defaults and deprecation markers are cut off and not recorded. Hidden verbs do not appear in `--help` and are not in this table; see the hidden-verb list in §3.2.

| Verb path | Flags and arguments (`= default`, `(env X)`) |
|---|---|
| `(root)` | `--log-format <LOG_FORMAT>`<br>`--fc-version <FC_VERSION>`<br>`--builder <BUILDER>`<br>`--kernel-source <KERNEL_SOURCE>`<br>`-v, --verbose...` |
| `machine` | - |
| `machine run` | `-m, --manifest <PATH>`<br>`--image <REF>`<br>`-a, --application <REF>`<br>`--flake <PATH>`<br>`--flake-profile <PROFILE>`<br>`--deployment <DIR>`<br>`--runtime-pack`<br>`--runtime <NAME>`<br>`--no-detect`<br>`--net`<br>`--network-preset <PRESET>`<br>`--allow-host <HOST[:PORT]>`<br>`--allow-endpoint <[METHOD ]URL>`<br>`--approval <BACKEND>`<br>`--approval-mode <MODE>`<br>`--ai-token-budget <TOKENS>`<br>`--peer <NAME:PORT=ADDR:PORT>`<br>`--cpus <CPUS>`<br>`--cpu-limit <MILLICORES>`<br>`--grants-file <PATH>`<br>`--memory <MEMORY>`<br>`--gpu`<br>`--gpu-device <ORDINAL>`<br>`--profile <PROFILE>`<br>`--mount <HOST:GUEST[:ro|SIZE]>`<br>`--asset <KIND:HOST_PATH>`<br>`--output <HOST_DIR:GUEST[:SIZE]>`<br>`-e, --env <ENV>`<br>`--allow-env <NAME>`<br>`--secret <NAME[:HOST,...]>`<br>`--timeout <TIMEOUT>`<br>`--receipt <PATH>`<br>`--caller-commitment <HEX>`<br>`--json`<br>`--dry-run`<br>`--launch-plan <PATH>`<br>`--from-workload-ir <PATH>`<br>`--prod`<br>`--agent-verb <VERB>`<br>`--host-service <SERVICE>`<br>`--hypervisor <HYPERVISOR>`<br>`--policy <NAME|PATH>`<br>`--plan <FILE>`<br>`--name <NAME>`<br>`-d, --detach`<br>`-p, --port <HOST_PORT:GUEST_PORT>`<br>`--up-json`<br>`--ttl <DURATION>`<br>`--healthcheck <CMD>`<br>`--health-interval <HEALTH_INTERVAL>`<br>`--health-timeout <HEALTH_TIMEOUT>`<br>`--health-retries <HEALTH_RETRIES>`<br>`--health-start-period <HEALTH_START_PERIOD>`<br>`-t, --tty`<br>`-i, --interactive`<br>`--force`<br>`--build`<br>`--no-build`<br>`--entrypoint`<br>`--fresh`<br>`--reset`<br>`--stdin <PATH>`<br>`--attach`<br>`--apply` |
| `machine build` | `-c, --mvm-config <MVM_CONFIG>`<br>`-o, --output <OUTPUT>`<br>`--flake <FLAKE>`<br>`--profile <PROFILE>`<br>`--watch`<br>`--force`<br>`--update-hash`<br>`--json`<br>`--deps`<br>`--no-persistent-builder`<br>`--allow-local-builder-build` |
| `machine create` | `--manifest <PATH>`<br>`--image <REF>`<br>`--net`<br>`--allow-host <HOST[:PORT]>`<br>`--peer <NAME:PORT=ADDR:PORT>`<br>`--gpu`<br>`--gpu-device <ORDINAL>`<br>`--cpus <CPUS>`<br>`--cpu-limit <MILLICORES>`<br>`--timeout <SECS>`<br>`--grants-file <PATH>`<br>`--memory <MEMORY>`<br>`--mem-initial <SIZE>`<br>`--profile <PROFILE>`<br>`--policy <NAME|PATH>`<br>`--force`<br>`--json` |
| `machine start` | `<NAME>...`<br>`--image <REF>`<br>`--manifest <PATH>`<br>`--net`<br>`--allow-host <HOST[:PORT]>`<br>`--peer <NAME:PORT=ADDR:PORT>`<br>`--gpu`<br>`--gpu-device <ORDINAL>`<br>`--cpus <CPUS>`<br>`--cpu-limit <MILLICORES>`<br>`--timeout <SECS>`<br>`--grants-file <PATH>`<br>`--memory <MEMORY>`<br>`--mem-initial <SIZE>`<br>`--profile <PROFILE>`<br>`--policy <NAME|PATH>`<br>`--force`<br>`--receipt <PATH>`<br>`--json`<br>`--dry-run`<br>`--hypervisor <HYPERVISOR>` |
| `machine reconfigure` | `<NAME>`<br>`--net`<br>`--no-net`<br>`--allow-host <HOST[:PORT]>`<br>`--clear-allow-host`<br>`--cpus <CPUS>`<br>`--memory <MEMORY>`<br>`--mem-initial <MEM_INITIAL>`<br>`--hypervisor <HYPERVISOR>` |
| `machine restart` | `<NAME>...`<br>`--image <REF>`<br>`--manifest <PATH>`<br>`--net`<br>`--allow-host <HOST[:PORT]>`<br>`--peer <NAME:PORT=ADDR:PORT>`<br>`--gpu`<br>`--gpu-device <ORDINAL>`<br>`--cpus <CPUS>`<br>`--cpu-limit <MILLICORES>`<br>`--timeout <SECS>`<br>`--grants-file <PATH>`<br>`--memory <MEMORY>`<br>`--mem-initial <SIZE>`<br>`--profile <PROFILE>`<br>`--policy <NAME|PATH>`<br>`--force`<br>`--receipt <PATH>`<br>`--json`<br>`--dry-run`<br>`--hypervisor <HYPERVISOR>` |
| `machine stop` | `--all`<br>`--yes` |
| `machine rm` | `--all`<br>`--yes`<br>`--force`<br>`--json` |
| `machine ps` | `--json`<br>`-a, --all`<br>`--tag <KEY=VALUE>`<br>`--show-expired` |
| `machine inspect` | `<NAME>`<br>`--json` |
| `machine shell` | `<NAME>`<br>`--force` |
| `machine exec` | `<NAME>`<br>`--force`<br>`-t, --tty`<br>`-i, --interactive`<br>`--tool <NAME>` |
| `machine set-timeout` | `<NAME>`<br>`<SECONDS>` |
| `machine logs` | `<NAME>`<br>`-f, --follow`<br>`-n, --lines <LINES>`<br>`--stream <STREAM>`<br>`--hypervisor` |
| `machine attach` | `<NAME>`<br>`--command <COMMAND>`<br>`--force`<br>`--list`<br>`--detach-timeout <SECONDS>` |
| `machine check-artifact` | `<PATH>`<br>`--trust-store <DIR>`<br>`--backend <BACKEND>`<br>`--json` |
| `machine detach` | `<NAME>` |
| `machine timeline` | `<TARGET>`<br>`--kind <KIND>`<br>`--json` |
| `machine revert` | `<TARGET>`<br>`--kind <KIND>`<br>`--hypervisor <HYPERVISOR>`<br>`--new-id <NEW_ID>`<br>`--json` |
| `machine rewind` | `<TARGET>`<br>`--kind <KIND>`<br>`--hypervisor <HYPERVISOR>`<br>`--new-id <NEW_ID>`<br>`--json` |
| `machine advance` | `<TARGET>`<br>`--to <TO>`<br>`--kind <KIND>`<br>`--hypervisor <HYPERVISOR>`<br>`--new-id <NEW_ID>`<br>`--json` |
| `machine warm-restore` | `<CHECKPOINT_ID>`<br>`--name <NAME>`<br>`--secret <SECRET>`<br>`--allow-secret-drop`<br>`--json` |
| `machine fork` | `<PARENT>`<br>`--as <NAME>`<br>`--branch <BRANCH>`<br>`--count <N>`<br>`--secret <SECRET>`<br>`--allow-secret-drop`<br>`--json` |
| `machine restore` | `<CHECKPOINT_ID>`<br>`--as <NAME>`<br>`--branch <BRANCH>`<br>`--secret <SECRET>`<br>`--allow-secret-drop`<br>`--json` |
| `machine prompt` | `<NAME>`<br>`--session <ID>`<br>`--request-id <ID>`<br>`--idempotency-key <KEY>`<br>`--timeout <SECS>`<br>`--no-step-checkpoint` |
| `machine diff` | `<NAME>`<br>`--from <CKPT>`<br>`--to <CKPT>`<br>`--volume <VOLUME>`<br>`--stat`<br>`--side-by-side`<br>`--json`<br>`--context <CONTEXT>`<br>`--max-files <MAX_FILES>`<br>`--max-file-bytes <MAX_FILE_BYTES>`<br>`--max-output-bytes <MAX_OUTPUT_BYTES>` |
| `machine apply` | `<NAME>`<br>`--volume <VOLUME>`<br>`--exclude <GLOB>`<br>`--protected-path <GLOB>`<br>`--yes`<br>`--dry-run` |
| `machine undo` | `<NAME>`<br>`--volume <VOLUME>` |
| `machine redo` | `<NAME>`<br>`--volume <VOLUME>` |
| `machine display` | `<NAME>`<br>`--input` |
| `machine telemetry` | `<NAME>`<br>`--json`<br>`-f, --follow`<br>`--tail <TAIL>` |
| `machine rekernel` | `<NAME>`<br>`--flake <FLAKE>`<br>`--kernel-pin <KERNEL_PIN>`<br>`--hypervisor <HYPERVISOR>` |
| `build` | `--out <FILE.mvmpkg>`<br>`--from <KIND>`<br>`--flake <REF>`<br>`--profile <PROFILE>`<br>`--arch <ARCH>`<br>`--production`<br>`--debug-out <FILE.json>`<br>`--lock <FILE>`<br>`--health-timeout <HEALTH_TIMEOUT>`<br>`--hypervisor <HYPERVISOR>`<br>`--input-observation <PATH>`<br>`--allow-local-builder-build`<br>`--label <LABEL>`<br>`--cmdline <FILE>`<br>`--posture <PROFILE>`<br>`--allow-egress`<br>`--allow-volumes`<br>`--allow-unauthenticated`<br>`--environment <FILE.json>` |
| `run` | `-m, --manifest <PATH>`<br>`--image <REF>`<br>`-a, --application <REF>`<br>`--flake <PATH>`<br>`--flake-profile <PROFILE>`<br>`--deployment <DIR>`<br>`--runtime-pack`<br>`--runtime <NAME>`<br>`--no-detect`<br>`--net`<br>`--network-preset <PRESET>`<br>`--allow-host <HOST[:PORT]>`<br>`--allow-endpoint <[METHOD ]URL>`<br>`--approval <BACKEND>`<br>`--approval-mode <MODE>`<br>`--ai-token-budget <TOKENS>`<br>`--peer <NAME:PORT=ADDR:PORT>`<br>`--cpus <CPUS>`<br>`--cpu-limit <MILLICORES>`<br>`--grants-file <PATH>`<br>`--memory <MEMORY>`<br>`--gpu`<br>`--gpu-device <ORDINAL>`<br>`--profile <PROFILE>`<br>`--mount <HOST:GUEST[:ro|SIZE]>`<br>`--asset <KIND:HOST_PATH>`<br>`--output <HOST_DIR:GUEST[:SIZE]>`<br>`-e, --env <ENV>`<br>`--allow-env <NAME>`<br>`--secret <NAME[:HOST,...]>`<br>`--timeout <TIMEOUT>`<br>`--receipt <PATH>`<br>`--caller-commitment <HEX>`<br>`--json`<br>`--dry-run`<br>`--launch-plan <PATH>`<br>`--from-workload-ir <PATH>`<br>`--prod`<br>`--agent-verb <VERB>`<br>`--host-service <SERVICE>`<br>`--hypervisor <HYPERVISOR>`<br>`--policy <NAME|PATH>`<br>`--plan <FILE>`<br>`--name <NAME>`<br>`-d, --detach`<br>`-p, --port <HOST_PORT:GUEST_PORT>`<br>`--up-json`<br>`--ttl <DURATION>`<br>`--healthcheck <CMD>`<br>`--health-interval <HEALTH_INTERVAL>`<br>`--health-timeout <HEALTH_TIMEOUT>`<br>`--health-retries <HEALTH_RETRIES>`<br>`--health-start-period <HEALTH_START_PERIOD>`<br>`-t, --tty`<br>`-i, --interactive`<br>`--force`<br>`--build`<br>`--no-build`<br>`--entrypoint`<br>`--fresh`<br>`--reset`<br>`--stdin <PATH>`<br>`--attach`<br>`--apply`<br>`--mode <MODE>`<br>`--dev`<br>`--ack-divergence <KIND>` |
| `kernel` | - |
| `kernel build` | `--which <WHICH>`<br>`--all`<br>`--source <SOURCE>`<br>`--arch <ARCH>`<br>`--boot-check` |
| `deploy` | `--from-ir <PATH>`<br>`-o, --out <DIR>`<br>`--manifest-dir <DIR>`<br>`--boot-artifact <PATH>`<br>`--dep-volume <DIR>`<br>`--kernel-sha256 <HEX64>`<br>`--mvmd-url <URL>` |
| `deployments` | - |
| `deployments ls` | `--workload <WORKLOAD>`<br>`--json` |
| `generate` | - |
| `generate sdk` | `<SCRIPT>`<br>`-o, --out <DIR>` |
| `generate template` | `<NAME>`<br>`<DIR>` |
| `generate prompt` | `<DESCRIPTION>`<br>`<DIR>` |
| `backend` | - |
| `backend list` | - |
| `backend add` | `<NAME>` |
| `backend remove` | `<NAME>` |
| `backend detect` | `--plain` |
| `doctor` | `--json`<br>`--workflow <WORKFLOW>` |
| `init` | `<DIR>`<br>`--preset <PRESET>`<br>`--prompt <PROMPT>`<br>`--catalog <CATALOG>` |
| `template` | - |
| `template list` | - |
| `template search` | `<QUERY>` |
| `template info` | `<NAME>` |
| `prepare` | `--dry-run` |
| `bench` | `--lane <LANE>`<br>`--runs <RUNS>`<br>`--warmup <WARMUP>`<br>`--out <PATH>`<br>`--json`<br>`--allow-debug-build` |
| `explain` | `<RUN_ID>`<br>`--tenant <TENANT>`<br>`--json`<br>`--review`<br>`--project <PATH>` |
| `why` | `--host <HOST[:PORT]>`<br>`--method <METHOD>`<br>`--request-path <PATH>`<br>`--path <PATH>`<br>`--tool <TOOL>`<br>`--secret <SECRET>`<br>`--profile <NAME|PATH>`<br>`--plan <FILE>`<br>`--project <DIR>`<br>`--backend <BACKEND>`<br>`--json` |
| `completions` | `<SHELL>` |
| `plugin` | - |
| `plugin list` | - |
| `plugin install` | `<TARGET>`<br>`--dir <DIR>`<br>`--force`<br>`--dry-run` |
| `watch` | `--from-ir <PATH>`<br>`-o, --out <DIR>`<br>`--manifest-dir <DIR>`<br>`--interval-ms <MILLISECONDS>`<br>`--once` |
| `pack` | - |
| `pack ls` | `--json` |
| `pack rm` | `<ns/name[@version]>` |
| `pack system` | - |
| `pack system list` | `--kind <KIND>`<br>`--json` |
| `pack system rollback` | `<KIND>`<br>`--to <TO>` |
| `pack system prune` | `--keep-recent <KEEP_RECENT>`<br>`--dry-run`<br>`--json` |
| `pack system download` | `<KIND>` |
| `pack system update` | `<KIND>` |
| `pack list` | `--kind <KIND>`<br>`--json` |
| `pack rollback` | `<KIND>`<br>`--to <TO>` |
| `pack prune` | `--keep-recent <KEEP_RECENT>`<br>`--dry-run`<br>`--json` |
| `pack download` | `<KIND>` |
| `pack update` | `<ns/name[@version]|SYSTEM_KIND>` |
| `pack info` | `<ns/name[@version]>`<br>`--json` |
| `pack verify` | `<ns/name[@version]>`<br>`--json` |
| `pack lock` | `<SPEC.json>`<br>`--mvm-revision <COMMIT>`<br>`--out <FILE>`<br>`--stdout` |
| `pack compile` | `<SPEC.json>`<br>`--lock <FILE>`<br>`--out <DIR>` |
| `pack search` | `--json` |
| `pack pull` | `<ns/name[@version]>`<br>`--json` |
| `pack registry` | - |
| `pack registry install-local` | `<REFERENCE>`<br>`--manifest-sha256 <MANIFEST_SHA256>`<br>`--manifest <MANIFEST>`<br>`--bundle <BUNDLE>`<br>`--files <FILES>` |
| `pack registry ls` | `--json` |
| `pack registry rm` | `<ns/name[@version]>` |
| `pack registry update` | `<ns/name[@version]>` |
| `pack registry revocations` | - |
| `pack registry revocations update` | `--official`<br>`--document <DOCUMENT>`<br>`--bundle <BUNDLE>` |
| `env` | - |
| `env caller-identity` | - |
| `env caller-identity enroll` | - |
| `env caller-identity show` | - |
| `env bootstrap` | `--production`<br>`--allow-local-builder-build` |
| `env cleanup` | `--keep <KEEP>`<br>`--all`<br>`--cache`<br>`--state`<br>`--nuclear`<br>`--keep-identity`<br>`--dry-run`<br>`--yes`<br>`--force` |
| `env uninstall` | `--purge`<br>`--dry-run`<br>`--force` |
| `env update` | `--check`<br>`--force`<br>`--skip-verify` |
| `env verify-release` | `<ARCHIVE>`<br>`--bundle <BUNDLE>`<br>`--tag <TAG>` |
| `env verify-runtime` | `--config <CONFIG>`<br>`--version <VERSION>`<br>`--arch <ARCH>`<br>`--json` |
| `env sign` | `--json` |
| `manifest` | - |
| `manifest ls` | `--json`<br>`--orphans`<br>`--tag <TAG>` |
| `manifest info` | `--json` |
| `manifest rm` | `--force`<br>`--manifest-file` |
| `manifest prune` | `--orphans`<br>`--dry-run`<br>`--json` |
| `manifest verify` | `--revision <REVISION>`<br>`--check-signature` |
| `manifest tag` | - |
| `manifest tag add` | `<TEMPLATE>`<br>`<TAG>` |
| `manifest tag rm` | `<TEMPLATE>`<br>`<TAG>` |
| `manifest tag ls` | `<TEMPLATE>`<br>`--json` |
| `manifest alias` | - |
| `manifest alias set` | `<TEMPLATE>`<br>`<ALIAS>`<br>`<REVISION_HASH>` |
| `manifest alias rm` | `<TEMPLATE>`<br>`<ALIAS>` |
| `manifest alias ls` | `<TEMPLATE>`<br>`--json` |
| `manifest export-oci` | `<TEMPLATE>`<br>`--out <PATH>` |
| `catalog` | - |
| `catalog list` | - |
| `catalog search` | `<QUERY>` |
| `catalog info` | `<NAME>` |
| `image` | - |
| `image build-layer` | `--source <DIR>`<br>`--output <DIR>` |
| `image pull` | `<REFERENCE>`<br>`--prod`<br>`--warm` |
| `image ls` | `--registry <HOST>`<br>`--json` |
| `image inspect` | `<REFERENCE>`<br>`--json`<br>`--digest-ref` |
| `image rm` | `<REFERENCE>` |
| `image boot` | - |
| `image boot status` | `--json` |
| `image boot check` | `--json` |
| `image boot update` | `--tag <TAG>`<br>`--force` |
| `image boot verify` | `--manifest <FILE>`<br>`--bundle <FILE>`<br>`--lock <FILE>`<br>`--artifacts <DIR>`<br>`--artifact <NAME>`<br>`--require-complete`<br>`--check-revocations`<br>`--json` |
| `image dev` | - |
| `image dev ensure` | `--warm` |
| `image revocations` | - |
| `image revocations update` | `--document <FILE>`<br>`--bundle <FILE>` |
| `image revocations status` | `--json` |
| `agent-session` | - |
| `agent-session open` | `<SESSION_ID>`<br>`--resume-point <RESUME_POINT>`<br>`--member <MEMBERS>` |
| `agent-session ls` | `--json` |
| `agent-session show` | `<SESSION_ID>`<br>`--json` |
| `agent-session park` | `<SESSION_ID>`<br>`--reason <REASON>`<br>`--journal-cursor <JOURNAL_CURSOR>`<br>`--approval-head <APPROVAL_HEAD>`<br>`--retain-for <DURATION>`<br>`--expected-generation <N>`<br>`--json` |
| `agent-session resume` | `<SESSION_ID>`<br>`--backend <BACKEND>`<br>`--image <IMAGE>`<br>`--image-sha256 <IMAGE_SHA256>`<br>`--kernel-sha256 <KERNEL_SHA256>`<br>`--cpus <CPUS>`<br>`--mem-mib <MEM_MIB>`<br>`--approval-head <APPROVAL_HEAD>`<br>`--boot`<br>`--kernel <KERNEL>`<br>`--expected-generation <N>`<br>`--json` |
| `agent-session renew` | `<SESSION_ID>`<br>`--for <DURATION>`<br>`--expected-deadline <UNIX_SECS>`<br>`--expected-generation <N>`<br>`--json` |
| `agent-session replay` | `<SESSION_ID>`<br>`--from <CHECKPOINT>`<br>`--as <NAME>`<br>`--dry-run`<br>`--timeout <SECS>` |
| `cache` | - |
| `cache prune` | `--dry-run`<br>`--orphan-builds`<br>`--no-reap-orphans`<br>`--orphan-dirs`<br>`--deep`<br>`--stage0-store` |
| `cache info` | `--json` |
| `cache status` | `--json` |
| `cache repair` | `--dry-run`<br>`--json`<br>`--force`<br>`--store-only` |
| `network` | - |
| `network create` | `<NAME>`<br>`--subnet <SUBNET>` |
| `network list` | `--json` |
| `network inspect` | `<NAME>`<br>`--json` |
| `network remove` | `<NAME>` |
| `pool` | - |
| `pool warm` | `--image <IMAGE>`<br>`--default`<br>`--manifest <PATH|SHA256>`<br>`--flake <PATH>`<br>`--flake-profile <PROFILE>`<br>`--cpus <CPUS>`<br>`--memory <MEMORY>`<br>`--egress` |
| `pool status` | `--json` |
| `artifact` | - |
| `artifact model-inspect` | `<ID>` |
| `artifact model-validate` | `<ID>` |
| `artifact model-config` | `<ID>`<br>`--backend <BACKEND>` |
| `artifact model-build` | `--arch <ARCH>`<br>`--backend <BACKEND>`<br>`--flake <FLAKE>` |
| `bundle` | - |
| `bundle fetch` | `<SOURCE>`<br>`--trust-store <DIR>`<br>`--registry <DIR>`<br>`--json`<br>`--allow-http`<br>`--prod` |
| `bundle push` | `<FILE>`<br>`<REFERENCE>`<br>`--trust-store <DIR>`<br>`--allow-http` |
| `bundle install` | `<SOURCE>`<br>`--trust-store <DIR>`<br>`--registry <DIR>`<br>`--allow-http`<br>`--prod`<br>`--force` |
| `bundle gc` | `--all`<br>`--registry <DIR>`<br>`--yes` |
| `policy` | - |
| `policy resolve` | `--project <DIR>`<br>`--backend <BACKEND>`<br>`-o, --output <FILE>` |
| `policy show` | `--project <DIR>`<br>`--backend <BACKEND>`<br>`--format <FORMAT> = toml` |
| `policy validate` | `--project <DIR>`<br>`--backend <BACKEND>`<br>`--strict` |
| `policy diff` | `<A>`<br>`<B>`<br>`--backend <BACKEND>`<br>`--json` |
| `policy groups` | `--json` |
| `pull` | `<ns/name[@version]>`<br>`--json` |
| `search` | `--json` |
| `secret` | - |
| `secret put` | `<NAME>`<br>`--tenant <TENANT>`<br>`--value <VALUE>`<br>`--value-file <VALUE_FILE>`<br>`--from <REF>` |
| `secret get` | `<NAME>`<br>`--tenant <TENANT> = local` |
| `secret set` | `<NAME>`<br>`--tenant <TENANT>`<br>`--provider <PROVIDER>`<br>`--host <HOSTS>`<br>`--type <AUTH_TYPE>`<br>`--inject <INJECT>`<br>`--aws-access-key-id <AWS_ACCESS_KEY_ID>`<br>`--region <REGION>`<br>`--service <SERVICE>`<br>`--approve <APPROVE>`<br>`--oauth-authorization-url <AUTHORIZATION_URL>`<br>`--oauth-token-url <TOKEN_URL>`<br>`--oauth-client-id <CLIENT_ID>`<br>`--oauth-scope <SCOPES>`<br>`--oauth-response-access-token-pointer <RESPONSE_ACCESS_TOKEN_POINTER>`<br>`--oauth-client-secret <CLIENT_SECRET>`<br>`--oauth-client-secret-file <CLIENT_SECRET_FILE>`<br>`--oauth-login`<br>`--value <VALUE>`<br>`--value-file <VALUE_FILE>`<br>`--from <REF>` |
| `secret login` | `<NAME>`<br>`--tenant <TENANT> = local`<br>`--no-browser`<br>`--timeout <SECONDS>` |
| `secret providers` | `--search <SEARCH>` |
| `secret ls` | `--tenant <TENANT> = local` |
| `secret rm` | `<NAME>`<br>`--tenant <TENANT> = local` |
| `trust` | - |
| `trust add` | `<PUBKEY>`<br>`--force` |
| `trust list` | `--json` |
| `trust remove` | `<KEY_ID>` |
| `trust instructions` | - |
| `trust instructions init` | `--project <DIR>`<br>`--enforcement <ENFORCEMENT>`<br>`--force` |
| `trust instructions sign` | `<PATH>...`<br>`--key <FILE>`<br>`--dry-run`<br>`--policy <FILE>` |
| `trust instructions verify` | `--policy <FILE>`<br>`--json` |
| `trust instructions policy` | `--project <DIR>`<br>`--policy <FILE>`<br>`--json` |
| `trust attest` | - |
| `trust attest export` | `--output <OUTPUT>` |
| `trust attest verify` | `<REPORT>`<br>`--trust <TRUST>`<br>`--trust-self` |
| `trust attest status` | - |
| `trust receipt` | - |
| `trust receipt verify` | `<PATH>`<br>`--pubkey <PUBKEY>` |
| `trust audit` | - |
| `trust audit tail` | `-n, --lines <LINES> = 20`<br>`-f, --follow`<br>`--chain`<br>`--tenant <TENANT>` |
| `trust audit verify` | `--tenant <TENANT>`<br>`--json` |
| `trust audit sessions` | `--tenant <TENANT>`<br>`--since <SINCE>`<br>`--until <UNTIL>`<br>`--json` |
| `trust audit asset` | - |
| `trust audit asset id` | `<PATH>` |
| `trust audit prune` | `--through <THROUGH>`<br>`--tenant <TENANT>`<br>`--ack` |
| `trust audit show` | `<SESSION>`<br>`--tenant <TENANT>`<br>`--kind <KIND>`<br>`--since <SINCE>`<br>`--until <UNTIL>`<br>`--json` |
| `trust audit posture` | `--json` |
| `trust audit verify-cert` | `<CERT>`<br>`--pubkey <PUBKEY>`<br>`--chain <CHAIN>`<br>`--json` |
| `trust audit publish-root` | `--tenant <TENANT>` |
| `trust audit prove` | `<SELECTOR>`<br>`--tenant <TENANT>`<br>`--json` |
| `trust audit verify-inclusion` | `--proof <PROOF>`<br>`--root <ROOT>`<br>`--pubkey <PUBKEY>`<br>`--tenant <TENANT>` |
| `trust audit provenance` | - |
| `trust audit provenance export` | `--tenant <TENANT>`<br>`-o, --output <OUTPUT>`<br>`--local` |
| `trust audit receipts` | - |
| `trust audit receipts export` | `--tenant <TENANT>`<br>`--plan-id <PLAN_ID>`<br>`--json`<br>`--archive <PATH>`<br>`--full-chain` |
| `trust audit receipts verify` | `<ARCHIVE>`<br>`--json` |
| `trust audit decisions` | - |
| `trust audit decisions list` | `--tenant <TENANT>`<br>`--json` |
| `trust audit decisions show` | `<DECISION_ID>`<br>`--tenant <TENANT>`<br>`--json` |
| `trust audit decisions export` | `--tenant <TENANT>`<br>`-o, --output <OUTPUT>`<br>`--format <FORMAT>` |
| `trust audit decisions trace` | `<DECISION_ID>`<br>`--tenant <TENANT>`<br>`--json` |
| `trust audit decisions impact` | `<DECISION_ID>`<br>`--tenant <TENANT>`<br>`--json` |
| `trust audit decisions similar` | `<DECISION_ID>`<br>`--tenant <TENANT>`<br>`--json` |
| `trust audit usage` | `--tenant <TENANT>`<br>`--vm <VM>`<br>`--json` |
| `trust audit transcript` | - |
| `trust audit transcript arm` | `<VM>`<br>`--tenant <TENANT>`<br>`--session <SESSION>`<br>`--max-bytes <MAX_BYTES>`<br>`--max-chunks <MAX_CHUNKS>`<br>`--max-duration <MAX_DURATION>` |
| `trust audit transcript disarm` | `<CAPTURE_ID>`<br>`--tenant <TENANT> = local` |
| `trust audit transcript reconcile` | `<CAPTURE_ID>`<br>`--tenant <TENANT> = local` |
| `trust audit transcript list` | `--tenant <TENANT>`<br>`--json` |
| `trust audit transcript export` | `<CAPTURE_ID>`<br>`--tenant <TENANT> = local`<br>`--out <OUT>` |
| `capture` | - |
| `capture project` | `<PATH>`<br>`--run <RUN>`<br>`-o, --output <OUTPUT>` |
| `capture resolve` | `<REPORT>`<br>`-o, --output <OUTPUT>` |
| `capture verify` | `<ENVIRONMENT>`<br>`--manifest-dir <MANIFEST_DIR>`<br>`--run <RUN>`<br>`-o, --out-dir <OUT_DIR>`<br>`--exec-in-builder-vm`<br>`--boot-and-replay` |
| `deps` | - |
| `deps inspect` | `<VOLUME_HASH>`<br>`--cache-root <CACHE_ROOT>`<br>`--json` |
| `deps audit` | `--all`<br>`--cache-root <CACHE_ROOT>`<br>`--json` |
| `deps capture` | `<VOLUME_HASH>`<br>`--content-dir <DIR>`<br>`--sbom <PATH>`<br>`--fetch-log <PATH>`<br>`--cve <PATH>`<br>`--cache-root <CACHE_ROOT>`<br>`--json`<br>`--declaration <PATH>`<br>`--lockfile <PATH>` |
| `deps install` | `--lockfile <PATH>`<br>`--source-root <DIR>`<br>`--language <LANGUAGE>`<br>`--cache-root <CACHE_ROOT>`<br>`--json` |
| `deps capture-live` | `<VOLUME_HASH>`<br>`--vm <VM>`<br>`--guest-content <PATH>`<br>`--guest-sbom <PATH>`<br>`--guest-fetch-log <PATH>`<br>`--guest-cve <PATH>`<br>`--cache-root <CACHE_ROOT>`<br>`--json`<br>`--declaration <PATH>`<br>`--lockfile <PATH>`<br>`--max-bytes <MAX_BYTES>`<br>`--max-files <MAX_FILES>` |
| `ops` | - |
| `ops metrics` | `--json`<br>`--instance <INSTANCE_ID>` |
| `ops config` | - |
| `ops config show` | - |
| `ops config edit` | - |
| `ops config set` | `<KEY>`<br>`<VALUE>` |
| `ops mcp` | - |
| `ops mcp stdio` | `--machine <MACHINE>` |
| `shell-init` | - |
| `dev` | `--allow-local-builder-build` |
| `dev compile` | `--from-ir <PATH>`<br>`--from-recording <PATH>`<br>`--recording-sha256 <HEX64>`<br>`-o, --out <PATH>`<br>`--mvm-revision <COMMIT>`<br>`--mode <MODE>`<br>`--prod`<br>`--dev` |
| `dev validate` | `--flake <FLAKE>`<br>`--json` |
| `dev kernel` | - |
| `dev kernel build` | `--which <WHICH>`<br>`--all`<br>`--source <SOURCE>`<br>`--arch <ARCH>`<br>`--boot-check` |
| `dev runtime-overlay` | - |
| `dev runtime-overlay build` | `--source <SOURCE>`<br>`--arch <ARCH>`<br>`--version <VERSION>`<br>`--force` |
| `dev sdk-sidecar` | - |
| `dev sdk-sidecar build` | `--source <SOURCE>`<br>`--force` |
| `dev address` | `--from-ir <PATH>`<br>`--json` |
| `dev image-set` | `<ROLE>`<br>`--attr <ATTR>` |
| `dev guest-bins` | `--out <DIR>`<br>`--arch <ARCH>`<br>`--check-release-archive <FILE>` |
| `bootstrap` | `--production` |
<!-- cli-tree:end -->

### 3.4 Environment knobs

Generated by `python3 scripts/gen-cli-surface-inventory.py` (block below; `--check` fails on drift). It scans every `.rs` under `crates` and `src`, test files included, for `"MVM_[A-Z0-9_]+"` literals and classifies each by the line it sits on. This is a line heuristic, not a parser: code after the first `#[cfg(test)]` in a file counts as test code; a literal on a line with `.env(`, `.envs(`, `set_var` or `env_remove` is a write. A `live-read` row can still be a `const` whose use is elsewhere, and a literal in the environment of a child can be read by a program outside the Rust scan (`set-only`). The earlier count of 307 excluded `tests/` and `tests.rs` only; the same scan including them is the 377 below, and moving `#[cfg(test)]` code out of "live" is what separates the classes.

Documented as removed or non-existent (checked against the generated block: none of these four has a `live-read` row):

| Knob | Source of the statement | Status in code |
|---|---|---|
| `MVM_NETWORKING`, `MVM_GATEWAY_BIN` | CLAUDE.md: gone with the gateway | no literal anywhere |
| `MVM_ACK_UNRESTRICTED_NETWORK` | CLAUDE.md claim 10: never existed | no literal; but `public/src/content/docs/guides/fleet-stream-edges.md:61` still documents it, see the docs-only table |
| `MVM_NO_VM` | read by the SDKs (`__sdk-no-vm`) | not a Rust literal |

<!-- env:begin -->
Distinct `MVM_*` literals in Rust (`crates`, `src`, tests included): **377**; live-read **222**, set-only **7**, test-only **148**; live-read and absent from `public/src/content/docs`: **150**; names in `public/src/content/docs` that no Rust literal or script/nix/feature/test file uses: **19**.

Columns: class (`live-read` = a literal on a non-test, non-write line; `set-only` = only written to a child process, so the reader is outside Rust or in another process; `test-only` = test code only), first reader `file:line`, count of live-read sites, documented in `public/src/content/docs`, referenced by a script/nix/feature/test file.

| Literal | Class | First site | Live sites | Documented | Non-Rust ref |
|---|---|---|---|---|---|
| `MVM_ACK_PERMISSIVE_RUN` | live-read | `crates/mvm-cli/src/commands/vm/run_validation.rs:46` | 1 | yes | - |
| `MVM_ACK_RAW_STREAM_EDGE` | live-read | `crates/mvm-contract/src/stream/edge.rs:38` | 1 | yes | - |
| `MVM_ACTIVATION_FILE` | live-read | `crates/mvm-runtime/src/wasm_activation.rs:56` | 1 | yes | - |
| `MVM_AC_E2E` | test-only | `crates/mvm-runtime/src/apple_container_backend.rs:521` | 0 | NO | - |
| `MVM_AC_E2E_ROOTFS` | test-only | `crates/mvm-runtime/src/apple_container_backend.rs:525` | 0 | NO | - |
| `MVM_ADDON_DNS_BIND_ADDRS` | live-read | `crates/mvm-agentd/src/addon_dns_launch.rs:72` | 2 | NO | - |
| `MVM_ADDON_DNS_FLOWMUX_RESOLVER` | live-read | `crates/mvm-agentd/src/bin/mvm-addon-dns.rs:77` | 1 | NO | - |
| `MVM_ADDON_DNS_UPSTREAM_ADDRS` | live-read | `crates/mvm-agentd/src/addon_dns_launch.rs:77` | 2 | NO | - |
| `MVM_ADDON_DNS_UPSTREAM_RESOLV_PATH` | live-read | `crates/mvm-agentd/src/addon_dns_launch.rs:82` | 2 | NO | - |
| `MVM_ADDON_DNS_ZONE_PATH` | live-read | `crates/mvm-agentd/src/addon_dns_launch.rs:73` | 2 | NO | - |
| `MVM_ADDON_LOOPBACK_BINDINGS_PATH` | live-read | `crates/mvm-agentd/src/bin/mvm-addon-vsock-bridge.rs:17` | 1 | NO | - |
| `MVM_AEAD_TEST_CHILD_KEY_PATH` | test-only | `crates/mvm-core/src/crypto/aead.rs:301` | 0 | NO | - |
| `MVM_AEAD_TEST_CHILD_START_PATH` | test-only | `crates/mvm-core/src/crypto/aead.rs:302` | 0 | NO | - |
| `MVM_AGENT_DIRECT_VSOCK_UDS` | test-only | `crates/mvm-agentd/tests/live_resource_usage.rs:15` | 0 | NO | - |
| `MVM_AGENT_EGRESS_ENDPOINT_SOCK` | live-read | `crates/mvm-agentd/src/flowmux_sync.rs:57` | 1 | NO | - |
| `MVM_AGENT_SMOKE` | test-only | `crates/mvm-cli/tests/agent_workload_example.rs:116` | 0 | NO | - |
| `MVM_AGENT_TRANSPORT` | live-read | `crates/mvm-agentd/src/bin/mvm-guest-agent/transport.rs:32` | 1 | NO | - |
| `MVM_AGENT_UNIX_SOCK` | live-read | `crates/mvm-agentd/src/bin/mvm-guest-agent/transport.rs:34` | 1 | NO | - |
| `MVM_AGENT_VSOCK_UDS` | test-only | `crates/mvm-agentd/tests/live_resource_usage.rs:19` | 0 | NO | - |
| `MVM_ALLOW_LOCAL_BUILDER_BUILD` | live-read | `crates/mvm-client/src/entrypoint/caller_registration_live_hvf.rs:218` | 2 | yes | yes |
| `MVM_ALLOW_STALE_SNAPSHOT` | live-read | `crates/mvm-runtime/src/base/snapshot_integrity.rs:107` | 2 | NO | - |
| `MVM_ALLOW_UNENCRYPTED_SNAPSHOT` | live-read | `crates/mvm-runtime/src/vm/instance_snapshot.rs:74` | 1 | yes | - |
| `MVM_ALLOW_UNENCRYPTED_VOLUME_STORAGE` | live-read | `crates/mvm-core/src/host_storage_encryption.rs:34` | 1 | yes | yes |
| `MVM_ALLOW_UNSIGNED_RUNTIME` | test-only | `crates/mvm-build/src/guest_runtime.rs:2416` | 0 | NO | - |
| `MVM_APFS_SNAPSHOT_HELPER_SOCKET` | live-read | `crates/mvm-fs/src/trusted_snapshot.rs:105` | 1 | NO | - |
| `MVM_API_TOKEN` | test-only | `crates/mvm-hostd/src/workload_env.rs:103` | 0 | NO | - |
| `MVM_ATTRIBUTION_ANSWER_PID` | test-only | `crates/mvm-agentd/src/tool_attribution.rs:1017` | 0 | NO | - |
| `MVM_ATTRIBUTION_CLIENT` | test-only | `crates/mvm-agentd/src/tool_attribution.rs:1009` | 0 | NO | - |
| `MVM_ATTRIBUTION_CREDENTIAL_WITNESS` | test-only | `crates/mvm-agentd/src/tool_attribution.rs:1007` | 0 | NO | - |
| `MVM_ATTRIBUTION_SERVER` | test-only | `crates/mvm-agentd/src/tool_attribution.rs:1013` | 0 | NO | - |
| `MVM_AUDIT_CONCURRENT_WORKER` | test-only | `crates/mvm-hostd/tests/audit_chain_concurrent_writers.rs:31` | 0 | NO | - |
| `MVM_AUDIT_SEGMENT_BYTES` | live-read | `crates/mvm-core/src/config.rs:1348` | 1 | yes | - |
| `MVM_AUDIT_SIGNER_PATH` | live-read | `crates/mvm-vmm/src/host/broker_services_spawn.rs:186` | 1 | NO | - |
| `MVM_AUDIT_WITNESS` | live-read | `crates/mvm-hostd/src/audit/witness.rs:367` | 2 | yes | yes |
| `MVM_AUTO_DEV` | live-read | `crates/mvm-vmm/src/host/linux_env.rs:99` | 1 | NO | - |
| `MVM_AUX_BIN_DIR` | live-read | `crates/mvm-vmm/src/host/aux_bin.rs:779` | 1 | NO | - |
| `MVM_BACKEND` | live-read | `crates/mvm-cli/src/commands/vm/run_policy.rs:152` | 2 | NO | - |
| `MVM_BASE_CONTRACT_TEST_CHILD` | live-read | `crates/mvm-cli/src/test_boot_payload.rs:12` | 1 | NO | - |
| `MVM_BDD_ALLOWED_SKIPS` | test-only | `crates/mvm-conformance/tests/conformance.rs:415` | 0 | NO | yes |
| `MVM_BDD_BUILD_MODE` | test-only | `crates/mvm-conformance/tests/steps/sdk.rs:243` | 0 | NO | yes |
| `MVM_BDD_BUNDLE` | test-only | `crates/mvm-conformance/tests/conformance.rs:581` | 0 | NO | yes |
| `MVM_BDD_BUNDLE_PUBKEY` | test-only | `crates/mvm-conformance/tests/conformance.rs:594` | 0 | NO | yes |
| `MVM_BDD_CALL_LOG` | test-only | `crates/mvm-conformance/tests/steps/sdk.rs:242` | 0 | NO | yes |
| `MVM_BDD_CVE_EVIDENCE_DIR` | test-only | `crates/mvm-conformance/tests/steps/cve_containment.rs:45` | 0 | NO | yes |
| `MVM_BDD_CVE_EXPLOIT` | test-only | `crates/mvm-conformance/tests/steps/cve_containment.rs:327` | 0 | NO | yes |
| `MVM_BDD_CVE_HYPERVISOR` | test-only | `crates/mvm-conformance/tests/steps/cve_containment.rs:397` | 0 | NO | yes |
| `MVM_BDD_CVE_INITRAMFS` | test-only | `crates/mvm-conformance/src/containment.rs:605` | 0 | NO | yes |
| `MVM_BDD_CVE_KERNEL` | test-only | `crates/mvm-conformance/src/containment.rs:576` | 0 | NO | yes |
| `MVM_BDD_DESTRUCTIVE_LAB` | test-only | `crates/mvm-conformance/tests/conformance.rs:477` | 0 | NO | yes |
| `MVM_BDD_DIR_SHARE` | test-only | `crates/mvm-conformance/tests/conformance.rs:556` | 0 | NO | yes |
| `MVM_BDD_GUEST_BIN_DIR` | test-only | `crates/mvm-conformance/tests/conformance.rs:532` | 0 | NO | yes |
| `MVM_BDD_LIVE` | test-only | `crates/mvm-conformance/tests/conformance.rs:464` | 0 | NO | yes |
| `MVM_BDD_ONLY_TAG` | test-only | `crates/mvm-conformance/tests/conformance.rs:331` | 0 | NO | yes |
| `MVM_BDD_PERF_BUDGET` | test-only | `crates/mvm-conformance/tests/conformance.rs:471` | 0 | NO | yes |
| `MVM_BDD_SHARD` | test-only | `crates/mvm-conformance/tests/conformance.rs:365` | 0 | yes | yes |
| `MVM_BDD_SNAPSHOT` | test-only | `crates/mvm-conformance/src/lib.rs:1213` | 0 | NO | yes |
| `MVM_BDD_STRICT_SKIPS` | test-only | `crates/mvm-conformance/tests/conformance.rs:412` | 0 | NO | yes |
| `MVM_BDD_TLS_CLIENT` | test-only | `crates/mvm-conformance/tests/conformance.rs:472` | 0 | NO | - |
| `MVM_BDD_WALL_CLOCK` | test-only | `crates/mvm-conformance/tests/conformance.rs:575` | 0 | NO | yes |
| `MVM_BDD_WARM_CLAIM` | test-only | `crates/mvm-conformance/tests/conformance.rs:476` | 0 | NO | yes |
| `MVM_BDD_WORKLOAD_KERNEL` | test-only | `crates/mvm-conformance/tests/conformance.rs:604` | 0 | NO | - |
| `MVM_BOOT_IMAGE` | live-read | `crates/mvm-build/src/boot_image_select.rs:32` | 1 | yes | yes |
| `MVM_BOOT_IMAGE_TAG` | live-read | `crates/mvm-core/src/config.rs:43` | 1 | NO | - |
| `MVM_BROKER_PATH` | live-read | `crates/mvm-vmm/src/host/broker_services_spawn.rs:508` | 1 | NO | - |
| `MVM_BUILDER_AGENT_PORT` | live-read | `crates/mvm-build/src/pipeline/vsock_builder.rs:9` | 1 | yes | - |
| `MVM_BUILDER_BACKEND` | live-read | `crates/mvm-build/src/builder_backend_select.rs:139` | 1 | yes | yes |
| `MVM_BUILDER_BOOT_STAGE` | live-read | `crates/mvm-builder-guest/src/builder_boot.rs:65` | 1 | NO | - |
| `MVM_BUILDER_CLOSURE_NAR` | live-read | `crates/mvm-runtime/examples/hvf-builder-transport.rs:72` | 1 | NO | - |
| `MVM_BUILDER_CMD_FILE` | live-read | `crates/mvm-runtime/examples/hvf-builder-transport.rs:56` | 2 | NO | - |
| `MVM_BUILDER_KERNEL` | live-read | `crates/mvm-runtime/examples/hvf-builder-transport.rs:24` | 1 | NO | - |
| `MVM_BUILDER_LOCK_WAIT_SECS` | live-read | `crates/mvm-build/src/builder_vm_runtime/image_lock.rs:191` | 1 | yes | yes |
| `MVM_BUILDER_MEM_MIB` | live-read | `crates/mvm-runtime/examples/hvf-builder-transport.rs:92` | 1 | NO | - |
| `MVM_BUILDER_MODE` | live-read | `crates/mvm-build/src/pipeline/orchestrator.rs:34` | 1 | yes | - |
| `MVM_BUILDER_ROOTFS` | live-read | `crates/mvm-runtime/examples/hvf-builder-transport.rs:29` | 1 | NO | - |
| `MVM_BUILDER_STORE_GC_GIB` | live-read | `crates/mvm-build/src/builder_vm_runtime.rs:120` | 1 | NO | - |
| `MVM_BUILDER_VM_BOOTSTRAP_ACTIVE` | live-read | `crates/mvm-build/src/builder_vm_bootstrap.rs:42` | 1 | NO | - |
| `MVM_BUILDER_VM_BOOTSTRAP_BIN` | live-read | `crates/mvm-build/src/builder_vm_bootstrap.rs:34` | 1 | NO | - |
| `MVM_BUILDER_VM_TIMEOUT_SECS` | live-read | `crates/mvm-build/src/builder_vm_runtime.rs:110` | 1 | yes | yes |
| `MVM_BUILD_SOURCE_COMMIT` | live-read | `crates/mvm-cli/build.rs:70` | 1 | NO | - |
| `MVM_BUILD_SOURCE_DIRTY` | live-read | `crates/mvm-cli/build.rs:74` | 1 | NO | - |
| `MVM_BUILD_STUB_OUTDIR` | live-read | `crates/mvm-build/src/pipeline/dev_build.rs:168` | 1 | NO | - |
| `MVM_CALLER_FIXTURE_ENABLE` | live-read | `crates/mvm-hostd/src/caller_identity/production_fixture.rs:64` | 2 | NO | - |
| `MVM_CALLER_FIXTURE_RECORD` | live-read | `crates/mvm-hostd/src/caller_identity/production_fixture.rs:336` | 3 | NO | - |
| `MVM_CALLER_REGISTRATION_REPLAY_DENIED` | live-read | `crates/mvm-hostd/src/supervisor/caller_registration.rs:24` | 1 | NO | - |
| `MVM_CALLER_REPLAY_CHALLENGE` | live-read | `crates/mvm-hostd/src/supervisor/caller_replay_tests.rs:226` | 2 | NO | - |
| `MVM_CALLER_REPLAY_CHILD` | live-read | `crates/mvm-hostd/src/supervisor/caller_replay_tests.rs:250` | 1 | NO | - |
| `MVM_CALLER_WITNESS_BIN` | live-read | `crates/mvm-hostd/src/caller_identity/production_fixture.rs:337` | 3 | NO | - |
| `MVM_CALLER_WITNESS_KERNEL` | live-read | `crates/mvm-client/src/entrypoint/caller_registration_live_hvf.rs:228` | 5 | NO | - |
| `MVM_CALLER_WITNESS_PIN_JSON` | live-read | `crates/mvm-client/src/entrypoint/caller_registration_live_hvf.rs:239` | 2 | NO | - |
| `MVM_CALLER_WITNESS_ROOT` | live-read | `crates/mvm-client/src/entrypoint/caller_registration_live_hvf.rs:91` | 5 | NO | - |
| `MVM_CALLER_WITNESS_SOURCE` | live-read | `crates/mvm-client/src/entrypoint/caller_registration_live_hvf.rs:225` | 5 | NO | - |
| `MVM_CALLER_WITNESS_START_GATE` | live-read | `crates/mvm-client/src/entrypoint/caller_registration_live_hvf.rs:130` | 2 | NO | - |
| `MVM_CLI` | test-only | `crates/mvm-sdk/src/env.rs:170` | 0 | NO | - |
| `MVM_COLD_BUILD` | live-read | `crates/mvm-core/src/cold_build.rs:19` | 1 | yes | yes |
| `MVM_COLD_LAUNCH_ARGS` | test-only | `crates/mvm-cli/tests/cold_launch_bench.rs:50` | 0 | NO | - |
| `MVM_COLD_LAUNCH_LANE` | test-only | `crates/mvm-cli/tests/cold_launch_bench.rs:54` | 0 | NO | - |
| `MVM_COLD_LAUNCH_MVMCTL` | test-only | `crates/mvm-cli/tests/cold_launch_bench.rs:49` | 0 | NO | - |
| `MVM_COLD_LAUNCH_RUNS` | test-only | `crates/mvm-cli/tests/cold_launch_bench.rs:58` | 0 | NO | - |
| `MVM_COLD_LAUNCH_WARMUP` | test-only | `crates/mvm-cli/tests/cold_launch_bench.rs:59` | 0 | NO | - |
| `MVM_CONFINEMENT_SELF_TEST_CHILD` | test-only | `crates/mvm-hostd/tests/confinement_self_test.rs:24` | 0 | NO | - |
| `MVM_CONFINEMENT_SELF_TEST_DIR` | test-only | `crates/mvm-hostd/tests/confinement_self_test.rs:25` | 0 | NO | - |
| `MVM_DECLARED_DIR_PROBE_CLI_PATH` | test-only | `crates/mvm-vmm/src/host/aux_bin.rs:1659` | 0 | NO | - |
| `MVM_DECLARED_DIR_PROBE_HELPER_PATH` | test-only | `crates/mvm-vmm/src/host/aux_bin.rs:1599` | 0 | NO | - |
| `MVM_DEV` | live-read | `crates/mvm-cli/src/commands/dashboard/mod.rs:50` | 1 | NO | - |
| `MVM_DEV_DAEMON` | live-read | `crates/mvm-vmm/src/host/linux_env.rs:96` | 1 | NO | - |
| `MVM_DIAGNOSTIC_APPROVED_REQUEST_SHA256` | live-read | `crates/mvm-client/src/portable_boot_assets_diagnostic.rs:231` | 1 | NO | - |
| `MVM_DIAGNOSTIC_FIXTURE_ROOT` | live-read | `crates/mvm-client/src/portable_boot_assets_diagnostic.rs:273` | 1 | NO | - |
| `MVM_DIAGNOSTIC_INPUT_ROOT` | live-read | `crates/mvm-client/src/portable_boot_assets_diagnostic.rs:226` | 1 | NO | - |
| `MVM_DIAGNOSTIC_PREFLIGHT_INPUT_ROOT` | live-read | `crates/mvm-client/src/portable_boot_assets_diagnostic.rs:342` | 1 | NO | - |
| `MVM_DIAGNOSTIC_TEST_CASE` | test-only | `crates/mvm-conformance/tests/failure_diagnostics.rs:107` | 0 | NO | - |
| `MVM_DIRECT_BOOT` | live-read | `crates/mvm-cli/src/commands/machine/runtime.rs:13` | 3 | NO | - |
| `MVM_DUMP_CORPUS` | test-only | `crates/mvm-conformance/src/doc_examples.rs:1668` | 0 | NO | - |
| `MVM_E2E_FAILURE_AUTHORIZATION` | test-only | `crates/mvm-conformance/tests/failure_diagnostics.rs:75` | 0 | yes | yes |
| `MVM_E2E_FAILURE_EXPORT` | test-only | `crates/mvm-conformance/tests/failure_diagnostics.rs:76` | 0 | yes | yes |
| `MVM_E2E_FAILURE_INITIALIZED` | test-only | `crates/mvm-conformance/tests/steps/cli.rs:199` | 0 | NO | yes |
| `MVM_E2E_FAILURE_MANIFEST` | test-only | `crates/mvm-conformance/tests/failure_diagnostics.rs:12` | 0 | yes | yes |
| `MVM_E2E_HOME` | test-only | `crates/mvm-conformance/tests/conformance.rs:521` | 0 | yes | yes |
| `MVM_E2E_IMAGE_REVOCATIONS_DIR` | test-only | `crates/mvm-conformance/tests/steps/cli.rs:770` | 0 | NO | yes |
| `MVM_E2E_KERNEL` | test-only | `crates/mvm-client/tests/launch_lifecycle_live.rs:23` | 0 | NO | yes |
| `MVM_E2E_LINGER_SECS` | test-only | `crates/mvm-client/tests/launch_lifecycle_live_hvf.rs:38` | 0 | NO | - |
| `MVM_E2E_MVMCTL` | test-only | `crates/mvm-client/tests/protected_capture_live_hvf.rs:62` | 0 | NO | yes |
| `MVM_E2E_PRODUCER_MVMCTL` | test-only | `crates/mvm-conformance/tests/steps/cli.rs:375` | 0 | NO | yes |
| `MVM_E2E_ROOTFS` | test-only | `crates/mvm-client/tests/launch_lifecycle_live.rs:24` | 0 | NO | yes |
| `MVM_E2E_RUNTIME_CANDIDATE_DIR` | test-only | `crates/mvm-conformance/tests/conformance.rs:353` | 0 | NO | yes |
| `MVM_EBPF_LIVE_TESTS` | test-only | `crates/mvm-hostd/src/supervisor/ebpf_telemetry/loader.rs:324` | 0 | NO | - |
| `MVM_EGRESS_LISTEN` | live-read | `crates/mvm-agentd/src/bin/mvm-egress-client.rs:135` | 1 | NO | - |
| `MVM_EGRESS_VSOCK_PORT` | live-read | `crates/mvm-agentd/src/bin/mvm-egress-client.rs:26` | 3 | NO | - |
| `MVM_EMBED` | live-read | `crates/mvm-cli/build.rs:152` | 1 | yes | yes |
| `MVM_EMBED_CACHE_DIR` | live-read | `crates/mvm-cli/build_embed_cache.rs:131` | 1 | NO | - |
| `MVM_EMBED_CACHE_MAX_BYTES` | live-read | `crates/mvm-cli/src/host_binaries/payload_build.rs:135` | 1 | NO | - |
| `MVM_EMBED_CARGO` | live-read | `crates/mvm-build/src/embed_toolchain.rs:219` | 1 | NO | yes |
| `MVM_EMBED_NO_CACHE` | live-read | `crates/mvm-cli/build.rs:337` | 2 | NO | yes |
| `MVM_EMBED_RUSTC` | live-read | `crates/mvm-build/src/embed_toolchain.rs:220` | 1 | NO | yes |
| `MVM_EMBED_ZIG` | live-read | `crates/mvm-build/src/embed_toolchain.rs:96` | 1 | NO | - |
| `MVM_ENDPOINT_HANDSHAKE_TIMEOUT_SECS` | live-read | `crates/mvm-vmm/src/host/network_endpoint_spawn.rs:409` | 1 | NO | - |
| `MVM_ENTRYPOINT_TEST_WRAPPER` | test-only | `crates/mvm-agentd/tests/process_fd_hygiene.rs:12` | 0 | NO | - |
| `MVM_ENV` | live-read | `crates/mvm-core/src/config.rs:1494` | 1 | NO | - |
| `MVM_ENV_HYGIENE_KEPT` | test-only | `crates/mvm-core/tests/env_hygiene_spawn.rs:96` | 0 | NO | - |
| `MVM_ENV_HYGIENE_SPAWN_PROBE` | test-only | `crates/mvm-core/tests/env_hygiene_spawn.rs:14` | 0 | NO | - |
| `MVM_FAILURE_DIAGNOSTICS` | live-read | `crates/mvm-core/src/launch_trace/failure.rs:7` | 1 | yes | - |
| `MVM_FAKE_RUNNER_BEHAVIOR` | test-only | `crates/mvm-agentd/tests/bin/fake_runner.rs:66` | 0 | NO | yes |
| `MVM_FC_BOOT_SMOKE` | test-only | `crates/mvm-builder-guest/src/bin/mvm-host-vm-init/workload.rs:483` | 0 | NO | - |
| `MVM_FC_IDLE_POOL` | live-read | `crates/mvm-backends/src/fc/idle_pool.rs:50` | 1 | yes | - |
| `MVM_FC_SMOKE_KERNEL` | test-only | `crates/mvm-builder-guest/src/bin/mvm-host-vm-init/workload.rs:491` | 0 | NO | - |
| `MVM_FC_SMOKE_ROOTFS` | test-only | `crates/mvm-builder-guest/src/bin/mvm-host-vm-init/workload.rs:493` | 0 | NO | - |
| `MVM_FC_VERSION` | live-read | `crates/mvm-core/src/config.rs:8` | 2 | yes | yes |
| `MVM_FLAKE_URL` | live-read | `crates/mvm-compiler/src/mvm_pin.rs:30` | 1 | yes | - |
| `MVM_FLEET` | live-read | `crates/mvm-cli/src/commands/dashboard/mod.rs:49` | 1 | NO | - |
| `MVM_FLOWMUX_GUEST_SIGNING_KEY_PATH` | live-read | `crates/mvm-agentd/src/flowmux_keys.rs:31` | 2 | NO | - |
| `MVM_FLOWMUX_INGRESS_TARGETS_PATH` | live-read | `crates/mvm-agentd/src/flowmux_keys.rs:55` | 1 | NO | - |
| `MVM_FOREGROUND_APPROVED_PROVENANCE_SHA256` | live-read | `crates/mvm-client/src/entrypoint/foreground_diagnostic.rs:114` | 1 | NO | - |
| `MVM_FOREGROUND_PROVENANCE_PATH` | live-read | `crates/mvm-client/src/entrypoint/foreground_diagnostic.rs:102` | 1 | NO | - |
| `MVM_FORMAT` | set-only | `crates/mvm-agentd/src/bin/mvm-runner.rs:94` | 0 | NO | - |
| `MVM_FRESH_PROCESS_TEST_CHILD` | live-read | `crates/mvm-cli/src/test_boot_payload.rs:13` | 1 | NO | - |
| `MVM_FUNCTION` | set-only | `crates/mvm-agentd/src/bin/mvm-runner.rs:93` | 0 | NO | - |
| `MVM_GATEWAY_TOKEN` | live-read | `crates/mvm-cli/src/commands/vm/volume/remote.rs:26` | 1 | yes | - |
| `MVM_GATEWAY_URL` | live-read | `crates/mvm-cli/src/commands/vm/volume/remote.rs:25` | 1 | yes | yes |
| `MVM_GPU_ENDPOINT_PATH` | live-read | `crates/mvm-vmm/src/host/gpu_endpoint_spawn.rs:38` | 1 | NO | - |
| `MVM_GPU_RPC` | live-read | `crates/mvm-gpu-shim-core/src/lib.rs:32` | 1 | NO | yes |
| `MVM_GPU_TEST_EXPECT_NATIVE` | test-only | `crates/mvm-gpu/src/native.rs:1415` | 0 | NO | - |
| `MVM_GUEST_BUILD_VERBOSE` | live-read | `crates/mvm-build/src/guest_agent_build.rs:23` | 1 | NO | - |
| `MVM_GUEST_CONSOLE_VERBOSE` | test-only | `crates/mvm-backends/src/driver/fc.rs:121` | 0 | NO | - |
| `MVM_GUEST_PRIVILEGED_TESTS` | live-read | `crates/mvm-agentd/src/tool_helper/capability_tests.rs:60` | 2 | NO | yes |
| `MVM_HARD_EXPIRY_FIXTURE` | test-only | `crates/mvm-hostd/src/supervisor/wall_clock.rs:394` | 0 | NO | - |
| `MVM_HIGH_CAPABILITY_PROBE_CHILD` | live-read | `crates/mvm-agentd/src/guest_mount/high_capability_tests.rs:13` | 1 | NO | - |
| `MVM_HOME` | live-read | `crates/mvm-cli/src/commands/vm/runtime_pack.rs:354` | 27 | yes | yes |
| `MVM_HOSTLIB_PATH` | live-read | `crates/mvm-sdk/src/env.rs:110` | 2 | yes | yes |
| `MVM_HOSTLIB_PATH_ENV` | test-only | `crates/mvm-sdk/src/env.rs:139` | 0 | NO | yes |
| `MVM_HOST_AGENT_DAEMON` | live-read | `crates/mvm-vmm/src/host/host_agent_spawn.rs:568` | 1 | yes | - |
| `MVM_HOST_AGENT_IDLE_TIMEOUT` | live-read | `crates/mvm-hostd/src/host_agent_idle.rs:48` | 1 | NO | - |
| `MVM_HOST_AGENT_PATH` | live-read | `crates/mvm-cli/src/commands/env/uninstall.rs:187` | 4 | NO | yes |
| `MVM_HOST_AGENT_WORKER` | live-read | `crates/mvm-hostd/src/bin/mvm-host-agent.rs:39` | 1 | NO | - |
| `MVM_HOST_BIN_DIR` | set-only | `crates/mvm-agentd/src/builder_build.rs:88` | 0 | NO | - |
| `MVM_HVF_AGENT_DEBUG` | live-read | `crates/mvm-vmm/src/agent_debug.rs:18` | 1 | NO | yes |
| `MVM_HVF_AGENT_SOCKET` | live-read | `crates/mvm-runtime/examples/hvf-agent-ping.rs:22` | 1 | NO | - |
| `MVM_HVF_BOOTARGS` | live-read | `crates/mvm-client/src/entrypoint/caller_registration_live_hvf.rs:216` | 3 | NO | - |
| `MVM_HVF_BOOTARGS_EXTRA` | live-read | `crates/mvm-runtime/examples/hvf-backend-egress.rs:92` | 4 | NO | - |
| `MVM_HVF_DIAGNOSTICS_TEST_CHILD` | test-only | `crates/mvm-vmm/src/host/hvf_supervisor/startup_diagnostics.rs:251` | 0 | NO | - |
| `MVM_HVF_DIAGNOSTICS_TEST_SYNC_FD` | test-only | `crates/mvm-vmm/src/host/hvf_supervisor/startup_diagnostics.rs:253` | 0 | NO | - |
| `MVM_HVF_DISK` | live-read | `crates/mvm-runtime/examples/hvf-agent-ping.rs:32` | 5 | NO | - |
| `MVM_HVF_ENABLE_TRUSTED_SNAPSHOT` | test-only | `crates/mvm-runtime/src/workload_runner/runner.rs:1279` | 0 | NO | yes |
| `MVM_HVF_INITRAMFS` | live-read | `crates/mvm-runtime/examples/hvf-kernel-boot.rs:29` | 1 | NO | - |
| `MVM_HVF_INITRD` | live-read | `crates/mvm-runtime/examples/hvf-backend-egress.rs:104` | 6 | NO | - |
| `MVM_HVF_KERNEL` | live-read | `crates/mvm-runtime/examples/hvf-agent-ping.rs:31` | 9 | NO | - |
| `MVM_HVF_LEGACY_CONFIG_REPLAY` | live-read | `crates/mvm-hostd/src/bin/mvm-hvf-supervisor.rs:23` | 2 | NO | - |
| `MVM_HVF_SIGNED` | live-read | `crates/mvm-hostd/src/bin/mvm-hvf-supervisor.rs:321` | 2 | NO | - |
| `MVM_HVF_STARTUP_DIAGNOSTICS_FD` | live-read | `crates/mvm-hostd/src/supervisor/caller_registration.rs:146` | 2 | NO | - |
| `MVM_HVF_SUBSTITUTION_SOCKET` | test-only | `crates/mvm-runtime/src/backends/hvf/kernel_boot.rs:1581` | 0 | NO | - |
| `MVM_HVF_SUPERVISOR_PATH` | live-read | `crates/mvm-backends/src/driver/hvf_process.rs:127` | 9 | yes | yes |
| `MVM_HVF_TIMEOUT` | live-read | `crates/mvm-runtime/examples/hvf-backend-persistent.rs:22` | 2 | NO | - |
| `MVM_HVF_VIRTIO_DEBUG` | live-read | `crates/mvm-vmm/src/vmm/virtio.rs:36` | 1 | NO | - |
| `MVM_HVF_VSOCK` | live-read | `crates/mvm-runtime/examples/hvf-kernel-boot.rs:42` | 1 | NO | - |
| `MVM_HVF_WARM_REQUIRE_CLAIM` | live-read | `crates/mvm-cli/src/commands/pool/cold_start.rs:110` | 1 | NO | yes |
| `MVM_HYPERVISOR` | live-read | `crates/mvm-cli/src/commands/vm/run_policy.rs:152` | 2 | NO | - |
| `MVM_IDLE_TIMEOUT` | live-read | `crates/mvm-hostd/src/supervisor/reaper.rs:90` | 1 | NO | - |
| `MVM_IMAGES_DIR` | live-read | `crates/mvm-build/src/image_source.rs:69` | 4 | yes | yes |
| `MVM_INSTALL_LIB_DIR` | live-read | `crates/mvm-cli/src/commands/env/uninstall.rs:40` | 1 | yes | yes |
| `MVM_IR_OUT` | live-read | `crates/mvm-sdk/src/emit.rs:10` | 1 | yes | yes |
| `MVM_ISOLATED_HELPER_TEST_MODE` | test-only | `crates/mvm-cli/src/test_boot_payload.rs:186` | 0 | NO | - |
| `MVM_KERNEL_HANDOFF_UNIT_CHILD` | live-read | `crates/mvm-runtime/src/kernel_custody/native_handoff_tests.rs:99` | 1 | NO | - |
| `MVM_KERNEL_PATH` | live-read | `crates/mvm-client/src/launch/machine_start.rs:165` | 1 | NO | - |
| `MVM_KERNEL_SOURCE` | live-read | `crates/mvm-cli/src/commands/env/builder_vm/kernel.rs:128` | 4 | yes | yes |
| `MVM_KRUN_LOG` | live-read | `crates/mvm-hostd/src/bin/mvm-libkrun-supervisor.rs:107` | 1 | NO | - |
| `MVM_LAUNCH_SAMPLE_JSON` | live-read | `crates/mvm-core/src/launch_trace.rs:96` | 1 | yes | - |
| `MVM_LIBKRUN_E2E` | test-only | `crates/mvm-runtime/tests/libkrun_lifecycle_e2e.rs:67` | 0 | NO | - |
| `MVM_LIBKRUN_HEADER` | live-read | `crates/deps/libkrun-sys/build.rs:61` | 1 | NO | yes |
| `MVM_LIBKRUN_SUPERVISOR` | test-only | `crates/mvm-vmm/src/host/aux_bin.rs:1557` | 0 | NO | - |
| `MVM_LIBKRUN_SUPERVISOR_PATH` | live-read | `crates/mvm-backends/src/driver/libkrun_process.rs:563` | 2 | NO | yes |
| `MVM_LINUX_BUILDER_VM` | live-read | `crates/mvm-build/src/builder_backend_select.rs:151` | 1 | NO | - |
| `MVM_LIVE_FORK_CHECKPOINT` | test-only | `crates/mvm-runtime/tests/fc_fork_live.rs:455` | 0 | NO | - |
| `MVM_LIVE_FORK_CHILD` | test-only | `crates/mvm-runtime/tests/fc_fork_live.rs:451` | 0 | NO | - |
| `MVM_LIVE_FORK_CHILDREN` | test-only | `crates/mvm-runtime/tests/fc_fork_live.rs:567` | 0 | NO | - |
| `MVM_LIVE_FORK_CHILD_NAME` | test-only | `crates/mvm-runtime/tests/fc_fork_live.rs:456` | 0 | NO | - |
| `MVM_LIVE_FORK_WITNESS` | test-only | `crates/mvm-runtime/tests/fc_fork_live.rs:458` | 0 | NO | - |
| `MVM_LIVE_GUEST_MIB` | test-only | `crates/mvm-hostd/tests/spawn_ceiling_audit_live.rs:50` | 0 | NO | - |
| `MVM_LIVE_HOME` | test-only | `crates/mvm-runtime/tests/fc_fork_live.rs:527` | 0 | NO | yes |
| `MVM_LIVE_KERNEL` | test-only | `crates/mvm-runtime/src/vm/instance_snapshot.rs:1763` | 0 | NO | yes |
| `MVM_LIVE_LUKS` | test-only | `crates/mvm-runtime/src/storage/volume/encrypted_linux.rs:270` | 0 | NO | - |
| `MVM_LIVE_RESTORE_CHECKPOINT` | test-only | `crates/mvm-runtime/tests/fc_warm_pool_live.rs:524` | 0 | NO | - |
| `MVM_LIVE_RESTORE_CHILD` | test-only | `crates/mvm-runtime/tests/fc_warm_pool_live.rs:527` | 0 | NO | - |
| `MVM_LIVE_RESTORE_WITNESS` | test-only | `crates/mvm-runtime/tests/fc_warm_pool_live.rs:529` | 0 | NO | - |
| `MVM_LIVE_ROOTFS` | test-only | `crates/mvm-runtime/src/vm/instance_snapshot.rs:1764` | 0 | NO | yes |
| `MVM_LIVE_SMOKE` | test-only | `crates/mvm-agentd/tests/live_resource_usage.rs:10` | 0 | NO | - |
| `MVM_LIVE_VMM_ARGV` | test-only | `crates/mvm-hostd/tests/spawn_ceiling_audit_live.rs:41` | 0 | NO | - |
| `MVM_MACHINE_MAX_OUTPUT_BYTES` | test-only | `crates/mvm-sdk/src/env.rs:172` | 0 | NO | - |
| `MVM_MACHINE_TIMEOUT_SEC` | test-only | `crates/mvm-sdk/src/env.rs:171` | 0 | NO | - |
| `MVM_MATERIALIZE_BUILDER_VM` | live-read | `crates/mvm-build/src/run_image.rs:927` | 1 | yes | yes |
| `MVM_MODULE` | set-only | `crates/mvm-agentd/src/bin/mvm-runner.rs:92` | 0 | NO | - |
| `MVM_MVMD_API_KEY` | live-read | `crates/mvm-cli/src/commands/deploy.rs:122` | 1 | NO | - |
| `MVM_MVMD_URL` | live-read | `crates/mvm-cli/src/commands/deploy.rs:164` | 1 | NO | - |
| `MVM_NATIVE_CALLER_TEST` | live-read | `crates/mvm-hostd/src/caller_identity/native_tests.rs:115` | 1 | NO | - |
| `MVM_NATIVE_CALLER_TEST_NAMESPACE` | live-read | `crates/mvm-hostd/src/caller_identity/native_tests.rs:166` | 1 | NO | - |
| `MVM_NATIVE_CALLER_TEST_OPERATION` | live-read | `crates/mvm-hostd/src/caller_identity/native_tests.rs:168` | 1 | NO | - |
| `MVM_NATIVE_CALLER_TEST_PIN` | live-read | `crates/mvm-hostd/src/caller_identity/native_tests.rs:35` | 3 | NO | - |
| `MVM_NETWORK_PERF_BACKEND` | live-read | `crates/mvm-hostd/examples/network_perf_probe.rs:78` | 1 | NO | - |
| `MVM_NETWORK_PERF_CPU` | live-read | `crates/mvm-hostd/examples/network_perf_probe.rs:76` | 1 | NO | - |
| `MVM_NETWORK_PERF_HOST_ID` | live-read | `crates/mvm-hostd/examples/network_perf_probe.rs:73` | 1 | NO | - |
| `MVM_NETWORK_PERF_IMPLEMENTATION` | live-read | `crates/mvm-hostd/examples/network_perf_probe.rs:93` | 1 | NO | - |
| `MVM_NETWORK_PERF_SAMPLES` | live-read | `crates/mvm-hostd/examples/network_perf_probe.rs:100` | 1 | NO | - |
| `MVM_NETWORK_PERF_SOURCE_COMMIT` | live-read | `crates/mvm-hostd/examples/network_perf_probe.rs:82` | 1 | NO | - |
| `MVM_NETWORK_PERF_STORAGE` | live-read | `crates/mvm-hostd/examples/network_perf_probe.rs:79` | 1 | NO | - |
| `MVM_NODE` | live-read | `crates/mvm-cli/src/commands/build/sandbox_record.rs:227` | 1 | NO | - |
| `MVM_NO_AUTO_DEV` | live-read | `crates/mvm-vmm/src/host/linux_env.rs:93` | 1 | NO | - |
| `MVM_NO_BUILD_CACHE` | live-read | `crates/mvm-build/src/pipeline/dev_build.rs:282` | 1 | NO | - |
| `MVM_NO_LEGACY_BANNER` | live-read | `crates/mvm-hostd/src/caller_identity/production_fixture/environment.rs:47` | 3 | NO | yes |
| `MVM_NO_PERSISTENT_BUILDER` | live-read | `crates/mvm-build/src/pipeline/dev_build.rs:509` | 1 | yes | - |
| `MVM_NO_UPDATE_CHECK` | live-read | `crates/mvm-cli/src/update_notice.rs:26` | 1 | NO | - |
| `MVM_OCI_BEARER_TOKEN` | live-read | `crates/mvm-cli/src/commands/image/trust.rs:101` | 1 | yes | - |
| `MVM_OCI_BEARER_TOKEN_GHCR_IO` | test-only | `crates/mvm-cli/src/commands/image/trust.rs:151` | 0 | yes | - |
| `MVM_OCI_POLICY` | live-read | `crates/mvm-cli/src/commands/image/trust_policy.rs:279` | 1 | yes | - |
| `MVM_OTLP_EXIT_TEST_CHILD` | test-only | `crates/mvm-cli/tests/otlp_exit.rs:19` | 0 | NO | - |
| `MVM_OTLP_FILTER` | live-read | `crates/mvm-cli/src/observability/otlp/config.rs:12` | 1 | yes | - |
| `MVM_OWNED_STOP_MODE` | live-read | `crates/mvm-hostd/src/supervisor/hvf_stop_native_tests.rs:18` | 1 | NO | - |
| `MVM_OWNED_STOP_VM` | live-read | `crates/mvm-hostd/src/supervisor/hvf_stop_native_tests.rs:17` | 1 | NO | - |
| `MVM_PACK_REGISTRY` | live-read | `crates/mvm-client/src/registry_application/discovery.rs:11` | 1 | yes | yes |
| `MVM_PHASE_TIMING` | live-read | `crates/mvm-core/src/launch_trace.rs:52` | 1 | yes | yes |
| `MVM_PINNED_CARGO_ZIGBUILD` | live-read | `crates/mvm-cli/src/doctor/toolchain.rs:70` | 1 | NO | - |
| `MVM_PINNED_TARGET` | live-read | `crates/mvm-cli/src/doctor/toolchain.rs:71` | 1 | NO | - |
| `MVM_PINNED_ZIG` | live-read | `crates/mvm-cli/src/doctor/toolchain.rs:69` | 1 | NO | - |
| `MVM_PRESERVE_TRANSIENT_STATE` | live-read | `crates/mvm-cli/src/exec/transient.rs:436` | 1 | yes | - |
| `MVM_PRINT_ADDRESS_VECTORS` | live-read | `crates/mvm-core/src/plan/bundle.rs:2874` | 1 | NO | - |
| `MVM_PRODUCTION` | live-read | `crates/mvm-cli/src/commands/dashboard/mod.rs:48` | 2 | yes | - |
| `MVM_PROTECTED_WITNESS_ROOT` | test-only | `crates/mvm-client/tests/protected_capture_live_hvf.rs:41` | 0 | NO | yes |
| `MVM_PYTHON` | live-read | `crates/mvm-cli/src/commands/build/sandbox_record.rs:213` | 1 | NO | - |
| `MVM_QEMU_BRIDGE_PATH` | live-read | `crates/mvm-backends/src/driver/qemu_process.rs:464` | 1 | NO | - |
| `MVM_REGENERATE_VECTORS` | test-only | `crates/mvm-core/tests/studio_telemetry_fixtures.rs:494` | 0 | NO | - |
| `MVM_REGEN_AUDIT_CORPUS` | test-only | `crates/mvm-hostd/src/supervisor/audit_file.rs:1905` | 0 | NO | - |
| `MVM_RESIDENCY` | live-read | `crates/mvm-client/src/entrypoint/caller_registration_live_hvf.rs:206` | 5 | yes | yes |
| `MVM_RESOLVE_SUBPROCESS_BIN_TEST_UNSET_PATH` | test-only | `crates/mvm-vmm/src/host/broker_services_spawn.rs:1202` | 0 | NO | - |
| `MVM_ROOTFS_PATH` | live-read | `crates/mvm-client/src/launch/machine_start.rs:167` | 1 | NO | - |
| `MVM_RUNTIME_CONFIG` | live-read | `crates/mvm-agentd/src/bin/mvm-runner.rs:52` | 1 | NO | - |
| `MVM_RUNTIME_DISPATCH_DIR` | live-read | `crates/mvm-agentd/src/bin/mvm-runner.rs:54` | 1 | NO | - |
| `MVM_RUNTIME_OVERLAY` | live-read | `crates/mvm-agentd/src/workload_env.rs:57` | 1 | yes | - |
| `MVM_RUNTIME_OVERLAY_ACQUIRE_MODE` | live-read | `crates/mvm-build/src/artifact_acquisition.rs:42` | 6 | yes | yes |
| `MVM_RUNTIME_OVERLAY_SOURCE_ROOT` | live-read | `crates/mvm-build/src/image_source.rs:405` | 1 | NO | - |
| `MVM_SDK_MODE` | live-read | `crates/mvm-sdk/src/env.rs:96` | 1 | yes | yes |
| `MVM_SDK_MODE_ENV` | test-only | `crates/mvm-sdk/src/env.rs:133` | 0 | NO | yes |
| `MVM_SDK_OUT_PATH` | live-read | `crates/mvm-sdk/src/env.rs:104` | 1 | yes | yes |
| `MVM_SDK_OUT_PATH_ENV` | test-only | `crates/mvm-sdk/src/env.rs:138` | 0 | NO | yes |
| `MVM_SDK_RUN_PROFILE` | live-read | `crates/mvm-sdk/src/env.rs:100` | 1 | NO | yes |
| `MVM_SDK_RUN_PROFILE_ENV` | test-only | `crates/mvm-sdk/src/env.rs:135` | 0 | NO | yes |
| `MVM_SECRET_STORE_BACKEND` | live-read | `crates/mvm-client/src/entrypoint/foreground_diagnostic.rs:27` | 2 | NO | - |
| `MVM_SESSION_TAG` | test-only | `crates/mvm-agentd/src/console.rs:1024` | 0 | NO | - |
| `MVM_SIGNED` | test-only | `crates/mvm-hostd/tests/prelaunch_live.rs:83` | 0 | yes | - |
| `MVM_SIGNER_HELPER_PATH` | live-read | `crates/mvm-hostd/src/bin/mvm-host-agent.rs:186` | 3 | NO | yes |
| `MVM_SKIP_BOOTSTRAP` | test-only | `crates/mvm-cli/src/update.rs:1201` | 0 | NO | yes |
| `MVM_SKIP_BUILDER_VM_AUTO_BOOTSTRAP` | live-read | `crates/mvm-build/src/builder_vm_bootstrap.rs:35` | 1 | NO | - |
| `MVM_SKIP_COSIGN_VERIFY` | live-read | `crates/mvm-build/src/release_signature.rs:30` | 6 | yes | yes |
| `MVM_SKIP_HASH_VERIFY` | live-read | `crates/mvm-build/src/runtime_overlay.rs:891` | 4 | yes | yes |
| `MVM_SKIP_RECONCILE` | test-only | `crates/mvm-cli/src/commands/mod.rs:927` | 0 | NO | - |
| `MVM_SNAPSHOT_HMAC_STRICT` | live-read | `crates/mvm-runtime/src/base/snapshot_integrity.rs:87` | 2 | NO | - |
| `MVM_SOURCE_COMMIT` | test-only | `crates/mvm-cli/src/update.rs:701` | 0 | NO | - |
| `MVM_SOURCE_DIRTY` | test-only | `crates/mvm-cli/src/update.rs:702` | 0 | NO | - |
| `MVM_SOURCE_HELPER_BASE_URL` | live-read | `crates/mvm-cli/src/update.rs:13` | 1 | yes | - |
| `MVM_SOURCE_PATH` | set-only | `crates/mvm-agentd/src/bin/mvm-runner.rs:95` | 0 | NO | - |
| `MVM_SPAN_TIMINGS` | live-read | `crates/mvm-core/src/observability/span_timing/mod.rs:36` | 1 | yes | - |
| `MVM_SPAN_TIMINGS_FILTER` | live-read | `crates/mvm-core/src/observability/span_timing/mod.rs:40` | 1 | yes | - |
| `MVM_SPAN_TIMINGS_OUT` | live-read | `crates/mvm-core/src/observability/span_timing/mod.rs:38` | 1 | yes | - |
| `MVM_STAGE0_BUILD_ATTR` | live-read | `crates/mvm-builder-guest/src/bin/stage0-init.rs:1072` | 1 | NO | - |
| `MVM_STAGE0_CONFIG_ATTR` | live-read | `crates/mvm-builder-guest/src/bin/stage0-init.rs:1154` | 1 | NO | - |
| `MVM_STAGE0_FLAKE` | live-read | `crates/mvm-builder-guest/src/bin/stage0-init.rs:1084` | 1 | NO | - |
| `MVM_STAGE0_OUTPUT_MODE` | live-read | `crates/mvm-builder-guest/src/bin/stage0-init.rs:1076` | 1 | NO | - |
| `MVM_SUBSTITUTION_ENDPOINT_PATH` | live-read | `crates/mvm-build/src/builder_vm_transport.rs:406` | 6 | NO | yes |
| `MVM_TELEMETRY_COLLECT` | live-read | `crates/mvm-vmm/src/host/telemetry_provisioning.rs:31` | 1 | yes | - |
| `MVM_TEMPLATE_LOCAL_API_KEY` | live-read | `crates/mvm-cli/src/template_cmd.rs:356` | 2 | yes | - |
| `MVM_TEMPLATE_LOCAL_BASE_URL` | live-read | `crates/mvm-cli/src/template_cmd.rs:349` | 1 | yes | - |
| `MVM_TEMPLATE_LOCAL_MODEL` | live-read | `crates/mvm-cli/src/template_cmd.rs:352` | 2 | yes | - |
| `MVM_TEMPLATE_LOCAL_PROBE_TARGETS` | live-read | `crates/mvm-cli/src/template_cmd.rs:403` | 1 | yes | - |
| `MVM_TEMPLATE_NO_LOCAL_PROBE` | live-read | `crates/mvm-cli/src/template_cmd.rs:381` | 1 | yes | - |
| `MVM_TEMPLATE_OPENAI_BASE_URL` | live-read | `crates/mvm-cli/src/template_cmd.rs:335` | 1 | yes | - |
| `MVM_TEMPLATE_OPENAI_MODEL` | live-read | `crates/mvm-cli/src/template_cmd.rs:339` | 1 | yes | - |
| `MVM_TEMPLATE_PROVIDER` | live-read | `crates/mvm-cli/src/template_cmd.rs:301` | 1 | yes | - |
| `MVM_TEMPLATE_REGISTRY` | live-read | `crates/mvm-cli/src/template_registry.rs:173` | 1 | yes | - |
| `MVM_TEMPLATE_REGISTRY_ACCESS_KEY_ID` | live-read | `crates/mvm-runtime/src/vm/template/registry.rs:47` | 1 | yes | - |
| `MVM_TEMPLATE_REGISTRY_BUCKET` | live-read | `crates/mvm-runtime/src/vm/template/registry.rs:43` | 1 | yes | - |
| `MVM_TEMPLATE_REGISTRY_ENDPOINT` | live-read | `crates/mvm-runtime/src/vm/template/registry.rs:29` | 2 | yes | - |
| `MVM_TEMPLATE_REGISTRY_INSECURE` | live-read | `crates/mvm-runtime/src/vm/template/registry.rs:33` | 1 | NO | - |
| `MVM_TEMPLATE_REGISTRY_PREFIX` | live-read | `crates/mvm-runtime/src/vm/template/registry.rs:54` | 1 | yes | - |
| `MVM_TEMPLATE_REGISTRY_REGION` | live-read | `crates/mvm-runtime/src/vm/template/registry.rs:60` | 1 | yes | - |
| `MVM_TEMPLATE_REGISTRY_SECRET_ACCESS_KEY` | live-read | `crates/mvm-runtime/src/vm/template/registry.rs:50` | 1 | yes | - |
| `MVM_TENANT` | live-read | `crates/mvm-cli/src/commands/vm/tenant_resolution.rs:20` | 1 | yes | - |
| `MVM_TENANT_ID` | live-read | `crates/mvm-cli/src/commands/vm/volume/remote.rs:27` | 1 | yes | - |
| `MVM_TENANT_KEY_ACME` | test-only | `crates/mvm-core/src/crypto/keystore.rs:439` | 0 | NO | - |
| `MVM_TENANT_KEY_ACME_1` | test-only | `crates/mvm-runtime/src/checkpoint/custody.rs:307` | 0 | NO | - |
| `MVM_TENANT_KEY_BADLEN` | test-only | `crates/mvm-core/src/crypto/keystore.rs:469` | 0 | NO | - |
| `MVM_TENANT_KEY_FOO_BAR` | test-only | `crates/mvm-core/src/crypto/keystore.rs:460` | 0 | NO | - |
| `MVM_TENANT_KEY_LOCAL` | live-read | `crates/mvm-runtime/src/vm/snapshot_key.rs:49` | 1 | yes | - |
| `MVM_TENANT_KEY_MVM_TEST_ENV_FALLBACK` | test-only | `crates/mvm-core/src/crypto/keystore.rs:677` | 0 | NO | - |
| `MVM_TENANT_KEY_MVM_TEST_LOOKUP_BAD` | test-only | `crates/mvm-core/src/crypto/keystore.rs:725` | 0 | NO | - |
| `MVM_TENANT_KEY_MVM_TEST_LOOKUP_UNSET` | test-only | `crates/mvm-core/src/crypto/keystore.rs:706` | 0 | NO | - |
| `MVM_TENANT_KEY_NOKEY_TENANT` | test-only | `crates/mvm-runtime/src/checkpoint/custody.rs:330` | 0 | NO | - |
| `MVM_TENANT_KEY_TESTX` | test-only | `crates/mvm-core/src/crypto/keystore.rs:448` | 0 | NO | - |
| `MVM_TEST_CANONICAL_ENVIRONMENT` | test-only | `crates/mvm-client/src/portable_boot_assets.rs:459` | 0 | NO | - |
| `MVM_TEST_CANONICAL_KERNEL` | live-read | `crates/mvm-bundler/src/export/canonical_tests.rs:353` | 6 | NO | - |
| `MVM_TEST_CANONICAL_OUTPUT` | test-only | `crates/mvm-client/src/portable_boot_assets.rs:458` | 0 | NO | - |
| `MVM_TEST_CANONICAL_ROOTFS` | test-only | `crates/mvm-client/src/portable_boot_assets.rs:457` | 0 | NO | - |
| `MVM_TEST_CGROUP_DIR` | test-only | `crates/mvm-vmm/src/host/fc_cgroup.rs:323` | 0 | NO | - |
| `MVM_TEST_FIRECRACKER_INVOKED` | test-only | `crates/mvm-backends/src/fc/daemon.rs:1111` | 0 | NO | - |
| `MVM_TEST_INSTALL_DIR` | test-only | `crates/mvm-cli/src/update.rs:2597` | 0 | NO | - |
| `MVM_TEST_LOCK_WAIT_CHILD` | test-only | `crates/mvm-build/tests/image_lock_holder.rs:202` | 0 | NO | - |
| `MVM_TEST_RUNTIME_UMASK_OUTPUT` | test-only | `crates/mvm-build/src/runtime_overlay.rs:1793` | 0 | NO | - |
| `MVM_TEST_SIGNED_RUNTIME_ARCHIVE` | test-only | `crates/mvm-client/src/portable_boot_assets.rs:456` | 0 | NO | - |
| `MVM_TEST_SIGNED_RUNTIME_VERSION` | test-only | `crates/mvm-client/src/portable_boot_assets.rs:481` | 0 | NO | - |
| `MVM_TEST_SOURCED_SECRET` | test-only | `crates/mvm-cli/src/commands/ops/secret.rs:1294` | 0 | NO | - |
| `MVM_TEST_STALE_SOCKET_PATH` | test-only | `crates/mvm-vmm/src/host/network_endpoint_spawn.rs:2107` | 0 | NO | - |
| `MVM_TEST_SUDO_MARKER` | test-only | `crates/mvm-cli/src/update.rs:2596` | 0 | NO | - |
| `MVM_TEST_SUDO_PID_FILE` | test-only | `crates/mvm-backends/src/fc/daemon.rs:1112` | 0 | NO | - |
| `MVM_TEST_VAR` | test-only | `crates/mvm-agentd/tests/entrypoint_execute.rs:158` | 0 | NO | - |
| `MVM_TEST_WEB_FETCH_ALLOWLIST_DEFINITELY_NOT_SET_XYZZY` | test-only | `crates/mvm-hostd/src/supervisor/tools/web_fetch.rs:711` | 0 | NO | - |
| `MVM_TEST_WEB_FETCH_ALLOWLIST_PARSE` | test-only | `crates/mvm-hostd/src/supervisor/tools/web_fetch.rs:685` | 0 | NO | - |
| `MVM_TEST_WEB_FETCH_ALLOWLIST_TRIM` | test-only | `crates/mvm-hostd/src/supervisor/tools/web_fetch.rs:697` | 0 | NO | - |
| `MVM_TEST_WEB_SEARCH_ALLOWLIST_PARSE` | test-only | `crates/mvm-hostd/src/supervisor/tools/web_search.rs:1448` | 0 | NO | - |
| `MVM_TEST_WEB_SEARCH_DEFINITELY_NOT_SET_PLUGH` | test-only | `crates/mvm-hostd/src/supervisor/tools/web_search.rs:1459` | 0 | NO | - |
| `MVM_TOOL_CAPABILITY_TEST_STAGE` | live-read | `crates/mvm-agentd/src/tool_helper/capability_tests.rs:8` | 1 | NO | - |
| `MVM_TOOL_CAPABILITY_TEST_STASH` | live-read | `crates/mvm-agentd/src/tool_helper/capability_tests.rs:9` | 1 | NO | - |
| `MVM_TOOL_READY_FD` | live-read | `crates/mvm-agentd/src/bin/mvm-tool-helper.rs:24` | 1 | NO | - |
| `MVM_TOOL_STAGING_DIR` | live-read | `crates/mvm-hostd/src/supervisor/tools/staging.rs:86` | 1 | NO | - |
| `MVM_TRUSTED_APFS_LIVE` | test-only | `crates/mvm-fs/src/trusted_snapshot.rs:910` | 0 | NO | - |
| `MVM_TRUSTED_ENV_PROBE` | test-only | `crates/mvm-agentd/src/trusted_env.rs:177` | 0 | NO | - |
| `MVM_TSX` | live-read | `crates/mvm-cli/src/commands/build/sandbox_record.rs:239` | 1 | yes | - |
| `MVM_TS_SDK_ROOT` | test-only | `crates/mvm-conformance/tests/steps/doc_examples.rs:1231` | 0 | NO | - |
| `MVM_TS_SDK_SRC` | test-only | `crates/mvm-conformance/tests/steps/doc_examples.rs:1127` | 0 | NO | - |
| `MVM_UNINSTALL_CHECKER` | live-read | `crates/mvm-cli/src/commands/env/uninstall.rs:42` | 1 | NO | yes |
| `MVM_UNPACK_DIRECTORY_UMASK_CHILD` | test-only | `crates/mvm-fs/src/oci/unpack/fs_ops.rs:685` | 0 | NO | - |
| `MVM_UPDATE_API_URL` | live-read | `crates/mvm-cli/src/update.rs:62` | 1 | NO | yes |
| `MVM_UPDATE_DOCS_COVERAGE` | test-only | `crates/mvm-conformance/tests/steps/doc_examples.rs:1518` | 0 | NO | yes |
| `MVM_UPDATE_DOWNLOAD_URL` | test-only | `crates/mvm-build/src/published_image_set.rs:45` | 0 | NO | yes |
| `MVM_UPDATE_MCP_TOOL_CONTRACT` | live-read | `crates/mvm-cli/src/mcp/protocol.rs:562` | 1 | NO | - |
| `MVM_VERIFY_TIMING_MEMORY_MIB` | live-read | `crates/mvm-runtime/src/checkpoint/durability_tests.rs:423` | 1 | NO | - |
| `MVM_VERIFY_TIMING_ROOTFS_MIB` | live-read | `crates/mvm-runtime/src/checkpoint/durability_tests.rs:424` | 1 | NO | - |
| `MVM_VOLUMES` | live-read | `crates/mvm-core/src/config.rs:500` | 1 | NO | - |
| `MVM_WEB_FETCH_ALLOWLIST` | live-read | `crates/mvm-hostd/src/supervisor/tools/web_fetch.rs:213` | 1 | NO | - |
| `MVM_WEB_SEARCH_ALLOWLIST` | live-read | `crates/mvm-hostd/src/supervisor/tools/web_search.rs:752` | 1 | NO | - |
| `MVM_WEB_SEARCH_DEFAULT` | live-read | `crates/mvm-hostd/src/supervisor/tools/web_search.rs:756` | 1 | NO | - |
| `MVM_WORKLOAD_KERNEL_VARIANT` | live-read | `crates/mvm-build/src/kernel_fetch.rs:255` | 1 | yes | - |
| `MVM_WORKSPACE_PATH` | set-only | `crates/mvm-build/src/image_source/build.rs:398` | 0 | NO | yes |
| `MVM_WRAPPER_CONFIG_PATH` | set-only | `crates/mvm-cli/src/commands/vm/sdk_no_vm.rs:127` | 0 | NO | yes |

Documented names with no reader anywhere (docs-only):

| Name | First doc site | Removal statement |
|---|---|---|
| `MVM_ACK_UNRESTRICTED_NETWORK` | `public/src/content/docs/guides/fleet-stream-edges.md:61` | no removal statement |
| `MVM_ASSURANCE_BOOT_CONFIG` | `public/src/content/docs/guides/assurance-runtime.md:57` | no removal statement |
| `MVM_BUILDER_AGENT_BIN` | `public/src/content/docs/reference/cli-commands.md:2835` | no removal statement |
| `MVM_DEV_FLAKE_URL` | `public/src/content/docs/reference/cli-commands.md:2833` | no removal statement |
| `MVM_EGRESS_BENCH` | `public/src/content/docs/guides/networking.md:201` | no removal statement |
| `MVM_FC_ASSET_BASE` | `public/src/content/docs/reference/cli-commands.md:2796` | no removal statement |
| `MVM_FC_ASSET_KERNEL` | `public/src/content/docs/reference/cli-commands.md:2798` | no removal statement |
| `MVM_FC_ASSET_ROOTFS` | `public/src/content/docs/reference/cli-commands.md:2797` | no removal statement |
| `MVM_RUNTIME_ARCH` | `public/src/content/docs/guides/assurance-runtime.md:64` | no removal statement |
| `MVM_RUNTIME_ARCHIVE` | `public/src/content/docs/guides/assurance-runtime.md:58` | no removal statement |
| `MVM_RUNTIME_CHECKSUM` | `public/src/content/docs/guides/assurance-runtime.md:58` | no removal statement |
| `MVM_RUNTIME_INITRAMFS` | `public/src/content/docs/guides/assurance-runtime.md:60` | no removal statement |
| `MVM_RUNTIME_ROOT_HASH` | `public/src/content/docs/guides/assurance-runtime.md:62` | no removal statement |
| `MVM_RUNTIME_SIGNATURE_BUNDLE` | `public/src/content/docs/guides/assurance-runtime.md:58` | no removal statement |
| `MVM_RUNTIME_VERITY` | `public/src/content/docs/guides/assurance-runtime.md:60` | no removal statement |
| `MVM_RUNTIME_VERSION` | `public/src/content/docs/guides/assurance-runtime.md:63` | no removal statement |
| `MVM_SRC` | `public/src/content/docs/reference/cli-commands.md:2834` | no removal statement |
| `MVM_STUDIO_BACKEND` | `public/src/content/docs/sdk/rust.md:146` | no removal statement |
| `MVM_TOKEN` | `public/src/content/docs/sdk/rust.md:136` | no removal statement |
<!-- env:end -->

### 3.5 Backend x platform x feature combinations

Selectors come from `BACKEND_DESCRIPTORS` in `crates/mvm-runtime/src/catalog.rs` (selector, aliases, tier); the platform column is `public/src/content/docs/reference/platform-support.md` plus CLAUDE.md's builder section. Eight `BackendKind`s exist (`crates/mvm-contract/src/protocol/vm_backend.rs:1276`).

| `--hypervisor` selector (alias) | Tier | Workload host | Builder role | Auto-detected? | Cargo gate |
|---|---|---|---|---|---|
| `firecracker` | 1 | Linux with `/dev/kvm`, x86_64 and aarch64 | default builder on Linux+KVM; persistent builder refuses it | yes (workload default) | none |
| `hvf` (`hypervisor`) | 2 | macOS 26+ Apple Silicon | default builder on Apple Silicon macOS | yes on macOS 26+ | `hvf-live-validation` for the live lane only |
| `libkrun` (`krun`) | 2 | macOS 13-25 Apple Silicon (preview); builds on Linux/KVM only via explicit `--builder libkrun` | explicit only, never auto-detected, never a fallback | no | `libkrun-sys`, `libkrun-live`, `builder-libkrun` (default in `mvm-build`) |
| `qemu` | 2 | any host; Linux without `/dev/kvm` runs TCG | auto-detect answer for every host that is neither Apple Silicon nor Linux+KVM | no | none |
| `apple-container` (`container`) | 2 | macOS Apple Silicon, HVF runner with Apple's container kernel | none | never (opt-in) | none |
| `wasm` | 3 | host `wasmtime`, claim-free, no guest network | none | never | `wasm-backend` |
| `web-linux` | 3 | browser (QEMU-Wasm), claim-free | none | never | none |
| `mock` | 3 | tests; refused outside `test-support` builds (`AnyBackend::require_hypervisor_selectable`, `crates/mvm-runtime/src/backend.rs:395`) | none | no | `test-support` |

Builder selector (`--builder` / `MVM_BUILDER_BACKEND`): `hvf`, `firecracker`, `libkrun`, `qemu`; `builder_attempt_order` (`crates/mvm-build/src/builder_backend_select.rs:558`) returns one element, so there is no fallback. `docker` is refused outright (`backend.rs:396`).

Host/architecture lanes CI actually builds or smokes (from `strategy.matrix` in `.github/workflows`, parsed with PyYAML; re-derive with the one-liner in §4):

| Workflow job | Lanes |
|---|---|
| `release.yml` `build` | `aarch64-apple-darwin` (macos-latest); `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu` (both ubuntu-24.04; the x86_64 one builds the musl target) |
| `first-run-smoke.yml` | macOS+HVF (self-hosted M1), Linux+Firecracker (ubuntu-24.04) |
| `ci-main.yml` `test-musl-confinement` | `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl` |
| `homebrew-smoke.yml` | ubuntu-latest, ubuntu-24.04-arm, macos-26 |
| `distro-packages.yml`, `installer-compat.yml` `distro` | debian:stable, ubuntu:24.04, fedora:latest, rockylinux:9, each x86_64 and aarch64 |
| `e2e-docs.yml` | Linux/Firecracker 2 shards; macOS 2 shards |
| `publish-npm.yml`, `publish-pypi.yml`, `sdk-registry-smoke.yml` (SDK hostlib) | darwin-arm64, linux x64/arm64 gnu, linux x64 musl (npm) |

Not covered by any matrix row: libkrun, QEMU, `apple-container`, `web-linux` and `wasm` as workload backends have no per-backend platform lane here; they run inside the generic workspace shards or feature-gated tests. Whether that is deliberate is not decided in this document.

Cargo features: 90 non-default features across 17 of the 32 packages (`cargo metadata --no-deps --format-version 1 --offline`). Defaults: `mvm-contract` -> `protocol`; `mvm-build` -> `builder-libkrun`; `mvm-client` -> `manifest-verify`; `mvmctl` -> `mvm-cli/manifest-verify`. The root `mvmctl` package re-exposes `attestation-tpm2 dev embed-host-bins host hostd-transport hvf-live-validation libkrun-live libkrun-sys native-caller-identity release-artifact-bootstrap release-channel template-registry-s3 test-support trusted-apfs user`. Feature-conditional behaviour that changes a supported combination: `embed-host-bins` (release/CI builds always on), `manifest-verify` (without it self-update and image verification cannot run), `release-channel`, `contributor-bootstrap` (source-checkout bootstrap), `trusted-apfs`, `custom-dns`, `ebpf-telemetry`, `network-perf`.

### 3.6 Live compatibility layers

| Layer | What is still accepted | Reader | Retirement condition |
|---|---|---|---|
| Builder boot ABI 0 / 1 / 2 | `BuilderBootAbi::{LEGACY=0, PAYLOAD=1, NO_MVM_BINARY=2}` (`crates/mvm-core/src/image_set/boot_abi.rs:38-44`). With a boot payload source registered the range is 0..=2 (`WITH_PAYLOAD`, `:78`); without one only 0 (`LEGACY_ONLY`, `:71`) (`crates/mvm-builder-guest/src/builder_boot/abi.rs:15-23`). `images.lock` pins ABI 1. | `supported_image_abis`, `crates/mvm-build/src/builder_boot/stage.rs:45` | published builder image declares ABI 2 (mvm-images change, CLAUDE.md) |
| Image-set retired roles | `ImageSetRole::RetiredGuestRuntime` (`crates/mvm-core/src/image_set.rs:446`): overlay, `{"sdk_sidecar": libc}`, initramfs members parsed, never selected or fetched; also skipped at `crates/mvm-bundler/tests/boot_assets.rs:290` | image-set parser | mvm-images drops the `mvm` input |
| Portable `.mvmpkg` boot assets | `BOOT_ASSET_OVERLAY_ROLE`, `BOOT_ASSET_INITRAMFS_ROLE` (`crates/mvm-core/src/plan/bundle.rs:995,1000`), the one remaining reader of overlay/initramfs members | bundle export | replacement decided in #3928 |
| Base-image contract 0 / 1 | `BaseImageContractRange::SUPPORTED` = `LEGACY(0)..=LINUX_LAYER(1)` (`crates/mvm-core/src/image_set/base_contract.rs:78`); a set declaring none is read as 0 by `base_image_contract_or_legacy` (`crates/mvm-core/src/image_set.rs:299`); marker `/etc/mvm/base-image-contract` (`base_contract.rs:38`) | image-set acquisition | mvm-images declares a contract (tinylabscom/mvm-images#64), then 0 can be dropped |
| `builder_boot_abi_or_legacy` | a set with no declared ABI is read as 0 (`crates/mvm-core/src/image_set.rs:318`) | same | same as ABI 0 |
| `[legacy]` section in `images.lock` | `boot-image/v0.1.5` pin | `crates/mvm-core/images.lock` | not analysed here |
| `--hypervisor` aliases | retained: `container` -> apple-container (named in CLAUDE.md and `reference/architecture.md`). Intentionally removed: `krun` and `hypervisor` (only the catalog tests named them). `AnyBackend::require_hypervisor_selectable` now refuses any name the catalog does not recognise, so a typo no longer runs Firecracker; `from_hypervisor` keeps its default only for internal callers that pass a vetted name | `require_hypervisor_selectable` at every CLI entry point | n/a |
| `MVM_BUILDER_BACKEND` retired names (retained) | unknown values warn and fall through to auto-detect. Kept: CLAUDE.md documents it as the selection contract and `builder_backend_select.rs` tests pin it; refusing instead is a behaviour change that needs its own decision | `builder_backend_select.rs` | a decision to refuse unknown names |
| Subcommand aliases | `list` (agent-session, manifest), `show`, `delete` (manifest), `new`/`ls`/`rm` (network), `ls`/`rm` (trust), `status` (caller identity), `ls` (machine ps), `console`, `checkpoint` (volume snapshot), `app`, `volume` (exec), `--debug` for `-v`. Found by `rg 'alias *= *"\|visible_alias' crates/mvm-cli/src`; the `--help` tree in §3.3a prints visible ones | clap | none stated |
| Hidden verbs and flags (retained, not yet proven unreachable) | 34 `hide = true` sites. Internal re-exec verbs (`__builder-*`, `__qemu-vsock-bridge`, `__sdk-no-vm`) are spawned by mvmctl itself and are required; the `vm/group.rs` hidden verbs are classified dispatchable by `commands/tests.rs:584`. Each remaining one needs a per-verb caller proof before deletion | clap | per-verb proof |


## 4. Reproduce

`git rev-parse HEAD` = `9168754adca89a00dbaf4bee109bd1966b2081bf` for §3.3a-§3.6 (§1-§3.3 were measured at `152ed1cebf1009da677f2298fab8209a49ffe671`). `python3 scripts/gen-cli-surface-inventory.py --bin target/debug/mvmctl --check` fails when §3.3a or §3.4 drifts (`--env-only` skips the binary). Other commands: `cargo metadata --no-deps --format-version 1 --offline`; the `rg` commands above; matrix lanes via PyYAML over `.github/workflows/*.yml` `jobs.*.strategy.matrix`; `gh issue view 4839 --json body`.
