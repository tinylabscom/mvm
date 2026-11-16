# ADR-061 — Crate layout by where code runs, with one hypervisor crate

Backing: preview
Validation: none

**Status: Accepted — 2026-11-15**

### Scope of the owner decision

The owner explicitly accepted this design, including the `mvm-crypto`
compilation-boundary exception, on 2026-11-15
([decision record](https://github.com/tinylabscom/mvm/issues/5510#issuecomment-6903558088)).
This accepts separately reviewed, behaviour-preserving prerequisite boundary
refactors before the pure-move extractions, and permits prerequisite planning.
It does not authorize implementation, a commit, push, queue or merge.

Acceptance is a design decision, not a shipped capability or additional test
evidence. The backing remains preview. The recorded source basis is
`052276763f889960b0fd16cb7d58583e6cce4ec5`; refresh it for each eventual change.

Keep wire meanings, enabled backends, process topology, key custody, admission,
refusal and cleanup behaviour unchanged. The combined signer helper remains
one process. No new admission gate, network path, fallback or security claim
follows from a crate boundary. ADR-001 remains the security-claim authority.
Issue #5510 owns work status; unfinished items remain unchecked.

## Context

The original size inventory counted 26 crates and about 1.16 million lines
of Rust, with 262 files over 1,000 lines and 67 over 2,000. Three problems
make it harder to change than its size alone explains. Cargo metadata counts 28 workspace
packages at the initial measurement, including the root package and tooling;
do not equate these counts. The later `052276763f889960b0fd16cb7d58583e6cce4ec5`
tree has 29 after adding `mvm-crypto`, addressed explicitly below.

**Hypervisor work is in three crates.** `mvm-vmm` holds the device model and
the platform-agnostic traits. `mvm-backends` holds the four backend drivers
(about 24,700 lines). The raw HVF substrate (about 8,600 lines) is in
`mvm-runtime`. And about half of `mvm-vmm` is not hypervisor work: its `host`
module is about 28,700 lines of process spawning, code signing, UI and
telemetry.

**The guest wire protocol lives in the guest daemon.** `mvm-vmm` and
`mvm-backends` refer to the vsock module of `mvm-agentd` 199 times. Anything
that talks to a guest therefore depends on the whole 75,000-line daemon, and
14 crates do.

**Names do not say where code runs.** `mvm-host-services` runs inside a guest.
`mvm-hostd` and `mvm-hostlib` run on the host. `mvm-hostd` is 166,000 lines
behind 11 binaries; its `supervisor` module is 58,000 lines, of which about
20,000 are the network endpoint, proxy and flow multiplexer.

A source review of a production macOS VM project with a much clearer layout
informed this. We take its structure and rules, not its code: a hypervisor
layer that contains only hypervisor work, a driver contract every backend
passes, written invariants per layer, and small files.

## Decision

1. **A crate exists only for one of three reasons:** it is a distinct shipped
   artifact, it is a dependency-closure boundary that a gate or a cache key
   depends on, or it is `no_std`. Anything else is a module.

   **Accepted exception for upstream `mvm-crypto`:** retain the newly landed,
   unpublished primitive crate as an independently optimized compilation
   boundary. Its purpose is to avoid optimizing all of core merely to optimize
   the concrete AES-GCM calls. Preserve the package-level profile override;
   key custody and protocol state remain with callers. This is a specific
   exception included in the owner's acceptance decision, not permission to
   create one crate per algorithm or a claim that this review measured speed.

2. **`mvm-vmm` is the one hypervisor crate.** No new crate is created. The HVF
   substrate moves in from `mvm-runtime`. `mvm-backends` folds in, each
   backend a feature-gated module. Split `host` by responsibility, not by its
   name: backend process, descriptor and control mechanisms remain below
   their callers in `mvm-vmm`; policy, service composition and presentation
   move to their owners.

3. **The common std guest-agent protocol moves to `mvm-core`.** It belongs
   under `protocol::guest_agent`, with synchronous transport and platform
   modules selected at their boundary. Guest execution stays in `mvm-agentd`.
   Move integration/probe report DTOs with their wire consumers, not their
   execution loops. A reduced `no_std` vocabulary in `mvm-contract` is a
   separate design, not a prerequisite: moving current `vsock` unchanged
   there makes `mvm-contract → mvm-core → mvm-contract`.

4. **Directories group crates by where the code runs.** Package names do not
   change in the regroup.

   ```
   crates/
     contract/  core/        foundation, including the guest wire protocol
     vmm/                    all hypervisor work
     guest/                  agentd, setpriv, host-services, builder-guest
     host/                   the mvm-hostd split
     sdk/                    sdk, hostlib, compiler, capture
     deps/                   http, fs, libkrun-sys, macho-sign
     build/  runtime/  client/  cli/
   ```

   `mvm-client` keeps its current path until `mvm-studio`, which depends on it
   by path, is updated in the same change. `mvm-hostlib` belongs under `sdk/`;
   its package name and shared-library filename do not change. Keep
   `mvm-gpu` at its current path for this regroup: one package emits a host
   endpoint and guest shared objects, so a single execution-domain label
   would conceal the mixed artifact boundary. Root facade, `xtask` and
   conformance tooling keep their current ownership.

5. **`mvm-hostd` aims to split along the processes it ships:** audit, egress,
   admission, broker, and supervisor. The measured import graph below prevents
   a direct five-crate split. The ownership map below assigns every root;
   mixed roots require the prerequisite cuts before independent crates.
   The new package names are `mvm-host-audit`, `mvm-host-egress`,
   `mvm-host-admission` and `mvm-host-broker`; supervisor retains `mvm-hostd`.
   These are accepted design names, not existing extracted packages. Existing
   binary and shared-library names do not change.

6. **Small crates fold into their owners.** `mvm-net` (582 lines) into
   `mvm_core::net`, beside its existing `session` and `telemetry` modules,
   without adding an async runtime to core's default closure. `mvm-bundler`
   becomes `mvm_core::plan::bundle::export`, gated by `host-state`; the
   caller still supplies the signer and retains signing authority.

7. **`runmvm-client` is deleted.** Nothing in the workspace depends on it and
   the known embedder uses `mvm-client`. Its publish lane and registry smoke
   test go with it.

8. **Guest binaries keep their closures.** `mvm-setpriv`, `mvm-builder-guest`
   and `mvm-host-services` stay separate crates under `guest/` wherever
   merging would widen what is compiled into a guest or change an image cache
   key.

9. **Moves do not mix with behaviour changes.** The `mvm-hostd` split first
   needs separately reviewed dependency-direction changes; the protocol
   and VMM host helpers also contain mixed ownership. Review these
   prerequisites explicitly rather than calling them file moves. Once
   the graph and ADR acceptance conditions below are met, each extraction
   is a separate pure-move PR. The claim gates stay green at each step.

10. **Extend the existing file-length gate.** `xtask check-file-size` already
    caps files at 1,500 production lines and pins six oversized files.
    Ratcheting every existing file, including smaller ones, is a tooling
    policy change, not a source move. Reuse that counter, preserve exclusions
    for tests/generated code, and carry ceilings through renames instead of
    resetting them. Each layer's invariants file records dependency direction,
    resource ownership, worker completion/cancellation and refusal behaviour,
    rather than duplicating the root agreement.

## Order

The owner has accepted the recorded cut map, conditional target/feature graph
and its bounded head reconciliation. Prerequisite planning may proceed.
Before implementing each cut, refresh the source-edge mapping and cycle check
for its actual branch, target and features. A desired DAG or successful Cargo
metadata resolution alone does not satisfy that check. Design acceptance does
not replace the separate implementation authorization or validation.

Prerequisite refactors receive separate review and behaviour-preservation
evidence. They are not silently bundled into the following move sequence.
The owner's extraction order remains:

1. Complete the approved dependency-direction prerequisites.
2. Move the wire protocol out of `mvm-agentd`.
3. Move the HVF substrate and `mvm-backends` into `mvm-vmm`; move `host` out.
4. Fold `mvm-net` and `mvm-bundler`; delete `runmvm-client`.
5. Extract audit, egress, admission, broker, then supervisor.
6. Regroup directories.
7. Add the ratchet and the per-layer invariants files.

Deletion of a published client and changes to validation policy are the
explicitly named retirement/tooling work, not pure source relocations.
Preserve the contract's publishing lane when removing the client lane.

## Ownership map

These are destination assignments, not a statement that current imports
already respect them. Descendants and unit tests travel with their root
unless a split below names a different owner. Cross-owner tests remain
integration tests; moving them must not add a production dependency.

### Guest-agent protocol

Source: `crates/mvm-agentd/src/vsock/`.

| Source | Destination |
| --- | --- |
| `activation`, `request`, `request_policy`, `response`, `response_payloads` | Future module `"mvm_core::protocol::guest_agent"`; move the referenced integration/probe report DTOs down too |
| `api`, `connection`, `framing`, `rpc` | Synchronous core guest-agent client/transport; split socket-free `api` items into portable support as specified below |
| `sys` | Core transport's Linux platform module; `connection` calls its AF_VSOCK dial primitive |
| `verb_grant` | Common verification/token helpers and the host-used key-file parser in core; guest anchor provisioning, persisted-grant loading and execution enforcement in agentd; exact split below |
| `workload_privilege` | Agentd execution boundary |
| `mod.rs` | Shared protocol constants/exports in core; guest-only exports remain agentd-owned |

Preserve version numbers, serde shape, frame bounds, authentication, grant
intersection and unsupported-platform behaviour. Keep the default core and
sealed guest closures runtime-free. Update protocol fingerprints, schema
emitters, fuzz manifests and host consumers with the eventual move.

The platform cut is explicit: `activation`, `request`, `request_policy`,
`response`, `response_payloads`, shared constants and pure grant helpers are
portable vocabulary. Put socket-dependent `api` operations, `connection`,
`framing` and `rpc` behind the core guest protocol's Unix platform-module
boundary; `sys` remains Linux-only.
Their current Unix socket imports must not enter core's Windows/Wasm build.
Move `socket2` with the Unix client and `nix`'s socket feature with the Linux
primitive, not with portable DTOs or `mvm-contract`. Neither needs Tokio.
This is not a new Windows/Wasm transport or guest-agent support claim.

| Current `vsock/api.rs` item | Core destination / predicate | Caller/export disposition |
| --- | --- | --- |
| `PostRestoreReply`, `describe_missing_reseed`, `PRIMED_MARKER_PATH`, `interpret_primed_status` | Portable guest-protocol support; no Unix predicate | Keep public guest-protocol exports; agentd re-exports downward and VMM's post-restore diagnostic re-export points to core. |
| `workload_is_primed_at` | Portable guest-protocol support; standard filesystem existence query, not a socket operation | Keep public export and exact marker semantics; this does not promise a filesystem on every target. |
| `interpret_sleep_prep`, `resource_usage_response`, `interpret_post_restore` | Portable response interpretation, visible only within the core guest-protocol implementation | Unix request helpers call these downward; move their pure tests with them, without creating new public APIs. |
| All remaining `api` functions | Unix client module, `cfg(unix)` | Preserve existing public exports under that predicate, result/error semantics and socket deadlines. |

The current item boundaries are in
[`api.rs`](../../crates/mvm-agentd/src/vsock/api.rs#L183-L248) and its
[primed helpers](../../crates/mvm-agentd/src/vsock/api.rs#L311-L339);
the diagnostic caller is [`mvm-vmm::post_restore`](../../crates/mvm-vmm/src/post_restore.rs#L13-L15).
These splits keep the core owner unchanged in the role graph while making
the symbol-availability predicates explicit.

### Hypervisor and backend code

All raw files under `mvm-runtime/src/backends/hvf/`, including the nested
kernel-boot image support, belong under `mvm-vmm`'s HVF implementation.
The designed `mvm-vmm/hvf` feature selects both the raw substrate and folded
driver, not just the driver. Do not gate the entire raw public surface to
macOS/aarch64: preserve its current internal platform predicates and
unsupported-platform refusals. Portable supervisor configuration/control
vocabulary need not inherit framework linkage.
Runtime re-exports may bridge an extraction, but must not duplicate ownership.

| Current raw surface | VMM predicate / preservation rule | Caller/export disposition |
| --- | --- | --- |
| `BootFault`, `BootProof`, `HvfError`, `MAGIC`, `boot_smoke`, `probe_available`, `ConsoleProof`, `console_smoke` | `feature = "hvf"`; no additional macOS/aarch64 gate on these exports | Runtime compatibility facade re-exports downward; non-Apple FFI failures and `probe_available() == false` remain, rather than removing Linux diagnostic entrypoints. |
| `HvfHandle`, `HvfVcpu`, `HvfVm`, `HostChannels`, `KernelBootResult`, `KernelBootUntilParams`, `KernelShutdownTiming`, `boot_kernel`, `boot_kernel_until`, `snapshot` and its existing public items | `feature = "hvf"` with existing item-internal predicates, not a blanket framework-platform gate | Preserve the exports named by the current raw module, including snapshot parsing/custody types. Supervisor, examples and conformance import VMM directly or use the runtime facade during transition. |
| `HvfDriver`, `driver::HvfDriver`, `default_bootargs`, `workload_bootargs` | Folded driver surface: `all(unix, feature = "hvf")` | Preserve driver aliases/exports for the existing Unix consumers. Runtime explicitly requests `hvf` as part of its all-four selection. |
| `DiskImage` re-export | Existing low VMM device type; its alias in the HVF facade follows `hvf` | Do not move its definition into raw HVF or make the underlying device type require the HVF feature. |
| Private `sys` FFI/assembly | Keep existing `target_os = "macos"` framework externs, `all(target_os = "macos", target_arch = "aarch64")` assembly and `not(target_os = "macos")` unsupported stubs | No new OS support, no new calls on unsupported hosts, and no connection to the empty `hvf-live-validation` marker. |

Source anchors are the [raw exports](../../crates/mvm-runtime/src/backends/hvf/mod.rs#L6-L36),
[framework declarations](../../crates/mvm-runtime/src/backends/hvf/sys.rs#L163-L165)
and [unsupported stubs](../../crates/mvm-runtime/src/backends/hvf/sys.rs#L250-L267).
Runtime's dependency selects the feature even when its own defaults are off,
so existing runtime users do not silently lose those exports. This specifies
source availability on existing consumers; it does not claim that the whole
VMM/runtime compiles or executes on Windows/Wasm.

The `mvm-backends` driver families (`fc`, `hvf`, `libkrun`, `qemu` and their
process/restore helpers), Firecracker subtree, `mock` and `run_sidecars` move
into `mvm-vmm`. Backend features must reproduce each existing consumer's
availability. The current Unix `mock` module is public without `test-support`;
silently hiding it is not a pure move. Preserve non-Unix sidecar/refusal
surfaces. Put the shared `VmmDriver` test kit with the VMM seam, not runtime.

### Feature and target preservation

Keep existing feature spellings at public facades. Forward to the implementation
owner only when code actually moves; do not broaden a feature's meaning to
enable another executable or platform. In particular, metadata feature union
is not a substitute for selecting a required-feature binary.

| Surface | Accepted design contract |
| --- | --- |
| Core defaults | Keep `default = []`. Guest protocol stays synchronous; shared host support uses the existing off-default `hostd-transport` boundary and applicable platform modules. `host-state` remains an explicit host-consumer request; folded bundle export stays behind it. |
| Protocol schema and addons | Core owns moved DTO schema derives under `schema`, continuing to forward to `mvm-contract/schema`. Keep `emit_protocol_schema` in agentd as the existing required-feature binary and `mvm-agentd/schema` as its forwarding facade. Agentd retains `addons` and its three async helper binaries; neither default core nor the sealed agent enables it. |
| VMM backend selection | Keep VMM's default feature set empty; add `fc`, `hvf`, `libkrun`, `qemu`. Root `mvmctl`, CLI and runtime, the current direct `mvm-backends` consumers, explicitly request all four when replacing each dependency in its existing target table. Preserve current Unix driver availability, public Unix mock, non-Unix `run_sidecars`, and the raw-HVF export/refusal predicates above. VMM's `libkrun` selects the optional Rust config/process dependency, not its separate FFI-linking feature. |
| Native caller identity | Admission owns `native-caller-identity` and its macOS dependencies/refusal path. Keep hostd, client, CLI and root forwarding; do not widen supported platforms. |
| Egress feature owners | Egress owns `custom-dns` and `ebpf-telemetry`, with hostd facades preserving existing selection. Resolver/Aya dependencies remain optional, and eBPF loading remains Linux-gated; they do not join core host support. |
| libkrun feature family | Preserve independent selection: root/CLI `libkrun-sys` links their dependency; hostd's feature selects its supervisor binary; build's `builder-libkrun` selects builder composition. Do not make root selection implicitly build the hostd executable. Preserve hostd's existing build-default activation in supervisor composition, not in lower extracted roles. Keep `libkrun-live` package-specific rather than treating every identically named feature as equivalent. |
| Trusted APFS | Admission owns the helper/custody surface; runtime/fs retain provider forwarding. Keep the hostd facade for its required-feature helper. Root/CLI forwarding does not currently select that helper; do not add that selection as part of extraction. |
| HVF validation marker | Preserve current root/CLI/hostd forwarding to runtime's empty `hvf-live-validation` marker. At the source pin it selects no Rust `cfg(feature = "hvf-live-validation")` implementation; do not invent a VMM gate or claim this flag alone supplies a live witness. Raw HVF platform gates remain separate. |
| Wasm backend | Keep `wasm-backend` and Wasmtime in runtime, with existing CLI/hostd forwarding and disabled-feature refusal. It is not part of the hypervisor fold. |
| Test support | VMM owns its driver test kit; runtime retains its mock-backend feature and forwards to VMM instead of backends. Preserve core/build/fs/client test-support forwarding and required-feature test targets. Do not turn dev dependencies into production edges. |

### Regroup path contract

These are the accepted final paths, not instructions to move files now.
Grouped packages keep their existing leaf names to avoid inventing new
artifact identities. The package names remain unchanged except for the
host role additions and package retirements specified above.
Quoted destination strings name the future layout, not files already present
in the workspace.

| Current package/path | Final path or disposition |
| --- | --- |
| `crates/mvm-contract`, `crates/mvm-core` | `"crates/contract"`, `"crates/core"` |
| `crates/mvm-crypto` | `"crates/crypto"`; retain the independently optimized package boundary |
| `crates/mvm-vmm`, `crates/mvm-backends` | `"crates/vmm"`; backends folds into it |
| `crates/mvm-agentd`, `crates/mvm-setpriv`, `crates/mvm-builder-guest`, `crates/mvm-host-services` | `"crates/guest/mvm-agentd"`, `"crates/guest/mvm-setpriv"`, `"crates/guest/mvm-builder-guest"`, `"crates/guest/mvm-host-services"` |
| `crates/mvm-hostd` | `"crates/host/mvm-hostd"` for supervisor; extracted roles at `"crates/host/mvm-host-audit"`, `"crates/host/mvm-host-egress"`, `"crates/host/mvm-host-admission"`, `"crates/host/mvm-host-broker"` |
| `crates/mvm-sdk`, `crates/mvm-hostlib`, `crates/mvm-compiler`, `crates/mvm-capture` | `"crates/sdk/mvm-sdk"`, `"crates/sdk/mvm-hostlib"`, `"crates/sdk/mvm-compiler"`, `"crates/sdk/mvm-capture"` |
| `crates/mvm-http`, `crates/mvm-fs` | `"crates/deps/mvm-http"`, `"crates/deps/mvm-fs"` |
| `crates/deps/libkrun-sys`, `crates/deps/mvm-macho-sign` | Unchanged |
| `crates/mvm-build`, `crates/mvm-runtime`, `crates/mvm-cli` | `"crates/build"`, `"crates/runtime"`, `"crates/cli"` |
| `crates/mvm-client`, `crates/mvm-gpu`, `crates/mvm-conformance`, root package, `xtask` | Unchanged; client relocation awaits coordinated Studio changes |
| `crates/mvm-net`, `crates/mvm-bundler` | Fold into core as specified above |
| `crates/runmvm-client` | Retire with its publish/registry-smoke lane; retain contract publication |

Nested fuzz workspaces travel with their owner, except the VMM geometry harness
at `mvm-runtime/fuzz-backend`: move it to `"crates/vmm/fuzz-backend"` and make its
VMM dependency direct rather than relying on runtime's compatibility facade.
The detached `mvm-hostd/ebpf` crate travels with the egress loader to
`"crates/host/mvm-host-egress/ebpf"`; preserve its binary name and update the
manifest-relative object lookup, build recipe and Linux CI lane together.

Update root members/exclusions, relative manifest/patch paths, generated-input
fingerprints, embedded-source/cache inputs, workflow filters/working directories,
schema/fuzz tooling, SDK packaging and publishing references atomically with
each applicable relocation. The [consumer inventory](../../xtask/data/evidence/adr-061/README.md#consumer-coverage)
names the detached manifests and existing validation entrypoints. At the source
pin, the root exclusion value `"crates/mvm-build/fuzz"` has no directory or
manifest; remove that reference during the path update, not invent a harness.

### VMM host roots

Source: the 42 declarations in `crates/mvm-vmm/src/host/mod.rs`.

| Destination | Roots |
| --- | --- |
| VMM backend support | `aux_bin` lookup/probe half, `boot_images`, `helper_contract`, `helper_exit`, `process_exit`, `process_identity`, `process_liveness`, `process_usage`, `uds_peer`, `runtime_meta` codec/store, `workload_wait`, `observability_target` PID readers |
| VMM backend-specific mechanisms | `codesign`, `fc_cgroup`, `fc_kernel`, `hvf_control_transport`, `hvf_stop`, `hvf_supervisor`, `snapshot_publish` |
| Runtime orchestration | `drive_file`, `egress_shared`, `snapshot_upper`, `broker_services_spawn`, `host_agent_spawn`, `vm_helpers`; these are launch/cleanup clients, not the service servers |
| Runtime environment implementation, consumed through existing build contracts | `linux_env` |
| Shared host-only support / build preparation | `ui` renderer/activity below all host callers; cold/rebuild consent and `aux_bin` source-build policy in build preparation |
| Audit owner | `audit_substrate` |
| Egress/service-process owner | `network_endpoint_spawn`, `gpu_endpoint_spawn` |
| Egress telemetry / shared host-state contract | `telemetry_provisioning` with egress; `telemetry_registration` record/read contract in core host-state; launch composition owns when registration occurs |
| Split caller policy from backend representation | `boot_config`, `cmdline`, `config`, `late_volumes`, `spec_map` |
| VMM channel primitive; broker protected-stream policy | `console_capture` |
| Runtime/host egress composition; VMM receives prepared tokens | `egress_bridge` |
| Host identity authority/image preparation; VMM receives an immutable prepared drive | `flowmux_identity` |
| VMM descriptor/custody mechanism; runtime restore selection | `restore_image` |
| Existing shell contract; execution adapter with its caller/backend | `shell` |

The runtime-owned spawn clients continue to speak the existing service
protocols; they do not import the broker server. This avoids
runtime → broker → runtime without inventing another transport. Egress
spawning accepts caller-prepared helper and telemetry inputs. Keep
backend-used support low; no VMM → runtime/build/hostd edge is allowed.
Source-build consent is not reporting: its call cannot be relabelled as a
VMM-local UI event to make a cycle disappear.

The endpoint PID identity is one such cut: `process_liveness` imports
`network_endpoint_spawn::EndpointPid`. Its implementation belongs with the
low process-identity primitive, not with endpoint launch orchestration.
Firecracker's `fc/control.rs::stop_vm` also calls endpoint reaping before
checking whether the VM is running. Moving teardown to a higher owner must
preserve that ordering, including a crashed VM's orphan endpoint; deleting
the call to remove an edge is not a permitted refactor.

Removal of VMM's HTTP/filesystem/agent dependencies is conditional on these
cuts and the protocol extraction. It is not implied by renaming directories.

### Host-service roots

Source: `crates/mvm-hostd/src/lib.rs`, including private and test roots.

| Owner | Roots |
| --- | --- |
| Audit | `audit`, `audit_signer`, except combined helper composition |
| Egress | `egress_broker`, `rate_limit`, `keyholder`, `vm_lifetime`, `workload_env` |
| Admission | `admission_budget`, `plan_admission`, `extension_admission`, `caller_identity`, `host_signer` |
| Broker | `broker`, `stream`, `host_agent_idle`, `host_agent_sessions`, `display`, `drive`, `health_probe` |
| Supervisor composition | `admitted_campaign_runner`, `assurance_agent_adapter`, `assurance_attestation`, `assurance_provider`, `assurance_session`, `operator_admitted_trial_booter`, `extension_controller`, `containment`, `mailbox_custody`, `mailbox_launch`, `mailbox_process`, `mailbox_service`, `prelaunch`, `run`, `session_resume`, `supervisor` |
| Shared host-only support below all roles | `blocking`, `framing`, `panic_hook`, `parent_death`, `jailer`, root `read_launch_config` |
| Split collector mechanism from launch composition | `telemetry_collector`: shared worker/sink with egress; per-backend construction and registration ownership with supervisor/runtime |
| Test-only support | `test_fixtures` |

This refines the initial keyholder grouping: the subtree implements egress
credential resolution, OAuth refresh, request signing and substitution, not
the host plan signer. Its `admission::assemble_registry` narrows the supplied
plan bindings through the existing core binding store. Keep this subtree
with its endpoint instead of inventing a second credential-custody interface
or an egress → admission package edge. Host plan signing remains admission
owned, and the plaintext credentials remain in the same endpoint process.

Use core's off-default `hostd-transport` boundary for shared async framing
and neutral clients, and an off-default host-support boundary for common
bootstrap/confinement code. Audit/egress/broker binaries must not depend
back on supervisor merely to read launch configuration or install confinement.
This is bounded shared support, not permission to move lifecycle or
service-specific policy into core. In particular, `vm_lifetime` stays with
egress: it is the endpoint keeper, uses VMM process-liveness helpers, and
is not a generic core bootstrap utility. Shared panic-hook installation
must keep its scanner dependency below all callers or receive the existing
scanner from composition; moving its supervisor-inspection import into
core unchanged would invert the graph. Jailer self-test adapters that call
the egress DNS resolver or audit file-locking code stay above those owners,
separate from the confinement primitive.

Within `supervisor/`:

| Source group | Destination |
| --- | --- |
| Audit chain/file/checkpoint/dedup/mirror/recorder/signer/transcript primitives | Audit |
| DNS/gateway/ICMP/secret event adapters | Their egress producer, consuming audit downward |
| `datapath`, `endpoint`, `inspection`, `egress` | Egress |
| Caller identity verification/replay, opaque admitted caller capability, restored-plan verification, `keystore` policy | Admission; preserve private fields and checked construction |
| Caller file/descriptor preparation, `claimed_child` timer arming, `protected_handoff` | Supervisor composition, which consumes admission and broker capture APIs downward |
| `aggregate`, `artifact`, `backend`, `lifecycle`, `state` | Supervisor composition; move lower-layer policy validators/DTOs out of the aggregate |
| `services/audit_signer_proxy` | Audit |
| `services/broker_proxy` | Broker |
| `services/config_signer`, `services/host_signer_proxy` | Admission |
| `services/frame`, `services/spawn`, `services/binary_integrity` | Shared host support, after separating service-specific adapters |
| `telemetry/ai_meter`, action enforcement, egress eBPF support | Egress |
| `telemetry/instance_sampler`, `telemetry/self_usage` | Supervisor |

`stream::redact` is a shared scanner seam used by the endpoint's telemetry
sink as well as the broker. Move that existing seam and curated-construction
restriction beside egress inspection; broker consumes it downward. Move
`stream::InputRefusal` and its reason mapping into audit event vocabulary,
and the capture seed filename into core's capture-path configuration. Do not
make audit import stream transport or copy the filename into two owners.

The executable owners are audit signer → audit; host signer and combined
signer helper → admission; network endpoint → egress; broker and host agent →
broker; mailbox, extension provider and per-VM supervisors → supervisor.
The APFS custody helper belongs to admission. Test/feature-only targets keep
their gates and binary names.

## Dependency cuts and preserved transitions

The intended direction is supervisor composition → broker/admission/egress
and runtime/build → lower audit/backend mechanisms → core → contract.
Among the new service roles, extraction requires no audit → higher-role
edge, no egress → admission/broker/supervisor implementation edge, and no
admission → broker/supervisor implementation edge. Runtime/build and VMM
must not acquire a reverse dependency through a service's launch client.

| Current edge | Prerequisite cut |
| --- | --- |
| `vsock` → core and agent-owned report DTOs | Common std protocol and report DTOs become core-owned; guest execution stays above it |
| `audit::assurance::SignerSink` → `broker::audit_client::AuditClient` | Relocate the existing audit client to its audit owner; broker consumes it downward |
| Audit emitters → supervisor audit primitives | Relocate chain/writer primitives; leave producer-specific event adapters with their producer |
| Audit emitters/inventory → stream refusal and capture-layout items | Move the existing `InputRefusal` enum/reason mapping to audit vocabulary and the seed filename to one shared layout owner |
| `audit_signer::helper` → host signer; host signer → helper client | Put the existing combined helper composition with admission; audit supplies chain APIs; the neutral helper client/protocol sits below both |
| Admission → supervisor session/mailbox/launch orchestration | Move the `AdmitAndStartParams`/`StartAdmittedParams` boot transaction, `StartedMachine` and rollback with supervisor composition; preserve private construction of `AdmittedPlan` and the same call sequence |
| Endpoint → keyholder, telemetry and stream redaction | Keep keyholder with endpoint, put AI metering and shared redaction with egress, and separate collector worker/sink from registration/composition |
| Collector → VMM telemetry registration that is moving upward | Keep passive peer/registration read contracts below worker and writer; lifecycle ownership stays above them |
| Signer-helper binary → broker listener bootstrap | Move the existing neutral `bind_host_agent_listener` helper to shared host bootstrap, not the whole broker daemon |
| Common panic/confinement support → service scanners and diagnostic adapters | Keep scanner construction and cross-service self-test adapters above the shared primitive; do not introduce core → egress/audit |
| Service spawn/frame support → service policy/errors | Keep `ProxyError` mapping and integrity-checker selection with service composition; share bounded I/O/child ownership without copying policy |
| Backend → runtime-shaped metadata, UI or service teardown | Pass prepared inputs/report structured outcomes; keep raw process/descriptor mechanisms low; preserve teardown before early returns |
| Low process liveness → endpoint PID representation | Move the existing identity type down without weakening PID-reuse checks |
| Runtime/build → moved service launch implementation | Distinguish client/launch contracts from server composition; a package move alone does not remove this edge |

These are source/API ownership changes, not behaviour-change authorizations.
Do not add a new process or transport merely to make the arrows point down.
Keep the same signer helper tenant/VM chain registration, append, host-sign
dispatch and key lifetime. Keep the single network endpoint, secret-value
location, readiness handshake, listener ownership and refusal ordering.
On launch failure, preserve audit evidence, backend rollback and session
cleanup; mailbox startup remains after its applicable admission.

For every cut, the review must identify the existing callers, moved
definitions and remaining references, including aliases/re-exports and
relative `super` imports. A root destination table does not resolve mixed
items by itself. The source-edge condition remains unsatisfied until those
cuts have an exhaustive mapping and a cycle check; the rank order above
must not be substituted for that check.

### Concrete item cuts

Paths below are relative to `crates/`. These refine the root assignments;
the named operations are design obligations, not implemented changes.

| Cut | Exact items / boundary |
| --- | --- |
| Report DTO closure | Move `IntegrationStatus`, `IntegrationHealthResult`, `IntegrationStateReport` from `mvm-agentd/src/integrations.rs`, and `ProbeResult` from `probes.rs`, to core guest protocol. Their fields close over primitives, strings, `Option`, JSON values and those DTOs. Keep serde/schema derives; integration/probe execution stays guest-owned. |
| Shared guest vocabulary outside `vsock` | Move `flowmux_drive::{GuestIngressTarget,IDENTITY_DRIVE_LABEL}`, `late_volumes::MAX_SLOTS`, `stream_input::MAX_PENDING_INPUT_BYTES`, the four `builder_agent` port constants and `encode_workload_forward_handshake` to core's corresponding guest/builder contract. Preserve the exact handshake bytes. VMM's nested transport uses that encoder; moving only the vsock directory does not remove its guest-daemon dependency. |
| Grant helpers | Core owns `verifying_key_from_hex`, `host_signer_pub_token`, `pin_verb_grant`, `re_pin_verb_grant`, `is_verb_trust_baseline`, `TrustDecision`, `trust_decision`, `parse_require_grant_cmdline`, `launch_requires_grant` and `load_host_signer_verifying_key`, with their shared constants. The last function is also called by the host runner. |
| Guest enforcement | Agentd retains `enforce_verb_grant`, `enforce_drive_grant`, `enforce_application_terminal_grant`, `program_identity_refusal`, `path_is_in_drive_roots`, anchor writing/provisioning, `load_pinned_verb_grant` and its persisted-envelope readers, and `load_verb_trust_policy`. |
| Audit substrate | Audit owns `supervisor/audit/{signer,audit_file,audit_recorder,audit_mirror,audit_checkpoint,audit_dedup,transcript_sink}`. Existing supervisor exports may re-export downward temporarily. DNS/ICMP/gateway/secret producer adapters remain egress-owned. |
| Audit clients and stream vocabulary | Move `broker/audit_client.rs` to audit; move `stream/input_gate.rs::InputRefusal` and its stable reason mapping to audit vocabulary. Move the single capture seed filename to core configuration. Keep input leases, session gates and journal implementation in broker. |
| Combined signer helper | Admission owns `audit_signer/helper.rs`, `SignerHelperConfig` and the same helper executable/process. Core transport owns `helper_client.rs` and its frame limit. Change the helper config's serde default from the audit server's private default function to the identical shared helper frame limit. Audit retains `Chain`, canonical validation and audit-category handling. |
| Admission versus boot transaction | Admission retains opaque `AdmittedPlan`, checked construction, policy/replay decisions and `MailboxLaunchPosture`. Supervisor owns `AdmitAndStartParams`, `StartAdmittedParams`, `StartedMachine`, `admit_and_start*`, `start_admitted*`, post-admission enforcement, `final_gates::run_post_admission_gates`, rollback and verb-grant-sidecar composition. Moving the caller but leaving `final_gates` in admission retains an upward edge through `use super::*`. |
| Built-pack preparation | In `plan_admission/registry_pack.rs`, admission keeps `verify_registry_pack_assets`; preparation/dispatch/freezing functions and their prepared-runtime/boot-check objects belong to the supervisor start transaction. Retain an admission-owned checked result wherever an `AdmittedPlan` exposes it, rather than exporting supervisor storage through admission. |
| Caller capability | Keep verified/consumed caller capabilities, verification and one-shot consumption in admission, with private fields and checked constructors. Broker capture consumes that API downward. Descriptor/file startup and timer/capture handoff stay supervisor-owned. Expose only the existing checked consumption/ownership methods and capture-run accessor needed across crates, as specified in the interface review below; no public authority fields. |
| Assurance registry | Move `HOST_ASSURANCE_PLANE`, `install_host_assurance_plane`, `host_assurance_plane` and `prepare_controller_proxy` from `assurance_session.rs` to broker registry ownership. Keep its existing `HostAssuranceV1Handler`, `AssuranceSessionSpec` and `DeclaredDestination` there. Campaign declaration/open/cleanup/finalization stay supervisor-owned. No new callback or transport is needed for this cut. |
| Host interactive services | Keep complete `display`, `drive` and `health_probe` APIs with broker. Splitting an authority struct from its inherent methods would create an illegal foreign inherent implementation or reopen constructor/privacy questions. Their existing signed-plan/grant checks and private fields stay together. |
| Native completion audit adapter | `audit/emitter/events.rs::emit_native_completed` consumes runtime's opaque `NativeCompletion`. Move that typed adapter upward as a free function. Move only the already-public passive `NativeCompletionEvidence` record to core; its fields are core types, strings and options. Use a purpose-specific public `AuditEmitter::append_native_completion_record(plan, evidence)` with the same workload/image checks and ordinary emission path; do not make generic `emit` public. The high completion path still requires the opaque runtime token, which retains `ConfirmedExit` and `CompletionBarrier`. The interface review below distinguishes the lower record API from completion authority and restricts production callers. No broker/IPC operation is added. |
| Shared redaction | Egress inspection owns `stream::{redact,secret_scan}`. The collector uses both, not just curated PII redaction. Core host support may own the synchronous `SecretsScanner` engine, `SecretRule`, rules and inherent methods; its `Inspector` implementation remains in egress, which owns that trait. No async-trait dependency moves into default core. |
| Common host support | Core's off-default host-support surface owns shared renderer/activity primitives, neutral bootstrap, framing and confinement primitives. Build preparation owns both `admit_cold_build`/`admit_rebuild_after_eviction` and their private `_with` implementations. Enabling host support must not silently enable it for guest consumers; check dependency closures and source/cache fingerprints. |
| Endpoint confinement diagnostics | Convert `ConfinementSelfTest::network_endpoint` into egress's future free factory named `"network_endpoint_self_test"`, returning the low generic test object. Move its private endpoint probe group with it: `confinement_covers_runtime_threads`, `spawn_and_join_a_thread`, `blocking_pool_round_trip`, `read_clock_and_entropy`, `TRUST_STORE_DIRS`, `walk_certificate_dirs`, `resolve_without_traffic`, `append_sync_and_rotate_in`, `accept_on_an_abstract_socket`. Reuse the already-public `new`, `probe`, `require` and `run` API; keep `ProbeLabel` private with the low runner. Expose audit's existing file-lock helper for the append probe. Keep the runtime-thread check mandatory. No foreign inherent implementation or new core confinement API is needed. |
| Backend metadata and wait | Keep `VmRuntimeMeta`, `StartModeKind`, their codec/store, `workload_wait` and observability PID readers low in VMM. Higher runtime code chooses when to persist/observe them. Moving these mechanically to runtime/CLI creates backedges from backend wait/status and egress telemetry. |
| Device configuration | Keep `FcDrive`/API bodies, command-line bounds, `effective_initrd`, `runtime_overlay`, `verity_enabled`, block/volume device mapping and descriptor custody low. Runtime owns `workload_device_spec`, workload/service listener selection, `workload_spec`, plan-binding construction and complete boot arguments. A restored HVF driver receives the prepared binding instead of calling `plan_binding_for`. Preserve absent versus malformed-binding refusals. |
| Console | Keep the complete bounded producer/consumer channel in VMM; the device model itself uses it. Broker/egress consume that channel downward. Protected capture policy does not move into the device model. |
| Helper preparation | Build/CLI preparation owns helper source freshness, consent, compilation and stale-helper recovery. Low lookup/contract probing does not invoke a higher build implementation. Proposed driver inputs are resolved supervisor paths for HVF/libkrun and a resolved bridge path for QEMU; service-spawn inputs likewise carry prepared helper paths. Preserve the existing library-embedder refusal and lazy preparation conditions, not a new eager build of every helper. |
| Firecracker stop | Runtime's public stop wrapper reaps the endpoint before calling the low FC stop primitive. Update the runtime/client re-export chain and checkpoint failure cleanup to the wrapper. Preserve reap-before-not-running-return and retain VM state when stop is uncertain. Renaming the low primitive is not permission to leave an operational bypass. |
| Shell execution | Backend shell adapters receive the existing core `LinuxEnv` contract rather than choosing runtime's default environment. Keep selected-backend errors, headless refusal, output routing and existing mock availability. This is an API change, not a shell implementation move alone. |
| Shared filenames/records | Core owns the host-signer key/public-key filenames, identity-drive filename and telemetry registration record/read contract. VMM, egress and runtime must not import a service launcher or CLI merely to name those values. Egress owns telemetry records-key provisioning; higher composition still owns registration decisions. |
| Prepared telemetry | Higher launch composition ensures host-agent registration and prepares the endpoint's telemetry inputs. Egress consumes those inputs without calling a broker/runtime implementation. Preserve the existing warning on daemon-registration failure, error on records-key provisioning failure, and private stdin transfer; do not serialize a secret into a new persistent artifact. |

Main changed during review: #5564 introduced `ResolvedLocal`, `VerifiedLocal`
and `AdmittedLocal` stages in `run.rs`, and
`admit_synthesized_with_verified_release` in `plan_admission.rs`.
The stages stay with supervisor composition. The latter is also a composition
adapter: it accepts `AdmitAndStartParams`, so placing it in lower admission
would reintroduce admission → supervisor through its parameter type. Keep
the checked `AdmittedPlan` constructor/decision below it; preserve the same
nonce ledger and one-use dispatch rather than rebuilding the pre-staging flow.

The protocol cut does not make every host consumer of agentd disappear.
The source inventory also finds build-side image-runtime configuration and
workload-identity provisioning, runtime netinit reports, volume-path checking,
and Wasm substitution relay. Those are separate shared-code ownership
questions, not wire-directory moves. Do not claim agentd is a dependency leaf
or guest-only library merely because VMM stops importing it.

### Interface review

The following source-based contracts resolve the three API design
questions raised by the projection. They are accepted design contracts, not
compiled interfaces or permission to begin extraction. Source
references below are against `dd2af0833eeaf1e2abd738e694dc1b463140ff25`.

**Native completion.** The supervisor-owned free function
`emit_native_completed(emitter: &AuditEmitter, plan: &ExecutionPlan,
completion: &NativeCompletion) -> anyhow::Result<()>` delegates to audit's
`append_native_completion_record(&self, plan: &ExecutionPlan,
evidence: &NativeCompletionEvidence) -> anyhow::Result<()>`. Keep
[`NativeCompletion`](../../crates/mvm-runtime/src/workload_runner/runner/cold_hvf_channel.rs#L108-L136)
in runtime with its private exit/barrier proofs. Move only the passive evidence
record, preserving `Debug, Serialize` without adding `Deserialize` or any
record-to-token conversion.

The lower method retains the [existing workload/image equality check](../../crates/mvm-hostd/src/audit/emitter/events.rs#L857-L885)
before serialization or append, the error text, event and label bytes, and
ordinary emission bookkeeping. Keep `emit` and `emit_entry` non-public outside
audit. Reusing [`emit_entry_for_evidence`](../../crates/mvm-hostd/src/audit/emitter.rs#L1118-L1173)
is not equivalent: its required/omitted receipt modes differ from ordinary
emission's best-effort receipt attempt.

This does weaken the named method's local misuse guard: trusted code holding
an emitter could submit fabricated matching observations. It does not newly
grant arbitrary signing authority to that holder, which already has the
public evidence-entry API. The lower method records observations; it cannot
promise original-owner provenance by its signature alone. Require an
architectural call-site check limiting production use to the typed supervisor
adapter. Keep guest [`host.audit.v1`](../../crates/mvm-hostd/src/broker/handlers/host_audit_v1.rs#L355-L415)
on its context-stamped `workload_audit` path, with no new completion verb or
conversion. Preserve the client's [attempt-before-append and closure ordering](../../crates/mvm-client/src/entrypoint/call.rs#L278-L354);
an ambiguous append is not grounds for a blind retry.

**Caller capability.** Move `RegisteredCaller`, `VerifiedCallerLaunch`,
`ConsumedCallerLaunch` and their validation/replay implementation together
into admission. Keep fields private, no `Clone`/`Deserialize` or raw constructor,
and retain the existing public `admit_caller`, `verify_cold_start` and immutable
`challenge` accessor. Widen only the existing
[`consume(self, vm)` and `into_owner(self, vm)`](../../crates/mvm-hostd/src/supervisor/admission/caller_registration.rs#L800-L880)
methods and `capture_run(&self)` accessor to `pub` for their cross-crate callers;
do not expose clock injection or replay-ledger mutation.

Verification still loads the canonical host public key internally, not a
caller-supplied trust root. Consumption rechecks binding/expiry, spends the
host replay ledger and exclusively writes the VM marker before returning
the consumed token. Later boot failure stays spent. Supervisor
[`prepare_startup`](../../crates/mvm-hostd/src/supervisor/admission/caller_registration.rs#L697-L733)
keeps the cold-workload-only preconditions and consumes before loading boot
inputs. Broker [`CaptureOwner`](../../crates/mvm-hostd/src/stream/protected.rs#L88-L123)
consumes ownership and rechecks time/binding before provisioning capture keys,
directories or listeners. Keep FD preflight/adoption and timer/handoff
composition above admission; do not create a later producer registration path.

**Confinement diagnostics.** Egress's free
`network_endpoint_self_test<'a>(audit_dir: &'a Path,
runtime: &'a tokio::runtime::Handle) -> ConfinementSelfTest<'a>` owns the
endpoint probe group listed above. The low
[`new`/`probe`/`require`/`run`](../../crates/mvm-hostd/src/jailer/self_test.rs#L79-L172)
methods already provide the needed API. `ProbeLabel`, its signal-reporting
state and the generic runner stay together in low host support, without
public fields or label access. Preserve all eight probe names and ordering,
the required worker-and-blocking-thread check, best-effort treatment of the
other probes, Linux gating and refusal before serving. No new process or
confinement policy is introduced. The append probe also needs audit's existing
[`flock_exclusive(&File) -> io::Result<()>`](../../crates/mvm-hostd/src/supervisor/audit/audit_file.rs#L1030-L1042)
widened from `pub(crate)` to `pub`, retaining the same blocking lock and
descriptor lifetime. This exposes an operation on a caller-owned file, not
audit keys or recorder state, and avoids duplicating the audit locking path.
The DNS probe's private resolver helper stays in the same egress crate.

Each eventual prerequisite PR must cover these contracts at its new crate
boundary, not infer them from the graph:

| Interface | Required validation |
| --- | --- |
| Native completion | Record/label compatibility; independent workload/image mismatch before effects; opaque-token compile-fail tests; only the typed production caller; receipt/append/closure failure compatibility; guest attempts remain workload data or a rejected verb. |
| Caller capability | External construction/clone/deserialization refusals; wrong key/signature/content/binding, expiry and backwards-clock cases; replay and corrupt-ledger refusals; failed setup stays spent; capture effects only after checked ownership; unchanged FD preflight and cold-only entrypoints. |
| Confinement | Same ordered probes and labels; required failure stops serving, optional errors remain reported; unchanged file-lock errors/lifetime; runtime worker and blocking-thread confinement checks on Linux. A fixture or graph result is not that live platform witness. |

## Import-graph validation

### Initial measurement

Measured at `f1bfd258bb3d71bdad2cf24039d90598f0804850` (the proposal's
head), with default features on macOS/aarch64. `cargo metadata --no-deps
--format-version=1` yields 28 workspace packages and 110 directed normal
local package-dependency edges: no package-level cycle. A production-only
lexical scan of `crates/mvm-hostd/src` (excluding binaries, tests, and
item-level inactive platform/feature code) finds 41 root modules, 262 source
files, 91 distinct directed `crate::root_module::…` edges and 242 references.
This is a target-specific source graph, not proof about all feature sets or
indirect imports; repeat it for the target and features of each actual move.

Two root-module strongly connected components (SCCs) have more than one
member:

- `audit_signer ↔ host_signer` (2 references one way, 1 back).
- `{admitted_campaign_runner, assurance_agent_adapter,
  assurance_attestation, assurance_session, audit, broker, display, drive,
  mailbox_custody, mailbox_launch, mailbox_process, mailbox_service,
  operator_admitted_trial_booter, plan_admission, run, stream, supervisor,
  telemetry_collector}`.

For the roots that the initial proposal named unambiguously, its grouping
is `audit = audit + audit_signer + host_signer`,
`admission = admission_budget + plan_admission`, `broker = broker`,
`egress = egress_broker`, and `supervisor = supervisor`. Its inter-group edges
are:

| Dependency | Files | References |
| --- | ---: | ---: |
| admission → audit | 5 | 22 |
| audit → broker | 1 | 2 |
| audit → supervisor | 11 | 17 |
| broker → audit | 2 | 2 |
| broker → egress | 1 | 1 |
| supervisor → admission | 1 | 1 |
| supervisor → audit | 7 | 14 |

`{admission, audit, broker, supervisor}` is one SCC: `audit → broker → audit`,
`audit → supervisor → audit`, and
`supervisor → admission → audit → supervisor` block independent crates built
by pure moves. This partial graph does **not** clear egress: much of its
candidate code is still under `supervisor`, and 33 root modules were not
assigned by that measurement. The ownership map above extends the proposal,
but does not turn this historical partial scan into an extraction check.

| Other proposed change | Cycle check against current package graph |
| --- | --- |
| Fold `mvm-backends` into `mvm-vmm` | Contracting these complete package nodes adds no cycle. |
| Move the HVF substrate | This is a partial-runtime extraction, not contraction of the whole runtime node; inspect the moved files and remaining callers. |
| Move `mvm-vmm::host` out | Backend consumers of helpers moved upward would introduce VMM → runtime/build/hostd cycles; apply the explicit cuts above first. |
| Move guest wire protocol to the foundation | Unchanged `vsock` in contract makes `mvm-contract → mvm-core → mvm-contract`; core ownership still needs the agent-owned DTO and transport cuts above. |
| Fold `mvm-net` into `mvm-core` | No cycle from the merge (`mvm-net → mvm-core`, not the reverse). |
| Fold `mvm-bundler` beside the bundle format | Destination is core's `plan::bundle::export`; contracting bundler into core adds no package cycle. Preserve `host-state` gating. |
| Delete `runmvm-client`; regroup directories without renaming packages | No new package dependency edge. |

### Broader package-graph measurement

At `e39660c6ecc4c7041fed2bd5faeddd4ad066447b`, the conservative union of
declared local normal/build dependencies, including optional and
target-conditional dependencies, has 28 packages and 110 edges, with no
nontrivial SCC. Contracting only backends into VMM and net/bundler into core
leaves 95 edges and no nontrivial SCC. This does not model partial-module
extraction. The later `870ac13db73047b20b7dd47280d01a57f8ca4905` changes only
the factory-edge demo script and its guide, not the inspected graph inputs.

The resolved package check used this command, substituting each target from
the table for `aarch64-apple-darwin`:

```sh
cargo metadata --offline --locked --format-version 1 --filter-platform aarch64-apple-darwin
```

For each target below, run it with default features, with
`--no-default-features`, with `--all-features`, and with
`--features host,user,release-artifact-bootstrap,release-channel,embed-host-bins`.
These were 32 successful metadata resolutions, not builds:

| Target | Default / no-default / release edges | All-features edges |
| --- | ---: | ---: |
| `aarch64-apple-darwin` | 109 | 110 |
| `x86_64-unknown-linux-gnu` | 107 | 108 |
| `aarch64-unknown-linux-gnu` | 107 | 108 |
| `x86_64-unknown-linux-musl` | 107 | 108 |
| `aarch64-unknown-linux-musl` | 107 | 108 |
| `x86_64-pc-windows-gnu` | 98 | 99 |
| `wasm32-unknown-unknown` | 98 | 99 |
| `wasm32-wasip1` | 98 | 99 |

Each current normal/build package graph and the three whole-package
contractions had no nontrivial SCC. Adding contract → core reproduced the
protocol cycle. Three additional default/no-default/all-features metadata
resolutions through `crates/mvm-contract/Cargo.toml` for
`riscv32imac-unknown-none-elf` found no local contract dependency.

Metadata applies workspace feature unification; `--no-default-features`
does not remove features requested by dependencies. It does not compile
code, resolve Rust imports, or validate an isolated guest closure. Windows
and Wasm resolution is not a claim that the whole workspace runs there.
Development edges are separate: folding them into the production graph
would conflate legal test relationships with production dependency cycles.

### Source-visible projection

The bounded follow-up at `dd2af0833eeaf1e2abd738e694dc1b463140ff25` parsed
1,261 Rust files in the nine packages named by the retained
[graph snapshot](../../xtask/data/evidence/adr-061/graph.json). It followed
module/path declarations, nested modules, aliases, wildcard imports and
source-visible references, retaining cfg predicates and separating
production from development targets. There were no parse errors or unresolved
module-file paths in that inventory. This is still syntax-based analysis,
not compiler name, trait or macro resolution.

After the item moves and explicit future call-site rewrites above, all 32
concrete production projections were acyclic. Eight additional target-specific
unions retained both possibilities of Cargo/CPU-feature and debug predicates;
those were acyclic too. The union of the source projection and the projected
normal/build manifests has 28 incident nodes and 122 edges, with no cycle.
Node counts are graph counts, not a claim about how many packages compile.
This was remeasured after #5564 and the rc.6 version change landed; all 40
projected source edge sets matched the earlier reviewed shape after assigning
the new staging adapter to composition.

| Target family | Source edges: default / all / feature-union | Combined edges: default / all / feature-union |
| --- | --- | --- |
| macOS/aarch64 | 60 / 61 / 61 | 120 / 122 / 122 |
| Linux, both architectures and both libc targets | 58 / 58 / 58 | 118 / 119 / 119 |
| Windows GNU and the two Wasm targets | 52 / 52 / 52 | 113 / 114 / 114 |

The retained masks preserve all 40 individual cases. Recheck the snapshot's
counts, masks and graph topology with:

```sh
python3 xtask/data/evidence/adr-061/replay.py --self-test
```

That command replays retained data; it does not re-extract source or certify a
changed checkout. The [measurement notes](../../xtask/data/evidence/adr-061/README.md)
record scope and limits. No runtime/library code was moved, no proposed Cargo
manifest was compiled, and no claim gate was waived.

Two rejected intermediate results matter. Wildcard imports exposed
`final_gates` still calling supervisor-owned enforcement. Separately, a
reporting-only rewrite incorrectly swallowed helper-build consent. The final
model moves the complete post-admission transaction and explicitly models
helper preparation above VMM instead; it does not erase either call.

**Graph evidence and owner acceptance are separate.** The interface review above
supplies concrete contracts for native completion, opaque caller
capabilities and confinement diagnostics; it does not compiler-validate them.
The feature/platform and consumer reviews supply preservation contracts, and
the [28 package-selected resolutions](../../xtask/data/evidence/adr-061/closure-baseline.json)
record current guest/default closure evidence, not future-build results.
The protocol/HVF item-predicate refinements remain within the existing core
and VMM owners and add no local dependency direction; the retained graph was
not regenerated as symbol-availability or compiler proof. The owner accepted
the complete design in the decision recorded above. Compiler,
claim-gate and behaviour evidence belongs to each eventual prerequisite or
extraction. The JSON snapshots retain their historical Proposed/false fields:
they record evidence captured before acceptance, not the current ADR status.

### Bounded head reconciliation

The final drift check found three upstream commits through
`052276763f889960b0fd16cb7d58583e6cce4ec5`. The design branch now uses that
revision. Do not relabel the earlier source fingerprint as a fresh extraction.

Comparing every workspace manifest's declared local normal/build edges adds
one package and one edge: `mvm-core → mvm-crypto`; none are removed. The
new crate wraps the existing AES-GCM dependency, with no local dependency
back to core. The runner split's start/standby/claim and broker registration
items remain runtime-owned. The existing egress/host-agent spawn-client cuts
therefore retain their direction despite their new caller file locations.
BDD's Cucumber dependency is now optional under `bdd`; its explicit
required-feature validation remains necessary.

The [retained delta](../../xtask/data/evidence/adr-061/head-reconciliation.json)
adds the crypto leaf to all 40 prior projected cases. Their composed union
is acyclic with 29 incident nodes and 123 edges. This is bounded
manifest/source-diff reconciliation, not another full source scan or a
compiler proof. All 28 package-selected closure cases were rerun on this
head: closures through core gain the crypto package, while their checked
default forbidden-dependency sets remain empty.

Upstream also suspended `check-rust-footprint` enforcement while #4839
cleanup proceeds. Its successful measurement is not an enforced ratchet.
The file-length work remains separate tooling policy; this review
neither restores that gate nor waives any claim or lifecycle gate.

### Evidence required for implementation

Refresh the conditional source mapping and preserve the following coverage in
each prerequisite and eventual extraction, not only a default
macOS library build:

- Preserve Linux-only confinement, eBPF telemetry and musl/gnu code paths.
- Include native caller identity, custom DNS, libkrun linkage/live targets,
  trusted APFS, HVF live validation, Wasm backend, schema, addons and
  test-support surfaces where applicable.
- Include required-feature binaries/examples, BDD, detached fuzz workspaces,
  browser consumers and the bare-metal contract target in their own scope.
- Distinguish host build scripts from target code and production edges from
  dev/test edges; account for relative imports, aliases and re-exports.
- Record a source/feature-labelled edge list and every prerequisite cut.
  Reject an unexplained edge or unassigned mixed item rather than dropping
  it from the graph. Check the projected graph per configuration; a
  conservative union with no cycles can cover its subsets, but a union
  with cycles needs configuration-specific analysis.

After each eventual source change, run the applicable compile/test matrix
and claim/closure gates. `check-all` includes claim catalog, witness
citations, single-network-path, one-guest-protocol, runtime-free and closure
checks. `--all-targets` alone skips required-feature and foreign-target
code; retain `just check::gated` and the relevant platform witnesses.
Graph checks do not replace behaviour or lifecycle evidence.

## Consequences

- Fewer redundant package boundaries, with service/artifact boundaries kept
  where they affect dependency closure or ownership.
- The intended hypervisor closure excludes HTTP, image construction and the
  guest daemon after the corresponding cuts; this is not a current result.
- Published surface shrinks to `mvm-contract`. An outside Rust embedder uses
  `mvm-client` from source until a published form is decided.
- The moves touch most import paths once. They conflict with any long-lived
  branch, so each lands small and quickly.

## Not decided

- Implementation and landing authorization for the individual changes.
- Whether to split the mixed host/guest GPU package in separate work.

Status is tracked in issue #5510.
