# Plan 200 — machine UX/DX layer

**Status:** in progress — `mvmctl machine run` shipped (Workstream A/B kickoff);
persistent verbs (`create/start/exec/shell/stop`), `--net`/`--allow-host`, local
image sources, `mvm.toml` schema v2, SDK parity, and `pack` pending
**Owner:** mvm
**Date:** 2026-06-15

## Goal

Add a first-class `mvmctl machine` command group that makes the common
microVM workflows obvious without weakening mvm's security, admission,
audit, or builder-VM guarantees.

The install and first-run bar is part of the goal:

- A user installs `mvmctl` with the existing one-line binary installer or a
  release archive. **Host Nix is never required** for normal use.
- Running an OCI image must not require a project flake, manifest, dev shell, or
  host Nix install.
- Linux build/eval work stays inside the builder VM when it is needed, but the
  image-backed `machine run --image ...` path should avoid Nix entirely.

The desired happy paths are:

```bash
mvmctl machine run --image alpine -- sh -c "echo 'hello from a microVM' && uname -a"
mvmctl machine run --net --image alpine -- nslookup example.com
mvmctl machine run --net --image alpine --allow-host registry.npmjs.org -- \
  wget -q -O /dev/null https://registry.npmjs.org

mvmctl machine create --net --name myvm --image alpine
mvmctl machine start --name myvm
mvmctl machine exec --name myvm -- apk add sl
mvmctl machine shell --name myvm
mvmctl machine stop --name myvm
```

This is a UX layer over mvm's existing primitives, not a parallel runtime
stack.

## Reference review

The external README linked in the request has a notably strong DX because it
keeps the object model small:

- `machine run` is the default ephemeral path: boot, execute, tear down.
- `machine create/start/exec/stop` is the persistent path: named state survives
  restarts.
- OCI images are the first examples; users do not need to learn manifests or
  flakes before running one command.
- Network is off by default and enabled by a single `--net` flag.
- Narrow egress is a simple `--allow-host` list, not a policy-file ceremony.
- Interactive shells are a flag or subcommand, not a separate conceptual mode.
- SSH-agent forwarding is explicit and promises host keys never enter the guest.
- A small TOML file can declare image, network, volumes, init, and auth for
  repeatable dev machines.
- Install is a binary/tool installer, not "install Nix, enter a shell, then run
  the tool."
- Portable artifacts are presented as a user-facing product, not only an
  internal archive format.
- The README claims a clear latency number. mvm needs an equally clear measured
  target, but the target must distinguish hot VM start from first image pull or
  build.

The lesson is not to copy names or implementation details. The lesson is to
offer one memorable path for beginners while preserving the deeper surfaces for
advanced users.

## What to adopt

Adopt these product patterns:

- Lead with a binary-installed CLI and an image-backed one-shot command. A new
  user should be able to install `mvmctl`, run an OCI image, and see output
  without learning flakes, manifests, dev shells, or host Nix.
- Treat persistent named machines as the second concept, not a separate product:
  `run` is ephemeral, while `create/start/exec/shell/stop` owns retained state.
- Make networking easy but explicit. `--net` is the dev-friendly opt-in;
  `--allow-host` narrows egress without requiring a policy file for the common
  case.
- Present portable artifacts as a first-class delivery unit: signed, verified,
  runnable elsewhere, and usable without host Nix.
- Keep the install story short. Optional Nix remains available, but the public
  beginner path should be release binary -> `mvmctl machine run`.
- State latency claims only after measurement and with phase boundaries. The
  credible public claim is hot cached execution, not first image pull or build.

Do not adopt these patterns:

- Do not make source-checkout Nix packages fetch project release binaries. A
  checkout build must use the checkout source and committed lockfiles.
- Do not hide native VMM linkage behind a default host package. FFI/native
  linkage stays explicit and opt-in.
- Do not reduce crate count by merging across real isolation boundaries. The
  target is fewer user-facing concepts and cleaner ownership, not a smaller
  number on its own.
- Do not let a portable artifact become a self-executing bypass around
  admission, audit, signature checks, or policy verification.

## Session synthesis

This plan captures the full set of lessons from the reference review and the
follow-up design discussion:

- **Nix templates are a maintainer/build tool, not a user prerequisite.** Keep
  Nix useful for reproducible source builds, native package recipes, and CI
  evaluation, but the beginner path remains release binary -> `mvmctl machine
  run`. Source-checkout Nix builds use checkout source; they must not download
  this project's release binaries.
- **Small surface beats small implementation count.** The user should see one
  beginner command group and one small machine file. Internally, mvm may keep
  separate crates where they preserve security boundaries, backend isolation, or
  testability.
- **The default runtime path must be lean.** `mvmctl machine run --image ...`
  should not pull builder/dev/backend extras into the normal binary unless the
  feature is actually needed.
- **macOS keeps the managed virtualization backend as the default.** The lower
  level hypervisor API requires a VMM to supply devices, boot flow, networking,
  vsock, ballooning, and lifecycle. The managed framework gives mvm a safer
  default device/lifecycle model on macOS, even if it exposes less low-level
  control.
- **Custom kernel support should be captured as a signed runtime capsule.** mvm
  already has direct-boot kernel paths and signed portable artifact primitives.
  The product shape should be "this artifact carries a verified kernel/rootfs
  payload" rather than a separate firmware brand or an unverified host-side
  download.
- **Portable artifacts are product surface.** Users should understand how to
  create, verify, transfer, run, inspect, and clean them up without knowing the
  registry/cache internals.
- **Local image inputs are a DX and resilience feature.** The beginner path
  should handle registry image refs, local OCI archives, stdin image streams,
  and already-unpacked rootfs directories without requiring a daemon at launch
  time. Every input shape still goes through the same extraction hardening,
  provenance recording, and admission path.
- **Docs are part of the product surface.** The getting-started flow should
  lead with "use this for" scenarios — sandbox untrusted code, run a command in
  an OCI image, pack a portable artifact, use a local image archive, create a
  persistent dev machine, forward an SSH agent, and declare the same workflow in
  `mvm.toml` — before architecture or flake details.
- **Known limitations should be explicit.** Network protocol scope, volume
  constraints, SSH-agent prerequisites, macOS signing/entitlement requirements,
  GPU availability, and backend/architecture constraints should appear in the
  machine docs so users do not infer stronger guarantees than we have measured.
- **Latency claims need measured phase boundaries.** A <200 ms claim is only
  credible for hot cached paths after image materialization and policy inputs
  are already available. First pull/build is a different product message.
- **Security properties remain visible, not implicit.** Network, auth, volumes,
  artifact verification, dev-only hooks, and source provenance all appear in
  admission/audit/receipts.
- **Embeddable SDKs should mirror the CLI.** Python, TypeScript, and Rust
  should expose the same machine vocabulary and structured errors instead of
  reimplementing pull, launch, verification, or policy logic.

## Session-learning checklist

These are the durable conclusions from the full review thread. They are marked
complete because they are planning decisions captured here, not implementation
completion.

- [x] UX should lead with `mvmctl machine run --image ... -- <cmd>` and named
      persistent machines, not flakes or manifests.
- [x] Normal users must not need host Nix. Optional Nix stays for source builds,
      package recipes, templates, and CI evaluation.
- [x] Nix package recipes should build from checkout source and lockfiles; they
      must not fetch this project's release binaries.
- [x] The schema direction is `mvm.toml` schema v2: `image` means OCI-backed
      machine, `flake` means existing flake-backed build flow, and both are
      mutually exclusive until explicit composition exists.
- [x] Unknown TOML keys are rejected so typos cannot silently widen network,
      auth, volume, or dev-init behavior.
- [x] Network remains default-deny. `net = true` / `--net` is dev-tier egress,
      and `allow_hosts` / `--allow-host` narrows it.
- [x] SSH-agent support forwards only an agent socket; private key files are
      never copied or mounted into guests.
- [x] Dev init hooks are dev-only. Sealed/prod machines reject them unless a
      future signed build-time equivalent is designed and audited.
- [x] Volumes default read-only; writable mounts require explicit `:rw`.
- [x] Effective network, auth, and volume policy must appear in admission,
      audit, dry-run, and receipts.
- [x] Portable artifacts verify before extract/launch and still go through
      admission; they are not self-executing bypass blobs.
- [x] Portable artifacts should be product surface: create, verify, transfer,
      run, inspect, and clean up.
- [x] Local image inputs should be supported as first-class sources: registry
      refs, local OCI archives, stdin archive streams, and unpacked rootfs
      directories, all behind the same hardened extraction and admission path.
- [x] Beginner docs should be scenario-led: untrusted-code sandboxing,
      image-backed one-shot run, portable artifact, local image archive,
      persistent dev machine, SSH-agent forwarding, and `mvm.toml`.
- [x] Known limitations should be documented beside the happy path so docs do
      not imply unmeasured support for ICMP, arbitrary volume shapes, GPU,
      signing/entitlement behavior, or unsupported host/guest architecture
      combinations.
- [x] Hot-start latency claims must be measured by phase and scoped to cached
      image/artifact paths, not first pull/build.
- [x] Elastic memory should be explained as `mem` cap plus `mem_initial`
      initial host commitment.
- [x] GPU stays out of the default beginner surface until it has explicit
      capability, admission, and audit semantics.
- [x] The managed macOS virtualization backend remains the safer default
      because the lower-level hypervisor API needs an external VMM for devices,
      boot, networking, vsock, ballooning, and lifecycle.
- [x] Custom kernels should be captured as signed runtime/artifact payloads,
      using existing direct-boot and packed-artifact primitives where possible.
- [x] SDKs are real embeddable surfaces and should mirror the machine CLI
      vocabulary instead of reimplementing runtime, pull, verification, or
      policy logic.
- [x] Dependency weight is a DX/security goal measured primarily by default
      binary closure, not raw crate count.
- [x] Crate consolidation must not merge across real security, backend, or test
      isolation boundaries just to reduce a number.
- [x] The default binary should keep builder/dev/backend/native extras behind
      features or sidecars where practical.
- [x] Security dependencies that enforce signing, verification, TLS, hashing,
      zeroization, secrecy, or artifact integrity stay unless replaced by an
      equally strong design.

## Priority and de-duplication map

Plans 199 and 200 are the priority product path. Older plans still own useful
primitives, but they should not create competing beginner surfaces.

| Area | Existing plan owner | Plan 199/200 ownership decision |
| --- | --- | --- |
| Install and host package shape | Plan 199 | Plan 199 is the source of truth. Optional source-built Nix packages remain for Nix users; normal install stays signed binary/package manager/one-line installer. |
| CLI beginner vocabulary | Plans 125, 159, 189 | Plan 200 owns the beginner command group: `machine run/create/start/exec/shell/stop/pack`. Do not spend priority work renaming the broader CLI tree before `machine` exists. |
| SDK lifecycle ergonomics | Plans 114, 125 | Plans 114/125 own the existing `Sandbox` surface. Plan 200 owns machine-oriented SDK wrappers that should reuse those primitives and not fork runtime logic. |
| Portable artifacts | Plans 136, 155 | Plan 200 owns the product story: `machine pack` and `machine run <artifact>`. Plan 155 remains the lower-level verify/extract/admitted-boot implementation source. Avoid two beginner-facing artifact command stories. |
| Dependency cuts | Plans 126, 156 | Plan 200 defines the default-machine-path closure goal. Plan 126 owns mechanical dependency reductions; Plan 156 owns binary-size measurement/gates unless a successor plan replaces it. Do not duplicate measurements in Plan 200. |
| VZ/macOS lifecycle polish | Plans 159, 189 | These remain backend/DX support plans. Their work should feed `machine` where user-facing lifecycle overlaps, not invent parallel beginner verbs. |
| Network/security substrate | Plans 193, 197 | These own rvproxy and workload-backend security obligations. Plan 200 consumes their guarantees and must not bypass them for UX. |
| Flake-build latency | Plan 198 | Completed input to Plan 200's performance targets. Do not redo cache work; use its phase data when shaping latency claims. |
| Crate boundaries | Plan 199, Plan 126 | Plan 199 owns workspace boundary audit; Plan 126 owns third-party closure cuts. Plan 200 only states the product requirement. |

Concrete priority rules:

- Implement `mvmctl machine` before broad CLI regrouping. Plan 125's nested CLI
  tree is not the beginner path while Plan 200 is active.
- Reuse existing `mvmctl run --image`, image cache, admission, audit, and
  backend launch paths; do not create a parallel runtime for machine UX.
- Fold public portable-artifact examples into `machine pack/run`; keep
  `artifact run` lower-level or advanced if it ships.
- Treat `machine` SDK wrappers as vocabulary alignment over the existing
  `Sandbox`/CLI/library paths, not a second SDK runtime.
- Attribute dependency reductions to Plan 126/156 or their successors. Plan 200
  should fail if the default machine path gets heavier, but it should not own
  every mechanical dependency cut.
- Keep VZ-specific save/restore/checkpoint verbs as backend capabilities. Only
  expose them through `machine` when the abstraction is backend-neutral and
  admission/audit semantics are preserved.

## Current mvm mapping

Existing pieces we should reuse:

- `mvmctl run --image <ref> -- <cmd>` already covers OCI-backed ephemeral
  command execution and emits OCI provenance.
- `mvmctl run` already has `--receipt`, `--json`, `--dry-run`, `--profile`,
  `--cpus`, `--memory`, `--timeout`, `--add-dir`, and `--env`.
- `mvmctl up --name <name>` already owns persistent named VM startup,
  admission, audit, volumes, ports, named networks, TTL, and policy bundles.
- `mvmctl down <name>` already owns stop/deregister behavior.
- `mvmctl console <name> --command <cmd>` and `mvmctl vm proc *` already provide
  running-VM command execution.
- `mvmctl image pull/ls/inspect/rm` already owns the local OCI cache.
- `mvm_core::network_policy::NetworkPolicy::default()` is deny-all, which
  matches the desired "network off unless explicit" UX.
- Python and TypeScript SDKs already ship, plus a Rust `mvm-sdk` crate. They are
  real embeddable authoring/control surfaces, but the machine-oriented APIs need
  to line up with the new CLI.
- `mvm-build::packed_artifact` already implements a signed `.mvm` portable
  artifact format with fail-closed verification properties. `mvmctl bundle`
  also has signed `.mvmpkg` export/install flows. The missing piece is a simple
  "pack/run this portable artifact" product path.
- Plan 198 measured the Firecracker VM boot leg around 70 ms on Linux/KVM after
  build work was skipped; warm end-to-end `up --flake` was 1.01 s, dominated by
  admission and config/secrets drive work rather than the VMM boot itself.
- `crates/mvm-vm-host/src/vz_objc.rs` already uses the managed macOS
  virtualization backend to direct-boot Linux kernels. This is the right place
  to preserve macOS lifecycle/device safety while still supporting custom
  runtime kernels.
- `public/src/content/docs/guides/kernels.md` and packed artifacts already give
  mvm a path to treat kernel/rootfs payloads as explicit, signed runtime inputs.

Gaps to close:

- `mvmctl run` does not expose ergonomic `--net` / `--allow-host` flags yet.
- Transient `ExecRequest` does not carry a selected `NetworkPolicy`, so
  transient network UX needs real plumbing, not just Clap aliases.
- Persistent `up` does not directly accept `--image <oci-ref>` today; persistent
  image-backed machines need a durable machine spec or direct OCI boot support.
- Running-VM exec is split across `console --command` and lower-level
  `vm proc`; users need `machine exec`.
- Docs lead with flakes, manifests, and project structure before the simplest
  image-backed "run a command" path.
- Machine docs do not yet have a scenario-led "use this for" guide that teaches
  untrusted-code sandboxing, local image use, persistent dev machines,
  SSH-agent forwarding, `mvm.toml`, and portable artifacts before internals.
- Local image inputs need product-level handling: registry reference, local OCI
  archive path, stdin archive stream, and unpacked rootfs directory.
- The docs need an explicit limitations section for machine UX: network
  protocol scope, volume constraints, SSH-agent prerequisites, macOS
  signing/entitlement requirements, GPU status, and backend/architecture
  support.
- The install story still has optional Nix material that can be misread as a
  prerequisite; beginner docs must lead with "no host Nix required."
- The existing SDKs do not yet present the same `machine` lifecycle vocabulary
  across Python, TypeScript, and Rust.
- SDKs do not yet prove that their machine wrappers reuse the same
  admission/audit/artifact verification path as the CLI instead of becoming a
  parallel launch surface.
- Portable artifacts exist at the lower layers, but users do not yet get a
  polished `machine pack` / `machine run <artifact>` path.
- Portable artifacts do not yet have an executable-feeling product loop: pack,
  verify, inspect, run, fail on tamper/wrong arch/wrong key, and clean up.
- The normal user binary still risks carrying too much build/dev/backend
  machinery. The machine UX should be paired with a default-closure budget, not
  only a nicer command parser.

## `mvm.toml` schema v2 for machine workflows

Support this as `mvm.toml` schema v2 for machine workflows, not as a day-one
replacement for the current flake/build manifest.

Rules:

- If `image = ...` exists, `mvm.toml` describes an OCI-backed machine.
- If `flake = ...` exists, `mvm.toml` describes the existing flake-backed build
  flow.
- `image` and `flake` are mutually exclusive unless a future plan deliberately
  defines that composition.
- Unknown TOML keys are rejected, not ignored.
- Existing flake-backed manifests remain valid while the machine workflow is
  added beside them.

Target shape:

```toml
schema_version = 2
image = "python:3.12-alpine"
net = false
cpus = 4
mem = "8G"
mem_initial = "512M"

[network]
allow_hosts = ["api.example.com"]

[dev]
init = ["pip install -r requirements.txt"]
volumes = ["./src:/work:rw"]

[auth]
ssh_agent = true
```

Security mapping:

- `net = false` is the default. `net = true` is dev-tier egress, and
  `[network].allow_hosts` narrows it.
- `[auth].ssh_agent = true` forwards an agent socket only. Private key files
  are never mounted or copied into the guest.
- `[dev].init` is dev-only. Sealed/prod machines reject it unless a future
  signed, audited build-time equivalent is defined.
- Volumes default read-only. `:rw` is required for writable mounts.
- The effective network/auth/volume policy appears in admission, audit, and
  receipts.
- Portable artifacts verify before extract/launch and still go through
  admission.

Product/DX mapping:

- Install/discovery should be agent-friendly: install, then immediately run
  `mvmctl --help` or `mvmctl doctor --workflow machine-run`.
- Portable artifacts should feel like a product, not a registry
  implementation detail.
- Elastic memory messaging should be explicit: `mem` is the cap, while
  `mem_initial` controls initial host commitment.
- GPU stays an explicit future capability, not default surface area.
- Keep one beginner command group:
  `machine run/create/start/exec/shell/stop/pack`.

## Performance target

mvm can target a comparable latency claim only if the claim is scoped precisely:

- **Hot VM start target:** `machine run --image <cached-image> -- true` should
  reach command execution in under 200 ms on Linux/KVM/Firecracker when the
  image rootfs and kernel are already materialized and no network pull/build is
  needed. The current measured VMM boot floor is about 70 ms; the remaining work
  is admission, drive creation, vsock readiness, and command dispatch.
- **Warm command target:** after the first command against a cached image,
  repeated `machine run --image <cached-image> -- <small-cmd>` should be tracked
  separately from VM boot. If command dispatch requires guest-agent readiness,
  the measured target must include readiness, not only hypervisor start.
- **First-run target:** first pull/unpack/materialize of an OCI image is not a
  <200 ms operation. The product should say what happened: pulled image,
  verified provenance, materialized rootfs, then cached it.
- **macOS target:** do not claim <200 ms until measured on the default macOS
  backend. Use "sub-second target" until live validation proves otherwise.

Work needed for the hot path:

- Measure `machine run --image alpine -- true` as phases: image-cache resolve,
  admission, config/secrets drive creation, backend start, vsock ready, command
  exit, teardown.
- Avoid config/secrets drive creation when the effective content is empty or
  already cached by digest.
- Prefer warm-pool/snapshot restore only when the security posture is unchanged
  and admission still binds the restored image.
- Add CI/live-bench guards that fail on regression only in hardware-backed
  jobs; keep host-unit tests structural.

## Dependency weight target

Dependency weight is a first-class DX and security goal for the machine UX. The
metric that matters most is the default binary closure, not raw crate count.
Crate count still matters when it predicts compile time, audit burden, duplicate
crypto/TLS stacks, or user-install size, but mvm should not merge crates across
real security boundaries just to lower a number.

Baseline from Plan 126:

- Default closure reduced from `407` to `347` packages.
- Lockfile reduced from `722` to `683` packages.
- The remaining biggest blocker is the duplicate OCI/TLS/native-crypto stack.

Priorities:

- **Replace or fork `oci-client`.** It currently pulls `reqwest 0.13` and
  `aws-lc-rs`, while the rest of the repo is mostly on `reqwest 0.12` plus
  `ring`. Removing that duplicate stack should cut compile time, C/CMake build
  weight, binary closure, and lockfile churn.
- **Keep dev/build/backend extras out of the normal path.** The default
  `mvmctl machine run --image ...` binary should not link builder VM internals,
  native libkrun FFI, dev-shell helpers, MCP, VZ tooling, or release/build
  helpers unless the user selected a feature or sidecar that needs them.
- **Replace heavy test-only HTTP fixtures.** Move expensive `httpmock` and
  `wiremock` usage toward tiny in-repo `tokio::net::TcpListener` fixtures where
  practical, so dev/test compile cost falls without changing runtime behavior.
- **Revisit CLI UI dependencies.** `inquire`, `indicatif`, and `colored` are
  not essential for agent-friendly UX. Prefer deterministic plain output and
  `--json` for the machine path; keep polished interactive UI behind an
  optional feature if it remains useful.
- **Freeze generated native bindings.** `libkrun-sys` should not require
  `bindgen`/libclang on normal builds. Checked-in generated bindings can keep
  bindgen on a regeneration-only path.
- **Keep security dependencies where they enforce real guarantees.** Do not cut
  `rustls`, `ring`, `ed25519-dalek`, `sha2`, `zeroize`, `secrecy`, or similar
  verification, signing, secret-handling, and artifact-integrity dependencies
  just to shrink the graph.

Target architecture:

- `mvmctl` default: small CLI, machine UX, OCI pull/run, signed artifact
  verify/run.
- Optional features: builder/dev, native libkrun, MCP, registry backends, and
  advanced verification.
- Sidecars: macOS virtualization, libkrun, Firecracker, or other host processes
  where sidecars keep native/device dependencies out of the main binary without
  weakening admission.
- CI gates: default-closure budget, duplicate-major budget, forbidden-heavy-dep
  budget, and binary-size budget.

The safe dependency posture is not "delete security machinery." It is to make
the common user path lean, push advanced/backend/build concerns behind features
or sidecars, and measure every cut.

## Command contract

### `mvmctl machine run`

Ephemeral by default. It boots a fresh VM, runs the command after `--`, then
tears down.

Required behavior:

- `--image <ref>` pulls or reuses an OCI image through the existing image cache.
- `--image <path.tar>` accepts a local OCI archive file without requiring a
  registry push/pull.
- `--image -` accepts an OCI archive from stdin for CI and agent workflows that
  already produced an image stream.
- `--image <rootfs-dir>` accepts an already-unpacked rootfs directory only after
  path traversal, symlink, ownership, architecture, and provenance rules are
  made explicit and tested.
- No `--net` means `NetworkPolicy::deny_all()`.
- `--net` means a dev-friendly outbound policy with DNS enabled.
- `--allow-host HOST[:PORT]` means allow-list egress only; `PORT` defaults to
  `443`, while DNS remains available so hostnames resolve.
- `--prod` requires digest-pinned, policy-verified OCI input; tag-based images
  remain dev-tier only.
- `--receipt`, `--json`, `--dry-run`, `--timeout`, `--cpus`, `--memory`,
  `--env`, and `--add-dir` stay available.
- `--add-dir` remains read-only by default; writable shares still require an
  explicit dev/permissive profile.

Implementation shape:

- Add `commands/machine.rs` with a `MachineCmd::Run` parser.
- Reuse `vm::exec::RunArgs` by adding missing network fields there first, then
  translate `machine run` into the same execution path.
- Add a typed `MachineImageSource` enum for registry refs, archive files, stdin
  archives, and unpacked rootfs directories. Avoid stringly typed source
  dispatch at call sites.
- Route every `MachineImageSource` through the existing OCI/rootfs hardening,
  provenance, policy admission, and receipt/audit code paths. Do not add a
  daemon-bypass or extraction shortcut for DX.
- Extend `crate::exec::ExecRequest` with a `network_policy` field.
- Thread that field into `VmStartConfig.network_policy`.
- Include the effective network policy in dry-run output and signed receipts
  as non-sensitive metadata.
- Add parser tests, dry-run tests, deny-by-default tests, and allow-list tests.
- Add source-shape tests for registry ref, local archive path, stdin archive,
  unpacked rootfs, malformed archive, traversal attempt, wrong architecture, and
  missing provenance handling.

### `mvmctl machine create/start/exec/shell/stop`

Persistent by default. `create` records intent; `start` boots; `exec` and
`shell` require the dev/accessible guest surface; `stop` powers down without
erasing state.

Required behavior:

- `create --name <name> --image <ref>` writes a durable machine spec under
  `MVM_DATA_DIR`, using existing config helpers, never raw `$HOME` paths.
- The spec records image ref, resolved digest when known, resources, network
  policy, volumes, SSH-agent setting, created-at, and last-start metadata.
- `start --name <name>` resolves the spec, verifies OCI provenance according to
  dev/prod posture, then launches through the same admission/audit path as
  `up`.
- `exec --name <name> -- <cmd>` is a friendly wrapper over the current
  guest-agent command path.
- `shell --name <name>` is a friendly wrapper over the current console path.
- `stop --name <name>` delegates to the current `down` path.
- `rm --name <name>` is explicit and separate from `stop`; it removes retained
  machine spec/state only after confirmation or `--yes`.

Implementation shape:

- Add a typed `MachineSpec` in the CLI layer or a small core module if reused by
  SDKs.
- Use builder methods for `MachineSpec` construction; avoid long positional
  constructors.
- Add serde roundtrip, unknown-field rejection, name validation, and traversal
  rejection tests.
- Reuse existing name registry and runtime metadata rather than inventing a
  second registry.
- Keep `mvmctl up` as the advanced manifest/flake path; `machine start` is the
  image/spec path.

### `mvmctl machine init`

Generate a small TOML file for repeatable local machines.

Target shape:

```toml
schema_version = 2
image = "python:3.12-alpine"
net = false
cpus = 4
mem = "8G"
mem_initial = "512M"

[network]
allow_hosts = ["api.example.com"]

[dev]
init = ["pip install -r requirements.txt"]
volumes = ["./src:/work:rw"]

[auth]
ssh_agent = true
```

Security rules:

- Generated files are examples, not trusted policy bundles.
- `net = false` is the default if omitted.
- `net = true` is dev-tier egress and `[network].allow_hosts` narrows the
  policy.
- `ssh_agent = true` only forwards an agent socket; it must never copy private
  key material into the guest.
- Volumes are read-only unless `:rw` is explicit.
- Unknown keys are rejected so typos do not silently widen behavior.
- A generated file uses either `image` or `flake`, never both, until explicit
  composition is designed.
- `[dev].init` remains dev-only and is rejected for sealed/prod machines.

### `mvmctl machine pack` / portable artifacts

Users should be able to ship one verified artifact and run it elsewhere on a
compatible host without installing Nix or rebuilding.

Required behavior:

- `machine pack --image <ref> -o app.mvm` or `machine pack <machine-name> -o
  app.mvm` produces a signed portable artifact using the existing packed
  artifact or bundle primitives.
- `machine run app.mvm -- <cmd>` verifies before extraction/boot and refuses on
  unknown manifest versions, bad signatures, hash mismatch, path traversal,
  missing verity sidecars for sealed-prod, or architecture mismatch.
- Portable artifact execution still goes through admission and audit. It must
  not become a self-executing blob that bypasses `mvmctl`.
- Artifacts are architecture-specific unless/until a multi-arch envelope is
  added.
- The artifact workflow feels executable from the user's perspective: pack,
  verify, inspect, run, transfer/copy guidance, and cleanup are all documented
  and test-covered.
- The public docs explain the difference between OCI images (distribution/base
  input), `.mvm` portable artifacts (signed runnable VM payload), and `.mvmpkg`
  bundles (publisher-signed installed package flow) if all three remain.

Implementation shape:

- Resume or merge Plan 155 into this plan's Workstream F: add
  verify-then-extract, then boot through the existing admitted launch path.
- Prefer one public artifact extension/command path. If `.mvm` and `.mvmpkg`
  both stay, document their roles and avoid two beginner-facing "portable"
  stories.
- Add artifact run tests for wrong key, tampered payload, traversal entries,
  missing verity sidecars, and architecture mismatch.
- Add docs/source tests that artifact examples do not imply host Nix is needed
  to run a verified portable artifact.

### Embeddable SDKs

mvm already has Python, TypeScript, and Rust SDK surfaces. The machine UX work
should make them feel like the CLI, not like a separate product.

Target API shape:

```python
import mvm

with mvm.Machine.run(image="alpine", net=True, command=["uname", "-a"]) as run:
    print(run.stdout)

with mvm.Machine.create(name="myvm", image="alpine", net=True) as vm:
    vm.exec(["apk", "add", "sl"])
```

```ts
import { Machine } from "@runmvm/mvm";

const result = Machine.run({ image: "alpine", net: true, command: ["uname", "-a"] });
```

Required behavior:

- SDKs shell to `mvmctl` or call the stable Rust library surface; they do not
  reimplement OCI pull, admission, networking, or artifact verification.
- SDK errors remain structured (`SandboxDevOnly`, policy refusal, image
  verification failure, timeout), not raw stderr scraping.
- SDK defaults match CLI defaults: no network, read-only volumes, explicit
  writable shares, prod digest verification, and no host Nix requirement.
- Rust `mvm-sdk` remains the stable embeddable crate for Rust hosts; Python and
  TypeScript wrap the same lifecycle semantics.
- SDK parity tests prove SDK machine wrappers and CLI machine commands produce
  equivalent admission inputs, effective policy, and receipt/audit summaries for
  the same config.
- Negative SDK tests prove wrappers cannot bypass artifact verification, network
  default-deny, unknown-key rejection, or source-selector conflict rejection.

## Security invariants

- Network stays off by default for the `machine` layer.
- `--net` and `--allow-host` must be reflected in audit/admission metadata.
- Production mode refuses tag-only OCI refs and requires the existing OCI policy
  verification path.
- No host Nix requirement is introduced. Image pulls and machine runs use the
  existing host CLI plus builder-VM boundary where Linux build/eval work is
  needed.
- The install guide and README must state plainly that host Nix is optional and
  not part of the beginner path.
- Persistent machine specs live under the existing mvm data-dir helpers and
  inherit worktree isolation through `MVM_DATA_DIR`.
- `machine exec` and `machine shell` remain dev/accessible-surface operations;
  sealed production images refuse them unless the existing explicit force path
  is used.
- SSH-agent forwarding is opt-in and must be transport/proxy based. Private key
  files are never mounted or copied.
- Portable artifact run verifies before extraction and launch, and launch still
  goes through signed admission/audit.
- Performance shortcuts are allowed only when they preserve the same
  image-digest, policy, and admission binding. A cache hit may skip redundant
  work; it may not skip verification.

## Workstreams

### A. CLI skeleton and docs-first contract

- [x] Record the adopted packaging/UX strategy: binary-first install,
      optional source-built Nix, image-backed one-shot UX, persistent named
      machines, verified portable artifacts, and no crate-count reduction across
      security boundaries.
- [x] Record the `mvm.toml` schema-v2 direction: `image` means an OCI-backed
      machine, `flake` means the existing flake-backed build flow, both are
      mutually exclusive for now, and unknown keys are rejected.
- [x] Add the current image-backed one-shot path to public quickstart and
      first-use happy-path docs before flake/manifests.
- [ ] Add `mvmctl machine --help` with `run`, `create`, `start`, `exec`,
      `shell`, `stop`, `ls`, `inspect`, and `rm` subcommands.
      (`run` shipped — `commands/machine/`; create/start/exec/shell/stop/ls/inspect/rm remain.)
- [ ] Add parser tests for every target command shown in this plan.
      (`machine run` parser + translation tests shipped; remaining verbs pending.)
- [x] Add the future `mvmctl machine run --image ...` quickstart to README and
      public docs after the command is implemented.
- [ ] Rewrite install docs so the primary path is binary install + `mvmctl
      machine run`; until then, keep binary install + `mvmctl run --image ...`
      as the documented current path and keep optional Nix clearly marked as
      optional.
- [ ] Add a scenario-led "use this for" guide before architecture internals:
      untrusted-code sandboxing, image-backed one-shot run, local image archive,
      persistent dev machine, SSH-agent forwarding, portable artifact, and
      `mvm.toml`.
- [ ] Add a machine limitations page covering network protocol scope, volume
      shapes, SSH-agent prerequisites, macOS signing/entitlement requirements,
      GPU status, and host/guest architecture support.
- [ ] Add docs/source guards that prevent beginner docs from implying host Nix,
      GPU, ICMP, or unsupported architectures are available by default.
- [ ] Keep old verbs documented as advanced/underlying surfaces, not removed.

### B. Ephemeral image runner parity

- [ ] Add `--net` and `--allow-host HOST[:PORT]` to `mvmctl run`.
- [ ] Add `MachineImageSource` support for registry refs, local OCI archive
      paths, stdin archive streams, and unpacked rootfs directories.
- [ ] Route every machine image source through hardened unpacking, source
      provenance, admission, receipts, and audit; do not add a daemon-bypass or
      extraction shortcut for DX.
- [ ] Thread transient run network policy through `ExecRequest` and
      `VmStartConfig`.
- [x] Make `mvmctl machine run` translate into `mvmctl run` internals.
- [ ] Add receipt/dry-run output for effective network posture.
- [ ] Add unit tests for deny-all, `--net`, allow-list parsing, conflict
      handling, and dry-run redaction.
- [ ] Add tests for local archive path, stdin archive, unpacked rootfs,
      malformed archive, traversal attempt, wrong architecture, and missing
      provenance handling.
- [ ] Add a Linux builder-VM/KVM smoke for `machine run --image alpine -- true`.
- [ ] Add a network smoke for `machine run --net --image alpine -- nslookup
      example.com`.

### B2. Hot-path latency target

- [ ] Add phase timing around `machine run`: cache resolve, admission, drive
      materialization, backend start, vsock ready, command exit, teardown.
- [ ] Add a hardware-gated Linux/KVM benchmark for cached
      `machine run --image alpine -- true`.
- [ ] Set the first acceptance bar at `<200 ms` for backend start to command
      dispatch when image artifacts are cached; track full command latency
      separately.
- [ ] Cache or elide empty config/secrets drives without weakening admission.
- [ ] Record macOS backend measurements before making a macOS latency claim.

### C. Persistent image-backed machines

- [ ] Add `MachineSpec` storage under the data dir with atomic writes and
      traversal-safe name handling.
- [ ] Implement `machine create --name <name> --image <ref>`.
- [ ] Implement `machine start --name <name>` through the existing admitted
      launch path.
- [ ] Implement `machine exec --name <name> -- <cmd>` through the existing
      guest-agent command path.
- [ ] Implement `machine shell --name <name>` through the existing console path.
- [ ] Implement `machine stop --name <name>` through the existing `down` path.
- [ ] Implement `machine inspect --json` and `machine ls --json`.
- [ ] Add tests for state persistence, state deletion, unknown-field rejection,
      and worktree-isolated `MVM_DATA_DIR`.

### C1. `mvm.toml` schema v2 machine specs

- [ ] Add a typed schema-v2 parser for machine workflows with strict
      unknown-key rejection.
- [ ] Enforce exactly one source selector: `image` or `flake`, never both.
- [ ] Map `net`, `[network].allow_hosts`, `[auth].ssh_agent`, `[dev].init`,
      `[dev].volumes`, `cpus`, `mem`, and `mem_initial` into the durable
      machine spec and launch request.
- [ ] Reject `[dev].init` for sealed/prod machines unless a signed, audited
      build-time equivalent is implemented in a later plan.
- [ ] Preserve read-only volume defaults and require explicit `:rw` for
      writable shares.
- [ ] Include effective network, auth, and volume policy in dry-run output,
      admission metadata, audit events, and receipts.
- [ ] Add serde roundtrip, unknown-key, image+flake conflict, no-source,
      read-only-volume-default, writable-volume-explicit, SSH-agent-no-key-file,
      and dev-init-prod-refusal tests.
- [ ] Update `guides/manifests.md`, quickstart, and CLI reference only after the
      parser and command behavior are implemented.

### C2. SDK parity

- [ ] Add Python `Machine.run/create/start/exec/shell/stop` wrappers over the
      CLI/library lifecycle.
- [ ] Add TypeScript `Machine.run/create/start/exec/shell/stop` wrappers with
      matching option names.
- [ ] Add Rust `mvm-sdk` machine lifecycle builders for embedders that do not
      want to shell out.
- [ ] Keep structured errors aligned across Python, TypeScript, and Rust.
- [ ] Add SDK tests proving no host Nix is invoked for image-backed machine
      runs.
- [ ] Add SDK/CLI parity tests proving equivalent admission inputs, effective
      policy, and receipt/audit summaries for the same machine config.
- [ ] Add SDK negative tests proving wrappers cannot bypass artifact
      verification, network default-deny, unknown-key rejection, or
      `image`/`flake` conflict rejection.

### D. Agent-safe auth and volumes

- [ ] Add `--ssh-agent` to `machine run/create` only after the transport is
      implemented as socket forwarding, not key mounting.
- [ ] Add tests proving the guest receives an agent endpoint but no private key
      file path.
- [ ] Normalize `-v/--volume HOST:GUEST[:ro|rw]` across `machine run` and
      `machine create`.
- [ ] Preserve read-only default and explicit `:rw` requirement.

### E. Polish and examples

- [ ] Add agent-friendly install/discovery docs that end with
      `mvmctl --help` or `mvmctl doctor --workflow machine-run`.
- [ ] Add examples for untrusted command, network denied, network allowed,
      persistent dev machine, and SSH-agent clone.
- [ ] Add concise first-run output that explains image pull, network posture,
      VM name, command exit, and cleanup.
- [ ] Document elastic memory clearly: `mem` is the cap, `mem_initial` is the
      initial host commitment.
- [ ] Keep GPU out of the beginner surface until it has an explicit capability
      model and admission/audit representation.
- [ ] Add shell completions for `machine` subcommands and flags.
- [ ] Add a migration table mapping advanced verbs to `machine` equivalents.

### F. Portable artifacts

- [ ] Decide whether `.mvm`, `.mvmpkg`, or one consolidated public artifact is
      the beginner-facing portable unit.
- [ ] Implement verify-then-extract for the selected artifact format if the
      existing primitive does not already expose it.
- [ ] Implement `mvmctl machine pack ... -o <artifact>` using source-built or
      image-backed inputs.
- [ ] Implement `mvmctl machine run <artifact> -- <cmd>` through the standard
      admission/audit path.
- [ ] Present portable artifacts as a product-level workflow: create, verify,
      transfer, run, inspect, and clean up.
- [ ] Add docs showing artifact creation, transfer, verification, run, and
      cleanup without host Nix.
- [ ] Add docs/source tests that portable artifact examples do not imply host
      Nix is required and do state host architecture/backend compatibility
      requirements.
- [ ] Add tamper, wrong-key, traversal, unknown-version, missing-verity, and
      arch-mismatch tests.

### G. Default binary closure and dependency weight

- [x] Record dependency weight as a first-class DX/security goal for the
      machine UX, with default binary closure as the main metric and raw crate
      count as secondary.
- [ ] Add a default `mvmctl` dependency/binary-size baseline for
      `machine run --image ...` and publish the measured budget in Plan 126 or
      a follow-up dependency plan.
- [ ] Replace or fork `oci-client` so the default path no longer pulls duplicate
      `reqwest`/native-crypto stacks.
- [ ] Split builder/dev/backend extras out of the normal user path behind
      features or sidecars where practical.
- [ ] Replace heavy test-only HTTP fixtures with small in-repo TCP fixtures
      where the tests do not need a full mock-server framework.
- [ ] Audit `inquire`, `indicatif`, and `colored` usage for the machine path;
      keep deterministic plain output and `--json` as the default.
- [ ] Move `libkrun-sys` bindgen/libclang usage to a regeneration-only path with
      checked-in generated bindings for normal builds.
- [ ] Add CI gates for default closure size, duplicate major versions,
      forbidden heavy deps, and binary-size regressions.
- [ ] Preserve verification, signing, secret-handling, TLS, hashing, zeroization,
      and artifact-integrity dependencies that enforce real security
      guarantees.

## Verification

- [ ] `cargo test -p mvm-cli commands::tests::machine`
- [ ] `cargo test --test nix_flake_structure` if docs/plans touch Nix install
      language.
- [ ] Default binary closure budget check for `mvmctl` with normal machine-run
      features only.
- [ ] Duplicate-major dependency budget check, including OCI/TLS stacks.
- [ ] Binary-size budget check for the default `mvmctl` artifact.
- [ ] Local image-source tests: registry ref, archive path, stdin archive,
      unpacked rootfs, malformed archive, traversal attempt, wrong
      architecture, and missing provenance.
- [ ] SDK/CLI parity and non-bypass tests: equivalent admission inputs,
      effective policy, artifact verification, unknown-key rejection,
      source-selector conflict rejection, and receipt/audit summaries.
- [ ] Docs/source guards for no-host-Nix default and explicit limitations:
      network protocol scope, volumes, SSH-agent prerequisites, macOS
      signing/entitlements, GPU status, and backend/architecture support.
- [ ] Portable artifact workflow tests/docs: pack, verify, inspect, run,
      transfer guidance, cleanup, tamper, wrong-key, wrong-arch, traversal,
      unknown-version, and missing-verity rejection.
- [ ] `cargo test --workspace`
- [ ] `cargo check --workspace`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] Builder-VM/Linux smoke: `machine run --image alpine -- true`
- [ ] Builder-VM/Linux smoke: `machine run --net --image alpine -- nslookup
      example.com`
- [ ] Hardware-gated Linux/KVM perf smoke: cached image hot start reaches the
      accepted phase target.
- [ ] SDK suites: Python, TypeScript, and Rust machine lifecycle wrappers.
- [ ] Portable artifact tamper/rejection tests.
- [ ] macOS smoke on the default supported backend for `machine run --image
      alpine -- uname -a`

## Open decisions

- Whether `machine create --image <tag>` should resolve the tag immediately and
  store a digest, or store the tag and resolve on each `start`. Safer default:
  resolve on create, store digest, and require `machine refresh` to move tags.
- Whether `--net` should mean unrestricted dev egress or a named "dev web"
  preset. Safer default: DNS plus broad outbound only in dev-tier, with
  production requiring explicit allow-hosts or policy bundles.
- Whether `machine start` should default to detached. Safer default: persistent
  machines start detached; `machine run` streams foreground output.
- Whether image+flake composition should ever be supported in `mvm.toml`. Safer
  default: schema v2 allows exactly one source selector, either `image` or
  `flake`, and rejects files that specify both until composition has a signed
  policy model.
- Whether `.mvm` and `.mvmpkg` should both remain public. Safer DX default: one
  public beginner-facing portable artifact, with any lower-level format treated
  as implementation detail.
- Whether the first public latency claim should say "hot VM start <200 ms" or
  "hot command starts in <200 ms". Safer default: claim only the narrower metric
  until command-dispatch measurements prove the broader one.
- Whether GPU belongs in the first machine UX release. Safer default: no; keep
  GPU as a future explicit capability with admission/audit representation.
- Whether dependency reduction should live entirely in Plan 126 or receive a
  dedicated follow-up for the machine path. Safer default: Plan 200 records the
  product requirement, while Plan 126 or a successor owns the mechanical cuts
  and CI budgets.
