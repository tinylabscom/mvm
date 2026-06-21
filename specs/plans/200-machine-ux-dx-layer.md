# Plan 200 — machine UX/DX layer

**Status:** in progress — `mvmctl machine run` shipped (Workstream A/B kickoff);
`--net`/`--allow-host`, local image sources, persistent spec verbs
(`create`/`start`/`ls`/`inspect`/`rm`), and running-VM wrappers
(`exec`/`shell`/`stop`) shipped; full `mvm.toml` machine runtime mapping,
Python/TypeScript/Rust SDK machine wrappers, and dev-tier persistent-machine
ssh-agent forwarding shipped; deeper SDK/CLI parity,
scenario docs, portable artifacts, perf/smoke coverage, and
duplicate-major/binary-size budgets remain
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
- **Mutable dev state must not silently become a prod input.** Persistent dev
  machines are allowed to be mutable, but prod/sealed builds still consume only
  declared host-side inputs. Anything learned or changed inside a dev VM must
  be promoted back across the boundary explicitly as source, config, or an
  exported artifact. See [ADR-088](../adrs/088-dev-vm-promotion-boundary.md).
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
- [x] The schema direction is `mvm.toml` schema v1: `image` means OCI-backed
      machine, `flake` means existing flake-backed build flow, and both are
      mutually exclusive until explicit composition exists.
- [x] Unknown TOML keys are rejected so typos cannot silently widen network,
      auth, volume, or dev-init behavior.
- [x] Network remains default-deny. `net = true` / `--net` is dev-tier egress,
      and `allow_hosts` / `--allow-host` narrows it.
- [x] SSH-agent support forwards only an agent socket; private key files are
      never copied or mounted into guests, Nix templates cannot add SSH
      clients/servers/config/material, SSH sessions remain banned, and the
      feature is dev-tier only.
- [x] Dev init hooks are dev-only. Sealed/prod machines reject them unless a
      future signed build-time equivalent is designed and audited.
- [x] Volumes default read-only; writable mounts require explicit `:rw`.
- [x] Effective network, auth, and volume policy must appear in admission,
      audit, dry-run, and receipts.
- [x] Mutable dev-machine state never implicitly becomes a prod input. Prod
      consumes declared host-side inputs only; anything produced in a dev VM
      must be promoted back explicitly as source, config, or an exported
      artifact.
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
- Python, TypeScript, and Rust now present the same `machine` lifecycle
  vocabulary for run/create/start/exec/shell/stop host automation.
- SDKs do not yet fully prove that their machine wrappers reuse the same
  admission/audit/artifact verification path as the CLI instead of becoming a
  parallel launch surface.
- Portable artifacts exist at the lower layers, but users do not yet get a
  polished `machine pack` / `machine run <artifact>` path.
- Portable artifacts do not yet have an executable-feeling product loop: pack,
  verify, inspect, run, fail on tamper/wrong arch/wrong key, and clean up.
- The normal user binary still risks carrying too much build/dev/backend
  machinery. The machine UX should be paired with a default-closure budget, not
  only a nicer command parser.

## `mvm.toml` schema v1 for machine workflows

Support this as `mvm.toml` schema v1 for machine workflows, not as a day-one
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
  are never mounted or copied into the guest, and the feature is dev-tier
  only: sealed/prod paths reject it. See
  [ADR-088](../adrs/088-dev-vm-promotion-boundary.md).
- `[dev].init` is dev-only. Sealed/prod machines reject it unless a future
  signed, audited build-time equivalent is defined.
- Volumes default read-only. `:rw` is required for writable mounts.
- The effective network/auth/volume policy appears in admission, audit, and
  receipts.
- Mutable guest state does not implicitly feed a prod build: prod/sealed paths
  only consume declared host-side inputs, and any dev-machine output must be
  promoted back explicitly as source/config/artifact before it can matter to
  production.
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
- Measure Stage 0 bootstrap separately from normal machine hot start. The active
  branch now caches the host materialized Stage 0 root, prefers verified native
  `tar -xJf --strip-components 1` for cold extraction, and makes libkrun
  Stage 0 use a prepopulated persistent `/dev/vda` Nix-store image when the
  host has `mkfs.ext4`. Firecracker-host measurement on `156391a4`, isolated
  cache/data dirs: cold builder-image cache miss reached `Fetching Stage 0
  bootstrap assets … 0.7s` and `Materializing Stage 0 root dir … 1.7s`;
  immediate warm rerun reached `Fetching … 0.1s` and `Materializing … 0.1s`.
  The same host confirmed the Nix seed has no `mkfs.ext4`; host-side
  prepopulation wrote the sparse `nix-store-stage0-x86_64.img` plus
  `.stage0-seed` sidecar before a bounded 180s libkrun run timed out. Remaining
  proof: capture the in-guest `stage0-init` adoption line and full libkrun
  cold/warm boot timing before making a public speed claim.
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
  - **Landed (classifier + seam):** `ImageSource` (`commands/image/source.rs`) —
    prefix-driven, filesystem-free taxonomy (`oci-archive:` / `rootfs-dir:` /
    `-` stdin / bare → registry), wired into `resolve_or_pull_run_image`. The
    registry path is byte-unchanged; local sources fail closed with a clear
    message until their ingest lands.
  - **Landed (per-variant ingest + tests):** `ingest_local_archive` /
    `ingest_stdin_archive` / `ingest_rootfs_dir` route every source through the
    same hardened unpack → inject → materialize → provenance → admission path
    (`inject_runtime_and_materialize`). Negative tests cover prod-refusal,
    missing file/dir, malformed archive, and wrong architecture
    (`local_archive_malformed_is_rejected`, `rootfs_dir_wrong_arch_is_rejected`,
    `*_prod_is_refused`, `*_missing*`); provenance labels are asserted by
    `provenance_labels_cover_claim_10_fields`; path traversal is covered in the
    `mvm-oci` unpacker (`archive.rs`/`unpack.rs`) and by a CLI local-archive
    traversal-layer regression proving the ingest path reaches hardened unpack
    refusal before materialization. Session 3 item 2 complete.
- Route every `MachineImageSource` through the existing OCI/rootfs hardening,
  provenance, policy admission, and receipt/audit code paths. Do not add a
  daemon-bypass or extraction shortcut for DX.
- Extend `crate::exec::ExecRequest` with a `network_policy` field.
- Thread that field into `VmStartConfig.network_policy`.
- Include the effective network policy in dry-run output and signed receipts
  as non-sensitive metadata.
- Add parser tests, dry-run tests, deny-by-default tests, and allow-list tests.

> **Implementation plan — SUPERSEDED: `--net`/`--allow-host` shipped and
> live-validated via WS-B (#1003).** `VmStartConfig.network_policy` now exists
> and is applied per-backend; the deny-all default holds. The investigation
> notes below are kept as history — note the `VmStartConfig` field that #1003
> added did *not* exist when this was written (a separate attempt confirmed the
> gap; #1003 closed it). See the "Deferred follow-ups (from WS-B live
> validation)" section lower in this doc for the remaining items.
>
> - **Reuse, don't reinvent:** `resolve_network_policy(preset, allow)`
>   (`commands/shared/resolve.rs`) already maps preset/allow-list → a
>   `NetworkPolicy`, rejects the mutual-exclusion case, and defaults to
>   `deny_all()`. `up` already exposes `--network-preset`/`--network-allow`
>   through it. Mirror that; the ergonomic `--net`/`--allow-host` names map onto
>   the same `(preset, allow)` signature.
> - **`VmStartConfig.network_policy` already exists** and is applied by the
>   backend (the run path defaults it to `deny_all` via `..Default::default()`
>   at `mvm-cli/src/exec.rs` `run_inner`; claim 10 holds today). So enforcement
>   is a one-line thread, **not** new backend work — the earlier worry that the
>   field was missing was wrong.
> - **Thread:** add `--net`/`--allow-host` to `RunArgs` *and* the internal
>   `Args` (`commands/vm/exec.rs`), map them in `RunArgs::into_exec_args`,
>   `resolve_network_policy` in `build_exec_request`, set
>   `ExecRequest.network_policy`, and set it on the `run_inner` `VmStartConfig`
>   (replacing the defaulted deny-all). `ExecRequest` gains a required field, so
>   the ~9 test constructions + `commands/ops/mcp.rs` need
>   `network_policy: NetworkPolicy::default()`.
> - **Machine:** add the same two flags to `MachineRunArgs` and pass them through
>   `into_run_args`.
> - **SECURITY DECISION (settled):** the transient policy is applied by the
>   backend (image-backed runs are ephemeral; it does **not** ride a signed
>   plan), **but every egress relaxation MUST be recorded in the chain-signed
>   audit** — `emit_oci_run_admission` gains an `oci_network_policy` audit label
>   (e.g. `"deny-all"` / `"preset:dev"` / `"allowlist:2"`). `network_policy_ref`
>   on `SynthesisInput` is a *named* bundle reference and is the wrong channel
>   for an inline transient policy. An enforcement-without-audit `--net` is
>   rejected as a claim-10 gap; do not ship enforcement and audit separately.
> - **Dry-run/receipt:** add a `network_policy` summary to `RunPreflightSummary`
>   and the redacted receipt (`ReceiptInput`): kind only, not the host list.
> - **Tests:** default→deny-all, `--net dev`, `--allow-host h:443`, mutual
>   exclusion, machine-run passthrough, dry-run surfaces the policy, and the
>   audit chain records the relaxation.
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
- [x] Record the `mvm.toml` schema-v1 direction: `image` means an OCI-backed
      machine, `flake` means the existing flake-backed build flow, both are
      mutually exclusive for now, and unknown keys are rejected.
- [x] Add the current image-backed one-shot path to public quickstart and
      first-use happy-path docs before flake/manifests.
- [x] Add `mvmctl machine --help` with `run`, `create`, `start`, `exec`,
      `shell`, `stop`, `ls`, `inspect`, and `rm` subcommands.
      The lifecycle verbs are implemented under `commands/machine/`; `pack`
      remains in the portable-artifact workstream below.
- [x] Add parser/state tests for the shipped machine lifecycle commands.
      Coverage includes `machine run` translation plus persistent
      create/start/exec/shell/stop/ls/inspect/rm parser and state behavior.
- [ ] Add parser tests for portable-artifact, SSH-agent, and volume flags as
      those still-open surfaces land.
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

> **Status:** `--net`/`--allow-host` + **uniform egress enforcement across
> Firecracker, libkrun, and Vz** are merged. Design: one `NetworkPolicy` on
> `VmStartConfig`; FC enforces via its firewall, libkrun/Vz via the gateway
> bridge — every transient run is admitted as a locally-signed workload so the
> bridge spawns.
>
> **Live-validated 2026-06-16 (macOS/Vz):** no regression (A/B vs `main`
> identical); admission + bridge-spawn + boot + run + teardown work; dry-run /
> receipt posture correct; fail-closed parse. The bare-`NetworkPolicy`
> enforcement is **proven through the live gateway bridge with real Unix
> datagram sockets** — deny-all drops at the flow gate, an allow-listed host's
> DNS + TCP are forwarded, and an unlisted host is sink-holed
> (`bare_*_through_the_live_bridge` tests in `mvm-hostd` `gateway_bridge`).
>
> **Remaining:** Linux builder-VM/KVM smoke coverage and the measured latency
> work below. The macOS transient guest networking, MCP admission, default
> libkrun/Vz bridge threading, and uniform host:port L4 follow-ups are closed in
> the deferred-follow-up section.

- [x] Add `--net` and `--allow-host HOST[:PORT]` to `mvmctl run`.
- [x] Add `MachineImageSource` support for registry refs, local OCI archive
      paths, stdin archive streams, and unpacked rootfs directories.
- [x] Route every machine image source through hardened unpacking, source
      provenance, admission, receipts, and audit; do not add a daemon-bypass or
      extraction shortcut for DX. Local archive/stdin sources share
      `read_oci_archive` + `unpack_layer` + ext4 materialization with registry
      pulls; rootfs-dir is dev-only and records explicit no-provenance
      local-source metadata before the existing `run_secure` admission/audit
      caller handles launch.
- [x] Thread transient run network policy through `ExecRequest` and
      `VmStartConfig` (and on to `SupervisorConfig` → `BridgeConfig` → the
      libkrun/Vz gateway-bridge enforcer; FC consumes the same field).
- [x] Make `mvmctl machine run` translate into `mvmctl run` internals.
- [x] Add receipt/dry-run output for effective network posture.
- [x] Add unit tests for deny-all, `--net`, allow-list parsing, conflict
      handling, and dry-run redaction.
- [x] Add tests for local archive path, stdin archive, unpacked rootfs,
      malformed archive, traversal attempt, wrong architecture, and missing
      provenance handling. Coverage includes classifier variants, prod refusal
      for local sources (missing registry/cosign provenance), missing/malformed
      archive rejection, malformed stdin rejection, rootfs-dir missing/wrong-arch
      rejection, and a local OCI archive whose layer contains a traversal entry
      proving ingest reaches the hardened unpack refusal path before
      materialization.
- [ ] Add a Linux builder-VM/KVM smoke for `machine run --image alpine -- true`.
- [ ] Add a network smoke for `machine run --net --image alpine -- nslookup
      example.com`.

### B2. Hot-path latency target

> **Measure-first.** Phase timing is the foundation: optimize nothing until a
> real run's breakdown is observable. The boot micro-benchmark substrate
> (`bench microvm-launch`: `BootMarks`→`IterationTiming`, percentile/summary,
> JSON report, baseline regression gate) already exists and is reused rather
> than rebuilt; B2 adds the end-to-end `machine run` breakdown the bench
> harness does not cover.

- [~] Add phase timing around `machine run`: cache resolve, admission, drive
      materialization, backend start, vsock ready, command exit, teardown.
      Landed: `commands::vm::phase_timing` (`RunPhaseMarks`→`RunPhaseTimings`,
      pure + unit-tested) wired at the `exec::run_inner` + `run_in_guest`
      seams — resolve, drives, admit, backend start, vsock wait (boot→agent
      reachable), command, teardown — emitting a single greppable line to
      stderr behind `MVM_PHASE_TIMING=1` (default off, zero behavior change).
      The line also reports `dispatch_window` (admitted→agent-reachable), the
      span the `<200 ms` bar below is set against. Deferred: capture the
      upstream OCI cache-resolve span that `run_secure` does before
      `run_inner` for `--image`.
- [ ] Add a hardware-gated Linux/KVM benchmark for cached
      `machine run --image alpine -- true`.
- [ ] Set the first acceptance bar at `<200 ms` for backend start to command
      dispatch when image artifacts are cached; track full command latency
      separately.
- [ ] Cache or elide empty config/secrets drives without weakening admission.
      Measured below: `resolve=0 ms` and the per-instance rootfs reflink is
      ~30 ms, so empty-drive materialization is **not** a hot-path cost on vz
      today — deprioritized until a backend shows it matters.
- [x] Record macOS backend measurements before making a macOS latency claim.
      First live numbers, `MVM_PHASE_TIMING=1 mvmctl run -- true` on macOS 26
      Apple Silicon / **vz**, dev default microVM (image artifacts warm), N=3:
      `resolve≈0 · drives≈46 ms (verity probe) · admit≈7 ms ·
      backend_start≈200 ms warm (1410 ms cold = one-time supervisor codesign) ·
      vsock_wait≈1061 ms (boot→agent reachable) · command≈53 ms ·
      teardown≈6140 ms · total≈7.5 s · dispatch_window≈1.26 s`.
      **Findings that redirect B2:** (1) `resolve≈0` empirically refutes the
      "Stage 0 install cache / seed materialization" thesis — there is no
      hot-path cost in image resolution. (2) **Teardown is ~82% of total**,
      driven by the vz guest not honoring graceful stop: the host waits
      `SIGTERM→2 s→SIGKILL` for the VM *then again* for the drainer (~4 s of
      sequential fixed timeouts) plus ACPI 250 ms. This is the single biggest
      lever and a teardown-path fix, not a cache. (3) `dispatch_window≈1.26 s`
      vs the `<200 ms` bar is missed almost entirely by `vsock_wait` (guest
      boot-to-agent), not host overhead; warm `backend_start` already sits at
      ~200 ms. Numbers are debug-build, one host; release + a Linux/KVM lane
      are follow-ups.
- [x] Make ephemeral teardown instant. `VmBackend::stop_transient` (new,
      defaults to `stop`) lets the transient `run` / `machine run` path skip
      the graceful-shutdown grace, since the guest command's exit code is
      already captured. Vz overrides it to SIGKILL the supervisor + drainer
      up front (no per-process 2 s `STOP_TIMEOUT` wait), and
      `host_gvproxy::kill_by_pid_file` SIGKILLs gvproxy immediately (it
      ignores SIGTERM, so the graceful path always burned the full 2 s).
      Persistent `machine stop` / `down` keep the graceful ladder. **Measured
      (vz, warm, N=3): teardown 6140 ms → ~0.5 ms, total ~7.5 s → ~1.36 s.**
      The hot path is now `vsock_wait` (~1.06 s guest boot) + `backend_start`
      (~190 ms) — addressed by the warm/standby-pool lever (D-tier follow-up).
- [x] Tighten the guest-agent readiness poll in `wait_for_agent` from 500 ms
      to 50 ms so `vsock_wait` is not rounded up to the next coarse tick.
      Measured (vz, N=3): `vsock_wait` ~1.06 s → ~0.79–1.12 s (best total
      ~1.08 s). The remaining `vsock_wait` is genuine guest boot — no further
      host-side slack. Closing the gap to "instant" (~150 ms) requires a
      pre-booted **same-image** standby (warm pool); see the deferred item.
- [ ] Hide guest boot with a warm/standby pool for `run` / `machine run`.
      The registry (`mvm_backend::standby_pool`) is backend-agnostic and
      vz-capable, and `up` already claims via `pool::try_warm_claim`. Two open
      pieces: (1) a warm claim only matches a *same-image* standby, so this
      helps repeated runs of one image (the common dev loop), not the first
      cold run; (2) a pre-fill/refill lifecycle (background warmer or
      warm-on-use) is needed so a standby exists at claim time. Overlaps active
      Plan 118 warm-pool work — coordinate, don't fork. This is the lever that
      takes a warm run from ~1.1 s to ~150 ms.

### C. Persistent image-backed machines

- [x] Add `MachineSpec` storage under the data dir with atomic writes and
      traversal-safe name handling. Landed as `<MVM_DATA_DIR>/machines/<name>/
      machine.json` via `mvm_core::config::{machine_state_root,
      machine_state_dir, machine_spec_path}`, strict JSON, and `naming::validate_id`
      before any path dereference.
- [x] Implement `machine create --name <name> --image <ref>`.
- [x] Implement `machine start --name <name>` through the existing admitted
      launch path.
- [x] Implement `machine exec --name <name> -- <cmd>` through the existing
      guest-agent command path. This wrapper requires a persisted `MachineSpec`
      and reuses the current `console --command` attach path with the same
      argv shell-quoting strategy as transient exec.
- [x] Implement `machine shell --name <name>` through the existing console path.
- [x] Implement `machine stop --name <name>` through the existing `down` path.
- [x] Implement `machine inspect --json` and `machine ls --json`.
- [x] Implement `machine rm <name> --yes` with confirmed spec deletion.
- [x] Add tests for state persistence, state deletion, unknown-field rejection,
      and worktree-isolated `MVM_DATA_DIR`.

### C1. `mvm.toml` schema v1 machine specs

- [x] Add a typed schema-v1 parser for machine workflows with strict
      unknown-key rejection. → `Manifest` (mvm-core `domain/manifest.rs`) is schema
      v1 with `#[serde(deny_unknown_fields)]`; unknown keys now fail to parse. (No
      version bump — there is no pre-release schema, so the strict parser + `image`
      selector are simply v1.)
- [x] Enforce exactly one source selector: `image` or `flake`, never both. → added
      `image: Option<String>`, made `flake` optional with a `flake_ref()` accessor
      (defaults to `"."`), and `validate()` rejects both-set; `is_image_source()`
      exposes the selected kind. `build` fails closed on an image-source manifest
      (image build path is a later slice). Conservative `image` ref validation
      (no shell-meta) mirrors `validate_flake_ref`.
- [x] Map `net`, `[network].allow_hosts`, `[auth].ssh_agent`, `[dev].init`,
      `[dev].volumes`, `cpus`, `mem`, and `mem_initial` into the durable
      machine spec and launch request. → `machine create --manifest <path>` and
      current-directory image-manifest discovery now read image-backed manifests,
      persist `net`, `allow_hosts`, `cpus`, `mem`, `mem_initial`, `dev.init`,
      `dev.volumes`, and `auth.ssh_agent` into `MachineSpec`, resolve relative
      manifest volume paths against the manifest directory, and
      `machine start --name` now applies
      `mem_initial`, admitted volume shares, and dev-init execution through the
      existing guest-agent path. `ssh_agent = true` now requires a dev-capable
      profile plus a live host `SSH_AUTH_SOCK`, spawns a per-machine socket
      proxy, and asks the dev guest agent to expose `/run/mvm/ssh-agent.sock`;
      no private key files, `~/.ssh`, or known-hosts material are copied or
      mounted.
- [ ] Reject `[dev].init` for sealed/prod machines unless a signed, audited
      build-time equivalent is implemented in a later plan.
- [ ] Preserve read-only volume defaults and require explicit `:rw` for
      writable shares.
- [x] Include effective network, auth, and volume policy in dry-run output,
      admission metadata, audit events, and receipts. →
      `machine start --dry-run` / `--dry-run --json` now emit redacted
      effective network posture, enforcement tier, auth mode, dev-init
      hash/count, and volume policy; `machine start --receipt <path>` now
      writes the same policy summary into a signed machine-start receipt; and
      successful starts emit a `VmStart` audit line summarizing the effective
      machine policy. SSH-agent auth is now reported as
      `ssh-agent-socket`, and the guest-agent setup RPC emits the same
      host→guest vsock RPC audit as other dev-only agent calls. The signed
      `ExecutionPlan` schema is now v6 and carries `auth.mode`
      (`none` / `ssh_agent_socket`), with `auth_mode=ssh-agent-socket` copied
      into `plan.admitted` / `plan.policy_resolved` audit labels so admission
      cannot diverge from dry-run, receipts, or machine-start audit output.
- [~] Add serde roundtrip, unknown-key, image+flake conflict, no-source,
      read-only-volume-default, writable-volume-explicit, SSH-agent-no-key-file,
      and dev-init-prod-refusal tests. → **parser-level tests done** (unknown-key,
      image+flake conflict, image-only, no-source-defaults-to-flake, `cpus` with
      legacy `vcpus` aliasing, shell-meta / empty image reject, `allow_hosts`
      validation, volume-shape validation, and typed machine-workflow projection;
      serde roundtrips already covered). Runtime mapping now has focused
      machine-layer tests for manifest-backed create, flake-manifest refusal,
      dev-init profile refusal, SSH-agent profile refusal, SSH-agent receipt
      auth mode, proxy host-socket validation, proxy state path isolation,
      guest socket-path confinement, console env injection, and relative-volume
      persistence, signed-plan auth metadata, dry-run/receipt/audit auth
      honesty, and the existing TCP/22 refusal/template-material ban
      regressions. A live VM proof that the guest endpoint can complete a real
      SSH-agent protocol round trip is still a follow-up.
- [x] Update `guides/manifests.md`, quickstart, and CLI reference only after the
      parser and command behavior are implemented.

### C2. SDK parity

- [x] Add Python `Machine.run/create/start/exec/shell/stop` wrappers over the
      CLI/library lifecycle. Landed as a thin `mvmctl machine ...` subprocess
      wrapper with bounded output/timeout handling and structured
      `MachineError`; fake-CLI tests pin `run`, persistent lifecycle, conflict
      rejection, empty-command rejection, and failed-process errors.
- [x] Add TypeScript `Machine.run/create/start/exec/shell/stop` wrappers with
      matching option names. Landed as a thin `mvmctl machine ...` subprocess
      wrapper with structured `MachineError`; fake-CLI tests pin `run`,
      persistent lifecycle, conflict rejection, empty-command rejection, and
      failed-process errors.
- [x] Add Rust `mvm-sdk` machine lifecycle builders for embedders. Landed as
      `MachineRun`, `MachineCreate`, and persistent `Machine` lifecycle
      builders backed by `MachineClient`; they shell only to `mvmctl machine
      ...` so the CLI remains the admission/audit/artifact owner.
- [x] Keep structured errors aligned across Python, TypeScript, and Rust.
      Python/TypeScript expose `MachineError`; Rust now exposes `MachineError`
      with invalid-input, spawn, failed-process, argv, exit-code, and stderr
      fields.
- [~] Add SDK tests proving no host Nix is invoked for image-backed machine
      runs. Python, TypeScript, and Rust fake-CLI tests prove these wrappers
      emit only `mvmctl machine ...` argv and never call `nix` or legacy `up`
      paths. Rust SDK run argv now also round-trips through the real CLI
      `machine run` parser into `mvmctl run` dry-run/preflight helpers without
      invoking Nix or a VM. Python/TypeScript `Machine.run` argv now shares
      checked-in fixtures with the Rust CLI parser/preflight tests, proving the
      default-deny and allow-host receipt posture is CLI-owned for those SDKs
      too. Shared richer fixtures now also prove the SDK argv reaches the same
      VM-free admission/preflight/receipt fields without invoking Nix or a VM.
      Live admission-path proof remains.
- [~] Add SDK/CLI parity tests proving equivalent admission inputs, effective
      policy, and receipt/audit summaries for the same machine config. Rust SDK
      `MachineRun` builder output now feeds the CLI `machine run` parser and
      preflight/receipt summary path, proving SDK default-deny and
      `--allow-host` posture matches the CLI for dry-run receipts.
      Python/TypeScript shared argv fixtures now feed the same CLI parser and
      preflight/receipt summary path for default-deny and allow-host receipts;
      the richer shared fixture now covers CPU/memory/profile, sorted env-key
      redaction, host-path hashing for volume shares, timeout propagation,
      command hashing, effective policy, and receipt-input parity. Remaining:
      artifact verification and live admission proof.
- [~] Add SDK negative tests proving wrappers cannot bypass artifact
      verification, network default-deny, unknown-key rejection, or
      `image`/`flake` conflict rejection. Python, TypeScript, and Rust now
      reject source conflicts or invalid commands at the wrapper boundary;
      Rust SDK `MachineCreate --manifest` argv now reaches the CLI manifest
      parser and proves strict unknown-key rejection is still owned by the CLI;
      Python/TypeScript shared create-manifest fixtures now reach that same CLI
      strict-manifest unknown-key gate. Artifact-verification and live
      non-bypass proof remain.

### D. Agent-safe auth and volumes

- [ ] Add `--ssh-agent` to `machine run/create` only after the transport is
      implemented as socket forwarding, not key mounting.
- [~] Add tests proving the guest receives an agent endpoint but no private key
      file path. → Host-side validation accepts only `SSH_AUTH_SOCK` Unix
      sockets; guest forwarding is confined to `/run/mvm/ssh-agent.sock`; the
      signed plan, machine receipt/audit auth mode, and admitted audit labels
      report `ssh-agent-socket`; and no code path copies `~/.ssh`, private key
      files, or known-hosts material. Remaining gated proof path:
      1. In the builder VM only, with isolated `MVM_DATA_DIR` /
         `CARGO_TARGET_DIR` / `CARGO_HOME`, start a throwaway host
         `ssh-agent` and add a generated throwaway key outside the repo.
      2. Create a dev-profile persistent image machine with
         `[auth].ssh_agent = true`, start it, and run an in-guest raw
         agent-protocol probe against `/run/mvm/ssh-agent.sock` that sends
         `SSH_AGENTC_REQUEST_IDENTITIES` and verifies an
         `SSH_AGENT_IDENTITIES_ANSWER`. The probe must not invoke `ssh`,
         `ssh-add`, `sshd`, or read any key/known-host path.
      3. Start a host test listener on a non-standard port such as `2222` that
         emits an SSH banner (`SSH-2.0-...`), allow that host:port explicitly,
         and prove guest egress is denied/audited as SSH protocol, not merely
         as TCP/22. Runtime packet enforcement now includes an ingress
         SSH-identification-string classifier (`ssh-banner-protocol-deny`) on
         any TCP port, plus reverse-flow kill matching so an inbound banner drop
         kills the matching egress flow; Firecracker's default bridge/TAP path
         also installs an inbound TCP string-match drop for the same `SSH-`
         banner prefix. Firecracker KVM proof at `4ce7d938` used the
         runtime-assigned/scoped guest IP plus a manual default route against
         `140.82.121.36:443`; TCP opened, but no `SSH-2.0-...` banner bytes
         reached the guest.
      4. 2026-06-19 Firecracker-box attempt now reaches guest boot but the live
         SSH-agent round-trip remains open. Branch-local `mvmctl` starts a
         dev-profile `alpine:latest` persistent machine with
         `[auth].ssh_agent = true`; dry-run, signed receipt, and audit surfaces
         report `ssh-agent-socket`; and raw `SSH_AGENTC_REQUEST_IDENTITIES`
         probes to both the throwaway host agent and spawned per-machine proxy
         UDS return an SSH-agent identities answer. The in-guest raw probe
         copied to `/tmp/mvm-agent-probe-c` reaches `/run/mvm/ssh-agent.sock`
         but reads `Connection reset by peer`, narrowing the remaining blocker
         to Firecracker guest-to-host host-listen forwarding for dev
         `SSH_AGENT_PORT` 5301. Follow-up code in this PR routes Firecracker
         SSH-agent proxy traffic through the per-port runtime UDS
         (`vm_vsock_port_socket(..., 5301)`) instead of raw host AF_VSOCK and
         unit-tests the backend transport selection. Remaining gated proof:
         rerun the same raw in-guest probe and observe
         `SSH_AGENT_IDENTITIES_ANSWER` before claiming the auth smoke.
- [ ] Normalize `-v/--volume HOST:GUEST[:ro|rw]` across `machine run` and
      `machine create`.
- [ ] Preserve read-only default and explicit `:rw` requirement.

### E. Polish and examples

- [ ] Add agent-friendly install/discovery docs that end with
      `mvmctl --help` or `mvmctl doctor --workflow machine-run`.
- [ ] Add examples for untrusted command, network denied, network allowed,
      persistent dev machine, and dev-tier agent-socket forwarding without SSH
      sessions.
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
- [x] Implement verify-then-extract for the selected artifact format if the
      existing primitive does not already expose it. The selected beginner-facing
      unit is the existing signed `.mvm` archive; `mvm_build::packed_artifact`
      verifies signature, hashes, format version, sealed-prod verity sidecars,
      size caps, and traversal-safe regular files before extraction. `mvmctl
      machine check-artifact` now reuses a single verified-admission gate:
      admission preview is derived only after artifact verification and host-arch
      acceptance pass.
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
- [~] Add tamper, wrong-key, traversal, unknown-version, missing-verity, and
      arch-mismatch tests. The lower-level packed-artifact verifier already
      covers traversal, unknown-version, and missing-verity refusal; Plan 200 now
      adds machine-level non-bypass coverage for wrong-key, tampered payload, and
      host-arch mismatch before any admission preview is returned.

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
- [~] Add CI gates for default closure size, duplicate major versions,
      forbidden heavy deps, and binary-size regressions. → **closure-size landed**
      (`xtask check-closure-budget`: distinct-crate ratchet on the pinned
      `x86_64-unknown-linux-gnu` target, wired into the CI Lint job); forbidden-heavy-deps
      already gated (Plan 126 D1). Duplicate-major + binary-size regression gates remain.
- [ ] Preserve verification, signing, secret-handling, TLS, hashing, zeroization,
      and artifact-integrity dependencies that enforce real security
      guarantees.

### Deferred follow-ups (from WS-B live validation, 2026-06-16)

Live validation of the WS-B network-policy work on macOS/Vz proved the enforcement
mechanism (deny-all drops, allow-list forwards-and-narrows) through the live gateway
bridge with real Unix datagram sockets (`bare_*_through_the_live_bridge` tests in
`mvm-hostd` `gateway_bridge`), and proved no regression (A/B vs `main` identical).
The bare allow-list is now `host:port` L4-enforced uniformly across Firecracker (nftables)
and libkrun/Vz (admission-time DNS pin → `L4PolicyScan`), closing the direct-IP-dial bypass
that the original name-only `DnsSinkholeScan` left open (see the "uniform L4" follow-up
below, now landed). WS-B also surfaced these pre-existing gaps, none caused by the WS-B
change:

- [x] **Vz `up --wait` (verdict-capture) — implemented; live-vz proof blocked by a separate
      vz-boot issue (below).** The libkrun egress matrix is live-verified `0/3/2` after the
      ingress-return fix (#1083). Vz uses a connected socketpair (`run_vz_gvproxy_bridge`) so it
      has **no** recvfrom-source addressing bug — the #1083 fix does not apply to it; its bridge
      enforcement is covered by the deterministic `*_live_vz_bridge` tests. Implemented: (1)
      extracted the `wait()` poll into a shared `mvm_backend::workload_wait` module
      (`read_exit_status_from` + `wait_for_workload_exit`, state-dir based, backend-agnostic);
      libkrun's `wait()` now delegates to it; (2) `VmBackend::wait` for the Vz backend delegates
      to the same helper (the vz supervisor already persists `<vm_state_dir>/workload.exit`,
      `vz_objc.rs` ~468); (3) relaxed both `up.rs` `--wait` gates to `matches!(.., "libkrun"|"vz")`;
      (4) `workload_wait` unit tests (read/zero/absent/staged). Unit-tested + clippy/fmt/spec
      gates + linux cross-compile clean. **Live-vz verdict-capture NOT yet proven** — see the
      vz-workload-boot blocker below; the `wait()` logic rides the exact shared path proven live
      on libkrun, so the gap is the boot, not the capture. Risk: additive + safe (if vz boot
      fails, `up` errors before reaching `wait`, exactly as today).
- [ ] **Vz one-shot workload boot fails: `supervisor exited before writing PID file (exit 1)`
      (surfaced 2026-06-19, blocks the Vz `up --wait` live proof).** Running `up --hypervisor vz
      --wait` on `examples/egress-probe` (isolated cache, `MVM_VZ_DRAINER_PATH` set) reaches
      `Booting Apple Virtualization` and spawns `mvm-vz-drainer`, then the vz-supervisor exits 1
      before writing its PID file, with an **empty `console.log`** (guest never hit userspace).
      All three matrix cases fail identically at boot — so it is not policy/`wait`. Likely the
      vz-supervisor's VZ config or the drainer-bridge integration on the workload path (a
      known-fragile area; cf. the vz workload-path bugs). Next: capture the vz-supervisor stderr
      (it currently isn't persisted — add a `<vm_state_dir>/supervisor.log` like libkrun, or run
      the supervisor in the foreground), repro on a quiet box, and fix the boot. Once green,
      re-run the Vz matrix → expect `0/3/2` (validating the `--wait` slice above end-to-end).
- [x] **macOS transient-run guest networking (blocks `machine run --net` on macOS).**
      Was: `mvmctl run` / `machine run` transient guests never brought up `eth0` (the init
      ran only loopback; the unprivileged uid-901 command couldn't DHCP), so a guest had no
      egress on the gvproxy backends regardless of policy. **Landed in #1020**: the shared
      `mvm_guest::guest_net::configure_guest_network` (eth0 link-up → resolv.conf seed →
      `udhcpc -n -q` → static gvproxy fallback) now runs in `mvm-guest-netinit` as **uid 0,
      before the agent drops privileges**, on every workload (incl. transient). The
      bring-up is **unconditional** and egress is enforced **host-side** (the gateway-bridge
      flow gate + mandatory-deny), not by withholding `eth0` — an untrusted guest can't be
      its own boundary, and under deny-all the flow gate drops all egress while the static
      fallback keeps `eth0` up without hanging (`udhcpc -n`; see the DHCP/ARP posture
      decision below). Claims 1–3 (uid/setpriv/verified-boot) are unaffected: DHCP runs in
      PID-1 init at uid 0, the entrypoint still drops to uid 901 under setpriv.
      **Live-validated on this Mac (2026-06-16):** the `examples/egress-probe` workload
      booted on libkrun and reached BOTH external probe targets (`up --wait` verdict 0),
      proving the guest now gets a working `eth0` (link-up → DHCP/static-fallback) — the
      `#1020` enabler. The Vz VM-level smoke is gated on `up --wait` being libkrun-only
      today (Plan 152 WS-A), an orthogonal pre-existing gap; the Vz *bridge* enforcement is
      covered by the deterministic `*_live_vz_bridge` tests.
      Follow-up surfaced by this validation and **fixed in #1034**: the `up --wait`
      direct-boot path (`commands/vm/up.rs`) previously built `VmStartConfig` without
      threading the resolved `--network-allow` policy, so a dev `up --network-allow` did not
      pass the bare policy to the libkrun supervisor. #1034 threads the resolved policy
      through the `up` boot path; the remaining enforcement proof is the native-rvproxy
      cutover work in Plan 193, not a missing `VmStartConfig.network_policy` field.
- [x] **OCI cache index `schema_version 0` bug.** `OciCacheIndex`
      (`crates/mvm-cli/src/commands/image/mod.rs`) derives `Default` (→ `schema_version:
      0`), overriding the `#[serde(default = "schema_version")]` (= 1), so `save_index`
      persists `0` and the next `load_index` rejects it (`unsupported OCI cache index
      schema_version 0`). Breaks `image ls` / `run --image` on any freshly-created OCI
      cache. Fixed: manual `impl Default` initializes the field to `schema_version()`, plus
      a save→load round-trip regression test.
- [x] **`run --image <oci>` boots end-to-end (Session 3 item 1).** Root cause was deeper
      than a missing sidecar: an arbitrary OCI image carries no mvm agent, so the guest had
      no vsock control plane and timed out at `wait_for_agent`. The settled "attach the
      runtime overlay" mechanism is Firecracker-only (`attach_runtime_overlay` returns early
      for libkrun/Vz; both backends have zero `runtime_overlay` references), so it is a no-op
      on macOS where the agent is delivered baked-in. Fix (all host-side): cross-compile the
      guest agent + netinit to static musl (`mvm_build::guest_agent_build`, the same
      `cargo-zigbuild` pattern `build.rs` uses for the host-vm bins) and **inject** them plus
      an overlay-preferring `/init` + `/mvm/runtime` mount point into the OCI rootfs at
      materialize time (`mvm_build::oci_runtime_inject`); write an honest
      `GuestSidecar::for_oci_run` (`overlay_aware: true`) so `admit_overlay_aware` passes
      without scoping the gate off. Also fixed a pre-existing OCI-materialize bug that blocked
      vz boot regardless: `mkfs.ext4` formatted to the full device size, but vz's virtio-blk
      reports ~64 KiB fewer blocks → "bad geometry" root-mount panic; now formats with a 1 MiB
      margin. **Live-verified** on macOS-26/vz: `mvmctl run --image docker.io/library/alpine:3.20
      -- /bin/echo <marker>` boots, the injected agent comes up on vsock 5252, runs the command
      in-guest, and streams the marker back (exit 0). `tests/oci_image_runner_smoke.rs` rewritten
      to drive the real CLI end-to-end (gate + agent round-trip), env-gated `MVM_OCI_IMAGE_RUNNER_SMOKE=1`.

      ### deferred follow-ups (OCI run)
      - [ ] `rootfs-dir:` source (`ingest_rootfs_dir`) is not yet injected — it would mutate
            the user's directory; needs a staging copy before inject. Registry + OCI-archive +
            stdin sources all inject via the shared `inject_runtime_and_materialize` helper.
      - [ ] End-user (non-source-checkout) agent source: `resolve_or_build_guest_binaries`
            builds from the workspace; an installed mvmctl has no workspace, so wire the
            published runtime-overlay download as the agent-binary source for that path.
      - [ ] Harden the OCI guest agent to uid 901 under `setpriv` (mkGuest parity, W4.5); the
            injected `/init` currently forks the agent as root (dev-tier acceptable).
      - [ ] Guest egress for OCI images: alpine lacks `udhcpc`, so netinit's DHCP leg is a
            no-op (deny-all default makes this moot today; revisit with `--net`).
- [x] **Stage 0 bootstrap materialization/cache performance substrate.** The
      Plan 200 auth-proof branch now avoids repeating the slow cold Stage 0
      root materialization path when the verified input marker matches, prefers
      native `tar -xJf --strip-components 1` after SHA-256 verification with
      pure-Rust extraction as fallback, and teaches libkrun Stage 0 PID 1 to
      mount/reuse the dedicated `nix-store-stage0-<arch>.img` (`/dev/vda`) by
      seed-store fingerprint. If the current seed lacks `mkfs.ext4` and the disk
      is still blank, bootstrap falls back to the prior tmpfs seed copy rather
      than blocking. Host tests/clippy cover the touched paths; Linux PID-1
      compile/proof plus live timing remain required before making any public
      latency claim.
- [x] **`up` egress enforcement on libkrun/Vz is gated off by default AND drops an explicit
      `--network-allow` when on (claim-10 relevant; two bugs).** Diagnosed live + by code
      trace 2026-06-16 and fixed 2026-06-17 (Firecracker is unaffected — it enforces via nftables regardless).
      The foreground `up --wait` (main) path **does** thread the resolved policy onto
      `VmStartConfig.network_policy` (`into_start_config`, `start.rs`); the libkrun backend
      threads it to the supervisor unconditionally (`libkrun.rs` ~384). The two real bugs:
      - **(A) Bridge gated off by default.** `should_thread_signed_plan = gateway_bridge_enabled
        || hypervisor=="qemu"` (`up.rs` ~781) only threads `plan_json` when
        `MVM_GATEWAY_BRIDGE=1`, and the libkrun/Vz backend spawns the **enforcing** bridge
        supervisor only `if config.plan_json.is_some()` (`libkrun.rs` ~344). So a default `up`
        takes the legacy gvproxy-direct path with **no egress enforcement** — live
        `up --network-allow` (no env) = egress-probe **verdict 0** (both reachable).
      - **(B) Signed bundle shadows the bare allow-list.** With `MVM_GATEWAY_BRIDGE=1` the
        bridge engages, but `up` also resolves a `PolicyBundle` from the **synthesized plan's**
        `network_policy_ref="local-default"` (deny-all) and threads it as `bundle_json`;
        `run_bridge_inner` prefers `cfg.bundle` over the bare `cfg.network_policy`, so the
        `--network-allow` allow-list is shadowed → live verdict **3** (both blocked = deny-all).
        The transient `run` path works because it threads **no** bundle (`cfg.bundle=None` →
        the bare path / `canonicalize_network_policy` runs).
      Fixed by defaulting signed-plan threading on for libkrun/Vz admitted workload boots
      (`should_thread_signed_plan(false, "libkrun"|"vz") == true`) so the gateway bridge is
      the default `up` data path, while Firecracker keeps its nftables default path and only
      uses `MVM_GATEWAY_BRIDGE=1` for the sidecar. Non-deny resolved `NetworkPolicy` values
      (`--network-allow`, non-`none` presets, and template defaults) now synthesize a generated
      in-memory `PolicyBundle`, set all signed plan policy refs to that generated ref, and pass
      the bundle as `bundle_json`; allow-lists are host-pinned into signed TCP `/32`/`/128`
      L4 rows and fail closed if a requested hostname cannot resolve. Deny-all stays
      `local-default` with no bundle. The transient `run` session substrate now carries the
      generated bundle too, so it does not regress to the unsigned bare carrier. Open-mode
      bundle lowering now maps to `CanonicalEgress::Unrestricted` instead of an empty L4
      deny-all scan. Fail-closed behavior is preserved by the existing hard-fail bridge restart
      policy and bridge-thread process exit on panic. Tests: `mvm-cli` admission generated-bundle
      tests, default signed-plan threading test, full `mvm-cli --lib`; `mvm-hostd`
      `open_mode_lowers_to_unrestricted_egress`.

Surfaced by the adversarial security review of the WS-B branch (verdict
`merge-after-fixes`; the three blockers — warm-claim AllowAll bypass, the
`mvm_keys_dir` stale-base revert, and the accidentally-committed local cache/audit
log — were fixed in the same branch). The fix pass also closed two further egress
holes: (a) `run_bridge_inner`'s no-bundle/no-policy fallback now fails CLOSED to
deny-all instead of honoring the supervisor's `AllowAll`; and (b) the primary Vz
path (`BridgeEndpoints::VzGvproxy`) now routes the resolved `flow_policy` to the
in-process bridge instead of `cfg.policy` (`AllowAll`) — without this, a bare
deny-all run on Vz (which installs no L4 scan) left general egress open, since the
flow gate was the sole enforcement. Proven by
`bare_deny_all_policy_drops_egress_through_the_live_vz_bridge`. Remaining
follow-ups:

- [x] **Uniform `host:port` L4 egress enforcement on the libkrun/Vz bare path.** Was: the
      no-bundle path lowered an allow-list to a `DnsSinkholeScan` over host *names* only
      (`bare_network_policy_egress` returned `egress_l4 = None`), so the port was ungated and
      a direct-IP dial bypassed the name gate; Firecracker gates `host:port` via nftables.
      Closed: `run_bridge_inner` now resolves the bare allow-list's hosts on the host
      (`resolve_bare_dns_pins`, the admission-time DNS pin, mirroring nftables resolving
      `-d <host>` at insert) and `mvm_core::policy::projection::canonicalize_network_policy`
      lowers `(pinned IP, port)` into `CanonicalEgress::Rules` (TCP per pin + a UDP/53-only
      carve-out so name resolution still works, gated on qname by the `DnsSinkholeScan`;
      TCP/53 is deliberately not carved out — the qname gate only covers UDP/53).
      `L4PolicyScan` then drops a direct-IP dial to an unlisted address and a connection to a
      pinned host on the wrong port — uniform with Firecracker. An unresolvable/expired pin
      fails CLOSED to deny-all. The receipt tier collapsed to a uniform
      `<backend>:l4-host-port` (no more `dns-name-only`). Proven by
      `bare_allow_list_l4_{forwards_pinned_host_port,drops_direct_ip_to_unlisted,drops_wrong_port_on_pinned_host}_through_the_live_bridge`
      (libkrun + Vz) + `canonicalize_network_policy` unit tests. deny-all / unrestricted were
      already uniform.
- [x] **Emit `plan.launched` / `plan.failed` on the universal transient-run path.** The
      run admit closure (`commands/vm/exec.rs`) consumed `admit_plan_for_boot`'s
      `AdmissionContext` for the substrate but dropped the emitter, so only `plan.admitted`
      landed for a transient run (chain integrity was intact — this was observability, not
      forgery). Fixed: the admit closure stashes the `AdmissionContext` into a cell as it
      runs during boot, and both the json/receipt and streaming branches emit
      launched/failed after the boot resolves via the `up.rs` `emit_launched_if` /
      `emit_failed_if` helpers; the run's admission/audit plumbing is grouped into a
      `RunAudit` struct. Full end-to-end verification is box-gated (the emit fires during a
      real boot); the emit helpers are unit-tested on the `up` path.
- [x] **Route MCP code-run through the admit closure so its `deny_all()` is enforced.**
      Fixed by #1017 (cold MCP code-run) and #1023 (warm MCP code-run): both paths now route
      through admission so deny-all is enforced on the libkrun/Vz gateway bridge; FC already
      enforced through nftables. This closes the bookkeeping mismatch with the rollup.
- [x] **Remove the vestigial `BridgeConfig.policy` field + the `AllowAll` type.**
      `run_bridge_inner` no longer read `cfg.policy` (the flow gate is derived from
      `bundle` / `network_policy`, failing closed to deny-all). The field was a write-only
      footgun. Dropped the field + the `AllowAll` `FlowPolicy` impl; the four supervisor-bin
      construction sites (`mvm-libkrun-supervisor`, `vz_objc`, `mvm-vz-drainer`,
      `mvm-firecracker-bridge`) no longer set it; the gateway-bridge tests that used
      `Arc::new(AllowAll)` as an allow-all gate now use
      `PlanFlowPolicy::from_network_policy(&NetworkPolicy::unrestricted())` (the production
      allow-mode gate); the `AllowAll`-only unit test was deleted (allow-mode is covered by
      the `PlanFlowPolicy` unrestricted test). Pure hygiene, no behavior change — cfg(linux)
      `mvm-firecracker-bridge` cross-compiled with cargo-zigbuild.
- [x] **Decide the DHCP/ARP posture under deny-all.** Decision: **loopback-only, no
      control-plane carve-out** — deny-all drops every egress flow, DHCP (UDP 67/68)
      included, so the guest gets no lease and self-assigns the static gvproxy fallback
      address (`eth0` up, no admitted egress; only loopback + the egress-denied local link
      usable). It does **not** hang: `udhcpc -n` exits on no-lease and the static fallback
      applies (both from the eth0 bring-up that already landed). ARP / IPv6-ND are non-IP L2
      frames the bridge forwards unchanged (it gates IP 5-tuples) — local-only, harmless
      under deny-all, no special handling. A minimal DHCP/ARP carve-out was considered and
      rejected (the static fallback already keeps `eth0` up; a UDP 67/68 allowance would be
      a needless flow-gate special case and, if unscoped, a covert-channel surface).
      Documented in ADR-002 §"Deny-all control-plane posture (DHCP/ARP)"; pinned by
      `bare_deny_all_drops_dhcp_discover_through_the_live_bridge`.

## Verification

- [ ] `cargo test -p mvm-cli commands::tests::machine`
- [ ] `cargo test --test nix_flake_structure` if docs/plans touch Nix install
      language.
- [x] Default binary closure budget check for `mvmctl` with normal machine-run
      features only. → `xtask check-closure-budget` (distinct-crate ratchet, pinned
      `x86_64-unknown-linux-gnu` target) in the CI Lint job.
- [ ] Duplicate-major dependency budget check, including OCI/TLS stacks.
- [ ] Binary-size budget check for the default `mvmctl` artifact.
- [x] Local image-source tests: registry ref, archive path, stdin archive,
      unpacked rootfs, malformed archive, traversal attempt, wrong
      architecture, and missing provenance.
- [~] SDK/CLI parity and non-bypass tests: equivalent admission inputs,
      effective policy, artifact verification, unknown-key rejection,
      source-selector conflict rejection, and receipt/audit summaries. Rust
      SDK -> CLI parser/preflight coverage now proves dry-run receipt posture
      parity for default-deny and `--allow-host`, plus CLI strict-manifest
      unknown-key rejection; full admission-input, artifact-verification,
      audit-summary, and Python/TS parity remain.
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
- [~] Stage 0 bootstrap perf proof: Linux PID-1 compile/clippy is green;
      Firecracker-host materialized-root timing is measured at 1.7s cold /
      0.1s warm; host-side libkrun prepopulation of `/dev/vda` is proven with
      `mkfs.ext4 -d` plus `.stage0-seed` sidecar. Remaining gated proof:
      in-guest `stage0-init` adoption of the prepopulated store and full
      libkrun cold/warm boot timing.
- [x] SDK suites: Python, TypeScript, and Rust machine lifecycle wrappers.
      Python and TypeScript focused machine wrapper suites are green from the
      previous SDK slice; Rust builder/fake-CLI lifecycle tests are green in
      the previous SDK slice. Rust SDK -> CLI parser/preflight parity tests are
      also green for default-deny, `--allow-host`, and strict manifest
      unknown-key rejection.
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
  default: schema v1 allows exactly one source selector, either `image` or
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

## Future-work session prompts

The remaining Plan 200 work (after the WS-B `--net`/`--allow-host` egress
enforcement shipped in #1003) is split into three focused sessions. Run them in
order: the quick security closeouts reduce risk first, the uniform-egress work
delivers the headline promise and its macOS enabler makes everything live-
verifiable, and the product workstreams are a separate (and ownership-gated)
track. Each prompt is self-contained — paste one into a fresh session.

### Session 1 — security closeouts (quick, high-value)

```
Close out three small Plan 200 WS-B security/observability follow-ups left after PR #1003.
Read specs/plans/200-machine-ux-dx-layer.md "Deferred follow-ups" + the memory note
project_plan_200_machine_run_shipped.md first. Branch off latest origin/main in a fresh
git worktree (NOT the main checkout). Land via PR + merge queue. Keep specs/SPRINT.md +
specs/REFACTOR-STATUS.md updated in the SAME change.

These three are independent — prefer three small PRs, do them in this order:

1. Emit plan.launched / plan.failed on the universal transient-run path (claim-8 completeness).
   crates/mvm-cli/src/commands/vm/exec.rs: the run admit closure consumes admit_plan_for_boot's
   AdmissionContext for the audit substrate but DROPS the emitter, so only plan.admitted lands for
   a transient run. Thread the AdmissionContext out and emit launched/failed mirroring up.rs
   (emit_launched_if / emit_failed_if). Chain integrity is intact today — this is observability.
   Add tests asserting all three entries land for a transient run and verify clean via
   `mvmctl trust audit verify`.

2. Route MCP code-run through admission. crates/mvm-cli/src/commands/ops/mcp.rs sets
   network_policy: deny_all() but passes admit=None, so on the gateway-bridge backends no bridge
   spawns and the deny-all is INERT (FC still enforces via nftables). MCP runs untrusted AI code —
   exactly claim-10's target. Route it through the same admit closure the transient run uses so the
   bridge actually spawns and enforces. Add a negative test that deny-all drops egress on the
   bridge backends for an MCP run.

3. Remove the vestigial BridgeConfig.policy field + the AllowAll type. run_bridge_inner
   (mvm-hostd/src/supervisor/gateway_bridge.rs) no longer reads cfg.policy — the flow gate is
   derived from bundle / network_policy and fails closed to deny-all. Drop the field across the
   supervisor bins (mvm-libkrun-supervisor, vz_objc, mvm-vz-drainer, mvm-firecracker-bridge) and
   the tests + the AllowAll type. Pure hygiene, no behavior change.

Guardrails:
- Keep egress UNIFORM across FC/libkrun/Vz; deny-all default; never weaken claims 8/10; never
  over-claim more enforcement than delivered.
- Several bridge files are cfg(target_os="linux") and macOS cargo check/clippy SKIPS them (#1003's
  first CI run failed on exactly this). Cross-compile the Linux target with cargo-zigbuild
  (cargo zigbuild --target x86_64-unknown-linux-gnu -p <crate> --bins --tests) before pushing.
- Full local gate before each PR: nextest --workspace (exclude package(mvm-backend) on macOS —
  amfid SIGKILLs it), cargo test --workspace --doc, clippy --all-targets -D warnings, nightly
  cargo fmt --all, xtask check-no-spec-refs-in-comments, xtask check-spec-numbers.
- No spec/PR/ADR citations in code comments. No Claude co-author trailer; attribute to the user.
```

### Session 2 — uniform egress (the headline; design-heavy)

```
Deliver genuinely UNIFORM host:port egress enforcement across Firecracker/libkrun/Vz for Plan 200,
and unblock live verification on macOS. Read specs/plans/200-machine-ux-dx-layer.md "Deferred
follow-ups", ADR-002 (security posture / claim 10), and the memory notes
project_plan_200_machine_run_shipped.md, reference_transient_run_no_guest_network_on_macos.md,
reference_transient_egress_enforced_only_on_firecracker.md FIRST. Branch off latest origin/main in
a fresh git worktree. Land via PR + merge queue; keep SPRINT.md + REFACTOR-STATUS.md current.
This is security-sensitive — run an adversarial security review before opening each egress PR.

Do these in order; each is its own PR:

1. (ENABLER) Fix the pre-existing macOS transient-guest networking gap. `mvmctl run` / `machine run`
   transient guests never bring up eth0: the transient init doesn't run mkGuest setup_network, and
   the run command is unprivileged (uid 901, setpriv) so it can't DHCP either. So today no transient
   guest reaches the network on macOS regardless of policy — which blocks live-proving any egress
   work and blocks the headline `machine run --net --image alpine -- nslookup example.com`. Fix: the
   transient init must bring up eth0 (DHCP) as root BEFORE the agent drops privileges, policy-gated
   so deny-all still means no egress. Live-validate on a Mac (macOS 26 / Vz). This must NOT
   weaken claims 1-3 (uid/setpriv/verified-boot) on the prod path.

2. Uniform host:port L4 egress on the libkrun/Vz bare path. Today bare_network_policy_egress
   (mvm-hostd/src/supervisor/gateway_bridge.rs) returns egress_l4=None, so an allow-list is gated by
   host NAME only (DnsSinkholeScan) — the port is not gated and a direct-IP dial bypasses the name
   gate. Firecracker gates host:port via nftables. Add an admission-time DNS pin that feeds
   L4PolicyScan on the bare (no-bundle) path, mirroring the bundle path, so libkrun/Vz enforce
   host:port like FC. Then collapse the per-backend egress_enforcement receipt tiers
   (firecracker:l4-host-port / libkrun:dns-name-only) now that they're uniform — keep the receipt
   honest. Prove with live gateway-bridge tests on libkrun AND Vz (deny-all drop, allow-listed
   host:port forward, wrong-port drop, direct-IP-to-unlisted drop), plus a real-guest end-to-end
   smoke now that (1) is fixed.

3. Decide + pin the DHCP/ARP posture under deny-all. The flow-open gate has no UDP 67/68 / ARP
   carve-out; once (1) lands a deny-all networked guest would hang on a DHCP OFFER. Choose
   loopback-only vs a minimal control-plane carve-out (DHCP/ARP only), document the decision in
   ADR-002 / the plan, and pin it with a live-bridge test.

Guardrails:
- Egress must be UNIFORM and deny-by-default; the signed receipt's egress_enforcement must never
  overstate. Don't reintroduce an AllowAll flow gate on any workload-bearing path.
- cfg(target_os="linux") bridge files are skipped by macOS cargo check/clippy — cross-compile with
  cargo zigbuild --target x86_64-unknown-linux-gnu -p <crate> --bins --tests before pushing.
- The primary Vz workload path is BridgeEndpoints::VzGvproxy (in-process), NOT mvm-vz-drainer
  (vestigial NDJSON). When touching run_bridge_inner dispatch, verify EVERY arm routes the resolved
  flow_policy, not cfg.policy.
- Full local gate (nextest --workspace excluding package(mvm-backend) on macOS, doctests, clippy
  -D warnings --all-targets, nightly fmt --all, xtask spec-ref + spec-number gates) + adversarial
  security review before each PR. No spec refs in code comments; no Claude trailer.

Also surfaced + filed during WS-B (fold in if cheap, else leave tracked): OCI cache index
schema_version 0 bug (OciCacheIndex derives Default→0, overriding #[serde(default)]=1; breaks fresh
OCI cache load), and `run --image <oci>` missing mvm-meta.json sidecar on macOS.
```

### Session 3 — product workstreams (plan first, then build)

```
Advance the remaining Plan 200 (machine UX/DX) PRODUCT workstreams. WS-B `--net`/`--allow-host`
egress enforcement already shipped (#1003); these are the user-facing surface, not security debt.
Read specs/plans/200-machine-ux-dx-layer.md and the memory note
project_plan_200_machine_run_shipped.md first.

STEP 0 (do before any code): re-confirm ownership. The Plan 200 de-duplication pass split
responsibilities against Plans 199 (install/host packaging), 126/156 (dependency + binary-size),
155 (low-level artifact execution), and 159/189 (VZ-specific). Verify each item below still belongs
to Plan 200 and isn't owned elsewhere; adjust scope before building. Output a short sequencing plan
and confirm with the owner before starting the first slice.

Then build, each as its own slice/PR off latest origin/main in a fresh worktree (NOT main checkout),
landing via PR + merge queue, keeping SPRINT.md + REFACTOR-STATUS.md current:

1. WS-B MachineImageSource enum: registry ref / local OCI archive / stdin archive stream /
   unpacked rootfs dir — every shape routed through the existing OCI extraction hardening +
   provenance recording + admission (mvm-oci unpack; image::resolve_or_pull_run_image in
   commands/image/mod.rs). No bypass — all sources go through the same admitted/audited path.

2. WS-C persistent verbs: machine create/start/exec/shell/stop/ls/inspect/rm, backed by a
   MachineSpec persisted under mvm-core::config data-dir helpers (NEVER inline $HOME — use
   vm_state_dir/mvm_data_dir/etc.). Mirror the run_secure admitted/audited posture; deny-all default.

3. C1 mvm.toml schema v2 parser: image|flake mutually exclusive, #[serde(deny_unknown_fields)],
   RO volumes default, ssh_agent socket-only, dev.init dev-only. NOTE: crates/mvm-backend/src/image.rs
   MvmImageConfig is the OLD Lima Mvmfile schema — find the real flake-backed mvm.toml parser before
   adding v2; do not extend the wrong type.

4. C2 SDK parity (Python/TS/Rust) for the machine surface + non-bypass tests: equivalent admission
   inputs produce equal effective policy, artifact verification, source-selector conflict rejection,
   and matching receipt/audit summaries across CLI and each SDK. SDKs must NOT bypass admission/audit.

5. F: machine pack / run <artifact> over the Plan 155 portable-artifact primitives (signed, verified,
   runnable elsewhere, no host Nix; never a self-executing bypass around admission/policy/signature).

Guardrails:
- Security posture stays identical to `up`/`run`: signed ExecutionPlan, OCI provenance, deny-all
  egress default, dev-only surfaces gated off in prod. Reuse existing helpers; don't reimplement.
- Full local gate (nextest --workspace excluding package(mvm-backend) on macOS, doctests, clippy
  -D warnings --all-targets, nightly fmt --all, xtask spec-ref + spec-number gates) before each PR.
- cfg(linux) files are skipped by macOS check — cross-compile with cargo-zigbuild before pushing.
- No spec/PR/ADR refs in code comments; no Claude co-author trailer; attribute to the user.
```
