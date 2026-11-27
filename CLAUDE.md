# mvm -- secure microVM workload tool

Backing: shipped-source
Validation: check-claim-catalog

Read `AGENTS.md` before changing this repository: it owns the product and
design boundaries, the git and worktree rules, the Definition of Done and the
coding rules. This file is what every task needs about the current code.
ADR-001 and its claims ledger govern every security claim.

## What this repository is

`mvmctl`, a Rust CLI that builds and runs microVM workloads from signed,
audited execution plans on macOS and Linux. Workload backends: HVF (the
in-house Hypervisor.framework VMM) on macOS 26+ Apple Silicon, Firecracker on
Linux with `/dev/kvm`; libkrun, QEMU (dev/test only, never used by `mvmd`),
`apple-container` (Apple's prebuilt container kernel on the HVF VMM) and Wasm
run only when selected. Auto-detect never picks libkrun or `apple-container`,
and `mvmctl` refuses macOS below 26. Builds run Nix inside a builder VM
(selection: `public/src/content/docs/guides/builder-vm.md`).

Neighbouring repositories: [mvmd](https://github.com/tinylabscom/mvmd) owns
fleet orchestration; [mvm-images](https://github.com/tinylabscom/mvm-images)
owns the Linux layer (builder image, kernels, base root filesystems, Stage 0
seeds); [mvm-packs](https://github.com/tinylabscom/mvm-packs) publishes packs.
The guest runtime (guest agent and helpers, initramfs agent, `mvm-setpriv`,
`libmvm_host_services.so`, GPU shims, Python SDK tree) is built from this tree
and ships as a signed asset with each `mvmctl` release; `mvmctl` assembles
the runtime overlay, initramfs and SDK sidecars from it (ADR-054). A
contributor build pair-builds workload images from a sibling or
`MVM_IMAGES_DIR` checkout of mvm-images; an official release binary only
downloads verified artifacts (ADR-030).

## Crates, low to high

A crate depends only on crates on its own line or above; each `lib.rs` documents its scope.

1. `mvm-contract` (`no_std` Workload IR, wire protocol, policy DTOs, audit verifier; builds for wasm), `mvm-crypto` (primitives), `mvm-http` (minimal HTTP/1.1 client), `mvm-setpriv` (guest privilege-drop helper), `crates/deps/mvm-macho-sign`.
2. `mvm-core` -- types, config and `~/.mvm` paths, signed `ExecutionPlan` and `.mvmpkg` bundles, policy, crypto, guest-service channels; no tokio by default (`check-core-runtime-free`); keeps only code several crates share.
3. `mvm-policy` (authored policy composition), `mvm-fs` (OCI client, allow-listed unpacker, pure-Rust ext4 writer), `crates/deps/libkrun-sys` (FFI + safe wrapper), `mvm-agentd` (guest agent, vsock protocol, console), `mvm-compiler` (workload compilation; no builds, network or signing), `mvm-gpu` (host GPU endpoint; guest shims are its cdylib examples).
4. `mvm-vmm` (device model, hypervisor traits, `VmmDriver` seam), `mvm-host-services` (guest `libmvm_host_services.so`), `mvm-builder-guest` (builder-VM binaries + contract), `mvm-capture`.
5. `mvm-backends` (Firecracker/HVF/libkrun/QEMU drivers), `mvm-build` (Nix builder pipeline, artifact cache, runtime-piece assembly).
6. `mvm-runtime` -- `VmBackend` + `AnyBackend`, VM lifecycle, workload runners.
7. `mvm-hostd` -- supervisor, broker, signers, jailer, per-VM supervisors.
8. `mvm-client` (`MvmClient`, `LocalBackend`, machine inventory); `mvm-sdk` (decorators to IR; language SDKs in `crates/mvm-sdk/sdks/`).
9. `mvm-cli` (the `mvmctl` surface) and `mvm-hostlib` (C ABI the language SDKs load in-process).

Root package `mvmctl` (`src/lib.rs` facade, `src/main.rs` calls
`mvm_cli::run()`); `xtask` holds tooling and gates; `mvm-conformance` is the
dev-only BDD harness (`--features bdd`). `ShellEnvironment` /
`BuildEnvironment` are split in `crates/mvm-core/src/build_env.rs`.

## Rules agents trip on

- **Scratch goes under `/tmp`**, never anywhere in the working tree, not even
  a gitignored path. `.agent-memory/notes/` (below) is the only exception.
- **Reuse first.** Search for an existing helper before writing one; extend it
  rather than fork it. All `~/.mvm` paths go through `mvm-core::config`
  helpers (`mvm_home`, `vm_state_dir`, `mvm_keys_dir`, `mvm_cache_dir`, ...),
  never `std::env::var("HOME")` + `.join(...)`, which ignores `MVM_HOME`.
- **`#[allow(clippy::too_many_arguments)]` is banned**; introduce a params
  struct with a builder. Only bindgen output (`crates/deps/libkrun-sys/src/sys.rs`) is exempt.
- **Worktrees and git**: follow AGENTS.md exactly (git only from the main
  checkout, every change in a worktree, `source scripts/dev-env.sh`).
- **Host Nix is never used**: `mvmctl` never shells out to a host `nix`, a
  `nix-darwin` linux-builder or a `nix-daemon`; every Nix evaluation runs in a
  VM we launched (ADR-004, ADR-030).
- **No SSH in any microVM or the builder VM**; both are headless. The only
  interactive path is the dev-only PTY-over-vsock console.
- **Guests have no NIC.** Every workload backend and the builder VM boot with
  vsock and no net device; egress crosses vsock to the per-VM
  `mvm-network-endpoint`, whose `EgressGate` is the only decision point.
  `xtask check-single-network-path` fails on a second path.

## Security model

ADR-001 (`specs/adrs/001-microvm-security-posture.md`) owns the threat model,
the per-backend tier matrix and the claims. **The ledger table in ADR-001 is
authoritative**: `xtask check-claim-catalog` fails when a witness
(`fn:<test>` / `ci:<job>`) stops existing, and `model/claims.toml` is the
conformance ID register `check-conformance` reads. Claim prose and code
locations are in ADR-001 §"The claims" and §"Appendix: Claim implementation
notes". Eighteen numbered claims (1-15, 19-21) plus three `Preview` (16-18):

| # | Claim |
|---|---|
| 1 | No host-fs access from a guest beyond explicit shares |
| 2 | No guest binary can elevate to uid 0 |
| 3 | A tampered rootfs ext4 fails to boot (block+ext4 backends) |
| 4 | A production-safe run cannot invoke DevOnly guest-agent verbs |
| 5 | Vsock framing, supervisor-config JSON and FlowMux decoding are fuzzed |
| 6 | The pre-built dev image is hash-verified |
| 7 | Cargo dependencies are checked on dependency PRs, nightly and before release |
| 8 | Every workload runs from a signed, audited `ExecutionPlan` |
| 9 | Every published bundle is content-addressed, key_id-pinned, re-verified at fetch and admit |
| 10 | No untrusted workload reaches the network unless policy admits it |
| 11 | Application-dependency volumes are CVE-scanned and SBOM-enumerated when sealed |
| 12 | Every broker service is bound to a signed plan binding, enforced and audited |
| 13 | The managed substitution path hands the guest placeholders, never raw secrets |
| 14 | Every OCI image admission records provenance in the audit log |
| 15 | A sealed production microVM has no shell, no DevOnly verbs, no PTY |
| 16 | *Preview*: egress substitution keeps a raw secret off the guest |
| 17 | *Preview*: workload stdin is grant-gated, single-writer, secret-scanned, audited |
| 18 | *Preview*: resource use is bounded at admission, and at spawn where the host can |
| 19 | Named assets carry content-derived identities; a drifted pinned share fails closed |
| 20 | Every release artifact is authenticated under the release workflow's identity |
| 21 | OCI base images are inventoried, CVE-scanned and SBOM-enumerated at pull |

Never paraphrase a claim, especially a Preview one, without its ledger limits.
A malicious host, multi-tenant guests and hardware key attestation are out of
scope. `mvmctl doctor` reports the live posture on a host.

Prose gates: `check-witness-citations` requires every backticked identifier in
this file, `README.md`, `AGENTS.md`, ADR-001, ADR-035 and every Accepted ADR to
exist in code (comments and string literals do not count). Record a name that
was never written inside an absence region (`<!-- absent:begin -->` ...
`<!-- absent:end -->`); `check-asserted-absence` fails if it starts to exist.
ADR numbers are not contiguous: resolve every citation against `specs/adrs/`
(`check-adr-coverage`).

## Build, test, gates

```bash
cargo build && cargo run -- --help    # every verb self-documents; reference: public/src/content/docs/reference/cli-commands.md
cargo fmt --all -- --check             # --all matters: without it only one crate is checked
cargo nextest run --workspace          # the test gate (`just test`)
cargo test --workspace --doc           # nextest skips doctests (`just test doc`)
cargo clippy --workspace -- -D warnings
cargo run -p xtask -- check-all        # the xtask gates; CI workflows hold the full list
```

`just lint`, `just ci` (lint, tests, doctests, BDD) and `just test scoped
<crate> <filter>` wrap these. A change to a shared type's shape also needs
`just check gated` (AGENTS.md, Definition of Done 4). `just setup hooks`
installs the pre-commit hook. Contributor setup (pinned zig, `embed-host-bins`,
guest-runtime pieces, libkrun): `public/src/content/docs/contributing/development.md`.

## Local findings (`.agent-memory/`)

Gitignored and local to your checkout: one finding per
`.agent-memory/notes/<slug>.md` (`title`, `date`, `tags` frontmatter); `just
mem recall|notes|remember`; checked by `xtask check-agent-notes`, which is not
in `check-all`. Recall before you investigate; record what the diff will not
say, above all what proved false. Anything others need goes somewhere tracked;
ADRs and the ledger win over a note.

## Where things live

- `AGENTS.md` -- working agreement; `public/src/content/docs/contributing/` -- contributor guides, repository layout
- `specs/adrs/` (decisions, e.g. ADR-001 security, ADR-004 builder trust, ADR-054 image boundary, ADR-058 trust-first sequencing) and `specs/contracts/`
- `specs/prd.md`, `specs/README.md` -- requirements and specs policy; GitHub issues own work status
- `public/src/content/docs/guides/nix-flakes.md` (mkGuest), `guides/troubleshooting.md`
