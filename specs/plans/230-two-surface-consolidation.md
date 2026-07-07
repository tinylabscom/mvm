# Plan 230 — Two-surface consolidation: host runtime + user client, nothing else

**Status: PROPOSED**
**Created: 2026-07-06**
**Owner directive:** "As few features as possible. One for the host machine to
run and another for the user to run. That's IT."

## The two surfaces (the only two)

Everything in the workspace collapses into exactly two product surfaces. Any
code that is neither is dev/test scaffolding and is quarantined out of the
shipped product (not a third surface).

### 1. `host` — what the host machine runs

The host-side runtime that boots, manages, secures, and builds sandboxes. One
install on a machine that hosts workloads. Comprises:

- **VMM + backends** (`mvm-backend`) and per-VM supervisors (`mvm-vm-host`:
  `mvm-hvf-supervisor`, `mvm-libkrun-supervisor`, `mvm-bridge`; `mvm-vz-supervisor`
  sunset).
- **Host daemons — the process moat** (`mvm-hostd`: `mvm-broker`,
  `mvm-host-signer`, `mvm-audit-signer`, `mvm-substitution-endpoint`,
  `mvm-host-agent`). These stay separate processes — claims 12/13 depend on it —
  but they are one *surface*: the host runtime.
- **Builder** (`mvm-build`: `mvm-builderd`, `mvm-host-vm-init`, `stage0-init`,
  `mvm-egress-proxy`, `mvm-rootfs-patcher`).
- **Guest binaries the host bakes into images** (`mvm-guest`, `mvm-guest-helpers`:
  `mvm-guest-agent`, `mvm-guest-netinit`, `mvm-runner`, `mvm-verity-init`,
  `mvm-exit-report`, `mvm-addon-*`). They run *in* the guest but are a build
  output of the host surface, not a third product.

### 2. `user` — what the user runs

The client a developer runs to create/run/drive sandboxes. Comprises:

- **`mvmctl`** (the CLI) — but as a *client*, driving the host runtime through
  the `MvmClient` facade (`mvm-client`), local or remote. No embedded host-side
  VM management in the user surface (that's the host runtime's job).
- **SDKs** — `mvm-sdk` (decorator authoring → Workload IR) + the Python/TS
  packages + `mvm-client` (runtime facade). `mvm-mcp` (the MCP sandbox server) is
  a user-surface entry point too.

### Not a surface (quarantine, do not ship)

`*/fuzz/*`, schema emitters (`emit_*_schema`), and test tools
(`syscall-probe`, `audit-probe`, `fake-runner`, `mvm-entrypoint-test-wrapper`,
`mvm-ext4`) are development scaffolding. They move behind a non-default
`dev-tools`/`fuzz` gate or out of the workspace default members, so a product
build of either surface never compiles them.

## The consolidation

### Feature flags: ~30 → 2 umbrellas

Today: `contributor-bootstrap builder-vm pure-mkfs custom-dns dev-watch
libkrun-live libkrun-sys hostd-transport manifest-verify template-registry-s3
release-artifact-bootstrap egress-ca test-support attestation-{tpm2,sev-snp,tdx}
schema remote client-facade protocol-only stdio s3 dev-shell` scattered across
14 crates.

Target: two workspace-root umbrella features a consumer selects, each
aggregating the sub-features by surface. Sub-features become internal
implementation detail (not deleted where they gate real platform code, but no
longer part of the consumer-facing knob set):

- **`host`** = builder-vm + pure-mkfs + libkrun-sys + libkrun-live + custom-dns +
  hostd-transport + egress-ca + attestation-* + template-registry-s3/s3 +
  the guest `dev-shell` build. Everything the host runtime needs.
- **`user`** = manifest-verify (cosign at the client) + `mvm-client/remote` +
  `mvm-sdk/client-facade` + MCP stdio. Everything the user client needs.
- Retire as product knobs: `contributor-bootstrap`, `dev-watch`,
  `release-artifact-bootstrap`, `test-support`, `schema` — dev/build/CI
  scaffolding, moved under a single non-default `dev` feature or out of the
  default build.

A consumer builds the host runtime with `--features host` or the client with
`--features user`. `default` picks the user client (the common case).

### CLI verbs: split client vs host-op

`mvmctl`'s verb sprawl divides: user-client verbs (`machine run/create/start/
stop/exec/logs/reconfigure/ls`, `secret`, SDK-facing) stay in the user surface
and route through `MvmClient`; host-operation verbs (`dev`, `build`, `bootstrap`,
`doctor` host-probes, `cache`, `pool`) belong to the host runtime. The user CLI
gains a `--remote` to drive a host runtime elsewhere; on a dev laptop the two
still ship together but the *code* boundary is the facade.

## Workstreams

- [x] **WS-1 (umbrella features):** root `host` + `user` features aggregating the
      existing flags; workspace builds under each. *(PR #1518)*
- [x] **WS-3a (`dev` meta-feature):** `dev = host + user + contributor-bootstrap +
      dev-watch` — the local-dev union that builds an `mvmctl` able to run **every**
      README/website-docs example on the default (HVF) backend (OCI + flake
      `machine run`, `machine build`/`build compile`, persistent-machine verbs,
      `dev up`/`shell`, the SDK compile path). Build-verified + smoke-tested
      (`machine run --image alpine` returns live). *(this PR)*
- [x] **WS-5a (enforcement lint):** `xtask check-two-surfaces` asserts exactly two
      product surfaces exist and that `dev` aggregates both — fails CI if a third
      consumer-facing product knob appears. Wired into the `ci.yml` Lint job. *(this PR)*
- [ ] **WS-2 (quarantine scaffolding):** move fuzz + schema-emitter + test-tool
      bins behind a non-default gate / out of default workspace members; a product
      build compiles neither surface's scaffolding.
- [ ] **WS-3b (retire dead knobs):** delete/fold any genuinely-unused flag once the
      release pipeline can be re-verified (release.yml/security.yml reference some
      by name — needs a pipeline run to change safely).
- [ ] **WS-4 (CLI client/host split):** route every user verb through
      `MvmClient` (Plan 216 S2); move host-op verbs behind the `host` surface;
      the user client is a facade consumer only.
- [ ] **WS-5 (docs + claims):** README/CLAUDE.md/doctor describe exactly two
      surfaces; `xtask` gate asserts no third product surface reappears (a lint
      that fails if a new consumer-facing feature is added outside `host`/`user`).

## Sequencing & safety

WS-1 is additive and safe (verify the workspace builds under `--features host`
and `--features user`). WS-2/WS-3 are removals gated on green CI. WS-4 is the
large one (depends on Plan 216 S2 facade routing) and is where the *runtime*
(not just build) boundary lands. Each slice keeps CI green; no surface merges
until it builds and tests pass.

## Non-goals

- Collapsing the host runtime's separate signer/broker/substitution processes
  into one binary — the process moat is load-bearing for claims 12/13. "One
  surface" ≠ "one process".
- Deleting platform sub-features that gate real per-OS code (libkrun-sys,
  attestation-*) — they stop being *consumer knobs*, not code.
