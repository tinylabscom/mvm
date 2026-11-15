# ADR-061 — Crate layout by where code runs, with one hypervisor crate

Backing: preview
Validation: none

**Status: Proposed**

## Context

The workspace has 26 crates and about 1.16 million lines of Rust. 262 files
are over 1,000 lines and 67 are over 2,000. Three problems make it harder to
change than its size alone explains.

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

2. **`mvm-vmm` is the one hypervisor crate.** No new crate is created. The HVF
   substrate moves in from `mvm-runtime`. `mvm-backends` folds in, each
   backend a feature-gated module. The `host` module moves out to its owners.

3. **The host-to-guest wire protocol moves to the foundation** (`mvm-contract`
   or `mvm-core`), so `mvm-agentd` becomes a guest-only crate.

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
   by path, is updated in the same change.

5. **`mvm-hostd` aims to split along the processes it ships:** audit, egress,
   admission, broker, and supervisor. The measured import graph below prevents
   a direct five-crate split. Assign every root module and resolve the reverse
   dependencies before choosing independent crate boundaries.

6. **Small crates fold into their owners.** `mvm-net` (582 lines) into
   `mvm-core`. `mvm-bundler` beside the bundle format it writes.

7. **`runmvm-client` is deleted.** Nothing in the workspace depends on it and
   the known embedder uses `mvm-client`. Its publish lane and registry smoke
   test go with it.

8. **Guest binaries keep their closures.** `mvm-setpriv`, `mvm-builder-guest`
   and `mvm-host-services` stay separate crates under `guest/` wherever
   merging would widen what is compiled into a guest or change an image cache
   key.

9. **Moves do not mix with behaviour changes.** The `mvm-hostd` split first
   needs a separately reviewed dependency-direction change; only then can
   each extraction be a move. The claim gates stay green at each step.

10. **A file-length ratchet.** No file may grow past its current length, and a
    new file is capped. Each layer directory carries its own invariants file.

## Order

1. Recheck the import graph below for the target and feature set of each
   merge, and assign destinations to the unassigned `mvm-hostd` roots.
2. Move the wire protocol out of `mvm-agentd`.
3. Move the HVF substrate and `mvm-backends` into `mvm-vmm`; move `host` out.
4. Fold `mvm-net` and `mvm-bundler`; delete `runmvm-client`.
5. Review and break `mvm-hostd`'s cross-boundary import cycles; then split
   audit, egress, admission, broker, and supervisor.
6. Regroup directories.
7. Add the ratchet and the per-layer invariants files.

## Import-graph validation

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

For the roots that the proposal names unambiguously, the provisional grouping
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
candidate code is still under `supervisor`, and 33 root modules have no
destination assigned. Give every root a destination and specify which
shared interfaces move down or become process boundaries before splitting.

| Other proposed change | Cycle check against current package graph |
| --- | --- |
| Fold `mvm-backends` and the HVF substrate from `mvm-runtime` into `mvm-vmm` | No cycle from collapsing these existing directed dependencies: `mvm-runtime → mvm-backends → mvm-vmm` and `mvm-runtime → mvm-vmm`. |
| Move `mvm-vmm::host` out | Cannot decide until each module's destination is named and its imports checked. |
| Move guest wire protocol to the foundation | Moving `vsock` unchanged to `mvm-contract` would make `mvm-contract → mvm-core → mvm-contract`: it currently imports core types. A reduced contract-only vocabulary or a core-owned module with its guest-daemon dependencies removed avoids this observed cycle. |
| Fold `mvm-net` into `mvm-core` | No cycle from the merge (`mvm-net → mvm-core`, not the reverse). |
| Fold `mvm-bundler` beside the bundle format | Destination not specified, so the actual cycle check remains open; it currently depends on `mvm-core` and is depended on by `mvm-client`. |
| Delete `runmvm-client`; regroup directories without renaming packages | No new package dependency edge. |

## Consequences

- Fewer crates, and each remaining name says what the crate ships or where it
  runs.
- The hypervisor crate stops depending on the HTTP client, the image library
  and the guest daemon. Not yet checked for the guest daemon: that depends on
  step 2 landing.
- Published surface shrinks to `mvm-contract`. An outside Rust embedder uses
  `mvm-client` from source until a published form is decided.
- The moves touch most import paths once. They conflict with any long-lived
  branch, so each lands small and quickly.

## Not decided

- Whether the three `host`-prefixed packages are renamed. The shared library
  the SDKs load has its filename as part of its ABI.
- Where the roughly 7,000 lines of assurance and campaign-runner files at the
  top of `mvm-hostd` belong.
- `sdk/` or `deps/` for `mvm-hostlib`.

Status is tracked in issue #5510.
