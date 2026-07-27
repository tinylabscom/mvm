# Plan 255 — Vsock-first snapshot, egress, and warm-start adoption

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Status:** Draft.

## Goal

Adopt the useful, externally-proven techniques identified in the prior
competitor research while keeping the vsock seam the *only* guest↔host and
egress boundary. The result is:

- snapshot-first templates with O(1) CoW clone and fast restore;
- a warm pool of clean paused parents that fork fresh, identity-scrubbed
  children on demand;
- richer, auditable egress policy on the existing typed-connector path;
- a one-step OCI-image → template build path;
- all of the above exposed through the `mvm-client` facade and CLI.

Nothing here weakens the standing invariants: one guest is one workload,
default-deny egress, guest sees no secrets, every egress byte crosses the
auditable vsock seam, and the host/guest remain single binaries.

## Why this plan exists

The open-source competitor validates several design choices mvm is already
moving toward: pre-baked memory snapshots, CoW storage for fast clone/restore,
pause/resume for density, host-side L7 egress rules with credential injection,
and an OCI-image template path. It also demonstrates some paths mvm should
refuse: transparent TLS MITM inside the guest, reusing dirty guests across
jobs, and a polyglot multi-process cluster stack for the local case.

This plan turns that survey into a bounded execution plan. It builds on the
simplification worktree's existing workstreams rather than replacing them:
WS-NET supplies the consolidated vsock seam, WS-DX supplies warm-start and
snapshot scaffolding, WS1g supplies the OCI-image build work, and WS10 supplies
the density/kernel/memory work. This plan adds the prior-art-shaped details.

## Invariants (non-negotiable)

1. **Vsock is the sole boundary.** Every byte between guest and host, and every
   egress byte to the outside world, crosses the vsock seam (or its wasm
   equivalent host-call transport). No default NIC/TAP/bridge path, no
   transparent TLS MITM, no host-level eBPF data plane as the default.
2. **One guest = one workload.** A warm parent is never resumed to continue a
   prior workload; it is forked into a fresh child with fresh identity.
3. **Guest sees no secrets.** Credential injection happens host-side on the
   typed-connector path only; secrets never enter guest memory, disk, or logs.
4. **Single-binary discipline.** `mvm-hostd` and `mvm-agentd` stay one process
   each; CLI stays a thin shell over `mvm-client`.
5. **Fork/restore never bypasses admission.** A forked or restored instance
   re-admits or inherits a bound, validity-windowed signed `ExecutionPlan`
   (claim 8) and, on block+ext4 backends, retains its dm-verity roothash
   binding (claim 3). A warm parent carries no workload authority; authority is
   minted per child at fork time and emits the normal `plan.admitted` /
   `plan.launched` audit entries. A fork that silently reuses a parent's
   authority is a claim-8 hole and must fail closed.

## Product decisions

1. **Adopt snapshot-first templates.** A template is a sealed base image *plus*
   an optional ready-point memory snapshot. Running an instance means CoW-cloning
   both and restoring from the memory snapshot when present.
2. **Keep CoW in `mvm-fs`, lifecycle in `mvm-runtime`.** `mvm-fs` owns the
   storage primitives (reflink clone, snapshot graph, memory-snapshot files);
   `mvm-runtime` owns pool sizing, pause/resume, and fork identity hygiene.
3. **Enrich egress policy, don't replace the seam.** The typed-connector path
   gains scheme/host/method/path matching and audit levels, but the transport
   stays vsock and the secret model stays destination-bound placeholders.
4. **Add operational JSONL access logs alongside the chain-signed audit log.**
   The audit log remains the tamper-evident source of truth; the JSONL log is
   for operator observability and SIEM ingest. Secrets are redacted from both.
5. **OCI image as a first-class template base.** `mvmctl template build --image
   <ref>` must work without a Nix flake, while Nix flakes remain a supported
   authoring surface.
6. **Reuse the chain-anchored checkpoint lineage; do not fork a second graph.**
   The warm-fork / snapshot graph *is* the existing content-addressed,
   hash-linked checkpoint lineage anchored to the chain-signed audit log
   (`mvm-runtime::lineage`, `crates/mvm-runtime/src/checkpoint/`,
   `crates/mvm-core/src/checkpoint.rs`), not a new flat graph. `SnapshotStore`
   supplies the O(1) copy primitive *under* that lineage; it does not own
   provenance.

## Architecture

### Storage model

```text
Template (sealed, signed, read-only)
  ├─ rootfs volume        (verity-sealed)
  ├─ warm overlay         (CoW, optional)
  └─ memory snapshot      (frozen at ready point, optional)

Instance = CoW clone of template rootfs + warm overlay + fresh per-instance
           volume + memory snapshot restore (if warm) OR cold boot (if not warm)

Snapshot graph (chain-anchored checkpoint lineage; content-addressed):
  Template ──► Instance A
         ├────► Instance B
         └────► Snapshot S ──► Instance C
```

- Reflink/FICLONE is used when the underlying filesystem supports it; otherwise
  a sparse copy fallback is used. The clone operation is hidden behind a
  `SnapshotStore` trait so callers do not branch on filesystem.
- Memory snapshots are captured at a template-defined ready point and restored
  on instance start. Page-cache priming (ADR-025) is applied at freeze time,
  confined to the read-only rootfs.
- The snapshot graph is the existing chain-anchored checkpoint lineage, not a
  new structure: every clone/snapshot is a content-addressed, hash-linked
  lineage node bound to the signed audit chain. `SnapshotStore` records nodes
  through `mvm-runtime::lineage`; a clone/fork from an un-audited, missing, or
  hash-mismatched parent fails closed.

### Warm-pool model

- A pool holds **paused clean parents** per template. A parent is *not* a
  workload; it is a factory.
- On request, the runtime:
  1. picks a paused parent;
  2. CoW-clones its rootfs, overlay, and memory snapshot;
  3. assigns a fresh `vm_id`, `boot_id`, `session_nonce`, generation id, and
     per-instance secrets disk;
  4. resumes the child;
  5. reseeds entropy and resyncs the clock;
  6. closes any stale vsock flows and re-handshakes.
- The parent remains paused and available for the next fork.
- Auto-pause of *running workloads* is a separate, opt-in lifecycle behavior and
  does not conflate with warm-parent reuse.

### Egress model

- The uniform vsock endpoint seam and typed connectors remain unchanged; the
  former generic L3 tunnel was deleted as a dead second egress model.
- The typed-connector policy DTOs in `mvm-protocol` gain:
  - `scheme`: `http` | `https`;
  - `host` / `sni`: exact or `*.example.com` subdomain;
  - `method`: list of HTTP methods;
  - `path`: exact or trailing-`*` prefix;
  - `audit_level`: `none` | `metadata` | `full`;
  - `inject`: header + format + placeholder name (secret value stays in
    `mvm-hostd`).
- `mvm-hostd` enforces first-match-wins default-deny, emits structured allow /
  deny / inject / security-event / TLS-handshake events, and writes a redacted
  JSONL access log in addition to the chain-signed audit log.

### Vsock-first adoption boundary

Distilled from the open-source-competitor research and the Invariants /
Non-goals above — what this plan takes, refuses, and why.

**Adopted:**
- snapshot-first templates (sealed rootfs plus optional ready-point memory
  snapshot);
- CoW O(1) clone with a sparse-copy fallback where the filesystem lacks
  reflink;
- a warm pool that forks a paused clean parent into a fresh child, never
  resuming a parent as a workload;
- richer egress-policy *vocabulary* on the existing typed-connector/vsock
  path;
- an OCI image as a first-class template base, alongside Nix flakes;
- publishing warm-start/density SLOs as gated, measured properties.

**Refused:**
- any default guest-NIC/TAP/bridge path or eBPF data plane;
- transparent TLS MITM inside the guest (baked root CA, guest trust-model
  change);
- reusing a dirty guest across workloads;
- a mutable shared store as control-plane authority;
- a container-runtime shim on the runtime path.

**Why:**
- vsock stays the sole guest↔host and egress boundary — the auditable
  chokepoint the egress and secret-substitution claims rest on;
- admission stays the signed, validity-windowed `ExecutionPlan` plus
  chain-signed audit log, never a mutable store;
- one guest is one workload;
- a forked or restored instance re-admits or inherits a bound signed plan
  and keeps its verity binding — it never bypasses admission.

## Phases

### Phase 0 — Boundary record and spec update

- [x] Update ADR-025 to add the open-source competitor as a second prior-art
      data point: confirm the snapshot/CoW model, confirm refusal of dirty-
      guest reuse, and note the richer egress-policy vocabulary as inspiration
      only (no MITM adoption).
- [x] Add a short design note in this plan (above) or in `03-networking.md`
      capturing the "vsock-first adoption boundary": what is adopted, what is
      refused, and why.
- [x] File/update a tracking issue for Plan 255 (#1851) and link it in
      `specs/SPRINT.md` under the appropriate phase.

**Acceptance gate:** ADR-025 updated and reviewed; no security claim changes;
`check-claim-catalog` still green.

### Phase 1 — Snapshot-first storage in `mvm-fs`

- [x] Introduce `SnapshotStore` trait in `mvm-fs` with content-addressed
      create/materialize/remove/list operations. Implementation uses
      reflink when supported, sparse copy fallback otherwise. (The trait
      and its `FsSnapshotStore` impl pre-existed as `create`/`materialize`/
      `remove`/`list`; this phase extended it with a sparse-copy fallback in
      `clone::reflink_or_copy`, a real content-addressed `create_content_addressed`
      with dedup, and `retain`/`release`/`refcount` reference counting.
      `list_parents` is deliberately not added — reference *counting* is a
      storage primitive, but parent *lineage* stays out of `mvm-fs` per this
      phase's task brief, to be plugged in from `mvm-runtime`'s checkpoint
      lineage in a later task.)
- [x] Move memory-snapshot file handling from `mvm-runtime` into `mvm-fs` if it
      is not already there; ensure content-addressed naming and reference
      tracking. (`mvm-fs` now owns content-addressed memory-snapshot
      *storage*: a `mem.bin` file or `{vmstate.bin, mem.bin}` directory is
      just another `create_content_addressed` artifact, materialized via the
      sparse-aware clone. The Firecracker pause/seal lifecycle that produces
      those bytes stays in `mvm-runtime` per Product decision 2.)
- [x] Add unit tests for reflink/fallback roundtrips and for snapshot graph
      integrity (deleting a child does not affect parent or siblings).
- [x] Add a BDD scenario: build a template with a warm snapshot, clone it into
      an instance, and verify the instance boots faster than a cold-booted
      equivalent. (`features/suites/s11_snapshot/warm_snapshot_clone.feature`,
      hermetic — no `@live` tag — driving `mvm_fs::snapshot_store` directly in
      the default `just bdd` lane; it proves the storage-layer basis for a
      warm start being faster than a cold boot (clone of a pre-built
      content-addressed artifact, not a rebuild). The live boot-time
      comparison itself is measured under the Phase 2 sub-second warm-launch
      acceptance gate.)
- [x] Plug `SnapshotStore` in *beneath* the existing checkpoint lineage: a warm
      snapshot is recorded as a lineage node (content-address + hash-link +
      audit anchor) via `mvm-runtime::{lineage, checkpoint}`; introduce no
      second provenance graph. (`mvm-runtime::warm_snapshot::stage_warm_snapshot`
      stores a checkpoint's content dir into `FsSnapshotStore` under its own
      content hash; the checkpoint's `meta.json` remains the sole lineage
      record — no second graph.)
- [x] A clone/fork from a parent whose lineage node is missing, un-audited, or
      hash-mismatched fails closed, reusing the checkpoint lineage's
      parent-verification path. Add a negative test.
      (`mvm-runtime::warm_snapshot::materialize_child_from_parent` runs
      `read_meta -> verify_content -> verify_lineage` before calling
      `SnapshotStore::materialize`; four tests cover the positive control plus
      missing/un-audited/tampered-parent refusal, each asserting `dst` is
      never created.)

**Acceptance gate:** `cargo test -p mvm-fs` green; BDD scenario passes on Linux;
no `mvm-fs` consumer sees filesystem-specific logic; clone/fork refuses an
un-audited or tampered parent; no second provenance graph is introduced (reuses
`mvm-runtime::lineage`).

### Phase 2 — Warm pool and fork hygiene in `mvm-runtime`

- [ ] Implement paused-parent pool keyed by template id in `mvm-runtime`:
      create, maintain, and evict parents based on TTL / memory budget.
- [ ] Implement `fork_from_parent` that performs the CoW clone and assigns fresh
      identity (CID, `boot_id`, `session_nonce`, generation id, per-instance
      secrets disk).
- [ ] Implement post-resume hygiene: entropy reseed, clock resync, vsock flow
      teardown, and fresh handshake.
- [ ] Add a hard guard that refuses to resume a warm parent as a workload
      (different code path / enum variant).
- [ ] Add unit tests for identity freshness and replay refusal; add BDD
      scenarios for sub-second warm launch and for fork isolation.
- [ ] `fork_from_parent` mints or inherits a fresh signed `ExecutionPlan` for
      the child and refuses to launch a child whose plan is unsigned, expired,
      or replayed (claim 8). Add a negative test.
- [ ] On block+ext4 backends the forked child inherits the parent template's
      dm-verity roothash binding; a fork that would drop verity fails closed
      (claim 3).

**Acceptance gate:** warm launch is sub-second on Linux and macOS; forked child
has a new session nonce and cannot reuse an old one; a forked/restored child
emits `plan.admitted` / `plan.launched` and a fork with an absent or tampered
plan is refused; `check-claim-catalog` green; clippy/test green.

### Phase 3 — Egress policy enrichment (vsock seam only)

- [ ] Extend typed-connector policy DTOs in `mvm-protocol` with scheme, host,
      sni, method, path, audit_level, and inject fields. Keep the DTO
      `#![no_std]`-clean.
- [ ] Implement rule matching in `mvm-net`/`mvm-hostd`: first-match-wins,
      default-deny, subdomain wildcard semantics, path-prefix semantics.
- [ ] Implement audit-event variants: `allow`, `deny`, `security_event`,
      `tls_handshake`, `inject_fired`. Secrets are redacted before logging.
- [ ] Add per-host JSONL access log at `~/.mvm/logs/egress-access.jsonl`,
      rotated, with the same redaction rules as the chain-signed audit log.
- [ ] Add BDD scenarios for allow/deny/subdomain/path/audit-level/security-event
      and for secret absence from both log sinks.

**Acceptance gate:** all new egress-policy BDD scenarios pass; secrets are
absent from logs and from guest memory; `mvm-protocol` stays `no_std` and
wasm-clean; clippy/test green.

### Phase 4 — OCI-image template build path

- [ ] Add `mvmctl template build --image <oci-ref>` support in `mvm-cli`,
      routed through `mvm-client` to `mvm-sdk`/`mvm-build`.
- [ ] Reuse `mvm-fs::oci` fetch/unpack and the ext4 writer to materialize the
      template rootfs.
- [ ] Optionally take a ready-point snapshot to produce a warm template if
      `--warm` is given.
- [ ] Ensure the produced template emits the same signed `ExecutionPlan` /
      bundle shape as the Nix path, so admission and audit are uniform.
- [ ] Add BDD scenario: `template build --image alpine` followed by
      `machine run --template <id>`.

**Acceptance gate:** OCI-built template is signed, admits cleanly, and boots;
Nix-built templates still work; clippy/test green.

### Phase 5 — CLI / SDK surface through `mvm-client`

- [ ] Add facade methods to `mvm-client`: `build_template`, `snapshot_machine`,
      `fork_machine`, `restore_machine`, `list_warm_pool`.
- [ ] Add CLI verbs/subcommands: `mvmctl template build --image`,
      `mvmctl machine snapshot`, `mvmctl machine fork`,
      `mvmctl machine restore`, `mvmctl pool ls`.
- [ ] Ensure all new commands route through `mvm-client` and do not reach into
      `mvm-runtime` directly (lint `check-cli-runtime-surface` must stay
      green).
- [ ] Update `tests/cli.rs` for help text and argument parsing of the new
      verbs.

**Acceptance gate:** `mvmctl --help` reflects new surface; `check-cli-runtime-surface` green; `tests/cli.rs` updated and passing.

### Phase 6 — Docs, ADRs, and close-out

- [ ] Update `03-networking.md` if egress policy details changed.
- [ ] Update `04-security.md` if the JSONL access log or audit-level semantics
      need documentation.
- [ ] Update website docs (`public/src/content/docs/**`) for templates,
      snapshots, warm start, and egress policy.
- [ ] Tick checkboxes in this plan and in `specs/SPRINT.md`; close the tracking
      issue.

**Acceptance gate:** docs match shipped behavior; no stale `specs/` paths;
SPRINT.md is consistent with this plan.

## Verification gates

No phase closes without:

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace` (or `cargo nextest run --workspace`)
- touched BDD scenarios green via `just bdd`
- `check-claim-catalog` green (no security claim regressed)
- `check-cli-runtime-surface` green (CLI does not bypass `mvm-client`)
- `check-core-runtime-free` green (no async runtime leaks into the default
  build)
- `mvm-protocol` `wasm32-unknown-unknown` build green if policy DTOs changed

## Risks

- **Filesystem support for reflink.** XFS and Btrfs support it; APFS has
  clonefile; ext4 generally does not. The fallback must be tested and fast
  enough not to destroy the warm-start value proposition.
- **Memory-snapshot size.** Restoring from a warm snapshot is fast only if the
  snapshot is small or demand-faulted. Page-cache priming must be limited to
  the read-only rootfs to avoid sharing mutable/sensitive state.
- **Identity hygiene on fork.** If `boot_id`/`session_nonce`/generation id are
  not correctly rotated, a restored child could replay a stale session or
  inherit entropy state. This is a correctness *and* security issue.
- **Policy grammar explosion.** Richer egress rules are useful but can become
  hard to reason about. Keep the grammar small and first-match-wins; document
  evaluation order explicitly.
- **Log duplication.** Two log sinks (chain-signed audit + JSONL access) could
  drift in redaction behavior. Share one redactor module and test both sinks
  with the same secrets corpus.

## Non-goals

- Replacing vsock with a NIC/TAP/bridge path or with an eBPF-only data plane.
- Transparent TLS MITM inside the guest (no baked root CA, no guest trust
  model change).
- Reusing dirty guests across workloads.
- Introducing a multi-process, multi-language cluster control plane for the
  local runtime.
- Full compatibility with the competitor's SDK or API surface.
- Changing the public package names on PyPI or npm.
