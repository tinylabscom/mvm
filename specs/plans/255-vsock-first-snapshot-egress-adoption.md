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

## Architecture

### Storage model

```text
Template (sealed, signed, read-only)
  ├─ rootfs volume        (verity-sealed)
  ├─ warm overlay         (CoW, optional)
  └─ memory snapshot      (frozen at ready point, optional)

Instance = CoW clone of template rootfs + warm overlay + fresh per-instance
           volume + memory snapshot restore (if warm) OR cold boot (if not warm)

Snapshot graph (flat, content-addressed):
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

## Phases

### Phase 0 — Boundary record and spec update

- [ ] Update ADR-025 to add the open-source competitor as a second prior-art
      data point: confirm the snapshot/CoW model, confirm refusal of dirty-
      guest reuse, and note the richer egress-policy vocabulary as inspiration
      only (no MITM adoption).
- [ ] Add a short design note in this plan (above) or in `03-networking.md`
      capturing the "vsock-first adoption boundary": what is adopted, what is
      refused, and why.
- [ ] File/update a tracking issue for Plan 255 and link it in
      `specs/SPRINT.md` under the appropriate phase.

**Acceptance gate:** ADR-025 updated and reviewed; no security claim changes;
`check-claim-catalog` still green.

### Phase 1 — Snapshot-first storage in `mvm-fs`

- [ ] Introduce `SnapshotStore` trait in `mvm-fs` with operations `create`,
      `clone`, `delete`, `list_parents`. Implementation uses reflink when
      supported, sparse copy fallback otherwise.
- [ ] Move memory-snapshot file handling from `mvm-runtime` into `mvm-fs` if it
      is not already there; ensure content-addressed naming and reference
      tracking.
- [ ] Add unit tests for reflink/fallback roundtrips and for snapshot graph
      integrity (deleting a child does not affect parent or siblings).
- [ ] Add a BDD scenario: build a template with a warm snapshot, clone it into
      an instance, and verify the instance boots faster than a cold-booted
      equivalent.

**Acceptance gate:** `cargo test -p mvm-fs` green; BDD scenario passes on Linux;
no `mvm-fs` consumer sees filesystem-specific logic.

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

**Acceptance gate:** warm launch is sub-second on Linux and macOS; forked child
has a new session nonce and cannot reuse an old one; clippy/test green.

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
