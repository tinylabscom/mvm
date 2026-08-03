# Refactor status

Last updated: 2026-08-02

This is the cross-plan progress index. The owning plan remains authoritative
for detailed scope and acceptance criteria.

## In-flight plans
- [~] Plan 283 — Workload stream plane
      (`specs/plans/283-workload-stream-plane.md`)
  - [x] T1–T3 — stream record DTOs + chain verify; transcript stream
        directions and per-chunk linkage; ring retention
  - [x] T4–T5b — guest pump emits as produced; fd-3 control records; the
        entrypoint RPC response streams
  - [x] T6–T6b — host broker ingest/redact/chain/fan-out; chunks batched into
        segments
  - [x] T7–T8 — console capture as a second broker source; the client reader
        trait, tracing bridge, and SDK surface
  - [x] T9 — `mvmctl logs` over the broker, the durable transcript, and the
        console capture (history splice + exited-VM path), `machine run`
        attaches unless `--detach`, and the builder-VM `tail -f` path is gone
  - [x] T9 fix round 1 — a capture the filter emptied reports as present rather
        than absent (`EmptyHistory`); a console-only read refuses a channel
        selection or resume point it cannot supply instead of ignoring it under
        a contradicting warning; and the hole between the sealed history and
        the live head is reported (`SpliceGap`) rather than rendering a partial
        log as a complete one
  - [x] T9b — the plane is constructed in production: `StreamPlane` stands a
        broker, its socket, its ring-retained transcript, and its console
        follower up on VM start and seals them on stop; `mvmctl` registers it
        at startup through the runtime's `ConsoleStreamer` hook, unconditional
        and never admission-gated
  - [x] T9c — the second source is wired: entrypoint `stdout`/`stderr`/fd-3
        frames are ingested as `StreamSource::Entrypoint` with their true
        channel, so `logs --stream stderr` returns what the workload wrote
        there. `mvmctl invoke` prints what the broker cleared rather than the
        raw frame, so it and `logs` show the same redacted, chained bytes and
        neither is a path around the redaction seam
  - [x] T9d — every workload shape seals: the durable writer mirrors each landed
        chunk into an append-only journal beside the segments, so a `stop` in a
        different process from the `start` rebuilds and seals that VM's
        transcript instead of leaving a directory of ciphertext no reader can
        open. A rebuilt seal is marked `adopted` (inside the sealed root) and
        reports as incomplete, because nothing on disk records what the
        departed process shed on its way out. Teardown also kills before
        releasing the capture, so a dying guest's last words reach the chain
  - [x] T10 — `ExecutionPlan.stream_retention` (`Persist` default / `Ephemeral`
        opt-out) is admitted, labelled on `plan.admitted`, and honoured by the
        plane: an ephemeral run gets the same broker, socket, redaction, chain
        and fan-out, creates no capture directory, and seals to no manifest
        rather than to an empty one that would assert the workload printed
        nothing. ADR-035 records the posture including the three limits found
        during execution (the console fallback is unredacted, the follow half
        is open for detached workloads, a spliced read repeats its adopted
        prefix). Website guide `guides/workload-output-streaming.md` plus the
        stream surfaces in the CLI reference. `CLAUDE.md` corrected on the
        claims-ledger location, the `mvm-client` facade, and the fabricated
        claim-12/13 witness names
  - [ ] T11–T16 — the input plane (Phase 2)
  - [~] Residual after T9b/T9d: T9d closed the *seal* half — a detached run's
        transcript is now sealed by whatever stops the VM. The *follow* half
        remains: the console follower still dies with the starting process, so
        output a detached VM produces after that point reaches no capture at
        all until a resident host process owns the plane
  - [ ] Deferred to the broker task: state a follower's start sequence in the
        first batch, so the reader can close the accept-window gap between the
        transcript snapshot and the live subscription
  - [ ] Deferred to the broker task: re-seal the stream transcript periodically,
        so durable history exists for a *running* VM and survives a kill

- [x] Plan 282 — Merge queue auto-requeue
      (`specs/plans/282-merge-queue-auto-requeue.md`)
  - [x] Refuse conflicts and bound retry attempts per PR
  - [x] Keep privileged execution on the trusted base ref with no checkout
  - [x] Complete repository validation and queue the PR

- [ ] Plan 279 — Build action identity and a real artifact manifest
      (`specs/plans/279-build-action-identity-and-artifact-manifest.md`)
  - [ ] WS1 — `ActionDigest` into the identity taxonomy (land after plan 276 WS6)
  - [ ] WS2 — `ArtifactManifest`: mode, xattrs, symlinks, hard links; one walk
        shared with the ext4 materializer
  - [ ] WS3 — Bind action → artifact, host-signed, into the chain-signed log
  - [ ] WS4 — Decision gate: measure, then decide the fetch/build network split
  - [x] Prerequisite, landed separately: narrow the nix workspace filter to an
        allow-list so a docs-only edit stops invalidating every guest binary
        (416 of 1872 files, 22%, stop being cache keys)

- [~] Plan 265 — Fast-start SLO, backend sequencing & competitive positioning
  (`specs/plans/265-fast-start-slo-sequencing-positioning.md`)
  - [x] WS1 — Finish the FC warm-restore story (no-NIC guard, real
        `FirecrackerIO`, un-bailed warm restore, teardown on refusal)
  - [x] WS2 — The ≤30 ms p50 SLO: native API client, `api_put_socket`
        privilege verdict, pooled/pre-staged FC saved-state claim, and live
        KVM-box measurements recorded in the plan. SLO not cleared; remaining
        ~5–6 ms gap is Firecracker process startup + snapshot resume.

- [x] Plan 273 — SDK sidecar release acquisition
  (`specs/plans/273-sdk-sidecar-release-acquisition.md`)
  - [x] Publish `sdk-sidecar-<arch>.tar.gz` per-arch release assets, with
        `tests/release_assets.rs` pinning the workflow's names to the Rust
        constructor that requests them
  - [x] `mvm_build::sdk_sidecar` fetch + integrity-verify + atomic install,
        reusing the runtime overlay's transport helpers and one generalized
        archive-entry validator
  - [x] Reach it from the launch path on the download-mode acquire path; a
        source checkout keeps the fail-closed refusal

- [x] Plan 277 — release-artifact signature verification
  (`specs/plans/277-release-artifact-signature-verification.md`)
  - [x] Sign the image tarballs with `--new-bundle-format`, the only shape the
        in-binary Rust verifier parses; binary tarballs stay legacy for the
        cosign-CLI consumers (`install.sh`, `mvmctl update`)
  - [x] `mvm_build::release_signature` — fetch the bundle, verify against the
        versioned release identity, fail closed with no digest-only downgrade
  - [x] Wire the rung into both download paths, before extraction
  - [x] Docs + rollup; closes plan 273's one deferred gap

- [x] Plan 266 — lightweight microVM guest
  (`specs/plans/266-lightweight-microvm-guest.md`)
  - [x] WS-1/WS-2: static-musl privilege drop via the in-house `mvm-setpriv`
  - [x] WS-3: static-musl runtime overlay with the glibc SDK FFI split out
  - [x] WS-3 follow-up: plan-driven automatic SDK-sidecar attachment, gated
        fail-closed on the shared admission path
  - [x] WS-4: capability-negotiated guest-agent RSS query + 8 MiB ceiling
  - [x] WS-5/WS-6: lean kernel-module metadata, re-minimized immutable ext4, and
        the unified footprint ledger against the literal 50,000,000-byte contract
        with the optional SDK sidecar reported separately

- [x] Plan 280 — transcript root audit binding
  (`specs/plans/280-transcript-root-audit-binding.md`)
  - [x] Version-2 manifest root over fixed metadata and ordered ciphertext
        chunk records, with deterministic and mutation coverage
  - [x] Ordered `gateway.transcript_sealed` emission after atomic manifest
        persistence, chain-signed through the existing per-VM signer
  - [x] Exact tenant audit-chain anchor required before transcript key unwrap
        and decryption, with hermetic operator-path BDD coverage

- [~] Plan 255 — vsock-first snapshot, egress, and warm-start adoption
  (`specs/plans/255-vsock-first-snapshot-egress-adoption.md`)
  - [x] Snapshot storage and lineage-protected clone primitives
  - [x] Template-scoped warm-parent reservation and memory bounds
  - [x] QEMU Stage 0 raw-egress proof on the FC host
  - [x] Linux regression coverage for concurrent raw-egress handlers
  - [x] Final-child verb grant issuance, validation, persistence, and
        PostRestore delivery without granting authority to the parent
  - [~] Live warm-launch, fork-isolation, and restore-clock verification
  - [ ] Typed-connector egress-policy enrichment
  - [ ] OCI-image template build path and CLI facade completion
