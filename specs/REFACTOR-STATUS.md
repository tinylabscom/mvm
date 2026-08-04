# Refactor status

Last updated: 2026-08-04

This is the cross-plan progress index. The owning plan remains authoritative
for detailed scope and acceptance criteria.

## In-flight plans
- [~] Plan 291 — Develop → build → deploy an attested workload image
      (`specs/plans/291-develop-build-deploy-attested.md`)
  - [x] WS1 `mvmctl deploy`: seal, BLAKE3 identity + SHA-256 interop, deploy
        record; retain the local sealed artifact and ship it to mvmd through
        the authenticated upload contract when a remote is configured
  - [x] WS2 `mvmctl watch`: rebuild on change, skip no-op rebuilds by address;
        long-running mode recovers from transient input/compile errors while
        `--once` remains fail-fast
  - [x] WS3 capture-from-sandbox via `reseal_volume`, converging on the
        declared-dependency path and keeping the lockfile hash pin; capture,
        `deps install`, and bounded `deps capture-live` implementation are
        present. PR #2132 passed branch and merge-group Test, Lint, and Nix
        gates and merged into main
  - [~] WS4 tier follows the attestation
    - [x] Agent-verb grant derives from admitted run shape, not image sidecar
    - [~] Bind the tier to an attested artifact and replace the interactive
          feature/symbol witnesses with conformance scenarios. Local
          `machine run --deployment` verifies and persists the signed record
          plus exact rootfs binding; remote extraction/boot, feature-fork
          removal, and guest-image validation remain. Grant enforcement now
          proves a complete ProdSafe grant refuses Exec and ConsoleOpen.

- [~] Plan 290 — Sensitive egress redaction
      (`specs/plans/290-sensitive-egress-redaction.md`)
  - [x] Validated byte detector and pinned, no-default-feature LeakGuard adapter
  - [x] Shared supplemental coverage for masking and reversible replacement
  - [x] Default secret/PII policy arms compressed and over-cap fail-closed gates
  - [~] Host workspace tests/check, workspace all-target Clippy and supply-chain
        gates pass; Linux builder-VM workspace all-target Clippy remains
  - [ ] Structured/streaming body coverage and split-boundary witnesses
  - [ ] Signed CLI policy lowering and admission posture reporting
  - [ ] Build-level claim promotion and adversarial backend witnesses

- [x] Plan 289 — Host-side machine logs
      (`specs/plans/289-host-side-machine-logs.md`)
  - [x] Read backend-captured logs from the isolated host VM state directory
  - [x] Preserve log flags and legacy fallback without shell interpolation;
        follow mode honors the requested line count
  - [x] Cover host-only CLI behavior and log resolution with regression tests
  - [x] Keep isolated test state behind the canonical config resolver and home
        isolation gates
  - [x] Complete workspace tests, check, formatting, and all-target clippy

- [x] Plan 286 — Guest-kernel hardware floor
      (`specs/plans/286-kernel-floor.md`)
  - [x] Audit resolved x86_64/aarch64 configs and enforce required cuts
  - [x] Ratchet workload configs to 902 x86_64 / 936 aarch64 built-ins
  - [x] Shrink the x86_64 workload image by 46.8% and boot it on Firecracker
  - [x] Preserve, build and boot the 955-symbol builder-kernel contract
  - [x] Native 936-symbol aarch64 artifact built and booted to PID 1 on HVF
  - [x] Full validation, merge-queue readiness and rollup closeout

- [x] Plan 285 — HVF virtio-rng
      (`specs/plans/285-hvf-virtio-rng.md`, issue #2060)
  - [x] Portable bounded virtio-mmio entropy device and negative tests
  - [x] HVF FDT/run-loop wiring while retaining the early boot seed
  - [x] Live HVF guest binds `virtio_rng.0` and serves distinct entropy reads
  - [x] Full gates, merge, and issue closeout

- [x] Plan 284 — Zero-open-issue reconciliation
      (`specs/plans/284-zero-open-issue-reconciliation.md`)
  - [x] Classify and reconcile the original 19 open issues
  - [x] Land the queued fixes for #2007, #2028, and #2029
  - [x] Land the security, kernel-pin, installer-fixture, and cold-cache-test
        fixes for #1983, #1937, #1972, and #2035
  - [x] Repair newly filed #2039
  - [x] Repair newly filed #2042
  - [x] Repair newly filed #2048
  - [x] Resolve newly filed #2052 through the merged shared guest-bootstrap fix
  - [x] Revalidate and close newly filed #2054 on current main
  - [x] Execute the refiled volume epic #2040
  - [x] Verify the repository has zero open GitHub issues
  - [x] Repair the subsequent scheduled-security alert #2067 and retain a
        PR-time regression witness for its mutation-shard toolchain
  - [x] Add executable Linux mutation witnesses for the L3 privilege-drop path
        exposed by #2067's exact security rerun
  - [x] Pin libkrun's L3 refusal and classify its default-equivalent mutation
        exposed by #2067's exact security rerun
  - [x] Add a fail-closed bounding-set result classifier whose Linux mutation
        witness kills the final comparison survivor from the corrected-head run

- [x] Plan 283 — Production object-store volumes
      (`specs/plans/283-production-object-store-volumes.md`, issue #2040)
  - [x] Canonical mvm contract and dead S3-path removal
  - [x] Live local/block attachment through the admitted VM launch path
  - [x] mvmd OpenDAL → `object_store` migration with mandatory encryption
  - [x] Authenticated remote volume CLI/client lifecycle with typed failures
  - [x] Canonical worker handoff, Linux/KVM composition proof, and follow-up PR
        matrices are green
  - [x] MinIO integration plus Linux/KVM persistence and restore proof
  - [x] Reconcile rejected speculative clauses and close #2040 with evidence

- [x] Plan 282 — Merge queue auto-requeue
      (`specs/plans/282-merge-queue-auto-requeue.md`)
  - [x] Refuse conflicts and bound retry attempts per PR
  - [x] Keep privileged execution on the trusted base ref with no checkout
  - [x] Complete repository validation and queue the PR

- [~] Plan 270 — Universal initramfs + vsock-activated boot
      (`specs/plans/270-universal-initramfs-vsock-activated-boot.md`)
  - [x] Core boot contract: `ActivateEnvironment` over the authenticated
        vsock session, `ActivationState` gate, PID-1 agent with mount
        library + uid-901 drop (#1914)
  - [x] Runner/driver adoption: QEMU unified runner (#1931), Docker
        dev-tier (#1933), Wasm activation (#1936), Apple Container kernel
        on HVF (#1968)
  - [x] Activation agent-readiness retry on the wire (#1985)
  - [x] Deterministic cargo initramfs replaces the Nix initramfs build
        (#1996); attestation stays the content hash + sidecar contract
  - [x] Retire the obsolete CLI workload-guest payload and dead
        skip-embedding switch; the universal initramfs/runtime overlay owns
        workload binaries (#2013)
  - [x] Pin `mvmctl` embedding to the builder/bootstrap host and seed
        manifests
  - [~] Deviations recorded at the unticked steps in the plan: capability-bit
        negotiation, chain-signed boot events, and vm_id/session binding were
        superseded by the path discriminator + session-key pinning; the
        guest-side activation idle timeout and focused zombie-reaping tests
        remain open
  - [~] Remaining rollout, snapshot, BDD, and live-smoke work stays in the
        plan

- [~] Plan 271 — Apple Container backend: Apple's container kernel on HVF
      (`specs/plans/271-apple-container-backend.md`)
  - [x] Stage 1 — fail-closed skeleton: kernel artifact resolution + thin
        HVF-runner delegation
  - [x] Stage 2 — live validation + claim review (2026-08-01): required
        `vmlinux.blake3` digest sidecar (fail-closed on absence/mismatch),
        sealed dm-verity boot proven on macOS HVF (gated e2e, 4.27s), CLI
        smoke via `machine run --hypervisor apple-container`, claims array
        stays a verbatim HVF-runner mirror (claim 3 stays DoesNotHold for
        the virtiofs-root path — owner decision)
  - [x] Admitted workload funnel un-barred (2026-08-01): `WorkloadBackend`
        implemented with the runner's `VsockUdsChannel` transport,
        `as_workload_backend` returns the backend, and
        `require_workload_backend` / `start_prepared` / the admitted
        persistent-OCI path accept `--hypervisor apple-container`
  - [ ] Container-mode closure (later stage)
- [x] Plan 281 — Merge queue latency audit
      (`specs/plans/281-merge-queue-latency.md`)
  - [x] Measure queue, merge-group, runner, execution, rebuild, and post-check
        latency from live GitHub metadata and logs
  - [x] Preserve required exact-commit validation while making merge-group
        triggering and cancellation behavior explicit
  - [x] Apply capacity-backed merge-queue settings in the repository ruleset

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

- [x] Plan 284 — CI lint and merge-queue latency
  (`specs/plans/284-ci-lint-latency.md`)
  - [x] Target only the packages that own `test-support` code
  - [x] Remove branch-local multi-gigabyte Cargo target caches
  - [x] Share nested `mvm-cli` builds across feature fingerprints
  - [x] Move man-page tests onto Test's warm compile graph
  - [x] Keep the removed MCP server and smoke lane out of CI
  - [x] Complete workspace and Linux clippy verification; the first live run
        passed and measured a 19–21 minute runner wait
- [~] Plan 276 — Content-addressing conformance and defense
      (`specs/plans/276-content-addressing-conformance-and-defense.md`)
  - [x] WS0 — plan + recon note landed (#1964); axis/policy ratification open
  - [x] WS1 — pin the evidence each claim rests on: `witness_kinds` per claim
        in `model/claims.toml`, gated by `check-claim-catalog`. The original
        premise (two tier vocabularies over the same claims) was wrong — the
        registers share no key; the real gap was that a claim could be
        delisted from a whole kind of witness with every gate green
  - [x] WS2 — prose over-claim meta-gate, shipped as `xtask check-no-overclaim`
  - [~] WS3 — replay golden-vector corpus. `ir_hash`, `leaf_hash`,
        `interior_hash`, `merkle_root`, `compute_plan_id` and `bundle_sha256`
        now carry frozen addresses. The existing `ir_hash` tests were all
        *relational*, so a canonicalization change moving every address
        consistently passed all four — planted and confirmed. The audit `prev_hash`
        spine is closed by WS4's frozen signed corpus
  - [x] WS4 — one frozen signed audit chain both verifiers read. The existing
        parity test compared them over a randomly-keyed chain generated per
        run, which no verifier outside that process could ever see. riscv32 is
        a compile oracle, not an executing one — the executing pair is the host
        verifier and the no_std mirror, with wasm executing the mirror
  - [ ] WS5 — bind each witness to its recorded red-proof
  - [~] WS6 — **lead item**: content-address the caches, verify on read. The
        2026-08-01 recon revision reverses finding 2 — integrity-on-read is the
        one attestation property no surveyed system enforces, mvm included —
        which promoted this from tail to lead
    - [x] Dev-build artifact cache, shipped in #2053: `mvm_core::action` +
          `verify_artifacts_on_disk`, verify on read, fail closed to a cold
          miss, and eviction of **both** the record and the build directory —
          a record-only eviction would leave the poisoned tree under a name a
          later build re-adopts. Unblocks plan 279 WS1
    - [ ] Workload/builder kernel cache: still path-trusting.
          `verify_fetched_kernel` exists with **no production caller** —
          neither the fetch nor the read path checks a kernel against its pin.
          Scoped as plan 288
          (`specs/plans/288-kernel-cache-verify-on-read.md`)
    - [ ] Cold-tier background scrub (recon §7.9)
  - [~] WS7 — σ/κ separation: `mvm_core::at_rest` gives the protocol digest
        over plaintext and the storage address over bytes at rest as disjoint
        types, σ as a set, and the transform descriptor as an open enumeration.
        The plan's "everything is Identity today" premise was wrong — OCI
        layers are tar+gzip and transcripts store ciphertext — which
        strengthens the case. Remaining: adopt the types at those two sites
  - [x] Discharged elsewhere: sealed transcript root anchored into the audit
        chain (recon §7.6 → plan 280, #2017); post-restore child verb grant
        (recon §7.7 → #2019)

- [~] Plan 285 — L3 TUN-over-vsock network mode
  (`specs/plans/285-l3-tun-over-vsock.md`, ADR-036)
  - [x] W1–W8 — canonical `NetworkMode::L3Vsock`, the shared fuzzable wire
        protocol, the pure policy core, the guest `mvm-net-agent`, the
        machine-scoped host gateway, audit kinds, docs, and the unprivileged
        end-to-end suite
  - [x] W9 — backend-neutral `GuestChannelProvider` + typed `GuestService`,
        host-owned `VmInstanceIdentity` per boot, the signed `NetworkLease`
        with a local standalone authority, capability-gated forwarding
        backends, and the launch-specification no-guest-NIC guard
  - [x] Privileged Linux lane executed on a Linux/KVM host: real host TUN,
        real nftables, live forwarding witness, verified-clean teardown
  - [x] BDD suite `s25_l3_vsock` (23 hermetic scenarios)
  - [ ] macOS forwarding backend — capability-declared and refusing; the
        userspace socket gateway is not implemented
  - [ ] WSL2 validation on a real runner; node-to-node transport; mvmd
        node-control RPC surface

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
  - [x] Persistent-machine Firecracker stop fails closed and preserves state
        until process exit is verified (#2007; live KVM recheck passed)
  - [~] Live warm-launch, fork-isolation, and restore-clock verification
        — parent audit anchoring is fixed and live-proven (#1962); the claim
        now restores a child and stops at post-restore identity/grant re-pin
  - [ ] Typed-connector egress-policy enrichment
  - [ ] OCI-image template build path and CLI facade completion
