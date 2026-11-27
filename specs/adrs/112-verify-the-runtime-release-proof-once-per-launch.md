# ADR-112 — Verify the signed runtime release proof once per launch

Backing: shipped-source
Validation: a_launch_reads_the_manifest_of_authenticated_bytes_without_walking_members

**Status: Accepted.** Direction chosen on 2026-11-14: verify once. Accepted on
2026-11-26 after security review of the claim-20 and claim-3 consequences and
the assurance boundary (issue #5931).

## Summary, for a reader in a hurry

- A launch of the signed `v0.28.0-rc.2` release takes about 5.6 s on an idle
  machine. The launch gates are 300 ms for a cold launch and 50 ms for a warm
  claim, so this is about 19 times over the cold gate.
- About 4.5 s of that, 80%, is one check repeated seven times: the signed
  guest-runtime archive is verified from scratch seven times per launch, at about
  640 ms each. Nothing else in a launch is large, and the guest itself is ready
  in about 12 ms.
- The cost is deterministic. It does not depend on load, the disk or the
  network, so it was invisible in noise and looked like "a slow machine".
- Verifying once per launch removes about 3.9 s of it. A launch-scoped change
  that only caches the single costliest step, tried as a throwaway on an idle
  VM, already took the launch from 5.58 s to 3.03 s.
- This does not reach 300 ms on its own. It is the largest single step toward
  it, and it is what makes the remaining costs visible.
- What changes is when a signed artifact is checked, which is claim 20 territory,
  so the exact conditions are written down below.

## Context

### What a launch costs today

Measured on a temporary Google Cloud VM with nothing else running (`n2-standard-4`,
Ubuntu 24.04, SSD, load average under 1, KVM, Firecracker), with the signed
`v0.28.0-rc.2` release installed by the repository installer, a cold launch of a
cached 36 MB OCI image (`MVM_RESIDENCY=cold`). Five runs agreed to within 1%. A build of the same tree with the timing spans, used
for the breakdown below, took about 5.6 s per launch; the figures in this ADR that
say "5.6 s" refer to that build, and the installed release is slower still.

| Phase | Time | Notes |
| --- | --- | --- |
| `admit_plan` | 2,967 to 2,977 ms | inside admission |
| `attach_overlay` | 1,721 to 1,729 ms | inside admission |
| `attach_initramfs` | 868 to 879 ms | |
| `backend_start` | 1,529 to 1,556 ms | includes two more proof checks |
| guest ready | 11.7 to 13.7 ms | the guest is not the cost |
| teardown | 86 to 94 ms | |
| total | 7,225 to 7,260 ms | the installed signed release |

The same phases on the developer Mac (HVF, the same signed release, under heavy
load from other builds) were `admit_plan` 1.7 to 2.7 s, `attach_overlay` 1.0 to
1.2 s and `vmm_create` 1.2 to 1.4 s, so the cost is not specific to one backend.
The physical M1 CI runner, which runs a source-built runtime, shows `admit_plan`
26 ms and `attach_overlay` 220 ms: it never takes the path described here.

### Where the 4.5 s goes

With the timing spans from #5508 and #5506 built into the exact release tree,
every cold launch showed the same thing, to within 1%:

| Span | Calls per launch | Total | Each |
| --- | --- | --- | --- |
| `verify_release_archive` | 7 | 4.50 s | 643 ms |
| `verify_runtime_release_proof` | 6 | 3.85 s | 641 ms |
| `verify_runtime_for_launch_at` | 4 | 2.56 s | 640 ms |
| `verify_assurance_guest_protocol` | 2 | 1.28 s | 641 ms |
| `runtime_lifecycle.bind` | 1 | 966 ms | contains about 1.5 verifications |

The callers are `acquire_runtime_overlay_for_launch` (twice),
`attach_universal_initramfs_if_cached`, `verify_runtime_for_launch_at` (four times,
at admission and again at dispatch) and the lifecycle bind. They each ask the
same question of the same archive and each pay for the whole answer.

One verification (643 ms) is made of:

| Step | Each | Share |
| --- | --- | --- |
| `verify_guest_bins_archive`, its own time | 422 ms | 66% |
| `read_and_digest_archive` | 107 ms | 17% |
| the two signature checks (`verify_release_archive_bytes`) | 105 ms | 16% |
| `write_archive_snapshot`, a temporary copy | 8 ms | 1% |

`verify_guest_bins_archive` opens the guest-runtime `.tar.gz`, decompresses all of
it (the archive is 19.8 MB compressed and 42.4 MB uncompressed, in 77 members) and
SHA-256s every member, then checks the manifest against those digests. That is
about 420 ms per call on the measurement VM. Whether software SHA-256 explains
part of it is not established: that CPU family generally lacks the SHA
extensions, but this was not confirmed from the CPU flags. Apple silicon has
them, so each call may be cheaper on a Mac, but the count is the same. It also
explains the seven temporary files of about 20 MB that a launch writes: one copy
of the archive per verification.

### What is not the cause

Each of these was measured and ruled out on the machines named above.

- CPU contention: a fixed 0.3 CPU-second task took 0.33 s of wall time at a load
  average of 90 on 16 cores.
- Signature verification alone: `mvmctl env verify-release` on the installed
  archive took 0.2 s including process start.
- The macOS Keychain: a lookup took about 0.1 s.
- Hashing the image: about 0.1 s in total.
- The size of the audit chain: `admit_plan` was the same on homes holding 177 and
  1,518 entries.
- File writes: a 20 MB copy took under 5 ms.
- Helper processes: only two are started, at the very end.
- Network: a system-call trace of a launch shows no outbound connection.
- Signing, audit and key load: `admit_plan.sign_and_verify_plan` 0.3 ms,
  `audit_record` 4.8 ms, `admit_plan.host_signing_key_load` 0.2 ms.

### Why the cost was hard to see

It is deterministic. A launch is not waiting on anything; it repeats the same
fixed work, so it costs the same every time on every host of a given speed. It
therefore looked like noise-free "slow hardware" and was attributed to load. The
spans from #5508 and #5506 are what exposed the repetition.

## Decision

Verify the signed runtime release proof **once per launch** and share that one
result among every step of that launch that needs it.

The conditions that make this the same verification, not a weaker one:

1. **Scope is one launch, not the process.** `mvmctl` starts a new process per
   launch, but `mvm-client` and `mvm-hostlib` run in one long-lived process that
   starts many VMs. A process-wide cache would turn "verified at every launch"
   into "verified at the first launch". The shared result is therefore created at
   the start of a launch and dropped at its end, passed through the launch
   context or held in a launch-scoped value, never in a `static`.
2. **The shared result owns the verified bytes.** `VerifiedRuntimeManifest`
   already owns a private snapshot of the exact signed archive bytes, so that
   later use reads what was verified. The shared value keeps that ownership; it
   is shared by reference (`Arc`), not re-derived from a path.
3. **The checked bytes, not mutable cache metadata, are the launch authority.**
   The result owns the verified archive, checksum and signature bytes and pins
   their digest, release version and guest architecture. A cache refresh after
   verification cannot change what this launch boots: custody copies and hashes
   the selected artifacts against the authenticated declaration into the
   retained generation. A mismatch refuses. A subsequent launch verifies its
   own selection afresh. This replaces the earlier proposal to reverify the
   on-disk archive or bundle if its path, size or modification time changes
   between steps of the same launch.
4. **Failures are not remembered.** A failed verification refuses this launch;
   another launch checks independently.
5. **Nothing is persisted.** No record is written for a later process to trust.
6. **Everything else is unchanged:** the overlay, verity and initramfs digests
   are still compared with the declaration, the plan is still signed and
   verified, and the built registry pack's dispatch-time selection recheck
   remains. Runtime binding consumes the launch's verified result and hashes
   selected artifacts while taking custody instead of repeating the archive
   signature work.
7. **`MVM_SKIP_COSIGN_VERIFY` keeps its present meaning** for each path that
   honours it today, and the Firecracker launch proof remains non-waivable.
   For the release guest runtime that meaning is an unverified *download*,
   never an unverified *install* (amended 2026-11-26): the download still
   proceeds and its bytes are returned, but bootstrap, first-use preparation
   and the image path refuse to install from it, so a hatched archive never
   reaches the object store, the launch pieces, the OCI shims or the adoption
   record.

The release identity (archive digest, selected artifact digests and verified
signer) is signed as an optional top-level `ExecutionPlan.runtime_identity`
and recorded in the chain-signed admission entry. A checkpoint fork resumes
an existing VM and selects no new kernel, so its plan may have no
`EnvironmentRef`; putting the runtime identity inside that kernel-only
reference would silently omit the retained generation or invent a kernel pin.
Restore, fork and warm claim verify their own retained generation rather than
using an unrelated fresh launch's verification result.

This gives a launch of about 1.7 s on the idle VM (projected from the spans:
5.58 s minus about 3.9 s), against 5.6 s.

## What this does not do

- It does not reach 300 ms. After it, the launch was dominated by about 640 ms for
  the one verification, about 320 ms in
  `admit_plan.grants_budget_and_host_interface`, about 300 ms in `driver_boot`,
  and teardown. Each is a separate piece of work. The
  one verification has since been cut by the adopted alternative below: on an
  Apple M4 Max with a load average of 17.6 / 40.1 / 47.7 across 16 cores, its
  median CPU time on the signed `v0.28.0-rc.11` archive went from 236.8 ms to
  32.3 ms. It has not been re-measured on the idle VM the 640 ms came from.
- It does not make a warm claim faster than a cold boot through the CLI. A warm
  claim costs the same admission and attach work, which is what this removes.
- It does not change which signatures are accepted or by whom.

## Alternatives considered

- **Persist a verification record across launches** (signed by the host key and
  keyed by the archive digest, like the source-runtime declaration cache). This
  would take the launch to about 1.1 s. It is a cached authorization, and the
  repository's rule is to reuse verified bytes and never cached authorization,
  so it needs its own decision and a claim note. Not chosen here.
- **Cache only the member check (`verify_guest_bins_archive`) by archive digest.**
  Tried as a throwaway on the idle VM: the launch went from 5,574 to 5,583 ms to
  3,032 to 3,038 ms, a saving of 2.55 s, repeatable to under 0.2%. It leaves six
  extra reads, six extra signature checks and six extra temporary copies, so it
  saves about 65% of what the decided design saves. It is the fallback if the
  review wants a smaller change first. The throwaway used a process-wide cache,
  which is not what is proposed; see condition 1.
- **Make one verification cheaper** with hardware SHA-256 or by not
  decompressing twice. Each changes what is checked and is a separate review.
- **Trust the signed manifest's member digests once the archive digest is
  authenticated.** Adopted on 2026-11-25 (issue #5931), after its own review.
  Whether an archive's members agree with its manifest is a pure function of
  the archive's bytes, so the verdict reached before signing
  (`check_release_archive` in the release workflow) and again at acquisition
  and installation (`acquire_release_guest_runtime`,
  `install_release_guest_runtime`, `install_signed_guest_runtime_archive`)
  holds for any copy whose digest and signatures a launch has just checked. A
  launch therefore reads the manifest from the first entry of the bytes it
  authenticated (`read_release_manifest`, under the 1 MiB manifest cap and a
  bound on the decompressed stream) and does not decompress or hash the
  members. The release contract makes the manifest the first entry, and both
  publish and launch refuse an archive that puts it elsewhere. What a launch
  no longer establishes itself is that a signed archive is internally
  consistent: a publisher that signs an inconsistent archive is caught at
  publish, acquisition or installation, not at launch, where the selected
  overlay, verity sidecar and initramfs are still hashed against the signed
  declaration. This is not a persisted verification record: nothing is written
  and conditions 4 and 5 are unchanged. On the `v0.28.0-rc.11` archive it takes
  one verification from about 237 ms to about 32 ms of CPU (medians of 15 fresh
  processes, an optimized build on an Apple M4 Max under other load).
- **Do nothing.** The launch stays at about 5.6 s, and no launch gate can pass.

## Consequences

- Claim 20's guest-runtime path stays "verified at every launch": every launch
  re-authenticates the whole archive (digest against the signed checksum, both
  signatures) and reads the manifest from the first archive entry; the
  member-by-member consistency check runs at publish and at
  acquisition/bootstrap, and a launch relies on the signed digest to make that
  verdict applicable to the bytes it holds. The ADR-001 row and the boundaries
  note need a sentence recording that the check is shared within a launch.
- A launch writes one temporary archive copy instead of seven, which also
  narrows the window in which a copy could be tampered with.
- The change touches `crates/mvm-build/src/guest_runtime/evidence.rs`,
  `crates/mvm-client/src/launch/runtime_overlay.rs`,
  `crates/mvm-runtime/src/runtime_evidence.rs` and
  `crates/mvm-runtime/src/universal_initramfs.rs`, so it conflicts with in-flight
  spans work in the same files.

## What the implementation must test

1. Attach, admission and bind in one launch share one whole-set verification;
   assert the number of archive and signature checks.
2. A different launch, even in the same process, independently verifies its
   selected version, architecture, archive, checksum and bundle.
3. A cache refresh between verification and bind does not change this launch's
   retained bytes; a changed selected artifact refuses at custody, and the
   next launch verifies the refreshed cache independently.
4. A refusal is not remembered: after a failing first launch, the next launch
   independently checks and refuses the same invalid bytes.
5. Two launches in one process verify twice, once each.
6. A tampered archive still refuses at the first call, with the same error and the
   same audit entry as before.
7. Every claim-20 witness named in the ADR-001 ledger still passes unchanged.

Acceptance, measured on an idle machine: `verify_release_archive` appears once in
the span table, and a cold launch of the cached image falls from about 5.6 s to
about 1.7 s.

## How this was measured

The spans are on `main` (`MVM_SPAN_TIMINGS=1`, and `MVM_PHASE_TIMING=1` or
`MVM_LAUNCH_SAMPLE_JSON=<path>` for the named laps). #5506 adds the inner steps of
the proof verification.

To repeat it on a clean machine:

1. Create a temporary VM that deletes itself, for example
   `gcloud compute instances create <name> --zone=<zone> --machine-type=n2-standard-4 --enable-nested-virtualization --min-cpu-platform="Intel Cascade Lake" --image-family=ubuntu-2404-lts-amd64 --image-project=ubuntu-os-cloud --boot-disk-size=60GB --boot-disk-type=pd-ssd --labels=purpose=<label> --max-run-duration=3h --instance-termination-action=DELETE`.
2. Install the release with the repository's `install.sh` pinned to the tag
   (`MVM_VERSION=<tag> MVM_SKIP_BOOTSTRAP=1`), make `/dev/kvm` readable by the
   user, and run one launch so the artifacts are prepared.
3. Take one warm-up and at least five cold launches with `MVM_RESIDENCY=cold`.
4. To get spans, build the exact release tree with the spans commit and pin the
   workspace version to the installed release (so the cached signed runtime
   applies). Two traps: `git archive` stamps files with the commit time, which can
   be older than an earlier build, so Cargo may recompile nothing (touch the
   sources first); and the release profile sets `strip = true`, so a profiler
   shows addresses, not names (the spans are the way to get names).
5. Delete the VM when finished, and check that no instance, disk or address of
   yours remains. Leave other people's instances alone.

## References

- Issue #5487, which holds the measurements and the discussion.
- Pull requests #5508 and #5506 (the timing spans).
- ADR-001, claim 20, and its boundaries note.
- Issue #4648, which tracks the published warm-claim budgets.
