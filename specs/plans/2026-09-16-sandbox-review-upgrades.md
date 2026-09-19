# Upgrades found by reviewing an external microVM sandbox

Backing: preview
Validation: workstream-specific. Each workstream names the tests and live
evidence required before its checkbox may be ticked.

**Issues:** #3378 (W1) · #3379 (W2) · #3380 (W3) · #3381 (W4) · #3382 (W5) ·
#3383 (W6) · #3384 (W7) · #3385 (W8) · #3386 (W9) · #3387 (W10) ·
#3404 (W1a) · #3432 (W10a)

## Outcome

We read an Apache-2.0 microVM sandbox with a similar shape to this project and
compared it with our tree area by area: forking and checkpoints, image
packaging, networking and secrets, the VMM layer, and the CLI, API and test
practice. Our security posture is stronger in nearly every area, so the review
produced no architecture to adopt. It produced two kinds of useful result:

1. **Three defects in our own tree**, found by checking our code against theirs.
   One of them is a security bug on the restore path.
2. **Seven mechanisms we do not have**, each confirmed missing before it was
   filed.

This plan fixes all ten. Every workstream keeps the existing invariants: signed
execution plans, the chain-signed audit log, guests with no network card,
sealed production VMs, and no single-VMM lock-in.

## Scope

Nothing is listed here unless we checked our own tree and confirmed the item is
missing or broken.

### Considered and excluded

- **Host-side request signing for object storage.** We already have it:
  `crates/mvm-hostd/src/keyholder/sigv4.rs`.
- **A CPU and runtime compatibility check before restore.** Our checkpoints are
  never exported to another host, so no host mismatch can occur today. Revisit
  if checkpoints become portable.
- **A single self-running artifact file.** Large, and it would bring
  bundle-executes-itself semantics that our admission path would have to
  re-prove. Not a clear upgrade over signed bundles plus W9.
- **Their egress model, secret injection, agent protocol, credential-agent
  forwarding, and forked VMM library.** Each is weaker than what we ship, or
  conflicts with an invariant listed above.

## Order

W1 comes first: it is a security bug. W2 and W3 are small correctness fixes and
can run in parallel with it. Among the upgrades:

- W5 lands before W4, because memory reclaim has to know which ranges are
  copy-on-write file mappings. (W4 was done first: it skips every private file
  mapping, so W5 inherits a device that never releases one.)
- W8 starts with a measurement and may close with no code change.
- W8 touches the same virtio-blk device as #3360 (no discard support), so the
  two should be sequenced rather than developed in parallel branches.
- W9 coordinates media-type naming with #3365.
- W6, W7 and W10 are independent.

## W1 — Restore reseed must be real and immediate (#3378)

**Problem.** Two related defects on the restore path:

- `GenIdReseeder::on_genid` (`crates/mvm-agentd/src/genid.rs:48-58`) returns
  `Reseeded` even when its write to `/dev/urandom` fails.
- `handle_post_restore` (`crates/mvm-agentd/src/bin/mvm-guest-agent/handlers.rs`)
  reports that as `reseeded: true`, and the host restore identity gate
  (`crates/mvm-runtime/src/workload_runner/runner.rs:4259`) trusts it.
- A successful write only mixes bytes into the input pool. It does not rekey the
  generator behind `getrandom`, so sibling clones can produce identical output
  until the kernel's scheduled reseed.

- [x] W1.1 Make `on_genid` return whether the reseed happened, and report
      `reseeded` only on success.
- [x] W1.2 Force an immediate reseed. Decide between:
  - [ ] a generation-ID device node from each backend, with `VMGENID` confirmed
        in the built guest kernel (`nix/images/kernel/base.nix`), or
  - [x] a privileged helper that calls `RNDADDENTROPY` and then
        `RNDRESEEDCRNG`. The agent runs as uid 901 and cannot make those calls
        itself.
        Decided: a helper holding only `CAP_SYS_ADMIN` under its own uid (988),
        seccomp-confined and non-dumpable, started by whatever is still root
        (PID 1 before its privilege drop, or the shell init). It credits the
        token with `RNDADDENTROPY`, then calls `RNDRESEEDCRNG`. The
        generation-ID device was rejected: the built workload kernel has
        `CONFIG_VIRT_DRIVERS` off, and the prebuilt container kernel's config
        is not ours. W1.2 stays open until W1.5 witnesses the reseed live.
- [x] W1.3 Correct the module comment that says the write alone makes clones
      diverge.
- [x] W1.4 Unit test: a failed reseed reports `reseeded: false`, and the host
      gate refuses the child.
- [x] W1.5 Live test: two clones of one snapshot return different `getrandom`
      output immediately after restore. The Firecracker/KVM witness captures
      one parent, restores each sibling in an isolated mount-namespace
      subprocess, requires the authenticated reseed acknowledgement, and
      compares the first 32 bytes returned by `getrandom(2)`.

## W1a — Keep agent descriptors out of every child process (#3404)

**Problem.** The cold entrypoint path closes inherited descriptors, but the
agent's process RPC, warm workers, detached execution, lifecycle hooks, init
helpers, health checks, and builder subprocesses do not. A descriptor that
misses close-on-exec can therefore carry a control-plane listener or live
connection into an untrusted child.

- [x] W1a.1 Create and accept every shared vsock descriptor close-on-exec.
- [x] W1a.2 Apply one close-range hook, with the existing bounded fallback, to
      every child spawn. Preserve only an explicitly required control or
      validation descriptor.
- [x] W1a.3 Linux real-process tests hold an intentionally inheritable socket
      while spawning through the cold entrypoint and process RPC paths, and
      prove the child sees only its declared descriptors.
- [x] W1a.4 Host tests, zero-warning clippy, Linux-gated compilation, the full
      workspace suite, and repository gates pass.

## W2 — Exclusive machine create (#3379)

**Problem.** `persist_definition` (`crates/mvm-client/src/launch/mod.rs:532-546`)
and `save_machine_spec` (`crates/mvm-runtime/src/machine/persist.rs:107-119`)
check whether the spec exists and then rename a temp file over it. Two creates
that run together both succeed, and the second overwrites the first.

- [x] W2.1 Make the non-force create exclusive at the filesystem (a
      no-clobber persist, or `create_new`), and map "already exists" to
      `MvmError::Conflict`.
- [x] W2.2 Leave `--force` and `overwrite_machine_spec` unchanged.
- [x] W2.3 Test: N concurrent creates of one name produce exactly one success.
      The existing reconcile tests still pass.

## W3 — Keep file ownership in container-layer rootfs images (#3380)

**Problem.** `Node` (`crates/mvm-fs/src/ext4/mod.rs:195-234`) has no owner
fields, `write_inode` (`:1171`) writes uid 0, and the unpacker writes into a
host directory that cannot keep the owners from tar headers. A service whose
data directory ships owned by its own account boots with root-owned files.

- [x] W3.1 Record each tar entry's uid and gid during unpack
      (`crates/mvm-fs/src/oci/unpack/`), in a side table keyed by path.
- [x] W3.2 Add owner fields to `Node`, and write the low and high uid/gid
      inode fields.
- [x] W3.3 Include ownership in `fingerprint_ext4_nodes`
      (`crates/mvm-fs/src/rootfs.rs`).
- [x] W3.4 Keep host-directory walks (`--mount`) normalized unless a caller
      asks for ownership.
- [x] W3.5 Tests:
  - [x] a layer file owned 999:999 round-trips;
  - [x] a uid above 65535 round-trips through the high fields;
  - [x] changing only an owner changes the fingerprint.
- [ ] W3.6 Live test: an image whose service data directory is owned by a
      non-root account starts that service.
- [x] W3.7 Keep the files mvm injects root-owned whatever a layer declares
      (#3430). The owner table forces root on every injected destination,
      mount point, directory leading to one, and mvm-only tree, so a layer
      cannot take `/etc/passwd`, `/etc/group`, the verb-trust policy, or the
      entrypoint wrapper.
  - [x] adversarial tests through the production materializer and the ext4
        oracle, including stacked layers (whiteout, opaque directory, hard
        link); a path mvm does not inject keeps its declared owner;
  - [x] the injection refuses an image that makes an injected path, or a
        directory on the way to one, a symbolic link or a name the host
        filesystem folds onto mvm's spelling, empties the mvm-only trees of
        image content, writes the files it creates (and the provenance mark)
        as fresh inodes, and checks the result by listing each directory;
  - [x] a deferred layer node at an injected path is refused rather than laid
        over the runtime's file;
  - [x] concurrent runs of one image no longer inject into its shared unpacked
        tree at once (a sealed image could be walked mid-way through a dev
        run's injection): every writer and copier of a tree takes its per-tree
        lock, the output is locked across materialization, and the
        overlay-lean staging tree is private per run;
  - [x] the builder-VM writer sets the claimed paths back to root after its
        copy;
  - [x] a builder-VM refusal names the route that reached it;
  - [x] owner and deferred-node sidecars are written atomically, and a corrupt
        one forces a re-unpack instead of a hard error.
- [ ] W3.8 Builder-VM input fidelity, found while closing W3.7. An image
      materialized through the builder VM does not keep the tree it was
      given:
  - [x] the work-input staging copied a symbolic link's host-resolved target
        instead of the link, so an absolute link in an image read a host file
        into the rootfs; staging and the input archive now carry links as
        links (#3430);
  - [x] the input tar recorded the host account's uid and gid for every file,
        and the guest extracted and copied them, so every path mvm does not
        claim was owned by the host account; the rootfs now reaches the builder
        as one archive the host writes with every entry owned 0:0 (#3430);
  - [x] the generic work-input staging dropped `node_modules`, `target`,
        `dist`, `.git` and `result*` at any depth (a node image lost
        `/usr/local/lib/node_modules`) and read special files (a FIFO hung
        the copy); the one-file archive passes through staging untouched and
        omits special files the way the in-process writer does (#3430);
  - [ ] on macOS the unpacker's hard-link fallback removes the link source,
        not the destination, when an earlier layer wrote it, and then refuses
        the link.

## W4 — Return freed guest memory on HVF (#3381)

**Problem.** HVF reports no balloon (`crates/mvm-backends/src/driver/hvf.rs:399`),
and guest RAM stays resident until teardown. The hypervisor pins every range it
maps into the guest, so advising the host that pages are free does nothing
while the range is mapped.

- [x] W4.1 Add a virtio-balloon device to the HVF device model (`crates/mvm-vmm`)
      that offers only free page reporting, plus `DEFLATE_ON_OOM`.
      `crates/mvm-vmm/src/vmm/virtio_balloon.rs`, at the MMIO slot and SPI
      after the entropy device. The reporting queue is index 2: the driver
      numbers only the queues whose features were negotiated, so stats and
      free page hinting would each move it up one; the device offers neither.
- [x] W4.2 For each reported range: unmap, release, remap, and only then
      acknowledge. Lazy remap on fault is ruled out: two vCPUs faulting
      together race, and that fault cannot be told apart from device access.
      The release is **not** `madvise(MADV_FREE_REUSABLE)`, which was built
      first and measured: it dropped the footprint, but when the guest
      refilled the memory it had freed the VM process showed 512 MiB of
      footprint against 1621 MiB resident — reused reusable pages are never
      charged back. The release maps fresh anonymous memory over the span
      instead, which frees the pages at once and charges them again on reuse
      (1611 MiB after the same refill). A span with no resident host page is
      skipped, so the report a fresh guest makes of its untouched memory costs
      no hypervisor calls. A span that cannot be remapped is never
      acknowledged and stops the device.
- [x] W4.3 Handle ranges that W5 backs with a copy-on-write file mapping.
      Such mappings already exist on `main` — the kernel image, and the whole
      of RAM on a restore from a memory blob — so this is live, not
      preparatory. `GuestRam` records each private file mapping; the device
      skips those parts of a report and still acknowledges it. A restored
      guest therefore returns no memory until W5 decides how its written
      pages should be reclaimed.
- [x] W4.4 Enable `VIRTIO_BALLOON` and `PAGE_REPORTING` in the guest kernel.
      No change: `nix/images/kernel/base.nix` already enables
      `VIRTIO_BALLOON`, which selects `PAGE_REPORTING` in 6.12, and a built
      workload config shows `CONFIG_PAGE_REPORTING=y` with
      `INIT_ON_FREE_DEFAULT_ON` and `PAGE_POISONING` off (either would make
      the driver drop reporting without `PAGE_POISON`). The kernel artifact is
      unchanged.
- [ ] W4.5 Advertise `balloon: true` for HVF, and let the existing
      `BalloonController` drive it. **Not done as written, on purpose.**
      `balloon` means host-driven inflate toward a target —
      `balloon_set_target`, and `mem_initial` booting pre-inflated — and the
      controller's only action is setting that target. A reporting-only
      device has no target, so `balloon: true` would be false and the
      controller would call a setter with nothing behind it. HVF instead
      advertises a new `free_page_reporting` capability, keeps `balloon`
      false, and the controller keeps skipping it, which is correct: reclaim
      happens without it. `mvmctl doctor` shows the two as separate columns.
      Target inflate on HVF would need a host-to-supervisor control channel
      and is not planned.
- [x] W4.6 Unit tests for the report queue: parsing, acknowledgement order,
      ranges that are misaligned or out of bounds. Plus zero-length, wrapping,
      straddling two regions, file-backed, untouched, the queue layout per
      feature set, failed unmap/release/remap, and device-state round trip.
- [x] W4.7 Live test: a 2 GiB guest allocates and frees 1.5 GiB, and the VM
      process's host footprint drops by at least 1 GiB within 30 s.
      macOS 26 Apple Silicon: 1610 MiB → 78 MiB, the first 1 GiB gone
      10.9 s after the free (main: 1613 MiB, no drop).
- [x] W4.8 Boot time does not regress. Twenty interleaved boots per build
      under host load ~170–210: `backend_start` median 926 ms on `main`,
      915 ms with the device; paired median difference +64 ms, the new build
      slower in 11 of 20 — within the noise of this host.

## W5 — Copy-on-write HVF restore (#3382)

**Problem.** `restore_bytes`
(`crates/mvm-runtime/src/backends/hvf/guest_ram.rs:90-100`) copies the whole
RAM section on every restore, so sibling children share no pages. The kernel is
already mapped `MAP_PRIVATE | MAP_FIXED` from its file in the same module.

- [ ] W5.1 Page-align the RAM section in the snapshot format.
- [ ] W5.2 After verification, map the RAM section `MAP_PRIVATE` at the guest
      address instead of copying it.
- [ ] W5.3 Make sure verified bytes cannot change underneath the mapping: map
      from a store the VM's user cannot write, opened with `O_NOFOLLOW`, or
      clone to a private file first.
- [ ] W5.4 Share pages only within one tenant's snapshots.
- [ ] W5.5 Record restore latency and resident size for 1 GiB and 4 GiB
      guests, before and after, in the PR.
- [ ] W5.6 Test: editing the snapshot file after restore does not change guest
      memory. The existing HVF restore and fork tests still pass.

## W6 — Memory and task limits at spawn (#3383)

**Problem.** `crates/mvm-core/src/cpu_scope.rs` puts a VMM spawn in a scope with
`CPUQuota=`, and only when a CPU share is granted. Nothing enforces a memory or
task ceiling, so the admission budget's memory charge is bookkeeping, not
enforcement.

- [x] W6.1 Put every VMM spawn in a scope carrying `MemoryMax=` (guest RAM plus
      a fixed overhead) and `TasksMax=`. Two spawns stay unscoped and are
      named in ADR-001's limit 6: the plan-less Firecracker harness entry and
      the macOS-only HVF rootfs-inject helper.
- [x] W6.2 Bound scope creation with a timeout.
- [x] W6.3 Read back the limits actually applied and audit them like the CPU
      tier. Record `declared` where the host has no scope mechanism.
- [x] W6.4 Update Preview claim 18's limits note in ADR-001 in the same change.
- [x] W6.5 Unit tests on the scope argv.
- [x] W6.6 Live test on a KVM host: a VMM pushed past its memory limit is killed
      and audited. Run against QEMU on an x86_64 KVM host; the probe and the
      emitter were driven directly, not through a full `mvmctl` launch.

## W7 — Chunked, parallel, durable checkpoints (#3384)

**Problem.** `crates/mvm-runtime/src/checkpoint/mod.rs` stores `memory.bin` and
`rootfs.ext4` as whole blobs, hashes them one after another in `verify_content`,
and never syncs blob copies.

**Scoped into its own plan:**
`specs/plans/2026-09-18-chunked-durable-checkpoints.md` (workstreams C0–C8).
The boxes below stay open until the chunked format ships. Its C0 has landed:
whole-blob capture is staged, synced and published with one rename, a failed
recapture no longer damages the checkpoint it was replacing, and
`verify_content` hashes blobs concurrently (one worker per blob, not per
chunk).

- [ ] W7.1 Split RAM and disk into 1 MiB SHA-256-keyed chunks. Record all-zero
      chunks in the index without storing them.
- [ ] W7.2 Give each checkpoint an index of chunk digests. Share objects across
      checkpoints so deleting one never breaks another.
- [ ] W7.3 Verify and hash chunks in parallel with the workspace `par_map`.
- [ ] W7.4 Restore by cloning the last restored file and rewriting only the
      chunks that differ.
- [ ] W7.5 Sync objects and the index, then the directory.
- [ ] W7.6 Anchor the index digest in the audit chain, so lineage verification
      is unchanged.
- [ ] W7.7 Dedup only within one encryption key domain.
- [ ] W7.8 Tests:
  - [ ] a second checkpoint of an idle machine adds under 10% of the first
        one's stored bytes;
  - [ ] a tampered chunk, a missing chunk, and a tampered index are each
        refused;
  - [ ] a crash injected between the object write and the index write leaves
        no checkpoint that verifies wrongly.

## W8 — Guest disk flush cost on HVF (#3385)

**Problem.** The virtio-blk device (`crates/mvm-vmm/src/vmm/virtio.rs`) serves
every guest flush with `sync_data`, which on the HVF host is a full device
flush, and it offers flush on every writable disk. We have never measured the
cost.

- [x] W8.1 Measure flush count and total flush time during a cold boot and a
      representative workload. Post the numbers on #3385.
      Measured on macOS 26 Apple Silicon under host load 250–320, isolated
      `MVM_HOME`, `alpine:3.20` workloads, N=5 per cell:
      - A cold workload boot sends **no** flushes. Every disk the HVF workload
        runner attaches is read-only (rootfs, verity, runtime overlay, identity
        drive), and a read-only disk does not offer flush.
      - A writable `--volume` disk doing 500 × (4 KiB write + fsync) sent 502
        flushes costing 3.1 s (median) of a 5.1 s workload. The same run with
        flushes served by `fsync(2)` spent 0.12 s in them (2.6 s workload); with
        flushes made no-ops, 2.0 s.
      - Bulk writes (256 MiB, fsync per 16 MiB) sent 18 flushes (0.21 s) and an
        untar of 5000 files plus `sync` sent 3 (0.05 s): below the noise.
      - One builder VM build sent 654 flushes costing 11.7 s over a 32-minute
        run on the nix-store disk, with a single flush taking up to 545 ms.
      - Host microbenchmark, 4 KiB write then sync: `F_FULLFSYNC` p50 4.9–5.7
        ms, `fsync(2)` p50 0.03–0.04 ms.
- [ ] W8.2 If the cost is material:
  - [ ] W8.2a stop offering flush on scratch disks that are thrown away at stop.
        **Not done: not material.** The scratch disks already cost nothing. An
        ephemeral disk is served from RAM, where a flush is a no-op, and the
        builder's per-job output disk sent zero flushes in a full build. The
        Stage 0 root disk is the one scratch disk left that still takes
        flushes. Stage 0 is a one-off bootstrap and was not measured.
  - [x] W8.2b serve guest flushes on persistent disks with a plain `fsync`, and
        keep the full flush for stop, checkpoint and snapshot.
        A guest flush on a writable file-backed disk is now `fsync(2)` on
        Apple hosts. On other hosts it stays `fdatasync`, which already is the
        cheap operation. A disk that took any write or discard gets exactly one
        full flush (`F_FULLFSYNC` on Apple) when the device is released at VM
        stop. Checkpoint and snapshot need no flush: HVF full-VM capture
        refuses a VM with any writable disk before asking the supervisor for
        anything, so there is no checkpoint of a writable disk to make durable.
        The trade is documented in the machine-limitations guide: a guest
        fsync survives a guest or VMM crash, but not a host power loss before
        the VM stops.
        Before/after, the two builds' supervisors interleaved in the same
        session (N=10 each, two batches of 5; median [min–max]):
        | | before | after |
        | --- | --- | --- |
        | 500 × fsync, guest workload | 6430 ms [4460–9200] | 2210 ms [1140–7190] |
        | same, whole run | 8238 ms [5701–10870] | 3880 ms [2049–12326] |
        | cold boot, whole run | 1430 ms [633–3423] | 1543 ms [1007–3246] |
        | cold boot, backend start | 643 ms [214–1175] | 654 ms [431–1577] |
        The cold-boot difference is noise: that path attaches no writable disk,
        so neither build flushes anything on it.
- [ ] W8.3 If the cost is not material, close #3385 with the numbers.
      Not applicable: the cost was material for writable persistent disks.
- [ ] W8.4 Tests:
  - [x] persistent-disk data survives stop and start. The device-level test
        writes through the virtio queue, releases the device and reads the
        bytes back from a fresh open. One live HVF check wrote a marker and an
        8 MiB random blob to a `--volume` disk in one `machine run` and read
        both back, with the same SHA-256, in a second run.
  - [ ] a checkpoint captured right after writes verifies after restore.
        Not applicable on HVF as the code stands. HVF full-VM capture
        refuses any VM with a writable disk, so no such checkpoint can exist,
        and no test can capture one. The test that stands in pins the refusal
        instead: a VM with a writable disk is refused before any snapshot
        request is written, and an all-read-only VM is admitted.

## W9 — Signed bundles through image registries (#3386)

**Problem.** `mvmctl bundle fetch` (`crates/mvm-cli/src/commands/bundle/fetch.rs`)
accepts only a path or an `https://` URL, and the registry client
(`crates/mvm-fs/src/oci/registry.rs`) can only pull.

- [x] W9.1 Add blob upload and manifest put to the registry client.
- [x] W9.2 `mvmctl bundle push <file> <ref>`: one artifact manifest carrying
      the `.mvmpkg` archive and its detached signature.
- [x] W9.3 `mvmctl bundle fetch <ref>` accepts tag and digest references, and
      re-hashes every manifest and blob fetched by digest.
- [x] W9.4 Trust decisions stay in `read_and_verify_bundle`; the registry is
      only a transport.
- [x] W9.5 `--prod` refuses a tag reference and requires a digest.
- [ ] W9.6 Align media-type naming with #3365. The push uses
      `application/vnd.mvm.bundle.v1` (`artifactType`) and
      `application/vnd.mvm.bundle.v1.tar` (layer), declared once in
      `mvm_contract::plan::bundle`. #3365 has not landed names yet; this box
      closes when its image-set manifest types are chosen consistently with
      these, or these are renamed to match.
- [x] W9.7 Tests: a push and fetch round trip against a local registry fixture,
      plus refusal of each of:
  - [x] a tampered blob;
  - [x] a tampered manifest;
  - [x] a manifest whose bytes don't match its digest;
  - [x] a tag reference under `--prod`;
  - [x] an unsigned or untrusted bundle.

## W10 — Agent-facing failures (#3387)

**Problem.** `tool_error` (`crates/mvm-mcp/src/lib.rs:719-727`) returns every
failure as plain text, although `MvmError` already classifies it. And
`mvmctl machine run <image-ref> -- <cmd>` treats a misplaced image reference as
the command, with no hint.

- [x] W10.1 Add a stable `code` and a `retryable` flag, derived from the
      `MvmError` variant, to every tool error's `_meta`.
- [x] W10.2 With no image source flag, refuse a first command word that parses
      as an image reference, and suggest `--image`.
- [x] W10.3 Refuse a known run flag placed after `--`, taking the flag list from
      the argument parser's own definitions.
- [x] W10.4 Tests:
  - [x] one tool server test per `MvmError` variant;
  - [x] CLI tests for both refusals;
  - [x] a colon-bearing command still runs when an image source is given.

## W10a — Review fixes for W10 (#3432)

**Problem.** The review of W10 asked for six changes that did not land with
it: the image-reference refusal ran after project detection, so detection
could win; `capabilities()` discarded the typed error; two tool-error paths
had no code; the flag-after-`--` check matched one spelling of one struct's
long flags; a real `app.d/run` path read as a registry host; and the code tests
compared the mapping against itself.

- [x] W10a.1 Run the image-reference refusal before any inference, with a
      test for the case where detection would have succeeded.
- [x] W10a.2 Carry the `code` and `retryable` flag through `capabilities()`
      into the JSON-RPC error's `data`, on both `tools/list` and `tools/call`.
- [x] W10a.3 Give the serialization and output-too-large paths their own codes
      (`INTERNAL`, `OUTPUT_TOO_LARGE`), and delete the uncoded builder, so
      `tool_error` now always takes a code and a retryable flag.
- [x] W10a.4 Split the flag token on `=`, include visible aliases, short
      flags, short clusters, attached short values and the global flags, and
      read the list from the command actually being run.
- [x] W10a.5 Do not treat a word as an image reference when it names an
      existing path, whether it carries a registry-host or a tag marker.
- [x] W10a.6 Assert literal code strings in the tool-server tests, and pin the
      `MvmError` code and retryable values in a wildcard-free `match`.

## Definition of done for each workstream

- [ ] `cargo fmt --all -- --check`, `cargo nextest run --workspace`,
      `cargo test --workspace --doc`, `cargo clippy --workspace -- -D warnings`
- [ ] `just check-gated` for any change to a shared type's shape
- [ ] `cargo run -p xtask -- check-all`
- [ ] ADR-001 ledger updated if a claim witness is added, renamed or changes
      scope
- [ ] This plan's checkboxes, `specs/SPRINT.md` and `specs/REFACTOR-STATUS.md`
      updated in the same change, and the issue closed
