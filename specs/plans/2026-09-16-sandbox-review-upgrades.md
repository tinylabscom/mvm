# Upgrades found by reviewing an external microVM sandbox

Backing: preview
Validation: none — no workstream has started. Each workstream names the tests
and live evidence required before its checkbox may be ticked.

**Issues:** #3378 (W1) · #3379 (W2) · #3380 (W3) · #3381 (W4) · #3382 (W5) ·
#3383 (W6) · #3384 (W7) · #3385 (W8) · #3386 (W9) · #3387 (W10)

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
  copy-on-write file mappings.
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
- [ ] W1.2 Force an immediate reseed. Decide between:
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
- [ ] W1.5 Live test: two clones of one snapshot return different `getrandom`
      output immediately after restore.

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

- [ ] W3.1 Record each tar entry's uid and gid during unpack
      (`crates/mvm-fs/src/oci/unpack/`), in a side table keyed by path.
- [ ] W3.2 Add owner fields to `Node`, and write the low and high uid/gid
      inode fields.
- [ ] W3.3 Include ownership in `fingerprint_ext4_nodes`
      (`crates/mvm-fs/src/rootfs.rs`).
- [ ] W3.4 Keep host-directory walks (`--mount`) normalized unless a caller
      asks for ownership.
- [ ] W3.5 Tests:
  - [ ] a layer file owned 999:999 round-trips;
  - [ ] a uid above 65535 round-trips through the high fields;
  - [ ] changing only an owner changes the fingerprint.
- [ ] W3.6 Live test: an image whose service data directory is owned by a
      non-root account starts that service.

## W4 — Return freed guest memory on HVF (#3381)

**Problem.** HVF reports no balloon (`crates/mvm-backends/src/driver/hvf.rs:399`),
and guest RAM stays resident until teardown. The hypervisor pins every range it
maps into the guest, so advising the host that pages are free does nothing
while the range is mapped.

- [ ] W4.1 Add a virtio-balloon device to the HVF device model (`crates/mvm-vmm`)
      that offers only free page reporting, plus `DEFLATE_ON_OOM`.
- [ ] W4.2 For each reported range: unmap, `madvise(MADV_FREE_REUSABLE)`, remap,
      and only then acknowledge. Lazy remap on fault is ruled out: two vCPUs
      faulting together race, and that fault cannot be told apart from device
      access.
- [ ] W4.3 Handle ranges that W5 backs with a copy-on-write file mapping.
- [ ] W4.4 Enable `VIRTIO_BALLOON` and `PAGE_REPORTING` in the guest kernel.
- [ ] W4.5 Advertise `balloon: true` for HVF, and let the existing
      `BalloonController` drive it.
- [ ] W4.6 Unit tests for the report queue: parsing, acknowledgement order,
      ranges that are misaligned or out of bounds.
- [ ] W4.7 Live test: a 2 GiB guest allocates and frees 1.5 GiB, and the VM
      process's host footprint drops by at least 1 GiB within 30 s.
- [ ] W4.8 Boot time does not regress.

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

- [ ] W6.1 Put every VMM spawn in a scope carrying `MemoryMax=` (guest RAM plus
      a fixed overhead) and `TasksMax=`.
- [ ] W6.2 Bound scope creation with a timeout.
- [ ] W6.3 Read back the limits actually applied and audit them like the CPU
      tier. Record `declared` where the host has no scope mechanism.
- [ ] W6.4 Update Preview claim 18's limits note in ADR-001 in the same change.
- [ ] W6.5 Unit tests on the scope argv.
- [ ] W6.6 Live test on a KVM host: a VMM pushed past its memory limit is killed
      and audited.

## W7 — Chunked, parallel, durable checkpoints (#3384)

**Problem.** `crates/mvm-runtime/src/checkpoint/mod.rs` stores `memory.bin` and
`rootfs.ext4` as whole blobs, hashes them one after another in `verify_content`,
and never syncs blob copies.

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

- [ ] W8.1 Measure flush count and total flush time during a cold boot and a
      representative workload. Post the numbers on #3385.
- [ ] W8.2 If the cost is material:
  - [ ] W8.2a stop offering flush on scratch disks that are thrown away at stop;
  - [ ] W8.2b serve guest flushes on persistent disks with a plain `fsync`, and
        keep the full flush for stop, checkpoint and snapshot.
- [ ] W8.3 If the cost is not material, close #3385 with the numbers.
- [ ] W8.4 Tests:
  - [ ] persistent-disk data survives stop and start;
  - [ ] a checkpoint captured right after writes verifies after restore.

## W9 — Signed bundles through image registries (#3386)

**Problem.** `mvmctl bundle fetch` (`crates/mvm-cli/src/commands/bundle/fetch.rs`)
accepts only a path or an `https://` URL, and the registry client
(`crates/mvm-fs/src/oci/registry.rs`) can only pull.

- [ ] W9.1 Add blob upload and manifest put to the registry client.
- [ ] W9.2 `mvmctl bundle push <file> <ref>`: one artifact manifest carrying
      the `.mvmpkg` archive and its detached signature.
- [ ] W9.3 `mvmctl bundle fetch <ref>` accepts tag and digest references, and
      re-hashes every manifest and blob fetched by digest.
- [ ] W9.4 Trust decisions stay in `read_and_verify_bundle`; the registry is
      only a transport.
- [ ] W9.5 `--prod` refuses a tag reference and requires a digest.
- [ ] W9.6 Align media-type naming with #3365.
- [ ] W9.7 Tests: a push and fetch round trip against a local registry fixture,
      plus refusal of each of:
  - [ ] a tampered blob;
  - [ ] a tampered manifest;
  - [ ] a manifest whose bytes don't match its digest;
  - [ ] a tag reference under `--prod`;
  - [ ] an unsigned or untrusted bundle.

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

## Definition of done for each workstream

- [ ] `cargo fmt --all -- --check`, `cargo nextest run --workspace`,
      `cargo test --workspace --doc`, `cargo clippy --workspace -- -D warnings`
- [ ] `just check-gated` for any change to a shared type's shape
- [ ] `cargo run -p xtask -- check-all`
- [ ] ADR-001 ledger updated if a claim witness is added, renamed or changes
      scope
- [ ] This plan's checkboxes, `specs/SPRINT.md` and `specs/REFACTOR-STATUS.md`
      updated in the same change, and the issue closed
