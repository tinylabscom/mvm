# Remove virtio-fs

Backing: shipped-source
Validation: check-sprint-append

**Status: IN PROGRESS — Stages A, B and D landed, and Stage C has taken every
backend it can reach without live hardware. Both builders are on the disk
transport, the host-side `virtiofsd` daemon is deleted (and with it the
`--sandbox none` flag this plan opened on), QEMU now *refuses* a spec carrying
shares rather than ignoring one, and the HVF backend can no longer express a
share at all. `check-no-virtio-fs` is down from 46 sites across 14 files to 38
across 10.

Four items remain, and none is a tidy-up. The largest is that **libkrun's
Stage 0 still boots a virtio-fs root** — the plan's headline is not yet true of
that path. The others: the libkrun persistent builder's shares, the guest's
install arm, and the HVF VirtioFs device with its 1,108-line FuseServer and fuzz
target. Two of the four need live hardware to validate.

The end state is **FFI-only rows, not zero**: 16 of the remaining sites declare
libkrun's C API, which exports `krun_add_virtiofs` whether or not we call it,
and three more are the `VirtioFsShare` type plus the QEMU and Firecracker tests
that assert a share is *refused*.

No guest gets a virtio-fs device. Not a workload, not the builder VM, not the
dev-tier root. The host filesystem reaches a guest as a block image or it does
not reach it at all.

## Why, beyond the flag that started this

The immediate finding was `crates/mvm-vmm/src/host/virtiofsd.rs:253`:

```rust
.args(["--sandbox", "none"])
```

— virtiofsd's own namespace/seccomp confinement, disabled, with no comment, no
ADR, and no mention in the commit that introduced it (`e54fd9769e`). The C
flavour passes no `-o sandbox=` at all.

But the flag is a symptom. virtio-fs puts a FUSE server on the host — in a
daemon for QEMU, in the VMM's address space for libkrun and HVF — and points it
at a host directory. Every request it parses comes from the guest. That is a
large, guest-driven parser sitting on the wrong side of the boundary, and it is
the one mechanism by which a guest addresses host filesystem *structure* rather
than opaque blocks. A block device is a byte array with no protocol for a guest
to attack.

This also removes the awkwardness in claim 1. "No host-fs access from a guest
beyond explicit shares" currently rests on virtio-fs behaving; afterwards the
shares are images, and the claim rests on the guest having no channel to the
host filesystem at all.

## What already points this way

- **Firecracker refuses virtio-fs outright** and has a test for it
  (`fc.rs::boot_rejects_virtio_fs_shares`). The Linux production workload path
  is already clean. This plan makes every backend match the one that is right.
- **The builder already migrated its largest share to a disk.**
  `pack_stage0_work_disk` copies the workspace tree, materializes an ext4 image
  with a volume label, and attaches it as virtio-blk — because "`nix build`
  reading a large workspace tree through virtio-fs-over-FUSE exhausts libkrun's
  virtio-fs handle pool". Different motive, same destination, and the machinery
  is written.
- **`--mount` is already read-only.** `exec.rs` refuses rw:
  "`--mount '{spec}'` requests rw, but transient live shares are read-only". So
  the only property a materialized image loses is *host edits becoming visible
  mid-run*, which a read-only mount consumed at boot barely has.
- **The timing surface already has slots for the replacement.**
  `mount_fingerprint`, `mount_cache_lookup` and `mount_materialize` are declared
  in `SubPhase`, rendered by the report, and have **no producer**. The comment
  says they exist because "a content-addressed mount image is what records
  them". Someone designed this and did not build it.

## Stages

Ordered by security value per unit of work. Each stage leaves the tree shippable.

### Stage A — workloads

The whole security argument lives here: an untrusted guest driving a FUSE
server. Everything below this is our own code.

**This stage is a deletion, not a feature.** Both halves of the fork already
exist and both are wired end to end:

```rust
pub enum LocalVolumeKind {
    /// Legacy host directory exposed only by backends with directory sharing.
    #[default]
    Directory,
    /// Portable ext4 image attached as a virtio block device.
    BlockImage { size_mib: u32 },
}
```

`as_vm_volume` maps those to `VmVolumeKind::DirShare` and `VmVolumeKind::Disk`.
The code already calls one legacy and the other portable. The work is removing
the legacy arm, not building the portable one.

- [x] `--mount <host>:<guest>` is materialized into an ext4 image by
      `mvm_build::rootfs::materialize_ext4_pure` and attached as virtio-blk.
      The volume stays `DirShare` so admission still records a *directory*
      grant; the new `VmVolume.materialized_image` carries what is attached.
      Landed as `feat(mount): deliver a granted directory as a block image`.
- [x] The guest mounts by volume label rather than by the device node
      `workload_volume_devices` resolves. `VmVolume.volume_label` is set from
      the same authority that stamps the image, carried to the guest on
      `VolumeConfig`, and preferred over the node — with resolution failure
      **fatal rather than a fallback**, since falling back to the slot is the
      silent wrong-device mount this exists to stop.

      The resolver is `flowmux_drive`'s, not a new one: it already enumerated
      from `/sys/class/block`, checked the ext4 magic before trusting the label
      field, and was the decoder the writer's stamp is tested against. The first
      draft of this change hand-rolled a second superblock parser over a guessed
      `/dev/vd[a-z]` range and was replaced.

      Only `--mount` images are labelled, so only they mount by label; managed
      volumes carry `None` and keep the node path explicitly. Live-validated on
      macOS 26 by reading `s_volume_name` off the image while the VM ran
      (`magic 53ef`, `label mvmmnt0`) — a passing mount alone would not have
      shown which path ran.
- [x] `refuse_unsupported_dir_shares` and both its call sites deleted: every
      backend can serve a mount now, so it could only produce a false refusal.
- [x] Deleted: the `supports_directory_shares` trait method (every driver
      answered the same thing once mounts materialize), HVF's override and its
      advertised `directory_shares` capability, the `directory_shares` field on
      `VmCapabilities`, the two-arm `ensure_dir_share_support`, and
      `workload_shares`' volume arm. 85 lines out, 10 in.
- [ ] `VmVolumeKind::DirShare` and `LocalVolumeKind::Directory` stay for now:
      `DirShare` is what records a *directory* grant in the plan, which claim 1
      matches against, so removing it means moving that fact somewhere else
      first. `VirtioFsShare` also stays — its only remaining producers are the
      dev-tier root (Stage B) and the builder VM (Stage C).

      **Designed out into its own plan:**
      `specs/plans/2026-09-02-retire-dirshare.md`. The fact lives in
      `enforce_admitted_shares`, which derives the `ShareKind` it demands from
      the runtime enum; the resolution is to derive it from
      `materialized_image` instead and keep `ShareKind::DirShare` in the signed
      plan. The blocker is that `LocalVolumeKind::Directory` can still produce
      an *unmaterialized* `DirShare`, so what a managed directory volume is has
      to be settled first.

**Custom volumes are unaffected.** A managed volume is already a
`BlockImage`/`Disk` today. Nothing about `mvmctl volume` changes.

**Deliberately not in this stage:** content-addressing and caching of the
materialized image. The `mount_fingerprint` / `mount_cache_lookup` /
`mount_materialize` spans exist for it and have never fired, so the slot is
there — but adding a cache is the "heavy new feature" this work is supposed to
avoid. Land the deletion, measure a cold `--mount`, and only then decide
whether a cache is worth its own plan.

**Semantic change to document, not hide:** a mount becomes a snapshot taken at
boot. Host edits during the run are not visible. Say so in `--mount --help` and
the README. The gap is small because `--mount` is already read-only — `exec.rs`
refuses rw with "transient live shares are read-only" — so the only lost
property is mid-run visibility.

### Stage B — the dev-tier root

**Evidence it costs nothing in practice:** across this host's entire recorded
history — 1,278 launches — the audited `root_strategy` is `block-ext4` **1,278
times and virtiofs-root zero times.** The dev-tier root was reachable in
principle and taken never.

- [x] Virtiofs-root is unreachable. `resolve_virtiofs_root` — the single
      authority, gating on backend capability x prod x sealed — is deleted, and
      the strategy is `BlockExt4` unconditionally. The security-posture ADR
      already called this a weaker contract that does not witness claim 3; it
      was the one boot mode that could not be dm-verity sealed.
- [x] `ImageSource::Prebuilt`'s virtiofs candidate became
      `unpacked_oci_root: Option<String>`. The field was doing double duty:
      besides feeding the gate, it was the only thing distinguishing an
      OCI-derived prebuilt from the cached dev image, and the two take
      different initrds. Deleting it outright would have quietly given every
      prebuilt the OCI initrd, and no test would have caught that —
      `only_an_oci_derived_prebuilt_resolves_the_oci_initrd` covers it now.
- [x] Deleted the machinery below the gate, in five units so a mistake is one
      `git revert`: the driver bootargs arm and `VIRTIOFS_ROOT_TAG`; the
      `VmStartConfig` field and `workload_shares`; the `VmCapabilities` flag
      with `select_root_strategy` and `RootStrategy::VirtiofsRoot`; and the HVF
      device model's root channel — its MMIO slot, the `mvmroot` tag the driver
      lifted out of the share list, the restore path's inheritance of it, and
      `MVM_HVF_VIRTIOFS_ROOT`, an env hook in `mvm-hvf-supervisor` that booted
      a virtio-fs root without going through the run-path gate at all.
- [x] `RuntimeSourceRootStrategy::VirtiofsRoot` **stays**, deliberately. It is
      not a boot mode — it is a value recorded on a warm-pool parent's on-disk
      spec. A parent warmed before this change still declares what it was
      warmed under, and the compat check has to be able to read that and refuse
      it. Deleting the variant would turn a clean refusal into a deserialization
      failure. Nothing produces it.

### Stage C — the builder VM

Largest, least security value: the builder runs our own Nix builds, and my
memory note already separates dev-builder from prod tiers. It is in scope
because the goal is *nowhere*, not *nowhere that matters*.

Remaining shares are `work`, `out`, `job`, `mvm-bins` and the closure seed.

**`out` is already solved, and this plan was wrong about it.** The decision it
said to make — ext4 reader vs vsock stream — was moot before it was written.
`mvm_build::builder_disk_transport` is a **raw tar written straight onto a disk
image, no filesystem on the transport disk**: the host packs a tar and the guest
`tar x`es it; the guest packs artifacts and the host `tar x`es them. Both sides
only ever run `tar`, so no host-side ext4 reader is needed — which is exactly
why it was built, since HVF's host is macOS and macOS can neither format nor
read an ext4. tar's end-of-archive marker stops extraction before the disk's
zero padding, so a fixed-size disk carrying a shorter archive round-trips.

**The one-shot builder already uses it** (`libkrun_builder.rs` packs the input
disk and reads the output disk; `builder_spec` lays out four disks in vda–vdd
order and asks for no shares). What is left is narrower than "the builder VM":

- [x] `work`, `job`, `mvm-bins` — inbound. Done for the one-shot builder via
      the disk transport; `work` was already done on Stage 0.
- [x] **The closure seed is done now.** This box used to claim it was done while
      `prepare_builder_transport_disks` passed a hardcoded `None` and both
      transport sites attached the NAR over virtio-fs a few lines later. Both
      now pass `self.closure_nar.as_deref()` and attach no share, so the
      one-shot libkrun builder boots with an empty `virtio_fs_mounts` list —
      verified against the supervisor config a live `--builder libkrun` run
      wrote, not just its exit status.

      `run_stage0_impl` keeps its share deliberately: Stage 0 boots a virtio-fs
      *root* and has no transport disks, so it predates this seam rather than
      lagging it.

      **The live run could not exercise the closure-carrying arm.** No builder
      pack on the dev host emits a `nix-closure.nar`, so
      `closure_nar_for_host_arch()` is `None` and old and new code produce
      identical bytes. That arm is unit-tested instead
      (`prepare_transport_disks_lands_the_closure_under_its_fixed_name`), which
      also pins the rename to `CLOSURE_FILE` — a differently-named source
      landing under its own name would make the guest's import a silent no-op.
**The guest is already most of the way there.** `mvm-host-vm-init` has a
complete disk-transport mode, selected by `mvm.builder_transport=disk` with
`mvm.builder_input=` / `mvm.builder_output=` naming the devices:
`stage_disk_transport_input` extracts `job`/`work`/`mvm-bins`/`closure-seed`
off the raw input disk and bind-mounts them at the same paths the shares used,
and `setup_modules_and_virtiofs` skips every virtio-fs mount when it is active.
The one-shot builder runs this way today. Nothing new has to be invented — the
persistent case just does not use it yet.

No protocol change is needed either. The input disk is a raw tar the host can
rewrite between dispatches; the guest re-reads it with `tar xf` per dispatch, so
`Run.job_dir_relpath` keeps working and stays pointing into `/job`. Sequencing is
already safe: the host finishes writing before it sends `Run`, and V1 serializes
dispatches behind the supervisor's mutex.

> **Re-scoped against the tree. Read this before the five boxes below.**
>
> The recipe that follows targets the `HostVmRequest::Run` shell-job dispatch.
> **A build does not take that path any more.** `dev_build.rs` says so in as
> many words — *"The legacy in-VM shell-job dispatch was removed; typed is the
> only persistent path"* — and routes through `try_typed_persistent_build`,
> where a reachable `mvm-builderd` builds `/work#<attr>` and **exports its
> artifacts into `/job/<uuid>/out`**, which the host then reads from the host
> side of that same share. `PersistentBuilderSupervisor::submit` still exists
> and is still called by the hidden `mvmctl persistent-builder` subcommand, but
> migrating it would move a path no build takes while leaving the live one on
> virtio-fs.
>
> **Two more corrections to this stage's framing:**
>
> *The blast radius is far smaller than stated.* The box below claiming "the
> persistent builder is what `mvmctl build` uses on macOS 26+" is wrong.
> `HvfPersistentHostVm` has exactly one caller, `mvmctl persistent-builder`,
> declared `#[command(hide = true)]`. `dev_build` routes through it only when a
> session record exists *and* residency policy allows, and **any** dispatch
> failure falls back to the single-shot builder — which the code itself calls
> "the safety net". This is opt-in, hidden, and already has a fallback.
>
> *The inbound half is not separately shippable.* "Move `work` and `mvm-bins`
> to the input disk, keep `/job` as a share" is not expressible:
> `mvm.builder_transport=disk` is all-or-nothing in the guest.
> `setup_modules_and_virtiofs` skips **every** virtio-fs mount when it is set,
> because in that mode the host declares no tags at all and each attempt would
> fail with "tag not found". A hybrid needs a guest change and an image rebuild.
>
> **Superseded on the spec side: the migration landed in #3061**, concurrently
> with this analysis and independently of it. `persistent_builder_spec` declares
> no shares, the two builder cmdlines collapsed into one vda–vdd contract, and
> `check-no-virtio-fs` dropped `builder_runner/spec.rs` from its table. The
> paragraph that stood here — "the remaining work is a protocol question,
> resolve before writing code" — was true of the tree it was written against and
> is not true now. It is struck rather than deleted so the reasoning survives:
> the question it posed (how a typed export returns artifacts without a writable
> host directory) is the one #3061 answered with `repack_dispatch_input` /
> `read_dispatch_artifacts` on the CLI dispatch path.
>
> **What this analysis got right and #3061 did not cover:** the typed
> `dev_build` route is a *second* consumer of `/job`, and #3061 does not touch
> `dev_build.rs`. `try_typed_persistent_build` still stages into
> `record.job_dir` on the host and tells the daemon to export to
> `/job/<uuid>/out`, with a comment that still calls it "the session's `/job`
> share". Whether that path still works against a disk-transport session, or
> silently reads an empty artifact dir and falls through to the single-shot
> safety net, is **open and worth checking before relying on the persistent
> builder for a real build**. Tracked separately; the fallback means a failure
> here costs build time rather than correctness.
>
> The two framing corrections above stand: the blast radius really is a hidden
> opt-in subcommand with a fallback, and the guest's transport token really is
> all-or-nothing.
>
> Everything below is preserved as the original recipe, and is accurate only for
> the `Run` dispatch path it was written against.

Five coordinated changes, host and guest:

- [x] `persistent_builder_spec`: replace the four shares with an input and an
      output disk, and add the three transport cmdline tokens. The two cmdlines
      collapsed into one — a persistent builder now boots the same contract as
      a one-shot, `vda`–`vdd` in the same order, so `PERSISTENT_BUILDER_CMDLINE`
      and its runtime-overlay device constant went with the shares.
- [x] `repack_input_disk_in_place` — **landed**. A persistent builder rewrites
      its input disk between dispatches, and `pack_input_disk` cannot do it: it
      calls `set_len`. A running VM's `DiskImage` captures the file length
      **once, at open**, and zero-fills reads past it — so growing the file hands
      the guest an archive it reads as short, and `tar` reports success on it.
      The in-place form never changes the length and refuses an archive that
      will not fit, because refusing is the only way that failure is visible.
- [x] `HvfPersistentHostVm::start`: `pack_input_disk` the boot-time inputs
      (`work`, `mvm-bins`, closure seed) and `create_output_disk`. Both helpers
      already exist and are what the one-shot builder calls. `job` is packed
      too, carrying only `dispatch.sock.marker`: its presence in the archive is
      what makes the guest bind `/job`, and the marker is what makes it enter
      the dispatch loop rather than run one job and power off.

      `work` is filtered through `stage_filtered_work_input` first, as the
      one-shot pack filters it. Packing the raw tree put 45 GB of `target/` on
      the input disk, filled the 64 GiB store image mid-extraction, and left
      every later boot failing at `setup_nix_store` — a failure naming neither
      the disk nor the cause. `mvmctl cache repair --store-only` recovers.

      The capacity is fixed for the VM's life, so the boot pack sets the size
      every later repack has to live inside. Per-dispatch repacks carry only the
      `job` tree (the guest bind-mounted `work` and `mvm-bins` at boot and never
      re-reads them), so they are always far smaller than the boot pack.
- [x] **Readiness has to move, and connect-polling is NOT the answer.** The host
      waits for the guest by polling for a `dispatch.ready` file *inside the
      `/job` share* (`wait_until_dispatch_ready`). With no share the host cannot
      see that marker at all.

      The obvious replacement — connect to the dispatch UDS and treat success as
      readiness — is wrong, and the repo already knew it. `hvf.rs`'s agent probe
      says so in as many words: *"Probe the authenticated RPC stream directly;
      this waits for a real guest response rather than treating the host-side
      listener as readiness."* Confirmed live: the backend binds that UDS during
      VM setup, before the guest boots, and the bridge only closes the
      connection when the *guest kernel* answers `OP_RST` — so early in boot a
      probe neither connects-and-fails nor gets refused. It hangs open and reads
      as ready.

      This plan offered two fixes: add a `Ping`/`Pong` pair (a wire change on
      both sides, so a second guest change and a second image rebuild), or delete
      the wait and let the first dispatch prove readiness (moves the failure out
      of `start()`).

      **What shipped is a third option that costs neither:** a round trip on an
      existing request — `submit_workload_status` for the nil UUID. Any
      well-formed reply, a `not_found` report or a typed failure, proves the loop
      is accepting and framing. No protocol surface is added, and the
      fail-fast-on-dead-VM diagnostics stay in `start()` where they were.
- [x] Host dispatch client: repack the input disk with the new job payload
      before each `Run`, and `read_output_disk` into the artifact dir after each
      `Result` — rather than once after poweroff. Both dispatch clients are
      wired: `PersistentBuilderVm::run_build` (what `mvmctl build` uses) and the
      `persistent-builder submit` verb. The repack pads back up to the disk's
      current length, because the guest's virtio-blk driver read that capacity
      at boot and cannot renegotiate it.
- [x] **A fifth change the plan missed, and the one that would have shipped
      broken.** The guest collects `/out` and only `/out` onto the output disk,
      but both host stagers rendered a `cmd.sh` writing to `/job/<job_id>/out` —
      which under the disk transport is the guest's own input stage, never read
      back. A build would have reported success and produced nothing. The
      guest-visible artifact dir is now chosen per transport
      (`guest_artifact_dir`), and the host reads the output disk into the same
      `artifact_dir_for` path a share-backed session writes to, so every caller
      downstream is transport-blind.

      The guest's **install** arm has the same shape and no host-side fix: it
      hardcodes `/job/<job_id>/out`. Rather than lose a claim-11 sealed volume's
      SBOM and CVE sidecars silently, an install dispatch on a disk-backed
      session is refused with a message naming the missing half.
- [x] Guest dispatch loop: re-stages `/job` from the input disk on each `Run`
      and collects `/out` onto the output disk after each job — the collection
      previously ran only on the one-shot path, since `run_dispatch_loop`
      returns straight into `power_off()`. `/out` is reset per dispatch for the
      reason the boot path documents: otherwise the host reads back a tar of
      every artifact any earlier dispatch left, including dangling `result-*`
      symlinks that fail extraction outright. Only the `job` member is
      re-extracted; `work` and `mvm-bins` do not change between dispatches.

      `clear_dir_contents` is new, and is why this could not reuse
      `reset_stage_dir`: that one removes and recreates the directory, which is
      right at boot and wrong afterwards, because `/job` and `/out` are
      bind-mounted onto those inodes. Orphan the bind and every later write
      lands somewhere nothing reads, silently. A test pins the surviving inode.

      **Runs only in the Linux test lane.** The guest bin is `cfg`-gated, so
      these tests compile on macOS via `just check-gated` but execute in CI.
- [x] **Cannot be validated in CI**, though it is validatable by hand: every
      guest-booting lane skips on hosted runners, so this needs a real Apple
      Silicon run. The rest of this box was wrong and is struck — the persistent
      builder is **not** what `mvmctl build` uses on macOS 26+. It is a hidden,
      opt-in subcommand with a single-shot fallback, so a break here degrades to
      a slower build rather than a broken one. **Done:** two `nix build`
      dispatches into one session on macOS 26.5.2, both exit 0.
- [x] **Sequence the guest half first.** `mvm-host-vm-init` is cross-compiled and
      baked into the builder rootfs, so a guest change only takes effect after
      the image is rebuilt. Landing the guest's per-dispatch staging while the
      host still declares shares is inert — disk transport stays off — which
      makes it separately validatable and removes version skew from the host
      flip. Flipping the host first against an old baked guest hangs the
      dispatch loop with no useful error. Done: the guest half shipped first,
      and the builder image must be rebuilt before this host flip is exercised.
- [x] **The persistent builder's network endpoint did not outlive the command
      that spawned it.** Fixed. The cause was not a leak or a missing detach —
      `spawn_network_endpoint` already calls `setsid`. It is
      `mvm_hostd::parent_death::exit_when_orphaned`, armed in the endpoint's own
      `main`: it watches its parent and exits cleanly (status 0, hence the
      silence) the moment it is reparented. That is deliberate — the endpoint
      holds a workload's secrets in the clear and must not serve as an orphan —
      and a persistent session is the first case where the VM outlives its
      spawner, so parent-death stopped being a good proxy for VM-death.

      The endpoint is now spawned by the **supervisor**, whose death *is* the
      VM's, so the guard keeps enforcing the property it exists for. It carries
      no key material: the endpoint's config needs the host signer by value and
      `supervisor.json` is persisted beside the VM, so the supervisor mints the
      FlowMux identity itself from the same `~/.mvm/keys/host-signer.ed25519`
      the config already names by path elsewhere, and writes the identity drive
      before opening disks. The policy and the empty secret set are fixed at
      that call site, so nothing on the wire can widen them, and a restored
      child never inherits the request (it names the parent's VM, socket and
      drive).

      Verified live: the endpoint stays up with the supervisor as its parent,
      serves the guest's egress through a whole `nix build`, and self-reaps when
      the supervisor exits.
- [x] **The HVF vsock idle eviction severed the dispatch connection.** Fixed,
      and it was in **two** layers, which is why fixing one was not enough:
      `host_dial_bridge::evict_idle_at` closes the host socket, and the
      transport's credit table (`vsock_transport::evict_idle_connections_at`)
      sends the guest an `OP_RST`. Exempting the port in the bridge alone still
      let the transport tear the stream down — observed live as the guest
      logging `write StderrChunk failed` while its build ran to completion.

      Idle eviction is now per guest port in both layers, with the builder's
      control ports exempt and console data ports still evictable. What makes
      that safe is that idle was never the mechanism that reclaims a dead peer —
      `drain_host`'s EOF arm is, and it still runs for every connection. Idle
      only ever described a stream that is alive and quiet, which for a
      request/response control channel is indistinguishable from working.

- [x] **The QEMU builder needs the same migration, and the plan missed it.**
      **Landed.** Both one-shot sites are on the disk transport; the `virtiofsd`
      spawn loops, the `memory-backend-memfd` + `-numa` object and the
      `vhost-user-fs-pci` loops are gone, along with `qemu_shares_with_closure_seed`
      and `qemu_virtiofs_socket_path`. Three things the recipe below did not
      predict, recorded because each would have cost a debugging session:

      1. **The cmdline half is one delegate swap.**
         `qemu_runtime_overlay_attachment` forwarded to
         `builder_virtiofs_runtime_overlay_attachment`; pointing it at
         `builder_runtime_overlay_attachment` emits `mvm.runtime_data=/dev/vde`
         *and* all three transport tokens, because
         `builder_runtime_overlay_cmdline` wraps `builder_disk_transport_cmdline`.
         The vde move and the transport tokens are the same edit, not two.
      2. **`work` has to go through `stage_filtered_work_input` first.** QEMU
         shared `job.work_dir` / `mounts.flake_src` directly, which on a source
         checkout is the repo root. A share tolerates that; a tar does not —
         libkrun stages a filtered copy precisely because `target/` + `.git/` +
         `.worktrees/` overflow the guest's RAM-capped extraction tmpfs.
      3. **A test asserted the trap.** `qemu_runtime_overlay_keeps_virtiofs_transport`
         asserted `mvm.runtime_data=/dev/vdc` and the *absence* of the transport
         tokens — it would have stayed green while the guest mounted the input
         tar as its runtime overlay. Now
         `qemu_runtime_overlay_rides_the_disk_transport_at_vde`, asserting the
         vde token and the absence of the vdc one.

      Original entry, for the record:

      `qemu_builder.rs` serves `work` / `out` / `job` / `mvm-bins` over
      vhost-user/virtiofsd — not the disk transport — and QEMU is the *Linux
      auto-detect default builder*. So this is not the "opt-in dev/test backend
      we can just delete the feature from": deleting its shares breaks every
      Linux build. It needs the same treatment as the persistent HVF builder,
      and the guest side already supports it, so it should be mostly a spec and
      client change. It is separately validatable on the Linux/KVM box, which
      makes it the better of the two to do first.

      **Recipe, mapped against the tree.** Both QEMU sites are one-shot
      (`run_shell_script_qemu` ~L1005 and `run_build_qemu` ~L1279 in
      `qemu_builder.rs`), so this is the simple migration, not the persistent
      one — no in-place repack, no per-dispatch staging. Two private helpers in
      `libkrun_builder.rs` already do the work and need only widening to
      `pub(crate)`: `prepare_builder_transport_disks` (packs the input disk,
      creates the output disk) and `extract_builder_transport_output`.

      Per site: build `[job, work, mvm-bins]` `InputTree`s the way
      `libkrun_builder.rs` does at L1132 and L1654, call the prep helper, attach
      the two images as ordinary `-drive`s, drop the `virtiofsd` spawn loop, the
      `memory-backend-memfd` + `-numa` object (it exists only because
      vhost-user-fs requires a shared memory backend whose size equals `-m`),
      and the `vhost-user-fs-pci` device loop, then extract from the output disk
      after QEMU exits.

      **Disk order matters and should match the one-shot spec exactly**: vda
      rootfs, vdb nix-store, vdc input, vdd output, vde runtime overlay,
      identity last. That is what the guest's cmdline defaults
      (`mvm.builder_input=/dev/vdc`, `mvm.builder_output=/dev/vdd`) and
      `BUILDER_RUNTIME_DEVICE=/dev/vde` already assume. Today QEMU puts the
      runtime overlay at vdc, so it moves — update the `mvm.runtime_data=` token
      from `qemu_runtime_overlay_attachment` to match. The identity drive is
      found by ext4 label, not slot, so it is unaffected.

      **The open closure-seed question, answered: it maps straight across, with
      a step removed rather than added.** `closure_share_dir` is not a share of
      anything durable. `stage_closure_seed_dir` copies a single file into
      `<vm_state_dir>/closure-seed/<CLOSURE_FILE>` and returns the wrapper
      directory; the wrapper exists only because virtio-fs shares directories
      and not files, which its own doc comment says. The source is already a
      file — `builder_pack::closure_nar_path(cache/<arch>)`, which QEMU computed
      *before* staging — and that is exactly what `pack_input_disk`'s
      `closure_nar` takes, archiving it at the same fixed
      `closure-seed/<CLOSURE_FILE>`. So the QEMU path passes the NAR straight to
      the transport and drops both `stage_closure_seed_dir` and
      `qemu_shares_with_closure_seed`.

      **The premise above was wrong, and the wrong part matters more than the
      question.** libkrun does not pass `None` because it has no closure:
      `builder_backend_select.rs` gives every libkrun builder
      `with_closure_nar(closure_nar_for_host_arch())`.
      `prepare_builder_transport_disks` hardcoded `None` because the closure was
      **left on virtio-fs** — the one-shot transport paths still call
      `closure_seed_share` and `add_virtio_fs(CLOSURE_SEED_TAG, …)` alongside
      their transport disks. The helper now takes a real `closure_nar` and
      libkrun's two sites pass `None` explicitly, with a comment saying why.
      See the corrected checkbox at the top of this stage.

- [x] The QEMU **workload** driver's share arm is a different matter and *is*
      free: workload specs carry `shares: Vec::new()` unconditionally since
      Stage A, so `qemu.rs`'s share handling is unreachable for workloads.
      **Deleted — but as a refusal, not a silent drop.** `QemuDriver::boot` now
      bails on a non-empty `spec.shares`, mirroring Firecracker's
      `boot_rejects_virtio_fs_shares`, because a driver that quietly ignores a
      share it was asked to serve hands the guest a VM missing a filesystem it
      expected. `argv_carries_no_virtio_fs_or_shared_memory_backend` pins the
      absence of the `-object`/`-numa` pair, which existed only because
      vhost-user-fs needs a shared memory backend sized to `-m`.

- [x] `crates/mvm-vmm/src/host/virtiofsd.rs` is **deleted**, along with its
      re-export from `mvm-build`, the module declaration, and `mvm-vmm`'s
      `which` dependency — which the manifest's own comment said was there for
      "binary lookup for host-side helpers (virtiofsd)" and which had no other
      user. With it goes the `--sandbox none` flag that started this plan.
      There was no `virtiofsd` dependency in the Linux install docs to remove;
      that line of the plan described a doc that does not exist.

      The ratchet does **not** drop to FFI-only rows yet — that needs libkrun's
      seeded closure and the remaining dead plumbing below. With the persistent
      HVF builder also on the disk transport, it went from 54 sites across 15
      files to **41 across 13**.
- [ ] The **libkrun** persistent builder still serves `work`/`mvm-bins`/`job`/
      `out` as shares (`libkrun_builder.rs`). Its VMM has virtio-fs, so nothing
      forced the move; the session record already carries the two-state
      distinction (`disk_transport: Option<…>`), so flipping it is a matter of
      packing disks in `LibkrunPersistentHostVm::start` and recording them.
- [ ] The guest's **install** arm writes to `/job/<job_id>/out`, which the disk
      transport does not collect. Point it at `/out` like the flake arm, then
      drop the refusal in `PersistentBuilderVm::run_install_dispatch`. Needs a
      guest change and therefore an image rebuild.
- [x] Now-dead HVF share **wiring**: `HvfVirtioFsShare` and its config field,
      the `hvf.rs` mapper, the supervisor's pass-through, the restore path's
      copy, and `kernel_boot.rs`'s FDT nodes + device construction. The HVF
      backend can no longer express a share at all, so the device is unreachable
      by construction rather than by policy.

      **The MMIO hole stays, deliberately.** `RNG_MMIO_BASE`/`RNG_IRQ` are
      computed from `FS_MMIO_BASE`/`MAX_VIRTIOFS_SHARES`; collapsing the range
      would silently move the entropy device to a different address and SPI,
      changing the device tree a guest boots against and the layout a saved
      snapshot was captured under. The constants are now documented as a
      reserved hole, and `RNG_MMIO_BASE` derives *from* it so the dependency is
      stated once instead of restated. Same address as before.
- [x] The `virtio.rs` VirtioFs MMIO **device**, its test suite, the 1,108-line
      `virtio_fs.rs` FuseServer, and that module's fuzz target. **Done.**

      The strongest form of this plan's argument: the fuzz target's own premise
      was *"the VirtioFs device hands guest-supplied bytes straight to
      `FuseServer::dispatch`; the guest is untrusted, so a byte pattern that
      panics the parser is a guest-triggerable host DoS."* That premise is false
      once no device hands it guest bytes — so the parser is deleted rather than
      fuzzed, and the DoS surface is removed rather than defended. The FUSE
      parser was cited as a witness in neither ADR-001 nor `model/claims.toml`,
      so the ledger is untouched.

      Went with it: the `RunDevice` impl, the shared-memory-region MMIO
      registers (a DAX-window concern, virtio-fs only), sixteen FUSE/FS
      constants, the differential reference-walk test suite, the
      `security.yml` fuzz step, and the fuzz crate's lockfile entry. The
      workflow gate's target floor moved 15 → 14, with a note that the floor
      guards against the parser failing to resolve targets rather than
      mandating a count.

### Stage D — the gate

Landed **before** Stage C rather than after, as a ratchet. Waiting for the
surface to reach zero before gating it meant the removal was unprotected for
exactly as long as it took to finish — and the finishing is the slow part.

- [x] `xtask check-no-virtio-fs`. It counts only sites that **attach a device or
      construct a share** (`add_virtiofs*`, `VirtioFs::new`/`with_tag`,
      `VirtioFsShare {`, `HvfVirtioFsShare {`, `krun_add_virtiofs`), with
      comments and strings blanked first. The word-matching version the plan
      originally described would have fired on ~70 files that merely discuss
      virtio-fs, and could have been satisfied by rewording a comment instead of
      deleting code.
- [x] **The first pattern was blind to two spellings, and the QEMU builder
      migration lowered no count because of it.** The libkrun C symbol is
      `krun_add_virtiofs`, but the safe wrapper is `add_virtio_fs` — with an
      underscore — so a pattern written for the C name walked past all 21 Rust
      call sites in `context.rs`, `libkrun_builder.rs` and `libkrun_process.rs`.
      Worse, the QEMU *builder* attached its shares through neither: it spawned
      `virtiofsd` and passed a `vhost-user-fs-pci` device, so `qemu_builder.rs`
      was not in the table at all and deleting ~60 lines of its wiring moved
      nothing. The device name is a string literal, which
      `blank_comments_and_strings` blanks before matching, so the spawn side is
      caught by `VirtiofsdGuard` / `locate_virtiofsd` instead. Widening took the
      gate from 23 sites across 11 files to **54 across 15** — 31 attach sites
      it could not see, including every one this stage is removing.
- [x] Pinned at **54 sites across 15 files**, each row carrying why it survives
      and what retires it. The count must match exactly: a new site fails as
      growth, and a *removed* one fails as a stale pin, so the table can only
      shrink and cannot drift into a ceiling nobody maintains. Four rows from
      the first draft turned out to be comment-only and were dropped — the gate
      caught them itself.
- [x] Added to `check-all`, which runs on every PR (`ci.yml`). Four tests ship
      with it, including one asserting the pattern still matches every real
      attach form: a gate that cannot fail is decoration.

## What this costs

- **Every `--mount` pays a materialization**, proportional to the tree, until
  something caches it. The `$PWD:/work` in this project's own README is a large
  tree. This cost is **unmeasured** — measure a cold `--mount` before deciding
  whether a cache is needed, rather than building one on the assumption.
- **It does not touch the launch budget.** `PREPARED_COLD_HARD_MAX_MS` is 200ms
  on the *dispatch window* (`backend_start + vsock_wait`), and the mount spans
  are parented to `drives`, which is outside it. A launch with no `--mount` is
  unchanged, and a custom volume is already a block image.
- **Stage C is smaller than "weeks"** — that estimate assumed `out` needed a
  new mechanism, and it does not (see Stage C). What is left is one transport
  swap on the persistent builder. The cost is not code volume; it is that no CI
  lane can witness it.
- **The QEMU workload driver may simply lose directory shares** rather than gain
  images — it is opt-in dev/test and `auto_select` never picks it, so it is the
  one place where deleting the feature outright is defensible.

## Stopgap — **moot, do not do this**

The stopgap was to restore virtiofsd's sandbox because that was a one-line
change and Stages A–C were not. Both boxes are struck: `virtiofsd.rs` is gone,
so there is no `--sandbox` argument left to pass and no flavour left to pass it
to. Doing this work now would reintroduce the file.

- [x] ~~`--sandbox namespace` for the Rust flavour, explicit
      `-o sandbox=namespace` for the C one.~~ Struck: the spawn helper that
      built these arguments no longer exists.
- [x] ~~**Needs Linux validation before it lands.**~~ Struck with the box above;
      nothing left to validate.

`specs/plans/2026-08-31-virtiofsd-sandbox-parity.md` is the standalone plan for
this same stopgap and is superseded for the same reason.
