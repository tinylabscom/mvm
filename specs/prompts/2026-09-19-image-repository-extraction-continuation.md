# Continue the image-repository extraction

Backing: preview
Validation: none — this is a session handoff, not a claim about the tree.

Paste the section below into a new session. Everything above the rule is
context for whoever is choosing what to work on next.

State captured 2026-09-19. Verify it before acting: `gh pr list`, `gh issue
list`, `git worktree list`, and `git log --oneline -20 origin/main` in both
`mvm` and the sibling `mvm-images` checkout. Several items moved while this was
being written.

---

Continue the image-repository extraction in tinylabscom/mvm and its sibling
tinylabscom/mvm-images. Follow AGENTS.md and CLAUDE.md exactly: worktree
workflow (never commit on main, never work in another session's worktree),
Definition of Done, reuse first, Rust best practices, no placeholders, no
plan/PR/issue references in code comments, no assistant attribution in commits
or PR bodies. The plan is
`specs/plans/2026-09-16-image-repository-extraction.md`; the rollups are
`specs/REFACTOR-STATUS.md` and `specs/SPRINT.md`, and each piece of work adds
`specs/sprint/delivery/<issue>-<slug>.md`.

## Where it stands

W1, W2 (governance half), W3 and W4a/W4b are done and merged. `mvm-images`
holds the image flakes, kernel, initramfs and QEMU-wasm pack, built from an
`mvm` commit pinned in one place, with a drift check against that commit, a
no-publish build workflow for both architectures, and a same-commit lane that
fails when a rebuild differs. `mvm` has one `images.lock`, an offline
`mvmctl image boot verify`, the `MVM_IMAGES_DIR` selector with `local-dev` and
`verified-release` tiers, a local-manifest reader, and a local image cache
(W5a–W5d).

W6 has moved further than the plan's checkboxes say: `mvm-images` has published
`image-set/v0.1.0`, `v0.1.1` and `v0.2.1` plus a `revocations` release, and
`crates/mvm-core/images.lock` on mvm main pins `image-set/v0.1.1` (proposed in
#3677), with the Stage 0 kernel on the same tag. Read the lock and the release
list before trusting any plan checkbox about publication.

## Pick up here

1. **Finish W4c (#3362).** The comparison against `boot-image/v0.1.5` is done
   and every difference is explained; see the delivery note
   `specs/sprint/delivery/3362-w4c-image-comparison.md`. Two witnesses are
   outstanding, and the box stays unticked until both land:
   - **aarch64 Firecracker boot.** Blocked on `rpi1.local`, which has not
     resolved on this LAN since 2026-09-19. Ask the user to power it on, or
     find another real aarch64 KVM host. Do not substitute a nested or
     emulated one and call it the witness.
   - **A completed HVF builder build.** A `nix build` through the
     mvm-images-built builder stalled after the host closed its egress
     connection, then spun to the 90-minute limit. That is issue #3522, and a
     fix is half-written (see the stalled branches below).
2. **W5e–W5m (#3364).** The slice list is in the plan's W5 section. W5e is the
   build verb plus the `bin/dev` wrapper; W5f–W5j move each in-tree image
   consumer onto the selector (the exact consumer list is in the plan's W4
   inventory); W5k makes admission read the recorded tier; W5l is docs and a
   two-repository example; W5m is the acceptance witnesses. Nothing may delete
   `nix/images` from `mvm` until W8.
3. **`mvm-images` issue #1, the no-publish dry run, together with W6.** It
   needs a manifest generator and a structure-and-completeness check for an
   **unsigned** candidate set. `mvmctl image boot verify` cannot serve that
   purpose: it refuses an unsigned or branch-signed set by design, and a lock
   may name a signing identity only at a tag ref. Decide that interface
   deliberately rather than loosening the verifier.
4. **Open issues from this work**, roughly in order of value: #3402
   (Firecracker Stage 0 on hosted runners — a fix is half-written, below),
   #3522 (HVF builder egress), #3524 (builder jobs boot a stale cached image),
   #3502 (Firecracker rewrites the cached dev rootfs), #3491 (the builder's
   host binaries are built by two different toolchains), #3492 (dead
   QEMU-wasm scripts), #3457 (fetch the published SDK sidecar when its
   fingerprint matches — blocked until published sidecars record that
   fingerprint, which is producer-side work in `mvm-images`).

## Stalled branches, committed but never opened as PRs

Three agents stopped mid-task on a session rate limit. Each has a real commit
in its worktree. Review the work rather than trusting these descriptions, then
run the gates, push, open a PR and take it through the merge queue.

- `fix/3402-fc-stage0-hosted`, worktree `.worktrees/mvm-3402-fc-stage0`.
  Commit `a9ede6f59b` plus uncommitted edits to `ci-full.yml`,
  `crates/mvm-backends/src/fc/{daemon,mod}.rs` and
  `tests/github_actions_extended_e2e.rs`, and an untracked delivery note. The
  root cause it reports: Firecracker put its API socket directly under the VM
  state dir, and a deep `MVM_HOME` pushes that path past the 107-byte
  `sun_path` limit, so Firecracker exits before creating the socket and the
  host only sees a socket that never appears. The fix routes the boot and
  control sockets through the same short hashed namespace every other per-VM
  socket already falls back to, and the uncommitted part moves the nightly
  `source-bootstrap-linux` witness back from QEMU to Firecracker. Verify that
  claim yourself — measure a path — before repeating it in a PR body.
- `fix/hvf-builder-egress-stall`, worktree `.worktrees/mvm-hvf-builder-stall`.
  Commit `9b822b0049`, "keep the HVF builder's FlowMux session alive, and fail
  instead of spinning when it is lost". Issue #3522 is filed. The branch is 13
  commits behind main and unpushed.
- Nothing else is outstanding: W5d merged as #3521, and #3511 (W5c) was closed
  because W5d carried its commits to main.

## Coordination with the builder-image plan

`specs/plans/2026-09-24-builder-image-without-host-bins.md` (another session,
branches `feat/builder-boot-payload`, `feat/builder-key-narrowing`) stops baking
mvm's Rust host binaries into the builder image and supplies them at boot from
mvmctl's own payload. Three agreed interfaces, as of 2026-09-25:

- **Cache key.** The builder image key becomes the resolved Nix inputs,
  including the mvm source closure the image actually compiles, rather than
  either repository's identity. Dropping the mvm commit from the key supersedes
  the extraction plan's "cache keys include both repository commits" item, which
  W5d implemented in its coarse form. `drvPath` keying is the intended end
  state. Note #3524: `ensure_builder_vm_image` does not consult the fingerprint
  at all yet, so a better key does not reach every builder path.
- **`builder_boot_abi`.** A new field in the image set's `[compatibility]`
  section: 1 means the host binaries arrive in the boot payload, 0 is the
  legacy baked image. The mvm side — the field, its validation, the
  `images.lock` plumbing, and a CLI that accepts both — belongs to that plan.
  This side owns emitting it from the release assembly and from
  `scripts/emit-local-manifest.py`, and dropping `MVM_HOST_BIN_DIR` from
  mvm-images' `images/builder-vm/image.nix` once a payload-supplying mvmctl is
  the pinned consumer. Those are two separate PRs in mvm-images, because the
  pin advance is its own change. `ImageSetCompatibility` carries
  `deny_unknown_fields`, so the two repositories must land in this order or a
  sibling pair build breaks: mvm teaches the schema the field as optional with a
  missing value meaning ABI 0 on both producers; then mvm-images emits it
  (`mvm-images#31`, ready and deliberately unqueued); then mvm flips a local set
  without the field to refused by name, which rides with W8. The emitter always
  writes the field — 0 while the flake still bakes, 1 in the same PR that drops
  `MVM_HOST_BIN_DIR` — so the release default only ever covers sets published
  before the field existed.

  The ABI-1 publish order is: publish the ABI-1 set from mvm-images, then an mvm
  PR re-pins `images.lock` to it with `xtask repin-image-lock`, which carries
  `builder_boot_abi` across. That re-pin is W8 and comes only after the
  payload-supplying mvmctl is on main.

  The published `image-set/v0.2.1` builder kernels already carry
  `CONFIG_BLK_DEV_INITRD=y`, `CONFIG_RD_GZIP=y` and `CONFIG_EXT4_FS=y` on both
  architectures, so the payload needs no kernel change. But none of those
  options is pinned in `kernel/base.nix` or `kernel/builder.nix` — they are
  inherited from nixpkgs while their `RD_*` neighbours are explicitly disabled —
  so pin them with a config test in the same change, in mvm first and then
  re-copied to mvm-images, or a nixpkgs bump can drop them and the failure
  arrives as a builder that cannot find PID 1.
- **W8.** Stage 0 stays a from-seed source build for contributors after
  `nix/images/builder-vm` is deleted. ADR-030 item 4 names that directory and
  "the in-repo flakes" explicitly, so W8 carries an explicit item amending it to
  the paired mvm-images checkout selected by `MVM_IMAGES_DIR`, leaving the
  no-silent-substitution and `source: fetched` rules unchanged.

## Traps this session hit

- **Do not stack a PR on another open PR in this repo.** The merge queue put
  the child ahead of the parent, and the child carried a stale copy of the
  parent's commit. W5d then merged its whole stack, and the parent PR had to
  be closed as redundant. Land one, rebase the next with `git rebase --onto`.
- **`check-all` is not the CI gate list.** Also run `check-declared-backing`
  (plus `--self-test`), `check-nextest-groups`, `check-single-workload-env`,
  `check-dormant-controls`, `check-cli-help-matches-docs` and
  `just check-gated`.
- **The pre-commit hook runs workspace clippy, 10+ minutes.** Commit from a
  detached `nohup` script and poll for a marker. Never bypass hooks; a hook
  also blocks a command containing both `git commit` and any `-n` flag (for
  example `git grep -n`), so keep them in separate commands.
- **A preview-backed document may not use assertive words** such as "proves";
  `check-declared-backing` fails on it.
- **Disk and load on the Mac are shared with other sessions.** The volume hit
  under 1 GB free during this work. Use one target directory per worktree,
  delete it when finished, and run Linux builds on the Hetzner box. Never
  `pkill` by pattern; kill only the PIDs you started.
- **Rollup files conflict on nearly every rebase.** Keep both sides.
- `git stash` is shared across worktrees. Don't use it.

## Hosts

- Hetzner x86_64 KVM: `ssh -o BatchMode=yes -o StrictHostKeyChecking=no -i
  ~/.ssh/hetzner-mvm root@88.99.197.234`. Make your own clone; `/root/mvm`
  belongs to other sessions. No system Nix — a static nix with a chroot store
  was used for image builds.
- rpi1 (`auser@rpi1.local`), the only real aarch64 KVM host, is off the
  network as of 2026-09-19.
- macOS 26 Apple Silicon, this machine, is the HVF witness.
