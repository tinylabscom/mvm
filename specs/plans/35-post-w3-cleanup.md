# Plan 35 — Post-W3 cleanup + cross-backend parity

> Status: ready to implement
> Owner: Ari
> Parent: closes the long tail from `specs/plans/25-microvm-hardening.md` (W3)
>          and `specs/runbooks/w3-verified-boot.md` (post-fix observations)
> ADR: `specs/adrs/002-microvm-security-posture.md`
> Estimated effort: ~1 week (4 PRs, each independently mergeable)

## Why

The W3 verified-boot work landed (plan 27, all 5 runbook steps green
on Lima/aarch64), but the live boot exposed loose ends that don't
fit inside W3 itself:

1. Two **pre-existing init-script defects** that crashloop services
   in production rootfs builds. They didn't manifest before W3
   because `mvmctl up` against templates was breaking earlier in the
   boot path (Firecracker's `root=/dev/vda` clobber); now that
   verity boots cleanly, the rootfs-side defects are visible.
2. **No snapshot/restore round-trip** has been re-run since W3
   added `/drives/verity` and the `initrd_path` to the Firecracker
   `/boot-source` request. The wiring is in place but unverified.
3. The **Apple Container path** has `start_with_verity()` wired
   but only Firecracker has live-tested it. The boot logic is
   identical, but the runbook doesn't have a §3.5 entry for VZ.
4. The verification runbook is **operator-driven**. There's no
   automated regression — a future change that breaks W3 won't
   surface until the next time someone runs the runbook by hand.

Plan 35 closes all four. It's a cleanup sprint; no new
architecture, no new ADRs.

## Threat shape addressed

None new. This plan upholds existing ADR-002 claims that the W3
work created the infrastructure for but doesn't yet *continuously
verify* in CI. Specifically:

- Claim #2 ("no guest binary can elevate to uid 0") relies on
  W2.3 setpriv. The setpriv defect (C1.2) means the guest agent
  has been crashlooping under setpriv on every verity boot —
  setpriv is technically still preventing escalation, but the
  agent is failing to start, which is its own incident shape.
- Claim #3 ("a tampered rootfs ext4 fails to boot") is verified
  manually today; C4 turns it into a `just w3-live-test` recipe
  + a CI-runnable script.

## Sub-items

### C1 — init-script defects exposed by W3 live boot

Two unrelated bugs surfaced in the same boot session:

#### C1.1 — `/etc/nsswitch.conf` bind-mount fails with ENOENT

`nix/lib/minimal-init/lib/04-etc-and-users.sh.in` stages
`/etc/{passwd,group,nsswitch.conf}` via `/run/mvm-etc/*` symlinks,
then later `rm -f` + `touch` + `mount --bind` to promote them to
read-only bind-mounts. The bind step succeeds for `passwd` and
`group` but fails for `nsswitch.conf`:

```
mount: mounting /run/mvm-etc/nsswitch.conf on /etc/nsswitch.conf failed: No such file or directory
mount: can't find /etc/nsswitch.conf in /proc/mounts
```

Hypothesis (needs confirmation while debugging): the symlink-then-
rewrite-through-symlink dance leaves `/run/mvm-etc/nsswitch.conf`
in an inconsistent state for one of the three files because the
write happens *through* the symlink while the others are written
directly after `rm -f`. The clean fix is to drop the symlinks
entirely and write content to `/run/mvm-etc/*` directly, then bind
on top of empty `/etc/*` targets. Eliminates the failure mode
without restructuring the init.

**Files**

- `nix/lib/minimal-init/lib/04-etc-and-users.sh.in`: refactor to
  write content into `/run/mvm-etc/*` paths with no intermediate
  symlinks. The `chown $user:$group $home` calls that motivated
  the symlinks (line 12-14 comment) need a separate fix — write
  user/group entries to `/run/mvm-etc/{passwd,group}` then bind-
  mount before any `chown` runs, OR use numeric uid/gid in chown.

**Tests**

- Boot regression: re-run the W3 runbook Step 3 inside Lima, grep
  for `mount: … failed`. Expected output is silence.
- Add an init-time sanity check after the mount loop:
  `for f in passwd group nsswitch.conf; do
     mountpoint -q /etc/$f || echo "[init] WARN: /etc/$f not bind-mounted" > /dev/console
   done`. The warning ought to print zero lines on a healthy boot.

#### C1.2 — `setpriv` flag conflict in `mkServiceBlock` + agent launch

`util-linux`'s `setpriv(1)` rejects the combination
`--clear-groups --groups=…` as mutually exclusive (along with
`--keep-groups` and `--init-groups`):

```
setpriv: mutually exclusive arguments: --clear-groups --keep-groups --init-groups --groups
```

Both the agent launcher (`nix/lib/minimal-init/default.nix::guestAgentBlock`)
and the per-service launcher (`mkServiceBlock`'s `setprivPrefix`
non-explicit branch) set `--clear-groups --groups=...`. The fix is
to drop `--clear-groups`: `--groups=N1,N2,…` already replaces the
supplementary group set with exactly the listed gids. The combination
was redundant; util-linux rejects it because it's ambiguous which
side wins.

**Files**

- `nix/lib/minimal-init/default.nix`:
  - `guestAgentBlock`: drop `--clear-groups`.
  - `setprivPrefix` (non-explicit branch, ~line 281): drop
    `--clear-groups`.

**Tests**

- Boot regression: same Lima re-run as C1.1, grep for
  `setpriv: mutually exclusive`. Zero matches expected.
- Add a one-shot guest-agent launch test in
  `nix/images/default-tenant/` that asserts the agent process
  reaches "ready" within 5 seconds of boot (currently it
  crashloops indefinitely).

#### Sequencing for C1

Both fixes are one-line edits. Land as a single PR; the boot
regression covers both at once. Estimate: ½ day.

### C2 — Verity snapshot/restore parity

`mvm-runtime/src/vm/microvm.rs::configure_flake_microvm_with_drives_dir`
adds `/drives/verity` and `initrd_path` to the Firecracker
configure-VM API call. Firecracker snapshots serialize the active
VM's drive list and boot-source. We have not re-run a template
snapshot/restore since W3, so the open questions are:

1. Is `/drives/verity` captured in the snapshot's drive metadata,
   and does Firecracker re-attach it on restore?
2. Is the dm-verity device-mapper state (the in-kernel verity
   target built by `mvm-verity-init`) preserved across snapshot?
   The initrd memory is freed after `switch_root`, so on restore
   there's no userspace component to rebuild the dm device.
3. If the kernel's dm-state IS preserved, restore "just works."
   If NOT, we need a recovery path — a small in-rootfs binary
   that re-applies the verity target on receipt of a post-restore
   signal (W2 already has the `PostRestore` vsock RPC).

**Approach**

Test first. Boot a verity-enabled template, snapshot it, restore
it from another mvmctl invocation, and inspect:

- `mount` inside the restored guest: does `/` still show
  `/dev/dm-0`?
- `ls /sys/block/dm-0`: is the verity device still active?
- Does the restored guest survive `cat /etc/passwd` (a verity
  read)?

If all three pass, this work item closes with a regression test
and a doc note. If any fails, scope grows to include the
`PostRestore`-handler verity-resume code.

**Files**

- `crates/mvm-runtime/tests/verity_snapshot_restore.rs` — new
  integration test, gated on Linux/KVM availability (skip on
  macOS). Builds a transient verity template, snapshots,
  restores, asserts `/dev/dm-0` is still root.
- `specs/runbooks/w3-verified-boot.md`: add §6 "Snapshot
  round-trip" with the manual procedure.

**Tests**

The snapshot/restore test itself is the regression. Run it in
Lima as part of `just w3-live-test` (see C4).

**Estimate**: 1-2 days. Could grow to 3 if dm-state isn't
preserved across snapshot — that's the investigation we owe
upfront.

### C3 — Apple Container live-boot smoke

`crates/mvm-apple-container/src/macos.rs::start_vm` calls
`setInitialRamdiskURL` and passes `mvm.roothash=` on the cmdline
when `VerityConfig` is present. The wiring is symmetric with the
Firecracker path. We haven't run it live because the dev VM
(`mvmctl dev up`) uses `verifiedBoot = false`, and we haven't had
a production-mode microVM booted via Apple Container.

**Approach**

Build a verity-enabled template on Lima, copy the artifacts to
the macOS host's `~/.mvm/templates/<id>/revisions/<rev>/`, and
boot via:

```bash
mvmctl up --hypervisor apple-container --template <verity-tmpl>
```

The first run will likely surface a small set of missing wiring
(perhaps the prebuilt-image copier doesn't currently move
`rootfs.initrd` alongside `rootfs.{ext4,verity,roothash}`). Fix
those, capture the boot log, and add §3.5 to the runbook.

**Files**

- `crates/mvm-cli/src/commands/env/apple_container.rs`: ensure
  `download_default_microvm_image` (or wherever the prebuilt
  copy lives) picks up `rootfs.initrd` when present.
- `specs/runbooks/w3-verified-boot.md`: §3.5 "Apple Container
  smoke" with the captured boot log.

**Tests**

Manual; the runbook is the test.

**Estimate**: ½ day if the wiring is intact, 1 day if a missing
copy step shows up.

### C4 — Live-KVM regression automation

The runbook is operator-driven today. C4 makes it a single
command that operators (or CI) can run:

```bash
just w3-live-test           # full runbook in Lima
just w3-live-test --tamper  # only the tamper step
```

The recipe wraps the existing runbook commands (`nix build`,
`firecracker --no-api`, log-grep) into a script that exits
non-zero on any step failure. Output captures the boot log so
operators can re-read it after the fact.

**CI integration**

GitHub-hosted Linux runners don't expose `/dev/kvm` by default.
Two options:

1. **Self-hosted runner** with KVM access. Right answer
   long-term; out of scope for this sprint.
2. **Soft-gated CI lane** that runs the script *if* `/dev/kvm`
   is present, skips otherwise. Lets operators run on a self-
   hosted runner without blocking sprint close on infra.

C4 ships option 2. The `security.yml` workflow gains a
`live-verity-boot` lane that's skipped on standard runners but
enforced on tagged self-hosted runners.

**Bonus: A.2 v2 latency comparison**

Sprint 43 deferred a "cold-boot vs warm-VM latency" test
(claude-code-vm) for the same Linux/KVM-required reason. Since
C4 sets up the infrastructure, it folds in cleanly. Adds:

```bash
just mcp-warm-vm-latency
```

That times a snapshot-restore (warm) vs a fresh boot (cold)
against `claude-code-vm`. Reuses C4's KVM detection.

**Files**

- `scripts/w3-live-test.sh` — one script, commented step-by-step
  to mirror the runbook.
- `justfile`: `w3-live-test`, `mcp-warm-vm-latency` recipes.
- `.github/workflows/security.yml`: `live-verity-boot` lane,
  conditional on `[ -e /dev/kvm ]`.

**Tests**

The script itself is the regression. CI proves it runs end-to-
end on any KVM-capable runner.

**Estimate**: 1-2 days.

## Sequencing

C1 → C2 → C3 ‖ C4. C1 unblocks the rest by making the boot
log noise-free; C2 has investigation depth that may extend the
sprint; C3 is the lightest item and slots in opportunistically;
C4 is independent and can land first or last.

PR sequence:

1. **PR-A**: C1 (init-script defects). Single PR, both fixes.
2. **PR-B**: C2 (snapshot/restore parity). Includes a new
   integration test + runbook §6.
3. **PR-C**: C3 (Apple Container live-boot smoke). Tiny PR;
   could be folded into PR-B if both are small.
4. **PR-D**: C4 (live-KVM regression automation). Self-
   contained.

## Out-of-sprint follow-ups (parked, not blocked on this sprint)

These stayed on the backlog at sprint 42 close but don't fit
under "post-W3 cleanup." Mentioning them so they're tracked
somewhere:

- **mkNodeService → buildNpmPackage** (deferred from W7.4 in
  plan 31). Output-layout-changing swap; needs a Linux builder
  validation against `hello-node` first.
- **L7 egress runtime backing** (sprint 43). Sized as its own
  sprint in plan 34.
- **Hosted MCP transport (HTTP/SSE)** (plan 33). Cross-repo
  work; lives in mvmd.
- **`scripts/check-prod-agent-no-exec.sh` Nix examples**
  cleanup — `nix/images/{paperclip,openclaw}/` deletion blocked
  by sandbox in W7.1; needs manual `git rm`.

## Acceptance criteria

Sprint closes when:

1. ✅ A fresh `mvmctl up` against a verity-enabled template
   boots cleanly with no `mount: failed` or
   `setpriv: mutually exclusive` warnings on the console.
2. ✅ A snapshot of a verity-enabled VM restores into a working
   verity-protected guest (or, if dm-state isn't preserved,
   the recovery path is implemented).
3. ✅ `mvmctl up --hypervisor apple-container` boots a verity
   template on macOS — runbook §3.5 has captured logs.
4. ✅ `just w3-live-test` passes in Lima end-to-end.
5. ✅ `security.yml::live-verity-boot` lane runs (skipped on
   public runners, enforced where KVM is available).

## Reversal cost

Low for all four items. C1 is an init-script edit; rollback is
git revert. C2/C4 add tests, no runtime behavior change. C3 is
runbook docs + a small wiring fix.

## Non-goals

- New W-workstream additions to ADR-002. Plan 25 is closed.
- Hosted CI infrastructure (self-hosted KVM runners, etc.).
  C4 ships the script + soft-gated lane; provisioning real
  runner capacity is operator work.
- Touching the snapshot wire format. C2 investigates and
  patches in-place; if dm-state preservation requires Firecracker
  patches, that's a separate plan.
