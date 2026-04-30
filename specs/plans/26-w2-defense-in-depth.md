# Plan 26 — W2: defense in depth inside the guest

> Status: ✅ shipped 2026-04-30 (W2.1, W2.2, W2.3, W2.4)
> Owner: Ari
> Parent: `specs/plans/25-microvm-hardening.md` §W2
> ADR: `specs/adrs/002-microvm-security-posture.md`
> Estimated effort: 2-3 days  · actual: 1 day

## Why

After W1, the *outside* of the guest is locked down (proxy socket
0700, port allowlist, default seccomp `standard`). The *inside* is
still soft: every service runs as the shared uid 900 in
`serviceGroup`, `/etc/passwd` is tmpfs-writable at runtime,
`busybox su` doesn't drop capabilities or set `no_new_privs`, and
syscall filtering is host-side advisory rather than wired through to
the guest's per-service launches. A buggy or compromised service
today gets full guest-side authority over its sibling services and
their secrets.

W2 turns each of those layers from "trust" into "enforce."

## Threat shape addressed

A malicious or compromised service inside a microVM:

- must not read another service's secrets (W2.1: per-service uid +
  per-service `/run/mvm-secrets/<svc>/` mode 0400).
- must not write to `/etc/passwd`/`/etc/group` to mint a uid 0 entry
  for itself (W2.2: bind-mount-ro after init writes them).
- must not regain capabilities or escalate via setuid binaries
  (W2.3: `setpriv --no-new-privs --bounding-set=-all`).
- must not call syscalls outside the tier its image was built with
  (W2.4: per-service seccomp filter applied via
  `setpriv --seccomp-filter`).

## Scope

In: changes to `nix/minimal-init/`, the rootfs lib fragments, and
`pkgs.util-linux` joining the production guest closure (`mkGuest`).
Tests live in `crates/mvm-build/` for the Nix-side rendering plus a
new test rootfs under `nix/examples/` that exercises the four
guarantees.

Out: dev VM exemptions (the dev VM intentionally runs everything as
root with no seccomp; W2 changes the *production* path and leaves
the dev VM untouched). Anything that requires a hypervisor change
(W3 verity).

## Sub-items

### W2.1 — Per-service uid

**What**

`mkServiceBlock` in `nix/minimal-init/default.nix` currently emits a
shell block that runs `su -s sh -c '<cmd>' ${svcUser}` where
`svcUser` defaults to `serviceGroup` (uid 900). Replace this with a
per-service identity:

- A unique uid: `1000 + (sha256(name) modulo 8000)` so the function
  is deterministic and collision-free for plausible service names.
- A unique primary group with the same id as the uid (per-user
  group convention).
- Membership in `serviceGroup` (uid 900) so existing flakes that
  rely on the secrets-share invariant still see secrets owned
  `root:serviceGroup` mode 0440 and gain read access via group.

`mkUserBlock` already supports a custom group; the change is
generating one entry per service whether the user supplied it or
not. Existing `mvm-guest-agent` user (uid 901) remains separate.

**Per-service secrets**

Today section 5 of init copies `/mnt/secrets/*` to
`/run/mvm-secrets/`, chowns root:serviceGroup mode 0440. That means
every service in `serviceGroup` reads every secret. Tighten:

- For each declared service `svc-name`, init creates
  `/run/mvm-secrets/svc-name/`.
- Files matching `/mnt/secrets/svc-name.*` (or a config-drive
  manifest `secrets-manifest.json` mapping service → secret list) get
  copied into the service's per-svc dir, mode 0400 owned by the
  service's uid:gid.
- The legacy `/mnt/secrets/` view stays mode 0440 for back-compat
  with flakes that expect the shared-group model; add a deprecation
  warning printed once at boot.

**Files**

- `nix/minimal-init/default.nix`: derive `svcUid`, `svcGid`,
  `svcGroup` from `name`, expose them to `mkServiceBlock`. Update
  `userBlocks` to include service-as-user entries.
- `nix/minimal-init/lib/04-etc-and-users.sh.in`: extend the user
  block to add per-service entries before the bind-mount-ro lands
  (W2.2 must run after).
- `nix/minimal-init/lib/06-optional-drives.sh.in`: split the
  secret-copy loop into per-service subdirs.

**Tests**

- Nix-eval test in `crates/mvm-build/tests/` that asks `mkGuest` for
  a 3-service image and asserts the rendered init contains three
  distinct `setpriv --reuid <N>` lines with distinct N values.
- Boot-time regression test (gated on Linux/KVM CI lane): boot a
  microVM with two services, assert that each can't read the
  other's secrets dir (`stat -c %a` returns 0400 + uid mismatch
  → EACCES).

**Compat / migration**

- A flake that defines no `services` is unchanged; uid 900 stays
  the default for the implicit "background" runtime.
- A flake that defines `services.<name>.user = "myuser"` keeps
  using the explicit user (we don't override). The auto-uid only
  applies when `user` is omitted.
- Document the migration in `CLAUDE.md`'s next update (W6.2).

### W2.2 — `/etc/{passwd,group,nsswitch}` read-only after init

**What**

Init currently writes these files directly into the live rootfs's
`/etc/`. After the writes, a compromised service running as uid 0
could rewrite them. We can't `chattr +i` on tmpfs, and we don't
want to make the rootfs's `/etc` itself read-only (it ships
config-drive symlinks that need to land here at boot). Solution:

1. Init writes the resolved files to `/run/mvm-etc/passwd`,
   `/run/mvm-etc/group`, `/run/mvm-etc/nsswitch.conf` instead of
   `/etc/passwd` etc.
2. After all writes (and after the user blocks from W2.1), init
   `mount --bind -o ro /run/mvm-etc/passwd /etc/passwd` and ditto
   for group + nsswitch.conf.
3. The tmpfs-backed source files at `/run/mvm-etc/` remain
   writable but are not what name resolution reads — that's the
   bind-mounted ro view.

A compromised process can `umount` the bind only with
`CAP_SYS_ADMIN`, which W2.3's bounding-set drop denies. Even if
something does manage it, the `nosuid` mount option for the rootfs
denies setuid escalation.

**Files**

- `nix/minimal-init/lib/04-etc-and-users.sh.in`: redirect writes
  to `/run/mvm-etc/`, then bind-mount ro at end of section.
- `nix/minimal-init/lib/08-signal-handlers.sh.in`: post-restore
  must umount the bind before re-running the writes, then
  re-mount. Add three `umount /etc/<file>` lines before the
  config-drive remount.

**Tests**

- Boot-time regression: `mount` output inside a microVM contains
  three `bind` lines for the three files; `cat >> /etc/passwd`
  fails with EROFS.
- Snapshot/restore test: send SIGUSR1, verify the bind is
  re-established and `mount` still reports the three bind lines.

### W2.3 — `setpriv` for service launch

**What**

Replace the current `su -s ${bb}/bin/sh -c '${svc.command}'  ${svcUser}`
in `mkServiceBlock` with:

```sh
setpriv \
  --reuid ${svcUid} --regid ${svcGid} \
  --clear-groups \
  --groups ${svcGid},${serviceGroupGid} \
  --bounding-set=-all \
  --no-new-privs \
  --inh-caps=-all \
  -- ${bb}/bin/sh -c '${svc.command}'
```

Each flag matters:

- `--reuid` / `--regid`: become the service uid/gid (no setuid
  binary required; setpriv itself isn't setuid, it just calls
  setresuid/setresgid as PID 1 root).
- `--clear-groups` / `--groups`: explicit supplementary group set;
  membership in `serviceGroup` (gid 900) preserves access to
  shared secrets where appropriate, plus the per-service gid.
- `--bounding-set=-all`: empty capability bounding set. A child
  cannot raise even if it has setuid bits.
- `--no-new-privs`: setting `PR_SET_NO_NEW_PRIVS`. Closes the
  `setuid /usr/bin/su` re-elevation route entirely.
- `--inh-caps=-all`: empty inheritable cap set; defense in depth
  against odd userspace that tries to inherit caps.

**Closure cost**

`pkgs.util-linux` adds ~1.5 MB to the production rootfs. Currently
only the dev image bundles it. Plan 25 §W2.3 names this cost as
accepted; we add it to `mkGuest`'s baseline closure (alongside
busybox), unconditionally.

**Files**

- `nix/flake.nix::mkGuestFn`: add `pkgs.util-linux` to the
  rootfs's closure regardless of caller `packages`.
- `nix/minimal-init/default.nix::mkServiceBlock`: rewrite the
  command line to `setpriv …`.

**Tests**

- Eval test asserting the rendered init contains
  `setpriv --no-new-privs --bounding-set=-all` for every service.
- Boot test running a service that does `su` to root inside the
  guest; assert it fails with EPERM (because of `no_new_privs`).
- Boot test running a service that calls `setcap cap_net_admin+ep
  /tmp/binary && /tmp/binary`; assert the cap acquisition succeeds
  but use is denied (bounding set is empty).

### W2.4 — Per-service seccomp filters

**What**

`mvm-security/src/seccomp.rs` already has tiered allowlists
(`Essential`, `Minimal`, `Standard`, `Network`, `Unrestricted`). They
exist as data; nothing currently applies them. Wire them through:

1. Add an optional `seccomp` attribute to `services.<name>` in
   `mkGuest`'s API. Default is `"standard"`. Accepts the same
   string values as the CLI's `--seccomp` flag.
2. At rootfs build time, `mkServiceBlock` consults
   `${pkgs.libseccomp}/bin/scmp_bpf_disasm`-rendered BPF programs
   per tier, written to `/etc/mvm/seccomp/<tier>.bpf`. (Or, simpler
   for v1: store the syscall allowlist as a JSON file and have
   `setpriv --seccomp-filter` consume a small wrapper that builds
   the filter at runtime.)
3. The wrapper emerges from a tiny Rust binary — call it
   `mvm-seccomp-apply` — that reads the tier from argv, applies
   the BPF filter via `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER)`,
   then `execve`'s the rest of argv. setpriv calls it; it calls
   the service.

The Rust shim approach (option 3) is preferred over inline
`setpriv --seccomp-filter` because:

- `setpriv --seccomp-filter` consumes a binary BPF dump; building
  the dump at Nix-eval time is awkward and pinning libseccomp
  versions across the dev/prod split is fragile.
- A purpose-built `mvm-seccomp-apply` binary lives in
  `crates/mvm-guest/src/bin/`, ships with the guest agent's
  closure, and uses `seccompiler` (already in the workspace's Cargo
  tree) to compile syscall lists into BPF in-process.
- The shim costs ~150 KB and removes the libseccomp build
  dependency from the closure entirely.

**Files**

- `crates/mvm-guest/src/bin/mvm-seccomp-apply.rs`: new binary.
  ~80 lines. Argv: `mvm-seccomp-apply <tier> -- <cmd> [args...]`.
- `crates/mvm-guest/Cargo.toml`: add `seccompiler`, register the new
  bin target.
- `nix/guest-agent-pkg.nix`: build the shim alongside
  `mvm-guest-agent` so it lands in the same store path.
- `nix/minimal-init/default.nix::mkServiceBlock`: wrap the
  `setpriv …` invocation with `mvm-seccomp-apply <tier> --`.

**Tests**

- Unit test in `crates/mvm-guest/`: `mvm-seccomp-apply standard --
  /bin/true` exits 0; `mvm-seccomp-apply essential --
  /usr/bin/mount /a /b` exits with `Bad system call` (signal 31).
- Eval test asserting every rendered service block contains
  `mvm-seccomp-apply <tier>`.
- Boot regression: a service with `seccomp = "essential"` cannot
  call `socket(2)`; with `seccomp = "network"` it can.

## Order of operations inside init

After W2.1-W2.4 land, section 2/2b of init runs:

1. Write `/run/mvm-etc/{passwd,group,nsswitch.conf}` with all
   users + per-service users.
2. `mount --bind -o ro` each onto `/etc/<file>` (W2.2).
3. Set up `/run/mvm-secrets/<svc>/` per service, chmod 0400, chown
   to per-service uid (W2.1).
4. Section 8 (services) renders each service launch as
   `mvm-seccomp-apply <tier> -- setpriv … -- /bin/sh -c '<cmd>'`
   (W2.3 + W2.4).

## CI gates added by this plan

- `cargo test -p mvm-build --test mkguest_w2`: a Nix-eval test that
  builds 2-3 contrived `mkGuest` invocations and asserts the
  rendered init contains the right setpriv/seccomp wrapping.
- A boot-time integration test in
  `tests/integration/w2-guest-hardening.rs` (Linux/KVM only;
  ignored on macOS via `#[cfg]`) that:
  - boots a microVM with two services (`alpha`, `beta`) that have
    different uids;
  - asserts `alpha` can't `cat /run/mvm-secrets/beta/foo`;
  - asserts `alpha` can't write to `/etc/passwd`;
  - asserts `alpha` can't call `mount(2)` when run with
    `seccomp = "essential"`.

These gates plug into the W6.3 `security.yml` workflow.

## Rollback shape

If a layer of W2 turns out to break a real-world flake we didn't
foresee:

- W2.1 (per-service uid): the user can restore the old shared-uid
  behavior by setting `services.<name>.user = "mvm"` explicitly.
  No rootfs rebuild needed.
- W2.2 (ro `/etc/passwd`): a single env-var on the kernel cmdline,
  `mvm.etc_writable=1`, makes init skip the bind-mounts. Document
  it as a debugging aid.
- W2.3 (`setpriv`): the current `su` path becomes a fallback
  triggered by `services.<name>.legacy_su = true`. Easier to delete
  the fallback once we trust the new path; the toggle is just for
  the migration window.
- W2.4 (per-service seccomp): default tier `standard`. A flake
  with a service that legitimately needs unrestricted syscalls
  sets `services.<name>.seccomp = "unrestricted"`.

## Reversal cost

Reversing W2.1 requires a flake-API version bump (existing flakes
may grow uid expectations). Reversing W2.2/W2.3/W2.4 is just
removing the wrapper or flipping the default — no API surface
breaks.

## Acceptance criteria

The sprint considers W2 done when:

1. ✅ `cargo test --workspace` and `cargo clippy --workspace
   --all-targets -- -D warnings` clean.
2. ✅ The four eval tests in `crates/mvm-build/` pass.
3. ✅ The Linux/KVM boot integration test asserts the four guest-
   side guarantees (per-service uid isolation, ro /etc/passwd,
   no_new_privs, per-service seccomp denials).
4. ✅ A real `template build hello-python` end-to-end run
   produces a microVM whose `getent passwd` shows the new
   per-service entries and whose `mount` shows three bind-ro lines.
5. ✅ Plan 25 §W2 checkboxes flipped to done in
   `specs/plans/25-microvm-hardening.md`.
6. ✅ SPRINT.md's W2 section reflects shipped status with the
   commit-link table.
