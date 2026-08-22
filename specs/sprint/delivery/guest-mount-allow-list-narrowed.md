# Guest-mount allow-list narrowed to `/data` and `/work`

Delivered 2026-08-22.

`/mnt` was an allow-root for user volumes while the runtime was already using
it: `/init` mounts the read-only config and secret drives at `/mnt/config` and
`/mnt/secrets` (`nix/lib/mk-guest.nix:435-437`) before any user volume is
attached. A share at `/mnt` passed both gates — the allow-root check because
`/mnt` is a root, the reserved check because that only refuses a path which
*names* a reserved drive — and mounted over drives that were already there,
hiding them from the guest.

The allow-list is now `/data`, `/work` in both `mvm_core`'s `MountPathPolicy`
and `mvm-cli`'s `ALLOWED_GUEST_MOUNT_ROOTS`. The whole `/mnt` subtree is
unreachable to a user volume, so the collision cannot be expressed rather than
being enumerated against.

## It closed an agent-side gap nobody had noticed

The reserved paths were only ever known to `mvm-cli`. `mvm_core`'s
`MountPathPolicy` — the policy the *agent* enforces before `mount(2)` — had no
entry for `/mnt/config` or `/mnt/secrets` at all, so a non-CLI caller could
mount over them. Removing `/mnt` from the roots in both crates closes that
without a new mechanism.

`RESERVED_UNDER_ALLOWED` is kept rather than deleted. It is checked first, so
the drives report as *reserved* instead of as a generic allow-root miss, and it
keeps them protected if `/mnt` is ever restored to the roots.

## What was explored and rejected

The session started from a usability complaint — `--mount $PWD:/usr/local` is
refused — and first built the opposite change: a per-tier protected-path policy
that kept the allow-list for `--prod`/sealed images but let an OCI image mount
anywhere mvm did not own, with the tier declared in `mvm-meta.json` and carried
into the activation payload. It was complete and green (PR #2795) and was
**rejected**: the allow-list is a deliberate strict requirement, and a tiered
deny-list ships the mechanism to escape strict — a permissive branch reachable
by declaration, plus `mount_tier` in the public wire schema and the SDK stubs.

Two facts, either of which would have ended the exercise in five minutes had
they been checked first, are worth recording because they are not obvious:

- `/usr/local` is **mvm-owned on both rootfs shapes**. `oci_runtime_inject.rs`
  writes the guest agent to `/usr/local/bin/mvm-guest-agent` in every OCI image,
  and mkGuest fills `/usr/local/bin` with the entrypoint symlinks. There is no
  tier on which a user volume can safely land there.
- The `/mnt` collision is a **breakage footgun, not a leak**. The drives mount
  before user volumes, so a share hides them rather than receiving their
  contents; and the guest's trust anchor lives at `/run/mvm/host-signer.pub`,
  delivered via the `mvm.host_signer_pub` cmdline token, so shadowing `/mnt`
  cannot strip it. Only the operator can trigger any of this, which puts it
  outside the ADR-001 threat model.

An intermediate version — keeping the allow-list but making containment
bidirectional, so a mountpoint that is an *ancestor* of a protected path is also
refused — was also green and also not merged. Narrowing the roots achieves the
same protection for this case with no new containment direction, though the
general ancestor problem remains unaddressed for any future reserved path placed
beneath an allow-root.

## Scope

`--mount HOST:/mnt/...` is refused; `/data` and `/work` remain. No docs directed
anyone at `/mnt`, and no runtime-attached volume targets it — the SDK sidecar
mounts at `/mvm/sdk` through its own `mvm.sdk_dev` contract and app-deps at
`/deps`, neither of which goes through the user-volume allow-list. `/mnt/root`,
the initramfs staging root in `guest_mount.rs`, is a different path and is
untouched. Everything else affected was test fixtures.

`mnt_is_not_an_allow_root_so_the_runtime_drives_are_unreachable` pins the
exclusion so it cannot be silently restored.
