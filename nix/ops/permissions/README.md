# `ops/permissions/`

One-shot privilege grants. Each script names a specific host change
and requires explicit user invocation — nothing here runs from
`mvmctl`, `nix develop`, or `shellHook`.

Currently empty. `/dev/kvm` access is the canonical case: on a Linux
host where `/dev/kvm` exists but is not readable by the current user,
Firecracker cannot open it until that user is granted access. The fix
script (`kvm-access.sh`) is intentionally *not* shipped — strict
reading of the
[`mvm-nix-best-practices` guide](../../../specs/references/mvm-nix-best-practices.md)
says the user runs it themselves so they see the `usermod -a -G kvm`
or `chmod` change before it lands.

A skeleton:

```bash
#!/usr/bin/env bash
# nix/ops/permissions/kvm-access.sh — grant the current user access to /dev/kvm
#
# Mutates: adds the current user to the `kvm` group via usermod.
#          You must log out and back in (or run `newgrp kvm`) for
#          the membership change to take effect.
# Idempotent: yes (usermod -a is additive).

set -euo pipefail
if [ ! -e /dev/kvm ]; then
  echo "/dev/kvm not present — this host has no KVM. Aborting." >&2
  exit 1
fi
sudo usermod -a -G kvm "$USER"
echo "Added $USER to the kvm group. Log out and back in (or run 'newgrp kvm')."
```

Add the actual script here when a contributor needs it.
