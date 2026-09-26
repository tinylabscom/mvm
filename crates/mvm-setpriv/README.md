# mvm-setpriv

`mvm-setpriv` is the static privilege-drop and exec helper a guest init runs
every service through. It replaces util-linux `setpriv` with the handful of
flags mkGuest emits: numeric uid/gid replacement, clearing supplementary
groups, `no_new_privs`, and an allowlist of inheritable and ambient
capabilities.

## Who uses it

`nix/packages/mvm-setpriv.nix` builds the binary for every Nix-built guest,
the builder image included. `mvm-agentd` depends on the library half for the
descriptor hygiene every guest spawn applies (`fd_hygiene`) and for the
capability numbers the agent retains.

## Why it is its own crate

The builder image compiles this binary from source, so the builder image's
cache key hashes the binary's dependency closure. When the binary lived in
`mvm-agentd`, that closure was `mvm-agentd`, `mvm-core` and `mvm-contract`, and
about a quarter of all commits rebuilt the builder image. As a leaf over
`libc`, only an edit to this crate does. Adding a dependency here widens that
key again; a test in the builder fingerprint holds the closure to `libc`.

## How it works

`run` parses the arguments, applies the identity change in the order the
kernel requires (keep-caps, groups, gid, uid, capabilities, then
`no_new_privs`), marks every descriptor above stderr close-on-exec, and execs
the command. A refused invocation exits 2, a failed privilege change 126, and a
failed exec 127. On a non-Linux host it refuses to run.

## Developing

Run `cargo test -p mvm-setpriv`. The privileged integration tests run only as
root on Linux.
