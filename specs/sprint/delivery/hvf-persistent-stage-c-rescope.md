# Stage C's persistent-builder recipe, re-scoped against the tree

No code. This corrects `specs/plans/2026-08-31-remove-virtio-fs.md`'s Stage C
persistent-builder section, which describes a migration of a code path that no
build takes and would have consumed a large implementation before that surfaced.

Recorded because the plan actively misdirects: following it produces a change
that looks like progress, passes its own tests, and leaves the live path on
virtio-fs.

## The recipe targets a deleted dispatch path

The five coordinated changes are written against the `HostVmRequest::Run`
shell-job dispatch — repack the input disk per `Run`, read the output disk after
each `Result`, replace `wait_until_dispatch_ready`.

`dev_build.rs` says otherwise, in its own words: *"The legacy in-VM shell-job
dispatch was removed; typed is the only persistent path."* A build routes
through `try_typed_persistent_build`, where a reachable `mvm-builderd` builds
`/work#<attr>` and **exports artifacts into `/job/<uuid>/out`**; the host reads
them from the host side of that same share.

`PersistentBuilderSupervisor::submit` still exists and is still called by the
hidden `mvmctl persistent-builder` subcommand. Migrating it would move a path no
build takes while leaving the live one exactly as it is.

## The blast radius is much smaller than stated

The plan says *"the persistent builder is what `mvmctl build` uses on macOS 26+…
a broken builder has no CI witness."*

`HvfPersistentHostVm` has exactly one caller: `mvmctl persistent-builder`,
declared `#[command(hide = true)]`. `dev_build` routes through a session only
when a record exists *and* residency policy allows, and any dispatch failure
falls back to the single-shot builder — which the code calls "the safety net".

Opt-in, hidden, with a fallback. A break degrades a build's speed, not its
correctness. That changes how much ceremony this stage deserves.

## The inbound half is not separately shippable

"Move `work` and `mvm-bins` to the input disk, keep `/job` as a share" is not
expressible. `mvm.builder_transport=disk` is all-or-nothing in the guest:
`setup_modules_and_virtiofs` skips **every** virtio-fs mount when it is set,
because in that mode the host declares no tags and each attempt would fail with
"tag not found". A hybrid needs a guest change and an image rebuild.

## What the remaining work actually is

A protocol question, not a spec change: how does the typed `mvm-builderd` export
return artifacts without a writable host directory?

- **(a)** builderd writes the artifact tar onto the output disk itself — needs
  the device inside the guest and a raw-tar writer in the daemon. This is the
  shape every other tier now uses.
- **(b)** the dispatch loop collects `/job/<uuid>/out` onto the output disk on a
  new request — reintroduces a dependency on that loop running alongside the
  daemon.

Neither is a line-edit. Resolve before writing code.

## Consequence for the ratchet

`check-no-virtio-fs` cannot reach FFI-only rows until this is answered. The
persistent builder's four shares in `builder_runner/spec.rs` are pinned and
stay pinned. The plan's claim that deleting `virtiofsd.rs` would take the gate
to FFI-only was already corrected separately; this is the other half of why.
