# Delivery: injected image files stay root-owned (#3430)

A container image layer could take ownership of the files mvm injects into
the built rootfs. The layer owner table was applied after injection, so a
layer that declared `etc/passwd` as uid 1000 produced an image whose
`/etc/passwd` belonged to uid 1000. Claim 2 depends on the account databases
being root-owned.

- `OwnerTable::apply` now takes a `RootOwnedPaths` set and forces root on
  every node the set claims. It sets root instead of skipping those nodes,
  because a deferred node arrives carrying its layer's owner even when the
  table doesn't name the path. `mvm_build::oci_runtime_inject::injected_root_owned_paths`
  builds the set from the tables the injection already walks (`INJECT_DESTS`,
  `INJECT_DIRS`), plus the trees mvm owns (`/etc/mvm`, `/mvm`,
  `/usr/lib/mvm`). The in-process materializer claims that set on every tree
  it builds.
- The adversarial tests cover `/etc/passwd`, `/etc/group`,
  `/etc/mvm/verb-trust.json` and the entrypoint wrapper. One test reads the
  image back through the independent ext4 oracle, and another runs the
  production materializer options. Both also check that a path mvm does not
  inject keeps the owner its layer declared.
- A builder-VM refusal now states the actual cause. When
  `MVM_MATERIALIZE_BUILDER_VM` selected the builder VM, the refusal tells the
  operator to unset it. On the automatic fallback, it names the in-process
  failure that caused the fallback.
- The owner and deferred-node sidecars are now written atomically. A corrupt
  or truncated sidecar makes the cached unpack unusable, so the layers get
  unpacked again. It no longer returns a hard error that blocks the image
  until someone deletes the file by hand. A corrupt deferred-node sidecar is
  treated as unknown, not as an empty list.
