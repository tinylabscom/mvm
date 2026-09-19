# The builder cache key covers every Nix file the builder flake imports

Backing: shipped-source
Validation: cargo nextest run -p mvm-cli -E 'test(/fingerprint/)'

`builder_vm_source_fingerprint` decides whether a cached builder image still
matches a source checkout. It hashed the builder-vm flake, the embedded host
binaries and `nix/lib`. The flake also imports the kernel configs, the
runtime-overlay flake, a guest recipe under `nix/packages`, and (once guest
recipes are exported from the top-level flake) `nix/flake.nix` itself. An edit to any of
those changed the built image but not the key, so the next boot silently reused
a stale builder.

The key now hashes every entry of `BUILDER_FLAKE_NIX_INPUTS`: `nix/flake.nix`,
`nix/flake.lock`, `nix/lib`, `nix/packages`, `nix/images/kernel` and
`nix/images/runtime-overlay`. A test reads the shipped builder-vm and
runtime-overlay flakes, collects every `+ "/nix/…"` import, and fails if one is
not under a listed input or if a listed input does not exist. Dropping
`nix/images/kernel` from the list turned it red with the kernel import named.

Existing cached builder images are rebuilt once, because the key changed.

## Not here

`mvm-setpriv` is compiled into the builder from `mvm-agentd` source, which the
key still does not hash (#3463). The function's doc comment used to claim the
embedded host binaries were the only Rust in the image; it now says otherwise.
