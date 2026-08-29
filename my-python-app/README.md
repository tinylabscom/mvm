# my-python-app

mvm microVM project.

Three files describe this microVM:

- `flake.nix` — what's _inside_ the microVM (services, packages, NixOS config). Customize freely.
- `baseline.nix` — baseline NixOS guest configuration imported by the flake.
- `mvm.toml` — how `mvmctl` builds and runs the flake (sizing, profile selector). Fields: `flake`, `profile`, `vcpus`, `mem`, `data_disk`, `net`.

To build and boot:

```bash
mvmctl build                 # discover mvm.toml in cwd; runs `nix build`
mvmctl machine run --flake . # boot and run the microVM
```

Edit `mvm.toml` to change sizing or pick a different flake profile; re-run `mvmctl build` to rebuild. Edit `flake.nix` to change what's inside the rootfs.

See the [Manifests guide](https://mvm.dev/guides/manifests/) for the full model.
