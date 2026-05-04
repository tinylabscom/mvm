# {{name}}

mvm microVM project.

Two files describe this microVM:

- `flake.nix` — what's *inside* the microVM (services, packages, NixOS config). Customize freely.
- `mvm.toml` — how `mvmctl` builds and runs the flake (sizing, profile selector). Five fields: `flake`, `profile`, `vcpus`, `mem`, `data_disk`.

To build and boot:

```bash
mvmctl build           # discover mvm.toml in cwd; runs `nix build`
mvmctl up              # boot the built microVM
```

Edit `mvm.toml` to change sizing or pick a different flake profile; re-run `mvmctl build` to rebuild. Edit `flake.nix` to change what's inside the rootfs.

See the [Manifests guide](https://mvm.dev/guides/manifests/) for the full model.
