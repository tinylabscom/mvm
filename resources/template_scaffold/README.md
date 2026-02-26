# {{name}}

mvm microVM template.

- Edit `flake.nix` to customize your guest image.
- `mvm template create {{name}} --flake . --profile minimal --role worker --cpus 2 --mem 1024`
- `mvm template build {{name}}`
