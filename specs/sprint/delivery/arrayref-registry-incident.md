- [x] The root and affected standalone fuzz workspaces no longer resolve the
      unbuildable `arrayref` replacement published after the established
      releases were yanked. The reviewed 0.3.9 source is vendored with pinned
      provenance and hashes, every active graph resolves that path, git sources
      remain denied, and CI consumes refreshed fuzz lockfiles with `--locked`.
      Regression coverage keeps the manifests, locks, vendored source, Nix
      filter, and source policy synchronized.
