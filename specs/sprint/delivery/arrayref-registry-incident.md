- [x] The root and standalone fuzz workspaces no longer resolve the unbuildable
      `arrayref` replacement published after the established releases were
      yanked. Every workspace pins the exact upstream revision that produced
      the previously reviewed 0.3.9 release, the source policy admits only
      that repository, and CI consumes each refreshed fuzz lockfile with
      `--locked`. Regression coverage keeps the manifest patches, immutable
      revision, root lock source, and deny allowlist synchronized.
