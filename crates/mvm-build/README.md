# mvm-build

Nix builder pipeline for producing Firecracker microVM images. Supports two build paths: dev-mode local builds and orchestrated pool builds with ephemeral builder VMs.

## Modules

| Module | Purpose |
|--------|---------|
| `dev_build` | Local `nix build` in Lima VM, artifact caching by Nix store hash |
| `build` | Orchestrated pool builds via ephemeral Firecracker builder VMs |
| `artifacts` | Artifact path resolution and caching |
| `cache` | Build cache utilities |
| `firecracker` | Firecracker-specific build configuration generation |
| `nix_manifest` | `NixManifest` parsing from `mvm-profiles.toml` |
| `orchestrator` | Ephemeral builder VM lifecycle management |
| `scripts` | Bash script templates (small placeholder renderer) |
| `template_reuse` | Template-based build optimization |
| `vsock_builder` | Vsock-based communication with builder VMs |
| `backend` | Storage backend implementations |

## Dev Build Flow

```
mvm build --flake .
    -> dev_build(env, flake_ref, profile)
        -> nix build <attr> --no-link          (visible output)
        -> nix build <attr> --print-out-paths  (capture store path)
        -> extract revision hash from /nix/store/<hash>-...
        -> check cache at ~/.mvm/dev/builds/<hash>/
        -> copy kernel + rootfs if cache miss
        -> return DevBuildResult
```

Cache hits are near-instant. The cache key is the Nix store hash, so identical inputs always produce cache hits.

## Key Types

- `DevBuildResult` — Build output paths (kernel, initrd, rootfs), revision hash, cache hit flag
- `NixManifest` — Maps (role, profile) pairs to Nix module paths

## Dependencies

- `mvm-core` (`ShellEnvironment` trait)
- `mvm-agentd` (builder agent protocol)
