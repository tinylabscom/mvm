# Plan 18: Wire the agent workload's Nix packaging into microVM rootfs + Nix probe module

**Status: PLANNED**

## Context

The agent-workload-worker integration shows `0/1 healthy` with "failed to execute: No such file or directory" because the `agent-workload` binary is never included in the microVM rootfs. Both `roles/worker.nix` and `roles/gateway.nix` do `exec agent-workload worker` / `exec agent-workload gateway`, but nothing puts the binary in PATH.

**Already implemented (unstaged on `feat/dev-shell-exec`):**
- Rust probe infrastructure: `probes.rs`, vsock protocol (`ProbeStatus`/`ProbeStatusReport`), guest agent probe execution loop
- CLI `mvm vm inspect <name>` command with human + JSON output
- `mvm vm status` column renamed INTEGRATIONS → HEALTH, combining probes + integrations
- LinuxEnv trait abstraction (staged)
- Plan 16 spec for full microvm.nix integration (staged)

**What's missing (this plan):**
1. The `agent-workload` binary in the rootfs (the agent workload's Nix packaging flake input)
2. A NixOS module for probes (`guest-probes.nix`) — the Nix counterpart to the Rust probe infrastructure
3. The `/etc/mvm/probes.d/` directory creation in the guest agent module
4. Example probes in the worker role

**References:**
- nix-agent-workload-integration — Nix flake for installing the agent workload
- [microvm.nix](https://github.com/microvm-nix/microvm.nix) — NOT used here (our `mkGuest` suffices), but referenced in Plan 16 for future hypervisor decoupling

## Changes

### Step 1: Add the agent workload's Nix flake input — `nix/agent-workload/flake.nix`

Add to `inputs`:
```nix
nix-agent-workload-integration = {
  url = "github:agent-workload/nix-agent-workload-integration";
  inputs.nixpkgs.follows = "nixpkgs";
};
```

Update `outputs` function signature:
```nix
outputs = { nixpkgs, flake-utils, rust-overlay, nix-agent-workload-integration, ... }:
```

Inside the `let` block, extract the agent-workload package:
```nix
agent-workload = nix-agent-workload-integration.packages.${system}.default;
```

Pass it to `mkGuest` via `specialArgs` (alongside existing `mvm-guest-agent`):
```nix
specialArgs = { inherit mvm-guest-agent agent-workload; };
```

This follows the same pattern already used for `mvm-guest-agent` (line 30–33 → specialArgs line 49).

### Step 2: Update role modules to use the package

**`nix/agent-workload/roles/worker.nix`:**
- Change function signature from `{ pkgs, ... }:` to `{ pkgs, agent-workload, ... }:`
- Change line 77 `exec agent-workload worker` to `exec ${agent-workload}/bin/agent-workload worker`

**`nix/agent-workload/roles/gateway.nix`:**
- Change function signature from `{ pkgs, ... }:` to `{ pkgs, agent-workload, ... }:`
- Change line 64 `exec agent-workload gateway` to `exec ${agent-workload}/bin/agent-workload gateway`

### Step 3: Create guest-probes NixOS module — `nix/modules/guest-probes.nix` (NEW)

Mirror `guest-integrations.nix` for the probe system. This lets any Nix flake declaratively define probes that get baked into `/etc/mvm/probes.d/*.json` — the directory the Rust guest agent's `load_probe_dropin_dir()` scans at startup.

Options match `ProbeEntry` fields in `crates/mvm-guest/src/probes.rs`:

```nix
{ lib, config, ... }:
let
  cfg = config.services.mvm-probes;

  probeJson = name: entry: builtins.toJSON ({
    inherit name;
    cmd = entry.cmd;
    interval_secs = entry.intervalSecs;
    timeout_secs = entry.timeoutSecs;
    output_format = entry.outputFormat;
  } // lib.optionalAttrs (entry.description != null) {
    description = entry.description;
  });

  probeSubmodule = {
    options = {
      cmd = lib.mkOption { type = lib.types.str; description = "Shell command. Exit 0 = healthy."; };
      description = lib.mkOption { type = lib.types.nullOr lib.types.str; default = null; };
      intervalSecs = lib.mkOption { type = lib.types.int; default = 30; };
      timeoutSecs = lib.mkOption { type = lib.types.int; default = 10; };
      outputFormat = lib.mkOption {
        type = lib.types.enum [ "exit_code" "json" ];
        default = "exit_code";
        description = "exit_code: healthy if exit 0. json: parse stdout as JSON.";
      };
    };
  };
in {
  options.services.mvm-probes = {
    enable = lib.mkEnableOption "mvm probe registration";
    probes = lib.mkOption {
      type = lib.types.attrsOf (lib.types.submodule probeSubmodule);
      default = {};
    };
  };
  config = lib.mkIf cfg.enable {
    environment.etc = lib.mapAttrs' (name: entry:
      lib.nameValuePair "mvm/probes.d/${name}.json" {
        text = probeJson name entry;
      }
    ) cfg.probes;
  };
}
```

### Step 4: Update guest-agent.nix to create probes.d directory

Add to existing `systemd.tmpfiles.rules` array in `nix/modules/guest-agent.nix`:
```nix
systemd.tmpfiles.rules = [
  "d /etc/mvm/integrations.d 0755 root root -"
  "d /etc/mvm/probes.d 0755 root root -"
];
```

### Step 5: Add probes to worker role — `nix/agent-workload/roles/worker.nix`

Import guest-probes module alongside existing guest-integrations import:
```nix
imports = [
  ../../../nix/modules/guest-integrations.nix
  ../../../nix/modules/guest-probes.nix
];
```

Register built-in probes:
```nix
services.mvm-probes = {
  enable = true;
  probes.disk-usage = {
    description = "Root filesystem usage percentage";
    cmd = "${pkgs.coreutils}/bin/df / --output=pcent | ${pkgs.coreutils}/bin/tail -1 | ${pkgs.jq}/bin/jq -Rs '{usage_pct: (. | gsub(\"[^0-9]\"; \"\") | tonumber)}'";
    intervalSecs = 60;
    outputFormat = "json";
  };
  probes.memory = {
    description = "Memory usage in MiB";
    cmd = "${pkgs.procps}/bin/free -m | ${pkgs.gawk}/bin/awk '/Mem:/ {printf \"{\\\"total_mb\\\": %d, \\\"used_mb\\\": %d, \\\"avail_mb\\\": %d}\", $2, $3, $7}'";
    intervalSecs = 30;
    outputFormat = "json";
  };
};
```

### Step 6: Update flake.lock

After editing `flake.nix`, update the lock file inside the Lima VM:
```bash
limactl shell mvm -- bash -c "cd /path/to/nix/agent-workload && nix flake update nix-agent-workload-integration"
```

## Files Modified

| File | Action |
|------|--------|
| `nix/agent-workload/flake.nix` | Add `nix-agent-workload-integration` input, pass `agent-workload` via specialArgs |
| `nix/agent-workload/flake.lock` | Auto-updated by `nix flake update` |
| `nix/agent-workload/roles/worker.nix` | Accept `agent-workload` arg, use `${agent-workload}/bin/agent-workload`, import probes, add probes |
| `nix/agent-workload/roles/gateway.nix` | Accept `agent-workload` arg, use `${agent-workload}/bin/agent-workload` |
| `nix/modules/guest-probes.nix` | **NEW** — NixOS module for declarative probe registration |
| `nix/modules/guest-agent.nix` | Add `/etc/mvm/probes.d` to tmpfiles.rules |

## Verification

```bash
# Nix evaluation (inside Lima VM):
cd nix/agent-workload
nix flake check                                # flake evaluates without errors
nix build .#tenant-worker --dry-run            # verify closure includes agent-workload

# Rust tests (from macOS host):
cargo test --workspace                          # all tests pass
cargo clippy --workspace -- -D warnings         # zero warnings

# End-to-end (rebuild + run):
mvm template build agent-workload
mvm run --template agent-workload
mvm vm inspect <name>
# Expected: agent-workload-worker healthy, probes showing disk-usage + memory with JSON output
```
