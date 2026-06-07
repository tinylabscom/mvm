{
  description = "exit_code — one-shot sealed workload for WS-A E2E regression (Plan 152).";

  # ── What this fixture tests ────────────────────────────────────────
  #
  # Plan 152 WS-A wires the guest /init to:
  #   1. Source /etc/mvm/entrypoint (or /etc/mvm/boot) as a child process.
  #   2. Capture its $? via MVM_CODE=$?.
  #   3. Call mvm-exit-report "$MVM_CODE" over the control vsock port.
  #   4. Sync + poweroff -f.
  #
  # The host (mvmctl up --wait) reads the reported code and exits with it.
  # This fixture bakes `sh -c 'exit 7'` as the sealed workload so a clean
  # E2E run of `mvmctl up --flake ./examples/exit_code --wait` must exit 7.
  #
  # ── entrypoint shape ──────────────────────────────────────────────
  #
  # `entrypoint.command = [ "/bin/busybox" "sh" "-c" "exit 7" ]`
  #
  # The `command` form → mkGuest infers sealed/prod (isDev = false),
  # builds the agent without `dev-shell` (no console, no do_exec),
  # and writes the rendered command to /etc/mvm/entrypoint (mode 0500).
  # /init sources it, captures $?, reports, poweroffs.
  #
  # No `bootCommand` is set — we want PID 1 to BE the one-shot command,
  # not an idle boot loop + per-call agent dispatch. That is exactly the
  # non-function-service sealed path.

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    microvm = {
      url = "github:microvm-nix/microvm.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    { self, nixpkgs, microvm, ... }:
    let
      systems = [ "aarch64-linux" "x86_64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;

      # Resolve the workspace root the same way builder-vm / default-tenant do:
      # - In the builder VM (Nix sandbox, impure eval), mvmctl sets MVM_WORKSPACE_PATH.
      # - On a developer host with impure allowed, the relative ../../.. fallback
      #   reaches the workspace root from examples/exit_code/.
      workspaceRoot =
        let envPath = builtins.getEnv "MVM_WORKSPACE_PATH";
        in if envPath != "" then /. + envPath else ../../..;

      # The workspace-filter.nix brings only non-artifact files into the store
      # so the Rust cross-compile sees the Cargo.lock without ingesting
      # multi-GB target/ or .build/ trees.
      workspace =
        (import (workspaceRoot + "/nix/lib/workspace-filter.nix") {
          inherit (nixpkgs) lib;
        })
        { inherit workspaceRoot; };

      libFor = system:
        (import (workspace + "/nix/lib") {
          inherit nixpkgs microvm;
          mvmSrc = workspace;
        }) { inherit system; };

    in
    {
      packages = forAllSystems (system:
        let
          lib = libFor system;

          rootfs = lib.mkGuest {
            name = "exit-code-7";

            # `command` form → sealed/prod image, no dev-shell.
            # mkGuest renders this to /etc/mvm/entrypoint; /init sources it,
            # captures $?, calls mvm-exit-report, poweroffs.
            # busybox is already in the rootfs as /bin/busybox — no packages = needed.
            entrypoint.command = [ "/bin/busybox" "sh" "-c" "exit 7" ];

            hypervisor = "libkrun";  # matches mvmctl default on macOS
            vcpus = 1;
            memory_mib = 256;
          };
        in
        {
          default = rootfs;
        });
    };
}
