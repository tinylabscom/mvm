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
  # The host (mvmctl machine run --flake .) reads the reported code and exits with it.
  # This fixture bakes `sh -c 'exit 7'` as the sealed workload so a clean
  # E2E run of `mvmctl machine run --flake ./examples/exit_code --timeout 120` must exit 7.
  #
  # ── Canonical user-flake form (matches `mvmctl compile`'s output) ──
  #
  # This is shaped EXACTLY like the SDK-generated flake
  # (crates/mvm-sdk/src/compile/flake.rs): it declares `inputs.mvm`
  # pinned to GitHub, follows `mvm/nixpkgs`, and builds the image via
  # `mvm.lib.<system>.mkGuest`. The literal `github:tinylabscom/mvm`
  # string is load-bearing: from a source checkout, `mvmctl machine run`'s
  # source-checkout override mode (dev_build.rs `local_mvm_workspace`)
  # only triggers when the user flake pins `mvm` to GitHub — it then
  # rewrites it to the in-repo `path:/work/nix` via
  # `--override-input mvm path:/work/nix --override-input
  # mvm/mvm-workspace "path:$MVM_SRC"`. So this resolves against the
  # in-repo flake at build time without a release round-trip, and locks
  # against GitHub on the host before staging.
  #
  # ── entrypoint shape ──────────────────────────────────────────────
  #
  # `entrypoint.command = [ "/bin/busybox" "sh" "-c" "exit 7" ]`
  #
  # The `command` form → mkGuest infers sealed/prod (dev = false),
  # builds the agent without `interactive` (no console, no do_exec),
  # and writes the rendered command to /etc/mvm/entrypoint (mode 0500).
  # /init sources it, captures $?, reports, poweroffs.
  #
  # No `bootCommand` is set — we want PID 1 to BE the one-shot command,
  # not an idle boot loop + per-call agent dispatch. That is exactly the
  # non-function-service sealed path.

  inputs.mvm.url = "github:tinylabscom/mvm/main?dir=nix";
  inputs.nixpkgs.follows = "mvm/nixpkgs";

  outputs =
    { self, mvm, nixpkgs, ... }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      eachSystem = f: builtins.listToAttrs
        (map (s: { name = s; value = f s; }) systems);
    in
    {
      packages = eachSystem (system:
        {
          default = mvm.lib.${system}.mkGuest {
            name = "exit-code-7";

            # `command` form → sealed/prod image, no interactive.
            # mkGuest renders this to /etc/mvm/entrypoint; /init sources it,
            # captures $?, calls mvm-exit-report, poweroffs.
            # busybox is already in the rootfs as /bin/busybox.
            entrypoint.command = [ "/bin/busybox" "sh" "-c" "exit 7" ];

            hypervisor = "libkrun"; # matches mvmctl default on macOS
            vcpus = 1;
            memory_mib = 256;
          };
        });
    };
}
