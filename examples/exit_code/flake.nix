{
  description = "exit_code — one-shot sealed workload for WS-A E2E regression (Plan 152).";

  # ── What this fixture tests ────────────────────────────────────────
  #
  # The guest agent runs /etc/mvm/entrypoint when the host asks and
  # reports its exit code back over vsock. The host
  # (mvmctl machine run --flake .) exits with that code.
  # This fixture bakes `sh -c 'exit 7'` as the sealed workload so a clean
  # E2E run of `mvmctl machine run --flake ./examples/exit_code` must exit 7.
  # Adding `--timeout` declares a wall-clock grant, which a backend that cannot
  # enforce one (Firecracker) refuses at admission instead of running.
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
  # and writes the rendered command to /etc/mvm/entrypoint. The guest
  # agent runs it when the host asks, and its exit status is the run's.

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
            # mkGuest renders this to /etc/mvm/entrypoint; the guest agent
            # runs it and reports its exit code to the host.
            # busybox is already in the rootfs as /bin/busybox.
            entrypoint.command = [ "/bin/busybox" "sh" "-c" "exit 7" ];

            hypervisor = "libkrun"; # matches mvmctl default on macOS
            vcpus = 1;
            memory_mib = 256;
          };
        });
    };
}
