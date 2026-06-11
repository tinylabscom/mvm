{
  description = "sleeper — long-lived sealed workload fixture for live Vz validation.";

  # A minimal sealed (prod) workload whose PID-1 command never exits, so the
  # VM stays resident long enough to checkpoint / fork / pause / resume and be
  # probed over the guest-agent vsock. The `command` form makes mkGuest infer
  # the sealed/prod image (agent built without the dev-shell console). The
  # `github:tinylabscom/mvm` pin is load-bearing: a source-checkout `mvmctl up`
  # rewrites it to the in-repo flake, so this builds without a release round-trip.

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
            name = "sleeper";

            # Never returns: PID-1's workload idles with a portable max-int sleep
            # loop (busybox is already in the rootfs as /bin/busybox), so the VM
            # stays up for live validation.
            entrypoint.command = [
              "/bin/busybox" "sh" "-c"
              "while :; do /bin/busybox sleep 2147483647; done"
            ];

            hypervisor = "libkrun";
            vcpus = 1;
            memory_mib = 256;
          };
        });
    };
}
