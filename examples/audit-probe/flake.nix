{
  description = "audit-probe — in-guest host.audit.v1 round-trip fixture.";

  # A sealed workload whose PID-1 command is the baked `audit-probe` binary.
  # On an admitted `mvmctl up` (tenant defaults to `local`) the backend spawns
  # the per-VM mvm-broker + mvm-audit-signer, the probe dials BROKER_PORT and
  # emits over `host.audit.v1`, and the entry lands in the per-VM workload
  # chain `~/.mvm/audit/<tenant>.<vm>.workload.jsonl` — verifiable with
  # `mvmctl trust audit verify --tenant <t>`. `withAuditProbe = true` is what
  # bakes the binary; the production guest closure never carries it.
  #
  # The `github:tinylabscom/mvm` pin is load-bearing: a source-checkout
  # `mvmctl up` rewrites it to the in-repo flake, so this builds without a
  # release round-trip.

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
            name = "audit-probe";

            # Bake the in-guest probe and run it as PID-1's workload. `all`
            # exercises the normal emit, the >4 KiB BadRequest, and the 20/s
            # rate-limit in one boot; exit 0 only if every step met its
            # success condition, so the workload exit status is an assertion.
            withAuditProbe = true;
            entrypoint.command = [ "/usr/local/bin/audit-probe" "all" ];

            hypervisor = "libkrun";
            vcpus = 1;
            memory_mib = 256;
          };
        });
    };
}
