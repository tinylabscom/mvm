{
  description = "egress-probe — one-shot workload that TCP-probes two targets and exits a verdict code, exercising libkrun workload egress.";

  # A sealed one-shot workload: PID-1 attempts two outbound TCP connections and
  # exits a verdict code encoding both results, captured over the control vsock
  # and returned by `mvmctl up --wait`. Used to verify a libkrun workload guest
  # actually gets network (the guest console is not host-readable, so the exit
  # code is the observable). Raw IPs (no DNS) keep the probe independent of name
  # resolution.
  #
  # Verdict = (allow_blocked ? 1 : 0) + (deny_blocked ? 2 : 0):
  #   0 = both reachable (open gateway, e.g. real gvproxy → network works)
  #   2 = allow reachable, deny blocked (correct allow+deny enforcement)
  #   3 = both blocked (deny-all, or — the bug this fixture caught — no network)
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
            name = "egress-probe";

            entrypoint.command = [
              "/bin/busybox" "sh" "-c"
              ''
                allow="''${PROBE_ALLOW:-1.1.1.1}"
                deny="''${PROBE_DENY:-8.8.8.8}"
                port="''${PROBE_PORT:-443}"
                # Give netinit's eth0 bring-up + DHCP a moment to settle.
                /bin/busybox sleep 3
                code=0
                /bin/busybox nc -w 4 -z "$allow" "$port" || code=$((code + 1))
                /bin/busybox nc -w 4 -z "$deny" "$port"  || code=$((code + 2))
                exit "$code"
              ''
            ];

            hypervisor = "libkrun";
            vcpus = 1;
            memory_mib = 256;
          };
        });
    };
}
