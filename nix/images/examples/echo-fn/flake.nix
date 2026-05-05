{
  description = ''
    Smoke fixture for plan 41 W3 — `mvmctl invoke` against a baked
    `/etc/mvm/entrypoint`. The wrapper is a tiny shell script that
    exec's `cat`, so a `RunEntrypoint` request with stdin "hello"
    receives `Stdout { chunk: b"hello" }` and an `Exit { code: 0 }`.

    Live-KVM smoke target: `MVM_LIVE_SMOKE=1 cargo test ...` against
    a host with vsock-capable Firecracker (native Linux/KVM, or
    macOS 26+ with Apple Container).
  '';

  inputs = {
    mvm.url = "path:../../..";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
  };

  outputs =
    { mvm, nixpkgs, ... }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      eachSystem =
        f:
        builtins.listToAttrs (
          map (system: {
            name = system;
            value = f system;
          }) systems
        );
    in
    {
      packages = eachSystem (
        system:
        let
          pkgs = import nixpkgs {
            inherit system;
            config = { };
            overlays = [ ];
          };
          # The wrapper baked at /usr/lib/mvm/wrappers/echo. ADR-007's
          # validation requires it to be a regular file under
          # /usr/lib/mvm/wrappers/, owned root, mode 0755, on the same
          # filesystem as /usr (verity rootfs in production; for this
          # non-verity smoke, simply the rootfs ext4).
          wrapperContent = ''
            #!/bin/sh
            # Smoke wrapper for plan 41 W3 — exec cat so the
            # RunEntrypoint stdin payload comes back unchanged on
            # stdout. No language runtime, no heavy deps. Real
            # workloads use a per-language wrapper from mvmforge's
            # forthcoming Nix factories.
            exec cat
          '';
          markerContent = "/usr/lib/mvm/wrappers/echo\n";
        in
        {
          default = mvm.lib.${system}.mkGuest {
            name = "echo-fn";
            packages = [ ];

            # ADR-007 / plan 41 W4 / W5: bake the wrapper plus the
            # marker file the agent reads at boot. extraFiles lands
            # them with mode 0755 / 0644 respectively, owned root,
            # on the verity-protectable rootfs (this fixture turns
            # verity off for ergonomics; a production fixture would
            # leave it on).
            extraFiles = {
              "/usr/lib/mvm/wrappers/echo" = {
                content = wrapperContent;
                mode = "0755";
              };
              "/etc/mvm/entrypoint" = {
                content = markerContent;
                mode = "0644";
              };
            };

            # Verity is off for the smoke — verity-on would require
            # baking the wrapper into a verity-sealed rootfs, which
            # this fixture is too minimal to exercise. Plan 41 W4's
            # snapshot HMAC + W3 verity together cover the
            # production posture; the smoke proves the substrate
            # path independent of those.
            verifiedBoot = false;
          };
        }
      );
    };
}
