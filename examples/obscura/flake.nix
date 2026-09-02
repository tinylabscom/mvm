{
  description = "Digest-pinned Obscura CDP browser guest";

  inputs.mvm.url = "github:tinylabscom/mvm/main?dir=nix";
  inputs.nixpkgs.follows = "mvm/nixpkgs";

  outputs =
    { mvm, nixpkgs, ... }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      eachSystem = f: builtins.listToAttrs
        (map (system: { name = system; value = f system; }) systems);
    in
    {
      packages = eachSystem (system:
        let
          pkgs = import nixpkgs { inherit system; };
          release = {
            x86_64-linux = {
              arch = "x86_64";
              sha256 = "d601f4f542319c3b9fa8dca9f5ccfc134a2ca001648da528db5f03c9e6c2599b";
            };
            aarch64-linux = {
              arch = "aarch64";
              sha256 = "8ac11fb7db704d2a5acfd917804e066b8f9a102f2f0a8eaef110322848e12565";
            };
          }.${system};
          obscura = pkgs.stdenvNoCC.mkDerivation {
            pname = "obscura";
            version = "0.2.0";
            src = pkgs.fetchurl {
              url = "https://github.com/h4ckf0r0day/obscura/releases/download/v0.2.0/obscura-${release.arch}-linux.tar.gz";
              inherit (release) sha256;
            };
            sourceRoot = ".";
            nativeBuildInputs = [ pkgs.autoPatchelfHook ];
            buildInputs = [ pkgs.glibc pkgs.stdenv.cc.cc.lib ];
            installPhase = ''
              runHook preInstall
              install -Dm755 obscura "$out/bin/obscura"
              install -Dm755 obscura-worker "$out/bin/obscura-worker"
              runHook postInstall
            '';
          };
        in
        {
          package = obscura;
          default = mvm.lib.${system}.mkGuest {
            name = "obscura";
            packages = [ obscura ];
            entrypoint.command = [
              "/bin/busybox" "sh" "-c"
              ''
                : "''${ALL_PROXY:?mvm egress proxy is required; pass --allow-host for every remote origin}"
                exec ${obscura}/bin/obscura \
                  --proxy "$ALL_PROXY" \
                  serve --host 127.0.0.1 --port 9222
              ''
            ];
            vcpus = 1;
            memory_mib = 512;
          };
        });
    };
}
