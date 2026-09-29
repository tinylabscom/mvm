{
  description = "mvm contributor development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    { nixpkgs, rust-overlay, ... }:
    let
      systems = [
        "aarch64-darwin"
        "x86_64-darwin"
        "aarch64-linux"
        "x86_64-linux"
      ];

      forAllSystems = nixpkgs.lib.genAttrs systems;

      prebuiltRelease = import ./nix/prebuilt-release.nix;

      prebuiltPackage =
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          archive = prebuiltRelease.archives.${system};
        in
        pkgs.stdenvNoCC.mkDerivation {
          pname = "mvmctl-prebuilt";
          version = nixpkgs.lib.removePrefix "v" prebuiltRelease.version;
          src = pkgs.fetchurl {
            url = "https://github.com/tinylabscom/mvm/releases/download/${prebuiltRelease.version}/mvmctl-${archive.target}.tar.gz";
            inherit (archive) sha256;
          };
          nativeBuildInputs = [
            pkgs.gnutar
            pkgs.gzip
          ];
          dontUnpack = true;
          dontConfigure = true;
          dontBuild = true;
          installPhase = ''
            runHook preInstall
            mkdir -p "$out/bin"
            tar -xzf "$src" -C "$out/bin" --strip-components=1
            test -x "$out/bin/mvmctl"
            runHook postInstall
          '';
          meta.mainProgram = "mvmctl";
        };
    in
    {
      devShells = forAllSystems (
        system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ (import rust-overlay) ];
          };

          rust = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;

          zig = if pkgs ? zig_0_13 then pkgs.zig_0_13 else pkgs.zig;

          optionalZigbuild = pkgs.lib.optional (pkgs ? cargo-zigbuild) pkgs.cargo-zigbuild;
          leanPackages =
            (with pkgs; [
              rust
              curl
              git
              jq
              just
              pkg-config
              protobuf
              zig
            ])
            ++ optionalZigbuild;

          buildInputs = with pkgs; [
            llvmPackages.libclang
            openssl
          ];
        in
        {
          default = pkgs.mkShell {
            packages = leanPackages;
            inherit buildInputs;
            LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
            PKG_CONFIG_PATH = pkgs.lib.makeSearchPath "lib/pkgconfig" [ pkgs.openssl.dev ];
            shellHook = ''
              echo "mvm development shell (${rust.version})"
              echo "Extended tools: nix develop .#full"
            '';
          };

          full = pkgs.mkShell {
            packages =
              leanPackages
              ++ (with pkgs; [
                rust-analyzer
                cargo-audit
                cargo-deny
                cargo-nextest
                lld
                nix
                nixfmt-rfc-style
                nodejs_22
                pnpm
                prettier
                python3
                ripgrep
                shellcheck
                shfmt
                treefmt
                zsh
              ])
              ++ (pkgs.lib.optional (pkgs ? cargo-machete) pkgs.cargo-machete);

            inherit buildInputs;

            LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
            PKG_CONFIG_PATH = pkgs.lib.makeSearchPath "lib/pkgconfig" [ pkgs.openssl.dev ];

            shellHook = ''
              # nix develop initially starts Bash. Replace only the
              # interactive shell with the user's configured zsh.
              if [[ "$-" == *i* ]]; then
                exec /bin/zsh -il
              fi

              echo "mvm development shell"
              echo "Rust toolchain: $(rustc --version)"
              echo "Try: just build, just test, or just lint"
              echo "Nix workload flake: ./nix"
            '';
          };
        }
      );

      formatter = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        pkgs.nixfmt-rfc-style
      );

      packages = forAllSystems (
        system:
        nixpkgs.lib.optionalAttrs (builtins.hasAttr system prebuiltRelease.archives) {
          prebuilt = prebuiltPackage system;
        }
      );
    };
}
