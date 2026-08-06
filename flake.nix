{
  description = "mvm contributor development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { nixpkgs, rust-overlay, ... }:
    let
      systems = [
        "aarch64-darwin"
        "x86_64-darwin"
        "aarch64-linux"
        "x86_64-linux"
      ];

      forAllSystems = nixpkgs.lib.genAttrs systems;
      toolchain = builtins.fromTOML (builtins.readFile ./rust-toolchain.toml);
      rustChannel = toolchain.toolchain.channel;
    in
    {
      devShells = forAllSystems (system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ (import rust-overlay) ];
          };

          rust = pkgs.rust-bin.stable.${rustChannel}.default.override {
            extensions = [
              "clippy"
              "rust-src"
              "rustfmt"
            ];
            targets = [
              "aarch64-unknown-linux-musl"
              "x86_64-unknown-linux-musl"
            ];
          };

          zig = if pkgs ? zig_0_13 then pkgs.zig_0_13 else pkgs.zig;

          optionalCargoTools =
            (pkgs.lib.optional (pkgs ? cargo-machete) pkgs.cargo-machete)
            ++ (pkgs.lib.optional (pkgs ? cargo-zigbuild) pkgs.cargo-zigbuild);
        in
        {
          default = pkgs.mkShell {
            packages = (with pkgs; [
              rust
              rust-analyzer
              cargo-audit
              cargo-deny
              cargo-nextest
              curl
              git
              jq
              just
              lld
              nix
              nixfmt-rfc-style
              nodejs_22
              pkg-config
              pnpm
              prettier
              protobuf
              python3
              ripgrep
              shellcheck
              shfmt
              treefmt
              zig
            ]) ++ optionalCargoTools;

            buildInputs = with pkgs; [
              llvmPackages.libclang
              openssl
            ];

            LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
            PKG_CONFIG_PATH = pkgs.lib.makeSearchPath "lib/pkgconfig" [ pkgs.openssl.dev ];

            shellHook = ''
              echo "mvm development shell"
              echo "Rust toolchain: ${rustChannel}"
              echo "Try: just build, just test, or just lint"
              echo "Nix workload flake: ./nix"
            '';
          };
        });

      formatter = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        pkgs.nixfmt-rfc-style);
    };
}
