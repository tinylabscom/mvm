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
    in
    {
      devShells = forAllSystems (system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ (import rust-overlay) ];
          };

          rust = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;

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
              zsh
            ]) ++ optionalCargoTools;

            buildInputs = with pkgs; [
              llvmPackages.libclang
              openssl
            ];

            LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
            PKG_CONFIG_PATH = pkgs.lib.makeSearchPath "lib/pkgconfig" [ pkgs.openssl.dev ];

            shellHook = ''
              # WASM target for the portable half of the workspace.
              if command -v rustup >/dev/null 2>&1; then
                rustup target add wasm32-unknown-unknown \
                  >/dev/null 2>&1 || true
              fi

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
        });

      formatter = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        pkgs.nixfmt-rfc-style);
    };
}
