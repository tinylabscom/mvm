{
  description = "Claude Code agent guest — interactive workbench and sealed headless profiles";

  # Two profiles off one image recipe:
  #   `default`  — accessible (dev-tier) image: `entrypoint.shell` puts an
  #                interactive bash behind `mvmctl machine console`, with
  #                `claude` on PATH.
  #   `headless` — sealed image: `entrypoint.command` runs `claude --bare -p`
  #                reading its task from the stdin input plane
  #                (`machine run --entrypoint --stdin -`).
  #
  # The binary is the first-party native musl build, pinned by version and
  # SHA-256 from downloads.claude.ai's per-version manifest.json. It is
  # dynamically linked against musl only (single DT_NEEDED), so the image
  # needs no glibc and no Node.js — just musl's own loader, supplied from
  # pkgs.musl via patchelf. Node/npm are NOT in this image; Claude Code's
  # own runtime is self-contained (Bun-compiled).
  #
  # The `github:tinylabscom/mvm` pin is load-bearing: a source-checkout
  # `mvmctl machine run` rewrites it to the in-repo flake, so this builds
  # without a release round-trip.

  inputs.mvm.url = "github:tinylabscom/mvm/main?dir=nix";
  inputs.nixpkgs.follows = "mvm/nixpkgs";

  outputs =
    { mvm, nixpkgs, ... }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      eachSystem = f: builtins.listToAttrs
        (map (system: { name = system; value = f system; }) systems);

      # Pinned release. Checksums come from
      # https://downloads.claude.ai/claude-code-releases/${version}/manifest.json
      # (first-party, per-platform SHA-256). Bump version + both checksums
      # together.
      version = "2.1.273";
      release = {
        x86_64-linux = {
          platform = "linux-x64-musl";
          muslLoader = "ld-musl-x86_64.so.1";
          sha256 = "19305145028dfb774ff16fd2066b8991cb93d1afbe4b8ff6389aec54f1b309f0";
        };
        aarch64-linux = {
          platform = "linux-arm64-musl";
          muslLoader = "ld-musl-aarch64.so.1";
          sha256 = "0ea64e932c6fac35ce4e992140612157fe1cecab052d59539873b350a594d3c6";
        };
      };
    in
    {
      packages = eachSystem (system:
        let
          pkgs = import nixpkgs { inherit system; };
          rel = release.${system};

          claudeBin = pkgs.stdenvNoCC.mkDerivation {
            pname = "claude-code-native";
            inherit version;
            src = pkgs.fetchurl {
              url = "https://downloads.claude.ai/claude-code-releases/${version}/${rel.platform}/claude";
              inherit (rel) sha256;
            };
            dontUnpack = true;
            nativeBuildInputs = [ pkgs.patchelf ];
            installPhase = ''
              runHook preInstall
              install -Dm755 "$src" "$out/bin/claude"
              patchelf --set-interpreter \
                "${pkgs.musl}/lib/${rel.muslLoader}" "$out/bin/claude"
              runHook postInstall
            '';
          };

          # Env-setting wrapper: every lane goes through it so the egress
          # guard, telemetry kill switches, key file, and state dir behave
          # identically whether launched from the console or as PID 1's
          # sealed command.
          claude = pkgs.writeShellScriptBin "claude" ''
            # No guest NIC exists: every remote origin must be admitted via
            # --allow-host / [network].allow_hosts, and traffic must ride the
            # injected proxy. Fail loudly rather than time out.
            : "''${ALL_PROXY:?mvm egress proxy is required; pass --allow-host for every remote origin}"

            # The bundled ripgrep is a glibc build; use the store's musl one.
            export USE_BUILTIN_RIPGREP=0
            export PATH="${pkgs.ripgrep}/bin:${pkgs.gitMinimal}/bin:${pkgs.coreutils}/bin:$PATH"

            # Optional traffic never gets to hit the deny wall. The rootfs is
            # read-only anyway, so the auto-updater could not work.
            export DISABLE_AUTOUPDATER=1
            export DISABLE_TELEMETRY=1
            export DISABLE_ERROR_REPORTING=1
            export CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1

            # Node subprocesses (MCP servers, hooks) ignore the injected
            # HTTPS_PROXY without this (node >= 22.18).
            export NODE_USE_ENV_PROXY=1

            # Guest $HOME is tmpfs and vanishes on stop. If a workspace disk
            # is mounted at /work, keep agent state there instead.
            if [ -z "''${CLAUDE_CONFIG_DIR:-}" ] && [ -d /work ] && [ -w /work ]; then
              export CLAUDE_CONFIG_DIR=/work/.claude
            fi

            # Interim key posture (guest-held; see the plan's W5 for the
            # placeholder-substitution destination): a key file mounted
            # read-only at /data/secrets/anthropic wins over nothing, and an
            # explicit env var wins over the file.
            if [ -z "''${ANTHROPIC_API_KEY:-}" ] && [ -r /data/secrets/anthropic ]; then
              ANTHROPIC_API_KEY="$(cat /data/secrets/anthropic)"
              export ANTHROPIC_API_KEY
            fi

            exec ${claudeBin}/bin/claude "$@"
          '';
        in
        {
          package = claude;

          # Interactive workbench: accessible image, attach with
          # `mvmctl machine console <name>` and run `claude`.
          default = mvm.lib.${system}.mkGuest {
            name = "claude-code";
            packages = [ claude pkgs.bashInteractive ];
            entrypoint.shell = "${pkgs.bashInteractive}/bin/bash";
            vcpus = 2;
            memory_mib = 2048;
          };

          # Sealed headless lane: task text arrives on stdin
          # (`machine run --entrypoint --stdin -`), result on stdout/console.
          # Non-default profiles are addressed as `tenant-<name>`; the CLI
          # selects this one as `--profile headless` / `--flake-profile
          # headless`.
          tenant-headless = mvm.lib.${system}.mkGuest {
            name = "claude-code-headless";
            packages = [ claude ];
            entrypoint.command = [ "${claude}/bin/claude" "--bare" "-p" ];
            vcpus = 2;
            memory_mib = 2048;
          };
        });
    };
}
