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

    in
    {
      packages = eachSystem (system:
        let
          pkgs = import nixpkgs { inherit system; };
          agentRecipe = import "${mvm}/images/examples/llm-agent" { inherit pkgs; };
          claudeBin = agentRecipe.claudeCode;
          version = agentRecipe.version;

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

            # Interim guest-held key posture: a key file mounted read-only at
            # /data/secrets/anthropic wins over nothing, and an explicit env
            # var wins over the file.
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
