{
  description = "LLM-agent microVM example — runs claude-code inside a Firecracker microVM";

  # ── What this example shows ──────────────────────────────────────────
  #
  # A microVM whose only service is an LLM coding agent (claude-code by
  # default). The agent's API key lives outside the rootfs at
  # `/run/mvm-secrets/claude-code/anthropic-api-key` — populated by
  # mvmctl's existing per-service secrets plumbing — so the secret never
  # enters the Nix store.
  #
  # Build (plan-38 manifest model — preferred):
  #   # Optional: scaffold an mvm.toml in this directory. Already shipped.
  #   #   mvmctl init nix/images/examples/llm-agent
  #   mvmctl build nix/images/examples/llm-agent
  #
  # Run with the project mounted at /workspace and the API key injected:
  #   mvmctl up nix/images/examples/llm-agent \
  #     --add-dir "$PWD:/workspace:rw" \
  #     --secret-file "$HOME/.config/mvm/secrets/anthropic:claude-code/anthropic-api-key"
  #
  # Legacy `mvmctl template create/build/up --template …` continues to
  # work as a hidden alias for one release; new code should use the
  # commands above. See specs/plans/38-manifest-driven-template-dx.md.
  #
  # The agent service follows ADR-002 §W2:
  #   - per-service uid auto-derived (NOT uid 0; NOT the guest agent's
  #     uid 901 — gets its own entry in the [1100..9099] range)
  #   - setpriv with --no-new-privs and an empty bounding capability set
  #   - seccomp tier `network` (allows socket/connect/sendto for HTTPS
  #     to the Anthropic API; blocks ptrace/keyctl/etc)
  #
  # ADR-002 §W3 verified-boot is intentionally on (default). The dev
  # variant of this flake (used for `mvmctl exec` / `mvmctl console`
  # iteration) is selected by mvmctl's --override-input dance, the same
  # way every other example works.
  #
  # Hypervisor-level egress policy (Proposal D in plan 32) is NOT yet
  # plumbed; today the agent has unrestricted outbound via NAT. When D
  # lands, this flake will gain `network_policy.egress_mode =
  # AllowDomainsStrict` + `domains = [ "api.anthropic.com" ]`.

  inputs = {
    mvm.url = "path:../../..";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    # Curated agent packages (claude-code, opencode, gemini-cli, …) with
    # a working binary cache at cache.numtide.com so we don't have to
    # rebuild Node + agents on every consumer machine.
    llm-agents = {
      url = "github:numtide/llm-agents.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { mvm, nixpkgs, llm-agents, ... }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      eachSystem = f: builtins.listToAttrs (map (system:
        { name = system; value = f system; }
      ) systems);
    in {
      packages = eachSystem (system:
        let
          pkgs = import nixpkgs { inherit system; config = {}; overlays = []; };
          claudeCode = llm-agents.packages.${system}.claude-code;

          # Service start script.
          #
          # 1. Refuses to crash-loop when the API key is missing — exit 0
          #    so the integration health check shows "no key configured"
          #    rather than burning CPU restarting forever. Operator drops
          #    the key file into ~/.config/mvm/secrets/ and re-runs
          #    `mvmctl up`.
          # 2. Mounts /workspace if `mvmctl up --add-dir <host>:/workspace:rw`
          #    was passed; otherwise warns and continues so the agent
          #    has a writable cwd in tmpfs.
          # 3. Execs claude-code under the workspace dir so the agent
          #    operates against the user's project tree.
          startScript = pkgs.writeShellScript "claude-code-start" ''
            set -eu

            secret_path=/run/mvm-secrets/claude-code/anthropic-api-key
            if [ ! -r "$secret_path" ]; then
              echo "[claude-code] no Anthropic API key at $secret_path"
              echo "[claude-code] populate via:"
              echo "    mvmctl up --secret-file \\"
              echo "      \"\$HOME/.config/mvm/secrets/anthropic:claude-code/anthropic-api-key\""
              echo "[claude-code] exiting cleanly so health check reports unconfigured."
              exit 0
            fi

            # claude-code reads ANTHROPIC_API_KEY from env. We
            # deliberately don't `cat` the secret into a long-lived
            # variable — read it once on exec and discard.
            ANTHROPIC_API_KEY="$(cat "$secret_path")"
            export ANTHROPIC_API_KEY

            workspace=/workspace
            if [ ! -d "$workspace" ]; then
              echo "[claude-code] no /workspace mount; falling back to /tmp/work"
              workspace=/tmp/work
              mkdir -p "$workspace"
            fi
            cd "$workspace"

            exec ${claudeCode}/bin/claude "$@"
          '';

        in {
          default = mvm.lib.${system}.mkGuest {
            name = "claude-code-vm";
            hostname = "claude-code-vm";

            # The agent's runtime closure. `claudeCode` covers the
            # binary; the others give the agent useful tools inside the
            # VM (ripgrep + jq are nigh-mandatory; git + curl let the
            # agent commit + fetch).
            packages = [
              claudeCode
              pkgs.git
              pkgs.curl
              pkgs.ripgrep
              pkgs.jq
              pkgs.coreutils
              pkgs.bashInteractive
            ];

            services.claude-code = {
              command = "${startScript}";
              # ADR-002 §W2.4: outbound HTTPS to the Anthropic API
              # needs `socket(2)`, `connect(2)`, etc. — `network` is
              # the smallest tier that allows them.
              seccomp = "network";
              env = {
                # Bias the agent toward the mounted workspace.
                HOME = "/workspace";
                # Without explicit TERM, claude-code's TUI tries to
                # negotiate a non-existent capability and 100% CPUs.
                TERM = "dumb";
              };
            };

            healthChecks.claude-code = {
              # Liveness: the process exists. claude-code listens on
              # stdin in interactive mode, not on a TCP port, so the
              # usual `/proc/net/tcp` hex-port grep doesn't apply.
              # `pgrep` is busybox-provided.
              healthCmd = "pgrep -f claude >/dev/null";
              healthIntervalSecs = 30;
              healthTimeoutSecs = 5;
            };
          };
        });
    };
}
