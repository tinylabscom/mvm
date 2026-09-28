{ pkgs }:

let
  version = "2.1.273";
  releases = {
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
  release = releases.${pkgs.stdenv.hostPlatform.system};

  claudeCode = pkgs.stdenvNoCC.mkDerivation {
    pname = "claude-code-native";
    inherit version;
    src = pkgs.fetchurl {
      url = "https://downloads.claude.ai/claude-code-releases/${version}/${release.platform}/claude";
      inherit (release) sha256;
    };
    dontUnpack = true;
    nativeBuildInputs = [ pkgs.patchelf ];
    installPhase = ''
      runHook preInstall
      install -Dm755 "$src" "$out/bin/claude"
      patchelf --set-interpreter \
        "${pkgs.musl}/lib/${release.muslLoader}" "$out/bin/claude"
      runHook postInstall
    '';
  };
in
{
  inherit version claudeCode;
  agent = pkgs.writeShellScriptBin "mvm-agent" ''
    : "''${HTTPS_PROXY:?mvm did not inject its governed egress proxy}"

    case "''${ANTHROPIC_API_KEY:-}" in
      mvm-secret-*) ;;
      *)
        echo "mvm-agent: ANTHROPIC_API_KEY is not a host-minted placeholder" >&2
        exit 78
        ;;
    esac

    export DISABLE_AUTOUPDATER=1
    export DISABLE_TELEMETRY=1
    export DISABLE_ERROR_REPORTING=1
    export CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1

    input="$(${pkgs.coreutils}/bin/cat)"
    if [ "$input" = "mvm-agent-smoke" ]; then
      echo "agent-workload smoke: placeholder-present"
      exec ${claudeCode}/bin/claude --version
    fi

    printf '%s' "$input" | ${claudeCode}/bin/claude --bare -p "$@"
  '';
}
