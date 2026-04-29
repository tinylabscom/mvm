{
  description = "OpenClaw microVM - pre-installed at build time";

  inputs = {
    mvm.url = "path:../..";
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  };

  outputs = { mvm, nixpkgs, ... }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      eachSystem = f: builtins.listToAttrs (map (system:
        { name = system; value = f system; }
      ) systems);
    in {
      packages = eachSystem (system:
        let
          pkgs = import nixpkgs { inherit system; };

          # Phase 1: Download openclaw via npm (fixed-output derivation).
          # FOD can access the network; output verified by content hash.
          # To update: change version, set outputHash = "", build to get new hash.
          openclaw-src = pkgs.stdenv.mkDerivation {
            pname = "openclaw-src";
            version = "2026.3.2";

            dontUnpack = true;
            dontFixup = true;

            outputHashMode = "recursive";
            outputHash = "";

            nativeBuildInputs = [ pkgs.nodejs_22 pkgs.cacert pkgs.git ];

            SSL_CERT_FILE = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";

            buildPhase = ''
              export HOME=$TMPDIR
              export npm_config_cache=$TMPDIR/.npm

              mkdir -p $out/lib
              cd $out/lib
              npm install --ignore-scripts --no-bin-links openclaw@$version

              rm -rf $out/bin
              find $out -name '.bin' -type d -exec rm -rf {} + 2>/dev/null || true
            '';

            installPhase = "true";
          };

          # Phase 2: Bundle all JS into a single file with esbuild.
          # Loading 932 JS files individually from virtio-blk takes 10+ min.
          # A single bundle loads in seconds.
          # Native .node addons are replaced with empty stubs (--loader:.node=empty)
          # so no autoPatchelf phase is needed.
          openclaw-bundle = pkgs.stdenv.mkDerivation {
            pname = "openclaw-bundle";
            version = openclaw-src.version;
            src = openclaw-src;
            nativeBuildInputs = [ pkgs.esbuild pkgs.nodejs_22 ];

            buildPhase = ''
              OC=$src/lib/node_modules/openclaw
              RUN_MAIN=$(ls $OC/dist/run-main-*.js | head -1)

              # Inject the real import path into the entry wrapper (see gateway-entry.mjs).
              sed "s|IMPORT_PATH|$RUN_MAIN|" ${./gateway-entry.mjs} > $TMPDIR/entry.mjs

              esbuild $TMPDIR/entry.mjs \
                --bundle --format=esm --platform=node --minify \
                --outfile=$TMPDIR/openclaw-bundle.mjs \
                --log-level=warning --log-limit=0 \
                --loader:.node=empty \
                --banner:js='import{createRequire as $$cr}from"module";const require=$$cr(import.meta.url);' \
                '--external:@node-llama-cpp/*' \
                --external:chromium-bidi --external:ffmpeg-static

              mkdir -p $out/lib/openclaw/dist
              cp $TMPDIR/openclaw-bundle.mjs $out/lib/openclaw/openclaw.mjs
              cp $OC/package.json $out/lib/openclaw/package.json
              cp -r $OC/dist/control-ui $out/lib/openclaw/dist/control-ui
              mkdir -p $out/lib/openclaw/docs/reference
              cp -r $OC/docs/reference/templates $out/lib/openclaw/docs/reference/templates
            '';

            installPhase = "true";
          };

          # Convenience wrapper: `openclaw <subcommand>` inside the VM.
          # Enables `mvmctl vm exec oc -- openclaw nodes pending` from the host.
          openclaw-cli = pkgs.writeShellScriptBin "openclaw" ''
            export HOME=/var/lib/openclaw
            export OPENCLAW_HOME=/var/lib/openclaw
            export OPENCLAW_CONFIG_PATH=/var/lib/openclaw/config.json
            exec ${pkgs.nodejs_22}/bin/node \
              --disable-warning=ExperimentalWarning \
              ${openclaw-bundle}/lib/openclaw/openclaw.mjs "$@"
          '';

        in {
          default = mvm.lib.${system}.mkGuest {
            name = "openclaw";
            hostname = "openclaw";
            packages = [ pkgs.nodejs_22 openclaw-bundle openclaw-cli ];

            users.openclaw = {
              home = "/var/lib/openclaw";
            };

            services.openclaw = {
              preStart = pkgs.writeShellScript "openclaw-setup" ''
                mountpoint -q /var/lib/openclaw || mount -t tmpfs -o mode=0755,size=512m tmpfs /var/lib/openclaw
                chown openclaw:openclaw /var/lib/openclaw
                install -d -o openclaw -g openclaw /var/lib/openclaw/{workspace,data}

                # Copy custom workspace templates from config drive (AGENTS.md, SOUL.md, etc.)
                if [ -d /mnt/config/templates ]; then
                  echo "[setup] Copying custom templates from /mnt/config/templates" >&2
                  cp -r /mnt/config/templates/* /var/lib/openclaw/workspace/
                  chown -R openclaw:openclaw /var/lib/openclaw/workspace/
                fi

                if [ -f /mnt/config/openclaw.json ]; then
                  echo "[setup] Using config from /mnt/config/openclaw.json" >&2
                  ${pkgs.envsubst}/bin/envsubst < /mnt/config/openclaw.json > /var/lib/openclaw/config.json
                  chown openclaw:openclaw /var/lib/openclaw/config.json
                else
                  echo "[setup] No config found, using defaults" >&2
                  cat > /var/lib/openclaw/config.json <<'CONFIG'
{
  "gateway": {
    "mode": "local",
    "channelHealthCheckMinutes": 0,
    "auth": { "mode": "none" },
    "reload": { "mode": "off" },
    "controlUi": {
      "dangerouslyAllowHostHeaderOriginFallback": true
    }
  }
}
CONFIG
                  chown openclaw:openclaw /var/lib/openclaw/config.json
                fi
              '';

              command = pkgs.writeShellScript "openclaw-start" ''
                set -eu
                cd /var/lib/openclaw

                [ -f /mnt/config/env.sh ] && . /mnt/config/env.sh || true
                [ -f /mnt/secrets/api-keys.env ] && . /mnt/secrets/api-keys.env || true

                export HOME=/var/lib/openclaw
                export OPENCLAW_HOME=/var/lib/openclaw
                export OPENCLAW_CONFIG_PATH=/var/lib/openclaw/config.json
                export OPENCLAW_NODE_OPTIONS_READY=1
                export OPENCLAW_GATEWAY_TOKEN=''${OPENCLAW_GATEWAY_TOKEN:-mvm}
                export NODE_COMPILE_CACHE=/var/lib/openclaw/.v8-cache
                mkdir -p "$NODE_COMPILE_CACHE"

                echo "[openclaw] starting gateway on loopback:3001" >&2
                exec ${pkgs.nodejs_22}/bin/node \
                  --disable-warning=ExperimentalWarning \
                  ${openclaw-bundle}/lib/openclaw/openclaw.mjs gateway run \
                  --bind loopback \
                  --port 3001 \
                  --allow-unconfigured \
                  --force \
                  --token "$OPENCLAW_GATEWAY_TOKEN"
              '';

              user = "openclaw";
            };

            # TCP proxy: 0.0.0.0:3000 -> 127.0.0.1:3001
            # Gateway binds to loopback so all connections appear local and
            # are auto-approved by OpenClaw (no device pairing prompts).
            # Token auth (--token) remains the actual security boundary.
            services.openclaw-proxy = {
              command = pkgs.writeShellScript "openclaw-proxy" ''
                set -eu
                # Wait for gateway on loopback:3001 (hex 0x0BB9).
                while ! grep -q ':0BB9 ' /proc/net/tcp 2>/dev/null; do
                  sleep 1
                done
                # Stabilization delay: the gateway's runGatewayLoop fires a second
                # concurrent startGatewayServer() that takes ~5s (lock timeout) and
                # briefly probes port 3001. Wait for that to settle before proxying.
                sleep 8
                echo "[proxy] gateway ready, proxying 0.0.0.0:3000 -> 127.0.0.1:3001" >&2
                exec ${pkgs.nodejs_22}/bin/node -e '
                  const net = require("net");
                  net.createServer(c => {
                    const t = net.connect(3001, "127.0.0.1");
                    c.pipe(t); t.pipe(c);
                    c.on("error", () => t.destroy());
                    t.on("error", () => c.destroy());
                  }).listen(3000, "0.0.0.0", () => {
                    process.stderr.write("[proxy] listening on 0.0.0.0:3000\n");
                  });
                '
              '';

              user = "openclaw";
            };

            healthChecks.openclaw = {
              healthCmd = "grep -q ':0BB8 ' /proc/net/tcp 2>/dev/null || grep -q ':0BB8 ' /proc/net/tcp6 2>/dev/null";
              healthIntervalSecs = 10;
              healthTimeoutSecs = 5;
              startupGraceSecs = 120;
            };
          };
        });
    };
}
