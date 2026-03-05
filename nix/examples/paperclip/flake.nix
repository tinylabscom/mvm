{
  description = "Paperclip microVM — AI agent orchestration platform";

  inputs = {
    mvm.url = "path:../../guest-lib";
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

          version = "2026.3.4";
          rev = "c7c96feef77e20bee60be39ad17a664a14a0c3f1";

          # Phase 1: Clone repo + pnpm install (fixed-output derivation).
          # FOD can access the network; output verified by content hash.
          # To update: change rev, set outputHash = "", build to get new hash.
          paperclip-src = pkgs.stdenv.mkDerivation {
            pname = "paperclip-src";
            inherit version;

            dontUnpack = true;
            dontFixup = true;

            outputHashMode = "recursive";
            outputHash = "";  # Build once to get the correct hash

            nativeBuildInputs = [ pkgs.nodejs_22 pkgs.cacert pkgs.git ];

            SSL_CERT_FILE = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";

            buildPhase = ''
              export HOME=$TMPDIR
              export COREPACK_ENABLE_STRICT=0

              # Enable pnpm via corepack
              corepack enable --install-directory=$TMPDIR/bin
              export PATH=$TMPDIR/bin:$PATH
              corepack prepare pnpm@9.15.4 --activate

              # Clone at pinned commit
              git clone https://github.com/paperclipai/paperclip.git $TMPDIR/paperclip
              cd $TMPDIR/paperclip
              git checkout ${rev}

              # Install dependencies
              pnpm install --frozen-lockfile --ignore-scripts

              # Copy to output (without .git to save space)
              cp -r $TMPDIR/paperclip $out
              rm -rf $out/.git
            '';

            installPhase = "true";
          };

          # Phase 2: Patch native binaries (embedded-postgres, etc.).
          # Separate from FOD because patching changes the content hash.
          paperclip-pkg = pkgs.stdenv.mkDerivation {
            pname = "paperclip";
            inherit version;
            src = paperclip-src;
            nativeBuildInputs = [ pkgs.autoPatchelfHook ];
            buildInputs = [ pkgs.stdenv.cc.cc.lib pkgs.glibc ];
            autoPatchelfIgnoreMissingDeps = true;
            dontBuild = true;
            installPhase = "cp -r $src $out";
          };

          # Phase 3: Build TypeScript (compile server + UI).
          paperclip-built = pkgs.stdenv.mkDerivation {
            pname = "paperclip-built";
            inherit version;
            src = paperclip-pkg;

            nativeBuildInputs = [ pkgs.nodejs_22 ];

            buildPhase = ''
              export HOME=$TMPDIR
              export COREPACK_ENABLE_STRICT=0

              corepack enable --install-directory=$TMPDIR/bin
              export PATH=$TMPDIR/bin:$PATH
              corepack prepare pnpm@9.15.4 --activate

              # Build in a writable copy
              cp -r $src $TMPDIR/build
              chmod -R u+w $TMPDIR/build
              cd $TMPDIR/build

              pnpm --filter @paperclipai/shared build
              pnpm --filter @paperclipai/db build
              pnpm --filter @paperclipai/ui build
              pnpm --filter @paperclipai/server build

              mkdir -p $out
              cp -r $TMPDIR/build/* $out/
            '';

            installPhase = "true";
          };

        in {
          default = mvm.lib.${system}.mkGuest {
            name = "paperclip";
            hostname = "paperclip";
            packages = [ pkgs.nodejs_22 pkgs.git paperclip-built ];

            users.paperclip = {
              home = "/var/lib/paperclip";
            };

            services.paperclip = {
              preStart = pkgs.writeShellScript "paperclip-setup" ''
                mount -t tmpfs -o mode=0755,size=1g tmpfs /var/lib/paperclip
                chown paperclip:paperclip /var/lib/paperclip
                install -d -o paperclip -g paperclip /var/lib/paperclip/{instances,data}
              '';

              command = pkgs.writeShellScript "paperclip-start" ''
                set -eu
                cd /var/lib/paperclip

                [ -f /mnt/config/env.sh ] && . /mnt/config/env.sh || true
                [ -f /mnt/secrets/api-keys.env ] && . /mnt/secrets/api-keys.env || true

                export HOME=/var/lib/paperclip
                export NODE_ENV=production
                export PAPERCLIP_HOME=/var/lib/paperclip
                export PAPERCLIP_INSTANCE_ID=''${PAPERCLIP_INSTANCE_ID:-default}
                export HOST=0.0.0.0
                export PORT=''${PORT:-3100}
                export SERVE_UI=true
                export PAPERCLIP_DEPLOYMENT_MODE=''${PAPERCLIP_DEPLOYMENT_MODE:-local_trusted}
                export PAPERCLIP_DEPLOYMENT_EXPOSURE=''${PAPERCLIP_DEPLOYMENT_EXPOSURE:-private}

                echo "[paperclip] starting server on port $PORT" >&2
                exec ${pkgs.nodejs_22}/bin/node \
                  --import ${paperclip-built}/server/node_modules/tsx/dist/loader.mjs \
                  ${paperclip-built}/server/dist/index.js
              '';

              user = "paperclip";
            };

            # Port 3100 = 0x0C1C
            healthChecks.paperclip = {
              healthCmd = "grep -q ':0C1C ' /proc/net/tcp 2>/dev/null || grep -q ':0C1C ' /proc/net/tcp6 2>/dev/null";
              healthIntervalSecs = 10;
              healthTimeoutSecs = 5;
            };
          };
        });
    };
}
