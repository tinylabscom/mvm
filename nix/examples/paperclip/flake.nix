{
  description = "Paperclip microVM — AI agent orchestration platform";

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

          version = "2026.3.4";
          rev = "c7c96feef77e20bee60be39ad17a664a14a0c3f1";

          # Source: Nix fetchGit is deterministic — same rev always produces
          # the same hash, so this never breaks after garbage collection.
          paperclip-git = builtins.fetchGit {
            url = "https://github.com/paperclipai/paperclip.git";
            inherit rev;
            allRefs = true;
          };

          # Phase 1: pnpm install (fixed-output derivation).
          # FOD can access the network; output verified by content hash.
          # Uses npm instead of pnpm for deterministic node_modules output.
          # To update: change rev above, set outputHash = "", build to get new hash.
          paperclip-src = pkgs.stdenv.mkDerivation {
            pname = "paperclip-src";
            inherit version;
            src = paperclip-git;

            dontFixup = true;

            outputHashMode = "recursive";
            outputHashAlgo = "sha256";
            outputHash = "sha256-h5jP1tuywwblhFDhMOrKC3frkB3dE0SqAIWStBfsrvg=";

            nativeBuildInputs = [ pkgs.nodejs_22 pkgs.cacert ];

            SSL_CERT_FILE = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";

            buildPhase = ''
              export HOME=$TMPDIR
              export npm_config_cache=$TMPDIR/.npm

              cp -r $src $out
              chmod -R u+w $out
              cd $out

              # npm install is more deterministic than pnpm for FODs.
              # The pnpm content-addressable store uses hardlinks whose
              # ordering varies between runs, breaking the fixed hash.
              # Upstream uses pnpm-workspace.yaml + workspace:* protocol.
              # npm needs a "workspaces" field and doesn't support workspace:*.
              # Patch all package.json files to be npm-compatible.
              node -e "
                const fs = require('fs');
                const path = require('path');
                // Add workspaces to root package.json
                const rootPkg = JSON.parse(fs.readFileSync('package.json','utf8'));
                rootPkg.workspaces = ['packages/*','packages/adapters/*','server','ui','cli'];
                // Force modern @types/node (npm resolves to 12.x otherwise)
                // Pin better-auth to match pnpm lock (1.5.x moved drizzle adapter)
                rootPkg.overrides = rootPkg.overrides || {};
                rootPkg.overrides['@types/node'] = '>=20';
                rootPkg.overrides['better-auth'] = '1.4.18';
                fs.writeFileSync('package.json', JSON.stringify(rootPkg, null, 2) + '\n');
                // Replace workspace:* with * in all package.json files
                function walk(dir) {
                  for (const f of fs.readdirSync(dir, {withFileTypes:true})) {
                    if (f.name === 'node_modules') continue;
                    const p = path.join(dir, f.name);
                    if (f.isDirectory()) walk(p);
                    else if (f.name === 'package.json') {
                      let txt = fs.readFileSync(p,'utf8');
                      if (txt.includes('workspace:')) {
                        txt = txt.replace(/\"workspace:\*\"/g, '\"*\"').replace(/\"workspace:\^[^\"]*\"/g, '\"*\"');
                        fs.writeFileSync(p, txt);
                      }
                    }
                  }
                }
                walk('.');
              "
              npm install --ignore-scripts --no-bin-links --legacy-peer-deps
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
          # npm flat layout means @types/* are hoisted to root node_modules
          # so tsc resolution works without the pnpm symlink workaround.
          paperclip-built = pkgs.stdenv.mkDerivation {
            pname = "paperclip-built";
            inherit version;
            src = paperclip-pkg;

            nativeBuildInputs = [ pkgs.nodejs_22 ];

            buildPhase = ''
              export HOME=$TMPDIR

              # Build in a writable copy
              cp -r $src $TMPDIR/build
              chmod -R u+w $TMPDIR/build
              cd $TMPDIR/build

              ROOT=$TMPDIR/build
              TSC="$ROOT/node_modules/typescript/bin/tsc"
              VITE="$ROOT/node_modules/vite/bin/vite.js"

              # Upstream is missing @types/ws — add a minimal type shim so tsc
              # can compile server/src/realtime/live-events-ws.ts.
              cat > server/src/types/ws.d.ts << 'WS_TYPES'
              declare module "ws" {
                import { EventEmitter } from "events";
                import { IncomingMessage, Server as HttpServer } from "http";
                import { Duplex } from "stream";
                class WebSocket extends EventEmitter {
                  static readonly OPEN: number;
                  static readonly CLOSED: number;
                  readyState: number;
                  send(data: any, cb?: (err?: Error) => void): void;
                  close(code?: number, reason?: string): void;
                  on(event: string, listener: (...args: any[]) => void): this;
                  terminate(): void;
                  ping(data?: any, mask?: boolean, cb?: (err: Error) => void): void;
                }
                class WebSocketServer extends EventEmitter {
                  clients: Set<WebSocket>;
                  constructor(options?: { noServer?: boolean; server?: HttpServer });
                  on(event: "connection", listener: (socket: WebSocket, request: IncomingMessage) => void): this;
                  on(event: string, listener: (...args: any[]) => void): this;
                  handleUpgrade(request: IncomingMessage, socket: Duplex, head: Buffer, callback: (ws: WebSocket) => void): void;
                  emit(event: string, ...args: any[]): boolean;
                }
                export { WebSocket, WebSocketServer };
              }
              WS_TYPES

              # Helper: rewrite a workspace package's exports from src/*.ts → dist/*.js.
              # Preserves all existing export keys; only rewrites the file paths.
              # Called after tsc so Node.js resolves compiled JS instead of src TS.
              patch_exports() {
                local pkg_dir="$1"
                node -e "
                  const fs = require('fs');
                  const path = require('path');
                  const f = path.join('$pkg_dir', 'package.json');
                  const p = JSON.parse(fs.readFileSync(f, 'utf8'));

                  // Rewrite a single path: ./src/foo.ts -> ./dist/foo.js
                  function rewrite(v) {
                    if (typeof v !== 'string') return v;
                    return v.replace(/^\.\/src\//, './dist/').replace(/\.ts$/, '.js');
                  }

                  // Rewrite all values in an exports map (handles nested conditions)
                  function rewriteExports(e) {
                    if (typeof e === 'string') return rewrite(e);
                    if (typeof e === 'object' && e !== null) {
                      const out = {};
                      for (const [k, v] of Object.entries(e)) out[k] = rewriteExports(v);
                      return out;
                    }
                    return e;
                  }

                  if (p.main) p.main = rewrite(p.main);
                  if (p.module) p.module = rewrite(p.module);
                  if (p.types) p.types = rewrite(p.types);
                  if (p.exports) p.exports = rewriteExports(p.exports);
                  fs.writeFileSync(f, JSON.stringify(p, null, 2) + '\n');
                "
              }

              echo "Building @paperclipai/shared..."
              (cd packages/shared && node "$TSC")
              patch_exports packages/shared

              echo "Building @paperclipai/db..."
              (cd packages/db && node "$TSC" && cp -r src/migrations dist/migrations)
              patch_exports packages/db

              echo "Building @paperclipai/adapter-utils..."
              (cd packages/adapter-utils && node "$TSC")
              patch_exports packages/adapter-utils

              echo "Building @paperclipai/adapters (claude-local, codex-local, openclaw)..."
              (cd packages/adapters/claude-local && node "$TSC")
              patch_exports packages/adapters/claude-local
              (cd packages/adapters/codex-local && node "$TSC")
              patch_exports packages/adapters/codex-local
              (cd packages/adapters/openclaw && node "$TSC")
              patch_exports packages/adapters/openclaw

              echo "Building UI..."
              (cd ui && node "$VITE" build)

              echo "Building server..."
              (cd server && node "$TSC")

              # Phase 2: Prune dev-only packages from node_modules before copying
              # to $out.  These are only needed at build time (compile, lint, test)
              # and add tens of MB to the rootfs closure for no runtime benefit.
              echo "Pruning dev-only packages from node_modules..."
              cd $TMPDIR/build

              # Remove dev-only top-level packages by name.
              for pkg in \
                typescript \
                vite \
                @vitejs \
                vitest \
                "@vitest" \
                eslint \
                "@eslint" \
                tsx \
                esbuild \
                "drizzle-kit" \
                "@biomejs" \
                "@tanstack/react-query-devtools" \
                "rollup" \
                "postcss" \
                "tailwindcss" \
                "autoprefixer" \
                "prettier" \
              ; do
                rm -rf "node_modules/$pkg"
              done

              # Remove @types/* — not needed at runtime (type declarations only).
              rm -rf node_modules/@types

              # Remove .d.ts files that live outside dist/ directories — these are
              # source-level type declarations, not runtime artifacts.
              find node_modules -name '*.d.ts' -not -path '*/dist/*' -delete 2>/dev/null || true

              # Strip devDependencies from workspace package.json files so that any
              # post-install tooling doesn't try to re-fetch them.
              node -e "
                const fs = require('fs');
                const path = require('path');
                function strip(dir) {
                  const pkgPath = path.join(dir, 'package.json');
                  if (!fs.existsSync(pkgPath)) return;
                  const p = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
                  if (p.devDependencies) {
                    delete p.devDependencies;
                    fs.writeFileSync(pkgPath, JSON.stringify(p, null, 2) + '\n');
                  }
                }
                const dirs = ['packages/shared','packages/db','packages/adapter-utils',
                  'packages/adapters/claude-local','packages/adapters/codex-local',
                  'packages/adapters/openclaw','server','ui','cli','.'];
                dirs.forEach(strip);
              "

              echo "Prune complete."

              mkdir -p $out
              cp -r $TMPDIR/build/* $out/
            '';

            installPhase = "true";
          };

        in {
          default = mvm.lib.${system}.mkGuest {
            name = "paperclip";
            hostname = "paperclip";
            packages = [ pkgs.nodejs_22 pkgs.git pkgs.postgresql_16 paperclip-built ];

            users.paperclip = {
              home = "/var/lib/paperclip";
            };

            users.postgres = {
              home = "/var/lib/postgresql";
            };

            # PostgreSQL service — runs before paperclip.
            # The embedded-postgres npm module ships platform binaries that
            # don't survive Nix patching in the microVM, so we use Nix's
            # own PostgreSQL and expose it via DATABASE_URL.
            services.postgres = {
              preStart = pkgs.writeShellScript "postgres-setup" ''
                mount -t tmpfs -o mode=0755,size=512m tmpfs /var/lib/postgresql
                chown postgres:postgres /var/lib/postgresql
                install -d -o postgres -g postgres /var/lib/postgresql/data
              '';

              command = pkgs.writeShellScript "postgres-start" ''
                set -eu
                export PGDATA=/var/lib/postgresql/data

                if [ ! -f "$PGDATA/PG_VERSION" ]; then
                  echo "[postgres] initializing database" >&2
                  ${pkgs.postgresql_16}/bin/initdb -D "$PGDATA" --no-locale --encoding=UTF8
                  # Allow local connections without password
                  echo "host all all 127.0.0.1/32 trust" >> "$PGDATA/pg_hba.conf"
                  echo "local all all trust" >> "$PGDATA/pg_hba.conf"
                fi

                echo "[postgres] starting on port 5432" >&2
                exec ${pkgs.postgresql_16}/bin/postgres \
                  -D "$PGDATA" \
                  -k /tmp \
                  -h 127.0.0.1 \
                  -p 5432
              '';

              user = "postgres";
            };

            services.paperclip = {
              preStart = pkgs.writeShellScript "paperclip-setup" ''
                mount -t tmpfs -o mode=0755,size=1g tmpfs /var/lib/paperclip
                chown paperclip:paperclip /var/lib/paperclip
                install -d -o paperclip -g paperclip /var/lib/paperclip/instances/default/logs
                install -d -o paperclip -g paperclip /var/lib/paperclip/instances/default/data/storage
                install -d -o paperclip -g paperclip /var/lib/paperclip/instances/default/secrets

                # Copy config.json from config drive mount if provided via
                # mvmctl run -v path/to/config:/mnt/config
                if [ -f /mnt/config/paperclip.json ]; then
                  cp /mnt/config/paperclip.json /var/lib/paperclip/instances/default/config.json
                  chown paperclip:paperclip /var/lib/paperclip/instances/default/config.json
                fi

                # Wait for postgres to be ready
                for i in $(seq 1 30); do
                  if ${pkgs.postgresql_16}/bin/pg_isready -h 127.0.0.1 -p 5432 -q 2>/dev/null; then
                    break
                  fi
                  sleep 1
                done

                # Create the paperclip database
                ${pkgs.postgresql_16}/bin/psql -h 127.0.0.1 -p 5432 -U postgres \
                  -tc "SELECT 1 FROM pg_database WHERE datname='paperclip'" | grep -q 1 || \
                  ${pkgs.postgresql_16}/bin/createdb -h 127.0.0.1 -p 5432 -U postgres paperclip
              '';

              # Default env vars for paperclip.  These can be overridden at
              # launch with: mvmctl run --env DATABASE_URL=... --env PORT=...
              # (--env values are sourced globally by the init before services
              # start, so they take precedence over these defaults).
              env = {
                HOME = "/var/lib/paperclip";
                NODE_ENV = "production";
                PAPERCLIP_HOME = "/var/lib/paperclip";
                PAPERCLIP_INSTANCE_ID = "default";
                HOST = "0.0.0.0";
                PORT = "3100";
                SERVE_UI = "true";
                PAPERCLIP_DEPLOYMENT_MODE = "authenticated";
                PAPERCLIP_DEPLOYMENT_EXPOSURE = "private";
                DATABASE_URL = "postgresql://postgres@127.0.0.1:5432/paperclip";
              };

              command = pkgs.writeShellScript "paperclip-start" ''
                set -eu
                cd "$PAPERCLIP_HOME"

                echo "[paperclip] starting server on port $PORT" >&2
                exec ${pkgs.nodejs_22}/bin/node \
                  ${paperclip-built}/server/dist/index.js
              '';

              user = "paperclip";
            };

            # Port 3100 = 0x0C1C
            # startupGraceSecs: paperclip runs 24 Drizzle migrations on first boot
            # which takes ~60-90 s.  Suppress health check failures for 3 minutes
            # so the log isn't flooded before the server is ready.
            healthChecks.paperclip = {
              healthCmd = "grep -q ':0C1C ' /proc/net/tcp 2>/dev/null || grep -q ':0C1C ' /proc/net/tcp6 2>/dev/null";
              healthIntervalSecs = 10;
              healthTimeoutSecs = 5;
              startupGraceSecs = 180;
            };
          };
        });
    };
}
