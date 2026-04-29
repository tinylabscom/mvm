{
  description = "mvm — Firecracker microVM guest image builders (production default).";

  # ── Production-only API surface ────────────────────────────────────────
  #
  # This flake exposes ONLY the production-safe `mkGuest`. The vsock guest
  # agent embedded in the resulting rootfs is built without the `dev-shell`
  # Cargo feature, so the Exec handler is physically absent from the binary.
  # No runtime configuration can re-enable arbitrary command execution over
  # vsock against an image produced here.
  #
  # The dev variant (Exec handler compiled in) lives in the sibling flake
  # at `nix/dev/`. Dev tooling (mvmctl) injects that variant transparently
  # at build time via `nix build --override-input mvm <abs>/nix/dev`. User
  # flakes carry NO dev/prod toggle in their source — they always reference
  # this flake and always get the production agent unless mvmctl explicitly
  # overrides the input. mvmd (production coordinator) never overrides, so
  # production pool builds are guaranteed prod-only.

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils, ... }:
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" ] (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };

        # Rust 1.85+ for edition 2024.
        rustToolchain = pkgs.rust-bin.stable.latest.minimal;
        rustPlatform = pkgs.makeRustPlatform {
          cargo = rustToolchain;
          rustc = rustToolchain;
        };

        # Shared Firecracker kernel.
        #
        # Wrapped in a thunk (function) so the kernel derivation is only
        # constructed when a consumer actually asks for it. Apple Container
        # and Docker consumers don't need a Linux kernel at all — eagerly
        # importing here would force evaluation for every output and pull
        # the kernel-config file into pure-eval scope unnecessarily.
        firecrackerKernel = _: import ./firecracker-kernel-pkg.nix { inherit pkgs; };

        # Production guest agent — Exec handler NOT compiled in.
        # `mvmSrc = ./..;` reaches the workspace root from `nix/`.
        mvm-guest-agent = import ./guest-agent-pkg.nix {
          inherit pkgs rustPlatform;
          mvmSrc = ./..;
          devShell = false;
        };

        # Dev guest agent — Exec handler compiled in. Exposed under
        # `packages.<system>.mvm-guest-agent-dev` so the dev sibling flake
        # (`nix/dev/`) can pull it in via its `mvm` input. NOT used by
        # `mkGuest` here — that always picks the prod agent.
        mvm-guest-agent-dev = import ./guest-agent-pkg.nix {
          inherit pkgs rustPlatform;
          mvmSrc = ./..;
          devShell = true;
        };

        busybox = pkgs.pkgsStatic.busybox;

        # Shared kernel copy logic. Always exposes the kernel as $out/vmlinux
        # regardless of arch — Firecracker accepts the file by path, not name,
        # and consumers (release.yml, runtime image fetch) expect that name.
        copyKernel = kernel: ''
          if [ -f "${kernel}/vmlinux" ]; then
            cp "${kernel}/vmlinux" "$out/vmlinux"
          elif [ -f "${kernel}/Image" ]; then
            cp "${kernel}/Image" "$out/vmlinux"
          elif [ -f "${kernel}/bzImage" ]; then
            cp "${kernel}/bzImage" "$out/vmlinux"
          else
            echo "ERROR: cannot find kernel image in ${kernel}:" >&2
            ls -la "${kernel}/" >&2
            exit 1
          fi
        '';

        # mkGuest's implementation. Kept as an internal `let` binding so
        # the dev sibling flake can pull in `mkGuest` and re-wrap it with
        # a different agent without seeing or being able to flip a boolean.
        # See documentation on `lib.mkGuest` below for the full contract.
        mkGuestFn = { name, packages ? [], services ? {}, healthChecks ? {},
                      users ? {}, hostname ? name, serviceGroup ? "mvm",
                      cacert ? pkgs.cacert, hypervisor ? "firecracker",
                      guestAgent ? mvm-guest-agent }:
          let
            initScript = import ./minimal-init.nix {
              inherit pkgs hostname serviceGroup users services healthChecks busybox;
              guestAgentPkg = guestAgent;
            };

            cacertPaths = pkgs.lib.optionals (cacert != null) [ cacert ];

            populateCommands = ''
                mkdir -p ./files/dev ./files/proc ./files/sys
                mkdir -p ./files/bin ./files/sbin
                mkdir -p ./files/etc/mvm/integrations.d
                mkdir -p ./files/tmp ./files/run ./files/var/lib ./files/var/run ./files/var/log
                mkdir -p ./files/root ./files/home
                mkdir -p ./files/mnt/config ./files/mnt/secrets ./files/mnt/data
                printf '#!/bin/sh\nexport PATH="${busybox}/bin:/bin:/sbin:$PATH"\nexec ${busybox}/bin/sh ${initScript}\n' > ./files/init
                chmod +x ./files/init
                ln -s /init ./files/sbin/vminitd
                ln -s ${busybox}/bin/sh ./files/bin/sh
              '' + pkgs.lib.optionalString (cacert != null) ''
                mkdir -p ./files/etc/ssl/certs
                mkdir -p ./files/etc/pki/tls/certs
                ln -s ${cacert}/etc/ssl/certs/ca-bundle.crt ./files/etc/ssl/certs/ca-bundle.crt
                ln -s ${cacert}/etc/ssl/certs/ca-bundle.crt ./files/etc/ssl/certs/ca-certificates.crt
                ln -s ${cacert}/etc/ssl/certs/ca-bundle.crt ./files/etc/pki/tls/certs/ca-bundle.crt
              '';

            wantsFirecracker = hypervisor == "firecracker";

            rootfs = pkgs.callPackage
              (nixpkgs + "/nixos/lib/make-ext4-fs.nix") {
              storePaths = [ initScript guestAgent ] ++ cacertPaths ++ packages;
              volumeLabel = "mvm";
              populateImageCommands = populateCommands;
            };

            ociImage = pkgs.dockerTools.streamLayeredImage {
              inherit name;
              tag = "latest";
              contents = [ guestAgent busybox ] ++ cacertPaths ++ packages;
              fakeRootCommands = ''
                mkdir -p ./dev ./proc ./sys ./tmp ./run
                mkdir -p ./var/lib ./var/run ./var/log
                mkdir -p ./bin ./sbin ./root ./home
                mkdir -p ./etc/mvm/integrations.d
                mkdir -p ./mnt/config ./mnt/secrets ./mnt/data
                ln -sf ${initScript} ./init
                ln -sf /init ./sbin/vminitd
                ln -sf ${busybox}/bin/sh ./bin/sh
              '' + pkgs.lib.optionalString (cacert != null) ''
                mkdir -p ./etc/ssl/certs ./etc/pki/tls/certs
                ln -sf ${cacert}/etc/ssl/certs/ca-bundle.crt ./etc/ssl/certs/ca-bundle.crt
                ln -sf ${cacert}/etc/ssl/certs/ca-bundle.crt ./etc/ssl/certs/ca-certificates.crt
                ln -sf ${cacert}/etc/ssl/certs/ca-bundle.crt ./etc/pki/tls/certs/ca-bundle.crt
              '';
              config = {
                Cmd = [ "/init" ];
                WorkingDir = "/";
              };
            };
          in
          pkgs.runCommand "mvm-${name}" {} (''
            mkdir -p $out
            ${ociImage} > "$out/image.tar.gz"
          '' + pkgs.lib.optionalString wantsFirecracker ''
            ${copyKernel (firecrackerKernel null)}
            cp "${rootfs}" "$out/rootfs.ext4"
          '');
      in {
        # ── mkNodeService — Node.js service helper ──────────────────────
        #
        # Builds a Node.js app from source (npm install → autoPatchelf → tsc),
        # and returns { package, service, healthCheck } for use with mkGuest.
        #
        # Usage:
        #   let p = mvm.lib.${system}.mkNodeService {
        #     name       = "my-app";
        #     src        = fetchGit { url = ...; rev = ...; };
        #     npmHash    = "sha256-...";  # FOD hash — set to "" to get it
        #     buildPhase = ''             # optional; default: run tsc
        #       node "$TSC"
        #     '';
        #     entrypoint = "dist/index.js"; # relative to built output root
        #     env        = { PORT = "3000"; };
        #     user       = "myapp";
        #     port       = 3000;
        #   };
        #   in mvm.lib.${system}.mkGuest {
        #     packages          = [ pkgs.nodejs_22 p.package ];
        #     services.myapp    = p.service;
        #     healthChecks.myapp = p.healthCheck;
        #     ...
        #   }
        lib.mkNodeService = {
          name,
          src,
          npmHash,
          buildPhase ? "node \"$TSC\"",
          entrypoint,
          env ? {},
          user ? name,
          port,
          nodejs ? pkgs.nodejs_22,
          pruneDevDeps ? true,
        }:
          let
            intToHex4 = n:
              let
                digits = [ "0" "1" "2" "3" "4" "5" "6" "7" "8" "9"
                           "A" "B" "C" "D" "E" "F" ];
                d = i: builtins.elemAt digits i;
              in "${d (n / 4096)}${d (builtins.mod (n / 256) 16)}${d (builtins.mod (n / 16) 16)}${d (builtins.mod n 16)}";

            portHex = intToHex4 port;

            node-src = pkgs.stdenv.mkDerivation {
              pname = "${name}-src";
              version = "0";
              inherit src;
              dontFixup = true;
              outputHashMode = "recursive";
              outputHashAlgo = "sha256";
              outputHash = npmHash;
              nativeBuildInputs = [ nodejs pkgs.cacert ];
              SSL_CERT_FILE = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
              buildPhase = ''
                export HOME=$TMPDIR
                export npm_config_cache=$TMPDIR/.npm
                cp -r $src $out
                chmod -R u+w $out
                cd $out
                npm install --ignore-scripts --no-bin-links --legacy-peer-deps
              '';
              installPhase = "true";
            };

            node-pkg = pkgs.stdenv.mkDerivation {
              pname = "${name}";
              version = "0";
              src = node-src;
              nativeBuildInputs = [ pkgs.autoPatchelfHook ];
              buildInputs = [ pkgs.stdenv.cc.cc.lib pkgs.glibc ];
              autoPatchelfIgnoreMissingDeps = true;
              dontBuild = true;
              installPhase = "cp -r $src $out";
            };

            node-built = pkgs.stdenv.mkDerivation {
              pname = "${name}-built";
              version = "0";
              src = node-pkg;
              nativeBuildInputs = [ nodejs ];
              buildPhase = ''
                export HOME=$TMPDIR
                cp -r $src $TMPDIR/build
                chmod -R u+w $TMPDIR/build
                cd $TMPDIR/build
                TSC="$TMPDIR/build/node_modules/typescript/bin/tsc"
                VITE="$TMPDIR/build/node_modules/vite/bin/vite.js"
                ${buildPhase}
              '' + pkgs.lib.optionalString pruneDevDeps ''
                for pkg in typescript vite "@vitejs" vitest "@vitest" eslint "@eslint" tsx esbuild drizzle-kit; do
                  rm -rf "node_modules/$pkg"
                done
                rm -rf node_modules/@types
                find node_modules -name '*.d.ts' -not -path '*/dist/*' -delete 2>/dev/null || true
              '' + ''
                mkdir -p $out
                cp -r $TMPDIR/build/* $out/
              '';
              installPhase = "true";
            };
          in {
            package = node-built;
            service = {
              command = pkgs.writeShellScript "${name}-start" ''
                set -eu
                exec ${nodejs}/bin/node ${node-built}/${entrypoint}
              '';
              env = { NODE_ENV = "production"; } // env;
              user = user;
            };
            healthCheck = {
              healthCmd = "grep -q ':${portHex} ' /proc/net/tcp 2>/dev/null || grep -q ':${portHex} ' /proc/net/tcp6 2>/dev/null";
              healthIntervalSecs = 10;
              healthTimeoutSecs = 5;
            };
          };

        # ── mkPythonService — Python service helper ──────────────────
        lib.mkPythonService = {
          name,
          src,
          pythonPackages ? (ps: []),
          entrypoint,
          env ? {},
          user ? name,
          port,
          python ? pkgs.python3,
        }:
          let
            intToHex4 = n:
              let
                digits = [ "0" "1" "2" "3" "4" "5" "6" "7" "8" "9"
                           "A" "B" "C" "D" "E" "F" ];
                d = i: builtins.elemAt digits i;
              in "${d (n / 4096)}${d (builtins.mod (n / 256) 16)}${d (builtins.mod (n / 16) 16)}${d (builtins.mod n 16)}";

            portHex = intToHex4 port;
            pythonEnv = python.withPackages pythonPackages;
            appPkg = pkgs.stdenv.mkDerivation {
              pname = "${name}-app";
              version = "0";
              inherit src;
              installPhase = "cp -r . $out";
            };
          in {
            package = appPkg;
            service = {
              command = pkgs.writeShellScript "${name}-start" ''
                set -eu
                exec ${pythonEnv}/bin/python3 ${appPkg}/${entrypoint}
              '';
              env = { PYTHONUNBUFFERED = "1"; } // env;
              user = user;
            };
            healthCheck = {
              healthCmd = "grep -q ':${portHex} ' /proc/net/tcp 2>/dev/null || grep -q ':${portHex} ' /proc/net/tcp6 2>/dev/null";
              healthIntervalSecs = 10;
              healthTimeoutSecs = 5;
            };
          };

        # ── mkStaticSite — Static file server helper ──────────────────
        lib.mkStaticSite = {
          name,
          src,
          port ? 8080,
          user ? name,
        }:
          let
            intToHex4 = n:
              let
                digits = [ "0" "1" "2" "3" "4" "5" "6" "7" "8" "9"
                           "A" "B" "C" "D" "E" "F" ];
                d = i: builtins.elemAt digits i;
              in "${d (n / 4096)}${d (builtins.mod (n / 256) 16)}${d (builtins.mod (n / 16) 16)}${d (builtins.mod n 16)}";

            portHex = intToHex4 port;
            sitePkg = pkgs.stdenv.mkDerivation {
              pname = "${name}-site";
              version = "0";
              inherit src;
              installPhase = "cp -r . $out";
            };
          in {
            package = sitePkg;
            service = {
              command = "${busybox}/bin/busybox httpd -f -p ${toString port} -h ${sitePkg}";
              user = user;
            };
            healthCheck = {
              healthCmd = "grep -q ':${portHex} ' /proc/net/tcp 2>/dev/null || grep -q ':${portHex} ' /proc/net/tcp6 2>/dev/null";
              healthIntervalSecs = 10;
              healthTimeoutSecs = 5;
            };
          };

        # ── mkGuest — Production microVM image builder ─────────────────
        #
        # mvm.lib.<system>.mkGuest {
        #   name, packages?, services?, healthChecks?, users?, hostname?,
        #   hypervisor?
        # }
        #
        # Builds a microVM image with busybox init as PID 1 — no NixOS,
        # no systemd. Handles mounts, networking, and service supervision
        # via respawn loops.
        #
        # The embedded vsock guest agent is built without the `dev-shell`
        # Cargo feature, so the Exec handler is physically absent from the
        # binary. Production. No runtime config can re-enable arbitrary
        # command execution over vsock.
        #
        # For dev-mode iteration that needs `mvmctl exec` / `mvmctl console`,
        # the host CLI transparently overrides this flake's `mvm` input with
        # `nix/dev/`, which re-exports the same `lib.<system>.mkGuest` symbol
        # but with the dev guest agent injected. User flake source never
        # changes — the choice is made by the build invocation, not the
        # source file.
        #
        # Produces:
        #   $out/vmlinux       — uncompressed kernel (firecracker only)
        #   $out/rootfs.ext4   — ext4 root filesystem (firecracker only)
        #   $out/image.tar.gz  — OCI image (always)
        lib.mkGuest = mkGuestFn;

        packages.mvm-guest-agent = mvm-guest-agent;
        packages.mvm-guest-agent-dev = mvm-guest-agent-dev;
      }
    );
}
