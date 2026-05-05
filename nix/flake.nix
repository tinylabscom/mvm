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

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
      flake-utils,
      ...
    }:
    flake-utils.lib.eachSystem
      [
        # Linux production targets — full image-build outputs.
        "x86_64-linux"
        "aarch64-linux"
        # Darwin development targets — host shell + mvmctl binary only.
        # Image-build outputs (mvm-guest-agent, firecracker-kernel, mkGuest)
        # are gated to Linux below via `optionalAttrs pkgs.stdenv.isLinux`.
        "aarch64-darwin"
        "x86_64-darwin"
      ]
      (
        system:
        let
          pkgs = import nixpkgs {
            inherit system;
            config = { };
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
          firecrackerKernel = _: import ./packages/firecracker-kernel.nix { inherit pkgs; };

          # Workspace source path. Each package's `pkgs.lib.fileset.toSource`
          # call restricts what actually enters its closure (Cargo.toml,
          # Cargo.lock, src, crates, xtask) so the giant `nixos.qcow2` next
          # to the repo root and friends never get rebuilt-against. We
          # initially tried `builtins.path` here with a name+filter, but
          # the resulting store path doesn't compose with `fileset.toSource`
          # (lib.fileset rejects string-coerced path values). The eval-time
          # snapshot of the flake source is handled by Nix's flake machinery
          # one layer above; .gitignore is the right knob for that.
          mvmSrc = ./..;

          # Production guest agent — Exec handler NOT compiled in.
          mvm-guest-agent = import ./packages/mvm-guest-agent.nix {
            inherit pkgs rustPlatform mvmSrc;
            devShell = false;
          };

          # Dev guest agent — Exec handler compiled in. Exposed under
          # `packages.<system>.mvm-guest-agent-dev` so the dev sibling flake
          # (`nix/dev/`) can pull it in via its `mvm` input. NOT used by
          # `mkGuest` here — that always picks the prod agent.
          mvm-guest-agent-dev = import ./packages/mvm-guest-agent.nix {
            inherit pkgs rustPlatform mvmSrc;
            devShell = true;
          };

          # Static musl build of `mvm-verity-init` for the verity
          # initramfs (ADR-002 §W3). Separate derivation because the
          # initramfs has no glibc loader and a dynamic build panics
          # the kernel with ENOENT for `/init`. Linux-only.
          mvm-verity-init = pkgs.lib.optionalAttrs pkgs.stdenv.isLinux (
            import ./packages/mvm-verity-init.nix {
              inherit pkgs mvmSrc;
            }
          );

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

          # ── verityArtifacts — emit rootfs.verity + rootfs.roothash ──────
          #
          # Run `veritysetup format` against an ext4 image to produce a
          # Merkle hash tree and a 64-char hex root hash. Both files are
          # consumed at boot time:
          #   - `rootfs.verity` is attached as a second VirtioBlk device.
          #   - `rootfs.roothash` is read by the host's start_vm path and
          #     baked into the kernel cmdline as `dm-mod.create=`. The
          #     kernel sets up the verity target before init runs; a
          #     tampered ext4 fails verity setup and panics in early
          #     boot. ADR-002 §W3.
          #
          # `--salt=00…00` pins the salt so two builds of the same input
          # ext4 produce byte-identical sidecars. Determinism is required
          # by W3.1's reproducibility test; the security model only relies
          # on the root hash, not the salt.
          verityArtifacts =
            rootfsImage:
            pkgs.runCommand "mvm-rootfs-verity"
              {
                nativeBuildInputs = [ pkgs.cryptsetup ];
              }
              ''
                mkdir -p $out
                cp ${rootfsImage} $out/rootfs.ext4
                chmod u+w $out/rootfs.ext4
                # data-block-size=1024 matches the ext4 we ship (mkGuest's
                # rootfs is mke2fs'd with 1 KiB blocks at the sizes we
                # build at). Verity exposes its data-block-size as the
                # device's logical block size, and the kernel's ext4
                # refuses to mount when filesystem block size < device
                # logical block size — so they have to match.
                #
                # hash-block-size stays at 4096 because that's the typical
                # tree fan-out and what veritysetup defaults to.
                ${pkgs.cryptsetup}/bin/veritysetup format \
                  --hash=sha256 \
                  --data-block-size=1024 \
                  --hash-block-size=4096 \
                  --salt=0000000000000000000000000000000000000000000000000000000000000000 \
                  $out/rootfs.ext4 $out/rootfs.verity \
                  | tee /tmp/verity-output.txt
                # `veritysetup format` emits a human-readable summary; the
                # root hash line is `Root hash:    <64 hex>`. Capture it.
                grep '^Root hash:' /tmp/verity-output.txt \
                  | awk '{print $NF}' > $out/rootfs.roothash
                # Sanity check: the roothash file must be exactly 65 bytes
                # (64 hex + newline).
                test "$(wc -c < $out/rootfs.roothash)" = "65" \
                  || (echo "ERROR: rootfs.roothash has unexpected length" >&2 && exit 1)
                # Make the ext4 read-only after verity registration so a
                # later builder step can't write to it. Verity hashes are
                # tied to the exact bytes; a write would invalidate the
                # tree silently.
                chmod a-w $out/rootfs.ext4
              '';

          # mkGuest's implementation. Kept as an internal `let` binding so
          # the dev sibling flake can pull in `mkGuest` and re-wrap it with
          # a different agent without seeing or being able to flip a boolean.
          # See documentation on `lib.mkGuest` below for the full contract.
          mkGuestFn =
            {
              name,
              packages ? [ ],
              services ? { },
              healthChecks ? { },
              users ? { },
              hostname ? name,
              serviceGroup ? "mvm",
              cacert ? pkgs.cacert,
              hypervisor ? "firecracker",
              guestAgent ? mvm-guest-agent,
              # ADR-002 §W3 — production microVMs default to
              # verified boot via dm-verity. The dev sibling
              # flake (`nix/dev/`) overrides to false because
              # its overlayfs upper layer mutates /nix at
              # runtime, which can't compose with verity.
              verifiedBoot ? true,
              # Variant marker visible in the store path
              # (`mvm-<name>-<variant>`) and in the running
              # rootfs at `/etc/mvm/variant`. The dev sibling
              # flake passes "dev"; production stays "prod".
              # The assertion below pins the marker to the
              # agent's compiled features so they can't drift.
              variant ? "prod",
              # Role marker visible only on the derivation
              # (`passthru.role`). "builder" is reserved for
              # the dev-image / Lima builder VM rootfs; every
              # other consumer leaves the default. Used by
              # downstream tooling (mvmd, future mvmctl
              # security-status checks) to special-case the
              # builder VM without re-deriving from package
              # set heuristics.
              role ? "tenant",
              # Optional map of additional files to bake into
              # the rootfs at build time. Each entry is
              # `"absolute/guest/path" = { content :: str;
              # mode :: str (octal, e.g. "0755"); }`.
              # Parent directories are created automatically.
              # Files land owned uid 0 / gid 0 (mkfs.ext4 -d
              # under fakeroot preserves the populate-phase
              # ownership, which we set explicitly via
              # `chown 0:0`).
              #
              # Used by the function-entrypoint substrate
              # (ADR-007 / plan 41) to bake
              # `/etc/mvm/entrypoint` plus the wrapper binary
              # under `/usr/lib/mvm/wrappers/` without a
              # separate boot-time service. mvmforge's
              # forthcoming `mkPythonFunctionService` /
              # `mkNodeFunctionService` factories will set
              # this from the IR.
              extraFiles ? { },
            }:
            assert pkgs.lib.assertOneOf "variant" variant [
              "prod"
              "dev"
            ];
            assert pkgs.lib.assertOneOf "role" role [
              "tenant"
              "builder"
            ];
            assert pkgs.lib.assertMsg (
              (variant == "dev") -> (guestAgent.passthru.devShell or false)
            ) "mkGuest: variant=\"dev\" requires a guest agent built with the dev-shell feature";
            assert pkgs.lib.assertMsg (
              (variant == "prod") -> !(guestAgent.passthru.devShell or false)
            ) "mkGuest: variant=\"prod\" requires a guest agent built without the dev-shell feature";
            # ADR-002 §W3.4 / plan 36: the dev variant's overlay-on-/nix
            # mutates the lower layer at runtime, which can't compose with
            # dm-verity (the lower hash would change on every write). Refuse
            # the combination at evaluation time so a dev override applied
            # to a sealed builder output (or any future flake) fails loudly
            # instead of producing a runtime kernel panic at boot.
            assert pkgs.lib.assertMsg ((variant == "dev") -> !verifiedBoot)
              "mkGuest: variant=\"dev\" cannot compose with verifiedBoot=true; the dev VM's writable /nix overlay conflicts with dm-verity (ADR-002 §W3.4 / plan 36)";
            let
              # Compose `<pkg>/bin` for every caller-supplied package so
              # PID 1's PATH can find them. Without this, packages live in
              # the rootfs at their /nix/store paths but `command -v <tool>`
              # fails — every downstream `bash -c "..."` from the vsock Exec
              # handler inherits this PATH, so the dev image bundling
              # `pkgs.nix` would still report `nix: not found`.
              packageBinDirs = map (p: "${p}/bin") packages;

              initScript = import ./lib/minimal-init {
                inherit
                  pkgs
                  hostname
                  serviceGroup
                  users
                  services
                  healthChecks
                  busybox
                  ;
                guestAgentPkg = guestAgent;
                extraPathDirs = packageBinDirs;
                # ADR-002 §W2.3: every service launches under setpriv,
                # which lives in pkgs.util-linux. Pinning here so the
                # init's reference to `${utilLinux}/bin/setpriv`
                # resolves into a closure path, which we add to the
                # rootfs below.
                utilLinux = pkgs.util-linux;
              };

              cacertPaths = pkgs.lib.optionals (cacert != null) [ cacert ];

              # If the caller bundled `pkgs.nix`, materialise an /etc/nix/nix.conf
              # that turns on the modern command set (`nix build ...` and flakes).
              # Without this, every dispatch into the dev VM hits
              # `error: experimental Nix feature 'nix-command' is disabled`.
              # Detection is by attribute: any `p.pname == "nix"` flips it on.
              hasNix = builtins.any (p: (p.pname or "") == "nix") packages;

              # Closure info for everything baked into the rootfs's /nix.
              # The `registration` file is the wire format
              # `nix-store --load-db` accepts; we apply it once at rootfs
              # build time so the resulting image's /nix/var/nix/db is a
              # ready-to-use SQLite db naming every store path with its
              # canonical NAR hash. No runtime seeding, no boot-time race.
              closureInfo = pkgs.closureInfo {
                rootPaths = [
                  initScript
                  guestAgent
                  pkgs.util-linux
                ]
                ++ cacertPaths
                ++ packages;
              };

              # Render rootfs-template fragments. Each fragment is a real
              # `.sh.in` file that goes through `replaceVars`; we then
              # `readFile` the result so it can be inlined into the
              # parent template as a single substitution. Optional
              # blocks (`hasNix`, `cacert != null`) just become empty
              # strings when their feature isn't requested.
              renderTemplate = path: substs: builtins.readFile (pkgs.replaceVars path substs);

              nixBlock = pkgs.lib.optionalString hasNix (
                renderTemplate ./lib/rootfs-templates/populate-nix.sh.in {
                  nix = "${pkgs.nix}";
                  closureInfoRegistration = "${closureInfo}/registration";
                }
              );

              populateCacertBlock = pkgs.lib.optionalString (cacert != null) (
                renderTemplate ./lib/rootfs-templates/populate-cacert.sh.in {
                  cacert = "${cacert}";
                }
              );

              # Render the optional `extraFiles` map into a populate
              # block. Each entry stages content via `pkgs.writeText`
              # (so binary-safe) and copies it into the populate
              # directory tree, then chowns root + chmods the declared
              # mode. Order is alphabetical for byte-identical output
              # across evaluations.
              extraFilesBlock = pkgs.lib.concatStringsSep "\n" (
                pkgs.lib.mapAttrsToList (
                  path: spec:
                  let
                    contentPath = pkgs.writeText "mvm-extra-${pkgs.lib.replaceStrings [ "/" ] [ "_" ] path}" spec.content;
                    modeOctal = spec.mode or "0644";
                  in
                  ''
                    mkdir -p "./files$(dirname ${path})"
                    install -m 0644 ${contentPath} "./files${path}"
                    chmod ${modeOctal} "./files${path}"
                    chown 0:0 "./files${path}"
                  ''
                ) extraFiles
              );

              populateCommands = renderTemplate ./lib/rootfs-templates/populate.sh.in {
                busybox = "${busybox}";
                initScript = "${initScript}";
                nixBlock = nixBlock;
                cacertBlock = populateCacertBlock;
                variant = variant;
                extraFilesBlock = extraFilesBlock;
              };

              wantsFirecracker = hypervisor == "firecracker";

              rootfs = pkgs.callPackage (nixpkgs + "/nixos/lib/make-ext4-fs.nix") {
                # closureInfo lands in /nix/store too so its `registration`
                # file is reachable inside the VM (for diagnostics; the
                # actual db is already populated by populateImageCommands).
                storePaths = [
                  initScript
                  guestAgent
                  closureInfo
                  pkgs.util-linux
                ]
                ++ cacertPaths
                ++ packages;
                volumeLabel = "mvm";
                populateImageCommands = populateCommands;
              };

              # When verified boot is on, run veritysetup against the
              # finished ext4 image to produce the sidecar + roothash.
              # The output is a directory containing a *re-emitted* copy
              # of rootfs.ext4 (so the verity hashes match the bytes we
              # actually ship), the Merkle tree, and the roothash file.
              verityOut = pkgs.lib.optionalString verifiedBoot "${verityArtifacts rootfs}";

              # The verity initramfs (cpio.gz) bakes `mvm-verity-init` as
              # `/init` and ships empty mount targets for /proc, /dev,
              # /sysroot. The host's start_vm path points the VM's
              # `initrd_path` at this file when verifiedBoot is on. The
              # initramfs runs the verity setup in early userspace and
              # switch_root's to the real /init, which sidesteps the
              # Firecracker-aarch64 cmdline-append bug. ADR-002 §W3.
              verityInitrd = pkgs.lib.optionalString verifiedBoot "${import ./packages/verity-initrd.nix {
                inherit pkgs;
                verityInitPkg = mvm-verity-init;
              }}";

              ociImage = pkgs.dockerTools.streamLayeredImage {
                inherit name;
                tag = "latest";
                contents = [
                  guestAgent
                  busybox
                  pkgs.util-linux
                ]
                ++ cacertPaths
                ++ packages;
                fakeRootCommands =
                  let
                    ociCacertBlock = pkgs.lib.optionalString (cacert != null) (
                      renderTemplate ./lib/rootfs-templates/oci-fakeroot-cacert.sh.in {
                        cacert = "${cacert}";
                      }
                    );
                  in
                  renderTemplate ./lib/rootfs-templates/oci-fakeroot.sh.in {
                    busybox = "${busybox}";
                    initScript = "${initScript}";
                    cacertBlock = ociCacertBlock;
                  };
                config = {
                  Cmd = [ "/init" ];
                  WorkingDir = "/";
                };
              };
            in
            pkgs.runCommand "mvm-${name}-${variant}"
              {
                passthru = { inherit variant role; };
              }
              (
                ''
                  mkdir -p $out
                  ${ociImage} > "$out/image.tar.gz"
                ''
                + pkgs.lib.optionalString wantsFirecracker (
                  if verifiedBoot then
                    ''
                      ${copyKernel (firecrackerKernel null)}
                      # When verifiedBoot=true, the ext4 we ship is the one the
                      # verity tree was built against (verityOut/rootfs.ext4).
                      # Shipping the unhashed `${rootfs}` instead would silently
                      # break verity at boot.
                      cp "${verityOut}/rootfs.ext4"   "$out/rootfs.ext4"
                      cp "${verityOut}/rootfs.verity" "$out/rootfs.verity"
                      cp "${verityOut}/rootfs.roothash" "$out/rootfs.roothash"
                      # ADR-002 §W3: the verity initramfs runs as PID 1 before
                      # the real init and bypasses Firecracker's auto-appended
                      # `root=/dev/vda` by switch_root'ing into the verity
                      # device-mapper mount itself.
                      cp "${verityInitrd}" "$out/rootfs.initrd"
                    ''
                  else
                    ''
                      ${copyKernel (firecrackerKernel null)}
                      cp "${rootfs}" "$out/rootfs.ext4"
                    ''
                )
              );
        in
        {
          # ── mkNodeService — Node.js service helper ──────────────────────
          #
          # Builds a Node.js app from source via `pkgs.buildNpmPackage`
          # (single-stage, autoPatchelf'd in place) and returns
          # `{ package, service, healthCheck }` for use with mkGuest.
          #
          # The previous 3-stage FOD-then-patch pattern (`node-src` /
          # `node-pkg` / `node-built`) leaned on `chmod -R u+w` to
          # overwrite the 0555 store-path output of the previous stage —
          # standard Nix-sandbox idiom (audit category B in the W7
          # plan), but `buildNpmPackage` collapses it into one
          # derivation. Output layout is preserved: package files land
          # flat at `$out/` (not `$out/lib/node_modules/<pname>/`) so
          # `entrypoint = "dist/index.js"` resolves as
          # `${pkg}/dist/index.js`, matching the pre-swap interface and
          # leaving consumer flakes (hello-node etc.) unchanged.
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
          lib.mkNodeService =
            {
              name,
              src,
              npmHash,
              buildPhase ? "node \"$TSC\"",
              entrypoint,
              env ? { },
              user ? name,
              port,
              nodejs ? pkgs.nodejs_22,
              pruneDevDeps ? true,
            }:
            let
              intToHex4 =
                n:
                let
                  digits = [
                    "0"
                    "1"
                    "2"
                    "3"
                    "4"
                    "5"
                    "6"
                    "7"
                    "8"
                    "9"
                    "A"
                    "B"
                    "C"
                    "D"
                    "E"
                    "F"
                  ];
                  d = i: builtins.elemAt digits i;
                in
                "${d (n / 4096)}${d (pkgs.lib.mod (n / 256) 16)}${d (pkgs.lib.mod (n / 16) 16)}${d (pkgs.lib.mod n 16)}";

              portHex = intToHex4 port;

              pkg = pkgs.buildNpmPackage {
                pname = name;
                version = "0";
                inherit src nodejs;
                # `npmHash` is the parameter name the API has always used.
                # `buildNpmPackage` calls the same value `npmDepsHash` —
                # they are content-equivalent (the FOD shape is the same),
                # so existing consumer flakes can keep their hash strings
                # unchanged across this refactor.
                npmDepsHash = npmHash;

                # autoPatchelf for native node modules (postgres bindings,
                # etc.) lives in the same derivation now — no separate
                # FOD-then-patch stage. `buildNpmPackage`'s npmDeps FOD
                # only captures `node_modules/`; patching the consumer
                # output doesn't disturb the FOD's content addressing.
                nativeBuildInputs = [ pkgs.autoPatchelfHook ];
                buildInputs = [
                  pkgs.stdenv.cc.cc.lib
                  pkgs.glibc
                ];
                autoPatchelfIgnoreMissingDeps = true;

                # Match the previous mkNodeService's npm flags. Without
                # `--ignore-scripts`, postinstall hooks (e.g. esbuild's
                # binary download) try to fetch the network and fail in
                # the FOD sandbox.
                npmFlags = [
                  "--ignore-scripts"
                  "--no-bin-links"
                  "--legacy-peer-deps"
                ];

                # Skip the default `npm run build`; we run our own buildPhase.
                dontNpmBuild = true;

                buildPhase = ''
                  runHook preBuild
                  export HOME=$TMPDIR
                  TSC="node_modules/typescript/bin/tsc"
                  VITE="node_modules/vite/bin/vite.js"
                  ${buildPhase}
                  runHook postBuild
                '';

                # Override the default `installPhase` (which puts the
                # package at `$out/lib/node_modules/<pname>/`) to keep
                # the previous flat-at-`$out/` layout. Consumer flakes
                # write `entrypoint = "dist/index.js"` and reference
                # `${pkg}/dist/index.js` — preserving that resolution
                # is the whole point of overriding here.
                installPhase = ''
                  runHook preInstall
                  mkdir -p $out
                  cp -r . $out/
                ''
                + pkgs.lib.optionalString pruneDevDeps ''
                  for p in typescript vite "@vitejs" vitest "@vitest" eslint "@eslint" tsx esbuild drizzle-kit; do
                    rm -rf "$out/node_modules/$p"
                  done
                  rm -rf $out/node_modules/@types
                  # Strip stray .d.ts files outside dist/ to shrink the
                  # rootfs. These never get loaded at runtime.
                  find $out/node_modules -name '*.d.ts' -not -path '*/dist/*' -delete 2>/dev/null || true
                ''
                + ''
                  runHook postInstall
                '';
              };
            in
            {
              package = pkg;
              service = {
                command = pkgs.writeShellScript "${name}-start" ''
                  set -eu
                  exec ${nodejs}/bin/node ${pkg}/${entrypoint}
                '';
                env = {
                  NODE_ENV = "production";
                }
                // env;
                user = user;
              };
              healthCheck = {
                healthCmd = "grep -q ':${portHex} ' /proc/net/tcp 2>/dev/null || grep -q ':${portHex} ' /proc/net/tcp6 2>/dev/null";
                healthIntervalSecs = 10;
                healthTimeoutSecs = 5;
              };
            };

          # ── mkPythonService — Python service helper ──────────────────
          lib.mkPythonService =
            {
              name,
              src,
              pythonPackages ? (ps: [ ]),
              entrypoint,
              env ? { },
              user ? name,
              port,
              python ? pkgs.python3,
            }:
            let
              intToHex4 =
                n:
                let
                  digits = [
                    "0"
                    "1"
                    "2"
                    "3"
                    "4"
                    "5"
                    "6"
                    "7"
                    "8"
                    "9"
                    "A"
                    "B"
                    "C"
                    "D"
                    "E"
                    "F"
                  ];
                  d = i: builtins.elemAt digits i;
                in
                "${d (n / 4096)}${d (pkgs.lib.mod (n / 256) 16)}${d (pkgs.lib.mod (n / 16) 16)}${d (pkgs.lib.mod n 16)}";

              portHex = intToHex4 port;
              pythonEnv = python.withPackages pythonPackages;
              appPkg = pkgs.stdenv.mkDerivation {
                pname = "${name}-app";
                version = "0";
                inherit src;
                installPhase = "cp -r . $out";
              };
            in
            {
              package = appPkg;
              service = {
                command = pkgs.writeShellScript "${name}-start" ''
                  set -eu
                  exec ${pythonEnv}/bin/python3 ${appPkg}/${entrypoint}
                '';
                env = {
                  PYTHONUNBUFFERED = "1";
                }
                // env;
                user = user;
              };
              healthCheck = {
                healthCmd = "grep -q ':${portHex} ' /proc/net/tcp 2>/dev/null || grep -q ':${portHex} ' /proc/net/tcp6 2>/dev/null";
                healthIntervalSecs = 10;
                healthTimeoutSecs = 5;
              };
            };

          # ── mkStaticSite — Static file server helper ──────────────────
          lib.mkStaticSite =
            {
              name,
              src,
              port ? 8080,
              user ? name,
            }:
            let
              intToHex4 =
                n:
                let
                  digits = [
                    "0"
                    "1"
                    "2"
                    "3"
                    "4"
                    "5"
                    "6"
                    "7"
                    "8"
                    "9"
                    "A"
                    "B"
                    "C"
                    "D"
                    "E"
                    "F"
                  ];
                  d = i: builtins.elemAt digits i;
                in
                "${d (n / 4096)}${d (pkgs.lib.mod (n / 256) 16)}${d (pkgs.lib.mod (n / 16) 16)}${d (pkgs.lib.mod n 16)}";

              portHex = intToHex4 port;
              sitePkg = pkgs.stdenv.mkDerivation {
                pname = "${name}-site";
                version = "0";
                inherit src;
                installPhase = "cp -r . $out";
              };
            in
            {
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
          # `lib.mkGuest` is a function — exposing it on Darwin is safe
          # because it isn't *called* from this flake, only re-exported.
          # The Linux-only nixpkgs `make-ext4-fs.nix` it pulls in only
          # runs when a sibling flake calls it (and those flakes target
          # Linux systems explicitly).
          lib.mkGuest = mkGuestFn;

          # ── packages ──────────────────────────────────────────────────
          packages = {
            # Always-built: the mvmctl host CLI. Cargo cross-compiles to
            # whichever native target the system attribute names.
            mvm = import ./packages/mvmctl.nix {
              inherit pkgs rustPlatform mvmSrc;
            };
            default = self.packages.${system}.mvm;
            xtask = import ./packages/xtask.nix {
              inherit pkgs rustPlatform mvmSrc;
            };
          }
          // pkgs.lib.optionalAttrs pkgs.stdenv.isLinux {
            # Linux-only: the guest agent ships into a Linux microVM
            # rootfs. Cross-compiling to Linux from Darwin would require
            # a remote builder; rather than half-fake it, gate the
            # output. macOS dev users still build via `mvmctl dev` which
            # dispatches into the builder VM.
            mvm-guest-agent = mvm-guest-agent;
            mvm-guest-agent-dev = mvm-guest-agent-dev;
          };

          # ── apps (`nix run`) ──────────────────────────────────────────
          apps.mvm = {
            type = "app";
            program = "${self.packages.${system}.mvm}/bin/mvmctl";
          };
          apps.default = self.apps.${system}.mvm;
          apps.xtask = {
            type = "app";
            program = "${self.packages.${system}.xtask}/bin/xtask";
          };

          # ── devShells ────────────────────────────────────────────────
          # Host shell — for hacking on the mvmctl crate. Diagnostic-only
          # hook; never mutates the host (per the W7 plan + nix
          # best-practices guide).
          devShells = {
            host = import ./devshells/host.nix { inherit pkgs rustToolchain; };
            # Default = host shell. Contributors typing `nix develop` get
            # the same thing whether they're on darwin or linux.
            default = self.devShells.${system}.host;
          }
          // pkgs.lib.optionalAttrs pkgs.stdenv.isLinux {
            # Linux-only: the builder shell pulls in firecracker, kernel
            # build deps, etc. — none of which exist (or work) on darwin.
            # Lazy attr eval keeps the import from triggering on darwin.
            builder = import ./devshells/builder.nix {
              inherit pkgs rustToolchain;
            };
          };

          # ── formatter ────────────────────────────────────────────────
          formatter = pkgs.nixfmt-rfc-style;

          # ── checks (eval-only on darwin) ─────────────────────────────
          # The `mvm` package builds even on darwin (cargo cross-compiles
          # to the host's native target). Real flake-check is just an
          # eval gate here; CI's image-build lane lives in
          # .github/workflows/release.yml + security.yml.
          checks.mvm-eval = self.packages.${system}.mvm;
        }
      )
    // {
      # Top-level (non-per-system) outputs.
      # No nixosModules / overlays today — the W7 plan defers them
      # until mvmd or downstream consumers actually need them.
    };
}
