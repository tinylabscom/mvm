{
  description = "mvm runtime overlay disk — verity-sealed ext4 carrying the guest agent + seccomp shim + netinit + runner, mounted at /mvm/runtime in every microVM (ADR-018)";

  # ── Why this flake exists ─────────────────────────────────────────
  #
  # Every mvm microVM attaches a second virtio-blk device at
  # boot — Nix-built rootfs and OCI-pulled rootfs alike. The
  # overlay carries the in-VM binaries mvm controls (the guest
  # agent, the per-service seccomp shim, the function-workload
  # runner, `mvm-guest-netinit` which installs kernel blackhole
  # routes for `MANDATORY_DENY_RANGES` so OCI-imported workloads
  # get Layer 1 network defense too) plus the pure-Python SDK
  # source. The glibc host-services cdylib is a separate SDK
  # sidecar because it is workload-facing, not an agent runtime.
  #
  # The flake produces, per supported system, a `$out/` containing:
  #
  #   overlay.ext4      — the rootfs the kernel mounts at
  #                       /mvm/runtime via dm-verity. Read-only at
  #                       boot.
  #   overlay.verity    — dm-verity sidecar (Merkle tree).
  #   overlay.roothash  — 64 lowercase hex chars + newline. What
  #                       the guest agent reads from the kernel
  #                       cmdline as `mvm.runtime_roothash=<hex>`.
  #   VERSION           — semver of the producing mvmctl. The
  #                       resolver (`mvm_build::runtime_overlay`)
  #                       refuses to attach an
  #                       overlay whose VERSION disagrees with the
  #                       running mvmctl's version.
  #
  # The four file names + the per-arch directory layout under
  # `~/.cache/mvm/runtime-overlay/<version>/<arch>/` are the contract
  # `RuntimeOverlayResolver::resolve` enforces. Renaming any of
  # them breaks the resolver test
  # `resolve_returns_artifact_when_all_files_present_and_version_matches`.
  #
  # ── Why a *separate* flake rather than rolling this into
  # `nix/lib/mk-guest.nix` ───────────────────────────────────────────
  #
  # `mkGuest` builds per-image rootfs. The runtime overlay is *one*
  # artifact shared by every microVM mvmctl boots, regardless of
  # what `mkGuest` produces for the rootfs. Splitting the
  # derivation here keeps two properties:
  #
  # 1. The overlay is rebuilt only when mvm bumps the agent /
  #    runner / shim — *not* per user-supplied rootfs. The verity
  #    roothash is content-addressable, so two identical overlays
  #    cache-hit cleanly.
  # 2. The per-image closure stops carrying `mvm-guest-agent`,
  #    `mvm-seccomp-apply`, `mvm-runner`. Those binaries live here.
  #    Net effect: every Nix-built image shrinks by ~10-15 MB.
  #
  # ── Why this flake doesn't pull in microvm.nix ─────────────────
  #
  # microvm.nix is the NixOS module that turns a system
  # configuration into a Firecracker/Cloud-Hypervisor-bootable
  # rootfs. It's overkill here: the overlay isn't a bootable VM,
  # it's a verity-sealed data disk. We use bare `pkgs.runCommand`
  # + the workspace's binaries + `mkfs.ext4 -d` + `veritysetup
  # format`.
  #
  # ── Determinism ────────────────────────────────────────────────
  #
  # Two builds of this flake against the same workspace state
  # must produce byte-identical `overlay.ext4` + `overlay.verity`
  # + identical `overlay.roothash`. The per-version cache
  # depends on this property. We pin every source of mkfs.ext4
  # randomness (UUID, hash_seed, SOURCE_DATE_EPOCH) and every
  # source of veritysetup randomness (salt, data block size, hash
  # algo). Nix's sandbox covers the rest (timestamps,
  # parallelism-induced ordering).
  #
  # ── Cryptsetup version pin ─────────────────────────────────────
  #
  # The verity build pins `cryptsetup` via the same nixpkgs
  # commit. The OCI-pull path's seal_with_verity inherits
  # whatever cryptsetup is on `$PATH` in the builder VM. This
  # flake stays consistent with the verity derivation by routing
  # through the same `nixpkgs.cryptsetup` attribute. Tightening
  # this to an explicit version override is still open.

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
  };

  outputs =
    { self, nixpkgs, ... }:
    let
      systems = [
        "aarch64-linux"
        "x86_64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;

      # Workspace staging — same `MVM_WORKSPACE_PATH` env override
      # the builder-vm flake uses, for the libkrun-builder-VM
      # sandbox case.
      workspaceRoot =
        let
          envPath = builtins.getEnv "MVM_WORKSPACE_PATH";
        in
        if envPath != "" then /. + envPath else ../../..;

      # Filter list lives at nix/lib/workspace-filter.nix so the three
      # flakes that ingest the host workspace (this one, builder/,
      # builder-vm/) stay aligned with .gitignore in one place.
      workspace =
        (import (workspaceRoot + "/nix/lib/workspace-filter.nix") {
          inherit (nixpkgs) lib;
        })
          { inherit workspaceRoot; };

      # The `mvm` flake, evaluated against this flake's pinned nixpkgs and the
      # filtered workspace. Every binary and shared object below comes from its
      # `packages` output — the guest recipes stay in `mvm` beside Cargo.lock,
      # and an image repository builds through the same interface. The recipes
      # never touch microvm.nix, which this flake does not pin.
      mvm = (import (workspaceRoot + "/nix/flake.nix")).outputs {
        self = { };
        inherit nixpkgs;
        microvm = throw "the mvm guest recipes do not evaluate microvm.nix";
        mvm-workspace = workspace;
      };

      # mvmctl semver, shared with the universal initramfs. The
      # `RuntimeOverlayResolver` rejects an overlay whose VERSION file
      # disagrees with the running mvmctl; `../version.nix` says how the
      # pin is kept equal to the workspace version.
      overlayVersion = import ../version.nix;

      # mvm-agentd binaries — agent + seccomp shim + netinit + OCI entrypoint.
      # The universal initramfs agent is PID 1 and lives in the initramfs, not
      # in this overlay.
      mvmGuestFor = system: mvm.packages.${system}.mvm-guest-agent;

      # mvm-runner — the function-workload entrypoint runner.
      mvmRunnerFor = system: mvm.packages.${system}.mvm-runner;

      mvmEgressClientFor = system: mvm.packages.${system}.mvm-egress-client;

      mvmAddonDnsFor = system: mvm.packages.${system}.mvm-addon-dns;

      mvmExitReportFor = system: mvm.packages.${system}.mvm-exit-report;

      # libmvm_host_services.so — the in-guest host-services FFI shared object
      # the language SDKs dlopen, parameterized by the libc it is built
      # against. A guest can only dlopen the variant matching its own, and the
      # host selects from the libc recorded in the image's `mvm-meta.json`.
      mvmSdkCdylibForLibc =
        system: libc:
        mvm.packages.${system}."mvm-sdk-cdylib-${libc}";

      # The SDK FFI remains a glibc cdylib because Python and Node load it from
      # the workload process. It is packaged separately from the static-musl
      # runtime overlay so its loader and libc are not part of every guest.
      sdkRuntimeLoaderFor = pkgs: pkgs.stdenv.cc.bintools.dynamicLinker;
      sdkRuntimeLoaderBaseFor = pkgs: builtins.baseNameOf (sdkRuntimeLoaderFor pkgs);
      sdkRuntimeLibcFor = pkgs: "${pkgs.glibc.out}/lib/libc.so.6";
      sdkRuntimeLibgccFor = pkgs: "${pkgs.lib.getLib pkgs.stdenv.cc.cc}/lib/libgcc_s.so.1";

      # Pinned-for-determinism flags. MUST mirror:
      #
      # - `mvm_build::oci_to_rootfs::ext4::Mke2fsOptions::default`
      #   for ext4 (UUID, hash_seed, block size, SOURCE_DATE_EPOCH).
      # - `mvm_build::oci_to_rootfs::verity::VeritysetupOptions::default`
      #   for verity (data block 1024, hash block 4096, zero salt,
      #   sha256).
      #
      # The unit tests
      # `defaults_match_mvm_verity_init_constants` and
      # `defaults_are_deterministic_and_pinned` enforce
      # the Rust-side constants; this comment is the cross-stack
      # contract. If you bump either side, bump both.
      overlayUuid = "00000000-0000-0000-0000-00000000beef";
      overlayHashSeed = "00000000-0000-0000-0000-00000000cafe";
      overlayBlockSize = 1024;
      overlayVeritySalt = "0000000000000000000000000000000000000000000000000000000000000000";
      overlayVerityHashAlgorithm = "sha256";
      overlayVerityHashBlockSize = 4096;
      # Mirrors `mvm_fs::oci_to_rootfs::verity::MVM_VERITY_PINNED_UUID`.
      # Without it `veritysetup format` writes a random UUID into the hash
      # device's superblock, so the sidecar bytes differ on every build even
      # though the root hash does not.
      overlayVerityUuid = "00000000-0000-0000-0000-000000000003";

      # Keep the Nix-built verity baseline on
      # the exact same cryptsetup release as the builder VM's OCI-pull
      # path. A nixpkgs bump must not silently change `veritysetup`
      # output bytes; bump version + hash here and in
      # `nix/images/builder-vm/flake.nix` together.
      pinnedCryptsetupVersion = "2.8.6";
      pinnedCryptsetupSrcHash = "sha256-gAQmX9mTiF0I97Yz2+BWhR3hohAwdhOk693HQ/zO/lo=";
      pinnedCryptsetupFor =
        pkgs:
        pkgs.cryptsetup.overrideAttrs (_old: {
          version = pinnedCryptsetupVersion;
          src = pkgs.fetchurl {
            url =
              "mirror://kernel/linux/utils/cryptsetup/v${pkgs.lib.versions.majorMinor pinnedCryptsetupVersion}/"
              + "cryptsetup-${pinnedCryptsetupVersion}.tar.xz";
            hash = pinnedCryptsetupSrcHash;
          };
        });

      # Target overlay size: 16 MiB — a hard cap for the static-musl
      # runtime overlay. The SDK glibc closure lives in the separate
      # sidecar, so the production overlay no longer needs the old
      # 32 MiB allocation. When the mediated ping binary joined the
      # staged set the image briefly stopped fitting — the recovered
      # space came from dropping the ext4 journal (a full 1 MiB at this
      # image size), which a read-only dm-verity-sealed disk can never
      # replay anyway. Growing the allocation instead would blow the
      # `xtask perf footprint` guest-artifact budget: this file is
      # preallocated, so every byte of slack here is counted against
      # the 50 MB ceiling.
      overlaySizeBytes = 16 * 1024 * 1024;

      mkSdkSidecar =
        system:
        mkSdkSidecarForLibc system "glibc";

      # The musl sidecar carries only what the guest lacks.
      #
      # The glibc tree bundles a loader and a libc because the workload rootfs
      # has neither — the catalog is Alpine. A musl guest already has both: its
      # own interpreter is running under `/lib/ld-musl-<arch>.so.1`. So the musl
      # tree is the cdylib plus musl's libgcc, which the object still records as
      # NEEDED — rustc emits `-lgcc_s` for unwinding and `-static-libgcc` does
      # not remove it. The RPATH stays, because that libgcc is what the object
      # finds through it.
      mkSdkSidecarForLibc =
        system: libc:
        let
          pkgs = import nixpkgs { inherit system; };
          isMusl = libc == "musl";
          hostsvc = mvmSdkCdylibForLibc system libc;
          muslLibgcc = "${pkgs.pkgsMusl.lib.getLib pkgs.pkgsMusl.stdenv.cc.cc}/lib/libgcc_s.so.1";
        in
        pkgs.runCommand "mvm-sdk-sidecar-${libc}-${system}"
          {
            nativeBuildInputs = [ pkgs.patchelf ];
            passthru = {
              inherit hostsvc;
              version = overlayVersion;
            };
          }
          ''
            set -euo pipefail

            mkdir -p "$out/lib"
            cp ${hostsvc}/lib/libmvm_host_services.so \
              "$out/lib/libmvm_host_services.so"
            ${
              if isMusl then
                ''
                  cp ${muslLibgcc} "$out/lib/libgcc_s.so.1"
                ''
              else
                ''
                  cp ${sdkRuntimeLoaderFor pkgs} "$out/lib/${sdkRuntimeLoaderBaseFor pkgs}"
                  cp ${sdkRuntimeLibcFor pkgs} "$out/lib/libc.so.6"
                  cp ${sdkRuntimeLibgccFor pkgs} "$out/lib/libgcc_s.so.1"
                ''
            }
            chmod u+w "$out/lib/libmvm_host_services.so"
            patchelf \
              --set-rpath /mvm/sdk/lib \
              "$out/lib/libmvm_host_services.so"
            chmod 0555 "$out/lib"/*
            echo "${overlayVersion}" > "$out/VERSION"
            cat > "$out/README" <<'EOF'
            This read-only sidecar supplies the ${libc} SDK host-services cdylib.
            Attach it at /mvm/sdk for workloads that use mvm.audit or mvm.host.
            EOF
            chmod 0444 "$out/VERSION" "$out/README"
          '';

      # Target sidecar size: 8 MiB — a hard cap for the glibc SDK closure
      # (loader + libc + libgcc + the cdylib). The sidecar is attached only to
      # workloads whose signed plan binds an SDK-served host service, so this
      # allocation is never part of the base guest footprint; the footprint
      # ledger reports it as its own line rather than folding it into the base.
      sdkSidecarSizeBytes = 8 * 1024 * 1024;

      # The sidecar as a read-only ext4 the host attaches at /mvm/sdk. Same
      # deterministic mkfs parameters as the runtime overlay, and the same
      # `sha256sum`-format manifest the host-side resolver verifies before it
      # offers an attachment — so a truncated or drifted artifact refuses to
      # boot instead of surfacing as an in-guest dlopen failure.
      mkSdkSidecarImage =
        system:
        mkSdkSidecarImageForLibc system "glibc";

      mkSdkSidecarImageForLibc =
        system: libc:
        let
          pkgs = import nixpkgs { inherit system; };
          tree = mkSdkSidecarForLibc system libc;
        in
        pkgs.runCommand "mvm-sdk-sidecar-image-${libc}-${system}"
          {
            nativeBuildInputs = [
              pkgs.e2fsprogs
              pkgs.coreutils
            ];
            passthru = {
              inherit tree;
              version = overlayVersion;
              sizeBytes = sdkSidecarSizeBytes;
            };
          }
          ''
            set -euo pipefail

            staging="$TMPDIR/staging"
            mkdir -p "$staging/lib"
            cp -r ${tree}/lib/. "$staging/lib/"
            chmod -R u+rwX,go+rX "$staging"

            mkdir -p $out
            truncate -s ${toString sdkSidecarSizeBytes} $out/sdk.ext4
            SOURCE_DATE_EPOCH=0 \
              mkfs.ext4 -F \
                -t ext4 \
                -L mvm-sdk-sidecar \
                -U ${overlayUuid} \
                -E hash_seed=${overlayHashSeed},no_copy_xattrs \
                -b ${toString overlayBlockSize} \
                -d "$staging" \
                $out/sdk.ext4

            echo "${overlayVersion}" > $out/VERSION
            chmod 0644 $out/sdk.ext4 $out/VERSION

            # Manifest over exactly the files the resolver verifies, in the
            # order it walks them.
            ( cd $out && sha256sum sdk.ext4 VERSION > checksums-sha256.txt )
            chmod 0644 $out/checksums-sha256.txt

            echo "mvm-sdk-sidecar-image built for ${system}" >&2
            echo "  sdk.ext4 size: $(stat -c%s $out/sdk.ext4) bytes" >&2
            echo "  VERSION: $(cat $out/VERSION)" >&2
          '';

      mkRuntimeOverlay =
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          guest = mvmGuestFor system;
          runner = mvmRunnerFor system;
          egressClient = mvmEgressClientFor system;
          addonDns = mvmAddonDnsFor system;
          exitReport = mvmExitReportFor system;
        in
        pkgs.runCommand "mvm-runtime-overlay-${system}"
          {
            nativeBuildInputs = [
              pkgs.e2fsprogs
              (pinnedCryptsetupFor pkgs) # provides pinned veritysetup
              pkgs.coreutils
            ];
            passthru = {
              inherit
                guest
                runner
                egressClient
                addonDns
                exitReport
                ;
              sdkSidecar = mkSdkSidecar system;
              sdkSidecarImage = mkSdkSidecarImage system;
              version = overlayVersion;
              dataBlockSize = overlayBlockSize;
              verityHashAlgorithm = overlayVerityHashAlgorithm;
            };
          }
          ''
            set -euo pipefail

            # Staging tree — the eventual filesystem root inside the
            # overlay ext4. The kernel mounts this at /mvm/runtime
            # inside the guest, so the *FS root* contains
            # /agent, /display-bridge, /seccomp-apply, /ping, /netinit,
            # /runner, /egress-client, /addon-dns, /exit-report, /sdk-py/,
            # /sdk-ts/, /VERSION.
            staging="$TMPDIR/staging"
            mkdir -p "$staging"

            cp ${guest}/bin/mvm-guest-agent "$staging/agent"
            cp ${guest}/bin/mvm-display-bridge "$staging/display-bridge"
            cp ${guest}/bin/mvm-seccomp-apply "$staging/seccomp-apply"
            cp ${guest}/bin/mvm-ping "$staging/ping"
            cp ${guest}/bin/mvm-guest-netinit    "$staging/netinit"
            cp ${runner}/bin/mvm-runner "$staging/runner"
            cp ${egressClient}/bin/mvm-egress-client "$staging/egress-client"
            cp ${addonDns}/bin/mvm-addon-dns "$staging/addon-dns"
            cp ${exitReport}/bin/mvm-exit-report "$staging/exit-report"

            # In-guest Python runtime SDK. PYTHONPATH points at
            # /mvm/runtime/sdk-py (see mk-guest.nix), so the `mvm` package
            # lands at /mvm/runtime/sdk-py/mvm. Host-services calls load the
            # separately attached SDK sidecar at /mvm/sdk/lib. Pure Python,
            # copied from the workspace source.
            mkdir -p "$staging/sdk-py"
            cp -r ${workspace}/crates/mvm-sdk/sdks/python/mvm "$staging/sdk-py/mvm"
            # The copied Python package may carry read-only directories from
            # the Nix store source, so make the tree writable before trying
            # to prune any __pycache__ directories.
            chmod -R u+w "$staging/sdk-py"
            find "$staging/sdk-py" -name '__pycache__' -type d -prune \
              -exec rm -rf {} +

            # TS runtime SDK placeholder. The koffi shim (mvm.audit / mvm.host
            # in @runmvm/mvm) is built and tested, but baking it into the guest
            # needs a node runtime + the koffi native addon cross-built for the
            # guest arch (a packaging step beyond the Python case, where ctypes
            # is stdlib). That guest TS-runtime bake rides the live-E2E work.
            mkdir -p "$staging/sdk-ts"
            cat > "$staging/sdk-ts/README.md" <<EOF
            mvm-sdk-runtime TypeScript hooks — koffi shim shipped in @runmvm/mvm;
            guest node + koffi-addon bake pending (rides live E2E).
            EOF

            # Version pin. The resolver compares this to the
            # running mvmctl version and refuses to attach a
            # mismatched overlay.
            echo "${overlayVersion}" > "$staging/VERSION"

            chmod -R u+rwX,go+rX "$staging"

            mkdir -p $out

            # Host-side OCI materialization needs this compatibility set before
            # the overlay is attached. Publish the exact static binaries beside
            # the disk so an installed mvmctl never needs a Rust toolchain.
            mkdir -p $out/guest-runtime
            cp ${guest}/bin/mvm-guest-agent    $out/guest-runtime/mvm-guest-agent
            cp ${guest}/bin/mvm-guest-netinit  $out/guest-runtime/mvm-guest-netinit
            cp ${egressClient}/bin/mvm-egress-client $out/guest-runtime/mvm-egress-client
            cp ${guest}/bin/mvm-oci-entrypoint $out/guest-runtime/mvm-oci-entrypoint
            chmod 0555 $out/guest-runtime/*

            # ext4 generation. Mirrors
            # `mvm_build::oci_to_rootfs::ext4::materialize_to_ext4`
            # parameters — same UUID / hash_seed / block size /
            # SOURCE_DATE_EPOCH conventions. Pre-allocate the
            # output file at the fixed budget (16 MiB) so the size
            # is also part of the deterministic shape.
            #
            # `-O ^has_journal,^orphan_file` mirrors the builder VM's
            # `DISABLED_EXT4_FEATURES` (mvm_fs::oci_to_rootfs::ext4) and
            # the pure-Rust writer, which never emits a journal. The
            # overlay mounts read-only under dm-verity, so a journal is
            # never replayed — it only burned 1 MiB of the fixed
            # allocation and carried mkfs-version-dependent bytes.
            truncate -s ${toString overlaySizeBytes} $out/overlay.ext4
            SOURCE_DATE_EPOCH=0 \
              mkfs.ext4 -F \
                -t ext4 \
                -O ^has_journal,^orphan_file \
                -L mvm-runtime-overlay \
                -U ${overlayUuid} \
                -E hash_seed=${overlayHashSeed},no_copy_xattrs \
                -b ${toString overlayBlockSize} \
                -d "$staging" \
                $out/overlay.ext4

            # Verity sidecar. Parameters mirror
            # `mvm_build::oci_to_rootfs::verity::VeritysetupOptions::default` —
            # data block 1024 (must match the guest agent's
            # DATA_BLOCK_SIZE constant), hash block 4096, zero
            # salt, sha256.
            touch $out/overlay.verity
            veritysetup_out=$(
              veritysetup format \
                --data-block-size=${toString overlayBlockSize} \
                --hash-block-size=${toString overlayVerityHashBlockSize} \
                --salt=${overlayVeritySalt} \
                --hash=${overlayVerityHashAlgorithm} \
                --uuid=${overlayVerityUuid} \
                $out/overlay.ext4 \
                $out/overlay.verity
            )

            # Extract the root hash from veritysetup's
            # "Root hash:" output line and write it as
            # `<hex>\n` — the resolver reads the file with
            # `trim()` so the trailing newline is fine.
            echo "$veritysetup_out" \
              | grep -i '^Root hash:' \
              | sed 's/^[Rr]oot [Hh]ash:[[:space:]]*//' \
              | tr 'A-F' 'a-f' \
              > $out/overlay.roothash

            # Repeat VERSION at the artifact-dir level so the
            # resolver can read it without mounting the ext4. The
            # in-rootfs VERSION (under $staging) is for boot-time
            # introspection (an in-guest tool could read
            # /mvm/runtime/VERSION). Both must agree.
            echo "${overlayVersion}" > $out/VERSION

            # Permissions + summary.
            chmod 0644 $out/overlay.ext4 $out/overlay.verity $out/overlay.roothash $out/VERSION

            echo "mvm-runtime-overlay built for ${system}" >&2
            echo "  overlay.ext4 size: $(stat -c%s $out/overlay.ext4) bytes" >&2
            echo "  roothash: $(cat $out/overlay.roothash)" >&2
            echo "  VERSION: $(cat $out/VERSION)" >&2
          '';

    in
    {
      packages = forAllSystems (system: {
        default = mkRuntimeOverlay system;
        runtime-overlay = mkRuntimeOverlay system;
        sdk-sidecar = mkSdkSidecar system;
        sdk-sidecar-image = mkSdkSidecarImage system;
        # Exposed individually so each libc variant can be built and inspected
        # on its own; the musl one is what an Alpine guest can load.
        sdk-cdylib-glibc = mvmSdkCdylibForLibc system "glibc";
        sdk-cdylib-musl = mvmSdkCdylibForLibc system "musl";
        sdk-sidecar-musl = mkSdkSidecarForLibc system "musl";
        sdk-sidecar-image-musl = mkSdkSidecarImageForLibc system "musl";
      });
    };
}
