{
  description = "mvm runtime overlay disk — verity-sealed ext4 carrying the guest agent + seccomp shim + netinit + runner, mounted at /mvm/runtime in every microVM (ADR-051)";

  # ── Why this flake exists ─────────────────────────────────────────
  #
  # ADR-051 (`specs/adrs/051-mvm-runtime-overlay-disk.md`) introduces
  # a second virtio-blk device that every mvm microVM attaches at
  # boot — Nix-built rootfs and OCI-pulled rootfs alike. The
  # overlay carries the in-VM binaries mvm controls (the guest
  # agent, the per-service seccomp shim, the function-workload
  # runner, and — plan 74 W2 — `mvm-guest-netinit` which installs
  # kernel blackhole routes for `MANDATORY_DENY_RANGES` so OCI-
  # imported workloads get Layer 1 network defense too) plus a
  # placeholder for the per-language SDK runtime libraries that
  # ADR-049's vsock substitution depends on (the libraries
  # themselves land in plan 74 W4; this flake reserves the
  # directory layout today so the boot path is stable).
  #
  # The flake produces, per supported system, a `$out/` containing:
  #
  #   overlay.ext4      — the rootfs the kernel mounts at
  #                       /mvm/runtime via dm-verity. Read-only at
  #                       boot.
  #   overlay.verity    — dm-verity sidecar (Merkle tree).
  #   overlay.roothash  — 64 lowercase hex chars + newline. What
  #                       mvm-verity-init reads from the kernel
  #                       cmdline as `mvm.runtime_roothash=<hex>`.
  #   VERSION           — semver of the producing mvmctl. The
  #                       resolver (`mvm_build::runtime_overlay`,
  #                       plan 74 W1.4b.1) refuses to attach an
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
  # 2. Per ADR-051's `mkGuest` refactor (W1.4b.3), the per-image
  #    closure stops carrying `mvm-guest-agent`, `mvm-seccomp-apply`,
  #    `mvm-runner`. Those binaries live here. Net effect: every
  #    Nix-built image shrinks by ~10-15 MB.
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
  # + identical `overlay.roothash`. ADR-051's per-version cache
  # depends on this property. We pin every source of mkfs.ext4
  # randomness (UUID, hash_seed, SOURCE_DATE_EPOCH) and every
  # source of veritysetup randomness (salt, data block size, hash
  # algo). Nix's sandbox covers the rest (timestamps,
  # parallelism-induced ordering).
  #
  # ── Cryptsetup version pin (issue #223) ────────────────────────
  #
  # The W3 verity build pins `cryptsetup` via the same nixpkgs
  # commit. The OCI-pull path's seal_with_verity (W1.4a) inherits
  # whatever cryptsetup is on `$PATH` in the builder VM. This
  # flake stays consistent with the W3 derivation by routing
  # through the same `nixpkgs.cryptsetup` attribute. Issue #223
  # tracks tightening this to an explicit version override.

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
  };

  outputs =
    { self, nixpkgs, ... }:
    let
      systems = [ "aarch64-linux" "x86_64-linux" ];
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

      # mvmctl semver pinned to match
      # `[workspace.package].version` in the root Cargo.toml. The
      # `RuntimeOverlayResolver` rejects an overlay whose VERSION
      # file disagrees with the running mvmctl. Bumping the
      # workspace version requires bumping this string too — keep
      # the two in lock-step or `mvmctl up` admission fails.
      overlayVersion = "0.14.0";

      # mvm-guest binaries — agent + seccomp shim + verity-init.
      # `mvm-verity-init` is the initrd PID 1; it lives in the
      # initramfs cpio.gz, *not* in this overlay. We still build
      # it here because the rustPlatform derivation produces all
      # three binaries from one `--package mvm-guest` build (per
      # `nix/packages/mvm-guest-agent.nix`'s
      # `--bin mvm-guest-agent --bin mvm-seccomp-apply --bin mvm-verity-init`
      # flags); we just don't copy the verity-init binary into the
      # overlay's staging dir.
      mvmGuestFor = system:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        import (workspace + "/nix/packages/mvm-guest-agent.nix") {
          inherit pkgs;
          lib = pkgs.lib;
          mvmSrc = workspace;
          # No dev-shell — the overlay ships the production agent.
          # ADR-002 §W4.3's `prod-agent-no-exec` CI gate asserts
          # `mvm_guest_agent::do_exec` is absent from this binary.
          withDevShell = false;
        };

      # mvm-runner — the function-workload entrypoint runner
      # (plan 60 Phase 5 Slice C). Folded into mvm-guest as a [[bin]]
      # (plan 121 A1), so we select just that binary out of the
      # mvm-guest package; workspace Cargo.lock drives the closure.
      mvmRunnerFor = system:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        pkgs.rustPlatform.buildRustPackage {
          pname = "mvm-runner";
          version = overlayVersion;
          src = workspace;
          cargoLock = {
            lockFile = workspace + "/Cargo.lock";
          };
          cargoBuildFlags = [ "--package" "mvm-guest" "--bin" "mvm-runner" ];
          doCheck = false;
          meta = {
            description = "mvm function-workload entrypoint runner (plan 60 Phase 5 Slice C)";
            mainProgram = "mvm-runner";
          };
        };

      # Pinned-for-determinism flags. MUST mirror:
      #
      # - `mvm_build::oci_to_rootfs::ext4::Mke2fsOptions::default`
      #   for ext4 (UUID, hash_seed, block size, SOURCE_DATE_EPOCH).
      # - `mvm_build::oci_to_rootfs::verity::VeritysetupOptions::default`
      #   for verity (data block 1024, hash block 4096, zero salt,
      #   sha256).
      #
      # The unit tests
      # `defaults_match_mvm_verity_init_constants` (W1.4a) and
      # `defaults_are_deterministic_and_pinned` (W1.3b) enforce
      # the Rust-side constants; this comment is the cross-stack
      # contract. If you bump either side, bump both.
      overlayUuid = "00000000-0000-0000-0000-00000000beef";
      overlayHashSeed = "00000000-0000-0000-0000-00000000cafe";
      overlayBlockSize = 1024;
      overlayVeritySalt = "0000000000000000000000000000000000000000000000000000000000000000";
      overlayVerityHashAlgorithm = "sha256";
      overlayVerityHashBlockSize = 4096;

      # ADR-050 / issue #223 — keep the Nix-built verity baseline on
      # the exact same cryptsetup release as the builder VM's OCI-pull
      # path. A nixpkgs bump must not silently change `veritysetup`
      # output bytes; bump version + hash here and in
      # `nix/images/builder-vm/flake.nix` together.
      pinnedCryptsetupVersion = "2.8.6";
      pinnedCryptsetupSrcHash = "sha256-gAQmX9mTiF0I97Yz2+BWhR3hohAwdhOk693HQ/zO/lo=";
      pinnedCryptsetupFor = pkgs:
        pkgs.cryptsetup.overrideAttrs (_old: {
          version = pinnedCryptsetupVersion;
          src = pkgs.fetchurl {
            url =
              "mirror://kernel/linux/utils/cryptsetup/v${pkgs.lib.versions.majorMinor pinnedCryptsetupVersion}/"
              + "cryptsetup-${pinnedCryptsetupVersion}.tar.xz";
            hash = pinnedCryptsetupSrcHash;
          };
        });

      # Target overlay size: 32 MiB. ADR-051 §"Open questions" pins
      # a hard cap of 32 MiB for the overlay budget; today's
      # contents fit in well under that, but using the cap as the
      # nominal size leaves headroom for the W4 SDK runtime
      # libraries without re-allocating the ext4 each release.
      overlaySizeBytes = 32 * 1024 * 1024;

      mkRuntimeOverlay = system:
        let
          pkgs = import nixpkgs { inherit system; };
          guest = mvmGuestFor system;
          runner = mvmRunnerFor system;
        in
        pkgs.runCommand "mvm-runtime-overlay-${system}"
          {
            nativeBuildInputs = [
              pkgs.e2fsprogs
              (pinnedCryptsetupFor pkgs) # provides pinned veritysetup
              pkgs.coreutils
            ];
            passthru = {
              inherit guest runner;
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
            # /agent, /seccomp-apply, /runner, /sdk-py/, /sdk-ts/,
            # /VERSION.
            staging="$TMPDIR/staging"
            mkdir -p "$staging"
            cp ${guest}/bin/mvm-guest-agent      "$staging/agent"
            cp ${guest}/bin/mvm-seccomp-apply    "$staging/seccomp-apply"
            cp ${guest}/bin/mvm-guest-netinit    "$staging/netinit"
            cp ${runner}/bin/mvm-runner          "$staging/runner"

            # SDK runtime library placeholders. plan 74 W4 fills
            # these with the pyo3 / napi-rs hook libraries that
            # ADR-049's vsock substitution depends on. Today they
            # exist so the boot path stabilizes and downstream
            # code (PYTHONPATH/NODE_PATH injection in the service
            # supervisor) can reference fixed mount points.
            mkdir -p "$staging/sdk-py" "$staging/sdk-ts"
            cat > "$staging/sdk-py/README.md" <<EOF
            mvm-sdk-runtime Python hooks (plan 74 W4 — placeholder).
            EOF
            cat > "$staging/sdk-ts/README.md" <<EOF
            mvm-sdk-runtime TypeScript hooks (plan 74 W4 — placeholder).
            EOF

            # Version pin. The resolver compares this to the
            # running mvmctl version and refuses to attach a
            # mismatched overlay.
            echo "${overlayVersion}" > "$staging/VERSION"

            chmod -R u+rwX,go+rX "$staging"

            mkdir -p $out

            # ext4 generation. Mirrors
            # `mvm_build::oci_to_rootfs::ext4::materialize_to_ext4`
            # parameters — same UUID / hash_seed / block size /
            # SOURCE_DATE_EPOCH conventions. Pre-allocate the
            # output file at the fixed budget (32 MiB) so the size
            # is also part of the deterministic shape.
            truncate -s ${toString overlaySizeBytes} $out/overlay.ext4
            SOURCE_DATE_EPOCH=0 \
              mkfs.ext4 -F \
                -t ext4 \
                -L mvm-runtime-overlay \
                -U ${overlayUuid} \
                -E hash_seed=${overlayHashSeed} \
                -E no_copy_xattrs \
                -b ${toString overlayBlockSize} \
                -d "$staging" \
                $out/overlay.ext4

            # Verity sidecar. Parameters mirror
            # `mvm_build::oci_to_rootfs::verity::VeritysetupOptions::default` —
            # data block 1024 (must match `mvm-verity-init.rs`'s
            # DATA_BLOCK_SIZE constant), hash block 4096, zero
            # salt, sha256.
            touch $out/overlay.verity
            veritysetup_out=$(
              veritysetup format \
                --data-block-size=${toString overlayBlockSize} \
                --hash-block-size=${toString overlayVerityHashBlockSize} \
                --salt=${overlayVeritySalt} \
                --hash=${overlayVerityHashAlgorithm} \
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
      });
    };
}
