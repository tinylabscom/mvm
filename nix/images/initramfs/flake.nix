{
  description = "mvm universal initramfs — minimal gzip-compressed cpio containing a static `mvm-guest-agent` as `/init` (Plan 270)";

  # ── Why this flake exists ─────────────────────────────────────────
  #
  # Every sealed mvm workload boots from a tiny, content-addressed
  # initramfs.  The initramfs carries exactly one executable: a static
  # `mvm-guest-agent` binary installed as `/init` so the kernel execs it
  # as PID 1.  PID 1 then listens on vsock for an `ActivateEnvironment`
  # message from the host, mounts the verified rootfs + runtime overlay,
  # drops privilege, and starts the workload.
  #
  # The initramfs deliberately contains NO busybox, NO setpriv, NO
  # shells, NO secrets, and NO runtime overlay; all of that arrives from
  # the host after activation.  The result is a single, small artifact
  # shared by every workload rootfs image for a given (arch, agent
  # version, kernel version) tuple.
  #
  # Output layout under `$out/`:
  #
  #   initramfs.cpio.gz  — the gzip-compressed cpio the VMM loads as
  #                        the guest initrd.
  #   initramfs.hash     — SHA-256 of the uncompressed cpio payload,
  #                        exposed as a passthru so the host can select
  #                        the correct initramfs by content hash.
  #   initramfs.size     — byte size of the compressed artifact.
  #   VERSION            — semver of the producing mvmctl, matching the
  #                        runtime overlay VERSION contract.
  #
  # The Nix derivation output path itself is content-addressed by the
  # inputs (arch, agent derivation, kernel version parameter), so the
  # hash file is a convenience for the runtime resolver rather than the
  # source of truth.

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
  };

  outputs =
    { self, nixpkgs, ... }:
    let
      systems = [ "aarch64-linux" "x86_64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;

      # Workspace staging — same `MVM_WORKSPACE_PATH` env override the
      # runtime-overlay and builder-vm flakes use.
      workspaceRoot =
        let
          envPath = builtins.getEnv "MVM_WORKSPACE_PATH";
        in
        if envPath != "" then /. + envPath else ../../..;

      workspace =
        (import (workspaceRoot + "/nix/lib/workspace-filter.nix") {
          inherit (nixpkgs) lib;
        })
        { inherit workspaceRoot; };

      # mvmctl semver pinned to match `[workspace.package].version` in
      # the root Cargo.toml.  Kept in lock-step with the runtime overlay
      # VERSION pin.
      initramfsVersion = "0.18.0";

      # Static guest agent — the only binary in the initramfs.
      mvmGuestStaticFor = system:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        import (workspace + "/nix/packages/mvm-guest-agent-static.nix") {
          inherit pkgs;
          lib = pkgs.lib;
          mvmSrc = workspace;
          # The universal initramfs always ships the production agent.
          withInteractive = false;
        };

      # Kernel version is part of the content-addressing tuple.  Until the
      # kernel flake is wired to feed its version here, default to the
      # workload kernel's 6.12 baseline so the derivation is usable today
      # and can be pinned precisely later without invalidating the build.
      defaultKernelVersion = "6.12";

      mkInitramfs =
        { system
        , kernelVersion ? defaultKernelVersion
        }:
        let
          pkgs = import nixpkgs { inherit system; };
          agent = mvmGuestStaticFor system;
        in
        pkgs.runCommand "mvm-initramfs-${system}-${kernelVersion}"
          {
            nativeBuildInputs = [
              pkgs.coreutils
              pkgs.cpio
              pkgs.gzip
            ];
            passthru = {
              inherit agent kernelVersion;
              version = initramfsVersion;
            };
          }
          ''
            set -euo pipefail

            # Staging tree for the cpio payload.
            staging="$TMPDIR/initramfs-staging"
            mkdir -p "$staging/dev"

            # /init is the static guest agent.  Mode 0755 so the kernel can
            # exec it as PID 1.
            install -m 0755 "${agent}/bin/mvm-guest-agent" "$staging/init"

            # Minimal device nodes so PID 1 can log to /dev/console and open
            # /dev/null during early bring-up before devtmpfs is mounted.
            # Major/minor numbers are stable Linux conventions.
            mknod -m 0600 "$staging/dev/console" c 5 1
            mknod -m 0666 "$staging/dev/null"    c 1 3
            mknod -m 0666 "$staging/dev/zero"    c 1 5
            mknod -m 0666 "$staging/dev/random"  c 1 8
            mknod -m 0666 "$staging/dev/urandom" c 1 9

            # Deterministic metadata: epoch timestamps and root ownership keep
            # the content hash stable across rebuilds.
            find "$staging" -exec touch -hcd @0 {} +

            mkdir -p "$out"

            # Deterministic newc cpio: sorted paths, root owner, no timestamps.
            ( cd "$staging" \
              && find . -print0 | sort -z | cpio --null -o -H newc --owner=0:0 \
            ) > "$TMPDIR/initramfs.cpio"

            # Gzip without filename/timestamp in the header.
            gzip -n -9 < "$TMPDIR/initramfs.cpio" > "$out/initramfs.cpio.gz"

            # Content-addressable hash of the uncompressed cpio contents.
            sha256sum "$TMPDIR/initramfs.cpio" | awk '{print $1}' > "$out/initramfs.hash"
            echo "$(stat -c%s "$out/initramfs.cpio.gz")" > "$out/initramfs.size"

            # Version pin, matching the runtime overlay contract.
            echo "${initramfsVersion}" > "$out/VERSION"

            chmod 0644 \
              "$out/initramfs.cpio.gz" \
              "$out/initramfs.hash" \
              "$out/initramfs.size" \
              "$out/VERSION"

            echo "mvm-initramfs built for ${system} (kernel ${kernelVersion})" >&2
            echo "  compressed size: $(cat "$out/initramfs.size") bytes" >&2
            echo "  cpio hash:       $(cat "$out/initramfs.hash")" >&2
            echo "  VERSION:         $(cat "$out/VERSION")" >&2
          '';
    in
    {
      packages = forAllSystems (system: {
        default = mkInitramfs { inherit system; };
        initramfs = mkInitramfs { inherit system; };
      });
    };
}
