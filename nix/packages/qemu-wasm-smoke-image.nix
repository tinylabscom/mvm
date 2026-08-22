# Minimal x86_64 guest image for QEMU-Wasm engine smoke tests.
#
# This derivation cross-builds a tiny x86_64 Linux kernel and a busybox-based
# rootfs so that `nix build .#qemu-wasm-engine` can be exercised end-to-end in
# a browser without requiring container2wasm or Docker.

{ lib
, stdenv
, pkgs
, qemu-wasm-engine
}:

let
  # Full cross-compiling package set targeting x86_64-linux from the
  # evaluating host (e.g. aarch64-linux builder VM).  It exposes the same
  # top-level interface as the native package set, including
  # `linuxManualConfig`, `busybox`, and `stdenv`, so mvm's shared kernel
  # base can be reused unchanged.
  crossPkgs = pkgs.pkgsCross.gnu64;

  # Reuse mvm's slim kernel base, but cross-built for x86_64.
  kernelBase = import ../images/kernel/base.nix { pkgs = crossPkgs; };
  kernelConfig = kernelBase.mkConfigfile {
    extraDisables = [ "IPV6" ];
    extraEnables = [
      # QEMU-Wasm exposes the x86_64 machine's 8250 UART as the console
      # for -nographic. The base config enables these only on arm64.
      "SERIAL_8250"
      "SERIAL_8250_CONSOLE"
    ];
  };

  kernel = kernelBase.mkKernel {
    extraDisables = [ "IPV6" ];
    extraEnables = [
      # QEMU-Wasm exposes the x86_64 machine's 8250 UART as the console
      # for -nographic. The base config enables these only on arm64.
      "SERIAL_8250"
      "SERIAL_8250_CONSOLE"
    ];
  };

  # Static busybox for the guest.
  busybox = crossPkgs.busybox.override { enableStatic = true; };

  rootfs = pkgs.runCommand "qemu-wasm-smoke-rootfs"
    {
      nativeBuildInputs = [ pkgs.e2fsprogs ];
      inherit busybox;
    }
    ''
      mkdir -p rootfs/bin rootfs/etc rootfs/dev rootfs/proc rootfs/sys rootfs/tmp rootfs/run
      cp ${busybox}/bin/busybox rootfs/bin/busybox
      chmod +x rootfs/bin/busybox
      # Use the build-platform busybox to enumerate applets; the cross-built
      # binary cannot execute on the aarch64 builder.
      for applet in $(${pkgs.busybox}/bin/busybox --list); do
        ln -s busybox rootfs/bin/$applet
      done

      # Use busybox init directly so the marker is emitted as a sysinit
      # action and a shell is respawned on the serial console.  A script
      # shebang would also work, but relying on the init applet avoids any
      # permission/execution edge cases inside the minimal ext2 rootfs.
      ln -s bin/busybox rootfs/init

      cat > rootfs/etc/inittab <<'EOF2'
::sysinit:/bin/echo QEMU-WASM-SMOKE-READY
console::respawn:-/bin/sh
EOF2

      # Create a small ext2 rootfs. 8 MiB is enough for busybox + inodes.
      rm -f $out
      dd if=/dev/zero of=$out bs=1M count=8
      mkfs.ext2 -d rootfs -F -q $out
    '';
in

stdenv.mkDerivation {
  pname = "qemu-wasm-smoke-image";
  version = kernelBase.kernelVersion;

  srcs = [ ];
  sourceRoot = ".";

  dontUnpack = true;
  dontConfigure = true;
  dontBuild = true;

  installPhase = ''
    runHook preInstall
    mkdir -p $out
    cp ${kernel}/bzImage $out/kernel.img
    cp ${rootfs} $out/rootfs.bin
    # Keep the final .config for debugging kernel console/driver enablement.
    cp ${kernelConfig} $out/kernel.config
    runHook postInstall
  '';

  passthru = { inherit kernel rootfs kernelBase; };

  meta = {
    description = "Minimal x86_64 smoke-test guest image for QEMU-Wasm";
    platforms = [ "x86_64-linux" "aarch64-linux" ];
  };
}
