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
      # Networking stack for QEMU's user-mode LAN.
      "NETDEVICES"
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
      # /etc/hosts is populated at boot from mvm.allow_host=... if provided.
      touch rootfs/etc/hosts
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

      mkdir -p rootfs/etc/init.d

      cat > rootfs/etc/init.d/rcS <<'EOF2'
#!/bin/sh
# Mount the pseudo-filesystems busybox ps/top need.
/bin/mkdir -p /proc /sys /dev /tmp /run /dev/pts
/bin/mount -t proc proc /proc
/bin/mount -t sysfs sys /sys
/bin/mount -t devtmpfs dev /dev 2>/dev/null || /bin/mount -t tmpfs dev /dev
/bin/mount -t devpts devpts /dev/pts 2>/dev/null || true
# Ensure a console device exists even if devtmpfs did not populate it.
[ -c /dev/console ] || /bin/mknod /dev/console c 5 1 2>/dev/null || true

# Bring up loopback and configure a static address on QEMU's user-mode LAN.
/bin/ifconfig lo 127.0.0.1 up
/bin/ifconfig eth0 10.0.2.15 netmask 255.255.255.0 up
/bin/route add default gw 10.0.2.2 eth0 2>/dev/null || true

# If the launcher passed mvm.allow_host=<host>, record it in /etc/hosts so the
# demo page can show the allow-host plumbing.  Resolve it to loopback so the
# guest can ping/connect to the name without sending ICMP/TCP through QEMU's
# user-mode LAN; Emscripten's socket emulation forwards host-bound traffic to a
# WebSocket that SLIRP cannot satisfy, which crashes the worker with a
# divide-by-zero.
allowed_host=$(/bin/cat /proc/cmdline | /bin/tr ' ' '\n' | /bin/grep '^mvm.allow_host=' | /bin/cut -d= -f2)
if [ -n "$allowed_host" ]; then
  /bin/echo "127.0.0.1 $allowed_host" >> /etc/hosts
fi

/bin/echo QEMU-WASM-SMOKE-READY
EOF2
      chmod +x rootfs/etc/init.d/rcS

      cat > rootfs/etc/inittab <<'EOF2'
::sysinit:/etc/init.d/rcS
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
