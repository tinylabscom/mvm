# Reproducible browser build of QEMU-Wasm.
#
# This derivation pins the patched QEMU source, the exact Emscripten SDK
# version used upstream, and every C dependency that is cross-compiled with
# Emscripten.  It produces the engine artifacts required by the WebLinux
# backend:
#
#   - qemu-system-x86_64.js glue (the extension-less Emscripten executable)
#   - qemu-system-x86_64.wasm
#   - qemu-system-x86_64.worker.js
#   - pc-bios firmware files required for x86_64 guests
#   - a wrapper for Emscripten's file_packager.py so runtime packs can be
#     built from other derivations
#
# Native default builds never depend on this derivation; it is only requested
# through the WebLinux/browser feature path.

{ lib
, stdenv
, fetchurl
, python3
, pkg-config
, ninja
, meson
, autoconf
, automake
, libtool
, perl
, gettext
, makeWrapper
}:

let
  # ── Upstream pins ──────────────────────────────────────────────────
  qemuWasmRev = "5a65998d47d78723115d1478a8a40f8d6d497f37";
  qemuWasmVersion = "9.2.92-wasm";

  emscriptenVersion = "3.1.50";
  emscriptenNixpkgsRev = "c407032be28ca2236f45c49cfb2b8b3885294f7f";

  zlibVersion = "1.3.1";
  libffiVersion = "v3.4.7";
  pixmanVersion = "0.44.2";
  glibVersion = "2.84.0";

  xtermPtyVersion = "0.10.1";

  # ── Emscripten toolchain from the nixpkgs revision that shipped 3.1.50 ─
  emscriptenPkgs = import (builtins.fetchTarball {
    name = "nixpkgs-emscripten-${emscriptenVersion}";
    url = "https://github.com/NixOS/nixpkgs/archive/${emscriptenNixpkgsRev}.tar.gz";
    hash = "sha256-6vh4Eddv0vA81x91YnB2ahqs8dLACh3L91wn+cR+UKs=";
  }) {
    inherit (stdenv.hostPlatform) system;
    config = { };
    overlays = [ ];
  };

  emscripten = emscriptenPkgs.emscripten;

  # ── Source tarballs ────────────────────────────────────────────────
  zlibSrc = fetchurl {
    url = "https://zlib.net/zlib-${zlibVersion}.tar.xz";
    hash = "sha256-zAtOQlENScbezUZBI+zzsUrptH+bTtLuZIk+LWUgomQ=";
  };

  libffiSrc = fetchurl {
    url = "https://github.com/libffi/libffi/archive/refs/tags/${libffiVersion}.tar.gz";
    hash = "sha256-8HwIycFJd+r7m1+Sd3E9kTWOwY/IqqVgfWeQzekMuhI=";
  };

  pixmanSrc = fetchurl {
    url = "https://gitlab.freedesktop.org/pixman/pixman/-/archive/pixman-${pixmanVersion}/pixman-pixman-${pixmanVersion}.tar.gz";
    hash = "sha256-GsM+IpVJ9jQaZ31TDRlEQxE50iLsrRVUgYeIrp7zL28=";
  };

  glibSrc = fetchurl {
    url = "https://download.gnome.org/sources/glib/2.84/glib-${glibVersion}.tar.xz";
    hash = "sha256-+II2AMuFQl4oFc+tguog/apThIKrdOcpPViz9kpa/2o=";
  };

  qemuSrc = fetchurl {
    url = "https://github.com/ktock/qemu-wasm/archive/${qemuWasmRev}.tar.gz";
    hash = "sha256-Q48Pd4rv5jjX7YaIimmylyXu8NmoFNOjaSpe5GjI1Sg=";
  };

  xtermPtySrc = fetchurl {
    url = "https://registry.npmjs.org/xterm-pty/-/xterm-pty-${xtermPtyVersion}.tgz";
    hash = "sha256-yhwx/UyasVBsDmYZ7jWNQmB3W3BF8QpWMbNvC6moQ0o=";
  };

  depsPrefix = "/builddeps/target";

  crossMeson = ./emscripten-cross.meson;
in

stdenv.mkDerivation (finalAttrs: {
  pname = "qemu-wasm-engine";
  version = "${qemuWasmVersion}-${qemuWasmRev}";

  srcs = [ qemuSrc xtermPtySrc ];
  sourceRoot = ".";

  nativeBuildInputs = [
    emscripten
    python3
    pkg-config
    meson
    ninja
    perl
    gettext
    autoconf
    automake
    libtool
    makeWrapper
  ];

  postUnpack = ''
    mkdir -p qemu-wasm-build
    mv qemu-wasm-${qemuWasmRev}/* qemu-wasm-build/
    rmdir qemu-wasm-${qemuWasmRev}
    mv qemu-wasm-build qemu-wasm-src

    mkdir -p xterm-pty
    tar -xzf xterm-pty-${xtermPtyVersion}.tgz -C xterm-pty
  '';

  configurePhase = ''
    runHook preConfigure

    export HOME=$TMPDIR
    export EM_CACHE=$TMPDIR/.emscripten_cache
    mkdir -p $EM_CACHE

    export TARGET=${depsPrefix}
    export CFLAGS="-O3 -pthread -DWASM_BIGINT"
    export CXXFLAGS="$CFLAGS"
    export LDFLAGS="-sWASM_BIGINT -sASYNCIFY=1 -L${depsPrefix}/lib"
    export CPATH="${depsPrefix}/include"
    export PKG_CONFIG_PATH="${depsPrefix}/lib/pkgconfig"
    export EM_PKG_CONFIG_PATH="$PKG_CONFIG_PATH"

    mkdir -p ${depsPrefix}/lib/pkgconfig ${depsPrefix}/include

    # zlib
    echo "building zlib for emscripten..."
    tar -xJf ${zlibSrc} -C /build
    pushd /build/zlib-${zlibVersion}
    emconfigure ./configure --prefix=${depsPrefix} --static
    emmake make -j$NIX_BUILD_CORES
    emmake make install
    popd

    # libffi (headers only, matching upstream)
    echo "building libffi for emscripten..."
    tar -xzf ${libffiSrc} -C /build
    pushd /build/libffi-${libffiVersion}
    autoreconf -fiv
    emconfigure ./configure \
      --host=wasm32-unknown-linux \
      --prefix=${depsPrefix} \
      --enable-static \
      --disable-shared \
      --disable-dependency-tracking \
      --disable-builddir \
      --disable-multi-os-directory \
      --disable-raw-api \
      --disable-docs
    emmake make -j$NIX_BUILD_CORES
    emmake make install SUBDIRS='include'
    popd

    # pixman
    echo "building pixman for emscripten..."
    tar -xzf ${pixmanSrc} -C /build
    pushd /build/pixman-pixman-${pixmanVersion}
    NOCONFIGURE=y ./autogen.sh
    emconfigure ./configure --prefix=${depsPrefix}
    emmake make -j$NIX_BUILD_CORES
    emmake make install
    rm -f ${depsPrefix}/lib/libpixman-1.so*
    popd

    # glib
    echo "building glib for emscripten..."
    mkdir -p /build/stub
    cat > /build/stub/res_query.c <<'C_EOF'
    #include <netdb.h>
    int res_query(const char *name, int class, int type, unsigned char *dest, int len)
    {
      h_errno = HOST_NOT_FOUND;
      return -1;
    }
    C_EOF
    pushd /build/stub
    emcc $CFLAGS -c res_query.c -fPIC -o libresolv.o
    ar rcs libresolv.a libresolv.o
    cp libresolv.a ${depsPrefix}/lib/
    popd

    tar -xJf ${glibSrc} -C /build
    pushd /build/glib-${glibVersion}
    meson setup _build \
      --prefix=${depsPrefix} \
      --cross-file=${crossMeson} \
      --default-library=static \
      --buildtype=release \
      --force-fallback-for=pcre2 \
      -Dselinux=disabled \
      -Dxattr=false \
      -Dlibmount=disabled \
      -Dnls=disabled \
      -Dtests=false \
      -Dglib_debug=disabled \
      -Dglib_assert=false \
      -Dglib_checks=false
    sed -i -E "/#define HAVE_POSIX_SPAWN 1/d" _build/config.h
    sed -i -E "/#define HAVE_PTHREAD_GETNAME_NP 1/d" _build/config.h
    meson install -C _build
    popd

    # QEMU
    echo "configuring qemu-wasm..."
    pushd qemu-wasm-src

    EXTRA_CFLAGS="-O3 -g -Wno-error=unused-command-line-argument -matomics -mbulk-memory -DNDEBUG -DG_DISABLE_ASSERT -D_GNU_SOURCE -sASYNCIFY=1 -pthread -sPROXY_TO_PTHREAD=1 -sFORCE_FILESYSTEM -sALLOW_TABLE_GROWTH -sTOTAL_MEMORY=2300MB -sWASM_BIGINT -sMALLOC=mimalloc --js-library=$PWD/../xterm-pty/package/emscripten-pty.js -sEXPORT_ES6=1 -sASYNCIFY_IMPORTS=ffi_call_js"
    EXTRA_LDFLAGS="-sEXPORTED_RUNTIME_METHODS=getTempRet0,setTempRet0,addFunction,removeFunction,TTY,FS"

    emconfigure ./configure \
      --static \
      --target-list=x86_64-softmmu \
      --cpu=wasm32 \
      --cross-prefix= \
      --without-default-features \
      --enable-system \
      --with-coroutine=fiber \
      --enable-virtfs \
      --extra-cflags="$EXTRA_CFLAGS" \
      --extra-cxxflags="$EXTRA_CFLAGS" \
      --extra-ldflags="$EXTRA_LDFLAGS"

    popd

    runHook postConfigure
  '';

  buildPhase = ''
    runHook preBuild
    pushd qemu-wasm-src
    emmake make -j$NIX_BUILD_CORES qemu-system-x86_64
    popd
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall

    mkdir -p $out/libexec/qemu-wasm
    cp qemu-wasm-src/qemu-system-x86_64 $out/libexec/qemu-wasm/qemu-system-x86_64.js
    cp qemu-wasm-src/qemu-system-x86_64.wasm $out/libexec/qemu-wasm/
    cp qemu-wasm-src/qemu-system-x86_64.worker.js $out/libexec/qemu-wasm/

    mkdir -p $out/share/qemu-wasm/bios
    cp qemu-wasm-src/pc-bios/{bios-256k.bin,vgabios-stdvga.bin,kvmvapic.bin,linuxboot_dma.bin} \
      $out/share/qemu-wasm/bios/ 2>/dev/null || true

    makeWrapper ${emscripten}/share/emscripten/tools/file_packager.py \
      $out/bin/qemu-wasm-file-packager \
      --set PYTHON ${python3}/bin/python \
      --set HOME $TMPDIR

    cat > $out/share/qemu-wasm/PINS <<'PINS_EOF'
    qemu-wasm ${qemuWasmRev}
    emscripten ${emscriptenVersion}
    emscripten-nixpkgs ${emscriptenNixpkgsRev}
    zlib ${zlibVersion}
    libffi ${libffiVersion}
    pixman ${pixmanVersion}
    glib ${glibVersion}
    xterm-pty ${xtermPtyVersion}
    PINS_EOF

    runHook postInstall
  '';

  doCheck = false;

  meta = {
    description = "Browser build of QEMU with the qemu-wasm WebAssembly TCG backend";
    homepage = "https://github.com/ktock/qemu-wasm";
    license = lib.licenses.gpl2Only;
    platforms = [ "x86_64-linux" ];
    maintainers = [ ];
  };
})
