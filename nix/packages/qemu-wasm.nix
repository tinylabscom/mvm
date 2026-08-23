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

{
  lib,
  stdenv,
  fetchurl,
  python3,
  writeShellScript,
  pkg-config,
  ninja,
  meson,
  autoconf,
  automake,
  libtool,
  perl,
  gettext,
  unzip,
}:

let
  # ── Upstream pins ──────────────────────────────────────────────────
  qemuWasmRev = "5a65998d47d78723115d1478a8a40f8d6d497f37";
  qemuWasmVersion = "9.2.92-wasm";

  emscriptenVersion = "3.1.50";
  emscriptenNixpkgsRev = "c407032be28ca2236f45c49cfb2b8b3885294f7f";

  zlibVersion = "1.3.1";
  libffiVersion = "3.4.7";
  pixmanVersion = "0.44.2";
  glibVersion = "2.84.0";

  xtermPtyVersion = "0.10.1";
  pcre2Version = "10.44";
  dtcRev = "b6910bec11614980a21e46fbccc35934b671bd81";

  # ── Emscripten toolchain from the nixpkgs revision that shipped 3.1.50 ─
  emscriptenPkgs =
    import
      (builtins.fetchTarball {
        name = "nixpkgs-emscripten-${emscriptenVersion}";
        url = "https://github.com/NixOS/nixpkgs/archive/${emscriptenNixpkgsRev}.tar.gz";
        sha256 = "1a95d5g5frzgbywpq7z0az8ap99fljqk3pkm296asrvns8qcv5bv";
      })
      {
        inherit (stdenv.hostPlatform) system;
        config = { };
        overlays = [ ];
      };

  emscripten = emscriptenPkgs.emscripten;

  # ── Source tarballs ────────────────────────────────────────────────
  zlibSrc = fetchurl {
    url = "https://github.com/madler/zlib/releases/download/v${zlibVersion}/zlib-${zlibVersion}.tar.gz";
    hash = "sha256-mpOyt9/ax3zrpaVYpYDnRmfdb+3kWFuR7vtg8Dty3yM=";
  };

  libffiSrc = fetchurl {
    url = "https://github.com/libffi/libffi/archive/refs/tags/v${libffiVersion}.tar.gz";
    hash = "sha256-8HwIycFJd+r7m1+Sd3E9kTWOwY/IqqVgfWeQzekMuhI=";
  };

  pixmanSrc = fetchurl {
    url = "https://www.cairographics.org/releases/pixman-${pixmanVersion}.tar.gz";
    hash = "sha256-Y0kGHOGjOKtpUrkhlNGwN3RyJEII1H/yW++G/HGXNGY=";
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

  pcre2Src = fetchurl {
    url = "https://github.com/PCRE2Project/pcre2/releases/download/pcre2-${pcre2Version}/pcre2-${pcre2Version}.tar.bz2";
    sha256 = "15nyymp7q8ax1v8pw12fbm48s217qlx0sxzjxfhr6wfg2ghh4kyk";
  };

  pcre2Patch = fetchurl {
    url = "https://wrapdb.mesonbuild.com/v2/pcre2_${pcre2Version}-2/get_patch";
    sha256 = "02a0m4f8m2d76gfcqcbz0bjwkm20378bpnqhbrz88hwhxqid8dj3";
  };

  dtcSrc = fetchurl {
    url = "https://gitlab.com/qemu-project/dtc/-/archive/${dtcRev}/dtc-${dtcRev}.tar.gz";
    sha256 = "1iq7y2hcvadkmw2ljfrd0wb3gpkm2vnnr92ha6i1nfn2xs3zj5g1";
  };
  # ── QEMU subprojects (prefetched so meson does not need network) ─────
  keycodemapdbSrc = fetchurl {
    url = "https://gitlab.com/qemu-project/keycodemapdb/-/archive/f5772a62ec52591ff6870b7e8ef32482371f22c6/keycodemapdb-f5772a62ec52591ff6870b7e8ef32482371f22c6.tar.gz";
    sha256 = "15ci40abnv0swl5lpmgpp7qhw3gjww6za4mdjs0ppcfvh8rva56h";
  };

  berkeleySoftfloat3Src = fetchurl {
    url = "https://gitlab.com/qemu-project/berkeley-softfloat-3/-/archive/b64af41c3276f97f0e181920400ee056b9c88037/berkeley-softfloat-3-b64af41c3276f97f0e181920400ee056b9c88037.tar.gz";
    sha256 = "0mw7sjw25j1wi027hxv45ammpsf7wqv9ngd0ghpjjspa2jc8ibps";
  };

  berkeleyTestfloat3Src = fetchurl {
    url = "https://gitlab.com/qemu-project/berkeley-testfloat-3/-/archive/e7af9751d9f9fd3b47911f51a5cfd08af256a9ab/berkeley-testfloat-3-e7af9751d9f9fd3b47911f51a5cfd08af256a9ab.tar.gz";
    sha256 = "1pxib7dxfp7gca8qqqv7hmw4ygc3qdgwh6f94a2cp5kyvi8rv877";
  };

  libblkioSrc = fetchurl {
    url = "https://gitlab.com/libblkio/libblkio/-/archive/f84cc963a444e4cb34813b2dcfc5bf8526947dc0/libblkio-f84cc963a444e4cb34813b2dcfc5bf8526947dc0.tar.gz";
    sha256 = "1ia0lwkfvddcxxdw1rwb5jcg3vmrzaq139i72xkmzp3wb9sis3dn";
  };

  libvfioUserSrc = fetchurl {
    url = "https://gitlab.com/qemu-project/libvfio-user/-/archive/0b28d205572c80b568a1003db2c8f37ca333e4d7/libvfio-user-0b28d205572c80b568a1003db2c8f37ca333e4d7.tar.gz";
    sha256 = "1zhpyw37qihh5p69psg6b60m3qyc6svkx59j2fmmld3gz3a0rxnj";
  };

  slirpSrc = fetchurl {
    url = "https://gitlab.freedesktop.org/slirp/libslirp/-/archive/26be815b86e8d49add8c9a8b320239b9594ff03d/libslirp-26be815b86e8d49add8c9a8b320239b9594ff03d.tar.gz";
    sha256 = "1jdv47cq5aplyj3kz79jpapbfm3wv26inh8szjwrl99z47491ldb";
  };

  arbitraryIntSrc = fetchurl {
    url = "https://crates.io/api/v1/crates/arbitrary-int/1.2.7/download";
    sha256 = "0vgl3n5zzpdn2hxpz6gqk8zg2psk5gwyjzsgpngzd9iqwc1w0ky8";
  };

  bilgeSrc = fetchurl {
    url = "https://crates.io/api/v1/crates/bilge/0.2.0/download";
    sha256 = "0mvvwq9caiq701bmmwyd4q4pc8c69i5zaj3zdk6ya7gqxgc7ww6w";
  };

  bilgeImplSrc = fetchurl {
    url = "https://crates.io/api/v1/crates/bilge-impl/0.2.0/download";
    sha256 = "1n5jml0c1z0np76ms0h5rxx19krblz46h84wycx29b9q4001xcgy";
  };

  eitherSrc = fetchurl {
    url = "https://crates.io/api/v1/crates/either/1.12.0/download";
    sha256 = "12xmhlrv5gfsraimh6xaxcmb0qh6cc7w7ap4sw40ky9wfm095jix";
  };

  itertoolsSrc = fetchurl {
    url = "https://crates.io/api/v1/crates/itertools/0.11.0/download";
    sha256 = "0mzyqcc59azx9g5cg6fs8k529gvh4463smmka6jvzs3cd2jp7hdi";
  };

  libcSrc = fetchurl {
    url = "https://crates.io/api/v1/crates/libc/0.2.162/download";
    sha256 = "1633a00yyx45kzx9r54fndvr8njsjqyr7zl12mzgsmgyczg8glhq";
  };

  procMacroErrorSrc = fetchurl {
    url = "https://crates.io/api/v1/crates/proc-macro-error/1.0.4/download";
    sha256 = "1373bhxaf0pagd8zkyd03kkx6bchzf6g0dkwrwzsnal9z47lj9fs";
  };

  procMacroErrorAttrSrc = fetchurl {
    url = "https://crates.io/api/v1/crates/proc-macro-error-attr/1.0.4/download";
    sha256 = "0sgq6m5jfmasmwwy8x4mjygx5l7kp8s4j60bv25ckv2j1qc41gm1";
  };

  procMacro2Src = fetchurl {
    url = "https://crates.io/api/v1/crates/proc-macro2/1.0.84/download";
    sha256 = "1mj998115z75c0007glkdr8qj57ibv82h7kg6r8hnc914slwd5pc";
  };

  quoteSrc = fetchurl {
    url = "https://crates.io/api/v1/crates/quote/1.0.36/download";
    sha256 = "19xcmh445bg6simirnnd4fvkmp6v2qiwxh5f6rw4a70h76pnm9qg";
  };

  synSrc = fetchurl {
    url = "https://crates.io/api/v1/crates/syn/2.0.66/download";
    sha256 = "1xfgrprsbz8j31kabvfinb4fyhajlk2q7lxa18fb006yl90kyby4";
  };

  unicodeIdentSrc = fetchurl {
    url = "https://crates.io/api/v1/crates/unicode-ident/1.0.12/download";
    sha256 = "0jzf1znfpb2gx8nr8mvmyqs1crnv79l57nxnbiszc7xf7ynbjm1k";
  };

  depsPrefix = "/builddeps/target";

  # Wrapper for Emscripten's file_packager.py.  It must run with a writable
  # HOME because Emscripten writes cache/lock files there.  Using a runtime
  # expansion of TMPDIR keeps the wrapper usable from other derivations and
  # from user shells, instead of hardcoding the engine's build-time TMPDIR.
  filePackagerWrapper = writeShellScript "qemu-wasm-file-packager" ''
    export HOME="''${TMPDIR:-/tmp}"
    exec ${python3}/bin/python ${emscripten}/share/emscripten/tools/file_packager.py "$@"
  '';

  crossMeson = ./emscripten-cross.meson;
in

stdenv.mkDerivation (finalAttrs: {
  pname = "qemu-wasm-engine";
  version = "${qemuWasmVersion}-${qemuWasmRev}";

  srcs = [
    qemuSrc
    xtermPtySrc
  ];
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
    unzip
  ];

  postUnpack = ''
    mv qemu-wasm-${qemuWasmRev} qemu-wasm-src

    mkdir -p xterm-pty
    tar -xzf ${xtermPtySrc} -C xterm-pty

    mkdir -p qemu-wasm-src/subprojects
    tar -xzf ${dtcSrc} -C qemu-wasm-src/subprojects
    mv qemu-wasm-src/subprojects/dtc-${dtcRev} qemu-wasm-src/subprojects/dtc

    tar -xzf ${keycodemapdbSrc} -C qemu-wasm-src/subprojects
    mv qemu-wasm-src/subprojects/keycodemapdb-* qemu-wasm-src/subprojects/keycodemapdb

    tar -xzf ${berkeleySoftfloat3Src} -C qemu-wasm-src/subprojects
    mv qemu-wasm-src/subprojects/berkeley-softfloat-3-* qemu-wasm-src/subprojects/berkeley-softfloat-3

    tar -xzf ${berkeleyTestfloat3Src} -C qemu-wasm-src/subprojects
    mv qemu-wasm-src/subprojects/berkeley-testfloat-3-* qemu-wasm-src/subprojects/berkeley-testfloat-3

    tar -xzf ${libblkioSrc} -C qemu-wasm-src/subprojects
    mv qemu-wasm-src/subprojects/libblkio-* qemu-wasm-src/subprojects/libblkio

    tar -xzf ${libvfioUserSrc} -C qemu-wasm-src/subprojects
    mv qemu-wasm-src/subprojects/libvfio-user-* qemu-wasm-src/subprojects/libvfio-user

    tar -xzf ${slirpSrc} -C qemu-wasm-src/subprojects
    mv qemu-wasm-src/subprojects/libslirp-* qemu-wasm-src/subprojects/slirp

    tar -xzf ${arbitraryIntSrc} -C qemu-wasm-src/subprojects
    tar -xzf ${bilgeSrc} -C qemu-wasm-src/subprojects
    tar -xzf ${bilgeImplSrc} -C qemu-wasm-src/subprojects
    tar -xzf ${eitherSrc} -C qemu-wasm-src/subprojects
    tar -xzf ${itertoolsSrc} -C qemu-wasm-src/subprojects
    tar -xzf ${libcSrc} -C qemu-wasm-src/subprojects
    tar -xzf ${procMacroErrorSrc} -C qemu-wasm-src/subprojects
    tar -xzf ${procMacroErrorAttrSrc} -C qemu-wasm-src/subprojects
    tar -xzf ${procMacro2Src} -C qemu-wasm-src/subprojects
    tar -xzf ${quoteSrc} -C qemu-wasm-src/subprojects
    tar -xzf ${synSrc} -C qemu-wasm-src/subprojects
    tar -xzf ${unicodeIdentSrc} -C qemu-wasm-src/subprojects
  '';

  configurePhase = ''
        runHook preConfigure

        export HOME=$TMPDIR
        export EM_CACHE=$TMPDIR/.emscripten_cache
        mkdir -p $EM_CACHE

        export TARGET=${depsPrefix}
        export CFLAGS="-O3 -pthread -DWASM_BIGINT -Wno-incompatible-function-pointer-types"
        export CXXFLAGS="$CFLAGS"
        export LDFLAGS="-sWASM_BIGINT -sASYNCIFY=1 -L${depsPrefix}/lib"
        export CPATH="${depsPrefix}/include"
        export PKG_CONFIG_PATH="${depsPrefix}/lib/pkgconfig"
        export EM_PKG_CONFIG_PATH="$PKG_CONFIG_PATH"

        mkdir -p ${depsPrefix}/lib/pkgconfig ${depsPrefix}/include

        # zlib
        echo "building zlib for emscripten..."
        tar -xzf ${zlibSrc} -C /build
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
        pushd /build/pixman-${pixmanVersion}
        meson setup _build       --prefix=${depsPrefix}       --cross-file=${crossMeson}       --default-library=static       --buildtype=release       -Dmmx=disabled       -Dsse2=disabled       -Dssse3=disabled       -Dvmx=disabled       -Darm-simd=disabled       -Dneon=disabled       -Da64-neon=disabled       -Dmips-dspr2=disabled       -Drvv=disabled       -Dloongson-mmi=disabled       -Dgnu-inline-asm=disabled       -Dtls=disabled       -Dopenmp=disabled       -Dgtk=disabled       -Dlibpng=disabled       -Dtests=disabled       -Ddemos=disabled
        meson compile -C _build -j$NIX_BUILD_CORES
        meson install -C _build
        rm -f ${depsPrefix}/lib/libpixman-1.so*
        popd

        # glib
        echo "building glib for emscripten..."
        mkdir -p /build/stub
        cat > /build/stub/res_query.c <<'EOF'
    #include <netdb.h>
    int res_query(const char *name, int class, int type, unsigned char *dest, int len)
    {
      h_errno = HOST_NOT_FOUND;
      return -1;
    }
    EOF
        pushd /build/stub
        emcc $CFLAGS -c res_query.c -fPIC -o libresolv.o
        ar rcs libresolv.a libresolv.o
        cp libresolv.a ${depsPrefix}/lib/
        popd

        tar -xJf ${glibSrc} -C /build
        pushd /build/glib-${glibVersion}
        patchShebangs tools
        mkdir -p subprojects
        tar -xjf ${pcre2Src} -C subprojects
        unzip -o ${pcre2Patch} -d subprojects
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
          --enable-tcg \
          --with-coroutine=fiber \
          --enable-virtfs \
          --enable-slirp \
          -Ddefault_library=static \
          --extra-cflags="$EXTRA_CFLAGS" \
          --extra-cxxflags="$EXTRA_CFLAGS" \
          --extra-ldflags="$EXTRA_LDFLAGS"

        popd

        echo "patching build.ninja link target..."
        python3 <<'PYEOF'
    import re
    from pathlib import Path
    ninja = Path('qemu-wasm-src/build/build.ninja')
    txt = ninja.read_text()
    m = re.search(r'^(build qemu-system-x86_64\.js: c_LINKER_RSP .*)$', txt, re.M)
    if not m:
        raise SystemExit('qemu-system-x86_64.js link target not found in build.ninja')
    link_flags = (
        '-sERROR_ON_UNDEFINED_SYMBOLS=1 -static -Wno-unused-command-line-argument '
        '-g -O3 -pthread -sASYNCIFY=1 -sPROXY_TO_PTHREAD=1 -sFORCE_FILESYSTEM '
        '-sALLOW_TABLE_GROWTH -sTOTAL_MEMORY=2300MB -sWASM_BIGINT -sMALLOC=mimalloc '
        '--js-library=/build/xterm-pty/package/emscripten-pty.js -sEXPORT_ES6=1 '
        '-sASYNCIFY_IMPORTS=ffi_call_js '
        '-sEXPORTED_RUNTIME_METHODS=getTempRet0,setTempRet0,addFunction,removeFunction,TTY,FS'
    )
    link_libs = (
        '-Wl,--start-group libqemuutil.a subprojects/dtc/libfdt/libfdt.a '
        'subprojects/slirp/libslirp.a '
        '/builddeps/target/lib/libglib-2.0.a /builddeps/target/lib/libgobject-2.0.a '
        '/builddeps/target/lib/libgthread-2.0.a /builddeps/target/lib/libgmodule-2.0.a '
        '/builddeps/target/lib/libgio-2.0.a /builddeps/target/lib/libpcre2-8.a '
        '/builddeps/target/lib/libffi.a /builddeps/target/lib/libz.a -lm -Wl,--end-group'
    )
    insert = f"\n ARGS = {link_flags}\n LINK_ARGS = {link_libs}"
    pos = m.end()
    txt = txt[:pos] + insert + txt[pos:]
    ninja.write_text(txt)
    PYEOF

        runHook postConfigure
  '';

  buildPhase = ''
    runHook preBuild
    pushd qemu-wasm-src
    ninja -C build block.syms qemu.syms
    python3 - <<'PATCH_EOF'
    import os
    build_dir = os.path.abspath('build')
    for root, _, files in os.walk(build_dir):
        for f in files:
            if f.endswith('.ninja') or f.endswith('.rsp'):
                path = os.path.join(root, f)
                try:
                    with open(path, 'r') as fh:
                        lines = fh.readlines()
                except Exception:
                    continue
                filtered = [l for l in lines if not any(tok in l for tok in ('@block.syms', '@qemu.syms', '@' + os.path.join(build_dir, 'block.syms'), '@' + os.path.join(build_dir, 'qemu.syms')))]
                if len(filtered) != len(lines):
                    with open(path, 'w') as fh:
                        fh.writelines(filtered)
    PATCH_EOF
    echo "--- after patch ---"
    ls -la build/block.syms build/qemu.syms || true
    echo "--- link rsp grep glib ---"
    for f in build/qemu-system-x86_64.js.rsp build/qemu-system-x86_64.rsp; do
      if [ -f "$f" ]; then
        grep -oE 'glib[^ ]*' "$f" | head || true
        echo "rsp exists: $f"
      fi
    done
    emmake make -j$NIX_BUILD_CORES || {
      echo "--- link rsp stats ---"
      wc -c build/qemu-system-x86_64.js.rsp || true
      echo "--- link rsp first 2000 chars ---"
      head -c 2000 build/qemu-system-x86_64.js.rsp || true
      echo
      echo "--- link rsp last 2000 chars ---"
      tail -c 2000 build/qemu-system-x86_64.js.rsp || true
      echo
      echo "--- build.ninja link target ---"
      grep -n -A20 '^build qemu-system-x86_64.js:' build/build.ninja || true
      exit 1
    }
    popd
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall

    mkdir -p $out/libexec/qemu-wasm
    cp qemu-wasm-src/build/qemu-system-x86_64.js $out/libexec/qemu-wasm/qemu-system-x86_64.js
    cp qemu-wasm-src/build/qemu-system-x86_64.wasm $out/libexec/qemu-wasm/
    cp qemu-wasm-src/build/qemu-system-x86_64.worker.js $out/libexec/qemu-wasm/

    mkdir -p $out/share/qemu-wasm/bios
    cp qemu-wasm-src/pc-bios/{bios-256k.bin,vgabios-stdvga.bin,kvmvapic.bin,linuxboot_dma.bin} \
      $out/share/qemu-wasm/bios/ 2>/dev/null || true

    mkdir -p $out/bin
    cp ${filePackagerWrapper} $out/bin/qemu-wasm-file-packager
    chmod +x $out/bin/qemu-wasm-file-packager

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

  passthru = {
    inherit emscripten;
  };

  doCheck = false;

  meta = {
    description = "Browser build of QEMU with the qemu-wasm WebAssembly TCG backend";
    homepage = "https://github.com/ktock/qemu-wasm";
    license = lib.licenses.gpl2Only;
    platforms = [
      "x86_64-linux"
      "aarch64-linux"
    ];
    maintainers = [ ];
  };
})
