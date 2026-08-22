# Browser-ready asset bundle for the QEMU-Wasm smoke image.
#
# This derivation takes the engine (JS/WASM/worker + pc-bios) and the smoke
# guest image (kernel + rootfs) and produces a self-contained directory that
# can be served and booted in a browser.  All runtime assets are preloaded
# into Emscripten's MEMFS using the upstream `file_packager.py` tool.

{ lib
, stdenv
, python3
, qemu-wasm-engine
, qemu-wasm-smoke-image
}:

let
  # QEMU-Wasm looks for firmware and disk images under `-L pack/`.
  # The file packager mounts the preloaded tree at `/pack` in MEMFS.
  packName = "pack";
in

stdenv.mkDerivation {
  pname = "qemu-wasm-smoke-pack";
  version = qemu-wasm-smoke-image.version;

  srcs = [ ];
  sourceRoot = ".";

  dontUnpack = true;
  dontConfigure = true;
  dontBuild = true;

  nativeBuildInputs = [ qemu-wasm-engine python3 ];

  installPhase = ''
    runHook preInstall

    mkdir -p $out/${packName}

    # Engine runtime files.
    cp ${qemu-wasm-engine}/libexec/qemu-wasm/qemu-system-x86_64.js $out/
    cp ${qemu-wasm-engine}/libexec/qemu-wasm/qemu-system-x86_64.wasm $out/
    cp ${qemu-wasm-engine}/libexec/qemu-wasm/qemu-system-x86_64.worker.js $out/

    # PC-BIOS firmware that QEMU loads relative to the -L directory.
    cp ${qemu-wasm-engine}/share/qemu-wasm/bios/* $out/${packName}/

    # Smoke guest image.
    cp ${qemu-wasm-smoke-image}/kernel.img $out/${packName}/
    cp ${qemu-wasm-smoke-image}/rootfs.bin $out/${packName}/

    # Preload the whole pack tree into a single .data/.js pair.
    # file_packager.py writes its output next to the current working directory,
    # so run it from $out where ${packName}/ already contains the assets.
    # Emscripten's tooling needs a writable HOME for its lock/cache files.
    export HOME=$TMPDIR
    cd $out
    python3 ${qemu-wasm-engine.emscripten}/share/emscripten/tools/file_packager.py \
      ${packName}.data \
      --preload ${packName} \
      --js-output=${packName}.js

    # Minimal HTML runner.  It loads the engine, the preload manifest, and
    # starts QEMU-Wasm with the same arguments used by the upstream sample.
    cat > $out/index.html <<'EOF'
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>QEMU-Wasm smoke test</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
</head>
<body>
  <pre id="log"></pre>
  <script type="module">
    const logEl = document.getElementById('log');
    const marker = 'QEMU-WASM-SMOKE-READY';
    let markerSeen = false;

    function logLine(line) {
      logEl.textContent += line + '\n';
      if (!markerSeen && line.includes(marker)) {
        markerSeen = true;
        console.log('SMOKE-RESULT: READY');
      }
    }

    window.Module = {
      print: logLine,
      printErr: logLine,
      arguments: [
        '-nographic',
        '-m', '512M',
        '-accel', 'tcg,tb-size=500',
        '-L', 'pack',
        '-drive', 'if=virtio,format=raw,file=pack/rootfs.bin',
        '-kernel', 'pack/kernel.img',
        '-append', 'console=ttyS0 root=/dev/vda'
      ],
      onAbort: (what) => console.error('SMOKE-RESULT: ABORT', what),
    };

    // The file packager manifest loads first; it populates MEMFS before the
    // engine starts.
    import('./pack.js').then(() => {
      console.log('SMOKE-RESULT: PACK-LOADED');
      return import('./qemu-system-x86_64.js');
    }).catch(err => {
      console.error('SMOKE-RESULT: ERROR', err);
    });

    // Safety cap: if the marker never appears, report failure.
    setTimeout(() => {
      if (!markerSeen) {
        console.log('SMOKE-RESULT: TIMEOUT');
      }
    }, 120000);
  </script>
</body>
</html>
EOF

    runHook postInstall
  '';

  meta = {
    description = "Browser-ready asset bundle for the QEMU-Wasm smoke image";
    platforms = [ "x86_64-linux" "aarch64-linux" ];
  };
}
