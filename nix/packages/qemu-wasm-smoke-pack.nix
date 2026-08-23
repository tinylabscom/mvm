# Browser-ready asset bundle for the QEMU-Wasm smoke image.
#
# This derivation takes the engine (JS/WASM/worker + pc-bios) and the smoke
# guest image (kernel + rootfs) and produces a self-contained directory that
# can be served and booted in a browser.  All runtime assets are preloaded
# into Emscripten's MEMFS using the upstream `file_packager.py` tool.

{ lib
, stdenv
, fetchurl
, qemu-wasm-engine
, qemu-wasm-smoke-image
}:

let
  # QEMU-Wasm looks for firmware and disk images under `-L pack/`.
  # The file packager mounts the preloaded tree at `/pack` in MEMFS.
  packName = "pack";

  # Bundled copy of xterm-pty so the smoke page is self-contained.
  xtermPtyJs = fetchurl {
    url = "https://unpkg.com/xterm-pty@0.10.1/index.js";
    sha256 = "d242a568a3b1ef487ede00e10108edbc4b9fd93de12db0ef694c9b81e691c649";
  };
in

stdenv.mkDerivation {
  pname = "qemu-wasm-smoke-pack";
  version = qemu-wasm-smoke-image.version;

  srcs = [ ];
  sourceRoot = ".";

  dontUnpack = true;
  dontConfigure = true;
  dontBuild = true;

  nativeBuildInputs = [ qemu-wasm-engine ];

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

    # Bundled xterm-pty for the pseudo-terminal slave used by QEMU-Wasm.
    cp ${xtermPtyJs} $out/xterm-pty.js

    # Preload the whole pack tree into a single .data/.js pair.
    # file_packager.py writes its output next to the current working directory,
    # so run it from $out where ${packName}/ already contains the assets.
    # The engine's wrapper sets a writable HOME for Emscripten's cache files.
    cd $out
    qemu-wasm-file-packager \
      ${packName}.data \
      --preload ${packName} \
      --js-output=${packName}.js

    # Minimal HTML runner.  It loads the preload manifest as a classic script
    # so it shares the global Module object with the engine, wires up an
    # xterm-pty slave for serial I/O, and starts QEMU-Wasm with the same
    # arguments used by the upstream sample.
    cat > $out/index.html <<'EOF'
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>QEMU-Wasm smoke test</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <!-- xterm-pty provides the pty slave that QEMU-Wasm uses for serial I/O. -->
  <script src="xterm-pty.js"></script>
</head>
<body>
  <pre id="log"></pre>
  <script>
    window.onerror = function(msg, url, line, col, err) {
      console.error('SMOKE-RESULT: WINDOW-ERROR', msg, url, line, col, err);
    };
    window.addEventListener('unhandledrejection', function(e) {
      console.error('SMOKE-RESULT: UNHANDLED-REJECTION', e.reason);
    });

    window.Module = window.Module || {};
    window.Module.print = function(line) {
      if (typeof line === 'string') console.log('[print]', line);
    };
    window.Module.printErr = function(line) {
      if (typeof line === 'string') console.error('[printErr]', line);
    };
    window.Module.onAbort = function(what) {
      console.error('SMOKE-RESULT: ABORT', what);
    };
    window.Module.onRuntimeInitialized = function() {
      console.log('SMOKE: runtime initialized');
    };
    window.Module.arguments = [
      '-nographic',
      '-M', 'pc',
      '-m', '512M',
      '-cpu', 'qemu64',
      '-netdev', 'user,id=net0',
      '-device', 'virtio-net-pci,netdev=net0,romfile=',
      '-accel', 'tcg,tb-size=500',
      '-L', 'pack/',
      '-drive', 'if=virtio,format=raw,file=pack/rootfs.bin',
      '-kernel', 'pack/kernel.img',
      '-append', 'earlyprintk=ttyS0 console=ttyS0 root=/dev/vda rw loglevel=4 nokaslr quiet'
    ];
  </script>
  <script src="pack.js"></script>
  <script>console.log('SMOKE-RESULT: PACK-LOADED');</script>
  <script type="module">
    const logEl = document.getElementById('log');
    const marker = 'QEMU-WASM-SMOKE-READY';
    let markerSeen = false;

    function logLine(line) {
      logEl.textContent += line + '\n';
      console.log('[pty]', line);
      if (!markerSeen && line.includes(marker)) {
        markerSeen = true;
        console.log('SMOKE-RESULT: READY');
      }
    }

    const { master, slave } = window.openpty();

    let ptyBuffer = "";
    master.onWrite(([buf, callback]) => {
      // Buffer partial lines so we emit one console log per line instead of
      // one per character.  This keeps headless Chromium responsive during
      // the kernel's verbose early boot.
      ptyBuffer += new TextDecoder().decode(buf);
      let newline;
      while ((newline = ptyBuffer.indexOf('\n')) !== -1) {
        const line = ptyBuffer.slice(0, newline).replace(/\r$/, "");
        ptyBuffer = ptyBuffer.slice(newline + 1);
        if (line) logLine(line);
      }
      if (ptyBuffer.length > 4096) {
        logLine(ptyBuffer);
        ptyBuffer = "";
      }
      if (callback) callback();
    });

    window.Module.pty = slave;
    window.Module['mainScriptUrlOrBlob'] = location.origin + '/qemu-system-x86_64.js';

    // Patch the TTY poll to avoid blocking on the pty.
    const interval = setInterval(() => {
      if (window.Module['TTY']) {
        clearInterval(interval);
        const oldPoll = window.Module['TTY'].stream_ops.poll;
        window.Module['TTY'].stream_ops.poll = (stream, timeout) => oldPoll.call(stream, 0);
      }
    }, 10);

    // Safety cap: if the marker never appears, report failure.
    setTimeout(() => {
      if (!markerSeen) {
        console.log('SMOKE-RESULT: TIMEOUT');
      }
    }, 600000);

    const initEmscriptenModule = (await import('./qemu-system-x86_64.js')).default;
    await initEmscriptenModule(window.Module);
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
