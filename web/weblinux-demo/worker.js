// Dedicated worker that boots the QEMU-Wasm engine inside the browser.
// Uses OPFS for caching kernel, initramfs, and rootfs images.
//
// This is intentionally a classic (non-module) worker so that it can load the
// Emscripten preload manifest (pack.js) and the xterm-pty UMD bundle with
// importScripts(). The engine entry point is then imported dynamically.

const baseUrl = self.location.href.replace(/\/[^/]*$/, "/");
const marker = "QEMU-WASM-SMOKE-READY";

let inputCallback = null;
let outputBuffer = "";
let opfsStore = null;
let blockDevice = null;

// Initialize OPFS store and block device
async function initOPFS() {
  try {
    // Dynamically import OPFS modules
    const { OPFSStore } = await import("/web/common/opfs-store.ts");
    const { OPFSBlockDevice } = await import("/web/common/opfs-block-file.ts");

    opfsStore = await OPFSStore.getInstance();
    blockDevice = new OPFSBlockDevice(opfsStore);

    console.log("[worker] OPFS initialized successfully");
    return true;
  } catch (e) {
    console.error("[worker] Failed to initialize OPFS:", e);
    return false;
  }
}

function flushOutputBuffer() {
  let newline;
  while ((newline = outputBuffer.indexOf("\n")) !== -1) {
    const line = outputBuffer.slice(0, newline).replace(/\r$/, "");
    outputBuffer = outputBuffer.slice(newline + 1);
    if (line) {
      self.postMessage({ type: "log", line });
      console.log("[demo]", line);
    }
  }
  if (outputBuffer.length > 4096) {
    self.postMessage({ type: "log", line: outputBuffer });
    console.log("[demo]", outputBuffer);
    outputBuffer = "";
  }
}

function postStatus(status) {
  self.postMessage({ type: "status", status });
}

function postReady() {
  self.postMessage({ type: "ready" });
  console.log("DEMO-RESULT: READY");
}

function postError(error) {
  self.postMessage({ type: "error", error });
  console.error("DEMO-RESULT: ERROR", error);
}

async function loadCompressedWasm() {
  if (typeof DecompressionStream !== "function") {
    throw new Error("this browser does not support gzip decompression streams");
  }

  const response = await fetch(`${baseUrl}qemu-system-x86_64.wasm.gz`);
  if (!response.ok || !response.body) {
    throw new Error(
      `failed to load compressed QEMU-WASM module (${response.status})`,
    );
  }

  const decompressed = response.body.pipeThrough(
    new DecompressionStream("gzip"),
  );
  return new Response(decompressed).arrayBuffer();
}

async function loadPreloadData() {
  const manifestResponse = await fetch(`${baseUrl}pack.data.parts.json`);
  if (!manifestResponse.ok) {
    throw new Error(
      `failed to load preload manifest (${manifestResponse.status})`,
    );
  }

  const manifest = await manifestResponse.json();
  if (
    !Number.isSafeInteger(manifest.size) ||
    manifest.size <= 0 ||
    !Array.isArray(manifest.parts) ||
    manifest.parts.length === 0 ||
    manifest.parts.some(
      (part) =>
        typeof part !== "string" || !/^pack\.data\.part-\d{3}$/.test(part),
    )
  ) {
    throw new Error("invalid preload manifest");
  }

  const data = new Uint8Array(manifest.size);
  let offset = 0;
  for (const part of manifest.parts) {
    const response = await fetch(`${baseUrl}${part}`);
    if (!response.ok) {
      throw new Error(`failed to load preload part ${part} (${response.status})`);
    }
    const bytes = new Uint8Array(await response.arrayBuffer());
    if (offset + bytes.byteLength > data.byteLength) {
      throw new Error(`preload part ${part} exceeds declared size`);
    }
    data.set(bytes, offset);
    offset += bytes.byteLength;
  }

  if (offset !== data.byteLength) {
    throw new Error(
      `preload parts total ${offset} bytes, expected ${data.byteLength}`,
    );
  }
  return data.buffer;
}

// Minimal xterm.js-shaped object that lets xterm-pty's Master route output to
// the UI and accept injected input from the main thread.
function createFakeTerminal() {
  let markerSeen = false;
  // Reuse a single streaming decoder so a UTF-8 character split across
  // xterm-pty chunks is not replaced with U+FFFD.
  const decoder = new TextDecoder();
  return {
    write: (data, callback) => {
      let text =
        typeof data === "string"
          ? data
          : decoder.decode(data, { stream: true });
      outputBuffer += text;
      if (!markerSeen && outputBuffer.includes(marker)) {
        markerSeen = true;
        postReady();
      }
      flushOutputBuffer();
      if (callback) callback();
    },
    onData: (cb) => {
      inputCallback = cb;
      return { dispose: () => {} };
    },
    onBinary: (_cb) => {
      return { dispose: () => {} };
    },
    onResize: (_cb) => {
      return { dispose: () => {} };
    },
  };
}

self.onmessage = async (event) => {
  if (event.data.type === "stdin") {
    if (inputCallback && typeof event.data.data === "string") {
      // The main thread owns input encoding: submitted commands include their
      // carriage return, while terminal controls arrive as their raw byte.
      inputCallback(event.data.data);
    }
    return;
  }

  if (event.data.type === "init-opfs") {
    const success = await initOPFS();
    self.postMessage({ type: "opfs-ready", success });
    return;
  }

  if (event.data.type !== "run") {
    return;
  }

  const allowHost = event.data.allowHost
    ? String(event.data.allowHost).trim()
    : "";
  console.log("[worker] allowHost received:", allowHost);

  try {
    postStatus("loading support scripts");
    const preloadData = await loadPreloadData();
    self.Module = self.Module || {};
    self.Module.getPreloadedPackage = (name, size) => {
      if (name !== "pack.data" || size !== preloadData.byteLength) {
        throw new Error(
          `unexpected preload request ${name} (${size} bytes)`,
        );
      }
      return preloadData;
    };
    self.importScripts(`${baseUrl}xterm-pty.js`, `${baseUrl}pack.js`);

    postStatus("preload manifest loaded");

    self.Module = self.Module || {};
    self.Module.print = (line) => {
      if (typeof line === "string") {
        outputBuffer += `[print] ${line}\n`;
        flushOutputBuffer();
      }
    };
    self.Module.printErr = (line) => {
      if (typeof line === "string") {
        outputBuffer += `[err] ${line}\n`;
        flushOutputBuffer();
      }
    };
    self.Module.onAbort = (what) => {
      postError(`abort: ${what}`);
    };

    let kernelAppend =
      "earlyprintk=ttyS0 console=ttyS0 root=/dev/vda rw loglevel=4 nokaslr quiet";
    if (allowHost) {
      kernelAppend += ` mvm.allow_host=${allowHost}`;
    }

    self.Module.arguments = [
      "-nographic",
      "-M",
      "pc",
      "-m",
      "512M",
      "-cpu",
      "qemu64",
      // NOTE: QEMU's user-mode LAN is wired up for completeness, but the
      // Emscripten build routes host-bound sockets through the browser's
      // WebSocket layer.  That path currently crashes the worker with a
      // divide-by-zero when SLIRP tries to forward ICMP/UDP/TCP to the host.
      // The smoke rootfs resolves mvm.allow_host to 127.0.0.1 so that ping/
      // fetch against the demo name stays on loopback and avoids SLIRP.
      "-netdev",
      "user,id=net0",
      "-device",
      "virtio-net-pci,netdev=net0,romfile=",
      "-accel",
      "tcg,tb-size=500",
      "-L",
      "pack/",
      "-drive",
      "if=virtio,format=raw,file=pack/rootfs.bin",
      "-kernel",
      "pack/kernel.img",
      "-append",
      kernelAppend,
    ];

    const { master, slave } = self.openpty();
    const fakeTerm = createFakeTerminal();
    master.activate(fakeTerm);

    self.Module.pty = slave;
    self.Module["mainScriptUrlOrBlob"] =
      `${self.location.origin}${new URL("qemu-system-x86_64.js", self.location.href).pathname}`;

    // Patch the TTY poll to avoid blocking on the pty.  The original poll
    // expects (stream, timeout) and is called with stream_ops as |this|.
    const interval = setInterval(() => {
      if (self.Module["TTY"]) {
        clearInterval(interval);
        const streamOps = self.Module["TTY"].stream_ops;
        const oldPoll = streamOps.poll;
        streamOps.poll = (stream, _timeout) =>
          oldPoll.call(streamOps, stream, 0);
      }
    }, 10);

    postStatus("loading engine");
    self.Module.wasmBinary = await loadCompressedWasm();

    postStatus("initializing engine");
    const engineModule = await import(`${baseUrl}qemu-system-x86_64.js`);
    await engineModule.default(self.Module);
    postStatus("engine exited");
  } catch (err) {
    postError(err.message);
  }
};
