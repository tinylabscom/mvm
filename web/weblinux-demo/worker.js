// Dedicated worker that boots the QEMU-Wasm engine inside the browser.
//
// This is intentionally a classic (non-module) worker so that it can load the
// Emscripten preload manifest (pack.js) and the xterm-pty UMD bundle with
// importScripts(). The engine entry point is then imported dynamically.

const baseUrl = self.location.href.replace(/\/[^/]*$/, "/");
const marker = "QEMU-WASM-SMOKE-READY";

function postLog(line) {
  self.postMessage({ type: "log", line });
  console.log("[demo]", line);
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

self.onmessage = async (event) => {
  if (event.data.type !== "run") {
    return;
  }

  try {
    postStatus("loading support scripts");
    self.importScripts(`${baseUrl}xterm-pty.js`, `${baseUrl}pack.js`);

    postStatus("preload manifest loaded");

    self.Module = self.Module || {};
    self.Module.print = (line) => {
      if (typeof line === "string") {
        postLog(`[print] ${line}`);
      }
    };
    self.Module.printErr = (line) => {
      if (typeof line === "string") {
        postLog(`[err] ${line}`);
      }
    };
    self.Module.onAbort = (what) => {
      postError(`abort: ${what}`);
    };
    self.Module.arguments = [
      "-nographic",
      "-M", "pc",
      "-m", "512M",
      "-cpu", "qemu64",
      "-net", "none",
      "-accel", "tcg,tb-size=500",
      "-L", "pack/",
      "-drive", "if=virtio,format=raw,file=pack/rootfs.bin",
      "-kernel", "pack/kernel.img",
      "-append", "earlyprintk=ttyS0 console=ttyS0 root=/dev/vda loglevel=4 nokaslr quiet"
    ];

    const { master, slave } = self.openpty();
    let ptyBuffer = "";
    let markerSeen = false;

    master.onWrite(([buf, callback]) => {
      ptyBuffer += new TextDecoder().decode(buf);
      let newline;
      while ((newline = ptyBuffer.indexOf("\n")) !== -1) {
        const line = ptyBuffer.slice(0, newline).replace(/\r$/, "");
        ptyBuffer = ptyBuffer.slice(newline + 1);
        if (line) {
          postLog(line);
          if (!markerSeen && line.includes(marker)) {
            markerSeen = true;
            postReady();
          }
        }
      }
      if (ptyBuffer.length > 4096) {
        postLog(ptyBuffer);
        ptyBuffer = "";
      }
      if (callback) {
        callback();
      }
    });

    self.Module.pty = slave;
    // Point Emscripten's pthread bootstrap at the engine main script.
    self.Module["mainScriptUrlOrBlob"] = `${self.location.origin}${new URL("qemu-system-x86_64.js", self.location.href).pathname}`;

    // Patch the TTY poll so it does not block on the xterm-pty slave.
    const interval = setInterval(() => {
      if (self.Module["TTY"]) {
        clearInterval(interval);
        const oldPoll = self.Module["TTY"].stream_ops.poll;
        self.Module["TTY"].stream_ops.poll = (stream, _timeout) => oldPoll.call(stream, 0);
      }
    }, 10);

    postStatus("initializing engine");
    const engineModule = await import(`${baseUrl}qemu-system-x86_64.js`);
    await engineModule.default(self.Module);
    postStatus("engine exited");
  } catch (err) {
    postError(err.message);
  }
};
