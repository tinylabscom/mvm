// Main thread for the WebLinux browser demo.
// It owns the UI and a dedicated Worker that runs the QEMU-Wasm engine.

const statusEl = document.getElementById("status");
const logEl = document.getElementById("log");
const runBtn = document.getElementById("runBtn");
const stopBtn = document.getElementById("stopBtn");
const inputForm = document.getElementById("input-form");
const commandEl = document.getElementById("command");

let worker = null;

function setStatus(text, cls) {
  statusEl.textContent = `Status: ${text}`;
  statusEl.className = cls || "";
}

function logLine(line) {
  logEl.textContent += line + "\n";
  logEl.scrollTop = logEl.scrollHeight;
}

function clearLog() {
  logEl.textContent = "";
}

function stopWorker() {
  if (worker) {
    worker.terminate();
    worker = null;
  }
  setStatus("stopped");
  runBtn.disabled = false;
  stopBtn.disabled = true;
  commandEl.disabled = true;
}

function runWorker() {
  stopWorker();
  clearLog();
  setStatus("starting");
  runBtn.disabled = true;
  stopBtn.disabled = false;

  // The worker is intentionally a classic (non-module) worker so it can use
  // importScripts() to load the Emscripten preload manifest and xterm-pty.
  const workerUrl = new URL("./worker.js", import.meta.url).href;
  worker = new Worker(workerUrl);

  worker.onmessage = (event) => {
    const data = event.data;
    switch (data.type) {
      case "log":
        logLine(data.line);
        break;
      case "status":
        setStatus(data.status);
        break;
      case "ready":
        setStatus("ready", "ready");
        logLine("DEMO-RESULT: READY");
        commandEl.disabled = false;
        commandEl.focus();
        // Allow headless tests to inject a command via ?exec=...
        const exec = new URLSearchParams(location.search).get("exec");
        if (exec) {
          worker.postMessage({ type: "stdin", line: exec });
        }
        break;
      case "error":
        setStatus("error", "error");
        logLine(`ERROR: ${data.error}`);
        runBtn.disabled = false;
        stopBtn.disabled = true;
        commandEl.disabled = true;
        break;
      case "stopped":
        setStatus("stopped");
        runBtn.disabled = false;
        stopBtn.disabled = true;
        break;
      default:
        break;
    }
  };

  worker.onerror = (err) => {
    setStatus("worker error", "error");
    logLine(`WORKER ERROR: ${err.message}`);
    runBtn.disabled = false;
    stopBtn.disabled = true;
  };

  worker.postMessage({ type: "run" });
}

inputForm.addEventListener("submit", (event) => {
  event.preventDefault();
  if (!worker || commandEl.disabled) return;
  const line = commandEl.value;
  commandEl.value = "";
  worker.postMessage({ type: "stdin", line });
});

runBtn.addEventListener("click", runWorker);
stopBtn.addEventListener("click", stopWorker);

// Auto-run when the page is loaded with ?autorun=1, which the headless test
// harness uses to verify the demo without requiring UI interaction.
if (new URLSearchParams(location.search).has("autorun")) {
  runWorker();
}
