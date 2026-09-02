// Main thread for the WebLinux browser demo.
// It owns the UI and a dedicated Worker that runs the QEMU-Wasm engine.

import { terminalControlBytes } from "./terminal-input.mjs";

const statusEl = document.getElementById("status");
const logEl = document.getElementById("log");
const runBtn = document.getElementById("runBtn");
const stopBtn = document.getElementById("stopBtn");
const inputForm = document.getElementById("input-form");
const commandEl = document.getElementById("command");
const allowHostEl = document.getElementById("allowHost");

let worker = null;

const commandHistory = [];
let historyIndex = -1; // -1 means not navigating history
let savedInput = "";

const ANSI_COLORS = [
  "#000000", "#cd3131", "#0dbc79", "#e5e510",
  "#2472c8", "#bc3fbc", "#11a8cd", "#e5e5e5"
];
const ANSI_BRIGHT_COLORS = [
  "#666666", "#f14c4c", "#23d18b", "#f5f543",
  "#3b8eea", "#d670d6", "#29b8db", "#ffffff"
];

function ansiColor256(n) {
  if (n < 8) return ANSI_COLORS[n];
  if (n < 16) return ANSI_BRIGHT_COLORS[n - 8];
  if (n >= 232) {
    const gray = ((n - 232) * 10 + 8) / 255;
    const c = Math.round(gray * 255);
    return `rgb(${c},${c},${c})`;
  }
  const i = n - 16;
  const r = Math.floor(i / 36);
  const g = Math.floor((i % 36) / 6);
  const b = i % 6;
  const toChannel = (v) => v === 0 ? 0 : Math.round((v * 40 + 55) / 255 * 255);
  return `rgb(${toChannel(r)},${toChannel(g)},${toChannel(b)})`;
}

function escapeHtml(text) {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function ansiToHtml(text) {
  const re = /\x1b\[([0-9;]*)m/g;
  let out = "";
  let last = 0;
  let match;
  const state = { bold: false, fg: null, bg: null };

  function styleString() {
    const parts = [];
    if (state.bold) parts.push("font-weight:bold");
    if (state.fg) parts.push(`color:${state.fg}`);
    if (state.bg) parts.push(`background-color:${state.bg}`);
    return parts.join(";");
  }

  function emitStyle() {
    const s = styleString();
    return s ? `<span style="${s}">` : "";
  }

  let openSpan = false;

  function closeSpan() {
    if (openSpan) {
      out += "</span>";
      openSpan = false;
    }
  }

  while ((match = re.exec(text)) !== null) {
    out += escapeHtml(text.slice(last, match.index));

    const rawCodes = match[1].split(";").filter((c) => c !== "");
    const codes = rawCodes.length === 0 ? [0] : rawCodes.map(Number);

    let i = 0;
    while (i < codes.length) {
      const c = codes[i];
      if (c === 0) {
        state.bold = false;
        state.fg = null;
        state.bg = null;
        i++;
      } else if (c === 1) {
        state.bold = true;
        i++;
      } else if (c === 22) {
        state.bold = false;
        i++;
      } else if (c === 39) {
        state.fg = null;
        i++;
      } else if (c === 49) {
        state.bg = null;
        i++;
      } else if (c >= 30 && c <= 37) {
        state.fg = ANSI_COLORS[c - 30];
        i++;
      } else if (c >= 90 && c <= 97) {
        state.fg = ANSI_BRIGHT_COLORS[c - 90];
        i++;
      } else if (c >= 40 && c <= 47) {
        state.bg = ANSI_COLORS[c - 40];
        i++;
      } else if (c >= 100 && c <= 107) {
        state.bg = ANSI_BRIGHT_COLORS[c - 100];
        i++;
      } else if (c === 38 && codes[i + 1] === 5) {
        state.fg = ansiColor256(codes[i + 2]);
        i += 3;
      } else if (c === 38 && codes[i + 1] === 2) {
        state.fg = `rgb(${codes[i + 2]},${codes[i + 3]},${codes[i + 4]})`;
        i += 5;
      } else if (c === 48 && codes[i + 1] === 5) {
        state.bg = ansiColor256(codes[i + 2]);
        i += 3;
      } else if (c === 48 && codes[i + 1] === 2) {
        state.bg = `rgb(${codes[i + 2]},${codes[i + 3]},${codes[i + 4]})`;
        i += 5;
      } else {
        i++;
      }
    }

    closeSpan();
    const tag = emitStyle();
    if (tag) {
      out += tag;
      openSpan = true;
    }

    last = re.lastIndex;
  }

  out += escapeHtml(text.slice(last));
  closeSpan();
  return out;
}

function setStatus(text, cls) {
  statusEl.textContent = `Status: ${text}`;
  statusEl.className = cls || "";
}

function logLine(line) {
  logEl.innerHTML += ansiToHtml(line) + "\n";
  logEl.scrollTop = logEl.scrollHeight;
  // Emit a copy to the console so headless test harnesses can observe demo output.
  console.log("[demo] " + line.replace(/\n+$/, ""));
}

function clearLog() {
  logEl.innerHTML = "";
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
          worker.postMessage({ type: "stdin", data: exec + "\r" });
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
        commandEl.disabled = true;
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
    commandEl.disabled = true;
  };

  const allowHostValue = allowHostEl?.value || "";
  console.log("[demo] sending allowHost:", allowHostValue);
  worker.postMessage({ type: "run", allowHost: allowHostValue });
}

runBtn.addEventListener("click", runWorker);
stopBtn.addEventListener("click", stopWorker);

inputForm.addEventListener("submit", (event) => {
  event.preventDefault();
  if (!worker || commandEl.disabled) return;
  const line = commandEl.value;
  if (line) {
    // Avoid storing duplicate consecutive entries.
    if (commandHistory.length === 0 || commandHistory[commandHistory.length - 1] !== line) {
      commandHistory.push(line);
    }
  }
  commandEl.value = "";
  historyIndex = -1;
  savedInput = "";
  worker.postMessage({ type: "stdin", data: line + "\r" });
});

commandEl.addEventListener("keydown", (event) => {
  const controlBytes = terminalControlBytes(event);
  if (controlBytes && worker && !commandEl.disabled) {
    event.preventDefault();
    worker.postMessage({ type: "stdin", data: controlBytes });
  } else if (event.key === "ArrowUp") {
    event.preventDefault();
    if (commandHistory.length === 0) return;
    if (historyIndex === -1) {
      savedInput = commandEl.value;
      historyIndex = commandHistory.length - 1;
    } else if (historyIndex > 0) {
      historyIndex--;
    }
    commandEl.value = commandHistory[historyIndex];
  } else if (event.key === "ArrowDown") {
    event.preventDefault();
    if (historyIndex === -1) return;
    historyIndex++;
    if (historyIndex >= commandHistory.length) {
      historyIndex = -1;
      commandEl.value = savedInput;
    } else {
      commandEl.value = commandHistory[historyIndex];
    }
  }
});

// Auto-run when the page is loaded with ?autorun=1, which the headless test
// harness uses to verify the demo without requiring UI interaction.
if (new URLSearchParams(location.search).has("autorun")) {
  runWorker();
}

const urlAllowHost = new URLSearchParams(location.search).get("allowHost");
if (urlAllowHost && allowHostEl) {
  allowHostEl.value = urlAllowHost;
}
