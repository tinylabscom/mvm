const worker = new Worker("./worker.js", { type: "module" });

// Embed mode (?embed=1): the config pane is hidden, so launch immediately
// with its default values once the worker reports ready.
const EMBED = new URLSearchParams(location.search).has("embed");

const $ = (id) => document.getElementById(id);
const consoleEl = $("console");
const inputLineEl = $("input-line");
const commandEl = $("command");
const launchBtn = $("launch");
const stopBtn = $("stop");
const capabilityNoticeEl = $("capability-notice");
const cliPreviewEl = $("cli-preview");
const auditChainEl = $("audit-chain");

let ready = false;
let vmRunning = false;
let pending = new Map();
let idCounter = 1;

// Command history for the emulated terminal.
const history = [];
let historyIndex = -1;
let savedInput = "";

const BUILTINS = [
  "help", "clear", "exit", "pwd", "cd", "ls", "cat", "echo", "fetch", "ping",
  "whoami", "hostname", "date", "uname", "env", "printenv", "id", "ps",
  "top", "df", "free", "uptime", "history", "which", "man",
];

function rpc(type, payload = {}) {
  return new Promise((resolve, reject) => {
    const id = idCounter++;
    pending.set(id, { resolve, reject });
    worker.postMessage({ id, type, ...payload });
  });
}

worker.onmessage = (event) => {
  const data = event.data;
  if (data.type === "ready") {
    ready = true;
    capabilityNoticeEl.textContent = data.capabilityNotice || "";
    if (EMBED && !vmRunning) {
      launchBtn.click();
    }
    return;
  }
  if (data.type === "console") {
    appendConsole(data.chunk);
    return;
  }
  if (data.type === "audit") {
    renderAuditChain(data.auditChain);
    return;
  }
  const { id, ok, payload, error } = data;
  const handlers = pending.get(id);
  if (!handlers) return;
  pending.delete(id);
  if (ok) handlers.resolve(payload);
  else handlers.reject(new Error(error));
};

function appendConsole(text) {
  // A form-feed from the guest is a clear-screen request.
  if (text === "\x0c") {
    clearConsole();
    return;
  }
  const line = document.createElement("div");
  line.className = "console-line";
  const span = document.createElement("span");
  span.textContent = text;
  line.appendChild(span);
  consoleEl.insertBefore(line, inputLineEl);
  scrollToBottom();
}

function clearConsole() {
  Array.from(consoleEl.children)
    .filter((el) => el !== inputLineEl)
    .forEach((el) => el.remove());
}

function scrollToBottom() {
  consoleEl.scrollTop = consoleEl.scrollHeight;
}

function appendPrompt() {
  inputLineEl.style.display = "flex";
  scrollToBottom();
  commandEl.focus();
}

function setInput(enabled) {
  commandEl.disabled = !enabled;
  if (enabled) {
    appendPrompt();
  } else {
    inputLineEl.style.display = "none";
  }
}

function renderAuditChain(chain) {
  if (!chain || chain.length === 0) {
    auditChainEl.textContent = "—";
    return;
  }
  auditChainEl.textContent = chain
    .map((line) => JSON.stringify(JSON.parse(line), null, 2))
    .join("\n---\n");
}

function updateCliPreview() {
  const name = $("name").value || "browser-vm";
  const image = $("image").value || "mvm-demo-guest:latest";
  const memory = $("memory").value || "128";
  const cpus = $("cpus").value || "1";
  cliPreviewEl.textContent =
    `mvmctl up ${name} --image ${image} --memory ${memory} --cpus ${cpus}`;
}

function focusInput() {
  if (!commandEl.disabled) {
    commandEl.focus();
  }
}

function echoCommand(line) {
  const echo = document.createElement("div");
  echo.className = "console-line";
  const prompt = document.createElement("span");
  prompt.className = "prompt";
  prompt.textContent = "root@mvm:~#";
  const cmd = document.createElement("span");
  cmd.textContent = ` ${line}`;
  echo.appendChild(prompt);
  echo.appendChild(cmd);
  consoleEl.insertBefore(echo, inputLineEl);
  scrollToBottom();
}

function commonPrefix(strings) {
  if (strings.length === 0) return "";
  let prefix = strings[0];
  for (const s of strings.slice(1)) {
    while (!s.startsWith(prefix)) {
        prefix = prefix.slice(0, -1);
        if (prefix === "") return "";
      }
  }
  return prefix;
}

function completeCommand() {
  const value = commandEl.value;
  const matches = BUILTINS.filter((c) => c.startsWith(value));
  if (matches.length === 1) {
    commandEl.value = `${matches[0]} `;
  } else if (matches.length > 1) {
    commandEl.value = commonPrefix(matches);
    echoCommand(matches.join("  "));
  }
}

["name", "image", "memory", "cpus"].forEach((id) => {
  $(id).addEventListener("input", updateCliPreview);
});

// Click anywhere on the console to focus the prompt.
consoleEl.addEventListener("click", (e) => {
  if (e.target === consoleEl || e.target.closest(".console-line")) {
    focusInput();
  }
});

launchBtn.addEventListener("click", async () => {
  if (!ready) {
    appendConsole("Worker not ready yet.");
    return;
  }
  try {
    clearConsole();
    launchBtn.disabled = true;

    const policy = $("policy").value;
    JSON.parse(policy); // validate

    const config = {
      name: $("name").value || "browser-vm",
      image: $("image").value || "mvm-demo-guest:latest",
      memory_mib: parseInt($("memory").value, 10) || 128,
      cpus: parseInt($("cpus").value, 10) || 1,
      network_policy: JSON.parse(policy),
      authority: $("authority").value.trim(),
    };

    appendConsole(`Launching ${config.name}...`);
    const result = await rpc("launch", { configJson: JSON.stringify(config) });
    vmRunning = true;
    stopBtn.disabled = false;
    setInput(true);
    appendConsole(`MicroVM ${result.vmId} is ${result.status}.`);
    renderAuditChain(result.auditChain);
  } catch (err) {
    appendConsole(`Launch failed: ${err.message}`);
    launchBtn.disabled = false;
  }
});

stopBtn.addEventListener("click", async () => {
  try {
    const result = await rpc("stop");
    vmRunning = false;
    launchBtn.disabled = false;
    stopBtn.disabled = true;
    setInput(false);
    appendConsole("MicroVM stopped.");
    renderAuditChain(result.auditChain);
  } catch (err) {
    appendConsole(`Stop failed: ${err.message}`);
  }
});

commandEl.addEventListener("keydown", async (event) => {
  if (event.key === "Tab") {
    event.preventDefault();
    completeCommand();
    return;
  }

  if (event.key === "ArrowUp") {
    event.preventDefault();
    if (historyIndex === -1) {
      savedInput = commandEl.value;
    }
    if (historyIndex < history.length - 1) {
      historyIndex += 1;
      commandEl.value = history[history.length - 1 - historyIndex];
    }
    return;
  }

  if (event.key === "ArrowDown") {
    event.preventDefault();
    if (historyIndex > 0) {
      historyIndex -= 1;
      commandEl.value = history[history.length - 1 - historyIndex];
    } else if (historyIndex === 0) {
      historyIndex = -1;
      commandEl.value = savedInput;
    }
    return;
  }

  if (event.ctrlKey && event.key === "c") {
    event.preventDefault();
    commandEl.value = "";
    echoCommand("^C");
    return;
  }

  if (event.ctrlKey && event.key === "l") {
    event.preventDefault();
    clearConsole();
    return;
  }

  if (event.key !== "Enter") return;

  const line = commandEl.value.trim();
  commandEl.value = "";
  historyIndex = -1;
  savedInput = "";
  if (!line) return;

  history.push(line);
  echoCommand(line);

  // Handle purely local terminal commands without round-tripping to the guest.
  if (line === "clear") {
    clearConsole();
    return;
  }

  try {
    await rpc("stdin", { line });
  } catch (err) {
    appendConsole(`Error: ${err.message}`);
  }
});

window.addEventListener("beforeunload", () => {
  if (vmRunning) {
    worker.postMessage({ id: 0, type: "stop" });
  }
});

updateCliPreview();
