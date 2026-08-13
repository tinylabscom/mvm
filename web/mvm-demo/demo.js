const worker = new Worker("./worker.js", { type: "module" });

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
  const line = document.createElement("div");
  line.className = "console-line";
  const span = document.createElement("span");
  span.textContent = text;
  line.appendChild(span);
  consoleEl.insertBefore(line, inputLineEl);
  consoleEl.scrollTop = consoleEl.scrollHeight;
}

function appendPrompt() {
  // Ensure input line is visible and at the bottom.
  inputLineEl.style.display = "flex";
  consoleEl.scrollTop = consoleEl.scrollHeight;
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
  auditChainEl.textContent = chain.map((line) => JSON.stringify(JSON.parse(line), null, 2)).join("\n---\n");
}

function updateCliPreview() {
  const name = $("name").value || "browser-vm";
  const image = $("image").value || "mvm-demo-guest:latest";
  const memory = $("memory").value || "128";
  const cpus = $("cpus").value || "1";
  cliPreviewEl.textContent =
    `mvmctl up ${name} --image ${image} --memory ${memory} --cpus ${cpus}`;
}

["name", "image", "memory", "cpus"].forEach((id) => {
  $(id).addEventListener("input", updateCliPreview);
});

launchBtn.addEventListener("click", async () => {
  if (!ready) {
    appendConsole("Worker not ready yet.");
    return;
  }
  try {
    // Remove all previous output lines but keep the input line.
    Array.from(consoleEl.children)
      .filter((el) => el !== inputLineEl)
      .forEach((el) => el.remove());
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
  if (event.key !== "Enter") return;
  const line = commandEl.value.trim();
  commandEl.value = "";
  if (!line) return;

  // Echo the command with the prompt so it feels like a real terminal.
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
