const $ = (id) => document.getElementById(id);

const policies = {
  allowed: '{"type":"allowlist","rules":[{"host":"api.openai.com","port":443}]}',
  denied: '{"type":"allowlist","rules":[]}',
  unbound: '{"type":"allowlist","rules":[{"host":"api.openai.com","port":443}]}',
};

const worker = new Worker("./worker.js", { type: "module" });
let msgId = 0;
const pending = new Map();

let readyResolve;
const readyPromise = new Promise((resolve) => {
  readyResolve = resolve;
});

function setCapabilityNotice(notice) {
  const el = $("capability-notice");
  if (el) el.textContent = notice;
}

worker.onmessage = (event) => {
  const data = event.data;
  if (data.type === "ready") {
    if (data.verifyingKeyHex) {
      $("pubkey").value = data.verifyingKeyHex;
    }
    setCapabilityNotice(data.capabilityNotice);
    readyResolve();
    return;
  }

  const { id, ok, payload, error } = data;
  const handlers = pending.get(id);
  if (!handlers) return;
  pending.delete(id);
  const { resolve, reject } = handlers;
  if (ok) {
    resolve(payload);
  } else {
    reject(new Error(error));
  }
};

function post(type, payload) {
  const id = ++msgId;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    worker.postMessage({ id, type, ...payload });
  });
}

await readyPromise;

$("scenario").addEventListener("change", (e) => {
  $("policy").value = policies[e.target.value];
});

function appendChainLine(line) {
  const el = $("chain");
  const text = el.value.trim();
  el.value = text ? `${text}\n${JSON.stringify(line)}` : JSON.stringify(line);
}

$("run").addEventListener("click", async () => {
  const scenario = $("scenario").value;
  try {
    const result = await post("runScenario", {
      scenario,
      policyJson: $("policy").value,
      timestamp: new Date().toISOString(),
    });
    if (!result.ok) {
      throw new Error(result.error);
    }
    $("module-view").textContent = result.module_view;
    $("destination-view").textContent =
      result.destination_view ?? "(request refused; destination never contacted)";
    appendChainLine(result.chain_line);
    showResult(`audit_event: ${result.audit_event}`, true);
  } catch (err) {
    showResult(err.message, false);
  }
});

$("run-wasi").addEventListener("click", async () => {
  const fixture = $("scenario").value;
  try {
    const result = await post("runWasi", { fixture, policyJson: $("policy").value });
    if (result.exit === 0) {
      showResult(`WASI fixture "${result.fixture}" observed the expected outcome`, true);
    } else {
      showResult(
        `WASI fixture "${result.fixture}" exited ${result.exit} (outcome did not match)`,
        false
      );
    }
  } catch (err) {
    showResult(err.message, false);
  }
});

$("verify").addEventListener("click", () => doVerify($("chain").value, $("pubkey").value));
$("tamper").addEventListener("click", () => {
  const tampered = $("chain").value.replace("api.openai.com", "evil.example.com");
  doVerify(tampered, $("pubkey").value);
});

async function doVerify(chain, pubkey) {
  try {
    const result = await post("verify", { chain, pubkeyHex: pubkey });
    if (result.ok) {
      showResult(`Chain verifies: ${result.count} entries`, true);
    } else {
      showResult(`Chain rejected: ${result.error}`, false);
    }
  } catch (err) {
    showResult(err.message, false);
  }
}

function showResult(text, ok) {
  const el = $("result");
  el.hidden = false;
  el.className = ok ? "ok" : "bad";
  el.textContent = text;
}
