const $ = (id) => document.getElementById(id);

const policies = {
  allowed: '{"mode":"closed","rules":[{"host":"api.openai.com","port":443}]}',
  denied: '{"mode":"closed","rules":[]}',
  unbound: '{"mode":"closed","rules":[{"host":"api.openai.com","port":443}]}',
};

const worker = new Worker("./worker.js", { type: "module" });
let msgId = 0;
const pending = new Map();

worker.onmessage = (event) => {
  const { id, ok, payload, error } = event.data;
  const { resolve, reject } = pending.get(id);
  pending.delete(id);
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

await worker.ready;

$("scenario").addEventListener("change", (e) => {
  $("policy").value = policies[e.target.value];
});

$("run").addEventListener("click", async () => {
  const scenario = $("scenario").value;
  try {
    const result = await post("runScenario", { scenario, policyJson: $("policy").value });
    $("module-view").textContent = result.module_view;
    $("destination-view").textContent =
      result.destination_view ?? "(request refused; destination never contacted)";
    if (result.chain_line) {
      $("chain").value = JSON.stringify(result.chain_line);
      showResult(`audit_event: ${result.audit_event} — signed envelope generated`, true);
    } else {
      showResult(`audit_event: ${result.audit_event}`, true);
    }
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

// Publish a deterministic verifying key so the visitor can verify a signed
// envelope produced by the demo.  This is the public counterpart to the
// private key baked into worker.js.
$("pubkey").value =
  "ff57575dc7af8bfc4d0837cc1ce2017b686a88145dc5579a958e3462fe9a908e";
