import init, { run_scenario, verify } from "./pkg/mvm_demo_web.js";

const $ = (id) => document.getElementById(id);

const policies = {
  allowed: '{"mode":"closed","rules":[{"host":"api.openai.com","port":443}]}',
  denied: '{"mode":"closed","rules":[]}',
  unbound: '{"mode":"closed","rules":[{"host":"api.openai.com","port":443}]}',
};

const fixtureChain = `{"tenant":"demo","plan":"plan-allowed","event":"secret.substituted","labels":{"destination":"api.openai.com"},"canonical":"{\"tenant\":\"demo\",\"plan\":\"plan-allowed\",\"event\":\"secret.substituted\",\"labels\":{\"destination\":\"api.openai.com\"}}","prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","signature":"placeholder-signature-for-demo"}`;
const fixtureKey = "0000000000000000000000000000000000000000000000000000000000000000";

await init();

$("scenario").addEventListener("change", (e) => {
  $("policy").value = policies[e.target.value];
});

$("run").addEventListener("click", () => {
  const result = JSON.parse(run_scenario($("scenario").value, $("policy").value));
  if (!result.ok) {
    showResult(result.error, false);
    return;
  }
  $("module-view").textContent = result.module_view;
  $("destination-view").textContent =
    result.destination_view ?? "(request refused; destination never contacted)";
  showResult(`audit_event: ${result.audit_event}`, true);
});

$("chain").value = fixtureChain;
$("pubkey").value = fixtureKey;

$("verify").addEventListener("click", () => doVerify($("chain").value, $("pubkey").value));
$("tamper").addEventListener("click", () => {
  const tampered = $("chain").value.replace("api.openai.com", "evil.example.com");
  doVerify(tampered, $("pubkey").value);
});

function doVerify(chain, pubkey) {
  const result = JSON.parse(verify(chain, pubkey));
  if (result.ok) {
    showResult(`Chain verifies: ${result.count} entries`, true);
  } else {
    showResult(`Chain rejected: ${result.error}`, false);
  }
}

function showResult(text, ok) {
  const el = $("result");
  el.hidden = false;
  el.className = ok ? "ok" : "bad";
  el.textContent = text;
}
