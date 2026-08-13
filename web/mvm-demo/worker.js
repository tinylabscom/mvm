import init, {
  run_scenario,
  decide_egress,
  host_is_bound,
  substitute_placeholder,
  demo_capability_notice,
  demo_verifying_key_hex,
  verify,
} from "./pkg/mvm_demo_web.js";

// Demo fixture: one placeholder secret bound to api.openai.com.
const FIXTURE_SECRET = {
  placeholder: "mvm-secret-deadbeef",
  value: "sk-real-openai-key",
  allowed_hosts: ["api.openai.com"],
};

await init();
self.postMessage({
  type: "ready",
  capabilityNotice: demo_capability_notice(),
  verifyingKeyHex: demo_verifying_key_hex(),
});

self.onmessage = async (event) => {
  const { id, type } = event.data;
  try {
    let payload;
    switch (type) {
      case "runScenario":
        payload = JSON.parse(
          run_scenario(event.data.scenario, event.data.policyJson, event.data.timestamp)
        );
        break;
      case "runWasi":
        payload = await runWasi(event.data.fixture, event.data.policyJson);
        break;
      case "verify":
        payload = JSON.parse(verify(event.data.chain, event.data.pubkeyHex));
        break;
      default:
        throw new Error(`unknown worker message type: ${type}`);
    }
    self.postMessage({ id, ok: true, payload });
  } catch (err) {
    self.postMessage({ id, ok: false, error: err.message });
  }
};

async function runWasi(fixture, policyJson) {
  const response = await fetch(`./fixtures/${fixture}.opt.wasm`);
  if (!response.ok) {
    throw new Error(`failed to load fixture ${fixture}: ${response.status}`);
  }
  const bytes = await response.arrayBuffer();

  const memory = new WebAssembly.Memory({ initial: 3 });
  let respPtr = 0;
  let respCap = 0;

  function readString(ptr, len) {
    const view = new Uint8Array(memory.buffer, ptr, len);
    return new TextDecoder().decode(view);
  }

  function writeString(ptr, cap, text) {
    const encoded = new TextEncoder().encode(text);
    if (encoded.length > cap) {
      return -1;
    }
    const view = new Uint8Array(memory.buffer, ptr, cap);
    view.set(encoded);
    return encoded.length;
  }

  function parseUrlHostPort(url) {
    const withoutScheme = url.split("//").pop();
    const hostPort = withoutScheme.split("/")[0];
    const [host, port] = hostPort.includes(":")
      ? hostPort.split(":")
      : [hostPort, "443"];
    return { host, port: parseInt(port, 10) };
  }

  function mvmEgress(reqPtr, reqLen, outPtr, outCap) {
    respPtr = outPtr;
    respCap = outCap;
    const requestJson = readString(reqPtr, reqLen);
    const request = JSON.parse(requestJson);

    const decision = JSON.parse(decide_egress(policyJson, request.url));
    if (!decision.ok || !decision.allowed) {
      const resp = JSON.stringify({ result: "refused", message: "policy denied" });
      return writeString(outPtr, outCap, resp);
    }

    const { host } = parseUrlHostPort(request.url);
    const bound = JSON.parse(
      host_is_bound(JSON.stringify(FIXTURE_SECRET.allowed_hosts), host)
    );
    if (!bound.ok || !bound.bound) {
      const resp = JSON.stringify({ result: "refused", message: "secret not bound to host" });
      return writeString(outPtr, outCap, resp);
    }

    const headers = request.headers.map(([name, value]) => {
      const sub = JSON.parse(substitute_placeholder(value, FIXTURE_SECRET.value));
      return [name, sub.ok ? sub.text : value];
    });

    const resp = JSON.stringify({
      result: "ok",
      status: 200,
      headers,
      body_b64: "",
    });
    return writeString(outPtr, outCap, resp);
  }

  const module = await WebAssembly.instantiate(bytes, {
    wasi_snapshot_preview1: {
      proc_exit: (code) => {
        throw new ExitError(code);
      },
    },
    mvm: { egress: mvmEgress },
  });

  try {
    module.instance.exports._start();
    return { fixture, exit: 0, note: "module completed without exiting" };
  } catch (err) {
    if (err instanceof ExitError) {
      return { fixture, exit: err.code };
    }
    throw err;
  }
}

class ExitError extends Error {
  constructor(code) {
    super(`proc_exit(${code})`);
    this.code = code;
  }
}
