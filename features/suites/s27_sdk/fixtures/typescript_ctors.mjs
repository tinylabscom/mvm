// Tier A constructor fixture (TypeScript).
//
// Twin of `python_ctors.py`: the same constructor calls with the same
// inputs, emitting the same normalized JSON document so the scenario can
// compare both languages against one golden file.
//
// Imports the built artifact rather than the sources, for the reason the
// live-transport fixture does: only the emitted ESM shows packaging
// faults, and a source-level runner cannot see them.
import * as mvm from "../../../../crates/mvm-sdk/sdks/typescript/dist/index.js";

// Sort keys so the document is order-insensitive across languages.
function norm(value) {
  if (Array.isArray(value)) return value.map(norm);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((k) => [k, norm(value[k])]),
    );
  }
  return value;
}

function refusal(fn, ...args) {
  try {
    fn(...args);
  } catch (err) {
    // Python reports the exception class; the generated TypeScript throws
    // a plain Error, so the class name is normalized to Python's spelling
    // and the message — the part that would actually drift — is compared
    // verbatim.
    return { error: "ValueError", message: err.message };
  }
  return { error: null, message: null };
}

const built = {
  host_port: norm(mvm.host_port("example.com", 443)),
  host_port_low: norm(mvm.host_port("example.com", 1)),
  host_port_high: norm(mvm.host_port("example.com", 65535)),
  egress: norm(mvm.egress([mvm.host_port("a.example", 443), mvm.host_port("b.example", 80)])),
  egress_empty: norm(mvm.egress([])),
  dns_none: norm(mvm.dns_none()),
  dns_system: norm(mvm.dns_system()),
  dns_resolver_default_port: norm(mvm.dns_resolver("1.1.1.1")),
  dns_resolver_explicit_port: norm(mvm.dns_resolver("1.1.1.1", 5353)),
  no_deps: norm(mvm.no_deps()),
  python_deps_default_tool: norm(mvm.python_deps("uv.lock")),
  python_deps_alias: norm(mvm.python_deps("r.txt", "pip-tools")),
  python_deps_canonical: norm(mvm.python_deps("r.txt", "pip_tools")),
  node_deps_default_tool: norm(mvm.node_deps("pnpm-lock.yaml")),
  node_deps_npm: norm(mvm.node_deps("package-lock.json", "npm")),
};

const refusals = {
  host_port_empty_host: refusal(mvm.host_port, "", 443),
  host_port_port_zero: refusal(mvm.host_port, "example.com", 0),
  host_port_port_too_high: refusal(mvm.host_port, "example.com", 65536),
  dns_resolver_empty_host: refusal(mvm.dns_resolver, ""),
  python_deps_empty_lockfile: refusal(mvm.python_deps, "", "uv"),
  python_deps_unknown_tool: refusal(mvm.python_deps, "uv.lock", "poetry"),
  node_deps_empty_lockfile: refusal(mvm.node_deps, ""),
  node_deps_unknown_tool: refusal(mvm.node_deps, "x", "bun"),
};

process.stdout.write(JSON.stringify(norm({ built, refusals }), null, 2) + "\n");
