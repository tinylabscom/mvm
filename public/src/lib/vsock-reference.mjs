import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

// Docs commands run in public/; Node tests also run from the repository root.
// import.meta.url would point into dist/chunks during Astro prerendering.
const repo = resolve(process.cwd(), existsSync("src/content/docs") ? ".." : ".");
const sourceUrl = "https://github.com/tinylabscom/mvm/blob/main/";

// Only wire roots and their payload types belong here, not host-local handlers.
// GuestService coverage is checked separately: defining a DTO does not wire it.
export const families = {
  services: {
    sources: [
      ["crates/mvm-net/src/channel.rs", ["GuestService"]],
    ],
  },
  session: {
    sources: [
      ["crates/mvm-contract/src/policy/security.rs", [
        "SessionHello", "SessionHelloAck", "SessionHelloConfirm",
      ]],
      ["crates/mvm-core/src/net/session.rs", ["SealedFrame"]],
    ],
  },
  guest: {
    schema: "schema/protocol-v0.json",
    sources: [
      ["crates/mvm-agentd/src/vsock/response.rs", ["ToolCheckReply"]],
    ],
  },
  flow: {
    sources: [
      ["crates/mvm-contract/src/protocol/network_flow/frame.rs", ["FrameHeader"]],
      ["crates/mvm-contract/src/protocol/network_flow/opcode.rs", ["Opcode"]],
      ["crates/mvm-contract/src/protocol/network_flow/hello.rs", ["Handshake"]],
      ["crates/mvm-contract/src/protocol/network_flow/tool.rs", [
        "ToolCheckRequest", "ToolDecisionReply",
      ]],
      ["crates/mvm-contract/src/protocol/network_flow/attribution.rs", [
        "ToolInvocationBinding", "ToolInvocationRelease",
      ]],
      ["crates/mvm-core/src/substitution_wire.rs", [
        "HttpFlowHead", "HttpFlowResponseHead",
      ]],
      ["crates/mvm-contract/src/protocol/dns.rs", [
        "DnsRecordType", "DnsQuestion", "DnsRcode",
      ]],
      ["crates/mvm-core/src/icmp_wire.rs", [
        "IcmpEchoRequest", "IcmpEchoReply",
      ]],
    ],
  },
  telemetry: {
    sources: [
      ["crates/mvm-core/src/protocol/telemetry/record.rs", ["Format", "TelemetryRecord"]],
      ["crates/mvm-core/src/protocol/telemetry/mod.rs", [
        "ProducerEpoch", "TraceReference", "FiniteFloat", "Label", "Message",
        "Attributes", "AttributeValue", "Attribute", "SourceKind", "Level",
        "SpanOutcome", "StdioStream", "CoverageState", "GuestLossStage",
        "LossReason", "TailState", "RecordBody",
      ]],
      ["crates/mvm-core/src/protocol/telemetry/bounded.rs", ["Text", "BoundedList"]],
    ],
  },
  display: {
    sources: [
      ["crates/mvm-contract/src/stream/display.rs", ["DisplayMime", "DisplayFrame"]],
    ],
  },
  gpu: {
    sources: [
      ["crates/mvm-contract/src/protocol/gpu.rs", ["GpuError", "GpuRequest", "GpuResponse"]],
    ],
  },
  broker: {
    schema: "schema/broker-services-v0.json",
    sources: [
      ["crates/mvm-contract/src/protocol/host_beacon.rs", ["BeaconReport", "BeaconAck"]],
      ["crates/mvm-contract/src/protocol/host_kv.rs", [
        "KvGetRequest", "KvGetResponse", "KvPutRequest", "KvPutResponse",
        "KvDeleteRequest", "KvDeleteResponse", "KvListRequest", "KvListResponse",
      ]],
      ["crates/mvm-contract/src/protocol/host_tool.rs", ["ToolReleaseResponse"]],
    ],
  },
  builder: {
    sources: [
      ["crates/mvm-builder-guest/src/builder_protocol.rs", [
        "BuilderJob", "JobId", "WorkloadId", "HostVmRequest", "HostVmResponse",
        "JobTimings", "BootTimingsWire",
      ]],
    ],
  },
  builderd: {
    sources: [
      ["crates/mvm-builder-guest/src/builderd_protocol.rs", [
        "OperationId", "BuilderRequest", "BuilderResponse", "FailureCategory",
      ]],
    ],
  },
  legacy_builder: {
    sources: [
      ["crates/mvm-agentd/src/builder_agent.rs", ["HostVmRequest", "HostVmResponse"]],
    ],
  },
  addon: {
    sources: [
      ["crates/mvm-agentd/src/addon_vsock_bridge.rs", ["PeerHeader"]],
    ],
  },
};

export function readRepoFile(path) {
  return readFileSync(resolve(repo, path), "utf8");
}

// This is an excerpt reader, not a Rust parser. Only rustfmt's top-level,
// single-line signatures are supported; unexpected shapes fail the docs build.
export function rustDeclaration(source, name) {
  if (!/^\w+$/.test(name)) throw new Error(`Invalid type name: ${name}`);
  const pattern = new RegExp(
    `^(?:pub(?:\\([^)]*\\))? )?(?:struct|enum|type) ${name}\\b[^\\n]*`, "gm",
  );
  const matches = [...source.matchAll(pattern)];
  if (matches.length !== 1) throw new Error(`Expected exactly one declaration of ${name}`);
  const { index } = matches[0];
  const signature = matches[0][0].trimEnd();
  let end = index + matches[0][0].length;
  if (signature.endsWith("{")) {
    end = source.indexOf("\n}", end);
    if (end === -1) throw new Error(`Missing top-level closing brace for ${name}`);
    end += 2;
  } else if (!signature.endsWith(";")) {
    throw new Error(`Expected a single-line signature for ${name}`);
  }
  const start = source.lastIndexOf("\n\n", index) + 2;
  return {
    line: source.slice(0, index).split("\n").length,
    code: source.slice(start === 1 ? 0 : start, end)
      .split("\n")
      .join("\n")
      .trim(),
  };
}

export function wireDefinitions(family) {
  if (!Object.hasOwn(families, family)) throw new Error(`Unknown wire family: ${family}`);
  const { schema, sources } = families[family];
  const definitions = [];
  if (schema) {
    const text = readRepoFile(schema);
    for (const [name, value] of Object.entries(JSON.parse(text).definitions)) {
      const marker = `    "${name}": {`;
      const offset = text.indexOf(marker);
      if (offset < 0) throw new Error(`Cannot locate schema definition ${name} in ${schema}`);
      definitions.push({
        name, lang: "json", path: schema,
        line: text.slice(0, offset).split("\n").length,
        code: JSON.stringify(value, null, 2),
      });
    }
  }
  for (const [path, names] of sources) {
    const source = readRepoFile(path);
    for (const name of names) {
      definitions.push({ name, lang: "rust", path, ...rustDeclaration(source, name) });
    }
  }
  return definitions.map((item) => ({
    ...item,
    id: `${family}-${item.name}`,
    url: `${sourceUrl}${item.path}#L${item.line}`,
  }));
}

function schemaType(value) {
  if (value === true) return "any JSON value";
  if (value === false) return "never";
  if (value.$ref) return value.$ref.split("/").at(-1);
  if (value.enum) return value.enum.map((entry) => JSON.stringify(entry)).join(" | ");
  if (value.const !== undefined) return JSON.stringify(value.const);
  if (value.anyOf) return value.anyOf.map(schemaType).join(" | ");
  if (value.oneOf) return value.oneOf.map(schemaType).join(" | ");
  const type = Array.isArray(value.type) ? value.type.join(" | ") : value.type;
  if (type === "array") return `array<${schemaType(value.items ?? true)}>`;
  if (type === "object") return "object";
  return [type ?? "object", value.format].filter(Boolean).join(" ");
}

function variantNames(variant) {
  if (variant.enum) return variant.enum.map(String);
  if (variant.properties?.kind?.enum) return variant.properties.kind.enum.map(String);
  if (variant.properties) return Object.keys(variant.properties);
  return [schemaType(variant)];
}

// Compact, navigable field tables; the full definitions remain below them.
export function wireShape(item) {
  if (item.lang !== "json") return { fields: [], variants: [], unknownFields: null };
  const value = JSON.parse(item.code);
  const required = new Set(value.required ?? []);
  return {
    fields: Object.entries(value.properties ?? {}).map(([name, definition]) => ({
      name, required: required.has(name), type: schemaType(definition),
    })),
    variants: [
      ...(value.oneOf ?? []).flatMap((variant) => variantNames(variant).map((name) => ({
        name,
        type: schemaType(variant),
      }))),
      ...(value.enum ? value.enum.map((name) => ({ name: String(name), type: schemaType(value) })) : []),
    ],
    unknownFields: value.additionalProperties !== false,
  };
}

export function expandWireReferences(body) {
  return body.replace(/<VsockTypes family="(\w+)" \/>/g, (_, family) =>
    wireDefinitions(family).map((item) => [
      `<a id="${item.id}"></a>`,
      `### ${item.name}`,
      "",
      `[Source: ${item.path}:${item.line}](${item.url})`,
      "",
      `\`\`\`${item.lang}`,
      item.code,
      "```",
    ].join("\n")).join("\n\n"),
  );
}
