import assert from "node:assert/strict";
import test from "node:test";
import {
  families,
  readRepoFile,
  rustDeclaration,
  wireDefinitions,
  wireShape,
  expandWireReferences,
} from "../src/lib/vsock-reference.mjs";

const pagePath = "public/src/content/docs/reference/vsock-messages.mdx";

test("Rust excerpts preserve wire attributes and fields, not implementations", () => {
  const source = `use serde::Serialize;

/// A wire message.
#[derive(Serialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case"
)]
pub enum Message {
    /// Payload.
    Data { bytes: Vec<u8> },
    Done,
}

impl Message {
    fn local_only() {}
}
`;
  const item = rustDeclaration(source, "Message");
  assert.equal(item.line, 9);
  assert.match(item.code, /tag = "kind"/);
  assert.match(item.code, /Data \{ bytes: Vec<u8> \}/);
  assert.match(item.code, /\/\/\/ Payload\./);
  assert.doesNotMatch(item.code, /local_only/);
  assert.equal(item.code.trimEnd().endsWith("}"), true);
});

test("Rust excerpts handle private enums, newtypes and aliases", () => {
  for (const [name, source] of [
    ["Format", '#[serde(rename = "v1")]\nenum Format {\n    V1,\n}\n'],
    ["Id", "pub struct Id(pub Uuid);\n"],
    ["Text", "pub struct Text<const N: usize>(String);\n"],
    ["Labels", "pub type Labels = Vec<String>;\n"],
  ]) {
    assert.match(rustDeclaration(source, name).code, new RegExp(`\\b${name}\\b`));
  }
  assert.throws(() => rustDeclaration("pub struct Other;\n", "Missing"), /Missing/);
  assert.throws(
    () => rustDeclaration("pub struct Id;\npub struct Id;\n", "Id"),
    /exactly one/,
  );
  assert.throws(() => rustDeclaration("pub struct Broken {\n", "Broken"), /closing/);
  assert.throws(
    () => rustDeclaration("pub struct Multiline\n{\n}\n", "Multiline"),
    /single-line signature/,
  );
});

test("every schema definition and nested field is published without rewriting it", () => {
  for (const family of ["guest", "broker"]) {
    const schema = JSON.parse(readRepoFile(families[family].schema));
    const published = wireDefinitions(family).filter((item) => item.lang === "json");
    assert.deepEqual(published.map((item) => item.name), Object.keys(schema.definitions));
    for (const item of published) {
      assert.deepEqual(JSON.parse(item.code), schema.definitions[item.name]);
    }
    const visit = (value) => {
      if (!value || typeof value !== "object") return;
      if (value.$ref) {
        assert.match(value.$ref, /^#\/definitions\//);
        assert.ok(schema.definitions[value.$ref.slice("#/definitions/".length)]);
      }
      Object.values(value).forEach(visit);
    };
    visit(schema);
  }
});

test("schema summaries include every field, variant and nullable shape", () => {
  for (const family of ["guest", "broker"]) {
    for (const item of wireDefinitions(family).filter((entry) => entry.lang === "json")) {
      const schema = JSON.parse(readRepoFile(families[family].schema)).definitions[item.name];
      const summary = wireShape(item);
      for (const [name, definition] of Object.entries(schema.properties ?? {})) {
        const field = summary.fields.find((entry) => entry.name === name);
        assert.ok(field, `${item.id}: missing ${name}`);
        assert.equal(field.required, (schema.required ?? []).includes(name));
        if (definition.anyOf?.some((value) => value.type === "null")) {
          assert.match(field.type, /null/);
        }
      }
      for (const variant of schema.oneOf ?? []) {
        const names = variant.enum ?? variant.properties?.kind?.enum ?? Object.keys(variant.properties ?? {});
        for (const name of names) {
          assert.ok(
            summary.variants.some((entry) => entry.name === name),
            `${item.id}: missing variant ${name}`,
          );
        }
      }
      assert.equal(summary.unknownFields, schema.additionalProperties !== false);
    }
  }
  const nullable = wireShape(wireDefinitions("broker").find((item) => item.name === "ServiceCall"));
  assert.equal(nullable.fields.find((field) => field.name === "capability").required, false);
  assert.match(nullable.fields.find((field) => field.name === "capability").type, /CapabilityInvocation \| null/);
});

test("every catalogue family is rendered once in HTML and expanded for markdown readers", () => {
  const page = readRepoFile(pagePath);
  const expanded = expandWireReferences(page);
  const ids = new Set();
  for (const family of Object.keys(families)) {
    assert.equal(page.split(`<VsockTypes family="${family}" />`).length - 1, 1, family);
    const definitions = wireDefinitions(family);
    assert.ok(definitions.length, family);
    for (const item of definitions) {
      assert.ok(!ids.has(item.id), `duplicate anchor ${item.id}`);
      ids.add(item.id);
      assert.ok(expanded.includes(item.code), `${family}/${item.name} missing from markdown`);
      assert.match(item.url, /^https:\/\/github\.com\/tinylabscom\/mvm\/blob\/main\/.+#L\d+$/);
    }
  }
  assert.doesNotMatch(expanded, /<VsockTypes/);
  assert.throws(() => wireDefinitions("not-a-protocol"), /Unknown/);
  assert.match(readRepoFile("public/src/lib/docs-index.ts"), /expandWireReferences/);
});

test("new serialized types in dedicated wire modules need a catalogue disposition", () => {
  const published = Object.keys(families).flatMap(wireDefinitions);
  const schemaNames = new Set(published.filter((item) => item.lang === "json").map((item) => item.name));
  const paths = new Set(published.filter((item) => item.lang === "rust").map((item) => item.path));
  // This shared policy module has many non-wire policy/configuration types.
  // Its reachable control payloads are already covered by the generated schema.
  paths.delete("crates/mvm-contract/src/policy/security.rs");
  const exclusions = new Set([
    "ToolCheckDenial", "ToolOrigin", "LoopbackBinding",
    "WireRequest", "WireResponse", "ResolveWireRequest", "ResolveWireResponse",
  ]);
  const page = readRepoFile(pagePath);
  for (const name of exclusions) assert.ok(page.includes(`\`${name}\``), name);
  for (const path of paths) {
    const source = readRepoFile(path);
    for (const [, name] of source.matchAll(/^(?:pub(?:\([^)]*\))? )?(?:struct|enum|type) (\w+)\b/gm)) {
      const declaration = rustDeclaration(source, name);
      if (!/\bSerialize\b|\bDeserialize\b|#\[serde/.test(declaration.code)) continue;
      assert.ok(
        published.some((item) => item.path === path && item.name === name)
          || schemaNames.has(name) || exclusions.has(name),
        `${path}: classify new serialized type ${name}`,
      );
    }
  }
});

test("FlowMux documents the actual payload types for every typed frame family", () => {
  const flowTypes = wireDefinitions("flow").map((item) => item.name);
  for (const name of [
    "FrameHeader", "Opcode", "Handshake", "ToolCheckRequest", "ToolDecisionReply",
    "ToolInvocationBinding", "HttpFlowHead", "HttpFlowResponseHead",
    "DnsRecordType", "DnsQuestion", "DnsRcode", "IcmpEchoRequest", "IcmpEchoReply",
  ]) {
    assert.ok(flowTypes.includes(name), name);
  }
  const page = readRepoFile(pagePath);
  const opcode = rustDeclaration(
    readRepoFile("crates/mvm-contract/src/protocol/network_flow/opcode.rs"),
    "Opcode",
  );
  for (const [, name] of opcode.code.matchAll(/^    (\w+) = /gm)) {
    assert.ok(page.includes(`| \`${name}\``), `No exact payload disposition for ${name}`);
  }
  assert.match(page, /`UdpRecv` \| The same 19-byte peer-address prefix/);
  assert.match(page, /guest emits an empty payload/);
});

test("the transport table accounts for every registered service, including raw channels", () => {
  const page = readRepoFile(pagePath);
  const service = rustDeclaration(readRepoFile("crates/mvm-net/src/channel.rs"), "GuestService");
  const names = [...service.code.matchAll(/^    ([A-Z]\w*)(?:,| \{)/gm)].map((m) => m[1]);
  assert.ok(names.length >= 10);
  for (const name of names) assert.ok(page.includes(`\`${name}\``), name);

  const opcode = rustDeclaration(
    readRepoFile("crates/mvm-contract/src/protocol/network_flow/opcode.rs"),
    "Opcode",
  );
  for (const [, name] of opcode.code.matchAll(/^    (\w+) = /gm)) {
    assert.ok(page.includes(`\`${name}\``), `FlowMux disposition missing for ${name}`);
  }
  assert.match(readRepoFile("public/src/sidebar.ts"), /slug: "reference\/vsock-messages"/);
  for (const path of [
    "public/src/content/docs/reference/guest-agent.md",
    "public/src/content/docs/guides/networking.md",
    "public/src/content/docs/architecture/control-surfaces.mdx",
  ]) {
    assert.ok(readRepoFile(path).includes("/reference/vsock-messages/"), path);
  }
});

test("control schema roots still name every Rust request and response", () => {
  const schema = JSON.parse(readRepoFile("schema/protocol-v0.json"));
  for (const [name, file] of [
    ["GuestRequest", "request.rs"],
    ["GuestResponse", "response.rs"],
  ]) {
    const declaration = rustDeclaration(
      readRepoFile(`crates/mvm-agentd/src/vsock/${file}`),
      name,
    );
    const rustNames = [...declaration.code.matchAll(/^    (\w+)(?:,| \{|\()/gm)]
      .map((match) => match[1]);
    const schemaNames = schema.definitions[name].oneOf.flatMap(
      (variant) => Object.keys(variant.properties ?? {}).length
        ? Object.keys(variant.properties)
        : variant.enum,
    );
    assert.deepEqual(rustNames, schemaNames, "Run cargo xtask check-stubs for full schema drift");
  }
});

test("documented control bounds cannot regress to double JSON envelope accounting", () => {
  const source = readRepoFile("crates/mvm-agentd/src/vsock/mod.rs");
  for (const declaration of [
    "pub const PROTOCOL_VERSION: u32 = 2;",
    "pub const MIN_SUPPORTED_PROTOCOL_VERSION: u32 = 2;",
    "pub const MAX_FRAME_SIZE: usize = 256 * 1024;",
    "const JSON_BYTE_ARRAY_WORST_CASE: usize = 4;",
    "const SEALED_ENVELOPE_EXPANSION: usize = JSON_BYTE_ARRAY_WORST_CASE;",
    "const SEALED_ENVELOPE_OVERHEAD: usize = 8 * 1024;",
    "pub const MAX_DATA_CHUNK_SIZE: usize = (MAX_FRAME_SIZE - SEALED_ENVELOPE_OVERHEAD) / SEALED_ENVELOPE_EXPANSION;",
    "pub const MAX_SEALED_FRAME_SIZE: usize = MAX_FRAME_SIZE + SEALED_ENVELOPE_OVERHEAD;",
  ]) {
    assert.ok(source.replace(/\s+/g, " ").includes(declaration), declaration);
  }
  for (const path of [pagePath, "public/src/content/docs/reference/guest-agent.md"]) {
    const text = readRepoFile(path);
    assert.ok(text.includes("62 KiB"), `${path}: content chunk bound`);
    assert.ok(text.includes("264 KiB"), `${path}: sealed-frame bound`);
    assert.ok(
      !/15\.5 KiB|Each request receives exactly one response|encoded twice/.test(text),
      `${path}: obsolete framing claim`,
    );
  }
});

test("non-control framing bounds retain the documented values", () => {
  const contracts = {
    "crates/mvm-contract/src/protocol/network_flow/limits.rs": [
      "PROTOCOL_VERSION: u8 = 1", "HEADER_LEN: usize = 20",
      "MAX_PAYLOAD_LEN: usize = 64 * 1024", "LENGTH_PREFIX_LEN: usize = 4",
      "MAX_FRAME_LEN: usize = HEADER_LEN + MAX_PAYLOAD_LEN",
      "MAX_WIRE_LEN: usize = LENGTH_PREFIX_LEN + MAX_FRAME_LEN",
      "MAX_UDP_DATAGRAM_LEN: usize = 65_507", "UDP_ADDR_PREFIX_LEN: usize = 1 + 16 + 2",
      "INITIAL_STREAM_CREDIT: u32 = 4 * MAX_PAYLOAD_LEN as u32",
      "MAX_STREAM_CREDIT: u32 = 64 * MAX_PAYLOAD_LEN as u32",
    ],
    "crates/mvm-core/src/protocol/telemetry/mod.rs": [
      "TELEMETRY_PORT: u32 = 5254", "MAX_RECORD_BYTES: usize = 32 * 1024",
      "MAX_RECORD_DEPTH: usize = 8", "MAX_ATTRIBUTES: usize = 16",
      "MAX_LINKS: usize = 8", "MAX_STDIO_BYTES: usize = 4096",
      "Label = Text<128>", "Message = Text<2048>",
    ],
    "crates/mvm-contract/src/stream/display.rs": [
      "DISPLAY_FRAME_PORT: u32 = 5255", "MAX_DISPLAY_FRAME_BYTES: usize = 2 * 1024 * 1024",
      "MAX_STEP_ID_BYTES: usize = 256", "DISPLAY_FRAME_VERSION: u8 = 1",
      "HEADER_BYTES: usize = 16",
    ],
    "crates/mvm-contract/src/protocol/gpu.rs": [
      "GPU_RPC_PORT: u32 = 5256", "MAX_MESSAGE_LEN: u64 = 64 * 1024 * 1024",
      "MAX_KERNEL_PARAMS: usize = 256", "MAX_PARAM_LEN: u64 = 16 * 1024 * 1024",
    ],
  };
  for (const [path, expected] of Object.entries(contracts)) {
    const source = readRepoFile(path).replace(/\s+/g, " ");
    for (const declaration of expected) {
      assert.ok(source.includes(`${declaration};`), `${path}: review docs for changed ${declaration}`);
    }
  }
});

test("documented JSON examples use real guest tags and fields", () => {
  const page = readRepoFile(pagePath);
  const schema = JSON.parse(readRepoFile("schema/protocol-v0.json")).definitions;
  const example = (name) => {
    const section = page.split(`{/* example:${name} */}`)[1] ?? "";
    const match = section.match(/^\s*```json\n([\s\S]*?)\n```/);
    assert.ok(match, name);
    return JSON.parse(match[1]);
  };
  assert.ok(!page.includes("<!--"), "MDX comments must use JSX syntax");
  assert.equal(example("ping"), "Ping");
  assert.ok(schema.GuestRequest.oneOf.some((variant) => variant.enum?.includes(example("ping"))));
  const hello = example("hello").ProtocolHello;
  const shape = schema.GuestRequest.oneOf.find((v) => v.properties?.ProtocolHello)
    .properties.ProtocolHello;
  assert.deepEqual(Object.keys(hello).sort(), shape.required.toSorted());
  assert.equal(hello.host_protocol_version, 2);
  assert.equal(hello.min_supported_version, 2);
  assert.equal(shape.additionalProperties, false);
});
