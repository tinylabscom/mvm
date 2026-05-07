#!/usr/bin/env node
// mvmforge function-entrypoint wrapper (Node 22+). ADR-0009 / plan-0003.
//
// Baked into rootfs by mkNodeFunctionService (mvm side, future). Reads
// `[args, kwargs]` from stdin in the IR-declared format, dispatches the
// configured module:function, writes the encoded return on stdout.
//
// Single-shot invariant
// ---------------------
// Assumes exactly one invocation per process — the substrate agent
// spawns a fresh wrapper for every call (mvm ADR-007 §6 hygiene). The
// wrapper takes shortcuts that depend on this:
//   - `chdir(working_dir)` — never undone.
//   - dynamic `import(moduleUrl)` populates the loader cache for the
//     life of the process; user-module side effects persist.
//   - the stdin reader is a one-shot promise.
//
// Adapting this wrapper for warm-process reuse requires scrubbing all
// of the above between calls. Set `MVMFORGE_WRAPPER_ALLOW_REENTRY=1`
// to opt out of the second-call safety check below; otherwise the
// wrapper exits on a second invocation attempt.
//
// ADR-0009 invariants enforced:
//   - Two-mode (prod | dev) gated by /etc/mvm/wrapper.json's `mode`.
//   - prod: sanitized error envelope on stderr; no stack trace, no file
//     paths, no payload bytes in logs. Dev mode echoes the stack.
//   - decoder hardening: reject non-finite numbers, max nesting 64.
//   - serialization format is closed (json | msgpack). Code-execution
//     surfaces forbidden by ADR-0009 — never reachable from this file.
//     See scripts/wrapper_forbidden_check.py for the enforced list.
//     mvmforge-allow: this is the comment that documents the gate.

import { readFileSync } from "node:fs";
import { chdir } from "node:process";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { randomBytes } from "node:crypto";

const WRAPPER_CONFIG_PATH = "/etc/mvm/wrapper.json";
const MAX_NESTING_DEPTH = 64;
let mainInvoked = false;
// Defense-in-depth stdin cap. Substrate enforces a hard upstream cap
// (mvm M1); this is the wrapper's belt-and-suspenders.
const DEFAULT_MAX_INPUT_BYTES = 16 * 1024 * 1024; // 16 MiB

function loadConfig() {
  const text = readFileSync(WRAPPER_CONFIG_PATH, "utf8");
  const cfg = JSON.parse(text);
  if (typeof cfg !== "object" || cfg === null) {
    throw new Error("wrapper config must be a JSON object");
  }
  for (const key of ["module", "function", "format"]) {
    if (typeof cfg[key] !== "string") {
      throw new Error(`wrapper config missing/invalid: ${key}`);
    }
  }
  if (cfg.format !== "json" && cfg.format !== "msgpack") {
    throw new Error(`unsupported format: ${cfg.format}`);
  }
  cfg.mode ??= "prod";
  cfg.working_dir ??= "/app";
  cfg.max_input_bytes ??= DEFAULT_MAX_INPUT_BYTES;
  if (!Number.isInteger(cfg.max_input_bytes) || cfg.max_input_bytes <= 0) {
    throw new Error("max_input_bytes must be a positive integer");
  }
  // Optional schemas (plan-0009 v2). Validated at call time when ajv
  // is importable in the rootfs.
  if (cfg.args_schema !== undefined && (typeof cfg.args_schema !== "object" || cfg.args_schema === null)) {
    throw new Error("args_schema must be a JSON object");
  }
  if (cfg.return_schema !== undefined && (typeof cfg.return_schema !== "object" || cfg.return_schema === null)) {
    throw new Error("return_schema must be a JSON object");
  }
  return cfg;
}

async function loadAjv() {
  try {
    const Ajv = (await import("ajv")).default;
    return new Ajv({ allErrors: false, strict: false });
  } catch {
    return null;
  }
}

async function validateAgainstSchema(value, schema, where) {
  const ajv = await loadAjv();
  if (ajv === null) {
    // No-op: rootfs didn't bake ajv in; host build-time check still ran.
    return;
  }
  const validate = ajv.compile(schema);
  if (!validate(value)) {
    const detail = (validate.errors ?? []).map((e) => e.message).join("; ");
    throw new Error(`${where} validation failed: ${detail}`);
  }
}

function checkDepth(value, current = 0) {
  if (current > MAX_NESTING_DEPTH) {
    throw new Error(`payload nesting depth exceeds ${MAX_NESTING_DEPTH}`);
  }
  if (Array.isArray(value)) {
    for (const v of value) checkDepth(v, current + 1);
  } else if (value !== null && typeof value === "object") {
    for (const v of Object.values(value)) checkDepth(v, current + 1);
  }
}

function checkNumbers(value) {
  if (typeof value === "number" && !Number.isFinite(value)) {
    throw new Error("non-finite numbers are forbidden in payload");
  }
  if (Array.isArray(value)) {
    for (const v of value) checkNumbers(v);
  } else if (value !== null && typeof value === "object") {
    for (const v of Object.values(value)) checkNumbers(v);
  }
}

function decodeJson(buffer) {
  // Use a reviver to detect duplicate keys and reject them. Native
  // JSON.parse silently overwrites duplicates; we treat them as a hard
  // error per ADR-0009 decoder hardening.
  const seenSets = new WeakMap();
  const text = buffer.toString("utf8");
  const proxy = JSON.parse(text, function reviver(key, value) {
    if (typeof this === "object" && this !== null && key !== "") {
      let set = seenSets.get(this);
      if (set === undefined) {
        set = new Set();
        seenSets.set(this, set);
      }
      if (set.has(key)) {
        throw new Error(`duplicate key in JSON object: ${JSON.stringify(key)}`);
      }
      set.add(key);
    }
    return value;
  });
  return proxy;
}

async function loadMsgpack() {
  const mod = await import("@msgpack/msgpack");
  return mod;
}

async function decodeMsgpack(buffer) {
  const { decode } = await loadMsgpack();
  return decode(buffer);
}

function encodeJson(value) {
  return Buffer.from(JSON.stringify(value), "utf8");
}

async function encodeMsgpack(value) {
  const { encode } = await loadMsgpack();
  return Buffer.from(encode(value));
}

async function decodePayload(format, buffer) {
  const value = format === "json" ? decodeJson(buffer) : await decodeMsgpack(buffer);
  checkDepth(value);
  checkNumbers(value);
  return value;
}

async function encodeResult(format, value) {
  return format === "json" ? encodeJson(value) : await encodeMsgpack(value);
}

async function readStdin(maxBytes) {
  return new Promise((resolveFn, rejectFn) => {
    const chunks = [];
    let total = 0;
    let aborted = false;
    process.stdin.on("data", (c) => {
      if (aborted) return;
      total += c.length;
      if (total > maxBytes) {
        aborted = true;
        rejectFn(new Error(`input payload exceeded ${maxBytes}-byte cap before EOF`));
        return;
      }
      chunks.push(c);
    });
    process.stdin.on("end", () => {
      if (!aborted) resolveFn(Buffer.concat(chunks));
    });
    process.stdin.on("error", rejectFn);
  });
}

const ENVELOPE_MARKER = "MVMFORGE_ENVELOPE: ";

function emitEnvelope(mode, err) {
  const errorId = randomBytes(8).toString("hex");
  if (mode === "dev" && err instanceof Error && err.stack) {
    process.stderr.write(err.stack + "\n");
  }
  const envelope = {
    kind: err && err.name ? err.name : "Error",
    error_id: errorId,
    message: mode === "dev" ? String(err && err.message) : scrub(String(err && err.message)),
  };
  // Marker prefix: host SDK scans stderr for this token to recover the
  // envelope unambiguously regardless of other log output before/after.
  process.stderr.write(ENVELOPE_MARKER + JSON.stringify(envelope) + "\n");
}

function scrub(message) {
  if (!message) return "Error";
  const redacted = message
    .split(/\s+/)
    .filter((tok) => !tok.includes("/"))
    .join(" ");
  return redacted.slice(0, 200) || "Error";
}

async function main() {
  if (mainInvoked && process.env.MVMFORGE_WRAPPER_ALLOW_REENTRY !== "1") {
    throw new Error(
      "wrapper main() called twice without MVMFORGE_WRAPPER_ALLOW_REENTRY=1; " +
        "this wrapper assumes per-call respawn (mvm ADR-007 §6)",
    );
  }
  mainInvoked = true;
  const cfg = loadConfig();
  try {
    const data = await readStdin(cfg.max_input_bytes);
    const decoded = await decodePayload(cfg.format, data);
    if (
      !Array.isArray(decoded) ||
      decoded.length !== 2 ||
      !Array.isArray(decoded[0]) ||
      typeof decoded[1] !== "object" ||
      decoded[1] === null ||
      Array.isArray(decoded[1])
    ) {
      throw new Error("payload must be a 2-element array: [args, kwargs]");
    }
    const [args, kwargs] = decoded;
    chdir(cfg.working_dir);
    const modulePath = resolve(cfg.working_dir, cfg.module);
    const moduleUrl = pathToFileURL(modulePath).href;
    const mod = await import(moduleUrl);
    const fn = mod[cfg.function];
    if (typeof fn !== "function") {
      throw new Error(`exported function not found: ${cfg.function}`);
    }

    // Plan-0009 v2: schema-bound validation. TS/JS has no native
    // kwargs, so we validate the positional args array directly.
    // Schemas are typically `{type:"array", items:[...]}` for typed
    // function signatures. Best-effort if ajv isn't installed.
    if (cfg.args_schema !== undefined) {
      await validateAgainstSchema(args, cfg.args_schema, "args_schema");
    }

    const hasKwargs = Object.keys(kwargs).length > 0;
    const result = hasKwargs ? await fn(...args, kwargs) : await fn(...args);

    if (cfg.return_schema !== undefined) {
      await validateAgainstSchema(result, cfg.return_schema, "return_schema");
    }

    const out = await encodeResult(cfg.format, result);
    process.stdout.write(out);
    process.exit(0);
  } catch (err) {
    emitEnvelope(cfg.mode, err);
    process.exit(1);
  }
}

await main();
