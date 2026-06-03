#!/usr/bin/env node
// mvm function-entrypoint wrapper (Node 22+, ADR-0011 warm-process tier).
//
// Counterpart to ./oneshot.mjs: same dispatch + envelope semantics, but
// stays alive across many calls and speaks the framed multi-call protocol
// on its own stdin/stdout (matching mvm_guest::worker_protocol::
// {WorkerCallRequest, WorkerCallResponse}).
//
// Wire format (per call, both directions):
//   [4-byte big-endian length prefix] [JSON body of length bytes]
//
// Request body  (WorkerCallRequest):
//   { "stdin": base64-encoded encoded-args, "timeout_secs": number }
//
// Response body (WorkerCallResponse):
//   { "stdout": base64-encoded encoded-return,
//     "stderr": base64-encoded user-stderr,
//     "outcome": { "exit": { "code": 0 } }
//              | { "error": { "kind": "...", "message": "..." } } }
//
// Lifecycle:
//   - On startup: load /etc/mvm/wrapper.json, import the user module ONCE.
//   - Per call: read frame, dispatch fn, capture stdout/stderr, write
//     response frame, loop.
//   - On EOF (agent closed the pipe): exit 0 cleanly.
//
// Per ADR-0011, **cross-call state is the user's responsibility**. The
// wrapper does NOT scrub Node module cache, /tmp, or anything else
// between calls. Users opting into warm-process accept that.

import { readFileSync, existsSync } from "node:fs";
import { chdir } from "node:process";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { randomBytes } from "node:crypto";

// See oneshot.mjs: `cfg.module` is a bare stem; Node ESM won't
// extension-resolve absolute file: URLs, so probe the bundled file. `.ts`
// first — the bundler keeps the user's source and Node ≥22.18 strips types.
const MODULE_EXTS = [".ts", ".mts", ".cts", ".mjs", ".js", ".cjs", ""];

function resolveModuleUrl(workingDir, module) {
  const base = resolve(workingDir, module);
  const hit = MODULE_EXTS.map((e) => base + e).find((p) => existsSync(p));
  if (hit === undefined) {
    throw new Error(`module not found for "${module}" under ${workingDir}`);
  }
  return pathToFileURL(hit).href;
}

const WRAPPER_CONFIG_PATH =
  process.env.MVM_WRAPPER_CONFIG_PATH || "/etc/mvm/wrapper.json";
const MAX_NESTING_DEPTH = 64;
const DEFAULT_MAX_INPUT_BYTES = 16 * 1024 * 1024; // 16 MiB
const MAX_FRAME_BYTES = 256 * 1024; // mvm_guest::worker_protocol cap
const ENVELOPE_MARKER = "MVM_ENVELOPE: ";

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
  return cfg;
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
  const seenSets = new WeakMap();
  const text = buffer.toString("utf8");
  return JSON.parse(text, function reviver(key, value) {
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
}

async function decodeMsgpack(buffer) {
  const { decode } = await import("@msgpack/msgpack");
  return decode(buffer);
}

function encodeJson(value) {
  return Buffer.from(JSON.stringify(value), "utf8");
}

async function encodeMsgpack(value) {
  const { encode } = await import("@msgpack/msgpack");
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

function scrub(message) {
  if (!message) return "Error";
  const redacted = message
    .split(/\s+/)
    .filter((tok) => !tok.includes("/"))
    .join(" ");
  return redacted.slice(0, 200) || "Error";
}

function emitEnvelopeToStderr(mode, err) {
  // Wrapper-level error (frame protocol violation, config invalid).
  // Per-call user-code errors propagate via WorkerCallResponse.outcome.error.
  const errorId = randomBytes(8).toString("hex");
  if (mode === "dev" && err instanceof Error && err.stack) {
    process.stderr.write(err.stack + "\n");
  }
  const envelope = {
    kind: err && err.name ? err.name : "Error",
    error_id: errorId,
    message: mode === "dev" ? String(err && err.message) : scrub(String(err && err.message)),
  };
  process.stderr.write(ENVELOPE_MARKER + JSON.stringify(envelope) + "\n");
}

// ---------- Frame I/O over stdin/stdout ---------------------------

async function readExact(n) {
  // Read n bytes from stdin. Resolves to Buffer of length n, or null on
  // clean EOF before any byte was read. Rejects on partial read after
  // at least one byte arrived (truncated frame).
  return new Promise((resolveFn, rejectFn) => {
    const chunks = [];
    let total = 0;

    function tryRead() {
      while (total < n) {
        const chunk = process.stdin.read(n - total);
        if (chunk === null) return false; // need more data
        chunks.push(chunk);
        total += chunk.length;
      }
      cleanup();
      resolveFn(Buffer.concat(chunks, total));
      return true;
    }

    function onReadable() {
      tryRead();
    }

    function onEnd() {
      cleanup();
      if (total === 0) {
        resolveFn(null); // clean EOF
      } else {
        rejectFn(new Error(`truncated frame: expected ${n} bytes, got ${total}`));
      }
    }

    function onError(err) {
      cleanup();
      rejectFn(err);
    }

    function cleanup() {
      process.stdin.removeListener("readable", onReadable);
      process.stdin.removeListener("end", onEnd);
      process.stdin.removeListener("error", onError);
    }

    process.stdin.on("readable", onReadable);
    process.stdin.on("end", onEnd);
    process.stdin.on("error", onError);
    // Try once in case data is already buffered.
    if (!tryRead()) {
      // wait for events
    }
  });
}

async function readFrame() {
  const prefix = await readExact(4);
  if (prefix === null) return null;
  const length = prefix.readUInt32BE(0);
  if (length > MAX_FRAME_BYTES) {
    throw new Error(`frame length ${length} exceeds protocol cap ${MAX_FRAME_BYTES}`);
  }
  const body = await readExact(length);
  if (body === null) {
    throw new Error("unexpected EOF after frame length prefix");
  }
  return body;
}

function writeFrame(body) {
  if (body.length > MAX_FRAME_BYTES) {
    throw new Error(`response frame ${body.length} exceeds protocol cap ${MAX_FRAME_BYTES}`);
  }
  const prefix = Buffer.alloc(4);
  prefix.writeUInt32BE(body.length, 0);
  process.stdout.write(prefix);
  process.stdout.write(body);
}

// ---------- Per-call dispatch + stdout/stderr capture --------------

class CapturedWriter {
  constructor() {
    this.chunks = [];
  }
  write(chunk, _encoding, cb) {
    if (typeof chunk === "string") chunk = Buffer.from(chunk, "utf8");
    this.chunks.push(chunk);
    if (cb) cb();
    return true;
  }
  bytes() {
    return Buffer.concat(this.chunks);
  }
}

async function dispatchOneCall(fn, format, requestBody, mode) {
  const request = decodeJson(requestBody);
  if (typeof request !== "object" || request === null) {
    throw new Error("WorkerCallRequest must be a JSON object");
  }
  if (typeof request.stdin !== "string") {
    throw new Error("WorkerCallRequest.stdin must be a base64 string");
  }
  const timeoutSecs = Number.isInteger(request.timeout_secs) ? request.timeout_secs : 60;

  let callInput;
  try {
    callInput = Buffer.from(request.stdin, "base64");
  } catch (exc) {
    throw new Error(`WorkerCallRequest.stdin not valid base64: ${exc.message}`);
  }

  const capturedOut = new CapturedWriter();
  const capturedErr = new CapturedWriter();

  // Redirect process.stdout/stderr to the capturers for the duration
  // of this call. Restore after to keep the wrapper's own logging path
  // intact for subsequent calls.
  const realOutWrite = process.stdout.write.bind(process.stdout);
  const realErrWrite = process.stderr.write.bind(process.stderr);
  process.stdout.write = capturedOut.write.bind(capturedOut);
  process.stderr.write = capturedErr.write.bind(capturedErr);

  let outcome;
  try {
    const decoded = await decodePayload(format, callInput);
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
    const hasKwargs = Object.keys(kwargs).length > 0;

    const callPromise = (async () => {
      const result = hasKwargs ? await fn(...args, kwargs) : await fn(...args);
      const encoded = await encodeResult(format, result);
      capturedOut.write(encoded);
    })();

    if (timeoutSecs > 0) {
      let timer;
      const timeoutPromise = new Promise((_, rej) => {
        timer = setTimeout(
          () => rej(new Error(`call exceeded ${timeoutSecs}-second cap`)),
          timeoutSecs * 1000,
        );
      });
      try {
        await Promise.race([callPromise, timeoutPromise]);
      } finally {
        clearTimeout(timer);
      }
    } else {
      await callPromise;
    }

    outcome = { exit: { code: 0 } };
  } catch (exc) {
    outcome = {
      error: {
        kind: exc && exc.name ? exc.name : "Error",
        message: mode === "dev" ? String(exc && exc.message) : scrub(String(exc && exc.message)),
      },
    };
  } finally {
    process.stdout.write = realOutWrite;
    process.stderr.write = realErrWrite;
  }

  return {
    stdout: capturedOut.bytes().toString("base64"),
    stderr: capturedErr.bytes().toString("base64"),
    outcome,
  };
}

// ---------- Main loop ---------------------------------------------

async function main() {
  const cfg = loadConfig();

  let fn;
  try {
    chdir(cfg.working_dir);
    const moduleUrl = resolveModuleUrl(cfg.working_dir, cfg.module);
    const mod = await import(moduleUrl);
    fn = mod[cfg.function];
    if (typeof fn !== "function") {
      throw new Error(`exported function not found: ${cfg.function}`);
    }
  } catch (err) {
    emitEnvelopeToStderr(cfg.mode, err);
    process.exit(1);
  }

  while (true) {
    let body;
    try {
      body = await readFrame();
    } catch (err) {
      emitEnvelopeToStderr(cfg.mode, err);
      process.exit(1);
    }
    if (body === null) {
      // Clean EOF — agent closed the pipe.
      process.exit(0);
    }

    try {
      const response = await dispatchOneCall(fn, cfg.format, body, cfg.mode);
      writeFrame(Buffer.from(JSON.stringify(response), "utf8"));
    } catch (err) {
      emitEnvelopeToStderr(cfg.mode, err);
      try {
        writeFrame(
          Buffer.from(
            JSON.stringify({
              stdout: "",
              stderr: "",
              outcome: {
                error: {
                  kind: err && err.name ? err.name : "Error",
                  message: scrub(String(err && err.message)),
                },
              },
            }),
            "utf8",
          ),
        );
      } catch {
        process.exit(1);
      }
    }
  }
}

await main();
