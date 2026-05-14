/**
 * Sandbox — e2b-style imperative runtime SDK. SDK port Phase 7c.
 *
 * TypeScript mirror of `sdks/python/mvm/_sandbox.py`. The
 * decorator surface (`mvm.app({...})((fn))`) is static; the host
 * parses the source AST without running it. The runtime surface
 * (`Sandbox.create(...)`) is imperative: the host *does* run
 * the user's TypeScript module (per S2 in the SDK plan — a
 * documented departure), with the SDK reconfigured to record
 * each method call into a {@link RuntimeRecording} instead of
 * dialing a real microVM.
 *
 * Phase 7c ships *record mode only*. `MVM_SDK_MODE=record` is the
 * mode the recorder reads; `live` and `plan` throw
 * {@link SandboxModeError} until Plan 71 unblocks
 * `mvmctl up`/`exec`. The record-mode lowering happens on the
 * Rust side (`crates/mvm-sdk/src/runtime.rs::compile_recording`);
 * this module's only job is to build a wire-compatible recording
 * JSON document.
 *
 * Wire shape matches the Rust `RuntimeRecording` serde types,
 * `deny_unknown_fields` on both sides — a typo'd field fails
 * closed at the Rust boundary.
 */

import type { EnvValue, Network, Resources } from "./ir/workload.js";

// ────────────────────────────────────────────────────────────────────
// Wire types — mirror the Rust serde shape.
// ────────────────────────────────────────────────────────────────────

export interface SandboxCreateWire {
  template: string;
  env: Record<string, EnvValue>;
  include: string[];
  tags: Record<string, string>;
  ttl_seconds: number;
  resources?: Resources;
  network?: Network;
}

export type RecordedOpWire =
  | { kind: "command_start"; argv: string[]; env: Record<string, EnvValue> }
  | { kind: "files_write"; path: string; bytes_b64: string }
  | { kind: "kill" };

export interface RuntimeRecordingWire {
  workload_id: string;
  create: SandboxCreateWire;
  ops: RecordedOpWire[];
}

// ────────────────────────────────────────────────────────────────────
// Errors.
// ────────────────────────────────────────────────────────────────────

/** Raised when `MVM_SDK_MODE` is unsupported by this build. */
export class SandboxModeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SandboxModeError";
  }
}

/** Raised when a Sandbox method is called outside a recording
 *  session (before `Sandbox.create` ran or after `resetRecording()`). */
export class RecordingNotActiveError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RecordingNotActiveError";
  }
}

// ────────────────────────────────────────────────────────────────────
// Module state.
// ────────────────────────────────────────────────────────────────────

/** Default TTL — every `Sandbox.create()` sets this unless the
 *  caller passes `ttl`. Matches the Python SDK's
 *  `DEFAULT_TTL_SECONDS`. The orchestrator reaps orphaned VMs
 *  after this elapses (mitigates the plan's
 *  "orphan microVM cleanup" consideration). */
export const DEFAULT_TTL_SECONDS = 1800;

export const MVM_SDK_MODE_ENV = "MVM_SDK_MODE";

/** When set in the environment, the SDK writes the wire-shape
 *  recording JSON to this path on process exit. The CLI's Phase 7f
 *  auto-exec path uses this to capture the recording without
 *  parsing stdout (which the user's own script may write to). */
export const MVM_SDK_OUT_PATH_ENV = "MVM_SDK_OUT_PATH";

let recording: RuntimeRecordingWire | null = null;

/** Clear the in-flight recording. Tests use this between runs;
 *  production never calls it (the process exits). */
export function resetRecording(): void {
  recording = null;
}

/** Return the active recording (or null). Useful for tools that
 *  want to introspect mid-run; production uses
 *  {@link emitRecordingJson}. */
export function currentRecording(): RuntimeRecordingWire | null {
  return recording;
}

/** Serialize the active recording to the JSON wire shape the
 *  Rust core consumes. Throws {@link RecordingNotActiveError} if
 *  no recording has been started. */
export function emitRecordingJson(): string {
  if (recording === null) {
    throw new RecordingNotActiveError(
      "no Sandbox.create() recorded yet — emitRecordingJson called before any Sandbox method",
    );
  }
  return JSON.stringify(recording);
}

/** `process.on('exit')` handler counterpart to the Python SDK's
 *  `atexit` hook. When `MVM_SDK_OUT_PATH` is set and a recording
 *  is active, write the wire-shape JSON to that path before the
 *  process exits. The CLI's Phase 7f auto-exec path consumes the
 *  file post-exec.
 *
 *  No-op when the env var isn't set (the script was run directly
 *  by a user, not auto-exec'd) or no recording was built (the
 *  script imported `mvm` but never called `Sandbox.create`).
 *  Errors are surfaced on stderr but don't rethrow — the script
 *  has already finished by then.
 *
 *  `exit` only fires on clean exits; uncaught exceptions take a
 *  different path and won't flush. The CLI checks the result
 *  file's existence post-spawn, so a missing file fails closed. */
export function flushRecordingToOutPath(): void {
  const outPath =
    typeof process !== "undefined" ? process.env[MVM_SDK_OUT_PATH_ENV] : undefined;
  if (!outPath) {
    return;
  }
  if (recording === null) {
    // File-missing = "no Sandbox.create() ran" is the signal the
    // CLI relies on; skipping the write preserves that.
    return;
  }
  try {
    // Node only — the auto-exec path runs in Node, so we can
    // safely require it dynamically without bundling a polyfill.
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const fs: typeof import("node:fs") = require("node:fs");
    fs.writeFileSync(outPath, JSON.stringify(recording));
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error(`mvm-sdk: failed to write recording to ${outPath}: ${String(err)}`);
  }
}

// Auto-register on import so user scripts don't have to.
if (typeof process !== "undefined" && typeof process.on === "function") {
  process.on("exit", flushRecordingToOutPath);
}

// ────────────────────────────────────────────────────────────────────
// Mode + TTL helpers.
// ────────────────────────────────────────────────────────────────────

function resolveMode(): "record" {
  const raw =
    (typeof process !== "undefined" ? process.env[MVM_SDK_MODE_ENV] : undefined) ?? "record";
  const norm = raw.trim().toLowerCase();
  if (norm === "record") return "record";
  if (norm === "live" || norm === "plan") {
    throw new SandboxModeError(
      `MVM_SDK_MODE=${JSON.stringify(norm)} is not supported in this SDK build — ` +
        "live/plan transports are blocked on Plan 71. Use 'record' or the mvm.app decorator path.",
    );
  }
  throw new SandboxModeError(
    `MVM_SDK_MODE=${JSON.stringify(norm)} is invalid — expected one of: record, live, plan`,
  );
}

const TTL_RE = /^\s*(\d+)\s*(s|m|h)?\s*$/;

/** Accept `"30m"` / `"1h"` / `"3600s"` / `"3600"` / `3600` / `null`
 *  / `undefined` and return integer seconds. `null`/`undefined`
 *  means "default of {@link DEFAULT_TTL_SECONDS}" — callers in
 *  `Sandbox.create` substitute the default after this call. */
function parseTtl(ttl: string | number | null | undefined): number | null {
  if (ttl === null || ttl === undefined) return null;
  if (typeof ttl === "number") {
    if (!Number.isInteger(ttl) || ttl <= 0) {
      throw new RangeError(`ttl must be a positive integer of seconds, got ${ttl}`);
    }
    return ttl;
  }
  const m = TTL_RE.exec(ttl);
  if (!m) {
    throw new RangeError(
      `unrecognized ttl format ${JSON.stringify(ttl)} — expected '<n>s', '<n>m', '<n>h', or a bare integer of seconds`,
    );
  }
  const value = parseInt(m[1], 10);
  const unit = (m[2] ?? "s") as "s" | "m" | "h";
  const seconds = value * { s: 1, m: 60, h: 3600 }[unit];
  if (seconds <= 0) {
    throw new RangeError(`ttl must be > 0 seconds, got ${seconds}`);
  }
  return seconds;
}

// ────────────────────────────────────────────────────────────────────
// Wire-shape encoders.
// ────────────────────────────────────────────────────────────────────

function encodeEnvValue(value: EnvValue | string): EnvValue {
  if (typeof value === "string") {
    return { kind: "literal", value };
  }
  return value;
}

function encodeEnvMap(env: Record<string, EnvValue | string> | undefined): Record<string, EnvValue> {
  if (!env) return {};
  const out: Record<string, EnvValue> = {};
  for (const [k, v] of Object.entries(env)) {
    out[k] = encodeEnvValue(v);
  }
  return out;
}

function bytesToBase64(bytes: Uint8Array): string {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes).toString("base64");
  }
  // Fallback: chunk through btoa to avoid the "max call stack
  // exceeded" trap when bytes is huge.
  let bin = "";
  const chunk = 8192;
  for (let i = 0; i < bytes.length; i += chunk) {
    bin += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return (globalThis as { btoa: (s: string) => string }).btoa(bin);
}

// ────────────────────────────────────────────────────────────────────
// Sandbox.
// ────────────────────────────────────────────────────────────────────

export interface SandboxCreateOptions {
  workloadId?: string;
  env?: Record<string, EnvValue | string>;
  include?: string[];
  tags?: Record<string, string>;
  ttl?: string | number | null;
  resources?: Resources;
  network?: Network;
}

export interface SandboxCommandsStartOptions {
  env?: Record<string, EnvValue | string>;
}

function requireRecording(): RuntimeRecordingWire {
  if (recording === null) {
    throw new RecordingNotActiveError(
      "Sandbox method called before Sandbox.create() — every script must construct a Sandbox first.",
    );
  }
  return recording;
}

/** A recordable handle for an imperative Sandbox script.
 *
 *  Construct via `Sandbox.create(...)` — direct construction is
 *  used internally so the recording session is initialized first.
 *  Use `[Symbol.dispose]` (TS 5.2+) for automatic cleanup, or call
 *  `sb.kill()` explicitly. */
export class Sandbox {
  readonly workloadId: string;
  readonly commands: SandboxCommands;
  readonly files: SandboxFiles;

  private constructor(workloadId: string) {
    this.workloadId = workloadId;
    this.commands = new SandboxCommands();
    this.files = new SandboxFiles();
  }

  static create(template: string, options: SandboxCreateOptions = {}): Sandbox {
    resolveMode(); // throws if MVM_SDK_MODE is live/plan/garbage.
    if (recording !== null) {
      throw new Error(
        "a Sandbox session is already active — call Sandbox.kill() before creating another. " +
          "Per the SDK plan's 'v1 scope: one app per workload' decision, a script may construct at most one Sandbox.",
      );
    }
    if (typeof template !== "string" || template.length === 0) {
      throw new TypeError("template must be a non-empty string");
    }
    let ttlSeconds = parseTtl(options.ttl);
    if (ttlSeconds === null) {
      ttlSeconds = DEFAULT_TTL_SECONDS;
    }
    const wid = options.workloadId ?? template;

    const create: SandboxCreateWire = {
      template,
      env: encodeEnvMap(options.env),
      include: options.include ? [...options.include] : [],
      tags: options.tags ? { ...options.tags } : {},
      ttl_seconds: ttlSeconds,
    };
    if (options.resources !== undefined) create.resources = options.resources;
    if (options.network !== undefined) create.network = options.network;

    recording = {
      workload_id: wid,
      create,
      ops: [],
    };
    return new Sandbox(wid);
  }

  kill(): void {
    requireRecording().ops.push({ kind: "kill" });
  }

  // TS 5.2+ `using` declaration support — `using sb = Sandbox.create(...)`
  // auto-calls `kill()` at scope exit, mirroring Python's `with` block.
  [Symbol.dispose](): void {
    this.kill();
  }
}

export class SandboxCommands {
  start(argv: string[], options: SandboxCommandsStartOptions = {}): void {
    if (!Array.isArray(argv) || !argv.every((a) => typeof a === "string")) {
      throw new TypeError("argv must be a string[]");
    }
    if (argv.length === 0) {
      throw new RangeError("argv must be non-empty");
    }
    requireRecording().ops.push({
      kind: "command_start",
      argv: [...argv],
      env: encodeEnvMap(options.env),
    });
  }
}

export class SandboxFiles {
  write(path: string, content: Uint8Array | string): void {
    if (typeof path !== "string" || path.length === 0) {
      throw new TypeError("path must be a non-empty string");
    }
    let bytes: Uint8Array;
    if (typeof content === "string") {
      bytes = new TextEncoder().encode(content);
    } else if (content instanceof Uint8Array) {
      bytes = content;
    } else {
      throw new TypeError("files.write content must be Uint8Array or string");
    }
    requireRecording().ops.push({
      kind: "files_write",
      path,
      bytes_b64: bytesToBase64(bytes),
    });
  }
}
