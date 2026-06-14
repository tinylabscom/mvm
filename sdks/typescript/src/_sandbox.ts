/**
 * Sandbox — imperative runtime SDK. SDK port Phase 7c +
 * Plan 73 Followup H-live.
 *
 * TypeScript mirror of `sdks/python/mvm/_sandbox.py`. The
 * decorator surface (`mvm.app({...})((fn))`) is static; the host
 * parses the source AST without running it. The runtime surface
 * (`Sandbox.create(...)`) is imperative: the host *does* run
 * the user's TypeScript module (per S2 in the SDK plan — a
 * documented departure), with the SDK reconfigured to either
 * record each method call into a {@link RuntimeRecording} or
 * shell each call to `mvmctl` against a real microVM,
 * depending on the active mode.
 *
 * Two modes are live:
 *
 * - `MVM_SDK_MODE=record` (the original Phase 7c contract):
 *   every `Sandbox` call appends to an in-process recording;
 *   the Rust lowering at `mvm_sdk::runtime::compile_recording`
 *   produces a Workload.
 * - `MVM_SDK_MODE=live` (Plan 73 Followup H-live): every
 *   `Sandbox` call shells to `$MVM_CLI_BIN` (`mvmctl up`,
 *   `mvmctl proc start`, `mvmctl fs write`, `mvmctl down`)
 *   against a real microVM. The shell is dispatched by
 *   {@link LiveTransport} below.
 *
 * `MVM_SDK_MODE=plan` remains an error here — the host CLI's
 * `mvmctl run --mode plan` verb runs Sandbox scripts under that
 * transport; the SDK itself never enters "plan" mode directly.
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

/** Raised when `MVM_SDK_MODE` is unsupported by this build, or
 *  `MVM_SDK_MODE=live` is requested without `MVM_CLI_BIN` set. */
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

/** Raised when a live-mode shell to `mvmctl` fails. Carries the
 *  failing argv, exit code, and captured stderr so user scripts
 *  can see exactly which verb refused and why. */
export class SandboxLiveError extends Error {
  readonly argv: string[];
  readonly exitCode: number | null;
  readonly stderr: string;

  constructor(
    message: string,
    opts: { argv?: string[]; exitCode?: number | null; stderr?: string } = {},
  ) {
    super(message);
    this.name = "SandboxLiveError";
    this.argv = opts.argv ?? [];
    this.exitCode = opts.exitCode ?? null;
    this.stderr = opts.stderr ?? "";
  }
}

/** Raised when the SDK refuses a live-mode `commands.start` call
 *  because the resolved template is a *prod* template.
 *
 *  Per ADR-002 §W4.3 (security claim 4 in `CLAUDE.md`) the guest
 *  agent strips the `do_exec` handler in production builds. The
 *  agent itself fails closed, but the SDK refuses *before* any
 *  vsock traffic so a typo doesn't make a spurious round-trip.
 *  `commands.start` is the only Sandbox surface that hits
 *  `proc start`; `files.write` / `kill` route to verbs that are
 *  available in prod builds too. */
export class SandboxDevOnly extends SandboxLiveError {
  constructor(
    message: string,
    opts: { argv?: string[] } = {},
  ) {
    super(message, opts);
    this.name = "SandboxDevOnly";
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

/** Plan 73 Followup H-live — when `MVM_SDK_MODE=live` is set, the
 *  SDK shells out to the `mvmctl` binary at this path. The host's
 *  `mvmctl run --mode live` verb sets it to its own
 *  `current_exe()` so a `cargo run -- run --mode live` flow finds
 *  the same binary it invoked through. */
export const MVM_CLI_BIN_ENV = "MVM_CLI_BIN";

let recording: RuntimeRecordingWire | null = null;

/** Clear the in-flight recording state and any live registration.
 *  Tests use this between runs; production never calls it (the
 *  process exits). */
export function resetRecording(): void {
  recording = null;
  liveSandbox = null;
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

type SandboxMode = "record" | "live";

function resolveMode(): SandboxMode {
  const raw =
    (typeof process !== "undefined" ? process.env[MVM_SDK_MODE_ENV] : undefined) ?? "record";
  const norm = raw.trim().toLowerCase();
  if (norm === "record") return "record";
  if (norm === "live") {
    const bin =
      typeof process !== "undefined" ? process.env[MVM_CLI_BIN_ENV] : undefined;
    if (!bin) {
      throw new SandboxModeError(
        "MVM_SDK_MODE=live requires MVM_CLI_BIN to point at a `mvmctl` binary. " +
          "The host's `mvmctl run --mode live` verb sets this automatically; if you're " +
          "running the SDK directly, set MVM_CLI_BIN=/path/to/mvmctl before invoking your script.",
      );
    }
    return "live";
  }
  if (norm === "plan") {
    throw new SandboxModeError(
      "MVM_SDK_MODE=plan is not a SDK-side transport — the host CLI's `mvmctl run --mode plan` " +
        "verb runs your script under record mode and synthesises ExecutionPlans for admission " +
        "dry-run. Drop MVM_SDK_MODE and let `mvmctl run --mode plan` set the recording state for you.",
    );
  }
  throw new SandboxModeError(
    `MVM_SDK_MODE=${JSON.stringify(norm)} is invalid — expected one of: record, live`,
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

/** Live-mode transport — shells each Sandbox call to the host's
 *  `mvmctl` binary.
 *
 *  Created by `Sandbox.create(...)` when `MVM_SDK_MODE=live`. Holds
 *  the resolved `mvmctl` path, the generated `vmId`, and the
 *  template's `build_mode` parsed from the `mvmctl up --up-json`
 *  envelope. The `build_mode` is what the SDK uses to enforce the
 *  W4.3 dev-only `proc start` rule client-side. */
export class LiveTransport {
  static readonly SCHEMA_VERSION = 1;

  readonly mvmCliBin: string;
  readonly vmId: string;
  readonly buildMode: "dev" | "prod";
  private killed = false;

  constructor(opts: { mvmCliBin: string; vmId: string; buildMode: "dev" | "prod" }) {
    this.mvmCliBin = opts.mvmCliBin;
    this.vmId = opts.vmId;
    this.buildMode = opts.buildMode;
  }

  static forTemplate(opts: {
    template: string;
    workloadId: string;
    ttlSeconds: number;
  }): LiveTransport {
    const mvmCliBin =
      typeof process !== "undefined" ? process.env[MVM_CLI_BIN_ENV] ?? "" : "";
    if (!mvmCliBin) {
      throw new SandboxModeError(
        "MVM_SDK_MODE=live requires MVM_CLI_BIN to point at a `mvmctl` binary.",
      );
    }
    // Generate a short, validatable VM id. `mvmctl up` rejects
    // names that don't match its validator; alphanumerics with a
    // hyphen are safe.
    const suffix = randomHex(4);
    const slug = opts.workloadId
      .slice(0, 24)
      .toLowerCase()
      .replace(/[^a-z0-9-]/g, "-");
    const vmId = `sdk-${slug}-${suffix}`;

    const argv = [
      "up",
      "--up-json",
      "--name",
      vmId,
      "--manifest",
      opts.template,
      "--ttl",
      `${opts.ttlSeconds}s`,
    ];
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const child = require("node:child_process") as typeof import("node:child_process");
    let result;
    try {
      result = child.spawnSync(mvmCliBin, argv, {
        encoding: "utf-8",
      });
    } catch (err) {
      throw new SandboxLiveError(
        `\`${mvmCliBin}\` not found on disk; check MVM_CLI_BIN: ${String(err)}`,
        { argv: [mvmCliBin, ...argv] },
      );
    }
    if (result.error) {
      throw new SandboxLiveError(
        `failed to spawn \`${mvmCliBin}\`: ${result.error.message}`,
        { argv: [mvmCliBin, ...argv] },
      );
    }
    if (result.status !== 0) {
      throw new SandboxLiveError(
        `\`mvmctl up\` failed with exit code ${result.status}`,
        {
          argv: [mvmCliBin, ...argv],
          exitCode: result.status,
          stderr: result.stderr ?? "",
        },
      );
    }
    const envelope = parseUpEnvelope(result.stdout ?? "", [mvmCliBin, ...argv]);
    return new LiveTransport({
      mvmCliBin,
      vmId: envelope.vm_id,
      buildMode: envelope.build_mode,
    });
  }

  commandsStart(argv: string[], env: Record<string, EnvValue | string> | undefined): void {
    if (this.buildMode !== "dev") {
      throw new SandboxDevOnly(
        `\`commands.start\` requires a dev-mode template; resolved template ` +
          `build_mode=${JSON.stringify(this.buildMode)}. ADR-002 §W4.3 (security ` +
          `claim 4) strips the agent's \`do_exec\` handler in prod builds — ` +
          `re-build the template with \`mvmctl template build --dev <name>\`, ` +
          `or use \`files.write\` to stage inputs into the running VM instead.`,
        { argv: ["proc", "start", this.vmId, ...argv] },
      );
    }
    const shell = [this.mvmCliBin, "proc", "start", this.vmId];
    if (env) {
      for (const [key, value] of Object.entries(env)) {
        if (typeof value === "string") {
          shell.push("-e", `${key}=${value}`);
        } else if (
          typeof value === "object" &&
          value !== null &&
          (value as { kind?: string }).kind === "literal"
        ) {
          shell.push("-e", `${key}=${(value as { value: string }).value}`);
        } else {
          throw new SandboxLiveError(
            `\`commands.start\` env ${JSON.stringify(key)} carries a non-literal value; ` +
              "live mode only forwards literal env vars (secrets must be injected via " +
              "the host keystore + `--secret` on `mvmctl up`).",
            { argv: shell },
          );
        }
      }
    }
    shell.push("--", ...argv);
    this.runShell(shell);
  }

  filesWrite(path: string, data: Uint8Array): void {
    const shell = [this.mvmCliBin, "fs", "write", this.vmId, path];
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const child = require("node:child_process") as typeof import("node:child_process");
    let result;
    try {
      result = child.spawnSync(shell[0], shell.slice(1), {
        input: Buffer.from(data),
      });
    } catch (err) {
      throw new SandboxLiveError(
        `\`${this.mvmCliBin}\` not found on disk; check MVM_CLI_BIN: ${String(err)}`,
        { argv: shell },
      );
    }
    if (result.error) {
      throw new SandboxLiveError(`failed to spawn: ${result.error.message}`, {
        argv: shell,
      });
    }
    if (result.status !== 0) {
      throw new SandboxLiveError(
        `\`mvmctl fs write\` failed with exit code ${result.status}`,
        {
          argv: shell,
          exitCode: result.status,
          stderr: result.stderr ? result.stderr.toString("utf-8") : "",
        },
      );
    }
  }

  cp(source: string, destination: string): void {
    const shell = [this.mvmCliBin, "cp", source, destination];
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const child = require("node:child_process") as typeof import("node:child_process");
    let result;
    try {
      result = child.spawnSync(shell[0], shell.slice(1));
    } catch (err) {
      throw new SandboxLiveError(
        `\`${this.mvmCliBin}\` not found on disk; check MVM_CLI_BIN: ${String(err)}`,
        { argv: shell },
      );
    }
    if (result.error) {
      throw new SandboxLiveError(`failed to spawn: ${result.error.message}`, {
        argv: shell,
      });
    }
    if (result.status !== 0) {
      throw new SandboxLiveError(
        `\`mvmctl cp\` failed with exit code ${result.status}`,
        {
          argv: shell,
          exitCode: result.status,
          stderr: result.stderr ? result.stderr.toString("utf-8") : "",
        },
      );
    }
  }

  kill(): void {
    if (this.killed) return;
    this.killed = true;
    const shell = [this.mvmCliBin, "down", this.vmId];
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const child = require("node:child_process") as typeof import("node:child_process");
    try {
      const result = child.spawnSync(shell[0], shell.slice(1), {
        encoding: "utf-8",
      });
      if (result.status !== 0) {
        // Don't throw — kill is the cleanup path; a failure here
        // usually means the VM was already torn down by the
        // orchestrator's TTL reaper.
        // eslint-disable-next-line no-console
        console.error(
          `mvm-sdk live: \`mvmctl down ${this.vmId}\` exited with ${result.status}: ${result.stderr ?? ""}`,
        );
      }
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error(`mvm-sdk live: failed to spawn \`mvmctl down\`: ${String(err)}`);
    }
  }

  private runShell(shell: string[]): void {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const child = require("node:child_process") as typeof import("node:child_process");
    let result;
    try {
      result = child.spawnSync(shell[0], shell.slice(1), { encoding: "utf-8" });
    } catch (err) {
      throw new SandboxLiveError(
        `\`${this.mvmCliBin}\` not found on disk; check MVM_CLI_BIN: ${String(err)}`,
        { argv: shell },
      );
    }
    if (result.error) {
      throw new SandboxLiveError(`failed to spawn: ${result.error.message}`, {
        argv: shell,
      });
    }
    if (result.stdout) process.stdout.write(result.stdout);
    if (result.stderr) process.stderr.write(result.stderr);
    if (result.status !== 0) {
      throw new SandboxLiveError(
        `\`${shell.join(" ")}\` failed with exit code ${result.status}`,
        {
          argv: shell,
          exitCode: result.status,
          stderr: result.stderr ?? "",
        },
      );
    }
  }
}

/** Parse an `mvmctl up --up-json` stdout envelope. The envelope is
 *  a single JSON line; trailing newlines tolerated. Throws
 *  `SandboxLiveError` on any shape violation. Exported for tests. */
export function parseUpEnvelope(
  stdout: string,
  argv: string[],
): { vm_id: string; build_mode: "dev" | "prod" } {
  const line = stdout.trim();
  if (!line) {
    throw new SandboxLiveError(
      "`mvmctl up --up-json` produced empty stdout — expected a JSON envelope.",
      { argv },
    );
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(line);
  } catch (err) {
    throw new SandboxLiveError(
      `\`mvmctl up --up-json\` stdout is not valid JSON: ${String(err)}`,
      { argv, stderr: line },
    );
  }
  if (typeof parsed !== "object" || parsed === null) {
    throw new SandboxLiveError(
      "`mvmctl up --up-json` envelope must be a JSON object.",
      { argv },
    );
  }
  const obj = parsed as Record<string, unknown>;
  if (obj.schema_version !== LiveTransport.SCHEMA_VERSION) {
    throw new SandboxLiveError(
      `\`mvmctl up --up-json\` envelope schema_version=${JSON.stringify(obj.schema_version)}; ` +
        `SDK supports ${LiveTransport.SCHEMA_VERSION}`,
      { argv },
    );
  }
  if (typeof obj.vm_id !== "string" || obj.vm_id.length === 0) {
    throw new SandboxLiveError(
      "`mvmctl up --up-json` envelope is missing a non-empty `vm_id` field.",
      { argv },
    );
  }
  if (obj.build_mode !== "dev" && obj.build_mode !== "prod") {
    throw new SandboxLiveError(
      `\`mvmctl up --up-json\` envelope build_mode=${JSON.stringify(obj.build_mode)}; ` +
        "expected 'dev' or 'prod'.",
      { argv },
    );
  }
  return { vm_id: obj.vm_id, build_mode: obj.build_mode };
}

function randomHex(byteCount: number): string {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const crypto = require("node:crypto") as typeof import("node:crypto");
  return crypto.randomBytes(byteCount).toString("hex");
}

/** Live-mode bookkeeping. Mirrors `recording`'s "one session per
 *  process" invariant — a live Sandbox is stashed here so a second
 *  `Sandbox.create(...)` call inside the same process is refused. */
let liveSandbox: Sandbox | null = null;

function isLiveActive(): boolean {
  return liveSandbox !== null;
}

/** A recordable / live handle for an imperative Sandbox script.
 *
 *  Construct via `Sandbox.create(...)`. Under `MVM_SDK_MODE=record`
 *  the constructor sets up an in-process recording; under
 *  `MVM_SDK_MODE=live` it shells `mvmctl up` to boot a real
 *  microVM and stashes the resulting handle on
 *  `this._live`. Use `[Symbol.dispose]` (TS 5.2+) for automatic
 *  cleanup, or call `sb.kill()` explicitly. */
export class Sandbox {
  readonly workloadId: string;
  readonly commands: SandboxCommands;
  readonly files: SandboxFiles;
  readonly _live: LiveTransport | null;

  private constructor(workloadId: string, live: LiveTransport | null) {
    this.workloadId = workloadId;
    this._live = live;
    this.commands = new SandboxCommands(this);
    this.files = new SandboxFiles(this);
  }

  static create(template: string, options: SandboxCreateOptions = {}): Sandbox {
    const mode = resolveMode();
    if (recording !== null || isLiveActive()) {
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

    if (mode === "live") {
      const live = LiveTransport.forTemplate({
        template,
        workloadId: wid,
        ttlSeconds,
      });
      const sb = new Sandbox(wid, live);
      liveSandbox = sb;
      return sb;
    }

    // record mode (existing path).
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
    return new Sandbox(wid, null);
  }

  /** Copy a host file into the running sandbox at `guestPath`.
   *
   *  Shells `mvmctl cp <hostPath> <vm>:<guestPath>` — the host file
   *  streams into the guest over the agent fs RPC.
   *
   *  Live mode only: in record mode this throws `SandboxModeError`. To
   *  stage a file declaratively for a recorded workload, use
   *  `files.write(guestPath, content)`. */
  copyIn(hostPath: string, guestPath: string): void {
    if (typeof hostPath !== "string" || hostPath.length === 0) {
      throw new TypeError("hostPath must be a non-empty string");
    }
    if (typeof guestPath !== "string" || guestPath.length === 0) {
      throw new TypeError("guestPath must be a non-empty string");
    }
    if (this._live === null) {
      throw new SandboxModeError(
        "`Sandbox.copyIn` is a live-mode operation; under MVM_SDK_MODE=record " +
          "use `files.write(path, content)` to stage a file declaratively.",
      );
    }
    this._live.cp(hostPath, `${this._live.vmId}:${guestPath}`);
  }

  /** Copy a file out of the running sandbox to `hostPath`.
   *
   *  Shells `mvmctl cp <vm>:<guestPath> <hostPath>` — the guest file
   *  streams back over the agent fs RPC.
   *
   *  Live mode only: pulling a file from a running VM has no record-mode
   *  meaning, so in record mode this throws `SandboxModeError`. */
  copyOut(guestPath: string, hostPath: string): void {
    if (typeof guestPath !== "string" || guestPath.length === 0) {
      throw new TypeError("guestPath must be a non-empty string");
    }
    if (typeof hostPath !== "string" || hostPath.length === 0) {
      throw new TypeError("hostPath must be a non-empty string");
    }
    if (this._live === null) {
      throw new SandboxModeError(
        "`Sandbox.copyOut` is a live-mode operation; it pulls a file from a " +
          "running VM and has no record-mode meaning.",
      );
    }
    this._live.cp(`${this._live.vmId}:${guestPath}`, hostPath);
  }

  kill(): void {
    if (this._live !== null) {
      this._live.kill();
      liveSandbox = null;
      return;
    }
    requireRecording().ops.push({ kind: "kill" });
  }

  // TS 5.2+ `using` declaration support — `using sb = Sandbox.create(...)`
  // auto-calls `kill()` at scope exit, mirroring Python's `with` block.
  [Symbol.dispose](): void {
    this.kill();
  }
}

export class SandboxCommands {
  private readonly sandbox: Sandbox;

  constructor(sandbox: Sandbox) {
    this.sandbox = sandbox;
  }

  start(argv: string[], options: SandboxCommandsStartOptions = {}): void {
    if (!Array.isArray(argv) || !argv.every((a) => typeof a === "string")) {
      throw new TypeError("argv must be a string[]");
    }
    if (argv.length === 0) {
      throw new RangeError("argv must be non-empty");
    }
    if (this.sandbox._live !== null) {
      this.sandbox._live.commandsStart([...argv], options.env);
      return;
    }
    requireRecording().ops.push({
      kind: "command_start",
      argv: [...argv],
      env: encodeEnvMap(options.env),
    });
  }
}

export class SandboxFiles {
  private readonly sandbox: Sandbox;

  constructor(sandbox: Sandbox) {
    this.sandbox = sandbox;
  }

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
    if (this.sandbox._live !== null) {
      this.sandbox._live.filesWrite(path, bytes);
      return;
    }
    requireRecording().ops.push({
      kind: "files_write",
      path,
      bytes_b64: bytesToBase64(bytes),
    });
  }
}
