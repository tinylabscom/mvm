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
 *   `Sandbox` call shells to `$MVM_CLI_BIN` (`mvmctl machine run`,
 *   `mvmctl machine proc start`, `mvmctl machine fs write`, `mvmctl machine stop`)
 *   against a real microVM. The shell is dispatched by
 *   {@link LiveTransport} below.
 *
 * `MVM_SDK_MODE=plan` remains an error here — the host CLI's
 * `mvmctl run --mode plan` verb runs Sandbox scripts under that
 * transport; the SDK itself never enters "plan" mode directly.
 */

import type { EnvValue, Network, PortForward, Resources } from "./ir/workload.js";
import type {
  RuntimeFsEntry,
  RuntimeFsStat,
} from "./runtime/runtime.js";
import { cliResolutionHint, resolveCliBin } from "./_cli.js";

// This package is ESM ("type": "module"), so `require` does not exist at
// runtime. These node builtins are imported statically; a lazy `require` here
// throws `ReferenceError: require is not defined` for every consumer of the
// built artifact.
import * as child from "node:child_process";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
export { MVM_CLI_BIN_ENV } from "./_cli.js";

// ────────────────────────────────────────────────────────────────────
// Wire types — mirror the Rust serde shape.
// ────────────────────────────────────────────────────────────────────

export interface SandboxCreateWire {
  template?: string;
  image?: string;
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
 *  `MVM_SDK_MODE=live` is requested without a resolvable SDK CLI. */
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
 *  The guest agent's runtime profile and signed grant refuse DevOnly
 *  process-control requests in production. The agent itself fails closed,
 *  but the SDK refuses *before* any
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

export type FsEntry = RuntimeFsEntry;
export type FsStat = RuntimeFsStat;

export interface ProcessStreamEvent {
  stream: string;
  data: Uint8Array;
}

export interface ProcessResult {
  exitCode: number;
  stdout: Uint8Array;
  stderr: Uint8Array;
}

export class ProcessHandle {
  readonly token: string;
  private readonly transport: LiveTransport;

  constructor(transport: LiveTransport, token: string) {
    this.transport = transport;
    this.token = token;
  }

  wait(options: {
    timeout?: number;
    onEvent?: (event: ProcessStreamEvent) => void;
  } = {}): Promise<ProcessResult> {
    return this.transport.processWait(this.token, options);
  }

  sendStdin(data: Uint8Array | string): void {
    const bytes = typeof data === "string" ? new TextEncoder().encode(data) : data;
    this.transport.processStdin(this.token, bytes);
  }

  signal(signum: number): void {
    this.transport.processSignal(this.token, signum);
  }

  kill(): void {
    this.transport.processKill(this.token);
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

// Owned by the Rust registry (crates/mvm-sdk/src/env.rs) and generated
// into `_env/vars.ts`.
export { MVM_SDK_MODE_ENV, MVM_SDK_OUT_PATH_ENV } from "./_env/vars.js";
import { MVM_SDK_MODE_ENV, MVM_SDK_OUT_PATH_ENV } from "./_env/vars.js";


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
    try {
      resolveCliBin("MVM_SDK_MODE=live");
    } catch (err) {
      throw new SandboxModeError(String(err instanceof Error ? err.message : err));
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
  /** Entrypoint used for this boot. */
  command?: string[];
}

/** Typed boot source. A bare string remains a manifest for compatibility. */
export type SandboxSource = string | { manifest: string } | { image: string };

type BootSource = { kind: "manifest" | "image"; value: string };

function bootSource(source: SandboxSource): BootSource {
  if (typeof source === "string") {
    if (source.length === 0) throw new TypeError("source must be non-empty");
    return { kind: "manifest", value: source };
  }
  const keys = Object.keys(source);
  if (keys.length !== 1 || (keys[0] !== "manifest" && keys[0] !== "image")) {
    throw new TypeError("source must contain exactly one of manifest or image");
  }
  const kind = keys[0] as "manifest" | "image";
  const value = kind === "manifest" && "manifest" in source
    ? source.manifest
    : kind === "image" && "image" in source
      ? source.image
      : undefined;
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError(`${kind} source must be a non-empty string`);
  }
  return { kind, value };
}

function rejectLiveOption(name: string, reason: string): never {
  throw new SandboxModeError(`Sandbox live mode cannot represent \`${name}\` safely: ${reason}`);
}

function formatAllowHost(host: unknown, port: unknown): string {
  const wildcards = new Set(["*", "0.0.0.0", "::", "0.0.0.0/0", "::/0"]);
  if (typeof host !== "string" || host.length === 0 || wildcards.has(host)) {
    return rejectLiveOption("network.egress", "allowlist hosts must be specific");
  }
  if (!Number.isInteger(port) || (port as number) < 1 || (port as number) > 65535) {
    return rejectLiveOption("network.egress", "allowlist ports must be 1..65535");
  }
  const renderedHost = host.includes(":") && !host.startsWith("[") ? `[${host}]` : host;
  return `${renderedHost}:${String(port)}`;
}

function lowerLiveOptions(options: SandboxCreateOptions): string[] {
  const argv: string[] = [];
  const env = encodeEnvMap(options.env);
  for (const key of Object.keys(env).sort()) {
    const value = env[key];
    if (value?.kind !== "literal" || Object.keys(value).some((field) => field !== "kind" && field !== "value")) {
      rejectLiveOption("env", "only literal values can be placed on CLI argv");
    }
    if (typeof value.value !== "string") {
      rejectLiveOption("env", "literal values must be strings");
    }
    argv.push("--env", `${key}=${value.value}`);
  }
  if (options.include && options.include.length > 0) {
    rejectLiveOption("include", "the live CLI has no source-bundle equivalent");
  }
  if (options.tags && Object.keys(options.tags).length > 0) {
    rejectLiveOption("tags", "the live CLI has no tag equivalent");
  }
  if (options.resources !== undefined) {
    rejectLiveOption("resources", "rootfs_size_mb has no live CLI equivalent, so partial lowering is refused");
  }
  const network = options.network;
  if (network === undefined) return argv;
  const known = new Set(["mode", "egress", "ports", "peers", "dns"]);
  const unknown = Object.keys(network).filter((key) => !known.has(key));
  if (unknown.length > 0) rejectLiveOption("network", `unknown fields: ${unknown.join(", ")}`);
  if ((network.mode ?? "none") !== "none") {
    rejectLiveOption("network.mode", "only the NIC-less `none` mode is supported");
  }
  if (network.peers && network.peers.length > 0) rejectLiveOption("network.peers", "the live CLI has no peer equivalent");
  if (network.dns !== undefined && network.dns !== null) rejectLiveOption("network.dns", "the live CLI has no DNS equivalent");
  if (network.egress === undefined || network.egress === null) return argv;
  if (Object.keys(network.egress).some((key) => key !== "allowlist") || !Array.isArray(network.egress.allowlist)) {
    rejectLiveOption("network.egress", "expected only an allowlist");
  }
  for (const entry of network.egress.allowlist) {
    if (Object.keys(entry).some((key) => key !== "host" && key !== "port")) {
      rejectLiveOption("network.egress", "entries must contain only host and port");
    }
    argv.push("--allow-host", formatAllowHost(entry.host, entry.port));
  }
  return argv;
}

export interface SandboxCommandsStartOptions {
  env?: Record<string, EnvValue | string>;
}

/** Options for the one-shot {@link Sandbox.exec}. */
export interface SandboxExecOptions {
  env?: Record<string, EnvValue | string>;
  /** Wall-clock timeout in seconds; the agent kills the process on overrun. */
  timeout?: number;
  /** Working directory for the spawned process. */
  cwd?: string;
}

/** Result of a one-shot {@link Sandbox.exec} call.
 *
 *  `exitCode` is the child's exit code (0 on success). `stdout`/`stderr`
 *  are captured strings — exec is a one-shot that *captures* the streams,
 *  the distinction from `commands.start` + `mvmctl machine proc wait`. */
export interface ExecResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

/** Snapshot of a {@link Sandbox}'s identity + mode (local; no VM round-trip).
 *  `id` is the live VM id when live, else the workload id; `buildMode` is
 *  `"dev"`/`"prod"` when live and `null` in record mode. */
export interface SandboxInfo {
  id: string;
  workloadId: string;
  buildMode: "dev" | "prod" | null;
  live: boolean;
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
 *  template's `build_mode` parsed from the `mvmctl machine run --up-json`
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

  static forSource(opts: {
    source: BootSource;
    workloadId: string;
    ttlSeconds: number;
    createArgs: string[];
    bootCommand: string[] | null;
    ports: PortForward[];
  }): LiveTransport {
    let mvmCliBin: string;
    try {
      mvmCliBin = resolveCliBin("Sandbox live mode");
    } catch (err) {
      throw new SandboxModeError(String(err instanceof Error ? err.message : err));
    }
    // Generate a short, validatable VM id. `mvmctl machine run` rejects
    // names that don't match its validator; alphanumerics with a
    // hyphen are safe.
    const suffix = randomHex(4);
    const slug = opts.workloadId
      .slice(0, 24)
      .toLowerCase()
      .replace(/[^a-z0-9-]/g, "-");
    const vmId = `sdk-${slug}-${suffix}`;

    const argv = ["machine", "run"];
    if (opts.ports.length === 0) argv.push("-d");
    argv.push(
      "--up-json",
      "--name",
      vmId,
      opts.source.kind === "manifest" ? "--manifest" : "--image",
      opts.source.value,
      ...opts.createArgs,
      "--ttl",
      `${opts.ttlSeconds}s`,
    );
    for (const port of opts.ports) {
      if (
        port.proto !== "tcp" ||
        port.transform !== "opaque" ||
        port.host_addr !== "127.0.0.1" ||
        port.guest_addr !== "127.0.0.1"
      ) {
        throw new SandboxModeError(
          "Sandbox live mode currently accepts only opaque TCP ingress bound to host and guest 127.0.0.1",
        );
      }
      argv.push("--port", `${port.host}:${port.guest}`);
    }
    if (opts.bootCommand !== null) argv.push("--", ...opts.bootCommand);
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    let result;
    try {
      result = child.spawnSync(mvmCliBin, argv, {
        encoding: "utf-8",
      });
    } catch (err) {
      throw new SandboxLiveError(
        `\`${mvmCliBin}\` not found on disk; ${cliResolutionHint()}: ${String(err)}`,
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
        `\`mvmctl machine run\` failed with exit code ${result.status}`,
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

  /** Attach to an already-running machine by name. Shells
   *  `mvmctl machine ls --json` and re-derives `build_mode` from the
   *  listing entry (the attach path never boots, so there is no
   *  `--up-json` envelope). Fails closed: only an explicit
   *  `build_mode === "dev"` unlocks the dev-only exec path — a prod /
   *  missing / unknown value resolves to `"prod"`. */
  static forExisting(vmId: string): LiveTransport {
    let mvmCliBin: string;
    try {
      mvmCliBin = resolveCliBin("Sandbox.connect");
    } catch (err) {
      throw new SandboxModeError(String(err instanceof Error ? err.message : err));
    }
    const argv = ["machine", "ls", "--json"];
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    let result;
    try {
      result = child.spawnSync(mvmCliBin, argv, { encoding: "utf-8" });
    } catch (err) {
      throw new SandboxLiveError(
        `\`${mvmCliBin}\` not found on disk; ${cliResolutionHint()}: ${String(err)}`,
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
        `\`mvmctl machine ls --json\` failed with exit code ${result.status}`,
        {
          argv: [mvmCliBin, ...argv],
          exitCode: result.status,
          stderr: result.stderr ?? "",
        },
      );
    }
    const buildMode = deriveAttachedBuildMode(result.stdout ?? "", vmId, [
      mvmCliBin,
      ...argv,
    ]);
    return new LiveTransport({ mvmCliBin, vmId, buildMode });
  }

  commandsStart(argv: string[], env: Record<string, EnvValue | string> | undefined): ProcessHandle {
    this.requireDev("commands.start", ["machine", "proc", "start", this.vmId, ...argv]);
    const shell = [this.mvmCliBin, "machine", "proc", "start", this.vmId];
    shell.push(...this.encodeEnvFlags(env, shell));
    shell.push("--", ...argv);
    return this.startProcess(shell);
  }

  private requireDev(operation: string, argv: string[]): void {
    if (this.buildMode !== "dev") {
      throw new SandboxDevOnly(
        `\`${operation}\` requires a dev-mode template; resolved template ` +
          `build_mode=${JSON.stringify(this.buildMode)}. The guest policy refuses ` +
          "this runtime operation on production templates.",
        { argv },
      );
    }
  }

  private startProcess(shell: string[]): ProcessHandle {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    let result;
    try {
      result = child.spawnSync(shell[0], shell.slice(1), { encoding: "utf-8" });
    } catch (err) {
      throw new SandboxLiveError(
        `\`${this.mvmCliBin}\` not found on disk; ${cliResolutionHint()}: ${String(err)}`,
        { argv: shell },
      );
    }
    if (result.error) throw new SandboxLiveError(`failed to spawn: ${result.error.message}`, { argv: shell });
    if (result.status !== 0) {
      throw new SandboxLiveError(
        `\`mvmctl machine proc start\` failed with exit code ${result.status}`,
        { argv: shell, exitCode: result.status, stderr: result.stderr ?? "" },
      );
    }
    const token = (result.stdout ?? "").trim();
    if (!token) {
      throw new SandboxLiveError("`mvmctl machine proc start` produced no pid_token on stdout", {
        argv: shell,
        stderr: result.stderr ?? "",
      });
    }
    return new ProcessHandle(this, token);
  }

  processWait(
    token: string,
    options: { timeout?: number; onEvent?: (event: ProcessStreamEvent) => void } = {},
  ): Promise<ProcessResult> {
    this.requireDev("process wait", ["machine", "proc", "wait", this.vmId, token]);
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const shell = [this.mvmCliBin, "machine", "proc", "wait", this.vmId, token];
    if (options.timeout !== undefined) shell.push("--timeout", String(Math.trunc(options.timeout)));
    return new Promise((resolve, reject) => {
      let proc: import("node:child_process").ChildProcessByStdio<
        null,
        import("node:stream").Readable,
        import("node:stream").Readable
      >;
      try {
        proc = child.spawn(shell[0], shell.slice(1), { stdio: ["ignore", "pipe", "pipe"] });
      } catch (err) {
        reject(new SandboxLiveError(`failed to spawn: ${String(err)}`, { argv: shell }));
        return;
      }
      const stdout: Buffer[] = [];
      const stderr: Buffer[] = [];
      proc.stdout.on("data", (chunk: Buffer) => {
        stdout.push(chunk);
        options.onEvent?.({ stream: "stdout", data: new Uint8Array(chunk) });
      });
      proc.stderr.on("data", (chunk: Buffer) => {
        stderr.push(chunk);
        options.onEvent?.({ stream: "stderr", data: new Uint8Array(chunk) });
      });
      proc.on("error", (error) => reject(new SandboxLiveError(`process wait failed: ${error.message}`, { argv: shell })));
      proc.on("close", (code) => resolve({
        exitCode: code ?? -1,
        stdout: Buffer.concat(stdout),
        stderr: Buffer.concat(stderr),
      }));
    });
  }

  processStdin(token: string, data: Uint8Array): void {
    this.requireDev("process stdin", ["machine", "proc", "stdin", this.vmId, token]);
    this.runBytes([this.mvmCliBin, "machine", "proc", "stdin", this.vmId, token], data);
  }

  processSignal(token: string, signum: number): void {
    if (!Number.isInteger(signum) || signum <= 0) throw new RangeError("signum must be a positive integer");
    this.requireDev("process signal", ["machine", "proc", "signal", this.vmId, token]);
    this.runShell([this.mvmCliBin, "machine", "proc", "signal", this.vmId, token, String(signum)]);
  }

  processKill(token: string): void {
    this.requireDev("process kill", ["machine", "proc", "kill", this.vmId, token]);
    this.runShell([this.mvmCliBin, "machine", "proc", "kill", this.vmId, token]);
  }

  /** Encode `env` into `-e KEY=VALUE` flags for `mvmctl machine proc start`,
   *  rejecting non-literal (secret) values — live mode forwards only
   *  literals; secrets are injected host-side via `--secret` on `machine run`. */
  private encodeEnvFlags(
    env: Record<string, EnvValue | string> | undefined,
    shellForErr: string[],
  ): string[] {
    const flags: string[] = [];
    if (!env) return flags;
    for (const [key, value] of Object.entries(env)) {
      if (typeof value === "string") {
        flags.push("-e", `${key}=${value}`);
      } else if (
        typeof value === "object" &&
        value !== null &&
        (value as { kind?: string }).kind === "literal"
      ) {
        flags.push("-e", `${key}=${(value as { value: string }).value}`);
      } else {
        throw new SandboxLiveError(
          `env ${JSON.stringify(key)} carries a non-literal value; live mode only ` +
            "forwards literal env vars (secrets must be injected via the host keystore " +
            "+ `--secret` on `mvmctl machine run`).",
          { argv: shellForErr },
        );
      }
    }
    return flags;
  }

  /** One-shot exec: `mvmctl machine proc start ... -- argv` → pid_token, then
   *  `mvmctl machine proc wait <token>` to capture stdout/stderr/exit. Refuses
   *  with {@link SandboxDevOnly} on a prod template (claim 4). */
  commandsExec(argv: string[], options: SandboxExecOptions = {}): ExecResult {
    if (this.buildMode !== "dev") {
      throw new SandboxDevOnly(
        `\`exec\` requires a dev-mode template; resolved template ` +
          `build_mode=${JSON.stringify(this.buildMode)}. The guest runtime ` +
          `profile and signed grant refuse DevOnly process control in prod — ` +
          `re-build the template with \`mvmctl template build --dev <name>\`, ` +
          `or use \`files.write\` to stage inputs into the running VM instead.`,
        { argv: ["machine", "proc", "start", this.vmId, ...argv] },
      );
    }
    // eslint-disable-next-line @typescript-eslint/no-require-imports

    // 1) `machine proc start` → pid_token on stdout.
    const startShell = [this.mvmCliBin, "machine", "proc", "start", this.vmId];
    startShell.push(...this.encodeEnvFlags(options.env, startShell));
    if (options.cwd !== undefined) startShell.push("--cwd", options.cwd);
    startShell.push("--", ...argv);

    let startResult;
    try {
      startResult = child.spawnSync(startShell[0], startShell.slice(1), {
        encoding: "utf-8",
      });
    } catch (err) {
      throw new SandboxLiveError(
        `\`${this.mvmCliBin}\` not found on disk; ${cliResolutionHint()}: ${String(err)}`,
        { argv: startShell },
      );
    }
    if (startResult.error) {
      throw new SandboxLiveError(`failed to spawn: ${startResult.error.message}`, {
        argv: startShell,
      });
    }
    if (startResult.status !== 0) {
      throw new SandboxLiveError(
        `\`mvmctl machine proc start\` failed with exit code ${startResult.status}`,
        {
          argv: startShell,
          exitCode: startResult.status,
          stderr: startResult.stderr ?? "",
        },
      );
    }
    const pidToken = (startResult.stdout ?? "").trim();
    if (!pidToken) {
      throw new SandboxLiveError(
        "`mvmctl machine proc start` produced no pid_token on stdout",
        { argv: startShell, stderr: startResult.stderr ?? "" },
      );
    }

    // 2) `machine proc wait <token>` → captured stdout/stderr/exit.
    const waitShell = [this.mvmCliBin, "machine", "proc", "wait", this.vmId, pidToken];
    if (options.timeout !== undefined) {
      waitShell.push("--timeout", String(Math.trunc(options.timeout)));
    }
    let waitResult;
    try {
      waitResult = child.spawnSync(waitShell[0], waitShell.slice(1), {
        encoding: "utf-8",
        // +5s slack so the agent's pgroup-kill (on --timeout overrun) lands
        // before spawnSync gives up; the agent enforces first.
        timeout:
          options.timeout !== undefined ? (options.timeout + 5) * 1000 : undefined,
      });
    } catch (err) {
      throw new SandboxLiveError(
        `\`${this.mvmCliBin}\` not found on disk; ${cliResolutionHint()}: ${String(err)}`,
        { argv: waitShell },
      );
    }
    if (waitResult.error) {
      throw new SandboxLiveError(
        `\`mvmctl machine proc wait\` failed: ${waitResult.error.message}`,
        { argv: waitShell },
      );
    }
    return {
      exitCode: waitResult.status ?? -1,
      stdout: waitResult.stdout ?? "",
      stderr: waitResult.stderr ?? "",
    };
  }

  private runBytes(shell: string[], data: Uint8Array): void {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const result = child.spawnSync(shell[0], shell.slice(1), { input: Buffer.from(data) });
    if (result.error) throw new SandboxLiveError(`failed to spawn: ${result.error.message}`, { argv: shell });
    if (result.status !== 0) {
      throw new SandboxLiveError(`\`${shell.join(" ")}\` failed with exit code ${result.status}`, {
        argv: shell,
        exitCode: result.status,
        stderr: result.stderr ? result.stderr.toString("utf-8") : "",
      });
    }
  }

  private runJson(shell: string[]): unknown {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const result = child.spawnSync(shell[0], shell.slice(1), { encoding: "utf-8" });
    if (result.error) throw new SandboxLiveError(`failed to spawn: ${result.error.message}`, { argv: shell });
    if (result.status !== 0) {
      throw new SandboxLiveError(`\`${shell.join(" ")}\` failed with exit code ${result.status}`, {
        argv: shell,
        exitCode: result.status,
        stderr: result.stderr ?? "",
      });
    }
    try {
      return JSON.parse(result.stdout ?? "");
    } catch (err) {
      throw new SandboxLiveError(`\`${shell.join(" ")}\` returned invalid JSON`, {
        argv: shell,
        stderr: String(err),
      });
    }
  }

  filesWrite(
    path: string,
    data: Uint8Array,
    options: { mode?: number; createParents?: boolean; followSymlinks?: boolean } = {},
  ): void {
    this.requireDev("files.write", ["machine", "fs", "write", this.vmId, path]);
    const shell = [this.mvmCliBin, "machine", "fs", "write", this.vmId, path, "--mode", String(options.mode ?? 0o644)];
    if (options.createParents) shell.push("--create-parents");
    if (options.followSymlinks) shell.push("--follow-symlinks");
    this.runBytes(shell, data);
  }

  filesRead(path: string, offset = 0, length = 16 * 1024 * 1024): Uint8Array {
    if (offset < 0 || length < 0) throw new RangeError("offset and length must be non-negative");
    this.requireDev("files.read", ["machine", "fs", "read", this.vmId, path]);
    const shell = [this.mvmCliBin, "machine", "fs", "read", this.vmId, path, "--offset", String(offset), "--length", String(length)];
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    let result;
    try {
      result = child.spawnSync(shell[0], shell.slice(1));
    } catch (err) {
      throw new SandboxLiveError(
        `\`${this.mvmCliBin}\` not found on disk; ${cliResolutionHint()}: ${String(err)}`,
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
        `\`mvmctl machine fs read\` failed with exit code ${result.status}`,
        {
          argv: shell,
          exitCode: result.status,
          stderr: result.stderr ? result.stderr.toString("utf-8") : "",
        },
      );
    }
    return new Uint8Array(result.stdout ?? Buffer.alloc(0));
  }

  filesList(path: string): FsEntry[] {
    this.requireDev("files.list", ["machine", "fs", "ls", this.vmId, path]);
    const parsed = this.runJson([this.mvmCliBin, "machine", "fs", "ls", this.vmId, path, "--json"]);
    if (!Array.isArray(parsed)) throw new SandboxLiveError("filesystem listing must be an array");
    return parsed as FsEntry[];
  }

  filesStat(path: string, followSymlinks = true): FsStat {
    this.requireDev("files.stat", ["machine", "fs", "stat", this.vmId, path]);
    const shell = [this.mvmCliBin, "machine", "fs", "stat", this.vmId, path, "--json"];
    if (!followSymlinks) shell.push("--no-follow");
    const parsed = this.runJson(shell);
    if (typeof parsed !== "object" || parsed === null) throw new SandboxLiveError("filesystem stat must be an object");
    return parsed as FsStat;
  }

  filesMkdir(path: string, parents = false, mode = 0o755): void {
    this.requireDev("files.mkdir", ["machine", "fs", "mkdir", this.vmId, path]);
    const shell = [this.mvmCliBin, "machine", "fs", "mkdir", this.vmId, path, "--mode", String(mode)];
    if (parents) shell.push("--parents");
    this.runShell(shell);
  }

  filesRemove(path: string, recursive = false): void {
    this.requireDev("files.remove", ["machine", "fs", "rm", this.vmId, path]);
    const shell = [this.mvmCliBin, "machine", "fs", "rm", this.vmId, path];
    if (recursive) shell.push("--recursive");
    this.runShell(shell);
  }

  filesMove(source: string, destination: string): void {
    this.requireDev("files.move", ["machine", "fs", "mv", this.vmId, source, destination]);
    this.runShell([this.mvmCliBin, "machine", "fs", "mv", this.vmId, source, destination]);
  }

  cp(source: string, destination: string): void {
    this.requireDev("copy", ["machine", "cp", source, destination]);
    const shell = [this.mvmCliBin, "machine", "cp", source, destination];
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    let result;
    try {
      result = child.spawnSync(shell[0], shell.slice(1));
    } catch (err) {
      throw new SandboxLiveError(
        `\`${this.mvmCliBin}\` not found on disk; ${cliResolutionHint()}: ${String(err)}`,
        { argv: shell },
      );
    }
    if (result.error) {
      throw new SandboxLiveError(`failed to spawn: ${result.error.message}`, { argv: shell });
    }
    if (result.status !== 0) {
      throw new SandboxLiveError(
        `\`mvmctl machine cp\` failed with exit code ${result.status}`,
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
    // `--yes` skips the interactive confirmation prompt; the sandbox tears down
    // non-interactively.
    const shell = [this.mvmCliBin, "machine", "stop", this.vmId, "--yes"];
    // eslint-disable-next-line @typescript-eslint/no-require-imports
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
          `mvm-sdk live: \`mvmctl machine stop ${this.vmId}\` exited with ${result.status}: ${result.stderr ?? ""}`,
        );
      }
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error(`mvm-sdk live: failed to spawn \`mvmctl machine stop\`: ${String(err)}`);
    }
  }

  private runShell(shell: string[]): void {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    let result;
    try {
      result = child.spawnSync(shell[0], shell.slice(1), { encoding: "utf-8" });
    } catch (err) {
      throw new SandboxLiveError(
        `\`${this.mvmCliBin}\` not found on disk; ${cliResolutionHint()}: ${String(err)}`,
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

/** Parse an `mvmctl machine run --up-json` stdout envelope. The envelope is
 *  a single JSON line; trailing newlines tolerated. Throws
 *  `SandboxLiveError` on any shape violation. Exported for tests. */
export function parseUpEnvelope(
  stdout: string,
  argv: string[],
): { vm_id: string; build_mode: "dev" | "prod" } {
  const line = stdout.trim();
  if (!line) {
    throw new SandboxLiveError(
      "`mvmctl machine run --up-json` produced empty stdout — expected a JSON envelope.",
      { argv },
    );
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(line);
  } catch (err) {
    throw new SandboxLiveError(
      `\`mvmctl machine run --up-json\` stdout is not valid JSON: ${String(err)}`,
      { argv, stderr: line },
    );
  }
  if (typeof parsed !== "object" || parsed === null) {
    throw new SandboxLiveError(
      "`mvmctl machine run --up-json` envelope must be a JSON object.",
      { argv },
    );
  }
  const obj = parsed as Record<string, unknown>;
  if (obj.schema_version !== LiveTransport.SCHEMA_VERSION) {
    throw new SandboxLiveError(
      `\`mvmctl machine run --up-json\` envelope schema_version=${JSON.stringify(obj.schema_version)}; ` +
        `SDK supports ${LiveTransport.SCHEMA_VERSION}`,
      { argv },
    );
  }
  if (typeof obj.vm_id !== "string" || obj.vm_id.length === 0) {
    throw new SandboxLiveError(
      "`mvmctl machine run --up-json` envelope is missing a non-empty `vm_id` field.",
      { argv },
    );
  }
  if (obj.build_mode !== "dev" && obj.build_mode !== "prod") {
    throw new SandboxLiveError(
      `\`mvmctl machine run --up-json\` envelope build_mode=${JSON.stringify(obj.build_mode)}; ` +
        "expected 'dev' or 'prod'.",
      { argv },
    );
  }
  return { vm_id: obj.vm_id, build_mode: obj.build_mode };
}

/** Re-derive `build_mode` for an attached machine from
 *  `mvmctl machine ls --json` output. The listing is a JSON array of
 *  machine entries matched on `name`. Fails closed: only an explicit
 *  `"dev"` returns `"dev"`; a `"prod"` / missing / unknown value
 *  returns `"prod"`, so a stale or hostile listing can never *open*
 *  the dev-only exec path. Throws `SandboxLiveError` when `vmId` is
 *  absent from the listing. Exported for tests. */
export function deriveAttachedBuildMode(
  stdout: string,
  vmId: string,
  argv: string[],
): "dev" | "prod" {
  const line = stdout.trim();
  if (!line) {
    throw new SandboxLiveError(
      `\`mvmctl machine ls --json\` produced no output; cannot attach to ${JSON.stringify(vmId)}.`,
      { argv },
    );
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(line);
  } catch (err) {
    throw new SandboxLiveError(
      `\`mvmctl machine ls --json\` stdout is not valid JSON: ${String(err)}`,
      { argv, stderr: line },
    );
  }
  if (!Array.isArray(parsed)) {
    throw new SandboxLiveError("`mvmctl machine ls --json` must be a JSON array.", {
      argv,
    });
  }
  for (const entry of parsed) {
    if (
      typeof entry === "object" &&
      entry !== null &&
      (entry as { name?: unknown }).name === vmId
    ) {
      return (entry as { build_mode?: unknown }).build_mode === "dev" ? "dev" : "prod";
    }
  }
  throw new SandboxLiveError(
    `no machine named ${JSON.stringify(vmId)} in \`mvmctl machine ls\`; is it running?`,
    { argv },
  );
}

function randomHex(byteCount: number): string {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
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
 *  `MVM_SDK_MODE=live` it shells `mvmctl machine run` to boot a real
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

  /** Stable identifier: the live VM id when live, else the workload id. */
  get id(): string {
    return this._live !== null ? this._live.vmId : this.workloadId;
  }

  /** Local snapshot of this sandbox's identity + mode (no VM round-trip). */
  info(): SandboxInfo {
    return {
      id: this.id,
      workloadId: this.workloadId,
      buildMode: this._live !== null ? this._live.buildMode : null,
      live: this._live !== null,
    };
  }

  static create(sourceInput: SandboxSource, options: SandboxCreateOptions = {}): Sandbox {
    const mode = resolveMode();
    if (recording !== null || isLiveActive()) {
      throw new Error(
        "a Sandbox session is already active — call Sandbox.kill() before creating another. " +
          "Per the SDK plan's 'v1 scope: one app per workload' decision, a script may construct at most one Sandbox.",
      );
    }
    const source = bootSource(sourceInput);
    const command = options.command;
    if (command !== undefined && (command.length === 0 || !command.every((arg) => typeof arg === "string" && arg.length > 0))) {
      throw new TypeError("command must be a non-empty string array");
    }
    let ttlSeconds = parseTtl(options.ttl);
    if (ttlSeconds === null) {
      ttlSeconds = DEFAULT_TTL_SECONDS;
    }
    const wid = options.workloadId ?? source.value;

    if (mode === "live") {
      const live = LiveTransport.forSource({
        source,
        workloadId: wid,
        ttlSeconds,
        createArgs: lowerLiveOptions(options),
        bootCommand: command ? [...command] : null,
        ports: options.network?.ports ?? [],
      });
      const sb = new Sandbox(wid, live);
      liveSandbox = sb;
      return sb;
    }

    // record mode (existing path).
    const create: SandboxCreateWire = {
      ...(source.kind === "manifest"
        ? { template: source.value }
        : { image: source.value }),
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
      ops: command ? [{ kind: "command_start", argv: [...command], env: {} }] : [],
    };
    return new Sandbox(wid, null);
  }

  /** Attach to an already-running machine by name, from a fresh
   *  process. Unlike {@link Sandbox.create}, `connect` never boots a
   *  VM — so it re-derives the machine's `build_mode` from
   *  `mvmctl machine ls --json` (see {@link LiveTransport.forExisting})
   *  rather than an `--up-json` envelope.
   *
   *  The dev-only exec guard is inherited unchanged: the derived
   *  `build_mode` is never defaulted to `"dev"` — a prod / missing /
   *  unknown value resolves to `"prod"`, so `connect(...).exec(...)` /
   *  `.commands.start(...)` on a sealed prod machine throws
   *  {@link SandboxDevOnly} exactly like the create path (security
   *  claim 4).
   *
   *  Always a live operation: resolves the mvm CLI regardless of
   *  `MVM_SDK_MODE`. Throws {@link SandboxLiveError} when no machine of
   *  that name is listed. */
  static connect(id: string): Sandbox {
    if (typeof id !== "string" || id.length === 0) {
      throw new TypeError("Sandbox.connect requires a non-empty machine id");
    }
    if (recording !== null || isLiveActive()) {
      throw new Error(
        "a Sandbox session is already active — call Sandbox.kill() before attaching to another machine.",
      );
    }
    const live = LiveTransport.forExisting(id);
    const sb = new Sandbox(id, live);
    liveSandbox = sb;
    return sb;
  }

  /** One-shot: run `argv` inside the sandbox, capturing stdout / stderr /
   *  exit into an {@link ExecResult}. Convenience over `commands.start` +
   *  `mvmctl machine proc wait`. Refuses with `SandboxDevOnly` on a prod template
   *  (claim 4).
   *
   *  Live mode only: in record mode this throws `SandboxModeError` — the
   *  recording's lowering doesn't materialise return values, so use
   *  `commands.start(argv)` to append an op instead. */
  exec(argv: string[], options: SandboxExecOptions = {}): ExecResult {
    if (!Array.isArray(argv) || !argv.every((a) => typeof a === "string")) {
      throw new TypeError("exec argv must be a string[]");
    }
    if (argv.length === 0) {
      throw new RangeError("exec argv must be non-empty");
    }
    if (this._live === null) {
      throw new SandboxModeError(
        "`Sandbox.exec` is a live-mode operation; under MVM_SDK_MODE=record use " +
          "`commands.start(argv)` to append an op (return values are materialised " +
          "when the recording is lowered, not at call time).",
      );
    }
    return this._live.commandsExec(argv, options);
  }

  /** Run shell syntax in a live development sandbox. */
  shell(command: string, options: SandboxExecOptions = {}): ExecResult {
    if (typeof command !== "string" || command.length === 0) {
      throw new TypeError("shell command must be a non-empty string");
    }
    return this.exec(["/bin/sh", "-lc", command], options);
  }

  /** Copy a host file into the running sandbox at `guestPath`.
   *
   *  Shells `mvmctl machine cp <hostPath> <vm>:<guestPath>` — the host file
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
   *  Shells `mvmctl machine cp <vm>:<guestPath> <hostPath>` — the guest file
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

  /** Refuse dynamic ingress changes after admission.
   *
   *  Declare the mapping in `network.ports` before {@link Sandbox.create}; the
   *  host binds only listeners present in the signed admission plan. */
  forward(hostPort: number, guestPort: number): void {
    for (const [label, p] of [
      ["hostPort", hostPort],
      ["guestPort", guestPort],
    ] as const) {
      if (!Number.isInteger(p) || p <= 0 || p >= 65536) {
        throw new RangeError(`${label} must be an integer in 1..65535`);
      }
    }
    throw new SandboxModeError(
      "dynamic `Sandbox.forward` is retired; declare ingress with " +
        "`Sandbox.create(..., { network: mvm.network({ ports: [...] }) })` before boot",
    );
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

  // `await using sb = Sandbox.create(...)` — the async-scope counterpart,
  // mirroring Python's `async with`. (`await sb.exec(...)` already works:
  // exec is synchronous, and awaiting a non-promise is a passthrough.)
  async [Symbol.asyncDispose](): Promise<void> {
    this.kill();
  }
}

export class SandboxCommands {
  private readonly sandbox: Sandbox;

  constructor(sandbox: Sandbox) {
    this.sandbox = sandbox;
  }

  start(argv: string[], options: SandboxCommandsStartOptions = {}): ProcessHandle | undefined {
    if (!Array.isArray(argv) || !argv.every((a) => typeof a === "string")) {
      throw new TypeError("argv must be a string[]");
    }
    if (argv.length === 0) {
      throw new RangeError("argv must be non-empty");
    }
    if (this.sandbox._live !== null) {
      return this.sandbox._live.commandsStart([...argv], options.env);
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

  write(
    path: string,
    content: Uint8Array | string,
    options: { mode?: number; createParents?: boolean; followSymlinks?: boolean } = {},
  ): void {
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
      this.sandbox._live.filesWrite(path, bytes, options);
      return;
    }
    requireRecording().ops.push({
      kind: "files_write",
      path,
      bytes_b64: bytesToBase64(bytes),
    });
  }

  read(path: string, offset = 0, length = 16 * 1024 * 1024): Uint8Array {
    if (this.sandbox._live === null) {
      throw new SandboxModeError("`files.read` is a live-mode operation; record mode cannot resolve guest state.");
    }
    return this.sandbox._live.filesRead(path, offset, length);
  }

  list(path: string): FsEntry[] {
    if (this.sandbox._live === null) {
      throw new SandboxModeError("`files.list` is a live-mode operation; record mode cannot resolve guest state.");
    }
    return this.sandbox._live.filesList(path);
  }

  stat(path: string, followSymlinks = true): FsStat {
    if (this.sandbox._live === null) {
      throw new SandboxModeError("`files.stat` is a live-mode operation; record mode cannot resolve guest state.");
    }
    return this.sandbox._live.filesStat(path, followSymlinks);
  }

  mkdir(path: string, parents = false, mode = 0o755): void {
    if (this.sandbox._live === null) {
      throw new SandboxModeError("`files.mkdir` is a live-mode operation; record mode cannot mutate guest state.");
    }
    this.sandbox._live.filesMkdir(path, parents, mode);
  }

  remove(path: string, recursive = false): void {
    if (this.sandbox._live === null) {
      throw new SandboxModeError("`files.remove` is a live-mode operation; record mode cannot mutate guest state.");
    }
    this.sandbox._live.filesRemove(path, recursive);
  }

  move(source: string, destination: string): void {
    if (this.sandbox._live === null) {
      throw new SandboxModeError("`files.move` is a live-mode operation; record mode cannot mutate guest state.");
    }
    this.sandbox._live.filesMove(source, destination);
  }
}
