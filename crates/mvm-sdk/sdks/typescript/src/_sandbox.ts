/**
 * Sandbox — the imperative runtime SDK.
 *
 * TypeScript mirror of `sdks/python/mvm/_sandbox.py`. The decorator surface
 * (`mvm.app({...})((fn))`) is static; the host parses the source without
 * running it. The runtime surface (`Sandbox.create(...)`) is imperative: the
 * host *does* run the user's module, with the SDK configured either to record
 * each call into a {@link RuntimeRecordingWire} or to drive a real microVM,
 * depending on the active mode.
 *
 * - `MVM_SDK_MODE=record`: every `Sandbox` call appends to an in-process
 *   recording; the Rust lowering at `mvm_sdk::runtime::compile_recording`
 *   produces a Workload.
 * - `MVM_SDK_MODE=live`: every `Sandbox` call goes to the host library,
 *   loaded in-process (`machine.run`, `guest.proc.*`, `guest.fs.*`,
 *   `machine.stop`). No process is spawned; {@link LiveTransport} below is the
 *   only code that talks to the library.
 *
 * `MVM_SDK_MODE=plan` remains an error here — the host CLI's
 * `mvmctl run --mode plan` verb runs Sandbox scripts under that transport;
 * the SDK itself never enters "plan" mode directly.
 */

import type { EnvValue, Network, PortForward, Resources } from "./ir/workload.js";
import type {
  RuntimeFsEntry,
  RuntimeFsStat,
} from "./runtime/runtime.js";
import {
  fromBase64,
  startGuestProcess,
  toBase64,
  waitGuestProcess,
  type ReplyFailure,
} from "./_guest.js";
import { call } from "./_hostlib.js";
import {
  GUEST_CP,
  GUEST_FS_LIST,
  GUEST_FS_MKDIR,
  GUEST_FS_READ,
  GUEST_FS_REMOVE,
  GUEST_FS_RENAME,
  GUEST_FS_STAT,
  GUEST_FS_WRITE,
  GUEST_PROC_KILL,
  GUEST_PROC_SIGNAL,
  GUEST_PROC_STDIN,
  MACHINE_INVENTORY,
  MACHINE_RUN,
  MACHINE_STOP,
} from "./hostabi/methods.js";

// This package is ESM ("type": "module"), so `require` does not exist at
// runtime. These node builtins are imported statically; a lazy `require` here
// throws `ReferenceError: require is not defined` for every consumer of the
// built artifact.
import * as crypto from "node:crypto";
import * as fs from "node:fs";

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


/** Raised when `MVM_SDK_MODE` is unsupported by this build, or a live-mode
 *  request asks for something the in-process launch cannot do. */
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

/** Raised for a live-mode failure the SDK itself detects: a machine that is
 *  not there, a reply the library should not have sent, an env value live
 *  mode cannot forward. A failure the host library reports arrives instead
 *  as the typed `HostLibraryError` subclass its `code` names. */
export class SandboxLiveError extends Error {
  /** A short machine-readable reason, when the SDK has one. */
  readonly code: string | undefined;

  constructor(message: string, opts: { code?: string } = {}) {
    super(message);
    this.name = "SandboxLiveError";
    this.code = opts.code;
  }
}

/** Raised when the SDK refuses a DevOnly live operation because the machine
 *  was admitted as production.
 *
 *  The guest agent's runtime profile and signed grant refuse DevOnly process
 *  and filesystem requests in production, and the agent fails closed on its
 *  own. The SDK refuses first, before any library call, so a sealed machine
 *  never sees the attempt at all. `kill` routes to `machine.stop`, which is
 *  available in production too. */
export class SandboxDevOnly extends SandboxLiveError {
  constructor(message: string) {
    super(message, { code: "DEV_ONLY" });
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

  /** Collect the process's output until it ends. `onEvent` sees every chunk
   *  in arrival order, before this settles. The work is synchronous; the
   *  promise is kept so existing `await` and `.then` callers are unaffected. */
  wait(options: {
    timeout?: number;
    onEvent?: (event: ProcessStreamEvent) => void;
  } = {}): Promise<ProcessResult> {
    try {
      return Promise.resolve(this.transport.processWait(this.token, options));
    } catch (err) {
      return Promise.reject(err);
    }
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
export { MVM_SDK_MODE_ENV, MVM_SDK_OUT_PATH_ENV, MVM_SDK_RUN_PROFILE_ENV } from "./_env/vars.js";
import { MVM_SDK_MODE_ENV, MVM_SDK_OUT_PATH_ENV, MVM_SDK_RUN_PROFILE_ENV } from "./_env/vars.js";


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
  // Live mode needs the host library, but it is located on the first call
  // rather than here: that call reports a missing library as a typed
  // `MvmTransportError` naming every place it looked.
  if (norm === "live") return "live";
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

/** One admitted egress destination, as `machine.run` takes it. */
interface EgressTarget {
  host: string;
  port: number;
}

function egressTarget(host: unknown, port: unknown): EgressTarget {
  const wildcards = new Set(["*", "0.0.0.0", "::", "0.0.0.0/0", "::/0", "[::]"]);
  if (typeof host !== "string" || host.length === 0 || wildcards.has(host)) {
    return rejectLiveOption("network.egress", "allowlist hosts must be specific");
  }
  if (!Number.isInteger(port) || (port as number) < 1 || (port as number) > 65535) {
    return rejectLiveOption("network.egress", "allowlist ports must be 1..65535");
  }
  // The library takes the bare address; brackets are only URL syntax.
  const bare = host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
  return { host: bare, port: port as number };
}

/** Refuse what live mode cannot represent, and lower the egress allowlist. */
function lowerLiveOptions(options: SandboxCreateOptions): EgressTarget[] {
  const egress: EgressTarget[] = [];
  if (options.env !== undefined && Object.keys(options.env).length > 0) {
    rejectLiveOption(
      "env",
      "persistent creation cannot deliver environment; declare it in the image or pass env to Sandbox.commands.start",
    );
  }
  if (options.include && options.include.length > 0) {
    rejectLiveOption("include", "the in-process launch has no source-bundle equivalent");
  }
  if (options.tags && Object.keys(options.tags).length > 0) {
    rejectLiveOption("tags", "the in-process launch has no tag equivalent");
  }
  if (options.resources !== undefined) {
    rejectLiveOption("resources", "rootfs_size_mb has no in-process launch equivalent, so partial lowering is refused");
  }
  const network = options.network;
  if (network === undefined) return egress;
  const known = new Set(["mode", "egress", "ports", "peers", "dns"]);
  const unknown = Object.keys(network).filter((key) => !known.has(key));
  if (unknown.length > 0) rejectLiveOption("network", `unknown fields: ${unknown.join(", ")}`);
  if ((network.mode ?? "none") !== "none") {
    rejectLiveOption("network.mode", "only the NIC-less `none` mode is supported");
  }
  if (network.peers && network.peers.length > 0) rejectLiveOption("network.peers", "the in-process launch has no peer equivalent");
  if (network.dns !== undefined && network.dns !== null) rejectLiveOption("network.dns", "the in-process launch has no DNS equivalent");
  if (network.egress === undefined || network.egress === null) return egress;
  if (Object.keys(network.egress).some((key) => key !== "allowlist") || !Array.isArray(network.egress.allowlist)) {
    rejectLiveOption("network.egress", "expected only an allowlist");
  }
  for (const entry of network.egress.allowlist) {
    if (Object.keys(entry).some((key) => key !== "host" && key !== "port")) {
      rejectLiveOption("network.egress", "entries must contain only host and port");
    }
    egress.push(egressTarget(entry.host, entry.port));
  }
  return egress;
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
 *  `exitCode` is the process's exit code (0 on success; 128+N when killed by
 *  signal N; 124 when the timeout stopped it). `stdout`/`stderr` are the
 *  captured output decoded as UTF-8, with invalid sequences replaced. */
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

/** Live-mode transport: every call goes to the host library in-process.
 *
 *  Created by `Sandbox.create(...)` / `Sandbox.connect(...)` when live. Holds
 *  the machine's name and the `build_mode` the library reported for it; the
 *  SDK uses that to refuse DevOnly operations on a production machine before
 *  any guest traffic. */
export class LiveTransport {
  readonly vmId: string;
  readonly buildMode: "dev" | "prod";
  private killed = false;
  private readonly fail: ReplyFailure = (message) => new SandboxLiveError(message);

  constructor(opts: { vmId: string; buildMode: "dev" | "prod" }) {
    this.vmId = opts.vmId;
    this.buildMode = opts.buildMode;
  }

  /** Boot a transient machine with `machine.run` and attach to it. */
  static forSource(opts: {
    source: BootSource;
    workloadId: string;
    ttlSeconds: number;
    egress: EgressTarget[];
    bootCommand: string[] | null;
    ports: PortForward[];
  }): LiveTransport {
    if (opts.source.kind === "manifest") {
      throw new SandboxModeError(
        `Sandbox live mode boots an image, and ${JSON.stringify(opts.source.value)} names a ` +
          "template: the in-process launch has no template source yet. Pass " +
          "`{ image: <oci-ref | absolute path | flake:<ref>#<attr>> }` instead.",
      );
    }
    const profile = runProfile();
    const ports = opts.ports.map((port) => {
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
      return `${port.host}:${port.guest}`;
    });
    // A short name the launcher's validator accepts: lowercase alphanumerics
    // and hyphens, unique per boot.
    const slug = opts.workloadId
      .slice(0, 24)
      .toLowerCase()
      .replace(/[^a-z0-9-]/g, "-");
    const request: Record<string, unknown> = {
      image: opts.source.value,
      mode: "transient",
      name: `sdk-${slug}-${randomHex(4)}`,
      ttl_seconds: opts.ttlSeconds,
    };
    if (profile !== undefined) request.profile = profile;
    if (ports.length > 0) request.ports = ports;
    if (opts.egress.length > 0) request.egress = opts.egress;
    if (opts.bootCommand !== null) request.command = opts.bootCommand;
    const reply = call(MACHINE_RUN, request);
    return new LiveTransport(parseRunReply(reply));
  }

  /** Attach to an already-running machine by name.
   *
   *  The attach path never boots, so `build_mode` comes from the host's
   *  machine inventory. Fails closed: only an explicit `"dev"` unlocks the
   *  DevOnly surface. */
  static forExisting(vmId: string): LiveTransport {
    const records = call(MACHINE_INVENTORY);
    return new LiveTransport({ vmId, buildMode: deriveAttachedBuildMode(records, vmId) });
  }

  private requireDev(operation: string): void {
    if (this.buildMode !== "dev") {
      throw new SandboxDevOnly(
        `\`${operation}\` requires a dev-mode machine; ${JSON.stringify(this.vmId)} was admitted ` +
          `with build_mode=${JSON.stringify(this.buildMode)}. The guest runtime profile and ` +
          "signed grant refuse DevOnly process and filesystem control in production — boot a " +
          "dev image, or stage inputs into the image instead.",
      );
    }
  }

  commandsStart(argv: string[], env: Record<string, EnvValue | string> | undefined): ProcessHandle {
    this.requireDev("commands.start");
    const token = startGuestProcess(this.vmId, argv, { env: literalEnv(env) }, this.fail);
    return new ProcessHandle(this, token);
  }

  /** One-shot exec: start `argv`, then collect it through its output stream. */
  commandsExec(argv: string[], options: SandboxExecOptions = {}): ExecResult {
    this.requireDev("exec");
    const token = startGuestProcess(
      this.vmId,
      argv,
      { env: literalEnv(options.env), cwd: options.cwd },
      this.fail,
    );
    const result = waitGuestProcess(this.vmId, token, { timeout: options.timeout }, this.fail);
    const decoder = new TextDecoder("utf-8");
    return {
      exitCode: result.exitCode,
      stdout: decoder.decode(result.stdout),
      stderr: decoder.decode(result.stderr),
    };
  }

  processWait(
    token: string,
    options: { timeout?: number; onEvent?: (event: ProcessStreamEvent) => void } = {},
  ): ProcessResult {
    this.requireDev("process wait");
    return waitGuestProcess(this.vmId, token, options, this.fail);
  }

  processStdin(token: string, data: Uint8Array): void {
    this.requireDev("process stdin");
    call(GUEST_PROC_STDIN, { id: this.vmId, token, data_b64: toBase64(data) });
  }

  processSignal(token: string, signum: number): void {
    if (!Number.isInteger(signum) || signum <= 0) throw new RangeError("signum must be a positive integer");
    this.requireDev("process signal");
    call(GUEST_PROC_SIGNAL, { id: this.vmId, token, signum });
  }

  processKill(token: string): void {
    this.requireDev("process kill");
    call(GUEST_PROC_KILL, { id: this.vmId, token });
  }

  filesWrite(
    path: string,
    data: Uint8Array,
    options: { mode?: number; createParents?: boolean; followSymlinks?: boolean } = {},
  ): void {
    this.requireDev("files.write");
    // Both flags are always sent, as the Python SDK sends them, so the two
    // languages make byte-identical requests for the same write.
    call(GUEST_FS_WRITE, {
      id: this.vmId,
      path,
      data_b64: toBase64(data),
      mode: options.mode ?? 0o644,
      create_parents: options.createParents ?? false,
      follow_symlinks: options.followSymlinks ?? false,
    });
  }

  filesRead(path: string, offset = 0, length = 16 * 1024 * 1024): Uint8Array {
    if (offset < 0 || length < 0) throw new RangeError("offset and length must be non-negative");
    this.requireDev("files.read");
    const reply = call(GUEST_FS_READ, { id: this.vmId, path, offset, length });
    return fromBase64(reply?.data_b64, "guest.fs.read's data_b64", this.fail);
  }

  filesList(path: string): FsEntry[] {
    this.requireDev("files.list");
    const reply = call(GUEST_FS_LIST, { id: this.vmId, path });
    if (!Array.isArray(reply?.entries)) {
      throw new SandboxLiveError("guest.fs.list returned no entries array");
    }
    return reply.entries as FsEntry[];
  }

  filesStat(path: string, followSymlinks = true): FsStat {
    this.requireDev("files.stat");
    const reply = call(GUEST_FS_STAT, { id: this.vmId, path, follow_symlinks: followSymlinks });
    if (typeof reply !== "object" || reply === null || Array.isArray(reply)) {
      throw new SandboxLiveError("guest.fs.stat must return an object");
    }
    return reply as FsStat;
  }

  filesMkdir(path: string, parents = false, mode = 0o755): void {
    this.requireDev("files.mkdir");
    call(GUEST_FS_MKDIR, { id: this.vmId, path, mode, parents });
  }

  filesRemove(path: string, recursive = false): void {
    this.requireDev("files.remove");
    call(GUEST_FS_REMOVE, { id: this.vmId, path, recursive });
  }

  filesMove(source: string, destination: string): void {
    this.requireDev("files.move");
    call(GUEST_FS_RENAME, { id: this.vmId, from: source, to: destination });
  }

  copy(direction: "host_to_guest" | "guest_to_host", hostPath: string, guestPath: string): void {
    this.requireDev("copy");
    call(GUEST_CP, { id: this.vmId, direction, host_path: hostPath, guest_path: guestPath });
  }

  /** Stop the machine. Idempotent, and never throws: this is the cleanup
   *  path, and a failure here usually means the TTL reaper got there first. */
  kill(): void {
    if (this.killed) return;
    this.killed = true;
    try {
      call(MACHINE_STOP, { id: this.vmId });
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error(
        `mvm-sdk live: stopping ${JSON.stringify(this.vmId)} failed: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }
}

/** Forward only literal env values; a secret must be bound on the host, and
 *  handing its reference to a guest process would leak nothing useful and
 *  hide the mistake. */
function literalEnv(env: Record<string, EnvValue | string> | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!env) return out;
  for (const [key, value] of Object.entries(env)) {
    if (typeof value === "string") {
      out[key] = value;
    } else if (
      typeof value === "object" &&
      value !== null &&
      (value as { kind?: string }).kind === "literal"
    ) {
      out[key] = (value as { value: string }).value;
    } else {
      throw new SandboxLiveError(
        `env ${JSON.stringify(key)} carries a non-literal value; live mode only forwards ` +
          "literal env vars. Bind secrets on the host keystore so the substitution " +
          "endpoint injects them, rather than passing them to a guest process.",
      );
    }
  }
  return out;
}

/** The security profile `mvmctl run` handed down, validated. */
function runProfile(): string | undefined {
  const raw = process.env[MVM_SDK_RUN_PROFILE_ENV];
  const profile = raw?.trim().toLowerCase();
  if (
    profile !== undefined &&
    profile !== "restrictive" &&
    profile !== "standard" &&
    profile !== "dev" &&
    profile !== "permissive"
  ) {
    throw new SandboxModeError(
      `${MVM_SDK_RUN_PROFILE_ENV}=${JSON.stringify(profile)} is invalid — expected one of: ` +
        "restrictive, standard, dev, permissive",
    );
  }
  return profile;
}

/** Read the machine name and build mode out of a `machine.run` reply.
 *  Throws {@link SandboxLiveError} on any shape violation. Exported for tests. */
export function parseRunReply(reply: unknown): { vmId: string; buildMode: "dev" | "prod" } {
  if (typeof reply !== "object" || reply === null) {
    throw new SandboxLiveError("machine.run returned no reply object");
  }
  const { machine, build_mode: buildMode } = reply as { machine?: unknown; build_mode?: unknown };
  const name = (machine as { name?: unknown } | null | undefined)?.name;
  if (typeof name !== "string" || name.length === 0) {
    throw new SandboxLiveError("machine.run's reply names no machine");
  }
  if (buildMode !== "dev" && buildMode !== "prod") {
    throw new SandboxLiveError(
      `machine.run's reply has build_mode=${JSON.stringify(buildMode)}; expected "dev" or "prod"`,
    );
  }
  return { vmId: name, buildMode };
}

/** Re-derive `build_mode` for an attached machine from `machine.inventory`
 *  records, matched on `name`. Fails closed: only an explicit `"dev"` returns
 *  `"dev"`, so a stale or hostile record can never *open* the DevOnly path.
 *  Throws {@link SandboxLiveError} when `vmId` is absent. Exported for tests. */
export function deriveAttachedBuildMode(records: unknown, vmId: string): "dev" | "prod" {
  if (!Array.isArray(records)) {
    throw new SandboxLiveError("machine.inventory must return an array");
  }
  for (const entry of records) {
    if (
      typeof entry === "object" &&
      entry !== null &&
      (entry as { name?: unknown }).name === vmId
    ) {
      return (entry as { build_mode?: unknown }).build_mode === "dev" ? "dev" : "prod";
    }
  }
  throw new SandboxLiveError(
    `no machine named ${JSON.stringify(vmId)} in the host's machine inventory; is it running?`,
    { code: "NOT_FOUND" },
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
 *  `MVM_SDK_MODE=live` it boots a real microVM through the host
 *  library's `machine.run` and stashes the resulting handle on
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
        egress: lowerLiveOptions(options),
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
   *  VM — so it re-derives the machine's `build_mode` from the host's
   *  machine inventory (see {@link LiveTransport.forExisting}) rather
   *  than a `machine.run` reply.
   *
   *  The dev-only exec guard is inherited unchanged: the derived
   *  `build_mode` is never defaulted to `"dev"` — a prod / missing /
   *  unknown value resolves to `"prod"`, so `connect(...).exec(...)` /
   *  `.commands.start(...)` on a sealed prod machine throws
   *  {@link SandboxDevOnly} exactly like the create path (security
   *  claim 4).
   *
   *  Always a live operation, regardless of `MVM_SDK_MODE`. Throws
   *  {@link SandboxLiveError} when no machine of that name is listed. */
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
   *  `ProcessHandle.wait`. Refuses with `SandboxDevOnly` on a production
   *  machine, before any guest traffic.
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
   *  The host library reads the host file and writes it into the guest over
   *  the agent's filesystem RPC (`guest.cp`, `host_to_guest`).
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
    this._live.copy("host_to_guest", hostPath, guestPath);
  }

  /** Copy a file out of the running sandbox to `hostPath`.
   *
   *  The host library reads the guest file over the agent's filesystem RPC
   *  and writes it to the host (`guest.cp`, `guest_to_host`).
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
    this._live.copy("guest_to_host", hostPath, guestPath);
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
