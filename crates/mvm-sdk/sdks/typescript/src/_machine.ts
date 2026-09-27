/**
 * Machine lifecycle over the host library.
 *
 * Every method is one call into `libmvm_hostlib`, loaded in-process; nothing
 * here reimplements admission, policy, audit, OCI verification, or machine
 * state. The library owns all of that and reports failures as the typed
 * `HostLibraryError` subclass the error's `code` names, which propagate from
 * these methods unchanged. {@link MachineError} is only for what the SDK
 * refuses on its own: an argument it cannot send, or a reply it cannot read.
 */

import { randomBytes } from "node:crypto";

import {
  followMachineOutput,
  fromBase64,
  startGuestProcess,
  waitGuestProcess,
  type ReplyFailure,
} from "./_guest.js";
import { call } from "./_hostlib.js";
import {
  MACHINE_CREATE,
  MACHINE_INSPECT,
  MACHINE_INVENTORY,
  MACHINE_LOGS,
  MACHINE_RM,
  MACHINE_RUN,
  MACHINE_START,
  MACHINE_STOP,
} from "./hostabi/methods.js";

/** A machine as the library reports it (`id`, `name`, `status`, `backend`, …). */
export type MachineState = Record<string, unknown>;

/** One entry of the host-wide machine inventory (`name`, `build_mode`, `status`, …). */
export type MachineInventoryRecord = Record<string, unknown>;

/** A command run with {@link Machine.run} or {@link Machine.exec}: its exit
 *  code and decoded output. */
export interface MachineResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

/**
 * What a machine boots: exactly one of an `image` (an OCI reference, a rootfs
 * path, or `flake:<ref>#<attr>`), a `template` built on this host (by the name
 * its image was built under), or a `manifest` (a manifest path or a built
 * slot's address). A template or manifest boots as a persistent machine.
 */
export interface MachineSource {
  image?: string;
  template?: string;
  manifest?: string;
}

/** What {@link Machine.launch} and {@link Machine.create} both describe. */
interface MachineSpecOptions {
  cpus?: number;
  memoryMib?: number;
  /** Security profile; the library defaults to `standard`. */
  profile?: string;
  /** Egress destinations, each `host:port` or `[v6-address]:port`. */
  allowHosts?: string[];
  /** Opaque TCP ingress, each `host:guest`. */
  ports?: string[];
}

/** A command started once a machine is up. */
interface CommandOptions {
  /** The command's environment; the host's denylist refuses a loader, shell
   *  or credential variable. */
  env?: Record<string, string>;
  /** The command's working directory. */
  cwd?: string;
}

export interface MachineRunOptions extends CommandOptions {
  cpus?: number;
  memoryMib?: number;
  profile?: string;
  /** Egress destinations, each `host:port` or `[v6-address]:port`. */
  allowHosts?: string[];
  /** Wall-clock limit on the command in seconds (exit 124 on overrun). */
  timeout?: number;
}

export interface MachineLaunchOptions extends MachineSource, MachineSpecOptions, CommandOptions {
  /** Name for the machine; one is generated when absent. */
  name?: string;
  /** Started once the machine is up; {@link Machine.process} names it. */
  command?: string[];
  /** Seconds before the host reaps the machine. */
  ttlSeconds?: number;
  /** Replace a same-name definition whose configuration differs. */
  force?: boolean;
}

export interface MachineCreateOptions extends MachineSource, MachineSpecOptions {
  /** Replace a same-name definition whose configuration differs. */
  force?: boolean;
}

export interface MachineExecOptions {
  /** Wall-clock limit in seconds; the process is stopped on overrun (exit 124). */
  timeout?: number;
  /** Working directory for the process. */
  cwd?: string;
  env?: Record<string, string>;
}

export interface MachineLogsOptions {
  /** Return only the last `lines` lines. */
  lines?: number;
}

export interface MachineFollowLogsOptions extends MachineLogsOptions {
  /** Keep yielding output as the machine writes it. */
  follow: true;
}

/** A request the SDK refused before sending, or a reply it could not read. */
export class MachineError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "MachineError";
  }
}

const fail: ReplyFailure = (message) => new MachineError(message);

function requireString(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError(`${label} must be a non-empty string`);
  }
  return value;
}

function requireStringArray(value: unknown, label: string): string[] {
  if (!Array.isArray(value) || !value.every((v) => typeof v === "string" && v.length > 0)) {
    throw new TypeError(`${label} must be an array of non-empty strings`);
  }
  return [...value];
}

function requireCount(value: unknown, label: string): number {
  if (!Number.isInteger(value) || (value as number) <= 0) {
    throw new RangeError(`${label} must be a positive integer`);
  }
  return value as number;
}

/**
 * Parse one `host:port` egress destination. An IPv6 address carries a colon
 * of its own, so it must be bracketed (`[::1]:443`) to be unambiguous; the
 * library takes the bare address.
 */
export function parseAllowHost(entry: string): { host: string; port: number } {
  const text = requireString(entry, "allowHosts entry");
  let host: string;
  let portText: string;
  if (text.startsWith("[")) {
    const close = text.indexOf("]:");
    if (close < 0) throw new MachineError(`allowHosts entry ${JSON.stringify(text)} must be [address]:port`);
    host = text.slice(1, close);
    portText = text.slice(close + 2);
  } else {
    const colon = text.lastIndexOf(":");
    if (colon < 0) throw new MachineError(`allowHosts entry ${JSON.stringify(text)} must be host:port`);
    host = text.slice(0, colon);
    portText = text.slice(colon + 1);
    if (host.includes(":")) {
      throw new MachineError(
        `allowHosts entry ${JSON.stringify(text)} is ambiguous; bracket an IPv6 address as [address]:port`,
      );
    }
  }
  const port = /^\d+$/.test(portText) ? Number(portText) : NaN;
  if (host.length === 0 || !Number.isInteger(port) || port < 1 || port > 65535) {
    throw new MachineError(`allowHosts entry ${JSON.stringify(text)} needs a host and a port in 1..65535`);
  }
  return { host, port };
}

/** The one boot source `source` names, as its request field. */
function sourceField(source: MachineSource): Record<string, string> {
  const given = (["image", "template", "manifest"] as const).filter((f) => source[f] !== undefined);
  if (given.length !== 1) {
    throw new TypeError("pass exactly one of image, template and manifest");
  }
  const field = given[0] as keyof MachineSource;
  return { [field]: requireString(source[field], field) };
}

/** A command's request fields; `env` and `cwd` without a command are for the
 *  library to refuse, so they are sent as given. */
function commandFields(command: string[] | undefined, options: CommandOptions): Record<string, unknown> {
  const request: Record<string, unknown> = {};
  if (command !== undefined) {
    const argv = requireStringArray(command, "command");
    if (argv.length === 0) throw new RangeError("command must be non-empty");
    request.command = argv;
  }
  if (options.env !== undefined && Object.keys(options.env).length > 0) {
    request.env = { ...options.env };
  }
  if (options.cwd !== undefined) request.cwd = requireString(options.cwd, "cwd");
  return request;
}

/** The request fields `machine.run` and `machine.create` share. Absent and
 *  empty values are left out, so the library applies its own defaults. */
function specFields(options: MachineSpecOptions): Record<string, unknown> {
  const request: Record<string, unknown> = {};
  if (options.cpus !== undefined) request.cpus = requireCount(options.cpus, "cpus");
  if (options.memoryMib !== undefined) request.memory_mib = requireCount(options.memoryMib, "memoryMib");
  if (options.profile !== undefined) request.profile = requireString(options.profile, "profile");
  if (options.ports !== undefined) {
    const ports = requireStringArray(options.ports, "ports");
    if (ports.length > 0) request.ports = ports;
  }
  if (options.allowHosts !== undefined) {
    const egress = requireStringArray(options.allowHosts, "allowHosts").map(parseAllowHost);
    if (egress.length > 0) request.egress = egress;
  }
  return request;
}

function machineName(state: unknown, method: string): string {
  const name = (state as { name?: unknown } | null | undefined)?.name;
  if (typeof name !== "string" || name.length === 0) {
    throw new MachineError(`${method} returned a machine with no name`);
  }
  return name;
}

/** A machine name the library's validator accepts, unique per boot. */
function generatedName(prefix: string): string {
  return `sdk-${prefix}-${randomBytes(4).toString("hex")}`;
}

function decoded(result: { exitCode: number; stdout: Uint8Array; stderr: Uint8Array }): MachineResult {
  const decoder = new TextDecoder("utf-8");
  return {
    exitCode: result.exitCode,
    stdout: decoder.decode(result.stdout),
    stderr: decoder.decode(result.stderr),
  };
}

/**
 * A handle on one machine, by name. Constructing it makes no call.
 *
 * Every boot is a named machine started the way `mvmctl machine run -d`
 * starts one, so the SDK and the CLI admit it under the same plan.
 */
export class Machine {
  readonly name: string;
  /** `dev` or `prod` when this handle came from {@link Machine.launch}. */
  buildMode?: string;
  /** The admitted plan's id when this handle came from {@link Machine.launch}. */
  planId?: string;
  /** The token of the process a launch's `command` started, for {@link wait}. */
  process?: string;

  constructor(name: string) {
    this.name = requireString(name, "name");
  }

  /**
   * Boot a machine from `image`, run `command` in it, and return what the
   * command produced once it ends. The machine is stopped and removed on
   * every exit, including a throw. Running a command is a DevOnly guest
   * operation, so a sealed image refuses it.
   */
  static run(image: string, command: string[], options: MachineRunOptions = {}): MachineResult {
    const machine = Machine.launch({
      image,
      name: generatedName("run"),
      command,
      env: options.env,
      cwd: options.cwd,
      cpus: options.cpus,
      memoryMib: options.memoryMib,
      profile: options.profile,
      allowHosts: options.allowHosts,
    });
    try {
      return machine.wait({ timeout: options.timeout });
    } finally {
      machine.discard();
    }
  }

  /**
   * Boot a machine and return a handle on it. The machine is named — `name`,
   * or one generated here — and outlives this process until `stop()` and
   * `rm()`, or until `ttlSeconds` runs out. `command` starts once the machine
   * is up; {@link process} names it and {@link wait} collects its output.
   */
  static launch(options: MachineLaunchOptions): Machine {
    const source = sourceField(options);
    const request: Record<string, unknown> = {
      ...source,
      mode: "persistent",
      name: options.name !== undefined ? requireString(options.name, "name") : generatedName("machine"),
    };
    Object.assign(request, commandFields(options.command, options), specFields(options));
    if (options.ttlSeconds !== undefined) request.ttl_seconds = requireCount(options.ttlSeconds, "ttlSeconds");
    if (options.force) request.force = true;
    const reply = call(MACHINE_RUN, request);
    const machine = new Machine(machineName(reply?.machine, "machine.run"));
    if (typeof reply?.build_mode === "string") machine.buildMode = reply.build_mode;
    if (typeof reply?.plan_id === "string") machine.planId = reply.plan_id;
    const processToken = reply?.process;
    if (request.command !== undefined && (typeof processToken !== "string" || processToken.length === 0)) {
      throw new MachineError("machine.run started a command but named no process");
    }
    if (typeof processToken === "string") machine.process = processToken;
    return machine;
  }

  /** Persist a machine definition without booting it; `start()` boots it. */
  static create(name: string, source: MachineSource | string, options: MachineCreateOptions = {}): Machine {
    const request: Record<string, unknown> = {
      name: requireString(name, "name"),
      ...sourceField(typeof source === "string" ? { image: source } : source),
      ...specFields(options),
    };
    if (options.force) request.force = true;
    return new Machine(machineName(call(MACHINE_CREATE, request), "machine.create"));
  }

  /** Every machine on this host, with its dev/prod posture. */
  static ls(): MachineInventoryRecord[] {
    const records = call(MACHINE_INVENTORY);
    if (!Array.isArray(records)) throw new MachineError("machine.inventory must return an array");
    return records as MachineInventoryRecord[];
  }

  /** Boot this persisted machine. */
  start(): MachineState {
    return call(MACHINE_START, { id: this.name }) as MachineState;
  }

  /** Stop this machine. Stopping a stopped machine is not an error. */
  stop(): void {
    call(MACHINE_STOP, { id: this.name });
  }

  /** Remove this machine. A running persistent machine must be stopped first. */
  rm(): void {
    call(MACHINE_RM, { id: this.name });
  }

  inspect(): MachineState {
    return call(MACHINE_INSPECT, { id: this.name }) as MachineState;
  }

  /** Stop the machine and remove its definition, reporting rather than
   *  throwing a failure: this is cleanup, and whatever ended the caller's
   *  work is what they need to see. */
  private discard(): void {
    for (const [verb, method] of [
      ["stopping", MACHINE_STOP],
      ["removing", MACHINE_RM],
    ] as const) {
      try {
        call(method, { id: this.name });
      } catch (err) {
        process.stderr.write(`mvm: ${verb} ${this.name} failed: ${err instanceof Error ? err.message : String(err)}\n`);
        return;
      }
    }
  }

  /** Wait for the command {@link Machine.launch} started and return what it
   *  produced. `timeout` bounds the wait (exit 124 on overrun). */
  wait(options: { timeout?: number } = {}): MachineResult {
    if (this.process === undefined) {
      throw new MachineError(`machine ${this.name} was not launched with a command to wait for`);
    }
    return decoded(waitGuestProcess(this.name, this.process, { timeout: options.timeout }, fail));
  }

  /**
   * Captured console output, decoded as UTF-8. With `follow: true` it arrives
   * as an iterable of text chunks that keeps yielding as the machine writes,
   * until the output ends or iteration stops.
   */
  logs(options: MachineFollowLogsOptions): Iterable<string>;
  logs(options?: MachineLogsOptions): string;
  logs(options: MachineLogsOptions | MachineFollowLogsOptions = {}): string | Iterable<string> {
    const lines = options.lines === undefined ? undefined : requireCount(options.lines, "lines");
    if ("follow" in options && options.follow === true) {
      return followMachineOutput(this.name, { tailLines: lines }, fail);
    }
    const request: Record<string, unknown> = { id: this.name };
    if (lines !== undefined) request.tail_lines = lines;
    const reply = call(MACHINE_LOGS, request);
    return new TextDecoder("utf-8").decode(fromBase64(reply?.data_b64, "machine.logs's data_b64", fail));
  }

  /**
   * Run `command` in this machine and wait for it.
   *
   * This drives the guest agent's process control, which a machine admitted
   * as production refuses; that refusal arrives as `MachineBackendError`.
   */
  exec(command: string[], options: MachineExecOptions = {}): MachineResult {
    const argv = requireStringArray(command, "command");
    if (argv.length === 0) throw new RangeError("command must be non-empty");
    const token = startGuestProcess(this.name, argv, { env: options.env, cwd: options.cwd }, fail);
    return decoded(waitGuestProcess(this.name, token, { timeout: options.timeout }, fail));
  }
}
