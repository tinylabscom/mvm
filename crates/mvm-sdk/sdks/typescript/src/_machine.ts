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

import {
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

/** A command run with {@link Machine.exec}: its exit code and decoded output. */
export interface MachineResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

/** What {@link Machine.run} and {@link Machine.create} both describe. */
interface MachineSpecOptions {
  /** Command override for the image's entrypoint. */
  command?: string[];
  /** Guest environment. */
  env?: Record<string, string>;
  cpus?: number;
  memoryMib?: number;
  /** Security profile; the library defaults to `standard`. */
  profile?: string;
  /** Egress destinations, each `host:port` or `[v6-address]:port`. */
  allowHosts?: string[];
  /** Opaque TCP ingress, each `host:guest`. */
  ports?: string[];
}

export interface MachineRunOptions extends MachineSpecOptions {
  /** Name for the machine; the library generates one when absent. */
  name?: string;
  /** Seconds before the host reaps the machine. */
  ttlSeconds?: number;
}

export interface MachineCreateOptions extends MachineSpecOptions {
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

/** The request fields `machine.run` and `machine.create` share. Absent and
 *  empty values are left out, so the library applies its own defaults. */
function specFields(options: MachineSpecOptions): Record<string, unknown> {
  const request: Record<string, unknown> = {};
  if (options.command !== undefined) {
    const command = requireStringArray(options.command, "command");
    if (command.length > 0) request.command = command;
  }
  if (options.env !== undefined && Object.keys(options.env).length > 0) {
    request.env = { ...options.env };
  }
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

/** A handle on one machine, by name. Constructing it makes no call. */
export class Machine {
  readonly name: string;

  constructor(name: string) {
    this.name = requireString(name, "name");
  }

  /** Boot a transient machine from `image` and return a handle on it. */
  static run(image: string, options: MachineRunOptions = {}): Machine {
    const request: Record<string, unknown> = {
      image: requireString(image, "image"),
      mode: "transient",
    };
    if (options.name !== undefined) request.name = requireString(options.name, "name");
    Object.assign(request, specFields(options));
    if (options.ttlSeconds !== undefined) request.ttl_seconds = requireCount(options.ttlSeconds, "ttlSeconds");
    const reply = call(MACHINE_RUN, request);
    return new Machine(machineName(reply?.machine, "machine.run"));
  }

  /** Persist a machine definition without booting it; `start()` boots it. */
  static create(name: string, image: string, options: MachineCreateOptions = {}): Machine {
    const request: Record<string, unknown> = {
      name: requireString(name, "name"),
      image: requireString(image, "image"),
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

  /** Captured console output, decoded as UTF-8. */
  logs(options: MachineLogsOptions = {}): string {
    const request: Record<string, unknown> = { id: this.name };
    if (options.lines !== undefined) request.tail_lines = requireCount(options.lines, "lines");
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
    const result = waitGuestProcess(this.name, token, { timeout: options.timeout }, fail);
    const decoder = new TextDecoder("utf-8");
    return {
      exitCode: result.exitCode,
      stdout: decoder.decode(result.stdout),
      stderr: decoder.decode(result.stderr),
    };
  }
}
