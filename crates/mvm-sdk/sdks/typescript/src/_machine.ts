/**
 * Machine-oriented host SDK wrappers.
 *
 * These wrappers shell to `mvmctl machine ...` and deliberately avoid
 * reimplementing admission, policy, receipt, audit, OCI verification, or
 * persistent machine state in TypeScript.
 */

import { cliResolutionHint, resolveCliBin } from "./_cli.js";
import { envFloat, envInt } from "./_env/read.js";

// Owned by the Rust registry (crates/mvm-sdk/src/env.rs), generated into
// `_env/vars.ts`. Re-exported from this module so importers reach them where
// the Python SDK puts them too.
export { MVM_MACHINE_MAX_OUTPUT_ENV, MVM_MACHINE_TIMEOUT_ENV } from "./_env/vars.js";
import { MVM_MACHINE_MAX_OUTPUT_ENV, MVM_MACHINE_TIMEOUT_ENV } from "./_env/vars.js";

// This package is ESM ("type": "module"), so `require` does not exist at
// runtime. These node builtins are imported statically; a lazy `require` here
// throws `ReferenceError: require is not defined` for every consumer of the
// built artifact.
import * as child from "node:child_process";

/** Wall-clock budget for one `mvmctl machine` call, in seconds. */
const DEFAULT_MACHINE_TIMEOUT_SEC = 60;

/** Cap on captured output, per stream, in bytes. */
const DEFAULT_MACHINE_MAX_OUTPUT_BYTES = 16 * 1024 * 1024;

function machineTimeoutMs(): number {
  const seconds = envFloat(MVM_MACHINE_TIMEOUT_ENV, DEFAULT_MACHINE_TIMEOUT_SEC);
  const ms = Math.round(seconds * 1000);
  // `spawnSync` treats 0 (and anything non-positive) as "no timeout", which
  // inverts the meaning of a zero budget from "give up at once" — what the
  // Python SDK does with the same value — into the unbounded wait this bound
  // exists to remove. Floor it instead.
  return Number.isFinite(ms) && ms > 0 ? ms : 1;
}

function machineMaxOutputBytes(): number {
  const bytes = envInt(MVM_MACHINE_MAX_OUTPUT_ENV, DEFAULT_MACHINE_MAX_OUTPUT_BYTES);
  return bytes > 0 ? bytes : DEFAULT_MACHINE_MAX_OUTPUT_BYTES;
}

export interface MachineResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

export interface MachineRunOptions {
  image: string;
  command: string[];
  net?: boolean;
  allowHosts?: string[];
  cpus?: number;
  memory?: string;
  profile?: string;
  volumes?: string[];
  env?: string[];
  timeout?: number;
  receipt?: string;
  json?: boolean;
  dryRun?: boolean;
}

export interface MachineCreateOptions {
  name: string;
  image?: string;
  manifest?: string;
  net?: boolean;
  allowHosts?: string[];
  cpus?: number;
  memory?: string;
  memInitial?: string;
  profile?: string;
  force?: boolean;
  json?: boolean;
}

export interface MachineCheckArtifactOptions {
  path: string;
  key?: string;
  json?: boolean;
}

export interface MachineStartOptions {
  /** Describe the machine to create when the named spec does not exist yet;
   *  `machine start` auto-creates from these. */
  image?: string;
  cpus?: number;
  memory?: string;
  receipt?: string;
  json?: boolean;
  dryRun?: boolean;
}

export interface MachineExecOptions {
  force?: boolean;
}

export interface MachineShellOptions {
  force?: boolean;
}

export interface MachineLsOptions {
  json?: boolean;
}

export interface MachineLogsOptions {
  follow?: boolean;
  lines?: number;
}

export interface MachineInspectOptions {
  json?: boolean;
}

export interface MachineRmOptions {
  names?: string[];
  all?: boolean;
  yes?: boolean;
  json?: boolean;
}

export class MachineError extends Error {
  readonly argv: string[];
  readonly exitCode: number | null;
  readonly stderr: string;

  constructor(
    message: string,
    opts: { argv?: string[]; exitCode?: number | null; stderr?: string } = {},
  ) {
    super(message);
    this.name = "MachineError";
    this.argv = opts.argv ?? [];
    this.exitCode = opts.exitCode ?? null;
    this.stderr = opts.stderr ?? "";
  }
}

function cliBin(): string {
  return resolveCliBin("Machine CLI commands");
}

function requireString(value: string, label: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError(`${label} must be a non-empty string`);
  }
  return value;
}

function requireStringArray(value: string[], label: string): string[] {
  if (!Array.isArray(value) || !value.every((v) => typeof v === "string" && v.length > 0)) {
    throw new TypeError(`${label} must be a non-empty string[]`);
  }
  return [...value];
}

function appendRepeated(argv: string[], flag: string, values: string[] | undefined): void {
  if (values === undefined) return;
  for (const value of requireStringArray(values, flag)) {
    argv.push(flag, value);
  }
}

function runMachine(argv: string[]): MachineResult {
  let bin: string;
  try {
    bin = cliBin();
  } catch (err) {
    throw new MachineError(String(err instanceof Error ? err.message : err));
  }
  const full = [bin, "machine", ...argv];
  const timeoutMs = machineTimeoutMs();
  const maxBuffer = machineMaxOutputBytes();
  let result;
  try {
    // The substrate may hang or return gigabytes. Bounding both here is what
    // keeps a misbehaving machine from taking the caller down with it; the
    // Python SDK bounds the same two things with the same two variables.
    // Unlike Python's `run_capped`, `spawnSync` signals only the child, not
    // its process group, so a grandchild that outlives the kill can still hold
    // the pipes — the wait is bounded either way, the reap is best-effort.
    result = child.spawnSync(bin, ["machine", ...argv], {
      encoding: "utf-8",
      timeout: timeoutMs,
      maxBuffer,
    });
  } catch (err) {
    throw new MachineError(`\`${bin}\` not found on disk; ${cliResolutionHint()}: ${String(err)}`, {
      argv: full,
    });
  }
  if (result.error) {
    // `spawnSync` reports "could not start it", "it ran too long" and "it said
    // too much" through the same field. Reading all three as a spawn failure
    // sends the reader to look for a missing binary when the binary ran fine.
    const code = (result.error as NodeJS.ErrnoException).code;
    if (code === "ETIMEDOUT") {
      throw new MachineError(`\`${bin}\` did not exit within ${timeoutMs / 1000}s`, { argv: full });
    }
    if (code === "ENOBUFS") {
      // Node does not say which stream overflowed, so — unlike Python, which
      // caps each one itself and names it — this names the cap, not the side.
      throw new MachineError(`\`${bin}\` exceeded ${maxBuffer} bytes on stdout or stderr`, {
        argv: full,
      });
    }
    throw new MachineError(`failed to spawn \`${bin}\`: ${result.error.message}`, {
      argv: full,
    });
  }
  if (result.status !== 0) {
    // A signalled child has no exit code, and "exit code null" names nothing.
    const cause =
      result.status === null && result.signal
        ? `was killed by ${result.signal}`
        : `failed with exit code ${result.status}`;
    throw new MachineError(`\`mvmctl machine\` ${cause}`, {
      argv: full,
      exitCode: result.status,
      stderr: result.stderr ?? "",
    });
  }
  return {
    exitCode: result.status ?? 0,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
  };
}

export function machineRunArgv(options: MachineRunOptions): string[] {
  const command = requireStringArray(options.command, "command");
  if (command.length === 0) throw new RangeError("command must be non-empty");
  const argv = ["run", "--image", requireString(options.image, "image")];
  if (options.net) argv.push("--net");
  appendRepeated(argv, "--allow-host", options.allowHosts);
  if (options.cpus !== undefined) argv.push("--cpus", String(options.cpus));
  if (options.memory !== undefined) argv.push("--memory", requireString(options.memory, "memory"));
  if (options.profile !== undefined) argv.push("--profile", requireString(options.profile, "profile"));
  appendRepeated(argv, "--mount", options.volumes);
  appendRepeated(argv, "--env", options.env);
  if (options.timeout !== undefined) argv.push("--timeout", String(options.timeout));
  if (options.receipt !== undefined) argv.push("--receipt", requireString(options.receipt, "receipt"));
  if (options.json) argv.push("--json");
  if (options.dryRun) argv.push("--dry-run");
  argv.push("--", ...command);
  return argv;
}

export function machineCreateArgv(options: MachineCreateOptions): string[] {
  const name = requireString(options.name, "name");
  if (options.image !== undefined && options.manifest !== undefined) {
    throw new TypeError("Machine.create accepts image OR manifest, not both");
  }
  const argv = ["create", name];
  if (options.image !== undefined) argv.push("--image", requireString(options.image, "image"));
  if (options.manifest !== undefined) {
    argv.push("--manifest", requireString(options.manifest, "manifest"));
  }
  if (options.net) argv.push("--net");
  appendRepeated(argv, "--allow-host", options.allowHosts);
  if (options.cpus !== undefined) argv.push("--cpus", String(options.cpus));
  if (options.memory !== undefined) argv.push("--memory", requireString(options.memory, "memory"));
  if (options.memInitial !== undefined) {
    argv.push("--mem-initial", requireString(options.memInitial, "memInitial"));
  }
  if (options.profile !== undefined) argv.push("--profile", requireString(options.profile, "profile"));
  if (options.force) argv.push("--force");
  if (options.json) argv.push("--json");
  return argv;
}

export function machineCheckArtifactArgv(options: MachineCheckArtifactOptions): string[] {
  const argv = ["check-artifact", requireString(options.path, "path")];
  if (options.key !== undefined) argv.push("--key", requireString(options.key, "key"));
  if (options.json) argv.push("--json");
  return argv;
}

export function machineStartArgv(name: string, options: MachineStartOptions = {}): string[] {
  // `machine start` takes a positional name, not `--name`.
  const argv = ["start", requireString(name, "name")];
  if (options.image !== undefined) argv.push("--image", requireString(options.image, "image"));
  if (options.cpus !== undefined) argv.push("--cpus", String(options.cpus));
  if (options.memory !== undefined) argv.push("--memory", requireString(options.memory, "memory"));
  if (options.receipt !== undefined) argv.push("--receipt", requireString(options.receipt, "receipt"));
  if (options.json) argv.push("--json");
  if (options.dryRun) argv.push("--dry-run");
  return argv;
}

export function machineExecArgv(
  name: string,
  command: string[],
  options: MachineExecOptions = {},
): string[] {
  command = requireStringArray(command, "command");
  if (command.length === 0) throw new RangeError("command must be non-empty");
  // `machine exec` takes a positional name, not `--name`.
  const argv = ["exec", requireString(name, "name")];
  if (options.force) argv.push("--force");
  argv.push("--", ...command);
  return argv;
}

export function machineShellArgv(name: string, options: MachineShellOptions = {}): string[] {
  // `machine shell` takes a positional name, not `--name`.
  const argv = ["shell", requireString(name, "name")];
  if (options.force) argv.push("--force");
  return argv;
}

export function machineStopArgv(name: string): string[] {
  // `machine stop` takes a positional name, not `--name` (the CLI rejects the
  // flag form). See the shared `stop.argv` fixture. Pass `--yes` because the
  // SDK runs the CLI non-interactively — without it `machine stop` prompts for
  // y/n confirmation and aborts on no TTY.
  return ["stop", requireString(name, "name"), "--yes"];
}

export function machineLsArgv(options: MachineLsOptions = {}): string[] {
  const argv = ["ls"];
  if (options.json) argv.push("--json");
  return argv;
}

export function machineLogsArgv(name: string, options: MachineLogsOptions = {}): string[] {
  const argv = ["logs", requireString(name, "name")];
  if (options.follow) argv.push("--follow");
  if (options.lines !== undefined) argv.push("--lines", String(options.lines));
  return argv;
}

export function machineInspectArgv(name: string, options: MachineInspectOptions = {}): string[] {
  const argv = ["inspect", requireString(name, "name")];
  if (options.json) argv.push("--json");
  return argv;
}

export function machineRmArgv(options: MachineRmOptions = {}): string[] {
  const names = options.names ? requireStringArray(options.names, "names") : [];
  // The CLI requires exactly one of names / --all (a clap ArgGroup).
  if (Boolean(options.all) === names.length > 0) {
    throw new TypeError("Machine.rm requires exactly one of names or all: true");
  }
  const argv = ["rm"];
  if (options.all) argv.push("--all");
  else argv.push(...names);
  if (options.yes) argv.push("--yes");
  if (options.json) argv.push("--json");
  return argv;
}

export class Machine {
  readonly name: string;

  constructor(name: string) {
    this.name = requireString(name, "name");
  }

  static run(options: MachineRunOptions): MachineResult {
    return runMachine(machineRunArgv(options));
  }

  static create(options: MachineCreateOptions): Machine {
    runMachine(machineCreateArgv(options));
    return new Machine(options.name);
  }

  static checkArtifact(options: MachineCheckArtifactOptions): MachineResult {
    return runMachine(machineCheckArtifactArgv(options));
  }

  static ls(options: MachineLsOptions = {}): MachineResult {
    return runMachine(machineLsArgv(options));
  }

  start(options: MachineStartOptions = {}): MachineResult {
    return runMachine(machineStartArgv(this.name, options));
  }

  exec(command: string[], options: MachineExecOptions = {}): MachineResult {
    return runMachine(machineExecArgv(this.name, command, options));
  }

  shell(options: MachineShellOptions = {}): MachineResult {
    return runMachine(machineShellArgv(this.name, options));
  }

  stop(): MachineResult {
    return runMachine(machineStopArgv(this.name));
  }

  logs(options: MachineLogsOptions = {}): MachineResult {
    return runMachine(machineLogsArgv(this.name, options));
  }

  inspect(options: MachineInspectOptions = {}): MachineResult {
    return runMachine(machineInspectArgv(this.name, options));
  }

  rm(options: { yes?: boolean; json?: boolean } = {}): MachineResult {
    return runMachine(machineRmArgv({ names: [this.name], yes: options.yes, json: options.json }));
  }
}
