/**
 * Machine-oriented host SDK wrappers.
 *
 * These wrappers shell to `mvmctl machine ...` and deliberately avoid
 * reimplementing admission, policy, receipt, audit, OCI verification, or
 * persistent machine state in TypeScript.
 */

import { MVM_CLI_BIN_ENV } from "./_sandbox.js";

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
  receipt?: string;
  json?: boolean;
  dryRun?: boolean;
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
  return typeof process !== "undefined" ? process.env[MVM_CLI_BIN_ENV] || "mvmctl" : "mvmctl";
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
  const bin = cliBin();
  const full = [bin, "machine", ...argv];
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const child = require("node:child_process") as typeof import("node:child_process");
  let result;
  try {
    result = child.spawnSync(bin, ["machine", ...argv], { encoding: "utf-8" });
  } catch (err) {
    throw new MachineError(`\`${bin}\` not found on disk; check MVM_CLI_BIN: ${String(err)}`, {
      argv: full,
    });
  }
  if (result.error) {
    throw new MachineError(`failed to spawn \`${bin}\`: ${result.error.message}`, {
      argv: full,
    });
  }
  if (result.status !== 0) {
    throw new MachineError(`\`mvmctl machine\` failed with exit code ${result.status}`, {
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
  appendRepeated(argv, "--volume", options.volumes);
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
  const argv = ["create", "--name", name];
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

  start(options: MachineStartOptions = {}): MachineResult {
    const argv = ["start", "--name", this.name];
    if (options.receipt !== undefined) argv.push("--receipt", requireString(options.receipt, "receipt"));
    if (options.json) argv.push("--json");
    if (options.dryRun) argv.push("--dry-run");
    return runMachine(argv);
  }

  exec(command: string[], options: { force?: boolean } = {}): MachineResult {
    command = requireStringArray(command, "command");
    if (command.length === 0) throw new RangeError("command must be non-empty");
    const argv = ["exec", "--name", this.name];
    if (options.force) argv.push("--force");
    argv.push("--", ...command);
    return runMachine(argv);
  }

  shell(options: { force?: boolean } = {}): MachineResult {
    const argv = ["shell", "--name", this.name];
    if (options.force) argv.push("--force");
    return runMachine(argv);
  }

  stop(): MachineResult {
    return runMachine(["stop", "--name", this.name]);
  }
}
