import { afterEach, beforeEach, describe, expect, it } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import * as mvm from "../src/index.js";
import {
  machineCheckArtifactArgv,
  machineCreateArgv,
  machineExecArgv,
  machineInspectArgv,
  machineLogsArgv,
  machineLsArgv,
  machineRmArgv,
  machineRunArgv,
  machineShellArgv,
  machineStartArgv,
  machineStopArgv,
} from "../src/_machine.js";
import { resolveCliBin } from "../src/_cli.js";

let tmpDir: string;
let originalPath: string | undefined;

function writeFixtureMvmctl(exitCode = 0, runStdout = ""): string {
  const log = path.join(tmpDir, "fixture-calls.log");
  const script = path.join(tmpDir, "fake-mvmctl");
  fs.writeFileSync(
    script,
    `#!/usr/bin/env bash
set -u
verb=\${1:-}
shift || true
echo "$verb $*" >> ${JSON.stringify(log)}
if [ "$verb" != "machine" ]; then
  echo "expected machine verb" >&2
  exit 64
fi
sub=\${1:-}
shift || true
echo "machine:$sub $*" >> ${JSON.stringify(log)}
if [ "$sub" = "run" ]; then
  printf '%b' ${JSON.stringify(runStdout)}
fi
exit ${exitCode}
`,
    { mode: 0o755 },
  );
  return script;
}

function readFixtureLog(): string[] {
  const log = path.join(tmpDir, "fixture-calls.log");
  if (!fs.existsSync(log)) return [];
  return fs.readFileSync(log, "utf-8").split("\n").filter((l) => l.length > 0);
}

// Repo root, resolved from this file rather than the process cwd:
// tests/ -> typescript/ -> sdks/ -> mvm-sdk/ -> crates/ -> repo root.
const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..", "..");

// The canonical golden argv corpus. The CLI anchors it against the real clap
// parser and the Rust SDK asserts its builders reproduce it, which is what
// makes a fixture mean "argv mvmctl actually accepts". Resolving anywhere else
// silently opts this suite out of that contract.
export const MACHINE_FIXTURES = path.join(REPO_ROOT, "tests", "machine-fixtures");

function readArgvFixture(name: string): string[] {
  return fs.readFileSync(path.join(MACHINE_FIXTURES, `${name}.argv`), "utf-8")
    .split("\n")
    .filter((line) => line.length > 0);
}

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "mvm-sdk-machine-"));
  originalPath = process.env.PATH;
  delete process.env.MVM_CLI_BIN;
});

afterEach(() => {
  delete process.env.MVM_CLI_BIN;
  if (originalPath === undefined) {
    delete process.env.PATH;
  } else {
    process.env.PATH = originalPath;
  }
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

function writeNamedCli(name: string): string {
  const script = path.join(tmpDir, name);
  fs.writeFileSync(
    script,
    `#!/usr/bin/env bash
set -u
exit 0
`,
    { mode: 0o755 },
  );
  return script;
}

describe("resolveCliBin", () => {
  it("prefers the explicit env override", () => {
    const explicit = writeNamedCli("explicit-cli");
    writeNamedCli("mvmctl");
    process.env.MVM_CLI_BIN = explicit;
    process.env.PATH = tmpDir;
    expect(resolveCliBin("tests")).toBe(explicit);
  });

  it("resolves mvmctl on PATH", () => {
    const cli = writeNamedCli("mvmctl");
    process.env.PATH = tmpDir;
    expect(resolveCliBin("tests")).toBe(cli);
  });
});

describe("Machine.run", () => {
  it("emits the shared default preflight argv fixture", () => {
    expect(machineRunArgv({
      image: "alpine:latest",
      command: ["true"],
      json: true,
      dryRun: true,
    })).toEqual(readArgvFixture("run-default"));
  });

  it("emits the shared allow-host receipt preflight argv fixture", () => {
    expect(machineRunArgv({
      image: "alpine:latest",
      command: ["true"],
      allowHosts: ["api.example.com"],
      receipt: "/tmp/mvm-sdk-machine.receipt.json",
      json: true,
      dryRun: true,
    })).toEqual(readArgvFixture("run-allow-host-receipt"));
  });

  it("emits the shared admission parity argv fixture", () => {
    expect(machineRunArgv({
      image: "alpine:latest",
      command: ["sh", "-lc", "echo ok"],
      allowHosts: ["api.example.com"],
      cpus: 4,
      memory: "1G",
      profile: "dev",
      volumes: ["/tmp/mvm-sdk-src:/work:ro"],
      env: ["TOKEN=secret", "MODE=test"],
      timeout: 30,
      receipt: "/tmp/mvm-sdk-machine.receipt.json",
      json: true,
      dryRun: true,
    })).toEqual(readArgvFixture("run-admission"));
  });

  it("shells to mvmctl machine run", () => {
    const script = writeFixtureMvmctl(0, "hello\n");
    process.env.MVM_CLI_BIN = script;

    const result = mvm.Machine.run({
      image: "alpine:latest",
      command: ["uname", "-a"],
      net: true,
      allowHosts: ["example.com:443"],
      cpus: 1,
      memory: "256M",
      profile: "dev",
      env: ["MODE=test"],
    });

    expect(result.exitCode).toBe(0);
    expect(result.stdout).toBe("hello\n");
    const text = readFixtureLog().join("\n");
    expect(text).toContain("machine:run");
    expect(text).toContain("--image alpine:latest");
    expect(text).toContain("--net");
    expect(text).toContain("--allow-host example.com:443");
    expect(text).toContain("-- uname -a");
  });

  it("rejects an empty command", () => {
    expect(() => mvm.Machine.run({ image: "alpine", command: [] })).toThrow(/command/);
  });
});

describe("Machine.checkArtifact", () => {
  it("emits the shared check-artifact argv fixture", () => {
    expect(machineCheckArtifactArgv({
      path: "/tmp/app.mvm",
      key: "/tmp/app.pub",
      json: true,
    })).toEqual(readArgvFixture("check-artifact"));
  });

  it("shells check-artifact through mvmctl machine", () => {
    const script = writeFixtureMvmctl(0, "{\"runnable_here\":true}\n");
    process.env.MVM_CLI_BIN = script;

    const result = mvm.Machine.checkArtifact({
      path: "/tmp/app.mvm",
      key: "/tmp/app.pub",
      json: true,
    });

    expect(result.exitCode).toBe(0);
    const text = readFixtureLog().join("\n");
    expect(text).toContain("machine:check-artifact /tmp/app.mvm --key /tmp/app.pub --json");
  });

  it("rejects an empty path", () => {
    expect(() => mvm.Machine.checkArtifact({ path: "" })).toThrow(/path/);
  });
});

describe("Machine persistent lifecycle", () => {
  it("emits the shared manifest create argv fixture", () => {
    expect(machineCreateArgv({
      name: "web",
      manifest: "mvm.toml",
      profile: "dev",
      force: true,
      json: true,
    })).toEqual(readArgvFixture("create-manifest"));
  });

  it("emits the shared image create argv fixture", () => {
    // The --image + resources shape the MvmClient facade's create_machine emits.
    expect(machineCreateArgv({
      name: "web",
      image: "alpine:3.20",
      cpus: 2,
      memory: "512M",
    })).toEqual(readArgvFixture("create-image"));
  });

  it("shells create/start/exec/shell/stop through mvmctl machine", () => {
    const script = writeFixtureMvmctl();
    process.env.MVM_CLI_BIN = script;

    const machine = mvm.Machine.create({
      name: "devbox",
      manifest: "mvm.toml",
      profile: "dev",
      force: true,
    });
    machine.start({ dryRun: true });
    machine.exec(["echo", "hi"], { force: true });
    machine.shell({ force: true });
    machine.stop();

    const text = readFixtureLog().join("\n");
    expect(text).toContain("machine:create devbox --manifest mvm.toml --profile dev --force");
    expect(text).toContain("machine:start devbox --dry-run");
    expect(text).toContain("machine:exec devbox --force -- echo hi");
    expect(text).toContain("machine:shell devbox --force");
    expect(text).toContain("machine:stop devbox --yes");
  });

  it("emits the shared start/exec/shell/stop argv fixtures", () => {
    expect(machineStartArgv("web", {
      receipt: "/tmp/mvm-sdk-machine.receipt.json",
      json: true,
      dryRun: true,
    })).toEqual(readArgvFixture("start"));
    expect(machineExecArgv("web", ["sh", "-lc", "echo ok"], { force: true }))
      .toEqual(readArgvFixture("exec"));
    expect(machineShellArgv("web", { force: true })).toEqual(readArgvFixture("shell"));
    // Regression guard: `stop` takes a positional name, not `--name`.
    expect(machineStopArgv("web")).toEqual(readArgvFixture("stop"));
  });

  it("emits the shared start-image argv fixture", () => {
    expect(machineStartArgv("web", { image: "nginx", cpus: 2, memory: "512M" }))
      .toEqual(readArgvFixture("start-image"));
  });

  // Mirrors the Rust `fixture_coverage_is_accounted_for` tripwire: a fixture
  // added without a TypeScript assertion is a silent coverage hole in one of
  // the three languages the corpus is supposed to bind together.
  it("asserts every fixture in the shared corpus", () => {
    const onDisk = fs.readdirSync(MACHINE_FIXTURES)
      .filter((name) => name.endsWith(".argv") && !name.startsWith("."))
      .map((name) => name.slice(0, -".argv".length))
      .sort();
    expect(onDisk.length).toBeGreaterThan(0);
    expect(onDisk).toEqual([
      "check-artifact",
      "create-image",
      "create-manifest",
      "exec",
      "inspect",
      "logs",
      "ls",
      "rm",
      "rm-all",
      "run-admission",
      "run-allow-host-receipt",
      "run-default",
      "shell",
      "start",
      "start-image",
      "stop",
    ]);
  });

  it("emits the shared ls/logs/inspect/rm argv fixtures", () => {
    expect(machineLsArgv({ json: true })).toEqual(readArgvFixture("ls"));
    expect(machineLogsArgv("web", { follow: true, lines: 100 })).toEqual(readArgvFixture("logs"));
    expect(machineInspectArgv("web", { json: true })).toEqual(readArgvFixture("inspect"));
    expect(machineRmArgv({ names: ["web"], yes: true, json: true })).toEqual(readArgvFixture("rm"));
    expect(machineRmArgv({ all: true, yes: true, json: true })).toEqual(readArgvFixture("rm-all"));
  });

  it("rejects image and manifest together", () => {
    expect(() =>
      mvm.Machine.create({ name: "bad", image: "alpine", manifest: "mvm.toml" }),
    ).toThrow(/image OR manifest/);
  });

  it("surfaces mvmctl failures as MachineError", () => {
    const script = writeFixtureMvmctl(19);
    process.env.MVM_CLI_BIN = script;

    expect(() => mvm.Machine.run({ image: "alpine", command: ["true"] })).toThrow(
      mvm.MachineError,
    );
  });
});
