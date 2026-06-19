import { afterEach, beforeEach, describe, expect, it } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import * as mvm from "../src/index.js";
import { machineRunArgv } from "../src/_machine.js";

let tmpDir: string;

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

function readArgvFixture(name: string): string[] {
  return fs.readFileSync(path.join("..", "machine-fixtures", `${name}.argv`), "utf-8")
    .split("\n")
    .filter((line) => line.length > 0);
}

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "mvm-sdk-machine-"));
  delete process.env.MVM_CLI_BIN;
});

afterEach(() => {
  delete process.env.MVM_CLI_BIN;
  fs.rmSync(tmpDir, { recursive: true, force: true });
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

describe("Machine persistent lifecycle", () => {
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
    expect(text).toContain("machine:create --name devbox --manifest mvm.toml --profile dev --force");
    expect(text).toContain("machine:start --name devbox --dry-run");
    expect(text).toContain("machine:exec --name devbox --force -- echo hi");
    expect(text).toContain("machine:shell --name devbox --force");
    expect(text).toContain("machine:stop --name devbox");
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
