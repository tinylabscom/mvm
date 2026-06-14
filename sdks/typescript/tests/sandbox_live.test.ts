/**
 * Live-mode Sandbox tests (Plan 73 Followup H-live).
 *
 * Mirrors `sdks/python/tests/test_sandbox_live.py`. Each test stands
 * up a fixture `mvmctl` shell script that records its argv to a
 * sidecar file and emits the expected stdout. The SDK shells to the
 * fixture via `MVM_CLI_BIN`; no real microVM boots.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import * as mvm from "../src/index.js";

let tmpDir: string;

interface FixtureOptions {
  upEnvelope: Record<string, unknown> | null;
  upExit?: number;
  procExit?: number;
  fsExit?: number;
  cpExit?: number;
  downExit?: number;
}

function writeFixtureMvmctl(opts: FixtureOptions): string {
  const log = path.join(tmpDir, "fixture-calls.log");
  const stdinDir = path.join(tmpDir, "fixture-stdin");
  fs.mkdirSync(stdinDir, { recursive: true });

  const envelopeJson = opts.upEnvelope === null ? "" : JSON.stringify(opts.upEnvelope);
  const upExit = opts.upExit ?? 0;
  const procExit = opts.procExit ?? 0;
  const fsExit = opts.fsExit ?? 0;
  const cpExit = opts.cpExit ?? 0;
  const downExit = opts.downExit ?? 0;

  const script = path.join(tmpDir, "fake-mvmctl");
  fs.writeFileSync(
    script,
    `#!/usr/bin/env bash
set -u
verb=\${1:-}
shift || true
echo "$verb $*" >> ${JSON.stringify(log)}
case "$verb" in
  up)
    if [ -t 0 ]; then :; else cat > ${JSON.stringify(path.join(stdinDir, "up-stdin.bin"))} || true; fi
    if [ "${upExit}" -eq 0 ]; then
      echo '${envelopeJson}'
    fi
    exit ${upExit}
    ;;
  proc)
    sub=$1
    if [ -t 0 ]; then :; else cat > ${JSON.stringify(path.join(stdinDir, "proc-stdin.bin"))} || true; fi
    if [ "${procExit}" -eq 0 ] && [ "$sub" = "start" ]; then
      echo "pid-token-abc123"
    fi
    exit ${procExit}
    ;;
  fs)
    sub=$1
    if [ "$sub" = "write" ]; then
      cat > ${JSON.stringify(path.join(stdinDir, "fs-write-stdin.bin"))}
    fi
    exit ${fsExit}
    ;;
  cp)
    exit ${cpExit}
    ;;
  down)
    exit ${downExit}
    ;;
  *)
    echo "fake-mvmctl: unrecognized verb $verb" >&2
    exit 2
    ;;
esac
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

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "mvm-sdk-live-"));
  mvm.resetRecording();
  delete process.env.MVM_SDK_MODE;
  delete process.env.MVM_CLI_BIN;
});

afterEach(() => {
  mvm.resetRecording();
  delete process.env.MVM_SDK_MODE;
  delete process.env.MVM_CLI_BIN;
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

// ── envelope parsing ─────────────────────────────────────────────────

describe("parseUpEnvelope", () => {
  it("accepts a dev payload", () => {
    const parsed = mvm.parseUpEnvelope(
      '{"schema_version": 1, "vm_id": "sb-xyz", "build_mode": "dev"}\n',
      ["mvmctl", "up"],
    );
    expect(parsed).toEqual({ vm_id: "sb-xyz", build_mode: "dev" });
  });

  it("rejects unknown schema", () => {
    expect(() =>
      mvm.parseUpEnvelope('{"schema_version": 99, "vm_id": "x", "build_mode": "dev"}', [
        "mvmctl",
        "up",
      ]),
    ).toThrow(/schema_version/);
  });

  it("rejects missing vm_id", () => {
    expect(() =>
      mvm.parseUpEnvelope('{"schema_version": 1, "build_mode": "dev"}', ["mvmctl", "up"]),
    ).toThrow(/vm_id/);
  });

  it("rejects unknown build_mode", () => {
    expect(() =>
      mvm.parseUpEnvelope(
        '{"schema_version": 1, "vm_id": "x", "build_mode": "staging"}',
        ["mvmctl", "up"],
      ),
    ).toThrow(/build_mode/);
  });

  it("rejects empty stdout", () => {
    expect(() => mvm.parseUpEnvelope("", ["mvmctl", "up"])).toThrow(/empty stdout/);
  });

  it("rejects invalid JSON", () => {
    expect(() => mvm.parseUpEnvelope("not json", ["mvmctl", "up"])).toThrow(
      /not valid JSON/,
    );
  });
});

// ── live-mode boot ───────────────────────────────────────────────────

describe("Sandbox.create (live mode)", () => {
  it("parses envelope and records vm_id + build_mode", () => {
    const script = writeFixtureMvmctl({
      upEnvelope: {
        schema_version: 1,
        vm_id: "sb-test-vm",
        build_mode: "dev",
      },
    });
    process.env.MVM_SDK_MODE = "live";
    process.env.MVM_CLI_BIN = script;

    const sb = mvm.Sandbox.create("python-3.12", { workloadId: "testwid" });
    expect(sb._live).not.toBeNull();
    expect(sb._live!.vmId).toBe("sb-test-vm");
    expect(sb._live!.buildMode).toBe("dev");

    const calls = readFixtureLog();
    expect(calls.length).toBe(1);
    expect(calls[0]).toMatch(/^up --up-json --name /);
    expect(calls[0]).toContain("--manifest python-3.12");
    expect(calls[0]).toContain("--ttl");
  });

  it("propagates mvmctl failure", () => {
    const script = writeFixtureMvmctl({
      upEnvelope: null,
      upExit: 7,
    });
    process.env.MVM_SDK_MODE = "live";
    process.env.MVM_CLI_BIN = script;

    expect(() => mvm.Sandbox.create("python-3.12")).toThrow(/exit code 7/);
  });

  it("enforces one-sandbox-per-process", () => {
    const script = writeFixtureMvmctl({
      upEnvelope: {
        schema_version: 1,
        vm_id: "sb-first",
        build_mode: "dev",
      },
    });
    process.env.MVM_SDK_MODE = "live";
    process.env.MVM_CLI_BIN = script;

    mvm.Sandbox.create("python-dev");
    expect(() => mvm.Sandbox.create("python-dev")).toThrow(/already active/);
  });
});

// ── commands.start (claim-4 dev-only enforcement) ──────────────────

describe("Sandbox.commands.start (live mode)", () => {
  it("shells to proc start against dev template", () => {
    const script = writeFixtureMvmctl({
      upEnvelope: {
        schema_version: 1,
        vm_id: "sb-dev-vm",
        build_mode: "dev",
      },
    });
    process.env.MVM_SDK_MODE = "live";
    process.env.MVM_CLI_BIN = script;

    const sb = mvm.Sandbox.create("python-dev");
    sb.commands.start(["python", "run.py"], { env: { MODE: "test" } });

    const calls = readFixtureLog();
    expect(calls.length).toBe(2);
    expect(calls[1]).toMatch(/^proc start sb-dev-vm/);
    expect(calls[1]).toContain("-e MODE=test");
    expect(calls[1]).toContain("-- python run.py");
  });

  it("raises SandboxDevOnly against prod template (no vsock traffic)", () => {
    const script = writeFixtureMvmctl({
      upEnvelope: {
        schema_version: 1,
        vm_id: "sb-prod-vm",
        build_mode: "prod",
      },
    });
    process.env.MVM_SDK_MODE = "live";
    process.env.MVM_CLI_BIN = script;

    const sb = mvm.Sandbox.create("python-prod");
    expect(readFixtureLog().length).toBe(1); // only `up`

    expect(() => sb.commands.start(["python", "run.py"])).toThrow(
      mvm.SandboxDevOnly,
    );
    // Critical: SDK must NOT have shelled to `mvmctl proc start`.
    const calls = readFixtureLog();
    expect(calls.length).toBe(1);
    expect(calls.some((c) => c.startsWith("proc"))).toBe(false);
  });
});

// ── files.write ──────────────────────────────────────────────────────

describe("Sandbox.files.write (live mode)", () => {
  it("shells with stdin bytes", () => {
    const script = writeFixtureMvmctl({
      upEnvelope: {
        schema_version: 1,
        vm_id: "sb-fs-vm",
        build_mode: "dev",
      },
    });
    process.env.MVM_SDK_MODE = "live";
    process.env.MVM_CLI_BIN = script;

    const sb = mvm.Sandbox.create("python-dev");
    sb.files.write("/app/config.json", new TextEncoder().encode('{"x":1}'));

    const calls = readFixtureLog();
    expect(calls.some((c) => c.startsWith("fs write sb-fs-vm /app/config.json"))).toBe(true);
    const stdinPath = path.join(tmpDir, "fixture-stdin", "fs-write-stdin.bin");
    expect(fs.readFileSync(stdinPath, "utf-8")).toBe('{"x":1}');
  });
});

// ── kill / dispose ───────────────────────────────────────────────────

describe("Sandbox.kill (live mode)", () => {
  it("shells to mvmctl down", () => {
    const script = writeFixtureMvmctl({
      upEnvelope: {
        schema_version: 1,
        vm_id: "sb-kill-vm",
        build_mode: "dev",
      },
    });
    process.env.MVM_SDK_MODE = "live";
    process.env.MVM_CLI_BIN = script;

    const sb = mvm.Sandbox.create("python-dev");
    sb.kill();

    const calls = readFixtureLog();
    expect(calls).toContain("down sb-kill-vm");
  });

  it("[Symbol.dispose] kills once", () => {
    const script = writeFixtureMvmctl({
      upEnvelope: {
        schema_version: 1,
        vm_id: "sb-ctx-vm",
        build_mode: "dev",
      },
    });
    process.env.MVM_SDK_MODE = "live";
    process.env.MVM_CLI_BIN = script;

    const sb = mvm.Sandbox.create("python-dev");
    sb[Symbol.dispose]();

    const downCalls = readFixtureLog().filter((c) => c.startsWith("down "));
    expect(downCalls.length).toBe(1);
  });
});

// ── copyIn / copyOut (Plan 125 B1) ───────────────────────────────────

describe("Sandbox.copyIn / copyOut (live mode)", () => {
  it("copyIn shells to mvmctl cp host -> vm:guest", () => {
    const script = writeFixtureMvmctl({
      upEnvelope: { schema_version: 1, vm_id: "sb-cp-vm", build_mode: "dev" },
    });
    process.env.MVM_SDK_MODE = "live";
    process.env.MVM_CLI_BIN = script;
    const hostFile = path.join(tmpDir, "local.txt");
    fs.writeFileSync(hostFile, "hello");

    const sb = mvm.Sandbox.create("python-dev");
    sb.copyIn(hostFile, "/app/local.txt");

    const calls = readFixtureLog();
    expect(
      calls.some((c) => c.startsWith(`cp ${hostFile} sb-cp-vm:/app/local.txt`)),
    ).toBe(true);
  });

  it("copyOut shells to mvmctl cp vm:guest -> host", () => {
    const script = writeFixtureMvmctl({
      upEnvelope: { schema_version: 1, vm_id: "sb-cp-vm", build_mode: "dev" },
    });
    process.env.MVM_SDK_MODE = "live";
    process.env.MVM_CLI_BIN = script;
    const dest = path.join(tmpDir, "out.txt");

    const sb = mvm.Sandbox.create("python-dev");
    sb.copyOut("/app/out.txt", dest);

    const calls = readFixtureLog();
    expect(
      calls.some((c) => c.startsWith(`cp sb-cp-vm:/app/out.txt ${dest}`)),
    ).toBe(true);
  });

  it("copyIn propagates a mvmctl cp failure", () => {
    const script = writeFixtureMvmctl({
      upEnvelope: { schema_version: 1, vm_id: "sb-cp-vm", build_mode: "dev" },
      cpExit: 4,
    });
    process.env.MVM_SDK_MODE = "live";
    process.env.MVM_CLI_BIN = script;
    const hostFile = path.join(tmpDir, "local.txt");
    fs.writeFileSync(hostFile, "x");

    const sb = mvm.Sandbox.create("python-dev");
    expect(() => sb.copyIn(hostFile, "/app/local.txt")).toThrow(
      mvm.SandboxLiveError,
    );
  });

  it("copyIn is refused in record mode", () => {
    process.env.MVM_SDK_MODE = "record";
    const sb = mvm.Sandbox.create("python-dev");
    expect(() => sb.copyIn("/tmp/x", "/app/x")).toThrow(mvm.SandboxModeError);
  });
});
