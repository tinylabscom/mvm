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
import * as http from "node:http";
import * as os from "node:os";
import * as path from "node:path";
import * as mvm from "../src/index.js";
import { deriveAttachedBuildMode, parseUpEnvelope } from "../src/_sandbox.js";

let tmpDir: string;

interface FixtureOptions {
  upEnvelope: Record<string, unknown> | null;
  upExit?: number;
  procExit?: number;
  procWaitStdout?: string;
  procWaitStderr?: string;
  procWaitExit?: number;
  fsExit?: number;
  fsReadStdout?: string;
  fsLsJson?: string;
  fsStatJson?: string;
  cpExit?: number;
  forwardSleep?: number;
  downExit?: number;
  lsOut?: string;
  lsExit?: number;
}

function writeFixtureMvmctl(opts: FixtureOptions): string {
  const log = path.join(tmpDir, "fixture-calls.log");
  const stdinDir = path.join(tmpDir, "fixture-stdin");
  fs.mkdirSync(stdinDir, { recursive: true });

  const envelopeJson = opts.upEnvelope === null ? "" : JSON.stringify(opts.upEnvelope);
  const upExit = opts.upExit ?? 0;
  const procExit = opts.procExit ?? 0;
  const procWaitStdout = opts.procWaitStdout ?? "";
  const procWaitStderr = opts.procWaitStderr ?? "";
  const procWaitExit = opts.procWaitExit ?? 0;
  const fsExit = opts.fsExit ?? 0;
  const fsReadStdout = opts.fsReadStdout ?? "";
  const fsLsJson = opts.fsLsJson ?? "[]";
  const fsStatJson = opts.fsStatJson ?? "{}";
  const cpExit = opts.cpExit ?? 0;
  const forwardSleep = opts.forwardSleep ?? 0;
  const downExit = opts.downExit ?? 0;
  const lsOut = opts.lsOut ?? "[]";
  const lsExit = opts.lsExit ?? 0;

  const script = path.join(tmpDir, "fake-mvmctl");
  fs.writeFileSync(
    script,
    `#!/usr/bin/env bash
set -u
verb=\${1:-}
shift || true
echo "$verb $*" >> ${JSON.stringify(log)}
if [ "$verb" = "machine" ]; then
  verb=\${1:-}
  shift || true
fi
case "$verb" in
  up | run)
    if [ -t 0 ]; then :; else cat > ${JSON.stringify(path.join(stdinDir, "up-stdin.bin"))} || true; fi
    if [ "${upExit}" -eq 0 ]; then
      echo '${envelopeJson}'
    fi
    exit ${upExit}
    ;;
  proc)
    sub=$1
    if [ -t 0 ]; then :; else cat > ${JSON.stringify(path.join(stdinDir, "proc-stdin.bin"))} || true; fi
    if [ "$sub" = "start" ]; then
      if [ "${procExit}" -eq 0 ]; then echo "pid-token-abc123"; fi
      exit ${procExit}
    elif [ "$sub" = "wait" ]; then
      printf '%s' ${JSON.stringify(procWaitStdout)}
      printf '%s' ${JSON.stringify(procWaitStderr)} >&2
      exit ${procWaitExit}
    fi
    exit ${procExit}
    ;;
  fs)
    sub=$1
    if [ "$sub" = "write" ]; then
      cat > ${JSON.stringify(path.join(stdinDir, "fs-write-stdin.bin"))}
    elif [ "$sub" = "read" ]; then
      printf '%s' ${JSON.stringify(fsReadStdout)}
    elif [ "$sub" = "ls" ]; then
      printf '%s' ${JSON.stringify(fsLsJson)}
    elif [ "$sub" = "stat" ]; then
      printf '%s' ${JSON.stringify(fsStatJson)}
    fi
    exit ${fsExit}
    ;;
  ls)
    echo '${lsOut}'
    exit ${lsExit}
    ;;
  cp)
    exit ${cpExit}
    ;;
  forward)
    sleep ${forwardSleep}
    exit 0
    ;;
  stop)
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
    const parsed = parseUpEnvelope(
      '{"schema_version": 1, "vm_id": "sb-xyz", "build_mode": "dev"}\n',
      ["mvmctl", "up"],
    );
    expect(parsed).toEqual({ vm_id: "sb-xyz", build_mode: "dev" });
  });

  it("rejects unknown schema", () => {
    expect(() =>
      parseUpEnvelope('{"schema_version": 99, "vm_id": "x", "build_mode": "dev"}', [
        "mvmctl",
        "up",
      ]),
    ).toThrow(/schema_version/);
  });

  it("rejects missing vm_id", () => {
    expect(() =>
      parseUpEnvelope('{"schema_version": 1, "build_mode": "dev"}', ["mvmctl", "up"]),
    ).toThrow(/vm_id/);
  });

  it("rejects unknown build_mode", () => {
    expect(() =>
      parseUpEnvelope(
        '{"schema_version": 1, "vm_id": "x", "build_mode": "staging"}',
        ["mvmctl", "up"],
      ),
    ).toThrow(/build_mode/);
  });

  it("rejects empty stdout", () => {
    expect(() => parseUpEnvelope("", ["mvmctl", "up"])).toThrow(/empty stdout/);
  });

  it("rejects invalid JSON", () => {
    expect(() => parseUpEnvelope("not json", ["mvmctl", "up"])).toThrow(
      /not valid JSON/,
    );
  });
});

// ── deriveAttachedBuildMode + connect ────────────────────────────────

describe("deriveAttachedBuildMode", () => {
  const argv = ["mvmctl", "machine", "ls", "--json"];

  it("matches on name and returns the entry build_mode", () => {
    const stdout = JSON.stringify([
      { name: "a", build_mode: "prod", status: "running" },
      { name: "b", build_mode: "dev", status: "running" },
    ]);
    expect(deriveAttachedBuildMode(stdout, "b", argv)).toBe("dev");
    expect(deriveAttachedBuildMode(stdout, "a", argv)).toBe("prod");
  });

  it("fails closed on a missing build_mode", () => {
    const stdout = JSON.stringify([{ name: "a", status: "running" }]);
    expect(deriveAttachedBuildMode(stdout, "a", argv)).toBe("prod");
  });

  it("fails closed on an unknown build_mode", () => {
    const stdout = JSON.stringify([{ name: "a", build_mode: "staging" }]);
    expect(deriveAttachedBuildMode(stdout, "a", argv)).toBe("prod");
  });

  it("throws when the machine is absent", () => {
    const stdout = JSON.stringify([{ name: "other", build_mode: "dev" }]);
    expect(() => deriveAttachedBuildMode(stdout, "ghost", argv)).toThrow(
      /no machine named/,
    );
  });
});

describe("Sandbox.connect (attach; inherits dev-only guard)", () => {
  it("attaches to a dev machine and allows exec", () => {
    const lsOut = JSON.stringify([
      { name: "web-1", build_mode: "dev", status: "running" },
      { name: "other", build_mode: "prod", status: "running" },
    ]);
    const script = writeFixtureMvmctl({ upEnvelope: null, lsOut, procWaitStdout: "4" });
    process.env.MVM_CLI_BIN = script;

    const sb = mvm.Sandbox.connect("web-1");
    expect(sb._live).not.toBeNull();
    expect(sb._live!.vmId).toBe("web-1");
    expect(sb._live!.buildMode).toBe("dev");

    const r = sb.exec(["python", "-c", "print(2 + 2)"]);
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toBe("4");

    const calls = readFixtureLog();
    expect(calls[0]).toMatch(/^machine ls --json/);
    expect(calls.some((c) => c.startsWith("machine proc start web-1"))).toBe(true);
  });

  it("refuses exec on a prod machine (fail-closed, no proc traffic)", () => {
    const lsOut = JSON.stringify([{ name: "sealed", build_mode: "prod", status: "running" }]);
    const script = writeFixtureMvmctl({ upEnvelope: null, lsOut });
    process.env.MVM_CLI_BIN = script;

    const sb = mvm.Sandbox.connect("sealed");
    expect(sb._live!.buildMode).toBe("prod");
    expect(() => sb.exec(["python", "-c", "x"])).toThrow(mvm.SandboxDevOnly);
    expect(() => sb.commands.start(["python", "run.py"])).toThrow(mvm.SandboxDevOnly);
    expect(readFixtureLog().some((c) => c.startsWith("machine proc"))).toBe(false);
  });

  it("treats a missing build_mode as non-dev (fail-closed)", () => {
    const lsOut = JSON.stringify([{ name: "m", status: "running" }]);
    const script = writeFixtureMvmctl({ upEnvelope: null, lsOut });
    process.env.MVM_CLI_BIN = script;

    const sb = mvm.Sandbox.connect("m");
    expect(sb._live!.buildMode).toBe("prod");
    expect(() => sb.exec(["echo", "hi"])).toThrow(mvm.SandboxDevOnly);
  });

  it("throws when the machine is not listed", () => {
    const lsOut = JSON.stringify([{ name: "other", build_mode: "dev", status: "running" }]);
    const script = writeFixtureMvmctl({ upEnvelope: null, lsOut });
    process.env.MVM_CLI_BIN = script;
    expect(() => mvm.Sandbox.connect("ghost")).toThrow(/no machine named/);
  });

  it("propagates a machine ls failure", () => {
    const script = writeFixtureMvmctl({ upEnvelope: null, lsExit: 5 });
    process.env.MVM_CLI_BIN = script;
    expect(() => mvm.Sandbox.connect("web-1")).toThrow(/exit code 5/);
  });

  it("refuses a second concurrent session", () => {
    const lsOut = JSON.stringify([{ name: "a", build_mode: "dev", status: "running" }]);
    const script = writeFixtureMvmctl({ upEnvelope: null, lsOut });
    process.env.MVM_CLI_BIN = script;
    mvm.Sandbox.connect("a");
    expect(() => mvm.Sandbox.connect("a")).toThrow(/already active/);
  });

  it("rejects an empty id", () => {
    expect(() => mvm.Sandbox.connect("")).toThrow(/non-empty machine id/);
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
    expect(calls[0]).toMatch(/^machine run -d --up-json --name /);
    expect(calls[0]).toContain("--manifest python-3.12");
    expect(calls[0]).toContain("--ttl");
  });

  it("lowers an image, literal env, allowlist, and boot command", () => {
    const script = writeFixtureMvmctl({
      upEnvelope: { schema_version: 1, vm_id: "browser", build_mode: "dev" },
    });
    process.env.MVM_SDK_MODE = "live";
    process.env.MVM_CLI_BIN = script;
    mvm.Sandbox.create(
      { image: mvm.OBSCURA_IMAGE },
      {
        env: { MODE: "safe" },
        network: {
          mode: "none",
          egress: { allowlist: [{ host: "example.com", port: 443 }] },
        },
        command: ["/obscura", "serve"],
      },
    );
    const call = readFixtureLog()[0];
    expect(call).toContain(`--image ${mvm.OBSCURA_IMAGE}`);
    expect(call).toContain("--env MODE=safe");
    expect(call).toContain("--allow-host example.com:443");
    expect(call).toContain("-- /obscura serve");
  });

  it("rejects secrets and unrepresentable options before boot", () => {
    const script = writeFixtureMvmctl({
      upEnvelope: { schema_version: 1, vm_id: "unused", build_mode: "dev" },
    });
    process.env.MVM_SDK_MODE = "live";
    process.env.MVM_CLI_BIN = script;
    expect(() =>
      mvm.Sandbox.create("minimal", {
        env: { TOKEN: mvm.secret("token", { type: "bearer", hosts: ["example.com"] }) },
      }),
    ).toThrow(/only literal/);
    expect(readFixtureLog()).toEqual([]);
    expect(() =>
      mvm.Sandbox.create("minimal", {
        resources: { cpu_cores: 1, memory_mb: 256, rootfs_size_mb: 512 },
      }),
    ).toThrow(/resources/);
    expect(readFixtureLog()).toEqual([]);
    expect(() =>
      mvm.Sandbox.create("minimal", {
        network: { raw_ip_stack: true } as never,
      }),
    ).toThrow(/unknown fields/);
    expect(readFixtureLog()).toEqual([]);
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
    expect(calls[1]).toMatch(/^machine proc start sb-dev-vm/);
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
    // Critical: SDK must NOT have shelled to `mvmctl machine proc start`.
    const calls = readFixtureLog();
    expect(calls.length).toBe(1);
    expect(calls.some((c) => c.startsWith("machine proc"))).toBe(false);
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
    expect(calls.some((c) => c.startsWith("machine fs write sb-fs-vm /app/config.json"))).toBe(true);
    const stdinPath = path.join(tmpDir, "fixture-stdin", "fs-write-stdin.bin");
    expect(fs.readFileSync(stdinPath, "utf-8")).toBe('{"x":1}');
  });
});

describe("runtime process and filesystem surface", () => {
  it("returns a process handle with streamed output and controls", async () => {
    const script = writeFixtureMvmctl({
      upEnvelope: { schema_version: 1, vm_id: "sb-proc-vm", build_mode: "dev" },
      procWaitStdout: "out",
      procWaitStderr: "err",
    });
    process.env.MVM_SDK_MODE = "live";
    process.env.MVM_CLI_BIN = script;
    const sb = mvm.Sandbox.create("python-dev");
    const handle = sb.commands.start(["python", "run.py"]);
    expect(handle).toBeDefined();
    const events: mvm.ProcessStreamEvent[] = [];
    const result = await handle!.wait({ onEvent: (event) => events.push(event) });
    expect(new TextDecoder().decode(result.stdout)).toBe("out");
    expect(new TextDecoder().decode(result.stderr)).toBe("err");
    expect(events.map((event) => [event.stream, new TextDecoder().decode(event.data)]).sort()).toEqual([
      ["stderr", "err"],
      ["stdout", "out"],
    ]);
    handle!.sendStdin("input");
    handle!.signal(15);
    handle!.kill();
    const calls = readFixtureLog();
    expect(calls.some((c) => c.includes("machine proc stdin sb-proc-vm"))).toBe(true);
    expect(calls.some((c) => c.includes("machine proc signal sb-proc-vm"))).toBe(true);
    expect(calls.some((c) => c.includes("machine proc kill sb-proc-vm"))).toBe(true);
    sb.kill();
  });

  it("reads, lists, stats, and mutates guest files", () => {
    const script = writeFixtureMvmctl({
      upEnvelope: { schema_version: 1, vm_id: "sb-fs-vm", build_mode: "dev" },
      fsReadStdout: "hello",
      fsLsJson: '[{"name":"note.txt","kind":"file","size":5}]',
      fsStatJson: '{"canonical_path":"/app/note.txt","kind":"file","mode":420,"size":5,"mtime":null}',
    });
    process.env.MVM_SDK_MODE = "live";
    process.env.MVM_CLI_BIN = script;
    const sb = mvm.Sandbox.create("python-dev");
    expect(new TextDecoder().decode(sb.files.read("/app/note.txt"))).toBe("hello");
    expect(sb.files.list("/app")[0]?.name).toBe("note.txt");
    expect(sb.files.stat("/app/note.txt").size).toBe(5);
    sb.files.mkdir("/app/new", true);
    sb.files.remove("/app/old", true);
    sb.files.move("/app/a", "/app/b");
    const calls = readFixtureLog();
    expect(calls.some((c) => c.includes("machine fs read sb-fs-vm /app/note.txt"))).toBe(true);
    expect(calls.some((c) => c.includes("machine fs ls sb-fs-vm /app --json"))).toBe(true);
    expect(calls.some((c) => c.includes("machine fs stat sb-fs-vm /app/note.txt --json"))).toBe(true);
    expect(calls.some((c) => c.includes("machine fs mkdir sb-fs-vm /app/new"))).toBe(true);
    expect(calls.some((c) => c.includes("machine fs rm sb-fs-vm /app/old"))).toBe(true);
    expect(calls.some((c) => c.includes("machine fs mv sb-fs-vm /app/a /app/b"))).toBe(true);
    sb.kill();
  });

  it("fails closed for every development-only live verb on prod", () => {
    const script = writeFixtureMvmctl({
      upEnvelope: { schema_version: 1, vm_id: "sb-prod-vm", build_mode: "prod" },
    });
    process.env.MVM_SDK_MODE = "live";
    process.env.MVM_CLI_BIN = script;
    const sb = mvm.Sandbox.create("python-prod");
    const operations = [
      () => sb.commands.start(["python"]),
      () => sb.exec(["python"]),
      () => sb.files.write("/app/x", "x"),
      () => sb.files.read("/app/x"),
      () => sb.files.list("/app"),
      () => sb.files.stat("/app/x"),
      () => sb.files.mkdir("/app/x"),
      () => sb.files.remove("/app/x"),
      () => sb.files.move("/app/x", "/app/y"),
      () => sb.copyIn("/tmp/x", "/app/x"),
      () => sb.copyOut("/app/x", "/tmp/x"),
    ];
    for (const operation of operations) {
      expect(operation).toThrow(mvm.SandboxDevOnly);
    }
    expect(() => sb.forward(8080, 80)).toThrow(mvm.SandboxModeError);
    expect(readFixtureLog().slice(1).some((call) =>
      call.startsWith("machine proc") ||
      call.startsWith("machine fs") ||
      call.startsWith("machine cp") ||
      call.startsWith("forward"),
    )).toBe(false);
    sb.kill();
  });
});

// ── kill / dispose ───────────────────────────────────────────────────

describe("Sandbox.kill (live mode)", () => {
  it("shells to mvmctl machine stop", () => {
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
    expect(calls).toContain("machine stop sb-kill-vm --yes");
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

    const downCalls = readFixtureLog().filter((c) => c.startsWith("machine stop "));
    expect(downCalls.length).toBe(1);
  });
});

// ── copyIn / copyOut (Plan 125 B1) ───────────────────────────────────

describe("Sandbox.copyIn / copyOut (live mode)", () => {
  it("copyIn shells to mvmctl machine cp host -> vm:guest", () => {
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
      calls.some((c) => c.startsWith(`machine cp ${hostFile} sb-cp-vm:/app/local.txt`)),
    ).toBe(true);
  });

  it("copyOut shells to mvmctl machine cp vm:guest -> host", () => {
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
      calls.some((c) => c.startsWith(`machine cp sb-cp-vm:/app/out.txt ${dest}`)),
    ).toBe(true);
  });

  it("copyIn propagates a mvmctl machine cp failure", () => {
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

// ── declared ingress ─────────────────────────────────────────────────

describe("Sandbox.forward (live mode)", () => {
  it("refuses dynamic forwarding with the signed-plan migration", () => {
    const script = writeFixtureMvmctl({
      upEnvelope: { schema_version: 1, vm_id: "sb-fwd-vm", build_mode: "dev" },
    });
    process.env.MVM_SDK_MODE = "live";
    process.env.MVM_CLI_BIN = script;

    const sb = mvm.Sandbox.create("python-dev");
    expect(() => sb.forward(8080, 80)).toThrow(/before boot/);
    expect(readFixtureLog().some((c) => c.startsWith("machine forward"))).toBe(false);
  });

  it("passes declared opaque TCP ingress to machine run", () => {
    const script = writeFixtureMvmctl({
      upEnvelope: { schema_version: 1, vm_id: "sb-fwd-vm", build_mode: "dev" },
    });
    process.env.MVM_SDK_MODE = "live";
    process.env.MVM_CLI_BIN = script;

    mvm.Sandbox.create("python-dev", {
      network: {
        mode: "none",
        ports: [{
          mapping_id: 1,
          proto: "tcp",
          host_addr: "127.0.0.1",
          host: 8080,
          guest_addr: "127.0.0.1",
          guest: 80,
          transform: "opaque",
        }],
      },
    });
    const run = readFixtureLog()[0];
    expect(run).toContain("machine run");
    expect(run).toContain("--port 8080:80");
    expect(run.split(" ")).not.toContain("-d");
  });

  it("is refused in record mode", () => {
    process.env.MVM_SDK_MODE = "record";
    const sb = mvm.Sandbox.create("python-dev");
    expect(() => sb.forward(8080, 80)).toThrow(mvm.SandboxModeError);
  });
});

// ── exec (live mode, dev-only) — Plan 125 D1 TS parity ───────────────

describe("Sandbox.exec (live mode)", () => {
  it("runs argv and returns captured stdout + exit", () => {
    const script = writeFixtureMvmctl({
      upEnvelope: { schema_version: 1, vm_id: "sb-exec-vm", build_mode: "dev" },
      procWaitStdout: "4",
    });
    process.env.MVM_SDK_MODE = "live";
    process.env.MVM_CLI_BIN = script;

    const sb = mvm.Sandbox.create("python-dev");
    const r = sb.exec(["python", "-c", "print(2 + 2)"]);

    expect(r.exitCode).toBe(0);
    expect(r.stdout).toBe("4");
    const calls = readFixtureLog();
    expect(calls.some((c) => c.startsWith("machine proc start sb-exec-vm"))).toBe(true);
    expect(
      calls.some((c) =>
        c.startsWith("machine proc wait sb-exec-vm pid-token-abc123"),
      ),
    ).toBe(true);
  });

  it("surfaces a non-zero exit code", () => {
    const script = writeFixtureMvmctl({
      upEnvelope: { schema_version: 1, vm_id: "sb-exec-vm", build_mode: "dev" },
      procWaitExit: 3,
    });
    process.env.MVM_SDK_MODE = "live";
    process.env.MVM_CLI_BIN = script;

    const sb = mvm.Sandbox.create("python-dev");
    expect(sb.exec(["false"]).exitCode).toBe(3);
  });

  it("forwards literal env as -e KEY=VAL", () => {
    const script = writeFixtureMvmctl({
      upEnvelope: { schema_version: 1, vm_id: "sb-exec-vm", build_mode: "dev" },
      procWaitStdout: "ok",
    });
    process.env.MVM_SDK_MODE = "live";
    process.env.MVM_CLI_BIN = script;

    const sb = mvm.Sandbox.create("python-dev");
    sb.exec(["env"], { env: { MODE: "test" } });

    const calls = readFixtureLog();
    const start = calls.find((c) => c.startsWith("machine proc start"));
    expect(start).toContain("-e MODE=test");
    expect(start).toContain("-- env");
  });

  it("raises SandboxDevOnly against a prod template (no proc traffic)", () => {
    const script = writeFixtureMvmctl({
      upEnvelope: { schema_version: 1, vm_id: "sb-prod-vm", build_mode: "prod" },
    });
    process.env.MVM_SDK_MODE = "live";
    process.env.MVM_CLI_BIN = script;

    const sb = mvm.Sandbox.create("python-prod");
    expect(() => sb.exec(["python", "-c", "x"])).toThrow(mvm.SandboxDevOnly);
    // Claim 4: must not have shelled `mvmctl machine proc start`.
    expect(readFixtureLog().some((c) => c.startsWith("machine proc"))).toBe(false);
  });

  it("is refused in record mode", () => {
    process.env.MVM_SDK_MODE = "record";
    const sb = mvm.Sandbox.create("python-dev");
    expect(() => sb.exec(["python"])).toThrow(mvm.SandboxModeError);
  });
});

// ── async surface — Plan 125 B2 (await sb.exec + await using) ─────────

describe("Sandbox async surface", () => {
  it("await sb.exec(...) works (await passthrough on sync exec)", async () => {
    const script = writeFixtureMvmctl({
      upEnvelope: { schema_version: 1, vm_id: "sb-ae-vm", build_mode: "dev" },
      procWaitStdout: "4",
    });
    process.env.MVM_SDK_MODE = "live";
    process.env.MVM_CLI_BIN = script;

    const sb = mvm.Sandbox.create("python-dev");
    const r = await sb.exec(["python", "-c", "print(2 + 2)"]);
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toBe("4");
  });

  it("[Symbol.asyncDispose] tears down (await using parity)", async () => {
    const script = writeFixtureMvmctl({
      upEnvelope: { schema_version: 1, vm_id: "sb-ae-vm", build_mode: "dev" },
    });
    process.env.MVM_SDK_MODE = "live";
    process.env.MVM_CLI_BIN = script;

    const sb = mvm.Sandbox.create("python-dev");
    await sb[Symbol.asyncDispose]();
    expect(readFixtureLog().some((c) => c.startsWith("machine stop "))).toBe(true);
  });
});

// ── lifecycle: id + info — Plan 125 B3 ───────────────────────────────

describe("Sandbox id + info", () => {
  it("id is the vmId when live, info reflects live state", () => {
    const script = writeFixtureMvmctl({
      upEnvelope: { schema_version: 1, vm_id: "sb-id-vm", build_mode: "dev" },
    });
    process.env.MVM_SDK_MODE = "live";
    process.env.MVM_CLI_BIN = script;

    const sb = mvm.Sandbox.create("python-dev", { workloadId: "wl-1" });
    expect(sb.id).toBe("sb-id-vm");
    expect(sb.info()).toEqual({
      id: "sb-id-vm",
      workloadId: "wl-1",
      buildMode: "dev",
      live: true,
    });
  });

  it("id is the workloadId in record mode, info reflects record state", () => {
    process.env.MVM_SDK_MODE = "record";
    const sb = mvm.Sandbox.create("python-dev", { workloadId: "wl-1" });
    expect(sb.id).toBe("wl-1");
    expect(sb.info()).toEqual({
      id: "wl-1",
      workloadId: "wl-1",
      buildMode: null,
      live: false,
    });
  });
});

// ── CodeSandbox typed helper — Plan 125 C1 ───────────────────────────

describe("CodeSandbox", () => {
  it("run() returns stdout via python -c", () => {
    const script = writeFixtureMvmctl({
      upEnvelope: { schema_version: 1, vm_id: "sb-cs-vm", build_mode: "dev" },
      procWaitStdout: "4",
    });
    process.env.MVM_SDK_MODE = "live";
    process.env.MVM_CLI_BIN = script;

    const cs = new mvm.CodeSandbox("python:slim");
    try {
      expect(cs.run("print(2 + 2)")).toBe("4");
      const calls = readFixtureLog();
      expect(
        calls.some((c) => c.startsWith("machine proc start sb-cs-vm") && c.includes("-- python -c")),
      ).toBe(true);
    } finally {
      cs.kill();
    }
  });

  it("run() throws CodeError on a non-zero exit", () => {
    const script = writeFixtureMvmctl({
      upEnvelope: { schema_version: 1, vm_id: "sb-cs-vm", build_mode: "dev" },
      procWaitExit: 1,
    });
    process.env.MVM_SDK_MODE = "live";
    process.env.MVM_CLI_BIN = script;

    const cs = new mvm.CodeSandbox("python:slim");
    try {
      expect(() => cs.run("import sys; sys.exit(1)")).toThrow(mvm.CodeError);
    } finally {
      cs.kill();
    }
  });

  it("installPackage() shells the package manager", () => {
    const script = writeFixtureMvmctl({
      upEnvelope: { schema_version: 1, vm_id: "sb-cs-vm", build_mode: "dev" },
    });
    process.env.MVM_SDK_MODE = "live";
    process.env.MVM_CLI_BIN = script;

    const cs = new mvm.CodeSandbox("python:slim");
    try {
      cs.installPackage("requests");
      expect(readFixtureLog().some((c) => c.includes("-- pip install requests"))).toBe(true);
    } finally {
      cs.kill();
    }
  });

  it("runScript() copies then execs the script", () => {
    const script = writeFixtureMvmctl({
      upEnvelope: { schema_version: 1, vm_id: "sb-cs-vm", build_mode: "dev" },
      procWaitStdout: "ok",
    });
    process.env.MVM_SDK_MODE = "live";
    process.env.MVM_CLI_BIN = script;
    const hostScript = path.join(tmpDir, "job.py");
    fs.writeFileSync(hostScript, "print('ok')");

    const cs = new mvm.CodeSandbox("python:slim");
    try {
      expect(cs.runScript(hostScript)).toBe("ok");
      const calls = readFixtureLog();
      expect(calls.some((c) => c.startsWith("machine cp ") && c.includes("sb-cs-vm:/tmp/job.py"))).toBe(true);
      expect(calls.some((c) => c.includes("-- python /tmp/job.py"))).toBe(true);
    } finally {
      cs.kill();
    }
  });

  it("a node image uses the node runner", () => {
    const script = writeFixtureMvmctl({
      upEnvelope: { schema_version: 1, vm_id: "sb-cs-vm", build_mode: "dev" },
      procWaitStdout: "4",
    });
    process.env.MVM_SDK_MODE = "live";
    process.env.MVM_CLI_BIN = script;

    const cs = new mvm.CodeSandbox("node:22");
    try {
      cs.run("console.log(2 + 2)");
      expect(readFixtureLog().some((c) => c.includes("-- node -e"))).toBe(true);
    } finally {
      cs.kill();
    }
  });
});

// ── BrowserSandbox typed helper — Plan 125 C2 ────────────────────────

describe("BrowserSandbox", () => {
  it("uses the pinned image, fixed proxy/loopback command, and allowlist", () => {
    const script = writeFixtureMvmctl({
      upEnvelope: { schema_version: 1, vm_id: "obscura", build_mode: "dev" },
    });
    process.env.MVM_SDK_MODE = "live";
    process.env.MVM_CLI_BIN = script;
    const bs = new mvm.BrowserSandbox("obscura", {
      network: {
        mode: "none",
        egress: { allowlist: [{ host: "example.com", port: 443 }] },
      },
    });
    try {
      const call = readFixtureLog()[0];
      expect(call).toContain(`--image ${mvm.OBSCURA_IMAGE}`);
      expect(call).toContain("--allow-host example.com:443");
      expect(call).toContain("-- /obscura --proxy http://127.0.0.1:1080 serve");
      expect(call).toContain("--host 127.0.0.1 --port 9222");
      expect(call).not.toContain("private");
      expect(call).not.toContain("stealth");
    } finally {
      bs.kill();
    }
  });

  it("refuses an Obscura command override before boot", () => {
    const script = writeFixtureMvmctl({
      upEnvelope: { schema_version: 1, vm_id: "unused", build_mode: "dev" },
    });
    process.env.MVM_SDK_MODE = "live";
    process.env.MVM_CLI_BIN = script;
    expect(() => new mvm.BrowserSandbox("obscura", { command: ["/bin/sh"] })).toThrow(
      /does not allow command overrides/,
    );
    expect(readFixtureLog()).toEqual([]);
  });

  it("validates CDP readiness and cleans up after timeout", async () => {
    const server = http.createServer((_request, response) => {
      response.setHeader("content-type", "application/json");
      response.end(JSON.stringify({ webSocketDebuggerUrl: "ws://127.0.0.1/devtools/browser/test" }));
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    if (address === null || typeof address === "string") throw new Error("expected TCP address");
    const script = writeFixtureMvmctl({
      upEnvelope: { schema_version: 1, vm_id: "browser", build_mode: "dev" },
    });
    process.env.MVM_SDK_MODE = "live";
    process.env.MVM_CLI_BIN = script;
    const bs = new mvm.BrowserSandbox("chromium", { hostPort: address.port });
    expect(await bs.waitUntilReady({ timeoutMs: 1000 })).toBe(
      "ws://127.0.0.1/devtools/browser/test",
    );
    bs.kill();
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    );

    const failing = new mvm.BrowserSandbox("chromium", { hostPort: address.port });
    await expect(failing.waitUntilReady({ timeoutMs: 20, retryMs: 2 })).rejects.toBeInstanceOf(
      mvm.BrowserReadyError,
    );
    expect(readFixtureLog().some((call) => call.startsWith("machine stop browser --yes"))).toBe(true);
  });

  it("declares the CDP port and endpoint() returns the host URL", () => {
    const script = writeFixtureMvmctl({
      upEnvelope: { schema_version: 1, vm_id: "sb-br-vm", build_mode: "dev" },
    });
    process.env.MVM_SDK_MODE = "live";
    process.env.MVM_CLI_BIN = script;

    const bs = new mvm.BrowserSandbox("chromium");
    try {
      expect(bs.endpoint()).toBe("http://localhost:9222");
      expect(readFixtureLog()[0]).toContain("--port 9222:9222");
    } finally {
      bs.kill();
    }
  });

  it("honours a custom host port", () => {
    const script = writeFixtureMvmctl({
      upEnvelope: { schema_version: 1, vm_id: "sb-br-vm", build_mode: "dev" },
    });
    process.env.MVM_SDK_MODE = "live";
    process.env.MVM_CLI_BIN = script;

    const bs = new mvm.BrowserSandbox("chromium", { hostPort: 18222 });
    try {
      expect(bs.endpoint()).toBe("http://localhost:18222");
      expect(readFixtureLog()[0]).toContain("--port 18222:9222");
    } finally {
      bs.kill();
    }
  });

  it("throws on an unknown browser", () => {
    expect(() => new mvm.BrowserSandbox("safari")).toThrow(/unknown browser/);
  });
});
