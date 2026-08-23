/**
 * Typed `Sandbox` presets (Plan 125 Phase C).
 *
 * Mirror of `sdks/python/mvm/_helpers.py`. Thin, opinionated helpers built
 * entirely over the imperative `Sandbox` surface (`exec` / `copyIn`) — no
 * new transport or mechanism. `CodeSandbox` is the code-runner preset.
 */

import * as http from "node:http";
import {
  Sandbox,
  type ExecResult,
  type SandboxCreateOptions,
  type SandboxSource,
} from "./_sandbox.js";

/** A `CodeSandbox.run` / `runScript` / `installPackage` exited non-zero.
 *  Carries the captured exit code + streams for inspection. */
export class CodeError extends Error {
  readonly exitCode: number;
  readonly stdout: string;
  readonly stderr: string;
  constructor(
    message: string,
    info: { exitCode: number; stdout: string; stderr: string },
  ) {
    super(message);
    this.name = "CodeError";
    this.exitCode = info.exitCode;
    this.stdout = info.stdout;
    this.stderr = info.stderr;
  }
}

// Per-language runner: interpreter, inline-eval flag, package-install argv.
const RUNNERS = {
  python: { interp: "python", inlineFlag: "-c", install: ["pip", "install"] },
  node: { interp: "node", inlineFlag: "-e", install: ["npm", "install"] },
} as const;

type Lang = keyof typeof RUNNERS;

function runnerFor(image: string): Lang {
  return image.toLowerCase().includes("node") ? "node" : "python";
}

function basename(p: string): string {
  return p.split(/[\\/]/).pop() ?? p;
}

function checked(result: ExecResult): string {
  if (result.exitCode !== 0) {
    throw new CodeError(`code runner exited ${result.exitCode}`, {
      exitCode: result.exitCode,
      stdout: result.stdout,
      stderr: result.stderr,
    });
  }
  return result.stdout;
}

/** A `Sandbox` preset for running code snippets in a language-runner image.
 *  Live-tier (the underlying `Sandbox.exec` is dev-only).
 *
 *  @example
 *  const cs = new CodeSandbox("python:slim");
 *  try { expect(cs.run("print(2 + 2)").trim()).toBe("4"); }
 *  finally { cs.kill(); }
 */
export class CodeSandbox {
  private readonly _sandbox: Sandbox;
  private readonly lang: Lang;

  constructor(image = "python:slim", options: SandboxCreateOptions = {}) {
    this.lang = runnerFor(image);
    this._sandbox = Sandbox.create({ image }, options);
  }

  /** The underlying `Sandbox` for direct access (`copyIn`, `forward`, …). */
  get sandbox(): Sandbox {
    return this._sandbox;
  }

  /** Run `code` inline (`<interp> -c/-e <code>`) and return its stdout.
   *  Throws {@link CodeError} on a non-zero exit. */
  run(code: string): string {
    const r = RUNNERS[this.lang];
    return checked(this._sandbox.exec([r.interp, r.inlineFlag, code]));
  }

  /** Copy a host script into the sandbox and run it with the language
   *  interpreter; returns its stdout. Throws {@link CodeError} on failure. */
  runScript(hostPath: string): string {
    const r = RUNNERS[this.lang];
    const guestPath = `/tmp/${basename(hostPath)}`;
    this._sandbox.copyIn(hostPath, guestPath);
    return checked(this._sandbox.exec([r.interp, guestPath]));
  }

  /** Install a package with the language's package manager
   *  (`pip install` / `npm install`). Throws {@link CodeError} on failure. */
  installPackage(pkg: string): void {
    const r = RUNNERS[this.lang];
    checked(this._sandbox.exec([...r.install, pkg]));
  }

  kill(): void {
    this._sandbox.kill();
  }

  [Symbol.dispose](): void {
    this.kill();
  }

  async [Symbol.asyncDispose](): Promise<void> {
    this.kill();
  }
}

// Browser → image + default CDP port. Chromium-family browsers expose the
// Chrome DevTools Protocol on 9222.
export const OBSCURA_IMAGE =
  "docker.io/h4ckf0r0day/obscura@sha256:78c99ac89d010d444d96d85c183a2db912c41f807b7807d697df98ab7e4bd3c2";

const MVM_EGRESS_PROXY = "http://127.0.0.1:1080";

export class BrowserReadyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BrowserReadyError";
  }
}

interface BrowserPreset {
  source: SandboxSource;
  cdpPort: number;
  command?: readonly string[];
}

const BROWSERS: Record<string, BrowserPreset> = {
  chromium: { source: { manifest: "chromium" }, cdpPort: 9222 },
  chrome: { source: { manifest: "chrome" }, cdpPort: 9222 },
  obscura: {
    source: { image: OBSCURA_IMAGE },
    cdpPort: 9222,
    command: [
      "/obscura",
      "--proxy",
      MVM_EGRESS_PROXY,
      "serve",
      "--host",
      "127.0.0.1",
      "--port",
      "9222",
    ],
  },
};

function probeCdpVersion(port: number, timeoutMs: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const request = http.get(
      { host: "127.0.0.1", port, path: "/json/version", timeout: timeoutMs },
      (response) => {
        if (response.statusCode === undefined || response.statusCode < 200 || response.statusCode >= 300) {
          response.resume();
          reject(new Error(`CDP version endpoint returned ${String(response.statusCode)}`));
          return;
        }
        const chunks: Buffer[] = [];
        let size = 0;
        response.on("data", (chunk: Buffer) => {
          size += chunk.length;
          if (size > 65536) {
            request.destroy(new Error("CDP version response exceeds 64 KiB"));
            return;
          }
          chunks.push(chunk);
        });
        response.on("end", () => {
          try {
            const parsed = JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
            const websocket =
              typeof parsed === "object" && parsed !== null
                ? (parsed as Record<string, unknown>).webSocketDebuggerUrl
                : undefined;
            if (typeof websocket !== "string" || websocket.length === 0) {
              reject(new Error("CDP response lacks webSocketDebuggerUrl"));
              return;
            }
            resolve(websocket);
          } catch (error) {
            reject(error);
          }
        });
      },
    );
    request.on("timeout", () => request.destroy(new Error("CDP probe timed out")));
    request.on("error", reject);
  });
}

/** Options for {@link BrowserSandbox} — `Sandbox.create` options plus an
 *  optional host port override for the declared CDP ingress port. */
export interface BrowserSandboxOptions extends SandboxCreateOptions {
  hostPort?: number;
}

/** A `Sandbox` preset for a headless browser: a baked browser image with its
 *  CDP port declared as signed ingress before boot. Image + port preset only —
 *  no new mechanism (the protocol is the browser's own CDP).
 *
 *  `endpoint()` returns the host-side CDP HTTP base; pass it to a CDP client
 *  (Playwright/Puppeteer `connectOverCDP` / `browserURL`), which discovers the
 *  per-session WebSocket URL from `/json/version`. */
export class BrowserSandbox {
  private readonly _sandbox: Sandbox;
  private readonly hostPort: number;

  constructor(browser = "chromium", options: BrowserSandboxOptions = {}) {
    const preset = BROWSERS[browser];
    if (preset === undefined) {
      throw new RangeError(
        `unknown browser ${JSON.stringify(browser)}; supported: ${Object.keys(BROWSERS).join(", ")}`,
      );
    }
    const { hostPort, command: callerCommand, ...createOptions } = options;
    if (preset.command !== undefined && callerCommand !== undefined) {
      throw new RangeError("the obscura provider does not allow command overrides");
    }
    this.hostPort = hostPort ?? preset.cdpPort;
    const existingNetwork = createOptions.network ?? { mode: "none", ports: [] };
    const existingPorts = existingNetwork.ports ?? [];
    const mappingId = existingPorts.reduce(
      (highest, mapping) => Math.max(highest, mapping.mapping_id),
      0,
    ) + 1;
    this._sandbox = Sandbox.create(preset.source, {
      ...createOptions,
      network: {
        ...existingNetwork,
        ports: [
          ...existingPorts,
          {
            mapping_id: mappingId,
            proto: "tcp",
            host_addr: "127.0.0.1",
            host: this.hostPort,
            guest_addr: "127.0.0.1",
            guest: preset.cdpPort,
            transform: "opaque",
          },
        ],
      },
      ...(preset.command !== undefined
        ? { command: [...preset.command] }
        : callerCommand !== undefined
          ? { command: callerCommand }
          : {}),
    });
  }

  /** The underlying `Sandbox` for direct access. */
  get sandbox(): Sandbox {
    return this._sandbox;
  }

  /** Host-side CDP HTTP endpoint (e.g. `http://localhost:9222`). */
  endpoint(): string {
    return `http://localhost:${this.hostPort}`;
  }

  /** Wait for a bounded, structurally valid CDP version response. */
  async waitUntilReady(options: { timeoutMs?: number; retryMs?: number } = {}): Promise<string> {
    const timeoutMs = options.timeoutMs ?? 10000;
    const retryMs = options.retryMs ?? 100;
    if (timeoutMs <= 0 || retryMs <= 0) {
      throw new RangeError("timeoutMs and retryMs must be positive");
    }
    const deadline = performance.now() + timeoutMs;
    let lastError: unknown;
    while (performance.now() < deadline) {
      try {
        const remaining = Math.max(1, deadline - performance.now());
        return await probeCdpVersion(this.hostPort, Math.min(remaining, 1000));
      } catch (error) {
        lastError = error;
        const remaining = deadline - performance.now();
        if (remaining > 0) {
          await new Promise((resolve) => setTimeout(resolve, Math.min(retryMs, remaining)));
        }
      }
    }
    this.kill();
    throw new BrowserReadyError(
      `browser CDP endpoint http://127.0.0.1:${this.hostPort}/json/version was not ready within ${timeoutMs}ms${
        lastError instanceof Error ? `: ${lastError.message}` : ""
      }`,
    );
  }

  kill(): void {
    this._sandbox.kill();
  }

  [Symbol.dispose](): void {
    this.kill();
  }

  async [Symbol.asyncDispose](): Promise<void> {
    this.kill();
  }
}
