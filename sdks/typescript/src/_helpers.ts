/**
 * Typed `Sandbox` presets (Plan 125 Phase C).
 *
 * Mirror of `sdks/python/mvm/_helpers.py`. Thin, opinionated helpers built
 * entirely over the imperative `Sandbox` surface (`exec` / `copyIn`) — no
 * new transport or mechanism. `CodeSandbox` is the code-runner preset.
 */

import { Sandbox, type ExecResult, type SandboxCreateOptions } from "./_sandbox.js";

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
    this._sandbox = Sandbox.create(image, options);
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
const BROWSERS: Record<string, { image: string; cdpPort: number }> = {
  chromium: { image: "chromium", cdpPort: 9222 },
  chrome: { image: "chrome", cdpPort: 9222 },
};

/** Options for {@link BrowserSandbox} — `Sandbox.create` options plus an
 *  optional host port override for the forwarded CDP port. */
export interface BrowserSandboxOptions extends SandboxCreateOptions {
  hostPort?: number;
}

/** A `Sandbox` preset for a headless browser: a baked browser image with its
 *  CDP port forwarded to the host. Image + port preset only — no new
 *  mechanism (the forward is `Sandbox.forward`, the protocol is the browser's
 *  own CDP).
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
    const { hostPort, ...createOptions } = options;
    this.hostPort = hostPort ?? preset.cdpPort;
    this._sandbox = Sandbox.create(preset.image, createOptions);
    this._sandbox.forward(this.hostPort, preset.cdpPort);
  }

  /** The underlying `Sandbox` for direct access. */
  get sandbox(): Sandbox {
    return this._sandbox;
  }

  /** Host-side CDP HTTP endpoint (e.g. `http://localhost:9222`). */
  endpoint(): string {
    return `http://localhost:${this.hostPort}`;
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
