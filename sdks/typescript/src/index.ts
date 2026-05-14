/**
 * mvm — TypeScript SDK for declaring microVM workloads.
 *
 * SDK port Phase 6. Mirror of the Python SDK at `sdks/python/mvm/` —
 * the same `Workload` IR shape, the same `HELPER_ALLOWLIST` of
 * decorator-friendly helpers, the same four hook kwargs on `app(...)`.
 *
 * Surface aligned with the host-side decorator parser
 * (`crates/mvm-sdk/src/decorator/typescript.rs`) so a single TS file
 * can validate identically through:
 *
 *   - The in-process SDK (this module): user writes
 *     `import * as mvm from "mvm-sdk"; export const greet =
 *      mvm.app({...})((name: string) => ...)` and runs `tsc + node` /
 *     `tsx` to emit IR via `mvm.emitJson()`.
 *   - The AST-walking compiler: `mvmctl compile app.ts` reads the same
 *     file without executing it and produces the same IR.
 *
 * v1 ships the declarative shape:
 *
 *     mvm.app({
 *       image: mvm.python_image({ python: "3.12" }),
 *       resources: mvm.resources({ cpu: 1, memory_mb: 256 }),
 *       env: { API_KEY: mvm.secret("api-key") },
 *       before_start: mvm.hook("export FOO=1"),
 *       after_start: mvm.hook(["curl", "-fsS", "/h"]),
 *     })((name: string): string => `hello ${name}`);
 *
 * Imperative `Sandbox` + fluent `WorkloadBuilder` ergonomics ship in
 * a follow-up alongside the runtime record-mode (Phase 7).
 */

import type {
  AddonUse,
  App,
  Dependencies,
  Entrypoint,
  EnvValue,
  HookCmd,
  Hooks,
  Image,
  Mount,
  Network,
  PortForward,
  Resources,
  Source,
  ThreatTier,
  Workload,
} from "./ir/workload.js";

// Re-export the codegen output so callers `import { Workload } from
// "mvm-sdk"` directly rather than reaching into the `ir/` sub-path.
export * from "./ir/workload.js";

// Sandbox record-mode SDK (Phase 7c + 7f). Imperative companion to
// the static `mvm.app({...})` decorator above.
export {
  DEFAULT_TTL_SECONDS,
  MVM_SDK_MODE_ENV,
  MVM_SDK_OUT_PATH_ENV,
  RecordingNotActiveError,
  Sandbox,
  SandboxCommands,
  SandboxFiles,
  SandboxModeError,
  currentRecording,
  emitRecordingJson,
  flushRecordingToOutPath,
  resetRecording,
} from "./_sandbox.js";
export type {
  RecordedOpWire,
  RuntimeRecordingWire,
  SandboxCommandsStartOptions,
  SandboxCreateOptions,
  SandboxCreateWire,
} from "./_sandbox.js";

// ────────────────────────────────────────────────────────────────────
// Module state
// ────────────────────────────────────────────────────────────────────

const SCHEMA_VERSION = "0.1";

interface State {
  workloadId: string | null;
  apps: App[];
}

const state: State = {
  workloadId: null,
  apps: [],
};

/** Reset SDK module state. Exposed for tests. */
export function reset(): void {
  state.workloadId = null;
  state.apps = [];
}

/** Declare the workload identity. Must be called exactly once before
 *  any `app(...)` call. */
export function workload(opts: { id: string }): void {
  if (state.workloadId !== null) {
    throw new Error("mvm.workload(...) called twice");
  }
  if (!opts.id) {
    throw new Error("workload id must be a non-empty string");
  }
  state.workloadId = opts.id;
}

// ────────────────────────────────────────────────────────────────────
// Source / image helpers
// ────────────────────────────────────────────────────────────────────

/** Declare a local source tree to bundle into the VM rootfs. */
export function localPath(
  path: string,
  opts: { include?: string[]; exclude?: string[] } = {},
): Source {
  return {
    kind: "local_path",
    path,
    include: opts.include ?? ["**"],
    exclude: opts.exclude ?? [],
  };
}

/** Declare a nixpkgs-based image directly. */
export function nix_packages(packages: string[]): Image {
  return { kind: "nix_packages", packages: [...packages] };
}

/** Convenience over `nix_packages` — start with the Python
 *  interpreter at the requested minor version (`python: "3.12"` →
 *  nix attribute `python312`) and add any extra system packages. */
export function python_image(
  opts: { python?: string; packages?: string[] } = {},
): Image {
  const python = opts.python ?? "3.12";
  const pkgs = [`python${python.replace(/\./g, "")}`];
  pkgs.push(...(opts.packages ?? []));
  return nix_packages(pkgs);
}

/** Convenience over `nix_packages` — start with the Node.js
 *  interpreter at the requested major version (`node: "22"` → nix
 *  attribute `nodejs_22`) and add any extra system packages. */
export function node_image(
  opts: { node?: string; packages?: string[] } = {},
): Image {
  const node = opts.node ?? "22";
  const pkgs = [`nodejs_${node}`];
  pkgs.push(...(opts.packages ?? []));
  return nix_packages(pkgs);
}

// ────────────────────────────────────────────────────────────────────
// Resources / network
// ────────────────────────────────────────────────────────────────────

/** Per-VM resource budget. */
export function resources(opts: {
  cpu?: number;
  cpu_cores?: number;
  memory_mb?: number;
  rootfs_size_mb?: number;
}): Resources {
  // Accept either `cpu` (decorator-friendly short name, matches the
  // Python helper) or `cpu_cores` (full IR field name).
  const cpu_cores = opts.cpu_cores ?? opts.cpu ?? 1;
  return {
    cpu_cores,
    memory_mb: opts.memory_mb ?? 256,
    rootfs_size_mb: opts.rootfs_size_mb ?? 512,
  };
}

/** Declare a network policy. v1 surface: mode + ports. Egress, peers,
 *  DNS land alongside the imperative Sandbox surface (Phase 7). */
export function network(opts: {
  mode?: "none" | "bridge" | "host";
  ports?: PortForward[];
}): Network {
  return {
    mode: opts.mode ?? "none",
    ports: opts.ports ?? [],
    peers: [],
  };
}

// ────────────────────────────────────────────────────────────────────
// Env value helpers
// ────────────────────────────────────────────────────────────────────

/** Wrap a string as an explicit literal env value. Equivalent to
 *  passing the string directly in `env: {...}` — the wrapper exists
 *  for parity with `secret()` and for callers who want to be
 *  unambiguous. */
export function literal(value: string): EnvValue {
  return { kind: "literal", value };
}

/** Reference a named secret from the host keystore. `var` is the
 *  env-var name inside the guest; defaults to `name` itself. The
 *  supervisor's KeystoreReleaser resolves the value at admission
 *  time — the SDK only declares the reference. */
export function secret(
  name: string,
  opts: { var?: string } = {},
): EnvValue {
  return {
    kind: "secret_ref",
    ref: {
      name,
      mount: { kind: "env", var: opts.var ?? name },
    },
  };
}

// ────────────────────────────────────────────────────────────────────
// Hook helpers
// ────────────────────────────────────────────────────────────────────

/** Build a lifecycle-hook command.
 *
 *  - `hook("echo hi")` → Shell command.
 *  - `hook(["python", "-m", "migrate"])` → Argv command.
 *
 *  Throws `TypeError` on any other shape. Matches the Python helper
 *  + the host-side parser. */
export function hook(cmd: string | string[]): HookCmd {
  if (typeof cmd === "string") {
    return { kind: "shell", line: cmd };
  }
  if (Array.isArray(cmd) && cmd.every((s) => typeof s === "string")) {
    return { kind: "argv", argv: [...cmd] };
  }
  throw new TypeError(
    `mvm.hook expects a string (shell) or string[] (argv); got ${typeof cmd}`,
  );
}

type HookKwarg = string | string[] | HookCmd | Array<string | string[] | HookCmd>;

function resolveHookKwarg(
  raw: HookKwarg | undefined,
  phase: string,
): HookCmd[] | undefined {
  if (raw === undefined) return undefined;
  if (typeof raw === "string") return [hook(raw)];
  if (Array.isArray(raw)) {
    if (raw.length > 0 && raw.every((x) => typeof x === "string")) {
      // Flat list of strings → one Argv command.
      return [hook(raw as string[])];
    }
    return raw.map((item) => {
      if (typeof item === "string") return hook(item);
      if (Array.isArray(item)) return hook(item);
      if (isHookCmd(item)) return item;
      throw new TypeError(
        `app({${phase}: …}): list elements must be string, string[], or mvm.hook(...)`,
      );
    });
  }
  if (isHookCmd(raw)) return [raw];
  throw new TypeError(
    `app({${phase}: …}): expected string, list, or mvm.hook(...); got ${typeof raw}`,
  );
}

function isHookCmd(v: unknown): v is HookCmd {
  if (typeof v !== "object" || v === null) return false;
  const kind = (v as { kind?: unknown }).kind;
  return kind === "shell" || kind === "argv";
}

// ────────────────────────────────────────────────────────────────────
// Entrypoint helpers
// ────────────────────────────────────────────────────────────────────

/** Command-style entrypoint (legacy / non-function workload shape). */
export function entrypoint(opts: {
  command: string[];
  working_dir?: string;
  env?: Record<string, EnvValue>;
}): Entrypoint {
  if (opts.command.length === 0) {
    throw new Error("entrypoint command must have at least one element");
  }
  return {
    kind: "command",
    command: [...opts.command],
    working_dir: opts.working_dir ?? "/app",
    env: opts.env ?? {},
  };
}

/** Function-call entrypoint (plan 0003 / ADR-0009). */
export function entrypoint_function(opts: {
  module: string;
  function: string;
  language?: string;
  format?: "json" | "msgpack";
  working_dir?: string;
  env?: Record<string, EnvValue>;
  primary?: boolean;
}): Entrypoint {
  return {
    kind: "function",
    language: opts.language ?? "node",
    module: opts.module,
    function: opts.function,
    format: opts.format ?? "json",
    working_dir: opts.working_dir ?? "/app",
    env: opts.env ?? {},
    primary: opts.primary ?? false,
    extra_imports: [],
  };
}

// ────────────────────────────────────────────────────────────────────
// app() decorator (higher-order)
// ────────────────────────────────────────────────────────────────────

export interface AppOptions {
  name?: string;
  source?: Source;
  image: Image;
  entrypoint?: Entrypoint;
  entrypoints?: Entrypoint[];
  resources?: Resources;
  env?: Record<string, EnvValue | string>;
  mounts?: Mount[];
  network?: Network;
  dependencies?: Dependencies;
  addons?: AddonUse[];
  threat_tier?: ThreatTier;
  before_build?: HookKwarg;
  before_start?: HookKwarg;
  after_start?: HookKwarg;
  before_stop?: HookKwarg;
}

/**
 * Register an app on the current workload. Higher-order: returns a
 * function that takes the user's function and returns it unchanged
 * (the SDK only records the declaration).
 *
 *     export const greet = mvm.app({...})((name) => `hello ${name}`);
 */
export function app(opts: AppOptions): <F extends (...args: never[]) => unknown>(fn: F) => F {
  if (opts.entrypoint && opts.entrypoints) {
    throw new Error(
      "mvm.app({...}): pass `entrypoint` (single) OR `entrypoints` (list); not both.",
    );
  }
  const resolvedEntrypoints =
    opts.entrypoints ??
    (opts.entrypoint ? [opts.entrypoint] : undefined);

  const name = opts.name ?? state.workloadId ?? "app";

  const resolvedEnv: Record<string, EnvValue> = {};
  for (const [k, v] of Object.entries(opts.env ?? {})) {
    resolvedEnv[k] = typeof v === "string" ? literal(v) : v;
  }

  const bb = resolveHookKwarg(opts.before_build, "before_build");
  const bs = resolveHookKwarg(opts.before_start, "before_start");
  const af = resolveHookKwarg(opts.after_start, "after_start");
  const bp = resolveHookKwarg(opts.before_stop, "before_stop");
  let hooks: Hooks | undefined;
  if (bb || bs || af || bp) {
    hooks = {
      before_build: bb,
      before_start: bs,
      after_start: af,
      before_stop: bp,
    };
  }

  const record: App = {
    name,
    source: opts.source ?? localPath("."),
    image: opts.image,
    entrypoints:
      resolvedEntrypoints ??
      [entrypoint_function({ module: name, function: name, primary: true })],
    resources:
      opts.resources ??
      resources({ cpu_cores: 1, memory_mb: 256, rootfs_size_mb: 512 }),
    env: resolvedEnv,
    mounts: opts.mounts ?? [],
    network: opts.network,
    dependencies: opts.dependencies,
    addons: opts.addons,
    threat_tier: opts.threat_tier,
    hooks,
  };

  state.apps.push(record);

  return <F extends (...args: never[]) => unknown>(fn: F) => fn;
}

// ────────────────────────────────────────────────────────────────────
// emit
// ────────────────────────────────────────────────────────────────────

/** Emit the canonical-JSON Workload IR for the current state. */
export function emitJson(): string {
  if (state.workloadId === null) {
    throw new Error("mvm.workload(...) must be called before mvm.emitJson()");
  }
  if (state.apps.length === 0) {
    throw new Error("at least one mvm.app(...) call is required before emitJson()");
  }
  const workload: Workload = {
    schema_version: SCHEMA_VERSION,
    id: state.workloadId,
    apps: [...state.apps],
    volumes: [],
    extensions: {},
  };
  // Match `mvm_ir::canonicalize`'s shape: stable-keys JSON. JS
  // `JSON.stringify` preserves object insertion order; our object
  // construction is deterministic, so the output is stable for a
  // given input.
  return canonicalize(workload);
}

function canonicalize(value: unknown): string {
  return JSON.stringify(sortKeysDeep(value));
}

function sortKeysDeep(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortKeysDeep);
  }
  if (value !== null && typeof value === "object") {
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      const v = (value as Record<string, unknown>)[key];
      if (v === undefined) continue;
      sorted[key] = sortKeysDeep(v);
    }
    return sorted;
  }
  return value;
}

export { SCHEMA_VERSION };
