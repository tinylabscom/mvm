/**
 * Tests for the SDK-port Phase 6 TypeScript SDK. Mirrors
 * sdks/python/tests/test_hooks_and_helpers.py so a single user-side
 * decoration site validates identically through both the Python and
 * TypeScript SDKs.
 */

import { afterEach, describe, expect, it } from "vitest";
import * as mvm from "../src/index.js";

afterEach(() => mvm.reset());

describe("image helpers", () => {
  it("python_image with default python 3.12", () => {
    const img = mvm.python_image();
    expect(img).toEqual({ kind: "nix_packages", packages: ["python312"] });
  });

  it("python_image strips the dot and appends packages", () => {
    const img = mvm.python_image({ python: "3.13", packages: ["curl"] });
    expect(img).toEqual({
      kind: "nix_packages",
      packages: ["python313", "curl"],
    });
  });

  it("node_image default node 22", () => {
    expect(mvm.node_image()).toEqual({
      kind: "nix_packages",
      packages: ["nodejs_22"],
    });
  });

  it("node_image with packages", () => {
    expect(mvm.node_image({ node: "20", packages: ["jq"] })).toEqual({
      kind: "nix_packages",
      packages: ["nodejs_20", "jq"],
    });
  });

  it("nix_packages copies the input array", () => {
    const input = ["a", "b"];
    const img = mvm.nix_packages(input);
    input.push("c");
    expect(img).toEqual({ kind: "nix_packages", packages: ["a", "b"] });
  });
});

describe("hook()", () => {
  it("string becomes shell", () => {
    expect(mvm.hook("echo hi")).toEqual({ kind: "shell", line: "echo hi" });
  });

  it("string[] becomes argv", () => {
    expect(mvm.hook(["python", "-m", "migrate"])).toEqual({
      kind: "argv",
      argv: ["python", "-m", "migrate"],
    });
  });

  it("rejects non-string/non-array input", () => {
    // @ts-expect-error - intentional misuse
    expect(() => mvm.hook(42)).toThrow(TypeError);
  });
});

describe("literal() / secret()", () => {
  it("literal wraps a string", () => {
    expect(mvm.literal("hi")).toEqual({ kind: "literal", value: "hi" });
  });

  it("secret with default var matches name", () => {
    expect(mvm.secret("api-key")).toEqual({
      kind: "secret_ref",
      ref: {
        name: "api-key",
        mount: { kind: "env", var: "api-key" },
      },
    });
  });

  it("secret with explicit var", () => {
    expect(mvm.secret("api-key", { var: "API_KEY" })).toEqual({
      kind: "secret_ref",
      ref: {
        name: "api-key",
        mount: { kind: "env", var: "API_KEY" },
      },
    });
  });
});

describe("app() with all four hook phases", () => {
  it("emits merged hooks across phases", () => {
    mvm.workload({ id: "hello-hooks" });
    const greet = mvm.app({
      name: "hello-hooks",
      image: mvm.python_image(),
      resources: mvm.resources({ cpu: 1, memory_mb: 256 }),
      entrypoint: mvm.entrypoint({ command: ["python", "-m", "hello"] }),
      before_build: "python -m migrate",
      before_start: ["export", "MODEL=/m"],
      after_start: mvm.hook(["curl", "-fsS", "/h"]),
      before_stop: "pkill app",
    })(() => "hello");

    expect(typeof greet).toBe("function");

    const payload = JSON.parse(mvm.emitJson());
    const hooks = payload.apps[0].hooks;
    expect(hooks.before_build).toEqual([
      { kind: "shell", line: "python -m migrate" },
    ]);
    expect(hooks.before_start).toEqual([
      { argv: ["export", "MODEL=/m"], kind: "argv" },
    ]);
    expect(hooks.after_start).toEqual([
      { argv: ["curl", "-fsS", "/h"], kind: "argv" },
    ]);
    expect(hooks.before_stop).toEqual([
      { kind: "shell", line: "pkill app" },
    ]);
  });

  it("without hook kwargs, hooks is absent from the emitted app", () => {
    mvm.workload({ id: "hello" });
    mvm.app({
      name: "hello",
      image: mvm.python_image(),
      resources: mvm.resources({ cpu: 1 }),
      entrypoint: mvm.entrypoint({ command: ["python"] }),
    })(() => "x");

    const payload = JSON.parse(mvm.emitJson());
    expect(payload.apps[0].hooks).toBeUndefined();
  });

  it("list of mvm.hook(...) passes through", () => {
    mvm.workload({ id: "multi" });
    mvm.app({
      name: "multi",
      image: mvm.python_image(),
      resources: mvm.resources({ cpu: 1 }),
      entrypoint: mvm.entrypoint({ command: ["python"] }),
      before_start: [mvm.hook("setup-1"), mvm.hook(["setup-2", "--flag"])],
    })(() => "x");

    const payload = JSON.parse(mvm.emitJson());
    expect(payload.apps[0].hooks.before_start).toEqual([
      { kind: "shell", line: "setup-1" },
      { argv: ["setup-2", "--flag"], kind: "argv" },
    ]);
  });
});

describe("env helpers", () => {
  it("env accepts bare strings and wraps as literal", () => {
    mvm.workload({ id: "env-app" });
    mvm.app({
      name: "env-app",
      image: mvm.python_image(),
      resources: mvm.resources({ cpu: 1 }),
      entrypoint: mvm.entrypoint({ command: ["python"] }),
      env: {
        MODEL_PATH: "/data/model.pt",
        API_KEY: mvm.secret("api-key"),
      },
    })(() => "x");

    const payload = JSON.parse(mvm.emitJson());
    expect(payload.apps[0].env.MODEL_PATH).toEqual({
      kind: "literal",
      value: "/data/model.pt",
    });
    expect(payload.apps[0].env.API_KEY.kind).toBe("secret_ref");
    expect(payload.apps[0].env.API_KEY.ref.name).toBe("api-key");
  });
});

describe("network()", () => {
  it("bridge mode with ports", () => {
    const n = mvm.network({
      mode: "bridge",
      ports: [{ guest: 8080, host: 0, proto: "tcp" }],
    });
    expect(n.mode).toBe("bridge");
    expect(n.ports).toHaveLength(1);
    expect(n.ports?.[0]?.guest).toBe(8080);
  });
});

describe("workload() guards", () => {
  it("rejects double calls", () => {
    mvm.workload({ id: "first" });
    expect(() => mvm.workload({ id: "second" })).toThrow();
  });

  it("rejects empty id", () => {
    expect(() => mvm.workload({ id: "" })).toThrow();
  });
});

describe("emitJson() canonicalization", () => {
  it("sorts object keys deterministically", () => {
    mvm.workload({ id: "canon" });
    mvm.app({
      name: "canon",
      image: mvm.python_image(),
      resources: mvm.resources({ cpu: 1 }),
      entrypoint: mvm.entrypoint({ command: ["python"] }),
    })(() => "x");
    const json = mvm.emitJson();
    const parsed = JSON.parse(json);
    // schema_version and id appear in the same canonical order each run.
    expect(json.indexOf("\"apps\"")).toBeLessThan(json.indexOf("\"id\""));
    expect(parsed.id).toBe("canon");
  });

  it("two emits of the same state produce identical JSON", () => {
    mvm.workload({ id: "stable" });
    mvm.app({
      name: "stable",
      image: mvm.python_image(),
      resources: mvm.resources({ cpu: 1 }),
      entrypoint: mvm.entrypoint({ command: ["python"] }),
    })(() => "x");
    const a = mvm.emitJson();
    const b = mvm.emitJson();
    expect(a).toBe(b);
  });
});
