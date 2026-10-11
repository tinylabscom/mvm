import { afterEach, expect, it } from "vitest";
import { bundle, manifest, storage } from "../src/index.js";
import { setInvokeForTesting } from "../src/_hostlib.js";
import { MachineBackendError } from "../src/_errors/types.js";

afterEach(() => setInvokeForTesting(null));

const posture = {
  profile: "dev" as const, allow_egress: true, allow_volumes: true, allow_unauthenticated: true,
};
const cases = [
  { operation: () => manifest.remove(), method: "manifest.remove",
    request: { path: null, force: false, manifest_file: false } },
  { operation: () => manifest.remove("mvm.toml", { force: true, manifestFile: true }),
    method: "manifest.remove", request: { path: "mvm.toml", force: true, manifest_file: true } },
  { operation: () => manifest.prune(), method: "manifest.prune",
    request: { orphans: false, dry_run: true } },
  { operation: () => manifest.prune({ orphans: true, dryRun: false }), method: "manifest.prune",
    request: { orphans: true, dry_run: false } },
  { operation: () => manifest.exportOci("template", "image.tar.gz"), method: "manifest.export_oci",
    request: { template: "template", out: "image.tar.gz" } },
  { operation: () => storage.info(), method: "storage.info", request: { mock: false } },
  { operation: () => storage.info({ mock: true }), method: "storage.info", request: { mock: true } },
  { operation: () => storage.gc(), method: "storage.gc",
    request: { apply: false, mock: false, keep_prefix: [] } },
  { operation: () => storage.gc({ apply: true, mock: true, keepPrefix: ["live-"] }),
    method: "storage.gc", request: { apply: true, mock: true, keep_prefix: ["live-"] } },
  { operation: () => bundle.export("template", "out.mvmpkg"), method: "bundle.export",
    request: { template: "template", out: "out.mvmpkg", label: null, cmdline: null, posture: null } },
  { operation: () => bundle.export("template", "out.mvmpkg", { label: "label", cmdline: "cmdline", posture }),
    method: "bundle.export",
    request: { template: "template", out: "out.mvmpkg", label: "label", cmdline: "cmdline", posture } },
];

it.each(cases)("marshals $method and preserves reports", ({ operation, method, request }) => {
  const report = { path: "out", removed: [], future: { nested: [null, true, 42] } };
  const calls: unknown[] = [];
  setInvokeForTesting((name, body) => {
    calls.push({ method: name, request: JSON.parse(body.toString("utf8")) });
    return [0, Buffer.from(JSON.stringify(report))];
  });
  expect(operation()).toEqual(report);
  expect(calls).toEqual([{ method, request }]);
});

it.each(cases)("preserves $method errors", ({ operation }) => {
  setInvokeForTesting(() => [1, Buffer.from(JSON.stringify({
    code: "BACKEND_ERROR", message: "outer operation: inner cause", retryable: false,
  }))]);
  expect(operation).toThrow(MachineBackendError);
  expect(operation).toThrow("outer operation: inner cause");
});

it("preserves unknown posture fields for client validation", () => {
  const supplied = { ...posture, unexpected: true };
  setInvokeForTesting((_name, body) => {
    expect(JSON.parse(body.toString("utf8")).posture).toEqual(supplied);
    return [1, Buffer.from(JSON.stringify({
      code: "BACKEND_ERROR", message: "unknown field", retryable: false,
    }))];
  });
  expect(() => bundle.export("template", "out", { posture: supplied })).toThrow(MachineBackendError);
});
