import { afterEach, expect, it } from "vitest";
import { artifact, audit, posture, volumes, workspaces } from "../src/index.js";
import { setInvokeForTesting } from "../src/_hostlib.js";
import { MachineBackendError } from "../src/_errors/types.js";

afterEach(() => setInvokeForTesting(null));
const workspace = { vm: "worker", volume: null, exclude: [], protected_paths: [] };
const cases = [
  { operation: () => artifact.inspect("abc"), method: "artifact.inspect", request: { id: "abc" } },
  { operation: () => artifact.validate("abc"), method: "artifact.validate", request: { id: "abc" } },
  { operation: () => artifact.configureFirecracker("abc"), method: "artifact.configure_firecracker", request: { id: "abc" } },
  { operation: () => volumes.list(), method: "volume.list", request: {} },
  { operation: () => volumes.inspect("data"), method: "volume.inspect", request: { name: "data" } },
  { operation: () => volumes.create("data", 16), method: "volume.create", request: { name: "data", capacity_mib: 16, root: null } },
  { operation: () => volumes.unlock("data"), method: "volume.unlock", request: { name: "data" } },
  { operation: () => volumes.lock("data"), method: "volume.lock", request: { name: "data" } },
  { operation: () => volumes.mount("worker", "data", "/data"), method: "volume.mount",
    request: { vm: "worker", volume: "data", guest_path: "/data", host: null, access: "read-only" } },
  { operation: () => volumes.mount("worker", "data", "/data", { host: "/source", access: "read-write" }), method: "volume.mount",
    request: { vm: "worker", volume: "data", guest_path: "/data", host: "/source", access: "read-write" } },
  { operation: () => volumes.detach("worker", "/data"), method: "volume.detach", request: { vm: "worker", guest_path: "/data" } },
  { operation: () => volumes.attachments("worker"), method: "volume.attachments", request: { vm: "worker" } },
  { operation: () => volumes.snapshot("data", "before"), method: "volume.snapshot", request: { name: "data", snapshot: "before" } },
  { operation: () => volumes.restore("data", "before"), method: "volume.restore", request: { name: "data", snapshot: "before" } },
  { operation: () => workspaces.review("worker"), method: "workspace.review", request: workspace },
  { operation: () => workspaces.apply("worker", "digest"), method: "workspace.apply",
    request: { workspace, expected_fingerprint: "digest", approved: false } },
  { operation: () => workspaces.apply("worker", "digest", { approved: true }), method: "workspace.apply",
    request: { workspace, expected_fingerprint: "digest", approved: true } },
  { operation: () => workspaces.undo("worker"), method: "workspace.undo", request: { workspace, approved: false } },
  { operation: () => workspaces.redo("worker", { approved: true }), method: "workspace.redo", request: { workspace, approved: true } },
  { operation: () => audit.sessions.list(), method: "audit.sessions.list", request: { tenant: "local", range: { since: null, until: null } } },
  { operation: () => audit.sessions.show("abcdef01"), method: "audit.sessions.show",
    request: { tenant: "local", selector: "abcdef01", filter: { kind: null, range: { since: null, until: null } } } },
  { operation: () => audit.sessions.verify("abcdef01"), method: "audit.sessions.verify", request: { tenant: "local", selector: "abcdef01" } },
  { operation: () => posture.inspect(), method: "posture.inspect", request: {} },
];

it.each(cases)("marshals $method and preserves recovery reports", ({ operation, method, request }) => {
  const report = { recoveries: [{ kind: "interrupted", apply_id: "old" }], review: { status: "ready", fingerprint: "digest" } };
  setInvokeForTesting((name, body) => {
    expect(name).toBe(method);
    expect(JSON.parse(body.toString("utf8"))).toEqual(request);
    return [0, Buffer.from(JSON.stringify(report))];
  });
  expect(operation()).toEqual(report);
});

it.each(cases)("preserves $method cause chains", ({ operation }) => {
  setInvokeForTesting(() => [3, Buffer.from(JSON.stringify({
    code: "BACKEND_ERROR", message: "outer operation: inner cause", retryable: false,
  }))]);
  expect(operation).toThrow(MachineBackendError);
  expect(operation).toThrow("outer operation: inner cause");
});

it("adds protections without replacing the guest audit surface", () => {
  expect(typeof audit.emit).toBe("function");
  setInvokeForTesting((_name, body) => {
    expect(JSON.parse(body.toString("utf8")).protected_paths).toEqual(["private/**"]);
    return [0, Buffer.from('{"review":{"status":"refused"}}')];
  });
  workspaces.review("worker", { protectedPaths: ["private/**"] });
});
