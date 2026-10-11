import { afterEach, expect, it } from "vitest";
import { maintenance } from "../src/index.js";
import { setInvokeForTesting } from "../src/_hostlib.js";

afterEach(() => setInvokeForTesting(null));

it.each([false, true])("forwards explicit repair intent %s", (apply) => {
  const report = { live: [], errors: ["could not repair"] };
  setInvokeForTesting((method, bytes) => {
    expect(method).toBe("maintenance.reconcile");
    expect(JSON.parse(bytes.toString("utf8"))).toEqual({ apply });
    return [0, Buffer.from(JSON.stringify(report))];
  });
  expect(maintenance.reconcile({ apply })).toEqual(report);
});

it("defaults to preview", () => {
  setInvokeForTesting((method, bytes) => {
    expect(method).toBe("maintenance.reconcile");
    expect(JSON.parse(bytes.toString("utf8"))).toEqual({ apply: false });
    return [0, Buffer.from('{"errors":[]}')];
  });
  expect(maintenance.reconcile()).toEqual({ errors: [] });
});
