import { afterEach, expect, it } from "vitest";
import { attestation } from "../src/index.js";
import { setInvokeForTesting } from "../src/_hostlib.js";

afterEach(() => setInvokeForTesting(null));

it("sends literal empty objects and explicit trust through the actual transport", () => {
  const cases = [
    { method: "attestation.export", request: {}, run: () => attestation.exportReport() },
    { method: "attestation.status", request: {}, run: () => attestation.status() },
    { method: "attestation.verify", request: { report_path: "/report", trust: { kind: "self_identity" } },
      run: () => attestation.verify("/report", { kind: "self_identity" }) },
    { method: "attestation.verify",
      request: { report_path: "/report", trust: { kind: "public_key_file", path: "/key" } },
      run: () => attestation.verify("/report", { kind: "public_key_file", path: "/key" }) },
  ];
  for (const entry of cases) {
    const reply = { payload: [0, 255], signature: [1], signer_id: "host" };
    setInvokeForTesting((method, request) => {
      expect(method).toBe(entry.method);
      expect(JSON.parse(request.toString())).toEqual(entry.request);
      expect(request.length).toBeGreaterThan(0);
      return [0, Buffer.from(JSON.stringify(reply))];
    });
    expect(entry.run()).toEqual(reply);
  }
});
