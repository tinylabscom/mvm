import { afterEach, expect, it } from "vitest";
import { imageRevocations } from "../src/index.js";
import { setInvokeForTesting } from "../src/_hostlib.js";

afterEach(() => setInvokeForTesting(null));

it("delegates only the canonical file inputs and a literal empty status object", () => {
  const cases = [
    { method: "image_revocations.status", request: {}, run: () => imageRevocations.status() },
    { method: "image_revocations.update",
      request: { document_path: "/document", bundle_path: "/bundle" },
      run: () => imageRevocations.update("/document", "/bundle") },
  ];
  for (const entry of cases) {
    const reply = { publication: 1, issued_at: "2026-01-01T00:00:00Z", sha256: "00" };
    setInvokeForTesting((method, request) => {
      expect(method).toBe(entry.method);
      expect(JSON.parse(request.toString())).toEqual(entry.request);
      return [0, Buffer.from(JSON.stringify(reply))];
    });
    expect(entry.run()).toEqual(reply);
  }
});
