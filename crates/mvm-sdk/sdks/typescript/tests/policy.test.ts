import { expect, test } from "vitest";

import * as mvm from "../src/index.js";

test("the public typed policy profile carries composition and rules", () => {
  const profile: mvm.policy.ProfileFile = {
    extends: ["base"],
    groups: { include: ["required"] },
    when: [{ os: "linux", overrides: { network: { deny: ["blocked.test"] } } }],
  };
  expect(profile.groups?.include).toEqual(["required"]);
  expect(profile.when?.[0].overrides?.network?.deny).toEqual(["blocked.test"]);
});
