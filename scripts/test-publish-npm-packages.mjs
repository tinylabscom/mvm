import assert from "node:assert/strict";
import { test } from "node:test";
import { isPublished, publicationOrder, publishPackages } from "./publish-npm-packages.mjs";

const platform = { name: "@runmvm/mvm-linux-x64-gnu", version: "1.2.3" };
const main = {
  name: "@runmvm/mvm", version: "1.2.3",
  optionalDependencies: { [platform.name]: platform.version },
};

test("the complete version-matched platform set precedes the main package", () => {
  assert.deepEqual(publicationOrder([main, platform]), [platform, main]);
  for (const packages of [[main], [main, platform, platform], [platform],
    [{ ...main, optionalDependencies: {} }],
    [main, { ...platform, version: "9.9.9" }]]) {
    assert.throws(() => publicationOrder(packages));
  }
});

test("only an explicit 404 permits publication", async () => {
  assert.equal(await isPublished(platform, async () => ({ status: 404 })), false);
  for (const status of [301, 401, 403, 429, 500, 503]) {
    await assert.rejects(isPublished(platform, async () => ({ status })), /HTTP/);
  }
  await assert.rejects(isPublished(platform, async () => { throw new Error("offline"); }), /offline/);
});

test("existing versions must have coherent registry metadata", async () => {
  const request = (value) => async () => ({ status: 200, json: async () => value });
  assert.equal(await isPublished(platform, request({ ...platform, dist: { integrity: "sha512-test" } })), true);
  for (const value of [{}, { ...platform, dist: {} },
    { ...platform, dist: { integrity: {} } },
    { ...platform, version: "9.9.9", dist: { integrity: "sha512-test" } }]) {
    await assert.rejects(isPublished(platform, request(value)), /malformed/);
  }
  await assert.rejects(isPublished(main, request({
    ...main, optionalDependencies: {}, dist: { integrity: "sha512-test" },
  })), /new SDK version/);
});

test("a partial publication resumes without republishing or reordering", async () => {
  const uploaded = [];
  await publishPackages([main, platform], async (entry) => entry === platform,
    async (entry) => uploaded.push(entry.name));
  assert.deepEqual(uploaded, [main.name]);
});

test("registry uncertainty prevents every upload", async () => {
  const uploaded = [];
  await assert.rejects(publishPackages([main, platform], async (entry) => {
    if (entry === main) throw new Error("registry unavailable");
    return false;
  }, async (entry) => uploaded.push(entry.name)), /registry unavailable/);
  assert.deepEqual(uploaded, []);
});

test("a failed platform upload prevents main publication", async () => {
  const uploaded = [];
  await assert.rejects(publishPackages([main, platform], async () => false, async (entry) => {
    uploaded.push(entry.name);
    throw new Error("upload failed");
  }), /upload failed/);
  assert.deepEqual(uploaded, [platform.name]);
});
