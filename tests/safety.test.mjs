import test from "node:test";
import assert from "node:assert/strict";
import worker from "../worker.js";

test("scaffold worker fails closed and never serves OAuth", async () => {
  const response = await worker.fetch(new Request("https://example.invalid/oauth/token"), {});
  assert.equal(response.status, 503);
  assert.match(await response.text(), /not implemented/i);
});
