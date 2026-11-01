import test from "node:test";
import assert from "node:assert/strict";
import { authorizeApprovalPage, deviceDetailPage } from "../src/oauth/approval-page.js";

test("step21: primary button copies the full approval message, not just the id", () => {
  const page = authorizeApprovalPage({ clientName: "Test", redirectHost: "example.com", scopes: ["openid"], pendingId: "pendXYZ", basePath: "" });
  assert.match(page, /Approve with Muse AI/);
  assert.match(page, /navigator\.clipboard\.writeText\(msg\)/);
  assert.match(page, /Please approve my Muse sign-in\. Pending request: pendXYZ/);
  assert.doesNotMatch(page, /Copy ID &amp; Open Muse AI/);
});

test("step21: clipboard failure shows the full message in a selectable box", () => {
  const page = deviceDetailPage({ clientName: "Test", scopes: ["openid"], deviceCode: "dev123", userCode: "ABCD-1234", basePath: "" });
  assert.match(page, /id="approval-fallback"/);
  assert.match(page, /Please approve my Muse device sign-in\. Device code: dev123/);
  assert.match(page, /window\.open\("https:\/\/muse\.ai"/);
});
