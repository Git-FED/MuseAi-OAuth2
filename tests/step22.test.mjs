import test from "node:test";
import assert from "node:assert/strict";
import { authorizeApprovalPage, deviceDetailPage } from "../src/oauth/approval-page.js";

test("step22: copied message has introduction, instructions, and wait time", () => {
  const page = authorizeApprovalPage({ clientName: "Test", redirectHost: "example.com", scopes: ["openid"], pendingId: "pendXYZ", basePath: "" });
  assert.match(page, /Hi Muse, I'm signing in to FedPromptly/);
  assert.match(page, /Please approve my Muse sign-in\. Pending request: pendXYZ/);
  assert.match(page, /finishes itself in a few seconds/);
  assert.match(page, /checks every 2 seconds/);
  assert.match(page, /expires in 10 minutes/);
});

test("step22: page itself states the wait and expiry, device copy matches", () => {
  const page = authorizeApprovalPage({ clientName: "Test", redirectHost: "example.com", scopes: ["openid"], pendingId: "pendXYZ", basePath: "" });
  assert.match(page, /this page checks every 2 seconds/);
  assert.match(page, /expires in 10 minutes/);
  const dev = deviceDetailPage({ clientName: "Test", scopes: ["openid"], deviceCode: "dev123", userCode: "ABCD-1234", basePath: "" });
  assert.match(dev, /Hi Muse, I'm signing in to FedPromptly from a device/);
  assert.match(dev, /Device code: dev123/);
  assert.match(dev, /expires in 30 minutes/);
});
