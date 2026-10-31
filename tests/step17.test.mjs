import test from "node:test";
import assert from "node:assert/strict";
import { authorizeApprovalPage, deviceDetailPage } from "../src/oauth/approval-page.js";

test("step17: authorize page has Open Muse, Copy approval message, and Copy ID", () => {
  const page = authorizeApprovalPage({ clientName: "Hub", redirectHost: "hub.fedos.workers.dev", scopes: ["openid"], pendingId: "pend-123", basePath: "/login" });
  assert.match(page, /id="open-muse-btn"/);
  assert.match(page, /Open Muse AI to approve/);
  assert.match(page, /id="copy-btn"/);
  assert.match(page, /Copy approval message/);
  assert.match(page, /id="copy-id-btn"/);
  assert.match(page, /Copy ID/);
  assert.match(page, /pend-123/);
});

test("step17: device page has the same three buttons", () => {
  const page = deviceDetailPage({ clientName: "Hub", scopes: ["openid"], deviceCode: "dev-456", userCode: "ABCD-1234", basePath: "/login" });
  assert.match(page, /id="open-muse-btn"/);
  assert.match(page, /id="copy-btn"/);
  assert.match(page, /id="copy-id-btn"/);
  assert.match(page, /dev-456/);
});
