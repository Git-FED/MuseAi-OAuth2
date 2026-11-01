import test from "node:test";
import assert from "node:assert/strict";
import { authorizeApprovalPage, deviceDetailPage } from "../src/oauth/approval-page.js";

// Step 17's standalone Copy ID button was removed in step 19 as a
// duplicate of step 18's combined button. These tests now lock in
// that removal: three buttons total, no standalone copy-id-btn.
test("step17 (superseded by step19): authorize page has no standalone Copy ID", () => {
  const page = authorizeApprovalPage({ clientName: "Hub", redirectHost: "hub.fedos.workers.dev", scopes: ["openid"], pendingId: "pend-123", basePath: "/login" });
  assert.match(page, /id="open-muse-btn"/);
  assert.match(page, /Open Muse AI to approve/);
  assert.match(page, /id="copy-btn"/);
  assert.match(page, /Copy approval message/);
  assert.match(page, /id="copy-id-open-btn"/);
  assert.doesNotMatch(page, /id="copy-id-btn"/);
  assert.match(page, /pend-123/);
});

test("step17 (superseded by step19): device page has no standalone Copy ID", () => {
  const page = deviceDetailPage({ clientName: "Hub", scopes: ["openid"], deviceCode: "dev-456", userCode: "ABCD-1234", basePath: "/login" });
  assert.match(page, /id="open-muse-btn"/);
  assert.match(page, /id="copy-btn"/);
  assert.match(page, /id="copy-id-open-btn"/);
  assert.doesNotMatch(page, /id="copy-id-btn"/);
  assert.match(page, /dev-456/);
});
