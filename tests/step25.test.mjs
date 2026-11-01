import test from "node:test";
import assert from "node:assert/strict";
import { authorizeApprovalPage } from "../src/oauth/approval-page.js";
test("step25: approval page FAQ covers browser-not-app and expiry", () => {
  const html = authorizeApprovalPage({ clientName: "FedPromptly", redirectHost: "www.fedpromptly.com", scopes: ["openid"], pendingId: "test-pending-123", basePath: "" });
  assert.match(html, /web browser, not the Muse app/);
  assert.match(html, /logged into the phone app does not mean/);
  assert.match(html, /10 minutes/);
});
