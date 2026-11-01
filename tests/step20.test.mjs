import test from "node:test";
import assert from "node:assert/strict";
import { authorizeApprovalPage } from "../src/oauth/approval-page.js";
import { LOGIN_PAGE_HTML } from "../src/oauth/login-page.js";

test("step20: background is mint, not white, on both pages", () => {
  const page = authorizeApprovalPage({ clientName: "Test", redirectHost: "example.com", scopes: ["openid"], pendingId: "pend123", basePath: "" });
  assert.match(page, /background:#8fd8b8/);
  assert.match(page, /background:#f7f3ea/);
  assert.match(LOGIN_PAGE_HTML, /background: #8fd8b8/);
  assert.match(LOGIN_PAGE_HTML, /background: #f7f3ea/);
});

test("step20: every button is a different color, none black/white", () => {
  const page = authorizeApprovalPage({ clientName: "Test", redirectHost: "example.com", scopes: ["openid"], pendingId: "pend123", basePath: "" });
  assert.match(page, /#copy-id-open-btn\{background:#7c5cf0/);
  assert.match(page, /#open-muse-btn\{background:#22c55e/);
  assert.match(page, /#copy-btn\{background:#2563eb/);
  assert.doesNotMatch(page, /id="copy-id-btn"/);
  assert.match(LOGIN_PAGE_HTML, /background: #7c5cf0/);
});
