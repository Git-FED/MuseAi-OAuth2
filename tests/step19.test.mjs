import test from "node:test";
import assert from "node:assert/strict";
import { authorizeApprovalPage, deviceDetailPage } from "../src/oauth/approval-page.js";
import { LOGIN_PAGE_HTML } from "../src/oauth/login-page.js";

const base = { clientName: "Test", redirectHost: "example.com", scopes: ["openid"], pendingId: "pend123", basePath: "" };

test("step19: standalone Copy ID button is gone, combined button remains", () => {
  const page = authorizeApprovalPage(base);
  assert.doesNotMatch(page, /id="copy-id-btn"/);
  assert.match(page, /id="copy-id-open-btn"/);
  assert.match(page, /Approve with Muse AI/);
  const device = deviceDetailPage({ clientName: "Test", scopes: ["openid"], deviceCode: "dev123", userCode: "ABCD-1234", basePath: "" });
  assert.doesNotMatch(device, /id="copy-id-btn"/);
  assert.match(device, /id="copy-id-open-btn"/);
});

test("step19: login and approval pages share the non-white card look", () => {
  assert.match(LOGIN_PAGE_HTML, /background: #8fd8b8/);
  assert.match(LOGIN_PAGE_HTML, /border-top: 4px solid #7c5cf0/);
  const page = authorizeApprovalPage(base);
  assert.match(page, /background:#8fd8b8/);
  assert.match(page, /border-top:4px solid #7c5cf0/);
});
