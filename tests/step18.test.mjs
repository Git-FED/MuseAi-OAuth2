import test from "node:test";
import assert from "node:assert/strict";
import { authorizeApprovalPage, deviceDetailPage } from "../src/oauth/approval-page.js";

test("step18 (superseded by step21): one button copies then opens Muse AI, in order", () => {
  const page = authorizeApprovalPage({ clientName: "Hub", redirectHost: "hub.fedos.workers.dev", scopes: ["openid"], pendingId: "pend-123", basePath: "/login" });
  assert.match(page, /id="copy-id-open-btn"/);
  assert.match(page, /Approve with Muse AI/);
  const handler = page.indexOf("copy-id-open-btn");
  const copyAt = page.indexOf("navigator.clipboard.writeText(msg)", handler);
  const openAt = page.indexOf('window.open("https://muse.ai"', handler);
  assert.ok(copyAt > 0 && openAt > copyAt, "copy must come before open in the combined handler");
});

test("step18: device page has the same combined button", () => {
  const page = deviceDetailPage({ clientName: "Hub", scopes: ["openid"], deviceCode: "dev-456", userCode: "ABCD-1234", basePath: "/login" });
  assert.match(page, /id="copy-id-open-btn"/);
});
