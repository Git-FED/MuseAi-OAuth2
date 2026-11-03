import test from "node:test";
import assert from "node:assert/strict";
import { authorizeApprovalPage } from "../src/oauth/approval-page.js";
import { LOGIN_PAGE_HTML } from "../src/oauth/login-page.js";

const base = { clientName: "FedPromptly", redirectHost: "www.fedpromptly.com", scopes: ["openid", "email"], pendingId: "test-pending-26", basePath: "" };

test("step26: remember=true shows checked box, remember line, and verification confirmation", () => {
  const html = authorizeApprovalPage({ ...base, remember: true });
  assert.match(html, /id="remember-me" type="checkbox" checked/);
  assert.match(html, /Remember me: yes/);
  assert.match(html, /id="muse-verification-confirmation"/);
  assert.match(html, /must verify all of this information back to you/);
  assert.match(html, /No login completes without that confirmation/);
  assert.match(html, /FedPromptly/);
  assert.match(html, /openid/);
});

test("step26: remember omitted shows unchecked box and no remember line (one-time only)", () => {
  const html = authorizeApprovalPage({ ...base });
  assert.match(html, /id="remember-me" type="checkbox">/);
  assert.doesNotMatch(html, /Remember me: yes/);
  assert.match(html, /id="muse-verification-confirmation"/);
});

test("step26: login page has opt-in checkbox and carries remember=true only when checked", () => {
  assert.match(LOGIN_PAGE_HTML, /id="muse-remember" type="checkbox"/);
  assert.match(LOGIN_PAGE_HTML, /q\.set\("remember", "true"\)/);
  assert.match(LOGIN_PAGE_HTML, /rememberBox\.checked/);
});
