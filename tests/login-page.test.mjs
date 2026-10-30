// Step 10 tests: worker-hosted Sign in with Muse page at the mount root.
import test from "node:test";
import assert from "node:assert/strict";
import worker from "../worker.js";

function env(basePath) {
  return {
    BASE_PATH: basePath,
    OAUTH_KV: { put: async () => {}, get: async () => null, delete: async () => {} },
    OAUTH_STORE: {},
    RATE_LIMIT: {},
    ISSUER: "https://www.fedpromptly.com/login",
    ADMIN_TOKEN: "test-admin-token",
  };
}

async function get(envObj, url) {
  const res = await worker.fetch(new Request(url), envObj);
  return { status: res.status, text: await res.text(), headers: res.headers };
}

test("mount root serves the login page (no trailing slash)", async () => {
  const r = await get(env("/login"), "https://www.fedpromptly.com/login");
  assert.equal(r.status, 200);
  assert.match(r.headers.get("content-type"), /text\/html/);
  assert.ok(r.text.includes('id="muse-login-btn"'));
  assert.ok(r.text.includes("Sign in with Muse"));
  assert.equal(r.headers.get("x-frame-options"), null);
});

test("mount root serves the login page (trailing slash)", async () => {
  const r = await get(env("/login"), "https://www.fedpromptly.com/login/");
  assert.equal(r.status, 200);
  assert.ok(r.text.includes('id="muse-login-btn"'));
});

test("page script uses its own URL for authorize, token, userinfo", async () => {
  const r = await get(env("/login"), "https://www.fedpromptly.com/login");
  assert.ok(r.text.includes("/oauth/authorize"));
  assert.ok(r.text.includes("/oauth/token"));
  assert.ok(r.text.includes("/oauth/userinfo"));
  assert.ok(r.text.includes("location.pathname"));
  // No frame-busting: the page must stay usable inside an embed.
  assert.ok(!/top\.location|parent\.location/.test(r.text));
});

test("page script survives serving with its regexes intact (click bug regression)", async () => {
  const r = await get(env("/login"), "https://www.fedpromptly.com/login");
  const script = r.text.match(/<script>([\s\S]*)<\/script>/)[1];
  const bs = String.fromCharCode(92);
  assert.ok(r.text.includes("replace(/" + bs + "/$/"), "BASE regex backslash lost");
  assert.ok(r.text.includes("replace(/" + bs + "+/g"), "b64url plus regex backslash lost");
  assert.ok(r.text.includes("replace(/" + bs + "//g"), "b64url slash regex backslash lost");
  assert.doesNotThrow(() => new Function(script), "served page script must parse so the button works");
});

test("page route does not swallow subpaths", async () => {
  const r = await get(env("/login"), "https://www.fedpromptly.com/login/oauth/authorize");
  assert.ok(!r.text.includes('id="muse-login-btn"'));
});

test("root mount serves the page at /", async () => {
  const r = await get(env(""), "https://fedpromptly.com/");
  assert.equal(r.status, 200);
  assert.ok(r.text.includes('id="muse-login-btn"'));
});
