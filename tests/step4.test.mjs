// Step 4 tests: approval-page polish, device user-code entry page,
// deny flows, deploy-prep-adjacent behavior (verification URI).
// Fake env doubles mirror tests/step3.test.mjs.
import test from "node:test";
import assert from "node:assert/strict";
import worker from "../worker.js";
import { OAuthRecord } from "../src/store/oauth-record.js";
import { RateLimitBucket } from "../src/store/rate-limit.js";
import { recordStub } from "../src/store/oauth-record.js";
import { pkceChallenge } from "../src/lib/crypto.js";

function fakeStorage() {
  const m = new Map();
  return {
    async get(k) { return m.get(k) ?? null; },
    async put(k, v) { m.set(k, v); },
    async delete(k) { m.delete(k); },
    async setAlarm() {},
  };
}

function fakeNamespace(Class) {
  const instances = new Map();
  return {
    idFromName: (k) => k,
    get: (id) => {
      if (!instances.has(id)) instances.set(id, new Class({ storage: fakeStorage() }));
      return instances.get(id);
    },
  };
}

function fakeKV() {
  const m = new Map();
  return {
    async get(k) { return m.get(k) ?? null; },
    async put(k, v) { m.set(k, typeof v === "string" ? v : JSON.stringify(v)); },
    async delete(k) { m.delete(k); },
    async list(prefix) {
      return [...m.keys()].filter((k) => k.startsWith(prefix));
    },
  };
}

async function makeEnv() {
  const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const signing = await crypto.subtle.exportKey("jwk", kp.privateKey);
  const pub = await crypto.subtle.exportKey("jwk", kp.publicKey);
  const env = {
    OAUTH_STORE: fakeNamespace(OAuthRecord),
    OAUTH_KV: fakeKV(),
    RATE_LIMIT: fakeNamespace(RateLimitBucket),
    ISSUER: "https://login.example.com",
    SIGNING_KEY_JWK: JSON.stringify(signing),
    SIGNING_PUBLIC_JWK: JSON.stringify(pub),
    ADMIN_TOKEN: "test-admin-token",
  };
  await env.OAUTH_KV.put("client:fedpromptly", JSON.stringify({
    client_id: "fedpromptly",
    name: "FedPromptly",
    redirect_uris: ["https://www.fedpromptly.com/callback"],
  }));
  return env;
}

async function registerMuse(env, museId = "muse-test") {
  const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const pub = await crypto.subtle.exportKey("jwk", kp.publicKey);
  await env.OAUTH_KV.put(`muse_key:${museId}`, JSON.stringify({ muse_id: museId, public_key_jwk: pub }));
  return kp.privateKey;
}

function toBase64Url(bytes) {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function signApproval(privateKey, kind, id, museId, username, email) {
  const msg = `muse-approval-v1\n${kind}:${id}\n${museId}\n${username}\n${email}`;
  const sig = await crypto.subtle.sign("Ed25519", privateKey, new TextEncoder().encode(msg));
  return toBase64Url(new Uint8Array(sig));
}

async function call(env, method, path, { body, contentType, headers = {} } = {}) {
  const res = await worker.fetch(
    new Request(`https://login.example.com${path}`, {
      method,
      headers: { ...(contentType ? { "content-type": contentType } : {}), ...headers },
      body,
    }),
    env,
  );
  const text = await res.text();
  let data = null;
  try { data = JSON.parse(text); } catch { /* HTML */ }
  return { status: res.status, text, data, headers: res.headers };
}

async function auditEntries(env) {
  const keys = await env.OAUTH_KV.list("audit:");
  const out = [];
  for (const k of keys) out.push(JSON.parse(await env.OAUTH_KV.get(k)));
  return out;
}

const REDIRECT = "https://www.fedpromptly.com/callback";
const VERIFIER = "verifier-1234567890-abcdefghijklmnopqrstuvwxyz";

async function authorize(env, scope = "openid profile email") {
  const challenge = await pkceChallenge(VERIFIER);
  const auth = await call(env, "GET",
    `/oauth/authorize?client_id=fedpromptly&redirect_uri=${encodeURIComponent(REDIRECT)}&response_type=code&code_challenge=${challenge}&code_challenge_method=S256&scope=${encodeURIComponent(scope)}&state=xyz`);
  assert.equal(auth.status, 200, auth.text);
  const pending = /id="pending-id">([^<]+)/.exec(auth.text)[1];
  return { auth, pending };
}

async function startDevice(env, scope = "openid offline_access") {
  const dev = await call(env, "POST", "/oauth/device-authorization", {
    body: new URLSearchParams({ client_id: "fedpromptly", scope }).toString(),
    contentType: "application/x-www-form-urlencoded",
  });
  assert.equal(dev.status, 200, dev.text);
  return dev.data;
}

async function devicePoll(env, deviceCode) {
  return call(env, "POST", "/oauth/token", {
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:device_code",
      client_id: "fedpromptly",
      device_code: deviceCode,
    }).toString(),
    contentType: "application/x-www-form-urlencoded",
  });
}

test("approval page shows client, redirect host, scopes, and the email statement — and no typed username/email field", async () => {
  const env = await makeEnv();
  const { auth } = await authorize(env, "openid profile email");
  assert.match(auth.text, /FedPromptly/);
  assert.match(auth.text, /www\.fedpromptly\.com/);
  assert.match(auth.text, /<li>openid<\/li>/);
  assert.match(auth.text, /<li>profile<\/li>/);
  assert.match(auth.text, /<li>email<\/li>/);
  assert.match(auth.text, /email_verified: false/);
  assert.match(auth.text, /never blocks your sign-in/);
  // No typed username or email field: the only inputs are the payload
  // textarea and the hidden deny id.
  assert.doesNotMatch(auth.text, /name="username"/);
  assert.doesNotMatch(auth.text, /name="email"/);
  // The deny path is offered on the page.
  assert.match(auth.text, /\/oauth\/deny/);
  assert.match(auth.text, />Deny<\/button>/);
});

test("deny fails the pending request and later approval answers access_denied", async () => {
  const env = await makeEnv();
  const museKey = await registerMuse(env);
  const { pending } = await authorize(env);
  const deny = await call(env, "POST", "/oauth/deny", {
    body: JSON.stringify({ pending_id: pending }),
    contentType: "application/json",
  });
  assert.equal(deny.status, 200, deny.text);
  assert.equal(deny.data.denied, true);
  assert.match(deny.data.redirect_to, /error=access_denied/);
  assert.match(deny.data.redirect_to, /state=xyz/);

  // A valid signed approval after denial must NOT produce a code.
  const sig = await signApproval(museKey, "pending", pending, "muse-test", "git-fed", "user@example.com");
  const appr = await call(env, "POST", "/oauth/approval", {
    body: JSON.stringify({ pending_id: pending, muse_id: "muse-test", username: "git-fed", email: "user@example.com", signature: sig }),
    contentType: "application/json",
  });
  assert.equal(appr.status, 400);
  assert.equal(appr.data.error, "access_denied");

  // Deny is idempotent, and unknown ids fail without leaking anything.
  const again = await call(env, "POST", "/oauth/deny", {
    body: JSON.stringify({ pending_id: pending }),
    contentType: "application/json",
  });
  assert.equal(again.status, 200);
  assert.equal(again.data.denied, true);
  const unknown = await call(env, "POST", "/oauth/deny", {
    body: JSON.stringify({ pending_id: "no-such-pending" }),
    contentType: "application/json",
  });
  assert.equal(unknown.status, 400);
  assert.equal(unknown.data.error, "invalid_pending");
});

test("device entry page: blank form on GET, client + scopes on a valid user code", async () => {
  const env = await makeEnv();
  const form = await call(env, "GET", "/device");
  assert.equal(form.status, 200);
  assert.match(form.text, /name="user_code"/);

  const dev = await startDevice(env);
  assert.match(dev.verification_uri, /\/device$/);
  const page = await call(env, "POST", "/device", {
    body: new URLSearchParams({ user_code: dev.user_code }).toString(),
    contentType: "application/x-www-form-urlencoded",
  });
  assert.equal(page.status, 200, page.text);
  assert.match(page.text, /FedPromptly/);
  assert.match(page.text, /<li>openid<\/li>/);
  assert.match(page.text, /<li>offline_access<\/li>/);
  assert.match(page.text, /email_verified: false/);
  assert.match(page.text, /\/oauth\/deny/);
  assert.doesNotMatch(page.text, /name="username"/);
  assert.doesNotMatch(page.text, /name="email"/);
});

test("device approve (signed) lets the token endpoint issue tokens", async () => {
  const env = await makeEnv();
  const museKey = await registerMuse(env);
  const dev = await startDevice(env);
  const lookup = await call(env, "POST", "/device", {
    body: JSON.stringify({ user_code: dev.user_code }),
    contentType: "application/json",
  });
  assert.equal(lookup.status, 200, lookup.text);
  assert.equal(lookup.data.status, "pending");
  assert.equal(lookup.data.client_name, "FedPromptly");
  assert.equal(lookup.data.device_code, dev.device_code);

  const pending = await devicePoll(env, dev.device_code);
  assert.equal(pending.data.error, "authorization_pending");
  const sig = await signApproval(museKey, "device", dev.device_code, "muse-test", "git-fed", "user@example.com");
  const appr = await call(env, "POST", "/oauth/approval", {
    body: JSON.stringify({ device_code: dev.device_code, muse_id: "muse-test", username: "git-fed", email: "user@example.com", signature: sig }),
    contentType: "application/json",
  });
  assert.equal(appr.status, 200, appr.text);
  const tok = await devicePoll(env, dev.device_code);
  assert.equal(tok.status, 200, tok.text);
  assert.ok(tok.data.access_token);
});

test("device deny makes polling return access_denied, repeatedly", async () => {
  const env = await makeEnv();
  const dev = await startDevice(env);
  const deny = await call(env, "POST", "/oauth/deny", {
    body: JSON.stringify({ device_code: dev.device_code }),
    contentType: "application/json",
  });
  assert.equal(deny.status, 200);
  assert.equal(deny.data.denied, true);
  const poll1 = await devicePoll(env, dev.device_code);
  assert.equal(poll1.status, 400);
  assert.equal(poll1.data.error, "access_denied");
  const poll2 = await devicePoll(env, dev.device_code);
  assert.equal(poll2.data.error, "access_denied");
});

test("wrong, malformed, and expired user codes error cleanly with one generic message", async () => {
  const env = await makeEnv();
  const wrong = await call(env, "POST", "/device", {
    body: new URLSearchParams({ user_code: "ZZZZ-9999" }).toString(),
    contentType: "application/x-www-form-urlencoded",
  });
  assert.equal(wrong.status, 400);
  assert.match(wrong.text, /invalid or has expired/);
  assert.doesNotMatch(wrong.text, /Error:|at .*\.mjs|node:/);

  const malformed = await call(env, "POST", "/device", {
    body: JSON.stringify({ user_code: "not-a-code" }),
    contentType: "application/json",
  });
  assert.equal(malformed.status, 400);
  assert.equal(malformed.data.error, "invalid_user_code");

  // Expired: a device record whose TTL already passed, with its index
  // still present, must read as invalid — same message, no distinction.
  const deviceCode = "expired-device-code";
  await recordStub(env, `device:${deviceCode}`).create(
    { kind: "device", device_code: deviceCode, user_code: "ABCD-1234", client_id: "fedpromptly", scope: ["openid"], status: "pending" },
    1,
  );
  await env.OAUTH_KV.put("device_user_code:ABCD-1234", deviceCode);
  await new Promise((r) => setTimeout(r, 10));
  const expired = await call(env, "POST", "/device", {
    body: new URLSearchParams({ user_code: "ABCD-1234" }).toString(),
    contentType: "application/x-www-form-urlencoded",
  });
  assert.equal(expired.status, 400);
  assert.match(expired.text, /invalid or has expired/);

  // The invalid attempts were audited without the submitted code value.
  const audits = await auditEntries(env);
  assert.ok(audits.some((a) => a.event === "device_entry_invalid"));
  assert.ok(!JSON.stringify(audits).includes("ZZZZ-9999"), "audit must not contain the submitted code");
});

test("device submissions are rate-limited per IP", async () => {
  const env = await makeEnv();
  let last;
  for (let i = 0; i < 31; i++) {
    last = await call(env, "POST", "/device", {
      body: new URLSearchParams({ user_code: "ZZZZ-9999" }).toString(),
      contentType: "application/x-www-form-urlencoded",
      headers: { "cf-connecting-ip": "203.0.113.7" },
    });
  }
  assert.equal(last.status, 429, last.text);
  assert.equal(last.data.error, "rate_limited");
  assert.ok(last.headers.get("retry-after"));
});

test("approve and deny outcomes are audited, with no secret material", async () => {
  const env = await makeEnv();
  const museKey = await registerMuse(env);

  // Authorize deny.
  const { pending } = await authorize(env);
  await call(env, "POST", "/oauth/deny", {
    body: JSON.stringify({ pending_id: pending }),
    contentType: "application/json",
  });

  // Device approve.
  const devOk = await startDevice(env);
  const sig = await signApproval(museKey, "device", devOk.device_code, "muse-test", "git-fed", "user@example.com");
  await call(env, "POST", "/oauth/approval", {
    body: JSON.stringify({ device_code: devOk.device_code, muse_id: "muse-test", username: "git-fed", email: "user@example.com", signature: sig }),
    contentType: "application/json",
  });

  // Device deny + poll surfacing it.
  const devNo = await startDevice(env);
  await call(env, "POST", "/oauth/deny", {
    body: JSON.stringify({ device_code: devNo.device_code }),
    contentType: "application/json",
  });
  await devicePoll(env, devNo.device_code);

  const audits = await auditEntries(env);
  const byDetail = (event, detail) => audits.find((a) => a.event === event && a.detail === detail);
  assert.ok(byDetail("approval_denied", "denied_by_user"), "authorize deny audited");
  assert.ok(byDetail("approval_denied", "device_denied_by_user"), "device deny audited");
  assert.ok(byDetail("approval_approved", "device"), "device approve audited");
  assert.ok(byDetail("token_denied", "device_code"), "denied poll audited");
  const blob = JSON.stringify(audits);
  for (const secret of [devOk.device_code, devOk.user_code, devNo.device_code, devNo.user_code]) {
    assert.ok(!blob.includes(secret), "audit trail leaked device material");
  }
});
