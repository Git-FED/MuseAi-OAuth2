// Step 5 tests: /login path-prefix support (BASE_PATH env).
// Fake env doubles mirror tests/step4.test.mjs.
import test from "node:test";
import assert from "node:assert/strict";
import worker from "../worker.js";
import { OAuthRecord } from "../src/store/oauth-record.js";
import { RateLimitBucket } from "../src/store/rate-limit.js";
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

async function makeEnv({ basePath, issuer } = {}) {
  const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const signing = await crypto.subtle.exportKey("jwk", kp.privateKey);
  const pub = await crypto.subtle.exportKey("jwk", kp.publicKey);
  const env = {
    OAUTH_STORE: fakeNamespace(OAuthRecord),
    OAUTH_KV: fakeKV(),
    RATE_LIMIT: fakeNamespace(RateLimitBucket),
    ISSUER: issuer ?? "https://fedpromptly.com/login",
    SIGNING_KEY_JWK: JSON.stringify(signing),
    SIGNING_PUBLIC_JWK: JSON.stringify(pub),
    ADMIN_TOKEN: "test-admin-token",
  };
  if (basePath !== undefined) env.BASE_PATH = basePath;
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
    new Request(`https://fedpromptly.com${path}`, {
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

const REDIRECT = "https://www.fedpromptly.com/callback";
const VERIFIER = "verifier-1234567890-abcdefghijklmnopqrstuvwxyz";

test("full authorize flow works end to end through prefixed URLs", async () => {
  const env = await makeEnv({ basePath: "/login" });
  const museKey = await registerMuse(env);
  const challenge = await pkceChallenge(VERIFIER);
  const auth = await call(env, "GET",
    `/login/oauth/authorize?client_id=fedpromptly&redirect_uri=${encodeURIComponent(REDIRECT)}&response_type=code&code_challenge=${challenge}&code_challenge_method=S256&scope=${encodeURIComponent("openid profile email")}&state=xyz`);
  assert.equal(auth.status, 200, auth.text);
  assert.match(auth.text, /FedPromptly/);
  const pending = /id="pending-id">([^<]+)/.exec(auth.text)[1];

  const sig = await signApproval(museKey, "pending", pending, "muse-test", "git-fed", "user@example.com");
  const appr = await call(env, "POST", "/login/oauth/approval", {
    body: JSON.stringify({ pending_id: pending, muse_id: "muse-test", username: "git-fed", email: "user@example.com", signature: sig }),
    contentType: "application/json",
  });
  assert.equal(appr.status, 200, appr.text);
  assert.equal(appr.data.approved, true);
  // Client redirect URIs are NOT rewritten by the prefix.
  const redirectTo = new URL(appr.data.redirect_to);
  assert.equal(redirectTo.origin + redirectTo.pathname, REDIRECT);
  assert.equal(redirectTo.searchParams.get("state"), "xyz");
  const code = redirectTo.searchParams.get("code");
  assert.ok(code);

  const tok = await call(env, "POST", "/login/oauth/token", {
    body: new URLSearchParams({
      grant_type: "authorization_code",
      client_id: "fedpromptly",
      code,
      redirect_uri: REDIRECT,
      code_verifier: VERIFIER,
    }).toString(),
    contentType: "application/x-www-form-urlencoded",
  });
  assert.equal(tok.status, 200, tok.text);
  assert.ok(tok.data.access_token);

  const me = await call(env, "GET", "/login/oauth/userinfo", {
    headers: { authorization: `Bearer ${tok.data.access_token}` },
  });
  assert.equal(me.status, 200, me.text);
  assert.equal(me.data.email, "user@example.com");
  assert.equal(me.data.email_verified, false);
});

test("root-path requests 404 when a prefix is set, and the mount root 404s too", async () => {
  const env = await makeEnv({ basePath: "/login" });
  for (const path of ["/oauth/authorize", "/health", "/device", "/.well-known/openid-configuration", "/login/", "/login"]) {
    const res = await call(env, "GET", path);
    assert.equal(res.status, 404, `${path} -> ${res.status}`);
    assert.equal(res.data.error, "not_found");
  }
  // Wrong method under the prefix is still 405, not 404.
  const wrong = await call(env, "POST", "/login/oauth/authorize");
  assert.equal(wrong.status, 405);
  // Health works at the prefixed mount.
  const health = await call(env, "GET", "/login/health");
  assert.equal(health.status, 200);
  assert.equal(health.data.ok, true);
});

test("discovery returns the /login issuer with every endpoint under /login", async () => {
  const env = await makeEnv({ basePath: "/login" });
  const disc = await call(env, "GET", "/login/.well-known/openid-configuration");
  assert.equal(disc.status, 200, disc.text);
  assert.equal(disc.data.issuer, "https://fedpromptly.com/login");
  for (const field of ["authorization_endpoint", "token_endpoint", "userinfo_endpoint", "jwks_uri", "revocation_endpoint", "device_authorization_endpoint"]) {
    assert.ok(disc.data[field].startsWith("https://fedpromptly.com/login/"), `${field} = ${disc.data[field]}`);
  }
  assert.equal(disc.data.authorization_endpoint, "https://fedpromptly.com/login/oauth/authorize");
  assert.equal(disc.data.jwks_uri, "https://fedpromptly.com/login/jwks");
});

test("device verification_uri sits under /login, and the entry page posts there", async () => {
  const env = await makeEnv({ basePath: "/login" });
  const dev = await call(env, "POST", "/login/oauth/device-authorization", {
    body: new URLSearchParams({ client_id: "fedpromptly", scope: "openid offline_access" }).toString(),
    contentType: "application/x-www-form-urlencoded",
  });
  assert.equal(dev.status, 200, dev.text);
  assert.equal(dev.data.verification_uri, "https://fedpromptly.com/login/device");

  const form = await call(env, "GET", "/login/device");
  assert.equal(form.status, 200);
  assert.match(form.text, /action="\/login\/device"/);

  const page = await call(env, "POST", "/login/device", {
    body: new URLSearchParams({ user_code: dev.data.user_code }).toString(),
    contentType: "application/x-www-form-urlencoded",
  });
  assert.equal(page.status, 200, page.text);
  assert.match(page.text, /FedPromptly/);
  // The detail page carries prefixed approval/deny fetches (it has no
  // entry form — the action assertion belongs on the blank form above).
  assert.match(page.text, /fetch\("\/login\/oauth\/approval"/);
  assert.match(page.text, /fetch\("\/login\/oauth\/deny"/);
});

test("prefix-confusion paths never match: /loginevil and /loginfoo are 404", async () => {
  const env = await makeEnv({ basePath: "/login" });
  for (const path of [
    "/loginevil/oauth/authorize",
    "/loginevil/health",
    "/loginfoo/device",
    "/loginx",
    "/login-evil/health",
    "/LOGIN/oauth/authorize",
  ]) {
    const res = await call(env, "GET", path);
    assert.equal(res.status, 404, `${path} -> ${res.status}`);
  }
});

test("prefixed pages carry prefixed internal links, never root provider links", async () => {
  const env = await makeEnv({ basePath: "/login" });
  const challenge = await pkceChallenge(VERIFIER);
  const auth = await call(env, "GET",
    `/login/oauth/authorize?client_id=fedpromptly&redirect_uri=${encodeURIComponent(REDIRECT)}&response_type=code&code_challenge=${challenge}&code_challenge_method=S256&scope=openid&state=xyz`);
  assert.equal(auth.status, 200, auth.text);
  assert.match(auth.text, /fetch\("\/login\/oauth\/approval"/);
  assert.match(auth.text, /fetch\("\/login\/oauth\/deny"/);
  assert.doesNotMatch(auth.text, /fetch\("\/oauth\/approval"/);
  assert.doesNotMatch(auth.text, /fetch\("\/oauth\/deny"/);
});

test("rate limits still fire under the prefix", async () => {
  const env = await makeEnv({ basePath: "/login" });
  let last;
  for (let i = 0; i < 61; i++) {
    last = await call(env, "GET", "/login/oauth/authorize?client_id=nonexistent", {
      headers: { "cf-connecting-ip": "203.0.113.9" },
    });
  }
  assert.equal(last.status, 429, last.text);
  assert.equal(last.data.error, "rate_limited");
  assert.ok(last.headers.get("retry-after"));
});

test("BASE_PATH unset: previous root behavior is unchanged", async () => {
  const env = await makeEnv({ basePath: undefined, issuer: "https://login.example.com" });
  const museKey = await registerMuse(env);
  const challenge = await pkceChallenge(VERIFIER);
  const auth = await call(env, "GET",
    `/oauth/authorize?client_id=fedpromptly&redirect_uri=${encodeURIComponent(REDIRECT)}&response_type=code&code_challenge=${challenge}&code_challenge_method=S256&scope=openid&state=xyz`);
  assert.equal(auth.status, 200, auth.text);
  const pending = /id="pending-id">([^<]+)/.exec(auth.text)[1];
  assert.match(auth.text, /fetch\("\/oauth\/approval"/);
  const sig = await signApproval(museKey, "pending", pending, "muse-test", "git-fed", "user@example.com");
  const appr = await call(env, "POST", "/oauth/approval", {
    body: JSON.stringify({ pending_id: pending, muse_id: "muse-test", username: "git-fed", email: "user@example.com", signature: sig }),
    contentType: "application/json",
  });
  assert.equal(appr.status, 200, appr.text);
  const disc = await call(env, "GET", "/.well-known/openid-configuration");
  assert.equal(disc.status, 200);
  assert.equal(disc.data.issuer, "https://login.example.com");
  assert.equal(disc.data.authorization_endpoint, "https://login.example.com/oauth/authorize");
});
