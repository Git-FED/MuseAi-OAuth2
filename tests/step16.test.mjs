// Step 16 — profiles. A fresh sign-in (code or device redemption)
// creates/updates a KV profile keyed by sub; refresh rotation does
// not; GET /oauth/profile returns it to a valid token holder, 401
// without a valid token, 404 when no valid record exists. CORS
// matches userinfo so a third-party site page can read it.
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

function fakeStore() {
  const instances = new Map();
  return {
    idFromName: (k) => k,
    get: (id) => {
      if (!instances.has(id)) instances.set(id, new OAuthRecord({ storage: fakeStorage() }));
      return instances.get(id);
    },
  };
}

function fakeRateLimit() {
  const instances = new Map();
  return {
    idFromName: (k) => k,
    get: (id) => {
      if (!instances.has(id)) instances.set(id, new RateLimitBucket({ storage: fakeStorage() }));
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
  };
}

async function makeEnv() {
  const kv = fakeKV();
  const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const signing = await crypto.subtle.exportKey("jwk", kp.privateKey);
  const pub = await crypto.subtle.exportKey("jwk", kp.publicKey);
  const env = {
    OAUTH_STORE: fakeStore(),
    OAUTH_KV: kv,
    RATE_LIMIT: fakeRateLimit(),
    ISSUER: "https://login.example.com",
    SIGNING_KEY_JWK: JSON.stringify(signing),
    SIGNING_PUBLIC_JWK: JSON.stringify(pub),
  };
  await kv.put("client:fedpromptly", JSON.stringify({
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
  try { data = JSON.parse(text); } catch { /* HTML or empty */ }
  return { status: res.status, text, data, headers: res.headers };
}

const REDIRECT = "https://www.fedpromptly.com/callback";
const VERIFIER = "verifier-1234567890-abcdefghijklmnopqrstuvwxyz";

async function signIn(env, museKey, username = "git-fed", email = "user@example.com") {
  const challenge = await pkceChallenge(VERIFIER);
  const auth = await call(env, "GET",
    `/oauth/authorize?client_id=fedpromptly&redirect_uri=${encodeURIComponent(REDIRECT)}&response_type=code&code_challenge=${challenge}&code_challenge_method=S256&scope=${encodeURIComponent("openid profile email offline_access")}&state=xyz`);
  assert.equal(auth.status, 200, auth.text);
  const pending = /id="pending-id">([^<]+)/.exec(auth.text)[1];
  const sig = await signApproval(museKey, "pending", pending, "muse-test", username, email);
  const appr = await call(env, "POST", "/oauth/approval", {
    body: JSON.stringify({ pending_id: pending, muse_id: "muse-test", username, email, signature: sig }),
    contentType: "application/json",
  });
  assert.equal(appr.status, 200, appr.text);
  const code = new URL(appr.data.redirect_to).searchParams.get("code");
  const tok = await call(env, "POST", "/oauth/token", {
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
  return tok.data;
}

async function getProfile(env, token, extraHeaders = {}) {
  return call(env, "GET", "/oauth/profile", {
    headers: { authorization: `Bearer ${token}`, ...extraHeaders },
  });
}

test("profile: first sign-in creates a profile keyed by sub", async () => {
  const env = await makeEnv();
  const museKey = await registerMuse(env);
  const tok = await signIn(env, museKey);
  const prof = await getProfile(env, tok.access_token);
  assert.equal(prof.status, 200, prof.text);
  assert.equal(prof.data.sub, "muse:muse-test");
  assert.equal(prof.data.preferred_username, "git-fed");
  assert.equal(prof.data.email, "user@example.com");
  assert.equal(prof.data.email_verified, false);
  assert.equal(prof.data.sign_in_count, 1);
  assert.equal(prof.data.first_sign_in, prof.data.last_sign_in);
  assert.ok(!Number.isNaN(Date.parse(prof.data.first_sign_in)));
});

test("profile: second sign-in keeps first, bumps count, updates identity", async () => {
  const env = await makeEnv();
  const museKey = await registerMuse(env);
  const first = await signIn(env, museKey);
  const p1 = await getProfile(env, first.access_token);
  assert.equal(p1.status, 200);
  const second = await signIn(env, museKey, "git-fed-2", "other@example.com");
  const p2 = await getProfile(env, second.access_token);
  assert.equal(p2.status, 200, p2.text);
  assert.equal(p2.data.sign_in_count, 2);
  assert.equal(p2.data.first_sign_in, p1.data.first_sign_in);
  assert.ok(Date.parse(p2.data.last_sign_in) >= Date.parse(p2.data.first_sign_in));
  assert.equal(p2.data.preferred_username, "git-fed-2");
  assert.equal(p2.data.email, "other@example.com");
});

test("profile: refresh rotation does not count as a sign-in", async () => {
  const env = await makeEnv();
  const museKey = await registerMuse(env);
  const tok = await signIn(env, museKey);
  const before = await getProfile(env, tok.access_token);
  assert.equal(before.data.sign_in_count, 1);
  const rotated = await call(env, "POST", "/oauth/token", {
    body: new URLSearchParams({
      grant_type: "refresh_token",
      client_id: "fedpromptly",
      refresh_token: tok.refresh_token,
    }).toString(),
    contentType: "application/x-www-form-urlencoded",
  });
  assert.equal(rotated.status, 200, rotated.text);
  const after = await getProfile(env, rotated.data.access_token);
  assert.equal(after.status, 200);
  assert.equal(after.data.sign_in_count, 1);
  assert.equal(after.data.last_sign_in, before.data.last_sign_in);
});

test("profile: device sign-in also creates a profile", async () => {
  const env = await makeEnv();
  const museKey = await registerMuse(env);
  const dev = await call(env, "POST", "/oauth/device-authorization", {
    body: new URLSearchParams({ client_id: "fedpromptly", scope: "openid offline_access" }).toString(),
    contentType: "application/x-www-form-urlencoded",
  });
  assert.equal(dev.status, 200, dev.text);
  const sig = await signApproval(museKey, "device", dev.data.device_code, "muse-test", "git-fed", "user@example.com");
  const appr = await call(env, "POST", "/oauth/approval", {
    body: JSON.stringify({ device_code: dev.data.device_code, muse_id: "muse-test", username: "git-fed", email: "user@example.com", signature: sig }),
    contentType: "application/json",
  });
  assert.equal(appr.status, 200, appr.text);
  const tok = await call(env, "POST", "/oauth/token", {
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:device_code",
      client_id: "fedpromptly",
      device_code: dev.data.device_code,
    }).toString(),
    contentType: "application/x-www-form-urlencoded",
  });
  assert.equal(tok.status, 200, tok.text);
  const prof = await getProfile(env, tok.data.access_token);
  assert.equal(prof.status, 200, prof.text);
  assert.equal(prof.data.sub, "muse:muse-test");
  assert.equal(prof.data.sign_in_count, 1);
});

test("profile: no token or bad token is 401", async () => {
  const env = await makeEnv();
  const museKey = await registerMuse(env);
  await signIn(env, museKey);
  const noAuth = await call(env, "GET", "/oauth/profile");
  assert.equal(noAuth.status, 401);
  const bad = await call(env, "GET", "/oauth/profile", {
    headers: { authorization: "Bearer not-a-token" },
  });
  assert.equal(bad.status, 401);
  assert.equal(bad.data.error, "invalid_token");
});

test("profile: missing or malformed record is 404, next sign-in repairs it", async () => {
  const env = await makeEnv();
  const museKey = await registerMuse(env);
  const tok = await signIn(env, museKey);
  await env.OAUTH_KV.delete("profile:muse:muse-test");
  const missing = await getProfile(env, tok.access_token);
  assert.equal(missing.status, 404);
  assert.equal(missing.data.error, "profile_not_found");
  await env.OAUTH_KV.put("profile:muse:muse-test", "not-json");
  const malformed = await getProfile(env, tok.access_token);
  assert.equal(malformed.status, 404);
  const again = await signIn(env, museKey);
  const repaired = await getProfile(env, again.access_token);
  assert.equal(repaired.status, 200, repaired.text);
  assert.equal(repaired.data.sign_in_count, 1);
});

test("profile: CORS preflight and response headers match userinfo", async () => {
  const env = await makeEnv();
  const museKey = await registerMuse(env);
  const tok = await signIn(env, museKey);
  const pre = await call(env, "OPTIONS", "/oauth/profile", {
    headers: { origin: "https://hub.fedos.workers.dev" },
  });
  assert.equal(pre.status, 204);
  assert.equal(pre.headers.get("access-control-allow-origin"), "https://hub.fedos.workers.dev");
  const prof = await getProfile(env, tok.access_token, { origin: "https://hub.fedos.workers.dev" });
  assert.equal(prof.status, 200);
  assert.equal(prof.headers.get("access-control-allow-origin"), "https://hub.fedos.workers.dev");
});
