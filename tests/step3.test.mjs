// Step 3 tests: registries, admin registration, rate limits, audit.
// Fake env doubles mirror tests/oauth-flow.test.mjs (fake DO store,
// fake rate-limit namespace, fake KV Map, fresh Web Crypto keys).
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

async function makeEnv({ adminToken = "test-admin-token" } = {}) {
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
  };
  // adminToken === null means ADMIN_TOKEN is genuinely unset (not empty).
  if (adminToken !== null) env.ADMIN_TOKEN = adminToken;
  return env;
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

async function adminCall(env, method, path, body, token = "test-admin-token") {
  return call(env, method, path, {
    body: JSON.stringify(body),
    contentType: "application/json",
    headers: token ? { authorization: `Bearer ${token}` } : {},
  });
}

async function auditEntries(env) {
  const keys = await env.OAUTH_KV.list("audit:");
  const out = [];
  for (const k of keys) out.push(JSON.parse(await env.OAUTH_KV.get(k)));
  return out;
}

function toBase64Url(bytes) {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function makeEd25519Keypair() {
  const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const pub = await crypto.subtle.exportKey("jwk", kp.publicKey);
  return { privateKey: kp.privateKey, pub };
}

const REDIRECT = "https://www.fedpromptly.com/callback";
const VERIFIER = "verifier-1234567890-abcdefghijklmnopqrstuvwxyz";

async function approvedCode(env, museKey, museId = "muse-test") {
  const challenge = await pkceChallenge(VERIFIER);
  const auth = await call(env, "GET",
    `/oauth/authorize?client_id=fedpromptly&redirect_uri=${encodeURIComponent(REDIRECT)}&response_type=code&code_challenge=${challenge}&code_challenge_method=S256&scope=${encodeURIComponent("openid profile email offline_access")}&state=xyz`);
  assert.equal(auth.status, 200, auth.text);
  const pending = /id="pending-id">([^<]+)/.exec(auth.text)[1];
  const msg = `muse-approval-v1\npending:${pending}\n${museId}\ngit-fed\nuser@example.com`;
  const sig = await crypto.subtle.sign("Ed25519", museKey, new TextEncoder().encode(msg));
  const appr = await call(env, "POST", "/oauth/approval", {
    body: JSON.stringify({ pending_id: pending, muse_id: museId, username: "git-fed", email: "user@example.com", signature: toBase64Url(new Uint8Array(sig)) }),
    contentType: "application/json",
  });
  assert.equal(appr.status, 200, appr.text);
  return new URL(appr.data.redirect_to).searchParams.get("code");
}

test("admin registers a client, then authorize works with it", async () => {
  const env = await makeEnv();
  const reg = await adminCall(env, "POST", "/admin/clients", {
    client_id: "fedpromptly", name: "FedPromptly", redirect_uris: [REDIRECT],
  });
  assert.equal(reg.status, 201, reg.text);
  assert.equal(reg.data.client_id, "fedpromptly");
  const stored = JSON.parse(await env.OAUTH_KV.get("client:fedpromptly"));
  assert.equal(stored.name, "FedPromptly");
  const challenge = await pkceChallenge(VERIFIER);
  const auth = await call(env, "GET",
    `/oauth/authorize?client_id=fedpromptly&redirect_uri=${encodeURIComponent(REDIRECT)}&response_type=code&code_challenge=${challenge}&code_challenge_method=S256&scope=openid`);
  assert.equal(auth.status, 200, auth.text);
});

test("admin endpoints fail closed without or with a wrong token", async () => {
  const env = await makeEnv();
  const noToken = await adminCall(env, "POST", "/admin/clients",
    { client_id: "x", name: "X", redirect_uris: [REDIRECT] }, null);
  assert.equal(noToken.status, 403);
  const wrongToken = await adminCall(env, "POST", "/admin/clients",
    { client_id: "x", name: "X", redirect_uris: [REDIRECT] }, "not-the-token");
  assert.equal(wrongToken.status, 403);
  assert.equal(await env.OAUTH_KV.get("client:x"), null);

  const unsetEnv = await makeEnv({ adminToken: null });
  const unset = await adminCall(unsetEnv, "POST", "/admin/clients",
    { client_id: "x", name: "X", redirect_uris: [REDIRECT] }, "anything");
  assert.equal(unset.status, 403);
  assert.equal(await unsetEnv.OAUTH_KV.get("client:x"), null);
});

test("admin rejects bad redirect URIs and writes nothing", async () => {
  const env = await makeEnv();
  for (const bad of ["http://example.com/cb", "https://*.example.com/cb", "https://localhost/cb", "https://127.0.0.1/cb", "not-a-url", "https://example.com/*"]) {
    const res = await adminCall(env, "POST", "/admin/clients",
      { client_id: "badclient", name: "Bad", redirect_uris: [bad] });
    assert.equal(res.status, 400, bad);
  }
  assert.equal(await env.OAUTH_KV.get("client:badclient"), null);
});

test("admin rejects malformed muse key JWKs and writes nothing", async () => {
  const env = await makeEnv();
  const badKeys = [
    { kty: "EC", crv: "P-256", x: "abc" },                       // wrong kty
    { kty: "OKP", crv: "X25519", x: "a".repeat(43) },              // wrong curve
    { kty: "OKP", crv: "Ed25519" },                               // missing x
    { kty: "OKP", crv: "Ed25519", x: "not!base64url" },            // bad chars
    { kty: "OKP", crv: "Ed25519", x: "a".repeat(43), use: "enc" },  // wrong use
    { kty: "OKP", crv: "Ed25519", x: "a".repeat(43), key_ops: ["sign"] }, // public key must not claim sign
    // NOTE: a 32-byte x that imports is a valid-shape key even if nobody
    // holds the private half — Web Crypto cannot tell "real" from
    // arbitrary bytes, which is why registration is a reviewed human
    // action, not a self-service check. That case is NOT in this list.
  ];
  for (const jwk of badKeys) {
    const res = await adminCall(env, "POST", "/admin/muse-keys",
      { muse_id: "muse-bad", public_key_jwk: jwk });
    assert.equal(res.status, 400, JSON.stringify(jwk));
  }
  assert.equal(await env.OAUTH_KV.get("muse_key:muse-bad"), null);
});

test("admin registers a muse key, then approval succeeds with it", async () => {
  const env = await makeEnv();
  const { privateKey, pub } = await makeEd25519Keypair();
  const reg = await adminCall(env, "POST", "/admin/muse-keys",
    { muse_id: "muse-test", public_key_jwk: pub });
  assert.equal(reg.status, 201, reg.text);
  await adminCall(env, "POST", "/admin/clients",
    { client_id: "fedpromptly", name: "FedPromptly", redirect_uris: [REDIRECT] });
  const code = await approvedCode(env, privateKey);
  assert.ok(code);
});

test("strict reader rejects hand-written malformed registry records", async () => {
  const env = await makeEnv();
  // Malformed client: wildcard redirect slipped in by hand.
  await env.OAUTH_KV.put("client:evil", JSON.stringify({
    client_id: "evil", name: "Evil", redirect_uris: ["https://*.example.com/cb"],
  }));
  const challenge = await pkceChallenge(VERIFIER);
  const auth = await call(env, "GET",
    `/oauth/authorize?client_id=evil&redirect_uri=${encodeURIComponent("https://sub.example.com/cb")}&response_type=code&code_challenge=${challenge}&code_challenge_method=S256&scope=openid`);
  assert.equal(auth.status, 400);
  assert.equal(auth.data.error, "invalid_client");

  // Malformed muse key: wrong curve, hand-written.
  await env.OAUTH_KV.put("muse_key:muse-bad", JSON.stringify({
    muse_id: "muse-bad", public_key_jwk: { kty: "OKP", crv: "X25519", x: "a".repeat(43) },
  }));
  const appr = await call(env, "POST", "/oauth/approval", {
    body: JSON.stringify({ pending_id: "nope", muse_id: "muse-bad", username: "u", email: "e@x.com", signature: "sig" }),
    contentType: "application/json",
  });
  assert.equal(appr.status, 400); // no pending record -> invalid_pending, before key lookup
  // With a real pending record, the malformed key must read as unregistered (403).
  await adminCall(env, "POST", "/admin/clients",
    { client_id: "fedpromptly", name: "FedPromptly", redirect_uris: [REDIRECT] });
  const challenge2 = await pkceChallenge(VERIFIER);
  const auth2 = await call(env, "GET",
    `/oauth/authorize?client_id=fedpromptly&redirect_uri=${encodeURIComponent(REDIRECT)}&response_type=code&code_challenge=${challenge2}&code_challenge_method=S256&scope=openid`);
  const pending = /id="pending-id">([^<]+)/.exec(auth2.text)[1];
  const appr2 = await call(env, "POST", "/oauth/approval", {
    body: JSON.stringify({ pending_id: pending, muse_id: "muse-bad", username: "u", email: "e@x.com", signature: "sig" }),
    contentType: "application/json",
  });
  assert.equal(appr2.status, 403);
  assert.equal(appr2.data.error, "unregistered_muse");
});

test("per-client scope restriction is enforced", async () => {
  const env = await makeEnv();
  await adminCall(env, "POST", "/admin/clients",
    { client_id: "narrow", name: "Narrow", redirect_uris: [REDIRECT], allowed_scopes: ["openid"] });
  const challenge = await pkceChallenge(VERIFIER);
  const wide = await call(env, "GET",
    `/oauth/authorize?client_id=narrow&redirect_uri=${encodeURIComponent(REDIRECT)}&response_type=code&code_challenge=${challenge}&code_challenge_method=S256&scope=${encodeURIComponent("openid email")}`);
  assert.equal(wide.status, 302);
  assert.match(wide.headers.get("location"), /invalid_scope/);
  const narrow = await call(env, "GET",
    `/oauth/authorize?client_id=narrow&redirect_uri=${encodeURIComponent(REDIRECT)}&response_type=code&code_challenge=${challenge}&code_challenge_method=S256&scope=openid`);
  assert.equal(narrow.status, 200);
});

test("authorize rate limit blocks after 60 hits per IP per minute", async () => {
  const env = await makeEnv();
  await adminCall(env, "POST", "/admin/clients",
    { client_id: "fedpromptly", name: "FedPromptly", redirect_uris: [REDIRECT] });
  const challenge = await pkceChallenge(VERIFIER);
  const url = `/oauth/authorize?client_id=fedpromptly&redirect_uri=${encodeURIComponent(REDIRECT)}&response_type=code&code_challenge=${challenge}&code_challenge_method=S256&scope=openid`;
  let last;
  for (let i = 0; i < 61; i++) {
    last = await call(env, "GET", url, { headers: { "cf-connecting-ip": "203.0.113.9" } });
  }
  assert.equal(last.status, 429, last.text);
  assert.equal(last.data.error, "rate_limited");
  assert.ok(last.headers.get("retry-after"), "Retry-After header present");
  const audits = await auditEntries(env);
  const blocked = audits.find((a) => a.event === "rate_limited");
  assert.ok(blocked, "rate limit block is audited");
  assert.ok(!JSON.stringify(blocked).includes("203.0.113.9"), "audit entry must not contain the IP value");
});

test("approval rate limit blocks signature guessing per pending id", async () => {
  const env = await makeEnv();
  await adminCall(env, "POST", "/admin/clients",
    { client_id: "fedpromptly", name: "FedPromptly", redirect_uris: [REDIRECT] });
  const challenge = await pkceChallenge(VERIFIER);
  const auth = await call(env, "GET",
    `/oauth/authorize?client_id=fedpromptly&redirect_uri=${encodeURIComponent(REDIRECT)}&response_type=code&code_challenge=${challenge}&code_challenge_method=S256&scope=openid`);
  const pending = /id="pending-id">([^<]+)/.exec(auth.text)[1];
  let last;
  for (let i = 0; i < 11; i++) {
    last = await call(env, "POST", "/oauth/approval", {
      body: JSON.stringify({ pending_id: pending, muse_id: "muse-test", username: "u", email: "e@x.com", signature: "bad" }),
      contentType: "application/json",
    });
  }
  assert.equal(last.status, 429, last.text);
  assert.equal(last.data.error, "rate_limited");
});

test("audit trail covers flows and contains no secret material", async () => {
  const env = await makeEnv();
  const { privateKey, pub } = await makeEd25519Keypair();
  await adminCall(env, "POST", "/admin/muse-keys",
    { muse_id: "muse-test", public_key_jwk: pub });
  await adminCall(env, "POST", "/admin/clients",
    { client_id: "fedpromptly", name: "FedPromptly", redirect_uris: [REDIRECT] });
  const code = await approvedCode(env, privateKey);
  // Failed approval (bad signature) for the denial entry.
  const challenge = await pkceChallenge(VERIFIER);
  const auth = await call(env, "GET",
    `/oauth/authorize?client_id=fedpromptly&redirect_uri=${encodeURIComponent(REDIRECT)}&response_type=code&code_challenge=${challenge}&code_challenge_method=S256&scope=${encodeURIComponent("openid profile email offline_access")}`);
  const pending = /id="pending-id">([^<]+)/.exec(auth.text)[1];
  await call(env, "POST", "/oauth/approval", {
    body: JSON.stringify({ pending_id: pending, muse_id: "muse-test", username: "u", email: "e@x.com", signature: "bad-signature" }),
    contentType: "application/json",
  });
  // Token issue + revocation.
  const tok = await call(env, "POST", "/oauth/token", {
    body: new URLSearchParams({ grant_type: "authorization_code", client_id: "fedpromptly", code, redirect_uri: REDIRECT, code_verifier: VERIFIER }).toString(),
    contentType: "application/x-www-form-urlencoded",
  });
  assert.equal(tok.status, 200, tok.text);
  const accessToken = tok.data.access_token;
  const refreshToken = tok.data.refresh_token;
  assert.ok(accessToken && refreshToken);
  const revoke = await call(env, "POST", "/oauth/revoke", {
    body: new URLSearchParams({ token: refreshToken, token_type_hint: "refresh_token" }).toString(),
    contentType: "application/x-www-form-urlencoded",
  });
  assert.equal(revoke.status, 200);

  const audits = await auditEntries(env);
  const events = audits.map((a) => a.event);
  for (const want of ["admin_client_registered", "admin_muse_key_registered", "approval_approved", "approval_denied", "token_issued", "token_revoked"]) {
    assert.ok(events.includes(want), `missing audit event ${want} (have: ${events.join(", ")})`);
  }
  const blob = JSON.stringify(audits);
  for (const secret of [code, accessToken, refreshToken, "bad-signature", "test-admin-token"]) {
    assert.ok(!blob.includes(secret), `audit trail leaked secret material: ${secret.slice(0, 12)}...`);
  }
  // Every entry has the fixed shape and nothing else sensitive-looking.
  for (const entry of audits) {
    assert.deepEqual(Object.keys(entry).sort(),
      ["actor", "client_id", "detail", "event", "outcome", "route", "ts"]);
  }
});
