// End-to-end OAuth flow tests against the live worker, using fake env
// doubles: a fake OAUTH_STORE mapping names to live OAuthRecord
// instances with Map storage, a fake KV Map, and Web Crypto keys
// generated fresh per env. No network, no Cloudflare runtime.
import test from "node:test";
import assert from "node:assert/strict";
import worker from "../worker.js";
import { OAuthRecord } from "../src/store/oauth-record.js";
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

function fakeKV() {
  const m = new Map();
  return {
    async get(k) { return m.get(k) ?? null; },
    async put(k, v) { m.set(k, typeof v === "string" ? v : JSON.stringify(v)); },
    async delete(k) { m.delete(k); },
  };
}

async function makeEnv({ issuer = "https://login.example.com" } = {}) {
  const kv = fakeKV();
  const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const signing = await crypto.subtle.exportKey("jwk", kp.privateKey);
  const pub = await crypto.subtle.exportKey("jwk", kp.publicKey);
  const env = {
    OAUTH_STORE: fakeStore(),
    OAUTH_KV: kv,
    ISSUER: issuer,
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

// Full authorize -> approve -> token run. Returns the code + verifier.
async function approvedCode(env, museKey, scope = "openid profile email offline_access") {
  const challenge = await pkceChallenge(VERIFIER);
  const auth = await call(env, "GET",
    `/oauth/authorize?client_id=fedpromptly&redirect_uri=${encodeURIComponent(REDIRECT)}&response_type=code&code_challenge=${challenge}&code_challenge_method=S256&scope=${encodeURIComponent(scope)}&state=xyz`);
  assert.equal(auth.status, 200, auth.text);
  assert.match(auth.text, /FedPromptly/);
  assert.match(auth.text, /www\.fedpromptly\.com/);
  assert.doesNotMatch(auth.text, /type="text" name="username"/);
  const pending = /id="pending-id">([^<]+)/.exec(auth.text)[1];
  const sig = await signApproval(museKey, "pending", pending, "muse-test", "git-fed", "user@example.com");
  const appr = await call(env, "POST", "/oauth/approval", {
    body: JSON.stringify({ pending_id: pending, muse_id: "muse-test", username: "git-fed", email: "user@example.com", signature: sig }),
    contentType: "application/json",
  });
  assert.equal(appr.status, 200, appr.text);
  assert.equal(appr.data.approved, true);
  const code = new URL(appr.data.redirect_to).searchParams.get("code");
  assert.ok(code);
  assert.equal(new URL(appr.data.redirect_to).searchParams.get("state"), "xyz");
  return { code, verifier: VERIFIER };
}

async function redeem(env, code, verifier) {
  return call(env, "POST", "/oauth/token", {
    body: new URLSearchParams({
      grant_type: "authorization_code",
      client_id: "fedpromptly",
      code,
      redirect_uri: REDIRECT,
      code_verifier: verifier,
    }).toString(),
    contentType: "application/x-www-form-urlencoded",
  });
}

test("code grant happy path + userinfo returns email_verified:false", async () => {
  const env = await makeEnv();
  const museKey = await registerMuse(env);
  const { code, verifier } = await approvedCode(env, museKey);
  const tok = await redeem(env, code, verifier);
  assert.equal(tok.status, 200, tok.text);
  assert.equal(tok.data.token_type, "Bearer");
  assert.ok(tok.data.access_token);
  assert.ok(tok.data.id_token);
  assert.ok(tok.data.refresh_token);
  const me = await call(env, "GET", "/oauth/userinfo", {
    headers: { authorization: `Bearer ${tok.data.access_token}` },
  });
  assert.equal(me.status, 200, me.text);
  assert.equal(me.data.sub, "muse:muse-test");
  assert.equal(me.data.email, "user@example.com");
  assert.equal(me.data.email_verified, false);
});

test("PKCE bad verifier is rejected", async () => {
  const env = await makeEnv();
  const museKey = await registerMuse(env);
  const { code } = await approvedCode(env, museKey);
  const tok = await redeem(env, code, "wrong-verifier");
  assert.equal(tok.status, 400);
  assert.equal(tok.data.error, "invalid_grant");
});

test("double redeem of the same code fails", async () => {
  const env = await makeEnv();
  const museKey = await registerMuse(env);
  const { code, verifier } = await approvedCode(env, museKey);
  const first = await redeem(env, code, verifier);
  assert.equal(first.status, 200, first.text);
  const second = await redeem(env, code, verifier);
  assert.equal(second.status, 400);
  assert.equal(second.data.error, "invalid_grant");
});

test("refresh rotation kills the old token", async () => {
  const env = await makeEnv();
  const museKey = await registerMuse(env);
  const { code, verifier } = await approvedCode(env, museKey);
  const tok = await redeem(env, code, verifier);
  assert.equal(tok.status, 200, tok.text);
  const rotated = await call(env, "POST", "/oauth/token", {
    body: new URLSearchParams({
      grant_type: "refresh_token",
      client_id: "fedpromptly",
      refresh_token: tok.data.refresh_token,
    }).toString(),
    contentType: "application/x-www-form-urlencoded",
  });
  assert.equal(rotated.status, 200, rotated.text);
  assert.ok(rotated.data.refresh_token);
  assert.notEqual(rotated.data.refresh_token, tok.data.refresh_token);
  const stale = await call(env, "POST", "/oauth/token", {
    body: new URLSearchParams({
      grant_type: "refresh_token",
      client_id: "fedpromptly",
      refresh_token: tok.data.refresh_token,
    }).toString(),
    contentType: "application/x-www-form-urlencoded",
  });
  assert.equal(stale.status, 400);
  assert.equal(stale.data.error, "invalid_grant");
});

test("approval fails closed with no registered key", async () => {
  const env = await makeEnv();
  // No registerMuse call: no key exists for muse-test.
  const challenge = await pkceChallenge(VERIFIER);
  const auth = await call(env, "GET",
    `/oauth/authorize?client_id=fedpromptly&redirect_uri=${encodeURIComponent(REDIRECT)}&response_type=code&code_challenge=${challenge}&code_challenge_method=S256`);
  const pending = /id="pending-id">([^<]+)/.exec(auth.text)[1];
  const appr = await call(env, "POST", "/oauth/approval", {
    body: JSON.stringify({ pending_id: pending, muse_id: "muse-test", username: "git-fed", email: "user@example.com", signature: "AAAA" }),
    contentType: "application/json",
  });
  assert.equal(appr.status, 403);
  assert.equal(appr.data.error, "unregistered_muse");
});

test("approval with a bad signature is rejected", async () => {
  const env = await makeEnv();
  const museKey = await registerMuse(env);
  const challenge = await pkceChallenge(VERIFIER);
  const auth = await call(env, "GET",
    `/oauth/authorize?client_id=fedpromptly&redirect_uri=${encodeURIComponent(REDIRECT)}&response_type=code&code_challenge=${challenge}&code_challenge_method=S256`);
  const pending = /id="pending-id">([^<]+)/.exec(auth.text)[1];
  // Sign a different email than the one claimed: signature must not verify.
  const sig = await signApproval(museKey, "pending", pending, "muse-test", "git-fed", "someone-else@example.com");
  const appr = await call(env, "POST", "/oauth/approval", {
    body: JSON.stringify({ pending_id: pending, muse_id: "muse-test", username: "git-fed", email: "user@example.com", signature: sig }),
    contentType: "application/json",
  });
  assert.equal(appr.status, 403);
  assert.equal(appr.data.error, "invalid_signature");
});

test("approval rejects a self-supplied key", async () => {
  const env = await makeEnv();
  await registerMuse(env);
  const challenge = await pkceChallenge(VERIFIER);
  const auth = await call(env, "GET",
    `/oauth/authorize?client_id=fedpromptly&redirect_uri=${encodeURIComponent(REDIRECT)}&response_type=code&code_challenge=${challenge}&code_challenge_method=S256`);
  const pending = /id="pending-id">([^<]+)/.exec(auth.text)[1];
  const appr = await call(env, "POST", "/oauth/approval", {
    body: JSON.stringify({ pending_id: pending, muse_id: "muse-test", username: "git-fed", email: "user@example.com", signature: "AAAA", public_key: {} }),
    contentType: "application/json",
  });
  assert.equal(appr.status, 400);
  assert.equal(appr.data.error, "invalid_request");
});

test("discovery fails closed with no ISSUER", async () => {
  const env = await makeEnv({ issuer: undefined });
  delete env.ISSUER;
  const res = await call(env, "GET", "/.well-known/openid-configuration");
  assert.equal(res.status, 503);
  assert.equal(res.data.error, "not_configured");
});

test("unknown route 404, wrong method 405", async () => {
  const env = await makeEnv();
  const missing = await call(env, "GET", "/nope");
  assert.equal(missing.status, 404);
  const wrongMethod = await call(env, "POST", "/oauth/authorize");
  assert.equal(wrongMethod.status, 405);
  const wrongMethod2 = await call(env, "GET", "/oauth/token");
  assert.equal(wrongMethod2.status, 405);
});

test("authorize requires PKCE S256", async () => {
  const env = await makeEnv();
  const noChallenge = await call(env, "GET",
    `/oauth/authorize?client_id=fedpromptly&redirect_uri=${encodeURIComponent(REDIRECT)}&response_type=code`);
  assert.equal(noChallenge.status, 302);
  assert.match(noChallenge.headers.get("location"), /error=invalid_request/);
  const plain = await call(env, "GET",
    `/oauth/authorize?client_id=fedpromptly&redirect_uri=${encodeURIComponent(REDIRECT)}&response_type=code&code_challenge=abc&code_challenge_method=plain`);
  assert.equal(plain.status, 302);
  assert.match(plain.headers.get("location"), /error=invalid_request/);
});

test("device flow: pending, then approved, then tokens", async () => {
  const env = await makeEnv();
  const museKey = await registerMuse(env);
  const dev = await call(env, "POST", "/oauth/device-authorization", {
    body: new URLSearchParams({ client_id: "fedpromptly", scope: "openid offline_access" }).toString(),
    contentType: "application/x-www-form-urlencoded",
  });
  assert.equal(dev.status, 200, dev.text);
  assert.ok(dev.data.device_code);
  assert.match(dev.data.user_code, /^[A-Z0-9]{4}-[A-Z0-9]{4}$/);
  const poll = async () => call(env, "POST", "/oauth/token", {
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:device_code",
      client_id: "fedpromptly",
      device_code: dev.data.device_code,
    }).toString(),
    contentType: "application/x-www-form-urlencoded",
  });
  const pending = await poll();
  assert.equal(pending.status, 400);
  assert.equal(pending.data.error, "authorization_pending");
  const sig = await signApproval(museKey, "device", dev.data.device_code, "muse-test", "git-fed", "user@example.com");
  const appr = await call(env, "POST", "/oauth/approval", {
    body: JSON.stringify({ device_code: dev.data.device_code, muse_id: "muse-test", username: "git-fed", email: "user@example.com", signature: sig }),
    contentType: "application/json",
  });
  assert.equal(appr.status, 200, appr.text);
  assert.equal(appr.data.approved, true);
  const tok = await poll();
  assert.equal(tok.status, 200, tok.text);
  assert.ok(tok.data.access_token);
});

test("revocation kills refresh and access tokens", async () => {
  const env = await makeEnv();
  const museKey = await registerMuse(env);
  const { code, verifier } = await approvedCode(env, museKey);
  const tok = await redeem(env, code, verifier);
  assert.equal(tok.status, 200, tok.text);
  const revokeForm = (t, hint) => call(env, "POST", "/oauth/revoke", {
    body: new URLSearchParams({ token: t, token_type_hint: hint }).toString(),
    contentType: "application/x-www-form-urlencoded",
  });
  const r1 = await revokeForm(tok.data.refresh_token, "refresh_token");
  assert.equal(r1.status, 200);
  const stale = await call(env, "POST", "/oauth/token", {
    body: new URLSearchParams({ grant_type: "refresh_token", client_id: "fedpromptly", refresh_token: tok.data.refresh_token }).toString(),
    contentType: "application/x-www-form-urlencoded",
  });
  assert.equal(stale.status, 400);
  const r2 = await revokeForm(tok.data.access_token, "access_token");
  assert.equal(r2.status, 200);
  const me = await call(env, "GET", "/oauth/userinfo", {
    headers: { authorization: `Bearer ${tok.data.access_token}` },
  });
  assert.equal(me.status, 401);
});
