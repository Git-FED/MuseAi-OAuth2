import test from "node:test";
import assert from "node:assert/strict";
import worker from "../worker.js";
import { OAuthRecord } from "../src/store/oauth-record.js";
import { RateLimitBucket } from "../src/store/rate-limit.js";
import { pkceChallenge } from "../src/lib/crypto.js";

function fakeStorage() { const m = new Map(); return { async get(k) { return m.get(k) ?? null; }, async put(k, v) { m.set(k, v); }, async delete(k) { m.delete(k); }, async setAlarm() {} }; }
function fakeStore() { const instances = new Map(); return { idFromName: (k) => k, get: (id) => { if (!instances.has(id)) instances.set(id, new OAuthRecord({ storage: fakeStorage() })); return instances.get(id); } }; }
function fakeRateLimit() { const instances = new Map(); return { idFromName: (k) => k, get: (id) => { if (!instances.has(id)) instances.set(id, new RateLimitBucket({ storage: fakeStorage() })); return instances.get(id); } }; }
function fakeKV() { const m = new Map(); return { async get(k) { return m.get(k) ?? null; }, async put(k, v) { m.set(k, typeof v === "string" ? v : JSON.stringify(v)); }, async delete(k) { m.delete(k); } }; }
async function makeEnv() {
  const kv = fakeKV();
  const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const signing = await crypto.subtle.exportKey("jwk", kp.privateKey);
  const pub = await crypto.subtle.exportKey("jwk", kp.publicKey);
  const env = { OAUTH_STORE: fakeStore(), OAUTH_KV: kv, RATE_LIMIT: fakeRateLimit(), ISSUER: "https://login.example.com", SIGNING_KEY_JWK: JSON.stringify(signing), SIGNING_PUBLIC_JWK: JSON.stringify(pub) };
  await kv.put("client:fedpromptly", JSON.stringify({ client_id: "fedpromptly", name: "FedPromptly", redirect_uris: ["https://www.fedpromptly.com/callback"] }));
  return env;
}
async function registerMuse(env, museId = "muse-test") {
  const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const pub = await crypto.subtle.exportKey("jwk", kp.publicKey);
  await env.OAUTH_KV.put(`muse_key:${museId}`, JSON.stringify({ muse_id: museId, public_key_jwk: pub }));
  return kp.privateKey;
}
function toB64(bytes) { let b = ""; for (const x of bytes) b += String.fromCharCode(x); return btoa(b).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, ""); }
async function signApproval(pk, kind, id, museId, username, email) {
  const msg = `muse-approval-v1\n${kind}:${id}\n${museId}\n${username}\n${email}`;
  const sig = await crypto.subtle.sign("Ed25519", pk, new TextEncoder().encode(msg));
  return toB64(new Uint8Array(sig));
}
async function call(env, method, path, { body, contentType, headers = {} } = {}) {
  const res = await worker.fetch(new Request(`https://login.example.com${path}`, { method, headers: { ...(contentType ? { "content-type": contentType } : {}), ...headers }, body }), env);
  const text = await res.text(); let data = null; try { data = JSON.parse(text); } catch {}
  return { status: res.status, text, data };
}
const REDIRECT = "https://www.fedpromptly.com/callback";
const VERIFIER = "verifier-1234567890-abcdefghijklmnopqrstuvwxyz";
async function startFlow(env) {
  const challenge = await pkceChallenge(VERIFIER);
  const auth = await call(env, "GET", `/oauth/authorize?client_id=fedpromptly&redirect_uri=${encodeURIComponent(REDIRECT)}&response_type=code&code_challenge=${challenge}&code_challenge_method=S256&scope=${encodeURIComponent("openid profile email offline_access")}&state=xyz`);
  assert.equal(auth.status, 200, auth.text);
  return /id="pending-id">([^<]+)/.exec(auth.text)[1];
}
async function signInOnce(env, museKey) {
  const pending = await startFlow(env);
  const sig = await signApproval(museKey, "pending", pending, "muse-test", "git-fed", "user@example.com");
  const appr = await call(env, "POST", "/oauth/approval", { body: JSON.stringify({ pending_id: pending, muse_id: "muse-test", username: "git-fed", email: "user@example.com", signature: sig }), contentType: "application/json" });
  assert.equal(appr.status, 200, appr.text);
  const code = new URL(appr.data.redirect_to).searchParams.get("code");
  const tok = await call(env, "POST", "/oauth/token", { body: new URLSearchParams({ grant_type: "authorization_code", client_id: "fedpromptly", code, redirect_uri: REDIRECT, code_verifier: VERIFIER }).toString(), contentType: "application/x-www-form-urlencoded" });
  assert.equal(tok.status, 200, tok.text);
  return tok.data;
}

test("step24: two-step defaults off, toggle requires a token, toggle on/off works", async () => {
  const env = await makeEnv(); const museKey = await registerMuse(env);
  const tok = await signInOnce(env, museKey);
  const noAuth = await call(env, "GET", "/oauth/two-step");
  assert.equal(noAuth.status, 401);
  const off = await call(env, "GET", "/oauth/two-step", { headers: { authorization: `Bearer ${tok.access_token}` } });
  assert.equal(off.data.enabled, false);
  const on = await call(env, "POST", "/oauth/two-step", { body: JSON.stringify({ enabled: true }), contentType: "application/json", headers: { authorization: `Bearer ${tok.access_token}` } });
  assert.equal(on.data.enabled, true);
  const check = await call(env, "GET", "/oauth/two-step", { headers: { authorization: `Bearer ${tok.access_token}` } });
  assert.equal(check.data.enabled, true);
});

test("step24: two-step on requires a second Muse signature before any code", async () => {
  const env = await makeEnv(); const museKey = await registerMuse(env);
  const tok = await signInOnce(env, museKey);
  await call(env, "POST", "/oauth/two-step", { body: JSON.stringify({ enabled: true }), contentType: "application/json", headers: { authorization: `Bearer ${tok.access_token}` } });
  const pending = await startFlow(env);
  const sig1 = await signApproval(museKey, "pending", pending, "muse-test", "git-fed", "user@example.com");
  const first = await call(env, "POST", "/oauth/approval", { body: JSON.stringify({ pending_id: pending, muse_id: "muse-test", username: "git-fed", email: "user@example.com", signature: sig1 }), contentType: "application/json" });
  assert.equal(first.status, 200, first.text);
  assert.equal(first.data.second_approval_required, true);
  assert.ok(first.data.second_pending_id);
  const status = await call(env, "GET", `/oauth/pending-status?pending_id=${pending}`);
  assert.equal(status.data.status, "second_approval_required");
  assert.equal(status.data.second_pending_id, first.data.second_pending_id);
  const sig2 = await signApproval(museKey, "pending", first.data.second_pending_id, "muse-test", "git-fed", "user@example.com");
  const second = await call(env, "POST", "/oauth/approval", { body: JSON.stringify({ pending_id: first.data.second_pending_id, muse_id: "muse-test", username: "git-fed", email: "user@example.com", signature: sig2 }), contentType: "application/json" });
  assert.equal(second.status, 200, second.text);
  assert.equal(second.data.approved, true);
  const code = new URL(second.data.redirect_to).searchParams.get("code");
  const tok2 = await call(env, "POST", "/oauth/token", { body: new URLSearchParams({ grant_type: "authorization_code", client_id: "fedpromptly", code, redirect_uri: REDIRECT, code_verifier: VERIFIER }).toString(), contentType: "application/x-www-form-urlencoded" });
  assert.equal(tok2.status, 200, tok2.text);
});
