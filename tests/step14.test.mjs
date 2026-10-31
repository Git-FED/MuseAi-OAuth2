// Step 14 — speed-up popup: the approval page opens Muse AI in a
// popup and copies a one-line approval message, so the user does not
// have to switch apps or retype an id. The poller still finishes it.
import test from "node:test";
import assert from "node:assert/strict";
import worker from "../worker.js";
import { OAuthRecord } from "../src/store/oauth-record.js";
import { RateLimitBucket } from "../src/store/rate-limit.js";
import { pkceChallenge } from "../src/lib/crypto.js";

function fakeStorage() {
  const m = new Map();
  return { async get(k) { return m.get(k) ?? null; }, async put(k, v) { m.set(k, v); }, async delete(k) { m.delete(k); }, async setAlarm() {} };
}
function fakeStore() {
  const instances = new Map();
  return { idFromName: (k) => k, get: (id) => {
    if (!instances.has(id)) instances.set(id, new OAuthRecord({ storage: fakeStorage() }));
    return instances.get(id);
  } };
}
function fakeRateLimit() {
  const instances = new Map();
  return { idFromName: (k) => k, get: (id) => {
    if (!instances.has(id)) instances.set(id, new RateLimitBucket({ storage: fakeStorage() }));
    return instances.get(id);
  } };
}
function fakeKV() {
  const m = new Map();
  return { async get(k) { return m.get(k) ?? null; }, async put(k, v) { m.set(k, typeof v === "string" ? v : JSON.stringify(v)); }, async delete(k) { m.delete(k); } };
}
async function makeEnv() {
  const kv = fakeKV();
  const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const signing = await crypto.subtle.exportKey("jwk", kp.privateKey);
  const pub = await crypto.subtle.exportKey("jwk", kp.publicKey);
  const env = { OAUTH_STORE: fakeStore(), OAUTH_KV: kv, RATE_LIMIT: fakeRateLimit(), ISSUER: "https://login.example.com", SIGNING_KEY_JWK: JSON.stringify(signing), SIGNING_PUBLIC_JWK: JSON.stringify(pub) };
  await kv.put("client:fedpromptly", JSON.stringify({ client_id: "fedpromptly", name: "FedPromptly", redirect_uris: ["https://www.fedpromptly.com/callback"] }));
  return env;
}
async function call(env, method, path, { body, contentType } = {}) {
  const res = await worker.fetch(new Request(`https://login.example.com${path}`, { method, headers: contentType ? { "content-type": contentType } : {}, body }), env);
  const text = await res.text();
  let data = null;
  try { data = JSON.parse(text); } catch { /* HTML */ }
  return { status: res.status, text, data };
}
const REDIRECT = "https://www.fedpromptly.com/callback";
const VERIFIER = "verifier-1234567890-abcdefghijklmnopqrstuvwxyz";

test("authorize page: popup button + copy message, no paste form", async () => {
  const env = await makeEnv();
  const challenge = await pkceChallenge(VERIFIER);
  const auth = await call(env, "GET", `/oauth/authorize?client_id=fedpromptly&redirect_uri=${encodeURIComponent(REDIRECT)}&response_type=code&code_challenge=${challenge}&code_challenge_method=S256&scope=openid`);
  assert.equal(auth.status, 200);
  const pending = /id="pending-id">([^<]+)/.exec(auth.text)[1];
  assert.ok(pending);
  // Popup opens only on click (popup blockers allow click-opened windows).
  assert.match(auth.text, /id="open-muse-btn"/);
  assert.match(auth.text, /addEventListener\("click", function \(\) \{\s*window\.open\("https:\/\/muse\.ai"/);
  // Copy message carries the exact pending id, one line to paste.
  assert.match(auth.text, /id="copy-btn"/);
  assert.ok(auth.text.includes(`Please approve my Muse sign-in. Pending request: ${pending}`));
  assert.doesNotMatch(auth.text, /<textarea/);
  // Poller still present: popup approval still finishes this page.
  assert.match(auth.text, /oauth\/pending-status\?pending_id=/);
});

test("device page: popup + copy message carries the device code", async () => {
  const env = await makeEnv();
  const dev = await call(env, "POST", "/oauth/device-authorization", { body: new URLSearchParams({ client_id: "fedpromptly", scope: "openid offline_access" }).toString(), contentType: "application/x-www-form-urlencoded" });
  assert.equal(dev.status, 200, dev.text);
  const page = await call(env, "POST", "/device", { body: new URLSearchParams({ user_code: dev.data.user_code }).toString(), contentType: "application/x-www-form-urlencoded" });
  assert.equal(page.status, 200, page.text);
  assert.match(page.text, /id="open-muse-btn"/);
  assert.ok(page.text.includes(`Please approve my Muse device sign-in. Device code: ${dev.data.device_code}`));
  assert.doesNotMatch(page.text, /<textarea/);
});
