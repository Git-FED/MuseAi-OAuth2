// Step 7 tests: rate-limit hardening (production 503 outage, 2026-10-30).
// A storage/transient error must degrade (allow + audit + warn), never
// take the whole provider down with a silent 503. A missing binding
// still fails closed. Normal allow/block behavior is unchanged
// (covered by step3 tests); these tests cover the new branches only.
import test from "node:test";
import assert from "node:assert/strict";
import worker from "../worker.js";
import { OAuthRecord } from "../src/store/oauth-record.js";
import { RateLimitBucket } from "../src/store/rate-limit.js";

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

function throwingNamespace() {
  return {
    idFromName: (k) => k,
    get: () => ({ async hit() { throw new Error("store exploded"); } }),
  };
}

function malformedNamespace() {
  return {
    idFromName: (k) => k,
    get: () => ({ async hit() { return { remaining: 5 }; } }),
  };
}

async function makeEnv({ rateLimit = "working" } = {}) {
  const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const signing = await crypto.subtle.exportKey("jwk", kp.privateKey);
  const pub = await crypto.subtle.exportKey("jwk", kp.publicKey);
  const env = {
    OAUTH_STORE: fakeNamespace(OAuthRecord),
    OAUTH_KV: fakeKV(),
    ISSUER: "https://login.example.com",
    SIGNING_KEY_JWK: JSON.stringify(signing),
    SIGNING_PUBLIC_JWK: JSON.stringify(pub),
  };
  if (rateLimit === "working") env.RATE_LIMIT = fakeNamespace(RateLimitBucket);
  else if (rateLimit === "throwing") env.RATE_LIMIT = throwingNamespace();
  else if (rateLimit === "malformed") env.RATE_LIMIT = malformedNamespace();
  // rateLimit === "missing" leaves RATE_LIMIT unset: fail closed.
  return env;
}

async function call(env, method, path) {
  const res = await worker.fetch(
    new Request(`https://login.example.com${path}`, { method }),
    env,
  );
  const text = await res.text();
  let data = null;
  try { data = JSON.parse(text); } catch { /* HTML */ }
  return { status: res.status, text, data };
}

async function auditEntries(env) {
  const keys = await env.OAUTH_KV.list("audit:");
  const out = [];
  for (const k of keys) out.push(JSON.parse(await env.OAUTH_KV.get(k)));
  return out;
}

test("rate-limit store throw degrades to allow (not 503) and is audited", async () => {
  const env = await makeEnv({ rateLimit: "throwing" });
  const res = await call(env, "GET", "/device");
  assert.equal(res.status, 200, res.text);
  const audits = await auditEntries(env);
  assert.ok(audits.some((a) => a.event === "rate_limit_degraded"),
    `degraded allow must be audited (have: ${audits.map((a) => a.event).join(", ")})`);
});

test("malformed rate-limit result degrades to allow (not 503)", async () => {
  const env = await makeEnv({ rateLimit: "malformed" });
  const res = await call(env, "GET", "/device");
  assert.equal(res.status, 200, res.text);
});

test("missing RATE_LIMIT binding still fails closed with 503", async () => {
  const env = await makeEnv({ rateLimit: "missing" });
  const res = await call(env, "GET", "/device");
  assert.equal(res.status, 503, res.text);
  assert.equal(res.data.error, "temporarily_unavailable");
});

test("working rate limiter still serves the device page", async () => {
  const env = await makeEnv({ rateLimit: "working" });
  const res = await call(env, "GET", "/device");
  assert.equal(res.status, 200, res.text);
});
