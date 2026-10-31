// Step 11 tests: browser CORS on the two public-client endpoints that a
// third-party site (e.g. FED Hub) calls from its own pages.
import test from "node:test";
import assert from "node:assert/strict";
import worker from "../worker.js";

function env() {
  return {
    BASE_PATH: "/login",
    OAUTH_KV: { put: async () => {}, get: async () => null, delete: async () => {} },
    OAUTH_STORE: {},
    RATE_LIMIT: {},
    ISSUER: "https://www.fedpromptly.com/login",
  };
}

async function req(envObj, url, opts = {}) {
  const res = await worker.fetch(new Request(url, opts), envObj);
  return { status: res.status, text: await res.text(), headers: res.headers };
}

const ORIGIN = "https://hub.fedos.workers.dev";

test("OPTIONS preflight to /oauth/token answers 204 with CORS headers", async () => {
  const r = await req(env(), "https://www.fedpromptly.com/login/oauth/token", {
    method: "OPTIONS",
    headers: { Origin: ORIGIN, "Access-Control-Request-Method": "POST" },
  });
  assert.equal(r.status, 204);
  assert.equal(r.headers.get("access-control-allow-origin"), ORIGIN);
  assert.match(r.headers.get("access-control-allow-methods"), /POST/);
  assert.match(r.headers.get("access-control-allow-headers"), /Authorization/);
});

test("OPTIONS preflight to /oauth/userinfo answers 204 with CORS headers", async () => {
  const r = await req(env(), "https://www.fedpromptly.com/login/oauth/userinfo", {
    method: "OPTIONS",
    headers: { Origin: ORIGIN, "Access-Control-Request-Method": "GET" },
  });
  assert.equal(r.status, 204);
  assert.equal(r.headers.get("access-control-allow-origin"), ORIGIN);
});

test("OPTIONS to a non-CORS route stays 405 with no CORS headers", async () => {
  const r = await req(env(), "https://www.fedpromptly.com/login/admin/clients", {
    method: "OPTIONS",
    headers: { Origin: ORIGIN },
  });
  assert.equal(r.status, 405);
  assert.equal(r.headers.get("access-control-allow-origin"), null);
});

test("POST /oauth/token error responses carry the CORS headers", async () => {
  const r = await req(env(), "https://www.fedpromptly.com/login/oauth/token", {
    method: "POST",
    headers: { Origin: ORIGIN, "Content-Type": "application/x-www-form-urlencoded" },
    body: "grant_type=authorization_code",
  });
  assert.equal(r.status, 400);
  assert.equal(r.headers.get("access-control-allow-origin"), ORIGIN);
});

test("GET /oauth/userinfo without a token is 401 with CORS headers", async () => {
  const r = await req(env(), "https://www.fedpromptly.com/login/oauth/userinfo", {
    headers: { Origin: ORIGIN },
  });
  assert.equal(r.status, 401);
  assert.equal(r.headers.get("access-control-allow-origin"), ORIGIN);
});
