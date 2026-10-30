import test from "node:test";
import assert from "node:assert/strict";
import worker from "../worker.js";

// The worker is live now, but it still fails closed: /health answers,
// unknown routes 404, and unconfigured OAuth routes refuse to serve.
test("live worker: health ok, unknown route 404, unconfigured discovery 503", async () => {
  const health = await worker.fetch(new Request("https://example.invalid/health"), {});
  assert.equal(health.status, 200);
  assert.equal((await health.json()).ok, true);

  const missing = await worker.fetch(new Request("https://example.invalid/nope"), {});
  assert.equal(missing.status, 404);

  const discovery = await worker.fetch(
    new Request("https://example.invalid/.well-known/openid-configuration"),
    {},
  );
  assert.equal(discovery.status, 503);
  assert.equal((await discovery.json()).error, "not_configured");

  const authorize = await worker.fetch(
    new Request("https://example.invalid/oauth/authorize?client_id=x&redirect_uri=https://example.invalid/cb&response_type=code&code_challenge=c&code_challenge_method=S256"),
    {},
  );
  // No OAUTH_KV in this env at all: the handler throws, the router
  // answers 500 rather than serving anything permissive.
  assert.equal(authorize.status, 500);
});
