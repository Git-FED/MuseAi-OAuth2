// GET /jwks — publishes the ES256 public key for token verification.
// Fails closed (503) until SIGNING_PUBLIC_JWK is configured.

import { json } from "../lib/http.js";

export async function jwksHandler(request, env) {
  if (!env.SIGNING_PUBLIC_JWK) return json({ error: "not_configured" }, 503);
  let pub;
  try {
    pub = JSON.parse(env.SIGNING_PUBLIC_JWK);
  } catch {
    return json({ error: "server_error" }, 500);
  }
  return json(
    { keys: [{ ...pub, kid: "v1", alg: "ES256", use: "sig" }] },
    200,
    { "cache-control": "public, max-age=3600" },
  );
}
