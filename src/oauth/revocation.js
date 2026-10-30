// POST /oauth/revoke (RFC 7009) — revokes refresh tokens via the store
// and access tokens via a KV denylist keyed by jti. Access tokens are
// JWTs, so revocation is a denylist check at verify time, not deletion.
// Per RFC 7009, unknown tokens still return 200 (no existence leak);
// a missing token parameter is the only 400.

import { decodeJwtPayload } from "../lib/crypto.js";
import { audit } from "../lib/audit.js";
import { recordStub } from "../store/oauth-record.js";
import { json, parseFormOrJson } from "../lib/http.js";

export async function revocationHandler(request, env) {
  const body = await parseFormOrJson(request);
  if (!body || !body.token) return json({ error: "invalid_request" }, 400);
  const hint = body.token_type_hint;
  if (!hint || hint === "refresh_token") {
    await recordStub(env, `refresh:${body.token}`).revoke();
  }
  if ((!hint || hint === "access_token") && env.OAUTH_KV) {
    const payload = decodeJwtPayload(body.token);
    if (payload?.jti) {
      await env.OAUTH_KV.put(`revoked_access:${payload.jti}`, "1");
    }
  }
  await audit(env, "token_revoked", { route: "/oauth/revoke", outcome: "success", detail: hint || "token" });
  return new Response(null, { status: 200, headers: { "cache-control": "no-store" } });
}
