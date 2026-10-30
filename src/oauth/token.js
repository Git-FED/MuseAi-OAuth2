// POST /oauth/token — three grants, all against the Durable Object store:
//   authorization_code: consumes the code exactly once, verifies PKCE S256.
//   refresh_token: rotates (new pair issued, old refresh record revoked).
//   device_code: pending -> authorization_pending; approved -> tokens.
// Public clients only in this step (no client_secret); the client_id must
// be registered and must match the record being redeemed.

import { verifyPkce } from "../lib/crypto.js";
import { audit } from "../lib/audit.js";
import { getClient } from "../lib/registry.js";
import { isValidClientId } from "../lib/validate.js";
import { recordStub } from "../store/oauth-record.js";
import { issueTokenPair, requireTokenConfig, rotateRefresh } from "../auth/tokens.js";
import { json, parseFormOrJson } from "../lib/http.js";

export async function tokenHandler(request, env) {
  const body = await parseFormOrJson(request);
  if (!body) return json({ error: "invalid_request" }, 400);
  const clientId = body.client_id;
  if (!isValidClientId(clientId)) return json({ error: "invalid_client" }, 400);
  const client = await getClient(env, clientId);
  if (!client) return json({ error: "invalid_client" }, 400);
  if (!requireTokenConfig(env)) return json({ error: "temporarily_unavailable" }, 503);

  const grant = body.grant_type;
  if (grant === "authorization_code") {
    const { code, redirect_uri, code_verifier } = body;
    if (!code || !redirect_uri || !code_verifier) return json({ error: "invalid_request" }, 400);
    // consume() is atomic: a second redemption of the same code sees null.
    const rec = await recordStub(env, `auth_code:${code}`).consume();
    if (!rec) return json({ error: "invalid_grant" }, 400);
    if (rec.client_id !== clientId || rec.redirect_uri !== redirect_uri) {
      return json({ error: "invalid_grant" }, 400);
    }
    if (!(await verifyPkce(code_verifier, rec.code_challenge))) {
      return json({ error: "invalid_grant" }, 400);
    }
    const pair = await issueTokenPair(env, {
      sub: `muse:${rec.muse_id}`,
      username: rec.username,
      email: rec.email,
      clientId,
      scope: rec.scope,
      nonce: rec.nonce,
    });
    await audit(env, "token_issued", { actor: `muse:${rec.muse_id}`, clientId, route: "/oauth/token", outcome: "success", detail: "authorization_code" });
    return json(pair);
  }

  if (grant === "refresh_token") {
    const old = body.refresh_token;
    if (!old) return json({ error: "invalid_request" }, 400);
    const existing = await recordStub(env, `refresh:${old}`).read();
    if (!existing || existing.client_id !== clientId) return json({ error: "invalid_grant" }, 400);
    const pair = await rotateRefresh(env, old);
    if (!pair) return json({ error: "invalid_grant" }, 400);
    await audit(env, "token_issued", { actor: existing.sub, clientId, route: "/oauth/token", outcome: "success", detail: "refresh_token" });
    return json(pair);
  }

  if (grant === "urn:ietf:params:oauth:grant-type:device_code") {
    const deviceCode = body.device_code;
    if (!deviceCode) return json({ error: "invalid_request" }, 400);
    const stub = recordStub(env, `device:${deviceCode}`);
    const rec = await stub.read();
    if (!rec) return json({ error: "invalid_grant" }, 400);
    if (rec.client_id !== clientId) return json({ error: "invalid_grant" }, 400);
    if (rec.status === "pending") return json({ error: "authorization_pending" }, 400);
    if (rec.status === "denied") {
      // Terminal: the user denied this device. The denial was audited at
      // deny time; the poll surfacing it is audited too, so a denied
      // device leaves a complete trail.
      await audit(env, "token_denied", { actor: null, clientId, route: "/oauth/token", outcome: "denied", detail: "device_code" });
      return json({ error: "access_denied" }, 400);
    }
    if (rec.status !== "approved") return json({ error: "invalid_grant" }, 400);
    await stub.consume();
    const devicePair = await issueTokenPair(env, {
      sub: `muse:${rec.muse_id}`,
      username: rec.username,
      email: rec.email,
      clientId,
      scope: rec.scope,
      nonce: null,
    });
    await audit(env, "token_issued", { actor: `muse:${rec.muse_id}`, clientId, route: "/oauth/token", outcome: "success", detail: "device_code" });
    return json(devicePair);
  }

  return json({ error: "unsupported_grant_type" }, 400);
}
