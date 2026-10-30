// POST /oauth/device-authorization — creates a device code + user code
// in the Durable Object store (TTL 30 minutes, status pending). The
// device polls /oauth/token until the request is approved via
// /oauth/approval with a Muse-signed payload referencing the device code.
//
// The Durable Object store is keyed by device code and has no scan, so
// a KV index maps the human user code to the device code
// (device_user_code:<CODE> -> device_code, same 30-minute TTL). The index
// is data, never a consumable record — the device record itself stays
// the single source of truth for status. If the index write fails, the
// device record is revoked and the request fails closed: a device code
// whose user code no human can enter is a broken flow, not a live one.
// The verification URI is the human page GET /device.

import { randomString, randomUserCode } from "../lib/crypto.js";
import { getClient } from "../lib/registry.js";
import { isValidClientId, parseScope } from "../lib/validate.js";
import { recordStub } from "../store/oauth-record.js";
import { json, parseFormOrJson } from "../lib/http.js";

export async function deviceAuthorizationHandler(request, env) {
  const body = await parseFormOrJson(request);
  if (!body) return json({ error: "invalid_request" }, 400);
  const clientId = body.client_id;
  if (!isValidClientId(clientId)) return json({ error: "invalid_client" }, 400);
  const client = await getClient(env, clientId);
  if (!client) return json({ error: "invalid_client" }, 400);
  const scope = parseScope(body.scope);
  if (!scope) return json({ error: "invalid_scope" }, 400);
  // Per-client scope restriction, when the client record restricts scopes.
  if (client.allowed_scopes && !scope.every((s) => client.allowed_scopes.includes(s))) {
    return json({ error: "invalid_scope" }, 400);
  }

  const deviceCode = randomString(32);
  const userCode = randomUserCode();
  const stub = recordStub(env, `device:${deviceCode}`);
  await stub.create(
    {
      kind: "device",
      device_code: deviceCode,
      user_code: userCode,
      client_id: clientId,
      scope,
      status: "pending",
    },
    1_800_000,
  );
  // Index the user code so POST /device can resolve it. Fail closed on
  // index failure: revoke the device record rather than hand out a code
  // no human can enter.
  try {
    await env.OAUTH_KV.put(`device_user_code:${userCode}`, deviceCode, { expirationTtl: 1800 });
  } catch {
    await stub.revoke();
    return json({ error: "server_error" }, 500);
  }
  return json({
    device_code: deviceCode,
    user_code: userCode,
    verification_uri: env.ISSUER ? `${env.ISSUER.replace(/\/$/, "")}/device` : "/device",
    expires_in: 1800,
    interval: 5,
  });
}
