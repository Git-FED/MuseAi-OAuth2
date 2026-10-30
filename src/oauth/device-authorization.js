// POST /oauth/device-authorization — creates a device code + user code
// in the Durable Object store (TTL 30 minutes, status pending). The
// device polls /oauth/token until the request is approved via
// /oauth/approval with a Muse-signed payload referencing the device code.
// Note: a human-facing user-code entry page is not built in this step;
// approval currently references the device code directly.

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
  await recordStub(env, `device:${deviceCode}`).create(
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
  return json({
    device_code: deviceCode,
    user_code: userCode,
    verification_uri: env.ISSUER ? `${env.ISSUER.replace(/\/$/, "")}/oauth/approval` : "/oauth/approval",
    expires_in: 1800,
    interval: 5,
  });
}
