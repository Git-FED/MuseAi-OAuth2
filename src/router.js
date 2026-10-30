// Route table. Fail-closed dispatch: unknown path 404, wrong method 405,
// unhandled handler error 500. The manual kill switch (KILL_SWITCH=1)
// stops every OAuth route but leaves /health answering, so liveness
// checks still work while logins are paused.

import { json } from "./lib/http.js";
import { authorizeHandler } from "./oauth/authorize.js";
import { tokenHandler } from "./oauth/token.js";
import { userinfoHandler } from "./oauth/userinfo.js";
import { approvalHandler } from "./oauth/approval.js";
import { deviceAuthorizationHandler } from "./oauth/device-authorization.js";
import { revocationHandler } from "./oauth/revocation.js";
import { discoveryHandler } from "./oauth/discovery.js";
import { jwksHandler } from "./oauth/jwks.js";

const ROUTES = [
  {
    method: "GET",
    path: "/health",
    handler: async () => json({ ok: true, service: "museai-oauth" }),
  },
  { method: "GET", path: "/.well-known/openid-configuration", handler: discoveryHandler },
  { method: "GET", path: "/jwks", handler: jwksHandler },
  { method: "GET", path: "/oauth/authorize", handler: authorizeHandler },
  { method: "POST", path: "/oauth/token", handler: tokenHandler },
  { method: "GET", path: "/oauth/userinfo", handler: userinfoHandler },
  { method: "POST", path: "/oauth/approval", handler: approvalHandler },
  { method: "POST", path: "/oauth/device-authorization", handler: deviceAuthorizationHandler },
  { method: "POST", path: "/oauth/revoke", handler: revocationHandler },
];

export async function route(request, env) {
  const path = new URL(request.url).pathname;
  const match = ROUTES.find((r) => r.path === path);
  if (!match) return json({ error: "not_found" }, 404);
  if (request.method !== match.method) return json({ error: "method_not_allowed" }, 405);
  if (path !== "/health" && env.KILL_SWITCH === "1") {
    return json({ error: "temporarily_unavailable" }, 503);
  }
  try {
    return await match.handler(request, env);
  } catch {
    return json({ error: "server_error" }, 500);
  }
}
