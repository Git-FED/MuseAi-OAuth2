// Route table. Fail-closed dispatch: unknown path 404, wrong method 405,
// unhandled handler error 500. The manual kill switch (KILL_SWITCH=1)
// stops every OAuth route but leaves /health answering, so liveness
// checks still work while logins are paused. Rate-limited routes answer
// 429 (audited) when their bucket is exhausted, and 503 when the
// RATE_LIMIT binding is missing — limits never silently disappear.

import { json } from "./lib/http.js";
import { normalizeBasePath, stripBasePath } from "./lib/mount.js";
import { audit } from "./lib/audit.js";
import { RATE_LIMITS, checkRateLimit } from "./auth/rate-limit.js";
import { registerClientHandler, registerMuseKeyHandler } from "./admin/register.js";
import { authorizeHandler } from "./oauth/authorize.js";
import { tokenHandler } from "./oauth/token.js";
import { userinfoHandler } from "./oauth/userinfo.js";
import { approvalHandler } from "./oauth/approval.js";
import { denyHandler } from "./oauth/deny.js";
import { deviceGetHandler, devicePostHandler } from "./oauth/device-entry.js";
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
  { method: "POST", path: "/oauth/deny", handler: denyHandler },
  { method: "GET", path: "/device", handler: deviceGetHandler },
  { method: "POST", path: "/device", handler: devicePostHandler },
  { method: "POST", path: "/oauth/device-authorization", handler: deviceAuthorizationHandler },
  { method: "POST", path: "/oauth/revoke", handler: revocationHandler },
  { method: "POST", path: "/admin/clients", handler: registerClientHandler },
  { method: "POST", path: "/admin/muse-keys", handler: registerMuseKeyHandler },
];

export async function route(request, env) {
  // Mount prefix (step 5): strip BASE_PATH before matching. A request
  // that does not start with the configured prefix is not a provider
  // request at all — 404, never a provider route at the wrong mount.
  // From here on, `path` is always the STRIPPED path, so route
  // matching, rate-limit buckets, and audit route values are identical
  // under either mount.
  const basePath = normalizeBasePath(env.BASE_PATH);
  const rawPath = new URL(request.url).pathname;
  const { matched, stripped } = stripBasePath(rawPath, basePath);
  if (!matched) return json({ error: "not_found" }, 404);
  const path = stripped;
  // Match on path AND method: /device serves both GET and POST, and
  // matching on path alone would 405 the second method on a shared path.
  const match = ROUTES.find((r) => r.path === path && r.method === request.method);
  if (!match) {
    return ROUTES.some((r) => r.path === path)
      ? json({ error: "method_not_allowed" }, 405)
      : json({ error: "not_found" }, 404);
  }
  if (path !== "/health" && env.KILL_SWITCH === "1") {
    return json({ error: "temporarily_unavailable" }, 503);
  }
  // Rate limits run before the handler (and before admin auth, so token
  // guessing is throttled too). A missing RATE_LIMIT binding fails closed.
  if (RATE_LIMITS[path]) {
    try {
      const limit = await checkRateLimit(request, env, path);
      if (limit.unavailable) return json({ error: "temporarily_unavailable" }, 503);
      if (!limit.allowed) {
        await audit(env, "rate_limited", { clientId: limit.clientId, route: path, outcome: "blocked", detail: `bucket:${limit.bucket}` });
        return json({ error: "rate_limited" }, 429, { "retry-after": String(limit.retryAfter) });
      }
    } catch {
      return json({ error: "temporarily_unavailable" }, 503);
    }
  }
  try {
    return await match.handler(request, env);
  } catch {
    return json({ error: "server_error" }, 500);
  }
}
