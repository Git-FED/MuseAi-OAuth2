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
import { loginPageHandler } from "./oauth/login-page.js";
import { authorizeHandler } from "./oauth/authorize.js";
import { tokenHandler } from "./oauth/token.js";
import { userinfoHandler } from "./oauth/userinfo.js";
import { approvalHandler } from "./oauth/approval.js";
import { pendingStatusHandler } from "./oauth/pending-status.js";
import { denyHandler } from "./oauth/deny.js";
import { deviceGetHandler, devicePostHandler } from "./oauth/device-entry.js";
import { deviceAuthorizationHandler } from "./oauth/device-authorization.js";
import { revocationHandler } from "./oauth/revocation.js";
import { discoveryHandler } from "./oauth/discovery.js";
import { jwksHandler } from "./oauth/jwks.js";

// Step 11: browser CORS for the two public-client endpoints that a
// third-party site calls from its own pages (e.g. the FED Hub login).
// The login page itself is same-origin and never needed this; a site
// like hub.fedos.workers.dev cannot read /oauth/token or /oauth/userinfo
// responses without it. Narrow on purpose: admin, approval, and device
// routes get no CORS headers and still 405 OPTIONS. No credentials mode:
// the hub keeps tokens in sessionStorage, never cookies, so reflecting
// the Origin here cannot leak a session to another site.
const CORS_PATHS = new Set(["/oauth/token", "/oauth/userinfo"]);

function corsHeaders(request) {
  const origin = request.headers.get("origin");
  return {
    "access-control-allow-origin": origin || "*",
    "access-control-allow-methods": "GET, POST, OPTIONS",
    "access-control-allow-headers": "Content-Type, Authorization",
    vary: "Origin",
  };
}

function withCors(response, request) {
  const headers = new Headers(response.headers);
  for (const [k, v] of Object.entries(corsHeaders(request))) headers.set(k, v);
  return new Response(response.body, { status: response.status, headers });
}

const ROUTES = [
  {
    method: "GET",
    path: "/health",
    handler: async () => json({ ok: true, service: "museai-oauth" }),
  },
  // Step 10: the mount root serves the embeddable Sign in with Muse
  // page. Bare /login used to 404 by design (nothing lived at the mount
  // point); now it is the login surface itself.
  { method: "GET", path: "/", handler: loginPageHandler },
  { method: "GET", path: "/.well-known/openid-configuration", handler: discoveryHandler },
  { method: "GET", path: "/jwks", handler: jwksHandler },
  { method: "GET", path: "/oauth/authorize", handler: authorizeHandler },
  { method: "POST", path: "/oauth/token", handler: tokenHandler },
  { method: "GET", path: "/oauth/userinfo", handler: userinfoHandler },
  { method: "POST", path: "/oauth/approval", handler: approvalHandler },
  // Step 13: auto-finish poll for the approval page.
  { method: "GET", path: "/oauth/pending-status", handler: pendingStatusHandler },
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
  // Step 11: CORS preflight for the browser-called endpoints. This is
  // not an OAuth action, so it answers before route matching, the kill
  // switch, and rate limiting; the real call is still gated by all of
  // those. Other paths keep their existing 404/405 behavior.
  if (request.method === "OPTIONS" && CORS_PATHS.has(path)) {
    return new Response(null, { status: 204, headers: corsHeaders(request) });
  }
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
  // STEP 7: both 503 paths log loudly (a silent 503 hid the production
  // outage's cause on 2026-10-30 — the next tail must show which branch
  // fired). Degraded allows are audited so a broken limiter leaves a
  // trail in KV even while requests proceed.
  if (RATE_LIMITS[path]) {
    try {
      const limit = await checkRateLimit(request, env, path);
      if (limit.unavailable) {
        console.error(`rate-limit unavailable for ${path}: RATE_LIMIT binding missing`);
        return json({ error: "temporarily_unavailable" }, 503);
      }
      if (limit.degraded) {
        await audit(env, "rate_limit_degraded", { clientId: limit.clientId ?? null, route: path, outcome: "degraded_allow", detail: "storage error, throttling degraded" });
      }
      if (!limit.allowed) {
        await audit(env, "rate_limited", { clientId: limit.clientId, route: path, outcome: "blocked", detail: `bucket:${limit.bucket}` });
        return json({ error: "rate_limited" }, 429, { "retry-after": String(limit.retryAfter) });
      }
    } catch (e) {
      console.error(`rate-limit error for ${path}: ${String(e && e.message ? e.message : e).slice(0, 200)}`);
      return json({ error: "temporarily_unavailable" }, 503);
    }
  }
  try {
    const res = await match.handler(request, env);
    return CORS_PATHS.has(path) ? withCors(res, request) : res;
  } catch {
    return json({ error: "server_error" }, 500);
  }
}
