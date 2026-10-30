// Rate-limit enforcement for the router. Buckets are keyed per route:
//   - one bucket per client IP (always checked — every route has an IP),
//   - one bucket per client_id (only where the request identifies one),
//   - one bucket per pending/device id on /oauth/approval (signature
//     guessing against a single request must be slow).
//
// Limits are fixed windows of 60 seconds unless stated. The router audits
// every block (without logging the IP value) and answers 429 with a
// Retry-After header. A missing RATE_LIMIT binding fails closed (the
// caller gets { unavailable: true } and the router answers 503) —
// rate limiting is not a feature that silently disappears.
//
// The request body is read from a clone, never from the original request,
// so handlers can still parse the body themselves.

import { parseFormOrJson } from "../lib/http.js";
import { rateLimitStub } from "../store/rate-limit.js";

export const RATE_LIMITS = {
  "/oauth/authorize": { ip: 60, client: 300, windowMs: 60_000 },
  "/oauth/token": { ip: 120, client: 600, windowMs: 60_000 },
  "/oauth/approval": { ip: 30, pending: 10, pendingWindowMs: 600_000, windowMs: 60_000 },
  "/oauth/device-authorization": { ip: 30, client: 120, windowMs: 60_000 },
  "/admin/clients": { ip: 10, windowMs: 60_000 },
  "/admin/muse-keys": { ip: 10, windowMs: 60_000 },
};

export function clientIp(request) {
  const cf = request.headers.get("cf-connecting-ip");
  if (cf) return cf.trim();
  const forwarded = request.headers.get("x-forwarded-for");
  if (forwarded) return forwarded.split(",")[0].trim();
  return "unknown";
}

async function bodyField(request, field) {
  try {
    const body = await parseFormOrJson(request.clone());
    if (body && typeof body === "object" && typeof body[field] === "string") return body[field];
  } catch {
    // Unparseable body: the handler will 400. No client bucket for it.
  }
  return null;
}

// Returns { allowed: true } or { allowed: false, retryAfter, bucket,
// clientId } or { unavailable: true } when the binding is missing.
export async function checkRateLimit(request, env, path) {
  const cfg = RATE_LIMITS[path];
  if (!cfg) return { allowed: true };
  if (!env.RATE_LIMIT) return { unavailable: true };

  const ip = clientIp(request);
  const ipRes = await rateLimitStub(env, `rl:ip:${path}:${ip}`).hit(cfg.ip, cfg.windowMs);
  if (!ipRes.allowed) {
    return { allowed: false, retryAfter: Math.ceil(ipRes.resetMs / 1000) || 1, bucket: "ip", clientId: null };
  }

  if (cfg.client) {
    let clientId = null;
    if (request.method === "GET") {
      clientId = new URL(request.url).searchParams.get("client_id");
    } else {
      clientId = await bodyField(request, "client_id");
    }
    if (clientId) {
      const cRes = await rateLimitStub(env, `rl:client:${path}:${clientId}`).hit(cfg.client, cfg.windowMs);
      if (!cRes.allowed) {
        return { allowed: false, retryAfter: Math.ceil(cRes.resetMs / 1000) || 1, bucket: "client", clientId };
      }
      return { allowed: true, clientId };
    }
  }

  if (cfg.pending) {
    const pendingId = (await bodyField(request, "pending_id")) || (await bodyField(request, "device_code"));
    if (pendingId) {
      const pRes = await rateLimitStub(env, `rl:pending:${pendingId}`).hit(cfg.pending, cfg.pendingWindowMs);
      if (!pRes.allowed) {
        return { allowed: false, retryAfter: Math.ceil(pRes.resetMs / 1000) || 1, bucket: "pending", clientId: null };
      }
    }
  }

  return { allowed: true, clientId: null };
}
