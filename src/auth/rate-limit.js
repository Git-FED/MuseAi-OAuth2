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
  // Deny shares the approval shape: an IP bucket plus a per-request
  // bucket (the pending/device bucket reader already reads pending_id
  // or device_code from the body), so deny cannot be hammered either.
  "/oauth/deny": { ip: 30, pending: 10, pendingWindowMs: 600_000, windowMs: 60_000 },
  // Device entry: user codes are short by design (RFC 8628), so the IP
  // bucket is the guessing brake — 30 submissions per IP per minute.
  "/device": { ip: 30, windowMs: 60_000 },
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

// One bucket hit with shape validation: the store must answer with a
// boolean `allowed`, or the result is unusable (treated as a storage
// error by the caller, never as an allow or a block on its own).
async function hitBucket(env, key, limit, windowMs) {
  const res = await rateLimitStub(env, key).hit(limit, windowMs);
  if (!res || typeof res.allowed !== "boolean") {
    throw new Error(`malformed rate-limit result for ${key}`);
  }
  return res;
}

// Returns { allowed: true } or { allowed: false, retryAfter, bucket,
// clientId } or { unavailable: true } when the binding is missing.
// STEP 7: a storage/transient error does NOT fail closed. It logs loudly
// and returns { allowed: true, degraded: true } — throttling degrades,
// but a broken limiter must not take the whole provider down (that is
// exactly what happened in production 2026-10-30: the store call ran
// clean, yet every rate-limited route answered 503). The missing-binding
// case still fails closed (config error, not a transient). Degraded
// allows never skip authentication: admin tokens, Muse signatures, and
// PKCE still apply downstream.
export async function checkRateLimit(request, env, path) {
  const cfg = RATE_LIMITS[path];
  if (!cfg) return { allowed: true };
  if (!env.RATE_LIMIT) return { unavailable: true };
  try {
    const ip = clientIp(request);
    const ipRes = await hitBucket(env, `rl:ip:${path}:${ip}`, cfg.ip, cfg.windowMs);
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
        const cRes = await hitBucket(env, `rl:client:${path}:${clientId}`, cfg.client, cfg.windowMs);
        if (!cRes.allowed) {
          return { allowed: false, retryAfter: Math.ceil(cRes.resetMs / 1000) || 1, bucket: "client", clientId };
        }
        return { allowed: true, clientId };
      }
    }

    if (cfg.pending) {
      const pendingId = (await bodyField(request, "pending_id")) || (await bodyField(request, "device_code"));
      if (pendingId) {
        const pRes = await hitBucket(env, `rl:pending:${pendingId}`, cfg.pending, cfg.pendingWindowMs);
        if (!pRes.allowed) {
          return { allowed: false, retryAfter: Math.ceil(pRes.resetMs / 1000) || 1, bucket: "pending", clientId: null };
        }
      }
    }

    return { allowed: true, clientId: null };
  } catch (e) {
    console.warn(`rate-limit degraded for ${path}: ${String(e && e.message ? e.message : e).slice(0, 200)}`);
    return { allowed: true, degraded: true };
  }
}
