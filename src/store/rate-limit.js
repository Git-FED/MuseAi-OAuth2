// Rate-limit counters in a Durable Object. Counters need atomic
// increments, so they cannot live in KV (a KV read-then-write has a race
// window where a burst slips past the limit). One instance per bucket key,
// single-threaded, so hit() is atomic for its bucket.
//
// Fixed-window counting: each bucket holds { count, windowStart }. A hit
// past the window start resets the bucket. Blocked hits still increment
// the counter — the window does not grant a fresh burst to a client that
// is already over the limit.

// Step 9 (2026-10-30): see oauth-record.js — new_sqlite_classes
// requires classes that extend DurableObject, or RPC fails outright.
// Same fix here: the old-style constructor(state) could not receive
// hit() calls, which step 7 silently degraded to allow.
import { DurableObject } from "cloudflare:workers";

export class RateLimitBucket extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.ctx = ctx;
    this.storage = ctx.storage;
  }

  // Returns { allowed, remaining, resetMs }. resetMs is how long until
  // the current window ends (used for the Retry-After header).
  async hit(limit, windowMs) {
    const now = Date.now();
    let s = await this.storage.get("state");
    if (!s || now - s.windowStart >= windowMs) {
      s = { count: 0, windowStart: now };
    }
    s.count += 1;
    await this.storage.put("state", s);
    return {
      allowed: s.count <= limit,
      remaining: Math.max(limit - s.count, 0),
      resetMs: Math.max(s.windowStart + windowMs - now, 0),
    };
  }
}

// Worker-side helper, mirroring recordStub: one bucket instance per key.
export function rateLimitStub(env, key) {
  return env.RATE_LIMIT.get(env.RATE_LIMIT.idFromName(key));
}
