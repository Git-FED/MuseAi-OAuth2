// Atomic store for Login with Muse, built on a Durable Object.
//
// DESIGN: one Durable Object instance per one-time record (auth code,
// device code, pending approval, refresh token). Cloudflare runs each
// instance single-threaded, so every method call below is atomic for its
// own record. That is what makes consume() truly consume-once: two racing
// token redemptions reach the same instance in sequence, and only the
// first one sees the record.
//
// This is the store SPEC.md requires. KV alone cannot do this — a KV
// read-then-delete has a race window where the same code redeems twice.
// KV stays for non-atomic data only (see the scaffold's src/lib/kv.js).
//
// The store is type-agnostic: callers tag the record kind in the payload
// (e.g. { kind: "auth_code", ... }). Expiry is lazy (checked on every
// access) plus a Durable Object alarm that cleans up after the deadline.

// Step 9 (2026-10-30): Durable Object classes MUST extend DurableObject.
// The step-6 switch to new_sqlite_classes (free plan refuses new_classes)
// left these classes old-style (plain constructor(state)), and the live
// tail proved RPC then fails: "The receiving Durable Object does not
// support RPC, because its class was not declared with extends
// DurableObject." That failure is why authorize/device returned 500
// (store create threw) while the rate limiter only degraded (step 7
// masks limiter failures as allow). New style: constructor(ctx, env),
// storage on ctx.storage, alarms on ctx.setAlarm. Node tests resolve
// `cloudflare:workers` to tests/cloudflare-workers-shim.mjs via
// package.json imports; wrangler resolves it to the real runtime builtin.
import { DurableObject } from "cloudflare:workers";

export class OAuthRecord extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.ctx = ctx;
    this.storage = ctx.storage;
  }

  // Create a record that lives for ttlMs. Refuses to overwrite a live
  // record — a live code must be consumed or expired first, never silently
  // replaced by a second issuance.
  async create(record, ttlMs) {
    const existing = await this.storage.get("record");
    if (existing && existing.exp > Date.now()) {
      throw new Error("record already exists");
    }
    const stored = { ...record, exp: Date.now() + ttlMs };
    await this.storage.put("record", stored);
    if (typeof this.ctx.setAlarm === "function") {
      await this.ctx.setAlarm(stored.exp);
    }
    return true;
  }

  // Read without consuming. Returns null when missing or expired
  // (expired records are cleaned up on sight).
  async read() {
    const rec = await this.storage.get("record");
    if (!rec) return null;
    if (rec.exp <= Date.now()) {
      await this.storage.delete("record");
      return null;
    }
    return rec;
  }

  // Atomically read + delete. The first call returns the record; every
  // later call returns null. This is the consume-once primitive the
  // token endpoint, device flow, and approval flow will all use.
  async consume() {
    const rec = await this.read();
    if (!rec) return null;
    await this.storage.delete("record");
    return rec;
  }

  // Replace the record in one call. Used for refresh-token rotation:
  // the old token is gone the moment the new one exists, never both.
  async replace(record, ttlMs) {
    const stored = { ...record, exp: Date.now() + ttlMs };
    await this.storage.put("record", stored);
    if (typeof this.ctx.setAlarm === "function") {
      await this.ctx.setAlarm(stored.exp);
    }
    return true;
  }

  // Delete unconditionally. Used for revocation and logout.
  async revoke() {
    await this.storage.delete("record");
    return true;
  }

  // Fired by the alarm set at create/replace time. Cleans up records
  // that expired without ever being read.
  async alarm() {
    const rec = await this.storage.get("record");
    if (rec && rec.exp <= Date.now()) {
      await this.storage.delete("record");
    }
  }
}

// Worker-side helper: the stub for one record's Durable Object instance.
// Usage: const stub = recordStub(env, `auth_code:${code}`);
//        const rec = await stub.consume();
export function recordStub(env, key) {
  return env.OAUTH_STORE.get(env.OAUTH_STORE.idFromName(key));
}
