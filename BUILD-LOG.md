# Build log — Login with Muse worker

Build workspace: `~/workspace/museai-oauth-build/`. This holds worker code
only (no demo site, no images). Nothing here is deployed, and nothing has
been pushed to GitHub. The repo scaffold stays the design authority
(SPEC.md); this log records what was actually built, step by step.

## Step 1 — Atomic store (2026-10-30)

**Choice: Durable Objects, one instance per record.** SPEC allowed
Durable Objects or transactional D1. DO won because a one-time code needs
consume-once semantics, and a DO instance runs single-threaded: the
consume() call reads and deletes in one indivisible step, so two racing
redemptions can't both succeed. D1 could do it with transactions, but DO
fits the per-record shape with less machinery. D1 remains an option later
for audit logs and the client registry, which don't need consume-once.

**Built:**
- `src/store/oauth-record.js` — `OAuthRecord` class with create, read,
  consume, replace, revoke, alarm, plus the `recordStub(env, key)` helper
  for worker code. Expiry is lazy (checked on every access) plus an alarm
  that cleans up unread expired records.
- `wrangler.toml` — `OAUTH_STORE` binding, `OAuthRecord` class, v1
  migration. KV binding kept for non-atomic data only.
- `tests/atomic-store.test.mjs` — 8 tests, all passing under plain node
  (the class imports nothing Cloudflare-specific).

**Not yet real:** the worker entry (`worker.js`) still returns 503 by
design, and no route calls the store yet. Wiring the token, device, and
approval flows to this store is the next build step.

**Honest limit:** the tests prove the consume-once logic, not the
Cloudflare runtime. A live runtime check needs `wrangler dev` or a
deployed worker, neither of which has happened. The 503 fail-closed
worker is untouched until wiring is verified.
