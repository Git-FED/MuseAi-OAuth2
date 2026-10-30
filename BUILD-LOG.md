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

## Step 2 — Routes wired to the store (2026-10-30)

**The worker is live in code, still not deployed.** `worker.js` now
delegates to `src/index.js` (which routes to the handlers) and re-exports
`OAuthRecord` so the DO binding resolves. The old blanket-503 behavior
is gone; the safety test was updated to the new fail-closed behavior
(/health 200, unknown route 404, unconfigured discovery 503).

**Built:**
- `src/lib/crypto.js` — Web Crypto helpers: random strings, PKCE S256
  challenge/verify, ES256 JWT sign/verify from JWK env vars, Ed25519
  verify. No Node-only or Cloudflare-only APIs.
- `src/lib/validate.js` — client registry lookup in KV, exact
  redirect-URI match (no prefix/wildcard/localhost exceptions), scope
  validation (openid, profile, email, offline_access).
- `src/lib/http.js` — JSON/HTML responses with no-store + nosniff,
  form-or-JSON body parsing.
- `src/auth/tokens.js` — ES256 access + ID tokens (1h), opaque refresh
  tokens stored only in the DO store (30d), refresh rotation (new pair
  first, old record revoked after), access-token verification including
  the KV jti denylist.
- `src/router.js` — route table with 404/405 behavior and a manual
  `KILL_SWITCH=1` that pauses all OAuth routes while /health answers.
- `src/oauth/authorize.js` — validates client/redirect/PKCE, creates a
  pending record (TTL 10 min), returns an approval page showing the
  client name + redirect host. No typed username or email field: the
  page accepts only a Muse-signed approval payload.
- `src/oauth/approval.js` — verifies the Ed25519 signature against the
  registered key in KV (`muse_key:<muse_id>`). No registered key =
  403, bad signature = 403, a key supplied in the body = 400. On
  success, pending approvals mint an auth code and return the redirect
  URL; device approvals flip the device record to approved.
- `src/oauth/token.js` — authorization_code (consume-once + PKCE),
  refresh_token (rotation), device_code (pending -> authorization_pending,
  approved -> tokens). Public clients only in this step.
- `src/oauth/device-authorization.js` — device + user codes in the
  store (TTL 30 min).
- `src/oauth/userinfo.js` — Bearer token in, sub + email +
  email_verified:false out (option 2 policy).
- `src/oauth/revocation.js` — RFC 7009: refresh via store revoke,
  access via KV jti denylist; unknown tokens still return 200.
- `src/oauth/discovery.js` + `src/oauth/jwks.js` — from env ISSUER +
  public key; 503 when not configured.
- `tests/oauth-flow.test.mjs` — 12 tests with fake env doubles
  (fake DO store, fake KV, fresh Web Crypto keys): happy path, bad
  PKCE, double redeem, refresh rotation, unregistered-muse fail-closed,
  bad signature, self-supplied key rejection, discovery fail-closed,
  404/405, PKCE-required redirects, full device flow, revocation.

**Tests: 21/21 passing under plain node** (8 atomic-store + 12
oauth-flow + 1 updated safety test).

**Still gaps, declared honestly:**
- Key/client registry population: `client:<id>` and `muse_key:<id>`
  records must be written to KV by a reviewed admin process before any
  real login works. Nothing in this step invents or seeds them.
- Approval-page UX: the page takes a pasted signed JSON payload. A
  direct Muse-to-page handoff (no copy-paste) is a later polish step.
- Device flow has no human user-code entry page yet; device approval
  currently references the device code directly.
- Rate limits, audit logging, and security-header hardening beyond
  no-store/nosniff are still to come (SPEC pre-production list).
- Runtime proof: tests run under node, not the Cloudflare runtime.
  `wrangler dev` or a deployed worker is still the step that proves
  the DO binding, and neither has happened. Nothing deployed, nothing
  pushed to GitHub in this step.
