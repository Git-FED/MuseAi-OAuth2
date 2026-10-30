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

## Step 3 — Registries, rate limits, audit (2026-10-30)

**Built:**
- `src/lib/registry.js` — strict registry readers. `getClient` and
  `getMuseKey` re-validate shape on every read (client: id match, name,
  non-empty https redirect_uris with no wildcards/localhost/loopback,
  allowed_scopes subset when present; muse key: Ed25519 JWK with required
  kty/crv/x plus RFC-standard optional members with validated values).
  Malformed records read as unregistered. The old loose `getClient` in
  validate.js was removed; authorize, token, and device-authorization
  now import from registry.js. Per-client scope restriction is enforced
  in authorize and device-authorization when `allowed_scopes` is set.
- `src/admin/register.js` + routes `POST /admin/clients` and
  `POST /admin/muse-keys` — the ONLY way records enter the registries.
  Gated by an `ADMIN_TOKEN` env secret with a timing-safe comparison;
  missing/mismatched token is 403, and when `ADMIN_TOKEN` is unset the
  endpoints refuse everything. Payloads are validated strictly (redirect
  URIs, JWK shape, plus a real Web Crypto import check for muse keys).
  There is no public self-registration anywhere.
- `src/store/rate-limit.js` + `src/auth/rate-limit.js` — atomic
  fixed-window counters in a second Durable Object class
  (`RateLimitBucket`, binding `RATE_LIMIT`, migration v2, re-exported
  from worker.js). Counters live in the DO because KV read-then-write
  would let bursts slip past the limit. Enforced in the router before
  handlers (and before admin auth, so token guessing is throttled):
  429 + Retry-After on block, every block audited, and a missing
  `RATE_LIMIT` binding fails closed with 503 — limits never silently
  disappear. Exact limits (per 60s window unless stated):
  - /oauth/authorize: 60 per IP, 300 per client
  - /oauth/token: 120 per IP, 600 per client
  - /oauth/approval: 30 per IP, plus 10 per pending/device id per 10 min
  - /oauth/device-authorization: 30 per IP, 120 per client
  - /admin/clients, /admin/muse-keys: 10 per IP
- `src/lib/audit.js` — append-only audit entries in KV
  (`audit:<epoch-ms>:<random-id>`) with a fixed shape (ts, event,
  actor, client_id, route, outcome, short detail). No field exists for
  tokens, codes, signatures, secrets, or bodies, so they cannot leak
  into the log; the test asserts this. Wired into token issuance
  (per grant type), approval success and every denial, revocation,
  admin registry writes and admin auth failures, and rate-limit blocks
  (bucket kind only — the IP value is never logged). Audit failures are
  swallowed on purpose: a down audit store must not take logins down.
- `tests/step3.test.mjs` — 10 new tests: admin happy paths, token
  fail-closed (missing/wrong/unset), bad redirect URIs, malformed key
  JWKs, strict-reader rejection of hand-written bad records, per-client
  scope enforcement, both rate limits (IP + per-pending-id), and the
  audit trail's coverage and secret-freedom.
- Existing tests updated, not weakened: oauth-flow's fake env gained a
  fake RATE_LIMIT namespace, and the safety test's authorize-with-empty-
  env expectation moved from 500 to 503 (the limiter now fails closed
  before the handler runs).

**Tests: 31/31 passing under plain node** (8 atomic-store + 12
oauth-flow + 1 safety + 10 step3).

**Admin process (documented, not yet performed):** at deploy time, set
`ADMIN_TOKEN` as a Cloudflare dashboard secret — never in code, never
in wrangler.toml, never in the repo. Registration is then a reviewed
human action: the admin verifies who the client or Muse is, then POSTs
the record with `Authorization: Bearer <token>`. The module validates
shape only; it cannot validate trust. Note for the admin: Web Crypto's
own JWK export includes key_ops/ext/alg members, so those are accepted
with validated values; and any 32-byte value imports as an Ed25519
public key, so "it imports" proves shape, never ownership.

**Still gaps, declared honestly:**
- `ADMIN_TOKEN` is not set anywhere yet — it must be set as a dashboard
  secret at deploy time, or the admin endpoints refuse everything.
- Registry population still needs his admin action: no client or Muse
  key records exist until someone registers them through the admin
  endpoints above.
- Runtime proof: tests run under node, not the Cloudflare runtime.
  `wrangler dev` or a deployed worker is still what proves both DO
  bindings, and neither has happened. Nothing deployed, nothing pushed
  to GitHub in this step.
