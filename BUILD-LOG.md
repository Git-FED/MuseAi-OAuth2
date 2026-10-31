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

## Step 4 — Approval-page polish, device user-code entry page, deploy prep (2026-10-30)

**Built:**
- `src/oauth/approval-page.js` — shared HTML renderer for the human
  surfaces. Everything registry- or request-sourced is escaped before
  it reaches a page; error pages use plain language, never a stack
  trace or internal detail.
- Authorize approval page (via `src/oauth/authorize.js`, inline page
  replaced): before any approval it now shows the client name, the
  exact redirect host, the scopes being requested, and the option-2
  email statement ("signing in will share your email address...
  returned as unverified (email_verified: false). Verification is a
  later, separate step and never blocks your sign-in"), plus a DENY
  button next to Approve. Still no typed username or email field:
  approval is the signed payload only.
- `src/oauth/deny.js` — POST /oauth/deny, the clean deny path for
  both flows. Denial is terminal: the record's status becomes
  "denied" (never usable again, expires with its normal TTL, nothing
  left "awaiting"). A later approval attempt on the same id answers
  access_denied; a polling device answers access_denied (token
  handler updated for this). Authorize deny returns a redirect_to
  carrying error=access_denied (+ state) so the client sees a standard
  OAuth denial. Denying an already-approved request is refused
  (revocation is the path for that); denying an already-denied
  request is idempotent. Every denial is audited (approval_denied,
  detail denied_by_user / device_denied_by_user).
- `src/oauth/approval.js` — a denied record now answers access_denied
  on a late approval attempt (previously it would have fallen through
  to signature verification against a dead request).
- `src/oauth/token.js` — a denied device polls to access_denied
  (audited as token_denied), repeatedly until TTL expiry, instead of
  the generic invalid_grant.
- `src/oauth/device-entry.js` + routes GET/POST /device — the human
  user-code entry page (RFC 8628 verification URI). GET serves a blank
  code form; POST resolves the code, then shows the client name +
  scopes + approve/deny forms for a pending request, or a plain
  already-approved / denied page. Wrong, malformed, or expired codes
  get one generic message ("invalid or has expired") that does not
  say whether the code ever existed, and the submitted code value is
  never logged or audited (invalid attempts audit as
  device_entry_invalid with the generic detail only). Approval from
  the device page uses the SAME Muse-signed mechanism as the
  authorize flow — no second authentication mechanism was invented.
- `src/oauth/device-authorization.js` — writes the KV index
  device_user_code:<CODE> -> device_code (30-minute TTL, matching the
  device record) because the DO store is keyed by device code and has
  no scan. If the index write fails, the device record is revoked and
  the request fails closed rather than handing out a code no human
  can enter. verification_uri now points at /device (it previously
  pointed at the JSON /oauth/approval endpoint, which was never a
  human page).
- `src/router.js` — /oauth/deny, GET /device, POST /device added.
  Route matching fixed to match path AND method: /device serves both
  GET and POST, and matching on path alone would have 405'd the
  second method on the shared path. Existing 404/405 behavior
  unchanged (verified by the existing tests).
- `src/auth/rate-limit.js` — /oauth/deny: 30/IP/min + 10 per
  pending/device id per 10 min (same shape as approval, so deny can't
  be hammered either). /device: 30/IP/min — the guessing brake for
  short user codes.
- `docs/DEPLOY.md` — release checklist that separates code-done from
  human-action: custom domain + ISSUER (wrangler.toml still has
  workers_dev=false and ISSUER commented out — the domain is his
  call, none chosen here), ADMIN_TOKEN + ES256 signing keys as
  dashboard secrets, the three bindings with migrations v1/v2,
  registry population via the admin endpoints (reviewed human
  action), wrangler-dev runtime-proof steps (still not done),
  KILL_SWITCH procedure, rollback (fail-closed, redeploy previous
  git version), and a release checklist ending in his explicit
  go-ahead. No domain set, no secrets invented, no deploy step
  claimed done.

**Tests: 39/39 passing under plain node** (8 atomic-store + 12
oauth-flow + 1 safety + 10 step3 + 8 step4).
- `tests/step4.test.mjs` — 8 new tests: approval page shows client +
  redirect host + scopes + email statement with no typed
  username/email field; deny fails the pending request and later
  approval answers access_denied (plus idempotent re-deny and unknown
  id behavior); device entry GET form + valid-code detail page;
  device approve (signed) issues tokens; device deny polls to
  access_denied repeatedly; wrong/malformed/expired codes error
  cleanly with one generic message (expired simulated with a 1ms-TTL
  record); device submissions rate-limited per IP; approve/deny
  outcomes audited with no device material in the audit trail.
- Existing tests updated, not weakened: none needed changes — the
  device flow test still passes with the new verification_uri, and
  the 404/405 test still passes with the new router matching.

**Still gaps, declared honestly:**
- Runtime proof: tests run under node, not the Cloudflare runtime.
  `wrangler dev` or a deployed worker is still what proves both DO
  bindings, and neither has happened. docs/DEPLOY.md lists the exact
  proof steps.
- Domain + ISSUER: not chosen (his call).
- ADMIN_TOKEN and ES256 signing keys: unset anywhere.
- Registry population: no client or Muse key records exist until the
  admin action.
- Approval UX beyond this step: the signed payload is still pasted
  JSON; a direct Muse handoff (no paste) is later polish.
- His go-ahead + release checklist sign-off: not given. Nothing
  deployed, nothing pushed to GitHub in this step.

## Step 5 — /login path-prefix support (2026-10-30)

Git-FED's call, 2026-10-30: the provider lives at
https://fedpromptly.com/login (easier for him to make happen than a
subdomain). ISSUER is therefore https://fedpromptly.com/login, and the
worker mounts at BASE_PATH=/login. The code previously assumed a root
mount; this step makes the mount configurable without changing
root-mounted behavior.

- `src/lib/mount.js` (new) — `normalizeBasePath` (leading slash
  enforced, trailing slashes stripped, "/" or empty = no prefix) and
  `stripBasePath` (matches exactly one leading segment: "/login"
  matches "/login" and "/login/<anything>" and nothing else —
  "/loginevil", "/loginfoo", and "/LOGIN/..." do not match). A
  request that does not start with the prefix is not a provider
  request: the router answers 404, never a provider route at the
  wrong mount. "/login/" strips to "/" — the mount root, which is
  not a route, so it 404s like any unknown path.
- `src/router.js` — strips BASE_PATH before matching; from there on
  the stripped path is used for route matching, 405 detection, the
  kill-switch health exception, rate-limit buckets, and audit route
  values, so behavior is identical under either mount.
- `src/oauth/approval-page.js` — every internal link on the human
  pages is built from basePath: approval fetch
  `${basePath}/oauth/approval`, deny fetch `${basePath}/oauth/deny`,
  device entry form action `${basePath}/device`. Client redirect URIs
  are never touched — they are not provider URLs.
- `src/oauth/authorize.js`, `src/oauth/device-entry.js` — pass
  normalizeBasePath(env.BASE_PATH) into the page renderers.
- `wrangler.toml` — BASE_PATH documented as a commented dashboard
  variable alongside ISSUER (not set in the repo).
- `docs/DEPLOY.md` — ISSUER is now https://fedpromptly.com/login,
  BASE_PATH=/login for the fedpromptly deployment; the Cloudflare
  route to create is fedpromptly.com/login* (a dashboard action by
  the owner, NOT done); runtime-proof steps and the release checklist
  now use /login-prefixed paths; root mounting still works with
  BASE_PATH unset.
- No code change needed for discovery or the device verification_uri:
  both already derive from env ISSUER, so with ISSUER set to
  https://fedpromptly.com/login they sit under /login automatically
  (verified by test, not assumed).

**Tests: 47/47 passing under plain node** (8 atomic-store + 12
oauth-flow + 1 safety + 10 step3 + 8 step4 + 8 step5).
- `tests/step5.test.mjs` — 8 new tests: full authorize flow end to
  end through prefixed URLs (approval redirect_to still points at the
  client's registered callback, unrewritten); root-path requests 404
  when a prefix is set, mount root 404s, wrong method under the
  prefix is still 405, prefixed health answers; discovery returns
  issuer https://fedpromptly.com/login with every endpoint under
  /login; device verification_uri sits under /login and the entry
  page posts there; prefix-confusion paths never match; prefixed
  pages carry prefixed internal links and no root provider links;
  rate limits still fire under the prefix (61st authorize per IP
  → 429); BASE_PATH unset leaves previous root behavior unchanged.
- One test-side fix during this step (not a code fix): the device
  detail page has no entry form, so the form-action assertion was
  moved to the blank entry form where it belongs; the detail page
  asserts its prefixed approval/deny fetches instead.

**Still gaps, declared honestly:**
- Runtime proof: tests run under node, not the Cloudflare runtime.
  `wrangler dev` or a deployed worker is still what proves both DO
  bindings, and neither has happened. docs/DEPLOY.md lists the exact
  proof steps, now with /login paths.
- The fedpromptly.com/login* route itself: his dashboard action,
  not done.
- ADMIN_TOKEN and ES256 signing keys: unset anywhere.
- Registry population: no client or Muse key records exist until the
  admin action.
- Approval UX beyond this step: the signed payload is still pasted
  JSON; a direct Muse handoff (no paste) is later polish.
- His go-ahead + release checklist sign-off: not given. Nothing
  deployed, nothing pushed to GitHub in this step.

## Step 6 — deploy blockers fixed (2026-10-30 ~11:37 EDT, his tap)

Git-FED connected the repo to Cloudflare Workers Builds himself (worker
museai-oauth2, route fedpromptly.com/login) and pasted the 11:34–11:35
EDT build log. The build uploaded and Cloudflare recognized all three
bindings, then failed on two wrangler.toml items, both fixed here:

- Deploy error 10097 (free plan): migrations used `new_classes`.
  Free plans require `new_sqlite_classes` to create Durable Object
  classes. v1 (OAuthRecord) and v2 (RateLimitBucket) now use
  `new_sqlite_classes`. No deploy had succeeded before this change, so
  no existing class is affected. The DO code uses only the standard
  storage API (put/get/delete/alarm), which SQLite-backed objects
  support the same way.
- Worker name mismatch: config said `museai-oauth`, the dashboard
  worker is `museai-oauth2`. Config now says `museai-oauth2`, so
  Builds stops overriding and warning.

Verification: wrangler.toml parses (name museai-oauth2, both
migrations new_sqlite_classes, workers_dev still false); node tests
still 47/47 — this step touches config only, no code.

**Still gaps, declared honestly:**
- The redeploy itself: Git-FED pushes this zip; Workers Builds
  redeploys on push. A green deploy is expected but NOT yet observed.
- After a green deploy, logins still will not work until the
  dashboard variables and secrets are set (ISSUER, BASE_PATH,
  ADMIN_TOKEN, ES256 signing keys) — the worker fails closed without
  them. That is the next step, not a new problem.
- Runtime proof, registry population, his go-ahead + checklist
  sign-off: unchanged from step 5.

## Step 7 — rate-limit hardening (2026-10-30, after the production 503 outage)

Problem: after the step-6 rebuild + dashboard repair (all 8 bindings
verified live on serving v18, workers.dev back, health + JWKS 200),
EVERY rate-limited route still answered 503 — authorize, device,
token, admin — on fresh buckets and fresh windows, from both the
VM and Git-FED's own browser. A live wrangler tail with a marked
probe proved the RateLimitBucket `hit` RPC runs clean (outcome ok,
no exceptions) yet the worker still answers 503. Kill switch is off
(no binding), the deployed bundle is byte-identical to this source,
and the router's 503 branches (kill switch / unavailable / catch)
do not explain a clean RPC + no exception + 503. Root cause of the
original 503 is therefore still UNKNOWN — this step does not claim
otherwise.

What step 7 changes (src/auth/rate-limit.js, src/router.js):
- checkRateLimit never throws anymore. A storage/transient error
  (DO call throws, or returns a malformed result without a boolean
  `allowed`) logs loudly (console.warn, visible in wrangler tail)
  and returns { allowed: true, degraded: true }: throttling
  degrades, but a broken limiter no longer takes the whole provider
  down. The missing-binding case STILL fails closed (503) — a
  config error is not a transient, and that distinction is kept.
- Both router 503 paths now console.error the branch (unavailable
  vs catch) with the path, so the next tail shows which branch
  fired — the diagnostic that was missing on 2026-10-30.
- Degraded allows are audited (rate_limit_degraded) so a broken
  limiter leaves a trail in KV while requests proceed.
- Degraded allow removes THROTTLING only, never authentication:
  admin tokens, Muse signatures, and PKCE still apply downstream.

What step 7 deliberately does NOT do: move rate limiting to KV.
Free-tier KV allows 1,000 writes/day account-wide; a KV limiter
writes on every rate-checked request and would exhaust that in
minutes at any real traffic, then fail closed back into 503s.
The DO limiter stays (no write cap); only its failure mode changes.

Verification: node tests 51/51 (47 prior + 4 new step7 tests:
store throw -> degraded allow + audit; malformed result ->
degraded allow; missing binding -> still 503; working limiter ->
device page 200). Zip delivered for Git-FED to push; after a green
deploy, the tail check is: rate-limited routes must answer (not
503), and any `rate-limit degraded` warnings in the tail name the
real storage fault for step 8.

## Step 8 — deploy-proof config (2026-10-30, after the v19 wipe)

Found mechanism: a Workers Builds deploy applies ONLY what is in the
repo. Dashboard plain-text variables do NOT survive it — v14 (the
rebuild) and v19 (the step-7 push) both arrived missing BASE_PATH,
ISSUER, and SIGNING_PUBLIC_JWK, with workers.dev disabled again,
while the two secrets (ADMIN_TOKEN, SIGNING_KEY_JWK) survived both
times. That is why v19 answers 1042 on workers.dev: the code is
step 7, but the worker has no mount path, no issuer, and no public
key, and its workers.dev route is off.

Fix (wrangler.toml only, no code change): workers_dev = true, plus
a real [vars] section carrying the three public values (BASE_PATH,
ISSUER on www, SIGNING_PUBLIC_JWK). Public config lives in the repo
from here on, so every push deploys complete. Secrets stay
dashboard-only and are never committed. SIGNING_PUBLIC_JWK in the
repo is safe by design: it is the public key, already served to
anyone by /login/jwks (its x/y were verified to match the live JWKS
coordinates before writing it here).

Verification: wrangler.toml parses (workers_dev true, all three vars
present); node tests unaffected (config-only change). After this
push, the deploy must show all 8 bindings + workers.dev on, and the
rate-limited routes must answer (not 503) before registration runs.
The www route star (www.fedpromptly.com/login*) is still a separate
pending dashboard action for the www path.

## Step 9 — Durable Object classes must extend DurableObject (2026-10-30, after the v20 500s)

Root cause, proven by live wrangler tail (not guessed): authorize and
device-authorization returned 500 because every OAuthRecord RPC threw,
and the rate limiter was silently degraded at the same time. The tail
warned, verbatim: "The receiving Durable Object does not support RPC,
because its class was not declared with `extends DurableObject`."
Mechanism: step 6 switched migrations to new_sqlite_classes (free plan
refuses new_classes, error 10097) but the two classes stayed old-style
(plain constructor(state)). SQLite-class DOs require new-style classes
to receive RPC. RateLimitBucket.hit failing degraded to allow under
step 7 (routes kept answering, throttling silently off); OAuthRecord
calls have no degraded path, so authorize/device/token all 500'd.

Fix (code only, no migration change — the classes are already
provisioned as SQLite classes): both classes now `extends DurableObject`
(imported from `cloudflare:workers`), constructor(ctx, env), storage on
ctx.storage, alarms on ctx.setAlarm. Node tests resolve
`cloudflare:workers` to tests/cloudflare-workers-shim.mjs via
package.json imports; wrangler must resolve it to the real runtime
builtin — post-deploy bundle check: grep the served bundle for
NODE_TEST_SHIM_MARKER_9X7; if present, the deploy inlined the shim
and RPC is still broken. After this push, authorize (real client +
PKCE) must return the approval page (not 500), device-authorization
must return device_code + user_code, and the tail must show no
`rate-limit degraded` warnings (throttling back on).

Test-harness note (step 9): plain Node cannot import
`cloudflare:workers` (ERR_UNSUPPORTED_ESM_URL_SCHEME), and package.json
"imports" cannot map a colon-scheme specifier. Tests therefore run via
`node --import ./tests/register-shim.mjs --test` (package.json test
script): a resolve hook maps `cloudflare:workers` to the dummy class in
tests/cloudflare-workers-shim.mjs. The hook files live under tests/,
nothing in worker.js imports them, so they cannot reach the deployed
bundle. Tests: 51/51 pass with the hook.

## Step 10 — worker-hosted Sign in with Muse page at the mount root (2026-10-30, Git-FED order: "a working embed")

Problem: the step-9 button was a snippet file. Git-FED's site is Google
Sites, which cannot run that snippet (no page to host the button +
callback), so the snippet was unusable there. He deployed it to GitHub
Pages (test1) as a workaround, but the registered redirect still points
at the Google Sites homepage, so the auth code lands where no callback
code runs and is never redeemed.

Fix (code only): GET / after BASE_PATH stripping — i.e. /login on www,
previously a 404 by design — now serves the login page itself
(src/oauth/login-page.js, route added to src/router.js). The page is
the embed: a site embeds it by URL or iframe and the whole flow
(button, approval, callback, email display) happens on the page, same
origin throughout. The page derives its API base and redirect_uri from
its own URL (origin + path, trailing slash stripped), so it works on
any host it is served from — but that exact URL must be a registered
redirect_uri for client fedpromptly. No framing-blocking headers exist
anywhere in this worker (lib/http.js sets only no-store + nosniff), and
the page never navigates the top frame, so it stays usable inside an
embed. Google Sites needs only a plain link or iframe to the page URL,
nothing pasted into Google Sites.

Behavior change, declared: the step-5 test "mount root 404s too" is
updated — /login and /login/ now serve the page (200, HTML, button).
All other step-5 expectations (unprefixed paths 404, wrong-method 405,
/login/health 200) are unchanged.

Tests: 56/56 pass (51 step-9 tests + 5 new login-page tests:
mount root with/without trailing slash, page script endpoints +
no frame-busting, subpaths not swallowed, root mount at /).

Registry change (live, separate from this code push): client
fedpromptly re-registered with redirect_uris = homepage (kept, so the
GitHub Pages button keeps working) + https://www.fedpromptly.com/login
(the embed page) + https://museai-oauth2.fedos.workers.dev/login
(testing the page on workers.dev). No allowed_scopes on the record
(verified by KV read before re-posting), so nothing else changed.

After this push, verify: GET /login on workers.dev returns the page
(200, HTML, button); a full sign-in through the page on workers.dev
completes and shows the email; the same page on www does the same
once the route star (set 2026-10-30 ~17:53 EDT) routes it.

## STEP 10 FIX — button did nothing (2026-10-30 ~18:16-18:19 EDT)
His www screenshot proved the page serves, but clicking the button did
nothing. Root cause, proven by byte counts, not guessing: the page's
script lives inside a JS template literal in src/oauth/login-page.js, and
a template literal EATS a backslash before / or + (identity escape). So
the SERVED script had `replace(//$/, "")` and `replace(/+/g, ...)` —
a syntax error — the whole script failed to load and no click handler
was ever attached. The source file and the zip LOOKED right, and the old
tests checked the source text, not the served string, so they missed it.
Fix: double the backslashes in the template literal (3 markers), so the
served string carries the single backslashes the regexes need. Proof:
evaluated served script now parses (node --check OK, was FAIL), and a
stubbed-browser click run sets location.href to the exact authorize URL
(client + page redirect + S256 challenge + state, verifier/state stored).
Regression test added (login-page.test.mjs, "survives serving"): asserts
the served text keeps all three backslashes and that new Function on the
served script does not throw. Suite: 57/57 pass. Zip:
~/workspace/museai-oauth-step10-fix.zip (53 entries). NOTE: the plain
HTML button file (site/fedpromptly-login-button.html, GitHub Pages) was
never affected — it is not a template literal, its backslashes are fine.

## STEP 11 — CORS FOR THIRD-PARTY SITE LOGINS (2026-10-30 ~20:30 EDT, for FED Hub)
Git-FED ordered Muse login added to https://hub.fedos.workers.dev/ as the
first real-site test. Hub already has its own login UI (Supabase
email/password modal, browser-side); the Muse button joins that modal.
Hub becomes a real OAuth client: client "hub" registered 2026-10-30
(admin POST 201, authorize check 200 rendering the approval page naming
"FED Hub"), redirect_uri https://hub.fedos.workers.dev/ (exact match —
authorize.js requires includes(), so the hub page sends exactly that and
handles the returned ?code=&state= on the homepage itself; no new worker
route needed, because hub 404s unknown paths). Hub page flow (browser
PKCE, sessionStorage): button -> authorize -> approval page -> Continue
-> homepage callback exchanges code, fetches userinfo, stores the session,
header buttons show the Muse username; clicking a login button while a
Muse session exists clears it. Supabase and Muse sessions coexist; the
button shows one name (Supabase wins if both, via its own handler).
BLOCKER FOUND: the oauth2 worker sent NO CORS headers anywhere, so a
browser on hub.fedos.workers.dev could not read /oauth/token or
/oauth/userinfo responses at all (the step-10 login page never needed
CORS — it is same-origin to its own API base). Fix, in src/router.js
only: OPTIONS preflight to /oauth/token and /oauth/userinfo answers 204
with allow-origin (request Origin echoed, else *), allow-methods GET/
POST/OPTIONS, allow-headers Content-Type/Authorization, Vary Origin;
handler responses on those two paths are wrapped with the same headers.
Narrow on purpose: admin, approval, and device routes get no CORS headers
and still 405 OPTIONS. No credentials mode: hub keeps tokens in
sessionStorage, never cookies, so echoing Origin cannot leak a session.
Tests added (tests/cors.test.mjs, 5 tests: both preflights 204, admin
OPTIONS still 405 without headers, token 400 + userinfo 401 both carry
the headers). Suite: 62/62 pass (57 old + 5 new). Zip:
~/workspace/museai-oauth-step11-cors.zip. DEPLOY ORDER: (1) push this zip
to MuseAi-OAuth2 (Workers Builds), (2) deploy the hub page
(~/workspace/hub-login/hub-with-muse-login.html) via hub's wrangler
project, (3) test end to end. Hub deliverable notes:
~/workspace/hub-login/muse-login-snippet.html (the two insertions, for
patching hub source by hand if it drifted from the live HTML).

## STEP 13 — AUTOMATIC APPROVAL, NO MORE COPY AND PASTE (2026-10-31, Git-FED order: "its time to get to upgrading the oauth so its automatic no more copy and pasting")

This step supersedes step 12: it is built on the step-12 code (step-12
styling + step-11 CORS + step-10 login page), so pushing this zip
replaces the step-12 push — do NOT push step 12 separately.

What changed, and what "automatic" honestly means:
- The approval page NO LONGER has a paste box, an Approve click, or a
  Continue link. It shows "Waiting for your Muse to approve…" and
  polls GET /oauth/pending-status every 2 seconds. On approval it
  navigates itself to the client's callback with the code; on denial
  it navigates itself to the client's access_denied redirect. The
  Deny button stays — that is the human consent surface on the page.
- The Muse approves OUT OF BAND, exactly as before, by POSTing its
  Ed25519-signed payload to /oauth/approval — no paste, no browser
  form. What is new is only that the page finishes itself once that
  API approval lands. There is still no push from the worker to a
  Muse: the user tells their Muse to approve (in chat, as now), the
  Muse posts the signed approval, the page completes. A site can
  never auto-approve itself — approval still requires a registered
  Muse key and a valid signature, and the user still sees the client
  name, redirect host, and scopes before anything happens.
- New endpoint (src/oauth/pending-status.js, route in src/router.js):
  GET /oauth/pending-status?pending_id=… or ?device_code=…. Awaiting
  -> { status: "awaiting" }; approved authorize -> { status:
  "approved", redirect_to }; denied authorize -> { status: "denied",
  redirect_to }; device -> status only (the device client already
  polls /oauth/token). Unknown/expired ids fail closed with the same
  invalid_pending / invalid_device errors. Rate-limited 60/IP/min.
  No audit entry per poll (a 2s poll would flood KV); approvals,
  denials, and redemptions are still audited where they happen.
- approval.js now stores the auth code on the pending record when it
  flips to approved, so the poll endpoint can rebuild the redirect.
  The code is still useless without the PKCE verifier, which lives
  only in the client page that started the flow.
- Device detail page gets the same treatment: no paste form, poll
  shows "Approved. Your device can now finish signing in." (the
  device itself polls /oauth/token, unchanged).
- Tests: 67/67 pass (62 old + 5 new step13 tests: page has no
  textarea/form, only the poller; awaiting -> approved with a
  redeemable code via the polled redirect; denied -> access_denied;
  unknown/missing/both ids fail closed; device awaiting/approved
  status-only). Three step-5 assertions were updated, not weakened:
  they now assert the prefixed pending-status poll + deny fetches
  and the ABSENCE of any approval fetch. Page CSS for the removed
  approval form was deleted with the form.

What this does NOT change: PKCE S256 mandatory, exact redirect match,
registered Muse keys only, self-supplied keys rejected, email
unverified (option 2), 10-minute pending TTL, token/refresh/device
flows, CORS, login page, or any dashboard secret. Nothing deployed,
nothing pushed to GitHub in this step — Git-FED pushes the zip.

## STEP 14 — POPUP SPEED-UP (2026-10-31, Git-FED: "yes it did so we can speed it up" + "sign in buttons to open muse ai maybe in a pop up")

Step 13 was proven live on www 2026-10-31 ~11:24 EDT (fresh pending
approved by muse3, page finished itself, no paste). The remaining
delay was human: the page waits blind because it cannot ping a Muse,
so the user had to switch apps/chats and retype an id. This step
closes that gap on the page itself.

What changed (src/oauth/approval-page.js only, no server routes):
- Approval page (authorize) and device detail page now show, above
  the waiting line: "Open Muse AI to approve" + "Copy approval
  message". Open Muse opens https://muse.ai in a popup window
  (480x720, click handler only, so popup blockers allow it).
- Copy approval message copies one line: "Please approve my Muse
  sign-in. Pending request: <pending id>" (authorize) or "Please
  approve my Muse device sign-in. Device code: <device code>"
  (device). Paste that line into the popup chat; the Muse signs
  from it, and the step-13 poller (still 2s) finishes the page.
  Clipboard failure falls back to a plain message telling the user
  to paste the request shown above.
- No route, PKCE, signature, TTL, CORS, or token change. The popup
  is a browser window to muse.ai, not a new authentication channel:
  approval still requires a registered Muse key + valid signature,
  and the user still sees client/host/scopes on the page first.

Tests: 69/69 pass (67 old + 2 new step14 tests: authorize page has
click-opened muse.ai popup + copy message with the exact pending id
+ no textarea + poller still present; device page has popup + copy
message with the exact device code + no textarea). Zip below
supersedes step 13 the same way step 13 superseded step 12: full
bundle, push this one only.
