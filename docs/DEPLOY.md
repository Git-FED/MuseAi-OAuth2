# Deploy prep — Login with Muse worker (build step 5, 2026-10-30)

This document is a release checklist, not a release. It is honest about
what is code-done versus what still needs a human action. **Nothing in
this repo is deployed.** Nothing here deploys itself: every step below
that touches Cloudflare is a dashboard action by the owner, and the
final deploy needs his explicit go-ahead plus a signed-off checklist.

## What this code is

A Cloudflare Worker that speaks OAuth 2.0 + OIDC-flavored sign-in for
Muse agents: authorization code flow with mandatory PKCE S256, device
authorization flow, Muse-signed approvals (Ed25519, registered public
keys only — no typed username or email anywhere), ES256 access + ID
tokens, refresh rotation, revocation, strict registries, admin-only
registration, atomic rate limits, and an append-only audit log.

Entry point: `worker.js` (delegates to `src/index.js` → `src/router.js`).
Tests: `node --test` (plain node, no Cloudflare runtime — see
"Runtime proof" below; node tests prove logic, not the deployment).

## Decisions decided (owner's call, 2026-10-30)

- [x] **Provider home: https://fedpromptly.com/login.** The provider
  lives under a path of his own domain, not a subdomain and not a
  workers.dev URL. `ISSUER` is therefore
  `https://fedpromptly.com/login`, and the worker mounts at
  `BASE_PATH=/login` (build step 5: the router strips exactly that
  one leading segment before matching; root mounting still works with
  `BASE_PATH` unset). Discovery lives at
  `https://fedpromptly.com/login/.well-known/openid-configuration`
  and every endpoint URL in it sits under `/login`. Until `ISSUER`
  and `BASE_PATH` are set as dashboard variables, discovery and JWKS
  answer 503 by design.
- [x] **Cloudflare route — DONE by Git-FED 2026-10-30 (his dashboard
  action).** The route `fedpromptly.com/login*` points at worker
  `museai-oauth2`, proven by his 11:34–11:35 EDT Workers Builds log
  (route table shown in the log). Nothing in this repo creates that
  route. First deploy through it FAILED on wrangler.toml blockers
  (error 10097 + worker-name mismatch), fixed in build step 6 —
  redeploy on push is still unobserved.
- [ ] **First clients.** Which of his own sites become the first
  registered clients, and their exact redirect URIs. Registration is
  via the admin endpoints (below), never by editing code. (The
  button question — which sites get the login button first — comes
  after deploy; his own sites are first clients either way.)

## Secrets — dashboard only, never in code or in this repo

Set these as Cloudflare dashboard secrets/variables on the worker
before any deploy. If any one is missing, the worker fails closed
(503 or 403) rather than running degraded — that is intentional.

- [ ] `ADMIN_TOKEN` — dashboard secret. Gates `POST /admin/clients`
  and `POST /admin/muse-keys`. When unset, both endpoints refuse
  everything. Pick a long random value; it travels only as
  `Authorization: Bearer <token>` and is never logged or stored.
- [ ] `SIGNING_KEY_JWK` — dashboard secret. The ES256 (P-256) private
  key, as a JSON Web Key, used to sign access + ID tokens.
- [ ] `SIGNING_PUBLIC_JWK` — dashboard variable (public half of the
  same key pair). Served at `/jwks` so clients can verify tokens.
  Generate the pair once, e.g. with node Web Crypto
  (`generateKey({ name: "ECDSA", namedCurve: "P-256" })`, export both
  halves as JWK), keep the private half secret, publish the public
  half. **No key pair exists yet. Do not ship a test key.**
- [ ] `ISSUER` — dashboard variable:
  `https://fedpromptly.com/login` (decided 2026-10-30).
- [ ] `BASE_PATH` — dashboard variable: `/login` (decided 2026-10-30;
  step 5 mount support). Leave unset only for a root-mounted worker.

## Bindings — already declared in wrangler.toml, verify at deploy

- [ ] `OAUTH_KV` — KV namespace id
  `3d87785008fb439990fb9dde9490c152`. Holds NON-atomic data only:
  client + Muse key registries, the device user-code index, the audit
  log. One-time records never live here.
- [ ] `OAUTH_STORE` — Durable Object class `OAuthRecord`, migration
  `v1`. One instance per one-time record (auth codes, pending
  approvals, device codes, refresh tokens). This is what makes
  consume-once real.
- [ ] `RATE_LIMIT` — Durable Object class `RateLimitBucket`, migration
  `v2`. Atomic fixed-window counters. If this binding is missing, the
  router answers 503 — limits never silently disappear.

Verify after deploy that all three bindings resolve (a missing binding
shows up immediately as 503s on the affected routes, not as silent
misbehavior).

## Registry population — reviewed human action, via the admin endpoints

No client or Muse key record exists until a human registers it. The
admin endpoints are the ONLY way records enter the registries
(`src/admin/register.js`); there is no self-registration and no seed
data. Registration validates shape only — it cannot validate trust.
The admin checks who the client or Muse is BEFORE registering them.

- [ ] Register the first client(s):
  `POST /admin/clients` with `Authorization: Bearer <ADMIN_TOKEN>`,
  body `{ client_id, name, redirect_uris: ["https://..."] }`
  (exact https URIs, no wildcards, no localhost — anything else is
  rejected). Optional `allowed_scopes` restricts that client to a
  subset of `openid profile email offline_access`.
- [ ] Register the first Muse key(s):
  `POST /admin/muse-keys` with body `{ muse_id, public_key_jwk }`
  (Ed25519 JWK; the module also checks the key actually imports).
  Caveat, documented in BUILD-LOG.md: any 32-byte value imports as an
  Ed25519 public key, so "it imports" proves shape, never ownership.
  The admin's review is the trust step.
- [ ] Confirm a test authorize → approve → token run works against the
  deployed worker with a registered client + key before announcing
  anything.

## Runtime proof — NOT DONE (node tests only, so far)

This is the step that proves the Durable Object bindings on
Cloudflare's runtime. It has not happened. Do it before any public
announcement:

- [ ] `npx wrangler dev` (local dev against real bindings, or a
  staging worker — never production first).
- [ ] `GET /login/health` → `{"ok":true}` (root `/health` 404s under
  the `/login` mount — that is correct, not a failure).
- [ ] Full authorize flow: `GET /login/oauth/authorize` (page shows
  client name, redirect host, scopes, email statement) → signed
  approval via `POST /login/oauth/approval` → code →
  `POST /login/oauth/token` → tokens →
  `GET /login/oauth/userinfo` (email + `email_verified: false`).
- [ ] Full device flow: `POST /login/oauth/device-authorization`
  (verification_uri must read
  `https://fedpromptly.com/login/device`) → `GET /login/device` +
  `POST /login/device` with the user code (page shows client +
  scopes) → signed approval → polling `POST /login/oauth/token`
  issues tokens; a denied device polls to `access_denied`.
- [ ] Rate limits fire: 61st authorize per IP per minute → 429 with
  Retry-After; missing `RATE_LIMIT` binding → 503 (test on staging by
  removing the binding, then restore it).
- [ ] Deny paths: authorize deny redirects the client with
  `error=access_denied`; device deny polls to `access_denied`.
- [ ] Kill switch (below) actually pauses logins while `/login/health`
  still answers.

## Kill switch — the pause button

- Set the `KILL_SWITCH` variable to `1` and redeploy: every OAuth
  route answers 503 (`temporarily_unavailable`) while `/health` keeps
  answering, so liveness checks still work during a pause.
- To resume: remove the variable (or set it to anything other than
  `1`) and redeploy.
- There is deliberately NO cron-based global logout and NO automatic
  token invalidation: routine mass logout is unsafe (see SPEC.md).
  The kill switch is the manual path.

## Rollback — fail closed, then restore

- Immediate pause: set `KILL_SWITCH=1` and redeploy (logins stop,
  health stays up). This is the first move on any incident, before
  diagnosis.
- Restore: redeploy the previous known-good version from git history
  (the repo is the source of truth; the build zips are snapshots).
- The worker never serves a degraded mode: unconfigured issuer, keys,
  or bindings answer 503, and unregistered clients/keys answer 400/403.
  A rollback target that is itself unconfigured is still safe — it
  refuses logins rather than issuing bad ones.

## Release checklist — all boxes must be checked, then his go-ahead

- [x] Cloudflare route `fedpromptly.com/login*` created (his
  dashboard action, 2026-10-30).
- [ ] `ISSUER` set to `https://fedpromptly.com/login`, `BASE_PATH`
  set to `/login` (dashboard variables, not set yet).
- [ ] Secrets set as dashboard secrets (encrypted): `ADMIN_TOKEN`,
  `SIGNING_KEY_JWK`. Plain dashboard variable (NOT a secret):
  `SIGNING_PUBLIC_JWK`. No test keys.
- [ ] All three bindings verified live (OAUTH_KV, OAUTH_STORE,
  RATE_LIMIT; migrations v1 + v2 applied).
- [ ] First client(s) + Muse key(s) registered via the admin
  endpoints, by a reviewed human action.
- [ ] Runtime proof complete on staging (`wrangler dev` checklist
  above), including rate limits, deny paths, and the kill switch.
- [ ] Test authorize + device runs succeed against the deployed
  worker with real registered records.
- [ ] **His explicit go-ahead to deploy.** No deploy happens on a
  checklist alone.

## Step 7 — rate-limit hardening (2026-10-30, after the 503 outage)

All rate-limited routes answered 503 in production even though the
rate-limit store call ran clean (proven by live tail). Step 7 keeps
the DO limiter but changes its failure mode: a storage/transient
error now logs loudly and degrades to allow (throttling off, auth
still on); a missing binding still fails closed (503). Both router
503 paths now log which branch fired. After pushing step 7 and a
green deploy, re-test authorize/device/token/admin: they must
answer (not 503). If the tail shows `rate-limit degraded` warnings,
those lines name the real storage fault for step 8. If routes still
503 with `rate-limit unavailable` in the tail, the RATE_LIMIT
binding itself is not reaching the worker at runtime.

## Still not done, stated plainly

- Runtime proof on Cloudflare (above) — node tests only, so far.
- The `www.fedpromptly.com/login*` route itself — route exists as
  `www.fedpromptly.com/login` (no star yet, 2026-10-30); the star
  is still pending on the dashboard, or paths under /login will not
  route to the worker on www.
- `ADMIN_TOKEN` and signing keys — SET 2026-10-30 (dashboard +
  #private-data); SIGNING_PUBLIC_JWK re-added as a plain variable.
- Registry population — zero records exist until the admin action
  (blocked by the 503; step 7 unblocks the admin routes).
- Approval-page UX beyond this step: the signed payload is still
  pasted JSON; a direct Muse handoff (no paste) is a later polish.
- His go-ahead + release checklist sign-off — not given.

Domain + ISSUER are decided (`https://www.fedpromptly.com/login`,
`BASE_PATH=/login`, 2026-10-30) — that box is no longer open.
