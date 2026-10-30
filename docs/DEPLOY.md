# Deploy prep — Login with Muse worker (build step 4, 2026-10-30)

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

## Decisions still open (owner's call, not set here)

- [ ] **Custom domain + ISSUER.** `wrangler.toml` has `workers_dev =
  false` and the `ISSUER` var commented out. Discovery
  (`/.well-known/openid-configuration`), JWKS (`/jwks`), token
  issuance, and the device `verification_uri` all derive from `ISSUER`.
  Until a domain is attached and `ISSUER` is set to it (dashboard
  variable, e.g. `https://login.example.com` — replace with the real
  domain), discovery and JWKS answer 503 by design. **No domain is
  chosen in this repo. Do not invent one.**
- [ ] **First clients.** Which of his own sites become the first
  registered clients, and their exact redirect URIs. Registration is
  via the admin endpoints (below), never by editing code.

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
- [ ] `ISSUER` — dashboard variable, once the domain is chosen (above).

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
- [ ] `GET /health` → `{"ok":true}`.
- [ ] Full authorize flow: `GET /oauth/authorize` (page shows client
  name, redirect host, scopes, email statement) → signed approval via
  `POST /oauth/approval` → code → `POST /oauth/token` → tokens →
  `GET /oauth/userinfo` (email + `email_verified: false`).
- [ ] Full device flow: `POST /oauth/device-authorization` →
  `GET /device` + `POST /device` with the user code (page shows client
  + scopes) → signed approval → polling `POST /oauth/token` issues
  tokens; a denied device polls to `access_denied`.
- [ ] Rate limits fire: 61st authorize per IP per minute → 429 with
  Retry-After; missing `RATE_LIMIT` binding → 503 (test on staging by
  removing the binding, then restore it).
- [ ] Deny paths: authorize deny redirects the client with
  `error=access_denied`; device deny polls to `access_denied`.
- [ ] Kill switch (below) actually pauses logins while `/health`
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

- [ ] Custom domain attached; `ISSUER` set to it.
- [ ] `ADMIN_TOKEN`, `SIGNING_KEY_JWK`, `SIGNING_PUBLIC_JWK` set as
  dashboard secrets/variables. No test keys.
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

## Still not done, stated plainly

- Runtime proof on Cloudflare (above) — node tests only, so far.
- Domain + ISSUER choice — his call.
- `ADMIN_TOKEN` and signing keys — unset anywhere.
- Registry population — zero records exist until the admin action.
- Approval-page UX beyond this step: the signed payload is still
  pasted JSON; a direct Muse handoff (no paste) is a later polish.
- His go-ahead + release checklist sign-off — not given.
