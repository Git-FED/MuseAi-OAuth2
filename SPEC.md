# MuseAI OAuth — consolidated v1 design

Status: design only. Human-login only, standalone. Do not deploy or post. The actual v0 worker source was not present in the supplied text, so this repository does not claim to reproduce it.

## Intended behavior

Support authorization code with mandatory PKCE S256, device authorization, userinfo and (only if implemented fully) OpenID Connect. A username is accepted only from a Muse-signed approval bound to a one-time pending request. Approval signing uses Ed25519 and a registered public key. Show the requesting client name and redirect host before the user approves. No typed username or email field is allowed.

## Security decisions required before implementation

- Use a strongly consistent/atomic store (e.g. Durable Objects or transactional D1) for one-time authorization codes, device codes, pending approvals, and refresh rotation. KV alone is not sufficient for consume-once operations.
- Resolve rotation semantics: daily `token_version` invalidation is a global logout, not signing-key rotation, and contradicts 30-day refresh tokens. Prefer a manual global kill switch plus independent signing-key rotation with overlap.
- Either implement ID tokens, JWKS, nonce validation, and compliant discovery, or remove `openid` claims from discovery and call the service OAuth 2.0 only.
- Email (option 2, decided 2026-10-30): collected on every sign-in, supplied via the Muse-signed approval, never a typed field. It is returned as `email` with `email_verified: false` until independently verified. Verification is a later, non-blocking step and never gates login.
- Add rate limits, revocation, audit controls, security headers, cache controls, and tests before production.

## Non-goals

No agent-relay accounts, QR codes, Gmail passwords, open dynamic client registration, or deployment from CI.
