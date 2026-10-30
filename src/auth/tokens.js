// Token issuance and verification. Access tokens are ES256 JWTs signed
// with the env key; refresh tokens are opaque strings whose records live
// ONLY in the Durable Object store. Email policy (option 2): the ID token
// and userinfo carry email with email_verified:false until verification
// lands as a separate, non-blocking step.

import { randomString, signJwt, verifyJwt } from "../lib/crypto.js";
import { recordStub } from "../store/oauth-record.js";

export const ACCESS_TTL_S = 3600;
export const REFRESH_TTL_MS = 30 * 24 * 3600 * 1000;

export function requireTokenConfig(env) {
  return Boolean(env.ISSUER && env.SIGNING_KEY_JWK);
}

export async function issueTokenPair(env, { sub, username, email, clientId, scope, nonce }) {
  const now = Math.floor(Date.now() / 1000);
  const privateJwk = JSON.parse(env.SIGNING_KEY_JWK);
  const accessClaims = {
    iss: env.ISSUER,
    sub,
    aud: clientId,
    exp: now + ACCESS_TTL_S,
    iat: now,
    scope: scope.join(" "),
    email,
    preferred_username: username,
    jti: randomString(16),
  };
  const out = {
    access_token: await signJwt(accessClaims, privateJwk),
    token_type: "Bearer",
    expires_in: ACCESS_TTL_S,
    scope: scope.join(" "),
  };
  if (scope.includes("openid")) {
    const idClaims = {
      iss: env.ISSUER,
      sub,
      aud: clientId,
      exp: now + ACCESS_TTL_S,
      iat: now,
      email,
      email_verified: false,
      preferred_username: username,
    };
    if (nonce) idClaims.nonce = nonce;
    out.id_token = await signJwt(idClaims, privateJwk);
  }
  if (scope.includes("offline_access")) {
    const refresh = randomString(48);
    await recordStub(env, `refresh:${refresh}`).create(
      { kind: "refresh", sub, username, email, client_id: clientId, scope },
      REFRESH_TTL_MS,
    );
    out.refresh_token = refresh;
  }
  return out;
}

// Returns the access-token payload, or null for a bad signature, expiry,
// issuer mismatch, or a revoked jti.
export async function verifyAccessToken(env, token) {
  if (!env.SIGNING_PUBLIC_JWK) return null;
  let publicJwk;
  try {
    publicJwk = JSON.parse(env.SIGNING_PUBLIC_JWK);
  } catch {
    return null;
  }
  const payload = await verifyJwt(token, publicJwk);
  if (!payload) return null;
  if (env.ISSUER && payload.iss !== env.ISSUER) return null;
  if (payload.jti && env.OAUTH_KV) {
    const revoked = await env.OAUTH_KV.get(`revoked_access:${payload.jti}`);
    if (revoked) return null;
  }
  return payload;
}

// Rotation: the new pair is issued first so the user is never left with
// nothing, then the old refresh record is revoked. Returns null when the
// old token does not exist (already rotated, revoked, or expired).
export async function rotateRefresh(env, oldToken) {
  const oldStub = recordStub(env, `refresh:${oldToken}`);
  const rec = await oldStub.read();
  if (!rec) return null;
  const pair = await issueTokenPair(env, {
    sub: rec.sub,
    username: rec.username,
    email: rec.email,
    clientId: rec.client_id,
    scope: rec.scope,
    nonce: null,
  });
  await oldStub.revoke();
  return pair;
}
