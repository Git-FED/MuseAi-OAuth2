// Strict registry readers. Registries live in KV (they are data, never
// consumable records), but a record is only trusted when its shape checks
// out on read. Anything malformed is treated as unregistered — fail closed,
// never "close enough".
//
// Key shapes:
//   client:<id>   -> { client_id, name, redirect_uris, allowed_scopes? }
//   muse_key:<id> -> { muse_id, public_key_jwk, created_at? }
//
// The client and Muse-key writers (src/admin/register.js) validate on
// write too, but write-time checks are not a substitute for read-time
// checks: KV content can be edited by hand, so every read re-validates.

import { ALLOWED_SCOPES, isValidClientId } from "./validate.js";

export function isValidRedirectUri(uri) {
  if (typeof uri !== "string" || uri.includes("*")) return false;
  let u;
  try {
    u = new URL(uri);
  } catch {
    return false;
  }
  if (u.protocol !== "https:") return false;
  if (u.username || u.password) return false;
  const host = u.hostname.toLowerCase();
  if (host === "localhost" || host.endsWith(".localhost")) return false;
  if (host === "127.0.0.1" || host === "::1") return false;
  if (/^127\.\d+\.\d+\.\d+$/.test(host)) return false;
  return true;
}

// Ed25519 public key in JWK form. Required: kty "OKP", crv "Ed25519",
// and a base64url x. The RFC-standard optional members are allowed with
// validated values (alg "Ed25519", use "sig", kid a short string,
// key_ops a subset of ["verify"], ext a boolean) — standard exporters
// (including Web Crypto's own exportKey) emit key_ops/ext/alg, so
// rejecting them would reject real keys. Anything else is a rejection:
// a key record must not smuggle in fields that change what the key means.
export function isValidJwkEd25519(jwk) {
  if (!jwk || typeof jwk !== "object" || Array.isArray(jwk)) return false;
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519") return false;
  if (typeof jwk.x !== "string" || !/^[A-Za-z0-9_-]+$/.test(jwk.x)) return false;
  if (jwk.x.length < 20) return false;
  if (jwk.alg !== undefined && jwk.alg !== "Ed25519") return false;
  if (jwk.use !== undefined && jwk.use !== "sig") return false;
  if (jwk.kid !== undefined && (typeof jwk.kid !== "string" || !jwk.kid || jwk.kid.length > 128)) return false;
  if (jwk.key_ops !== undefined) {
    if (!Array.isArray(jwk.key_ops) || !jwk.key_ops.every((op) => op === "verify")) return false;
  }
  if (jwk.ext !== undefined && typeof jwk.ext !== "boolean") return false;
  if (!Object.keys(jwk).every((k) => ["kty", "crv", "x", "alg", "use", "kid", "key_ops", "ext"].includes(k))) return false;
  return true;
}

function isValidClientRecord(clientId, rec) {
  if (!rec || typeof rec !== "object" || Array.isArray(rec)) return false;
  if (rec.client_id !== clientId) return false;
  if (typeof rec.name !== "string" || !rec.name.trim() || rec.name.length > 200) return false;
  if (!Array.isArray(rec.redirect_uris) || rec.redirect_uris.length === 0) return false;
  if (!rec.redirect_uris.every((u) => typeof u === "string" && isValidRedirectUri(u))) return false;
  if (rec.allowed_scopes !== undefined) {
    if (!Array.isArray(rec.allowed_scopes) || rec.allowed_scopes.length === 0) return false;
    if (!rec.allowed_scopes.every((s) => ALLOWED_SCOPES.has(s))) return false;
  }
  return true;
}

// Returns the validated client record, or null when unregistered or
// malformed. A client without allowed_scopes may request any known scope;
// a client WITH allowed_scopes is restricted to that subset (enforced by
// the authorize and device-authorization handlers).
export async function getClient(env, clientId) {
  if (!isValidClientId(clientId) || !env.OAUTH_KV) return null;
  const raw = await env.OAUTH_KV.get(`client:${clientId}`);
  if (!raw) return null;
  try {
    const rec = JSON.parse(raw);
    return isValidClientRecord(clientId, rec) ? rec : null;
  } catch {
    return null;
  }
}

// Returns the validated Muse key record { muse_id, public_key_jwk }, or
// null when unregistered or malformed. Callers must treat null as
// "no trusted key" and fail closed (approval: 403).
export async function getMuseKey(env, museId) {
  if (!isValidClientId(museId) || !env.OAUTH_KV) return null;
  const raw = await env.OAUTH_KV.get(`muse_key:${museId}`);
  if (!raw) return null;
  try {
    const rec = JSON.parse(raw);
    if (!rec || typeof rec !== "object" || Array.isArray(rec)) return null;
    if (rec.muse_id !== museId) return null;
    if (!isValidJwkEd25519(rec.public_key_jwk)) return null;
    return { muse_id: rec.muse_id, public_key_jwk: rec.public_key_jwk };
  } catch {
    return null;
  }
}
