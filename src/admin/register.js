// Admin registration endpoints. These are the ONLY way client and Muse
// key records enter the KV registries: there is no public
// self-registration, no signup form, and no default record.
//
// Authorization: a single ADMIN_TOKEN secret, set as a Cloudflare
// dashboard secret at deploy time (never in code, never in wrangler.toml,
// never in the repo). When ADMIN_TOKEN is unset, every admin endpoint
// refuses everything — an unconfigured admin surface is a closed one.
// The token travels only as `Authorization: Bearer <token>` and is never
// logged, echoed, or written to KV.
//
// Registration is a reviewed human action: the admin checks who the client
// or Muse is before registering them. This module validates shape only;
// it cannot validate trust.

import { importEd25519Public } from "../lib/crypto.js";
import { audit } from "../lib/audit.js";
import { json, parseFormOrJson } from "../lib/http.js";
import { isValidJwkEd25519, isValidRedirectUri } from "../lib/registry.js";
import { ALLOWED_SCOPES, isValidClientId } from "../lib/validate.js";

function timingSafeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function adminAuthed(request, env) {
  if (!env.ADMIN_TOKEN) return false;
  const auth = request.headers.get("authorization") || "";
  const match = /^Bearer (.+)$/.exec(auth);
  if (!match) return false;
  return timingSafeEqual(match[1], env.ADMIN_TOKEN);
}

async function denied(request, env, route) {
  await audit(env, "admin_denied", { actor: "admin", route, outcome: "denied", detail: "bad_token" });
  return json({ error: "forbidden" }, 403);
}

function validateClientPayload(body) {
  if (!body || typeof body !== "object") return null;
  const { client_id, name, redirect_uris, allowed_scopes } = body;
  if (!isValidClientId(client_id)) return null;
  if (typeof name !== "string" || !name.trim() || name.length > 200) return null;
  if (!Array.isArray(redirect_uris) || redirect_uris.length === 0) return null;
  if (!redirect_uris.every((u) => typeof u === "string" && isValidRedirectUri(u))) return null;
  if (allowed_scopes !== undefined) {
    if (!Array.isArray(allowed_scopes) || allowed_scopes.length === 0) return null;
    if (!allowed_scopes.every((s) => ALLOWED_SCOPES.has(s))) return null;
  }
  const rec = { client_id, name: name.trim(), redirect_uris: [...redirect_uris] };
  if (allowed_scopes !== undefined) rec.allowed_scopes = [...allowed_scopes];
  return rec;
}

export async function registerClientHandler(request, env) {
  if (!adminAuthed(request, env)) return denied(request, env, "/admin/clients");
  const body = await parseFormOrJson(request);
  const rec = validateClientPayload(body);
  if (!rec) return json({ error: "invalid_request", error_description: "client record failed validation" }, 400);
  await env.OAUTH_KV.put(`client:${rec.client_id}`, JSON.stringify(rec));
  await audit(env, "admin_client_registered", { actor: "admin", clientId: rec.client_id, route: "/admin/clients", outcome: "success" });
  return json({ ok: true, client_id: rec.client_id }, 201);
}

async function validateMuseKeyPayload(body) {
  if (!body || typeof body !== "object") return null;
  const { muse_id, public_key_jwk } = body;
  if (!isValidClientId(muse_id)) return null;
  if (!isValidJwkEd25519(public_key_jwk)) return null;
  // Shape is not enough: the JWK must actually import as an Ed25519 key.
  try {
    await importEd25519Public(public_key_jwk);
  } catch {
    return null;
  }
  return { muse_id, public_key_jwk, created_at: Date.now() };
}

export async function registerMuseKeyHandler(request, env) {
  if (!adminAuthed(request, env)) return denied(request, env, "/admin/muse-keys");
  const body = await parseFormOrJson(request);
  const rec = await validateMuseKeyPayload(body);
  if (!rec) return json({ error: "invalid_request", error_description: "muse key record failed validation" }, 400);
  await env.OAUTH_KV.put(`muse_key:${rec.muse_id}`, JSON.stringify(rec));
  await audit(env, "admin_muse_key_registered", { actor: "admin", clientId: rec.muse_id, route: "/admin/muse-keys", outcome: "success" });
  return json({ ok: true, muse_id: rec.muse_id }, 201);
}
