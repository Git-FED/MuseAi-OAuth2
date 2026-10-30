// Validation against the KV client registry. Redirect URIs are matched
// exactly — no prefix, wildcard, or localhost exception anywhere.

export const ALLOWED_SCOPES = new Set(["openid", "profile", "email", "offline_access"]);

export function isValidClientId(id) {
  return typeof id === "string" && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(id);
}

// Client registry lives in KV: client:<client_id> -> { client_id, name, redirect_uris }.
// Returns null when unregistered or malformed. Registries are data, never
// consumable records, so KV is the right home for them.
export async function getClient(env, clientId) {
  const raw = await env.OAUTH_KV.get(`client:${clientId}`);
  if (!raw) return null;
  try {
    const client = JSON.parse(raw);
    if (client.client_id !== clientId || !Array.isArray(client.redirect_uris)) return null;
    return client;
  } catch {
    return null;
  }
}

export function validateRedirectUri(client, uri) {
  return typeof uri === "string" && client.redirect_uris.includes(uri);
}

// Returns the scope array, or null when any requested scope is unknown.
// No scope requested means the default: openid.
export function parseScope(scopeStr) {
  if (!scopeStr) return ["openid"];
  const parts = scopeStr.split(/\s+/).filter(Boolean);
  for (const scope of parts) {
    if (!ALLOWED_SCOPES.has(scope)) return null;
  }
  return parts;
}

export function redirectHost(uri) {
  try {
    return new URL(uri).host;
  } catch {
    return null;
  }
}
