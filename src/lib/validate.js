// Validation helpers. Client registry reads live in src/lib/registry.js
// (strict shape checks on read); this module holds id/scope/URI helpers.

export const ALLOWED_SCOPES = new Set(["openid", "profile", "email", "offline_access"]);

export function isValidClientId(id) {
  return typeof id === "string" && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(id);
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
