// GET /.well-known/openid-configuration — fails closed (503) until
// ISSUER is configured. No discovery document is served from an
// unconfigured worker, because every endpoint URL in it would be wrong.

import { json } from "../lib/http.js";

export async function discoveryHandler(request, env) {
  if (!env.ISSUER) return json({ error: "not_configured" }, 503);
  const iss = env.ISSUER.replace(/\/$/, "");
  return json(
    {
      issuer: iss,
      authorization_endpoint: `${iss}/oauth/authorize`,
      token_endpoint: `${iss}/oauth/token`,
      userinfo_endpoint: `${iss}/oauth/userinfo`,
      jwks_uri: `${iss}/jwks`,
      revocation_endpoint: `${iss}/oauth/revoke`,
      device_authorization_endpoint: `${iss}/oauth/device-authorization`,
      response_types_supported: ["code"],
      grant_types_supported: [
        "authorization_code",
        "refresh_token",
        "urn:ietf:params:oauth:grant-type:device_code",
      ],
      code_challenge_methods_supported: ["S256"],
      scopes_supported: ["openid", "profile", "email", "offline_access"],
      claims_supported: ["sub", "email", "email_verified", "preferred_username"],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["ES256"],
      token_endpoint_auth_methods_supported: ["none"],
    },
    200,
    { "cache-control": "public, max-age=3600" },
  );
}
