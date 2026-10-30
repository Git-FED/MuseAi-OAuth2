// GET /oauth/userinfo — Bearer access token in, identity out.
// Email policy (option 2): email is returned with email_verified:false
// until independent verification lands as a later, non-blocking step.

import { verifyAccessToken } from "../auth/tokens.js";
import { json } from "../lib/http.js";

export async function userinfoHandler(request, env) {
  const auth = request.headers.get("authorization") || "";
  const match = /^Bearer (.+)$/.exec(auth);
  if (!match) return json({ error: "invalid_token" }, 401);
  const payload = await verifyAccessToken(env, match[1]);
  if (!payload) return json({ error: "invalid_token" }, 401);
  const out = {
    sub: payload.sub,
    email: payload.email ?? null,
    email_verified: false,
  };
  if (payload.preferred_username) out.preferred_username = payload.preferred_username;
  return json(out);
}
