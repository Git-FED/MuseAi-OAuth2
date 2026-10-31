// GET /oauth/profile — Bearer access token in, profile record out.
// Same auth shape as userinfo (valid token or 401), plus the profile
// itself: 404 profile_not_found when no valid record exists for the
// token's sub (e.g. a token issued before step 16, or a login whose
// profile write failed). The next fresh sign-in creates the record.
// A site reads this with the same token it uses for userinfo, so it
// can tell a returning user (record exists, count > 1) from a
// stranger/first-timer — without the site holding any data itself.

import { verifyAccessToken } from "../auth/tokens.js";
import { getProfile } from "../lib/profile.js";
import { json } from "../lib/http.js";

export async function profileHandler(request, env) {
  const auth = request.headers.get("authorization") || "";
  const match = /^Bearer (.+)$/.exec(auth);
  if (!match) return json({ error: "invalid_token" }, 401);
  const payload = await verifyAccessToken(env, match[1]);
  if (!payload) return json({ error: "invalid_token" }, 401);
  const profile = await getProfile(env, payload.sub);
  if (!profile) return json({ error: "profile_not_found" }, 404);
  return json(profile);
}
