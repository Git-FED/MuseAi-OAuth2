// GET/POST /oauth/two-step — the user's own toggle, nothing else.
// Bearer access token in, only that token's sub can be toggled.
// GET -> { enabled }. POST { enabled: true|false } -> { enabled }.
// No admin token, no other sub, no forced default: off until turned on.
import { verifyAccessToken } from "../auth/tokens.js";
import { getTwoStep, setTwoStep } from "../lib/two-step.js";
import { json, parseFormOrJson } from "../lib/http.js";

export async function twoStepHandler(request, env) {
  const auth = request.headers.get("authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  const payload = token ? await verifyAccessToken(env, token) : null;
  if (!payload) return json({ error: "invalid_token" }, 401);
  const sub = payload.sub;
  if (request.method === "GET") {
    return json({ enabled: await getTwoStep(env, sub) });
  }
  const body = await parseFormOrJson(request);
  if (!body || typeof body.enabled !== "boolean") return json({ error: "invalid_request" }, 400);
  await setTwoStep(env, sub, body.enabled);
  return json({ enabled: body.enabled });
}
