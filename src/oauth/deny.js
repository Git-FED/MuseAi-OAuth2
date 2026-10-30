// POST /oauth/deny — the clean DENY path for both flows.
//
// A pending authorize request or a pending device request can be denied
// by anyone holding its id (the id is the capability: it is random, and
// it is only shown on the approval page or the device itself). Denial is
// terminal and terminal-only:
//   - the record's status becomes "denied" (it is never usable again),
//     and it expires with its normal TTL — nothing is left "awaiting";
//   - a later approval attempt on the same id answers access_denied;
//   - a polling device token request on a denied device answers
//     access_denied (see src/oauth/token.js).
// Denying an already-approved request is refused: the code is already
// out, and revocation (POST /oauth/revoke) is the path for that.
// Denial is audited like every other approval outcome. No denial ever
// leaks whether an id exists beyond what the caller already holds: an
// unknown id answers the same invalid_pending/invalid_device error an
// approval attempt would.

import { audit } from "../lib/audit.js";
import { recordStub } from "../store/oauth-record.js";
import { json, parseFormOrJson } from "../lib/http.js";

export async function denyHandler(request, env) {
  const body = await parseFormOrJson(request);
  if (!body || typeof body !== "object") return json({ error: "invalid_request" }, 400);
  const kind = body.pending_id ? "pending" : body.device_code ? "device" : null;
  const id = body.pending_id || body.device_code;
  if (!kind) return json({ error: "invalid_request", error_description: "pending_id or device_code required" }, 400);

  const stub = recordStub(env, `${kind}:${id}`);
  const rec = await stub.read();
  if (!rec) {
    return json({ error: kind === "pending" ? "invalid_pending" : "invalid_device" }, 400);
  }
  if (rec.status === "approved") {
    return json({ error: "already_approved", error_description: "this request was already approved; revoke instead" }, 400);
  }
  if (rec.status === "denied") {
    // Idempotent: already denied, still denied. No second audit entry.
    return json(denyResponse(rec));
  }

  const remaining = Math.max(rec.exp - Date.now(), 1000);
  await stub.replace({ ...rec, status: "denied" }, remaining);
  await audit(env, "approval_denied", {
    actor: null,
    clientId: rec.client_id || null,
    route: "/oauth/deny",
    outcome: "denied",
    detail: kind === "pending" ? "denied_by_user" : "device_denied_by_user",
  });
  return json(denyResponse(rec));
}

function denyResponse(rec) {
  // Authorize flow: send the user back to the client with the standard
  // OAuth denial, so the client sees access_denied, not a dead page.
  if (rec.kind === "pending" && rec.redirect_uri) {
    const redirect = new URL(rec.redirect_uri);
    redirect.searchParams.set("error", "access_denied");
    if (rec.state) redirect.searchParams.set("state", rec.state);
    return { denied: true, redirect_to: redirect.toString() };
  }
  return { denied: true };
}
