// GET /oauth/pending-status — the auto-finish poll endpoint (step 13).
//
// The authorize approval page no longer takes a pasted payload and no
// longer shows a Continue link. It polls this endpoint every 2 seconds
// and finishes itself the moment the request changes state:
//
//   awaiting -> { status: "awaiting" }              (keep polling)
//   approved -> { status: "approved", redirect_to } (page navigates)
//   denied   -> { status: "denied", redirect_to }   (page navigates
//                to the client's standard access_denied redirect)
//
// Security, kept exactly as the old Continue link had it:
// - The pending/device id is the capability: it is random, shown only
//   on the approval page or the device itself, and expires with the
//   10-minute pending TTL. Unknown or expired ids answer the same
//   invalid_pending / invalid_device error an approval attempt would.
// - The auth code is returned ONLY to a caller holding the pending id,
//   and only after approval. It is still useless without the PKCE
//   verifier, which lives only in the client page that started the
//   flow (sessionStorage) — never on this page, never in this response.
// - No audit entry per poll: polling every 2 seconds would flood KV.
//   Approvals, denials, and token redemptions are still audited where
//   they happen (approval.js, deny.js, token.js).
// - Device requests return status only, never a redirect: the device
//   client already polls /oauth/token for its tokens, so the device
//   page just shows "approved" and stops.

import { recordStub } from "../store/oauth-record.js";
import { json } from "../lib/http.js";

export async function pendingStatusHandler(request, env) {
  const q = new URL(request.url).searchParams;
  const pendingId = q.get("pending_id");
  const deviceCode = q.get("device_code");
  if ((pendingId && deviceCode) || (!pendingId && !deviceCode)) {
    return json({ error: "invalid_request", error_description: "pending_id or device_code required" }, 400);
  }
  const kind = pendingId ? "pending" : "device";
  const id = pendingId || deviceCode;
  const rec = await recordStub(env, `${kind}:${id}`).read();
  if (!rec) {
    return json({ error: kind === "pending" ? "invalid_pending" : "invalid_device" }, 400);
  }
  // Authorize records use "awaiting", device records use "pending"
  // for the same waiting state — the poll API normalizes both to
  // "awaiting" so the page script only ever checks one value.
  if (rec.status === "awaiting" || rec.status === "pending") return json({ status: "awaiting" });
  if (kind === "device") {
    // approved or denied: status only, the device client polls token.
    return json({ status: rec.status });
  }
  // Authorize flow: rebuild the exact redirect the approval/deny
  // handlers would have returned, so the page can navigate itself.
  const redirect = new URL(rec.redirect_uri);
  if (rec.status === "approved" && rec.auth_code) {
    redirect.searchParams.set("code", rec.auth_code);
    if (rec.state) redirect.searchParams.set("state", rec.state);
    return json({ status: "approved", redirect_to: redirect.toString() });
  }
  if (rec.status === "denied") {
    redirect.searchParams.set("error", "access_denied");
    if (rec.state) redirect.searchParams.set("state", rec.state);
    return json({ status: "denied", redirect_to: redirect.toString() });
  }
  // Approved without a stored code should never happen (approval.js
  // stores it atomically with the status flip); fail closed, not open.
  return json({ error: "server_error" }, 500);
}
